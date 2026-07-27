# SPDX-License-Identifier: MIT
"""Fail-closed key storage contracts with an explicit test-only backend."""

from __future__ import annotations

import inspect
import os
import threading
import weakref
from collections.abc import Callable, Mapping
from contextlib import AbstractContextManager
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Protocol, Self, SupportsIndex, cast

_MAX_IDENTIFIER_LENGTH = 128
_MAX_SECRET_BYTES = 65_536
_IDENTIFIER_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
)
_IDENTIFIER_EDGE_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
)


class KeyStoreError(Exception):
    """Base class for secret-free key-store failures."""

    code = "key_store_error"
    _safe_message = "The key store operation failed."

    def __init__(self) -> None:
        super().__init__(self.code, self._safe_message)

    @property
    def message(self) -> str:
        """Return the canonical safe message for this exact error class."""

        return self._safe_message

    def __setattr__(self, name: str, value: object) -> None:
        runtime_fields = {
            "__traceback__",
            "__cause__",
            "__context__",
            "__suppress_context__",
        }
        if name not in runtime_fields:
            raise AttributeError("Key-store errors are immutable.")
        Exception.__setattr__(self, name, value)

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self

    def __reduce__(
        self,
    ) -> tuple[Callable[..., KeyStoreError], tuple[type[KeyStoreError]]]:
        return _restore_key_store_error, (type(self),)

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"

    def __repr__(self) -> str:
        return f"{type(self).__name__}()"


class InvalidKeyIdentifier(KeyStoreError):
    """A tenant or key identifier is outside the safe identifier grammar."""

    code = "invalid_key_identifier"
    _safe_message = "The key identifier is invalid."


class InvalidKeyMaterial(KeyStoreError):
    """Transferred key material is not mutable, nonempty, and bounded."""

    code = "invalid_key_material"
    _safe_message = "The key material is invalid."


class KeyNotFound(KeyStoreError):
    """No key exists at the requested tenant-scoped identifier."""

    code = "key_not_found"
    _safe_message = "The requested key does not exist."


class KeyStoreUnavailable(KeyStoreError):
    """The required secure storage backend is unavailable."""

    code = "key_store_unavailable"
    _safe_message = "A supported secure key store is unavailable."


class KeyStoreCorrupt(KeyStoreError):
    """Stored key material could not be safely loaded."""

    code = "key_store_corrupt"
    _safe_message = "The stored key material is corrupt."


class KeyStoreClosed(KeyStoreError):
    """The key store or loaded secret lease has already closed."""

    code = "key_store_closed"
    _safe_message = "The key store is closed."


_KEY_STORE_ERROR_TYPES = frozenset(
    {
        KeyStoreError,
        InvalidKeyIdentifier,
        InvalidKeyMaterial,
        KeyNotFound,
        KeyStoreUnavailable,
        KeyStoreCorrupt,
        KeyStoreClosed,
    }
)


def _restore_key_store_error(
    error_type: type[KeyStoreError],
) -> KeyStoreError:
    """Restore only one canonical built-in error class with no runtime state."""

    if error_type not in _KEY_STORE_ERROR_TYPES:
        raise TypeError("Unsupported key-store error type.")
    return error_type()


class KeyStore(Protocol):
    """Static, synchronous key-store boundary.

    Implementations must use the exact ``load``/``store``/``delete`` shape and
    publish immutable, non-secret capability metadata. The protocol is not
    runtime-checkable: callers never guess whether an implementation is sync or
    async. Async callers cross this synchronous boundary through an explicitly
    selected executor when the backing implementation may block.

    This boundary prevents accidental or duck-typed insecure backends. It does
    not sandbox arbitrary code already executing in the same-process Python
    runtime; such code can introspect or monkeypatch internals and is trusted.

    ``store`` takes ownership of a mutable input buffer and must erase that
    input before returning, including on failure. ``load`` returns an opaque
    closing lease. Its explicit ``copy_bytes()`` operation creates immutable
    caller-owned bytes that the caller must minimize and discard promptly.
    """

    @property
    def capabilities(self) -> Mapping[str, bool | str]:
        """Return immutable, non-secret backend capability metadata."""

    def load(
        self,
        *,
        tenant_id: str,
        key_id: str,
    ) -> AbstractContextManager[_SecretLease]:
        """Load one tenant-scoped key into an opaque, closing lease."""

    def store(
        self,
        *,
        tenant_id: str,
        key_id: str,
        value: bytearray,
    ) -> None:
        """Take ownership of, copy, and erase mutable key material."""

    def delete(self, *, tenant_id: str, key_id: str) -> None:
        """Delete and erase one tenant-scoped key."""


_EPHEMERAL_CAPABILITIES: Mapping[str, bool | str] = MappingProxyType(
    {
        "backend": "ephemeral-memory",
        "fork_behavior": "clear",
        "os_backed": False,
        "persistent": False,
        "process_local": True,
        "production_ready": False,
        "testing_only": True,
    }
)


def _wipe(buffer: bytearray | None) -> None:
    """Best-effort in-place erasure without resizing an exported buffer."""

    if buffer is None:
        return
    try:
        for index in range(len(buffer)):
            buffer[index] = 0
    except Exception:
        # CPython cannot promise physical zeroization, but no cleanup failure
        # may replace the original safe failure or expose diagnostics.
        pass


def _validate_identifier(value: object) -> str:
    try:
        valid = (
            type(value) is str
            and 0 < len(value) <= _MAX_IDENTIFIER_LENGTH
            and value[0] in _IDENTIFIER_EDGE_CHARS
            and value[-1] in _IDENTIFIER_EDGE_CHARS
            and all(character in _IDENTIFIER_CHARS for character in value)
            and ".." not in value
        )
    except Exception:
        valid = False
    if not valid:
        del value
        raise InvalidKeyIdentifier() from None
    return cast(str, value)


def _take_secret(value: object) -> bytearray:
    """Copy transferred mutable input and erase the caller's buffer."""

    if type(value) is not bytearray:
        del value
        raise InvalidKeyMaterial() from None

    source = value
    del value
    owned: bytearray | None = None
    invalid = False
    try:
        size = len(source)
        if size < 1 or size > _MAX_SECRET_BYTES:
            invalid = True
        else:
            owned = bytearray(source)
            invalid = len(owned) != size
    except Exception:
        _wipe(owned)
        raise KeyStoreUnavailable() from None
    finally:
        _wipe(source)

    if invalid or owned is None:
        _wipe(owned)
        raise InvalidKeyMaterial() from None
    return owned


class _SecretLease:
    """PID-bound loaded secret with opaque diagnostics and owned erasure.

    ``copy_bytes`` is intentionally explicit: its immutable result cannot be
    zeroized by this lease. Callers must keep that copy short-lived and delete
    their reference promptly.
    """

    __slots__ = ("__weakref__", "_buffer", "_closed", "_owner_pid")

    _buffer: bytearray
    _closed: bool
    _owner_pid: int

    def __init__(self, owned_buffer: bytearray) -> None:
        object.__setattr__(self, "_buffer", owned_buffer)
        object.__setattr__(self, "_closed", False)
        try:
            owner_pid = os.getpid()
        except Exception:
            self._invalidate()
            raise KeyStoreUnavailable() from None
        object.__setattr__(self, "_owner_pid", owner_pid)

    def _invalidate(self) -> None:
        try:
            _wipe(self._buffer)
            object.__setattr__(self, "_closed", True)
        except Exception:
            pass

    def _owner_matches(self) -> bool:
        try:
            return os.getpid() == self._owner_pid
        except Exception:
            return False

    def _require_open(self) -> None:
        if not self._owner_matches():
            self._invalidate()
            raise KeyStoreClosed() from None
        if self._closed:
            raise KeyStoreClosed() from None

    @property
    def closed(self) -> bool:
        """Return closed state, invalidating an inherited fork copy first."""

        if not self._owner_matches():
            self._invalidate()
        return self._closed

    def copy_bytes(self) -> bytes:
        """Create an explicit, immutable, caller-owned copy of key material."""

        self._require_open()
        try:
            return bytes(self._buffer)
        except Exception:
            self._invalidate()
            raise KeyStoreUnavailable() from None

    def __enter__(self) -> Self:
        self._require_open()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def close(self) -> None:
        if not self._owner_matches():
            self._invalidate()
            raise KeyStoreClosed() from None
        self._invalidate()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("Loaded key material is immutable.")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("Loaded key material is immutable.")

    def __str__(self) -> str:
        closed = self.closed
        return f"_SecretLease(closed={closed}, value=[REDACTED])"

    def __repr__(self) -> str:
        closed = self.closed
        return f"_SecretLease(closed={closed}, value='[REDACTED]')"

    def __copy__(self) -> Self:
        self._require_open()
        raise TypeError("Loaded key material cannot be copied.")

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        self._require_open()
        raise TypeError("Loaded key material cannot be copied.")

    def __reduce__(self) -> str | tuple[Any, ...]:
        self._require_open()
        raise TypeError("Loaded key material cannot be serialized.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        self._require_open()
        raise TypeError("Loaded key material cannot be serialized.")

    def __getstate__(self) -> object:
        self._require_open()
        raise TypeError("Loaded key material cannot be serialized.")

    def __del__(self) -> None:
        self._invalidate()


class EphemeralKeyStore:
    """Explicit test-only, process-local, in-memory key store."""

    __slots__ = ("__weakref__", "_closed", "_entries", "_leases", "_lock", "_pid")

    _closed: bool
    _entries: dict[tuple[str, str], bytearray]
    _leases: weakref.WeakSet[_SecretLease]
    _lock: threading.RLock
    _pid: int

    def __init__(self, *, testing_only: bool | None = None) -> None:
        if testing_only is not True or type(testing_only) is not bool:
            raise KeyStoreUnavailable() from None
        object.__setattr__(self, "_lock", threading.RLock())
        object.__setattr__(self, "_entries", {})
        object.__setattr__(self, "_leases", weakref.WeakSet())
        object.__setattr__(self, "_closed", False)
        try:
            pid = os.getpid()
        except Exception:
            self.close()
            raise KeyStoreUnavailable() from None
        object.__setattr__(self, "_pid", pid)
        if hasattr(os, "register_at_fork"):
            store_reference = weakref.ref(self)

            def clear_in_child() -> None:
                store = store_reference()
                if store is not None:
                    store._after_fork_child()

            try:
                os.register_at_fork(after_in_child=clear_in_child)
            except Exception:
                self.close()
                raise KeyStoreUnavailable() from None

    @property
    def capabilities(self) -> Mapping[str, bool | str]:
        """Identify this backend as test-only and nonpersistent."""

        return _EPHEMERAL_CAPABILITIES

    @property
    def closed(self) -> bool:
        """Whether this store erased its contents and stopped accepting work."""

        self._clear_if_forked()
        with self._lock:
            return self._closed

    def _clear_if_forked(self) -> None:
        try:
            current_pid = os.getpid()
        except Exception:
            raise KeyStoreUnavailable() from None
        if current_pid == self._pid:
            return
        self._after_fork_child(current_pid=current_pid)

    def _after_fork_child(self, *, current_pid: int | None = None) -> None:
        # Only the calling thread survives a POSIX fork. Replace a potentially
        # inherited locked mutex before touching inherited secret state.
        if current_pid is None:
            try:
                current_pid = os.getpid()
            except Exception:
                current_pid = -1
        inherited = self._entries
        leases = tuple(self._leases)
        object.__setattr__(self, "_entries", {})
        object.__setattr__(self, "_leases", weakref.WeakSet())
        object.__setattr__(self, "_lock", threading.RLock())
        object.__setattr__(self, "_pid", current_pid)
        for value in inherited.values():
            _wipe(value)
        inherited.clear()
        for lease in leases:
            lease._invalidate()

    def _require_open(self) -> None:
        if self._closed:
            raise KeyStoreClosed() from None

    def load(
        self,
        *,
        tenant_id: str,
        key_id: str,
    ) -> AbstractContextManager[_SecretLease]:
        """Return a copied secret lease, never the stored buffer itself."""

        reference: tuple[str, str]
        try:
            reference = (
                _validate_identifier(tenant_id),
                _validate_identifier(key_id),
            )
        finally:
            del tenant_id, key_id
        self._clear_if_forked()
        loaded: bytearray | None = None
        lease: _SecretLease | None = None
        with self._lock:
            self._require_open()
            stored = self._entries.get(reference)
            if stored is None:
                raise KeyNotFound() from None
            if (
                type(stored) is not bytearray
                or not stored
                or len(stored) > _MAX_SECRET_BYTES
            ):
                invalid = self._entries.pop(reference)
                if type(invalid) is bytearray:
                    _wipe(invalid)
                del invalid, stored
                raise KeyStoreCorrupt() from None
            try:
                loaded = bytearray(stored)
            except Exception:
                del stored
                raise KeyStoreUnavailable() from None
            del stored
            try:
                lease = _SecretLease(loaded)
                self._leases.add(lease)
            except Exception:
                _wipe(loaded)
                raise KeyStoreUnavailable() from None
        return lease

    def store(
        self,
        *,
        tenant_id: str,
        key_id: str,
        value: bytearray,
    ) -> None:
        """Replace a key after taking ownership of and erasing caller input."""

        owned: bytearray | None = None
        reference: tuple[str, str] | None = None
        prepared = False
        try:
            owned = _take_secret(value)
            reference = (
                _validate_identifier(tenant_id),
                _validate_identifier(key_id),
            )
            prepared = True
        finally:
            del tenant_id, key_id, value
            if not prepared:
                _wipe(owned)
        if owned is None or reference is None:
            raise KeyStoreUnavailable() from None
        previous: bytearray | None = None
        transferred = False
        try:
            self._clear_if_forked()
            with self._lock:
                self._require_open()
                previous = self._entries.get(reference)
                self._entries[reference] = owned
                transferred = True
        finally:
            _wipe(previous)
            if not transferred:
                _wipe(owned)

    def delete(self, *, tenant_id: str, key_id: str) -> None:
        """Remove and erase one key without revealing whether identifiers leak."""

        reference: tuple[str, str]
        try:
            reference = (
                _validate_identifier(tenant_id),
                _validate_identifier(key_id),
            )
        finally:
            del tenant_id, key_id
        self._clear_if_forked()
        removed: bytearray | None = None
        with self._lock:
            self._require_open()
            removed = self._entries.pop(reference, None)
            if removed is None:
                raise KeyNotFound() from None
        _wipe(removed)

    def close(self) -> None:
        """Idempotently erase every stored secret."""

        try:
            self._clear_if_forked()
            with self._lock:
                if self._closed:
                    return
                entries = tuple(self._entries.values())
                leases = tuple(self._leases)
                self._entries.clear()
                self._leases.clear()
                object.__setattr__(self, "_closed", True)
            for value in entries:
                _wipe(value)
            for lease in leases:
                lease._invalidate()
        except Exception:
            # Finalization must remain safe even for a partially initialized
            # object or a failed process-identity lookup.
            try:
                entries = tuple(self._entries.values())
                leases = tuple(self._leases)
                self._entries.clear()
                self._leases.clear()
                object.__setattr__(self, "_closed", True)
                for value in entries:
                    _wipe(value)
                for lease in leases:
                    lease._invalidate()
            except Exception:
                pass

    def __enter__(self) -> Self:
        self._clear_if_forked()
        with self._lock:
            self._require_open()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def __str__(self) -> str:
        return "EphemeralKeyStore(testing_only=True)"

    def __repr__(self) -> str:
        closed = True
        try:
            closed = self.closed
        except Exception:
            pass
        return f"EphemeralKeyStore(testing_only=True, closed={closed})"

    def __copy__(self) -> Self:
        raise TypeError("Key stores cannot be copied.")

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        raise TypeError("Key stores cannot be copied.")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("Key stores cannot be serialized.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("Key stores cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Key stores cannot be serialized.")

    def __del__(self) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class _BuiltinBackendSpec:
    """Source-reviewed package-owned backend declaration."""

    backend_type: type[object]
    backend_id: str
    factory: Callable[..., object]


# Production backends are added only by a reviewed source change that declares
# an exact concrete type and package-owned factory here. Version 1 deliberately
# ships no OS-backed Python implementation, so no injected object is accepted.
# This is not a sandbox against arbitrary code already executing in-process:
# such code can monkeypatch Python internals and is part of the trusted process.
_BUILTIN_BACKEND_SPECS: Mapping[type[object], _BuiltinBackendSpec] = MappingProxyType(
    {}
)


def _annotation_matches(value: object, expected: type[object] | None) -> bool:
    try:
        if expected is None:
            return value is None or value is type(None) or value == "None"
        return value is expected or value == expected.__name__
    except Exception:
        return False


def _validated_bound_method(
    backend: object,
    name: str,
    parameters: tuple[tuple[str, type[object]], ...],
    return_type: type[object] | None,
) -> Callable[..., object] | None:
    try:
        descriptor = inspect.getattr_static(type(backend), name)
        if not inspect.isfunction(descriptor) or inspect.iscoroutinefunction(
            descriptor
        ):
            return None
        bound = object.__getattribute__(backend, name)
        if (
            not inspect.ismethod(bound)
            or bound.__self__ is not backend
            or bound.__func__ is not descriptor
        ):
            return None
        signature = inspect.signature(bound, follow_wrapped=False)
        actual = tuple(signature.parameters.values())
    except Exception:
        return None
    if len(actual) != len(parameters):
        return None
    for parameter, (expected_name, expected_type) in zip(
        actual, parameters, strict=True
    ):
        if (
            parameter.name != expected_name
            or parameter.kind is not inspect.Parameter.KEYWORD_ONLY
            or parameter.default is not inspect.Parameter.empty
            or not _annotation_matches(parameter.annotation, expected_type)
        ):
            return None
    if not _annotation_matches(signature.return_annotation, return_type):
        return None
    return cast(Callable[..., object], bound)


def _validated_backend_methods(
    backend: object,
) -> tuple[Callable[..., object], Callable[..., object], Callable[..., object]] | None:
    identifier_parameters = (("tenant_id", str), ("key_id", str))
    load = _validated_bound_method(
        backend,
        "load",
        identifier_parameters,
        bytearray,
    )
    store = _validated_bound_method(
        backend,
        "store",
        (*identifier_parameters, ("value", bytearray)),
        None,
    )
    delete = _validated_bound_method(
        backend,
        "delete",
        identifier_parameters,
        None,
    )
    if load is None or store is None or delete is None:
        return None
    return load, store, delete


def _invoke_backend(
    method: Callable[..., object],
    **kwargs: object,
) -> tuple[str, object | None]:
    """Invoke behind a non-propagating frame so raw backend failures disappear."""

    try:
        result = method(**kwargs)
    except KeyNotFound:
        return "not_found", None
    except KeyStoreCorrupt:
        return "corrupt", None
    except KeyStoreUnavailable:
        return "unavailable", None
    except Exception:
        return "unavailable", None
    try:
        awaitable = inspect.isawaitable(result)
    except Exception:
        awaitable = True
    if awaitable:
        try:
            close = getattr(result, "close", None)
            if callable(close):
                close()
        except Exception:
            pass
        del result
        return "invalid", None
    return "ok", result


def _raise_backend_status(status: str) -> None:
    if status == "not_found":
        raise KeyNotFound() from None
    if status == "corrupt" or status == "invalid":
        raise KeyStoreCorrupt() from None
    raise KeyStoreUnavailable() from None


def _take_backend_secret(value: object) -> bytearray | None:
    """Copy and erase mutable backend output without propagating failures."""

    if type(value) is not bytearray:
        del value
        return None
    source = value
    del value
    copied: bytearray | None = None
    try:
        if 0 < len(source) <= _MAX_SECRET_BYTES:
            copied = bytearray(source)
            if len(copied) != len(source):
                _wipe(copied)
                copied = None
    except Exception:
        _wipe(copied)
        copied = None
    finally:
        _wipe(source)
    return copied


class _ValidatedKeyStore:
    """PID-bound mediator for one source-reviewed raw backend."""

    __slots__ = (
        "_backend",
        "_capabilities",
        "_delete_method",
        "_load_method",
        "_lock",
        "_owner_pid",
        "_store_method",
    )

    _backend: object
    _capabilities: Mapping[str, bool | str]
    _delete_method: Callable[..., object]
    _load_method: Callable[..., object]
    _lock: threading.RLock
    _owner_pid: int
    _store_method: Callable[..., object]

    def __init__(
        self,
        backend: object,
        *,
        backend_id: str,
        methods: tuple[
            Callable[..., object],
            Callable[..., object],
            Callable[..., object],
        ],
        owner_pid: int,
    ) -> None:
        object.__setattr__(self, "_backend", backend)
        object.__setattr__(self, "_owner_pid", owner_pid)
        object.__setattr__(self, "_load_method", methods[0])
        object.__setattr__(self, "_store_method", methods[1])
        object.__setattr__(self, "_delete_method", methods[2])
        object.__setattr__(self, "_lock", threading.RLock())
        object.__setattr__(
            self,
            "_capabilities",
            MappingProxyType(
                {
                    "backend": backend_id,
                    "fork_behavior": "reject",
                    "os_backed": True,
                    "persistent": True,
                    "process_local": False,
                    "production_ready": True,
                    "testing_only": False,
                }
            ),
        )

    @property
    def capabilities(self) -> Mapping[str, bool | str]:
        return self._capabilities

    def _require_owner(self) -> None:
        try:
            owner_matches = os.getpid() == self._owner_pid
        except Exception:
            owner_matches = False
        if not owner_matches:
            raise KeyStoreUnavailable() from None

    def load(
        self,
        *,
        tenant_id: str,
        key_id: str,
    ) -> AbstractContextManager[_SecretLease]:
        reference: tuple[str, str]
        try:
            reference = (
                _validate_identifier(tenant_id),
                _validate_identifier(key_id),
            )
        finally:
            del tenant_id, key_id
        self._require_owner()
        with self._lock:
            status, result = _invoke_backend(
                self._load_method,
                tenant_id=reference[0],
                key_id=reference[1],
            )
        if status != "ok":
            del result
            _raise_backend_status(status)
        secret = _take_backend_secret(result)
        del result
        if secret is None:
            raise KeyStoreCorrupt() from None
        try:
            return _SecretLease(secret)
        except Exception:
            _wipe(secret)
            raise KeyStoreUnavailable() from None

    def store(
        self,
        *,
        tenant_id: str,
        key_id: str,
        value: bytearray,
    ) -> None:
        owned: bytearray | None = None
        reference: tuple[str, str] | None = None
        prepared = False
        try:
            owned = _take_secret(value)
            reference = (
                _validate_identifier(tenant_id),
                _validate_identifier(key_id),
            )
            prepared = True
        finally:
            del tenant_id, key_id, value
            if not prepared:
                _wipe(owned)
        if owned is None or reference is None:
            raise KeyStoreUnavailable() from None

        status = "unavailable"
        result: object | None = None
        try:
            self._require_owner()
            with self._lock:
                status, result = _invoke_backend(
                    self._store_method,
                    tenant_id=reference[0],
                    key_id=reference[1],
                    value=owned,
                )
        finally:
            _wipe(owned)
        if status != "ok":
            del result
            _raise_backend_status(status)
        if result is not None:
            del result
            raise KeyStoreCorrupt() from None

    def delete(self, *, tenant_id: str, key_id: str) -> None:
        reference: tuple[str, str]
        try:
            reference = (
                _validate_identifier(tenant_id),
                _validate_identifier(key_id),
            )
        finally:
            del tenant_id, key_id
        self._require_owner()
        with self._lock:
            status, result = _invoke_backend(
                self._delete_method,
                tenant_id=reference[0],
                key_id=reference[1],
            )
        if status != "ok":
            del result
            _raise_backend_status(status)
        if result is not None:
            del result
            raise KeyStoreCorrupt() from None

    def __str__(self) -> str:
        return "_ValidatedKeyStore(backend=[BUILTIN])"

    def __repr__(self) -> str:
        return "_ValidatedKeyStore(backend=[BUILTIN])"

    def __copy__(self) -> Self:
        raise TypeError("Key stores cannot be copied.")

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        raise TypeError("Key stores cannot be copied.")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("Key stores cannot be serialized.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("Key stores cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Key stores cannot be serialized.")


def _require_production_key_store(store: object | None) -> KeyStore:
    """Return a mediator only for a source-reviewed built-in backend type."""

    if store is None:
        raise KeyStoreUnavailable() from None
    specification = _BUILTIN_BACKEND_SPECS.get(type(store))
    if specification is None or type(store) is not specification.backend_type:
        raise KeyStoreUnavailable() from None
    methods = _validated_backend_methods(store)
    if methods is None:
        raise KeyStoreUnavailable() from None
    try:
        owner_pid = os.getpid()
    except Exception:
        raise KeyStoreUnavailable() from None
    return _ValidatedKeyStore(
        store,
        backend_id=specification.backend_id,
        methods=methods,
        owner_pid=owner_pid,
    )


__all__ = [
    "EphemeralKeyStore",
    "InvalidKeyIdentifier",
    "InvalidKeyMaterial",
    "KeyNotFound",
    "KeyStore",
    "KeyStoreClosed",
    "KeyStoreCorrupt",
    "KeyStoreError",
    "KeyStoreUnavailable",
]
