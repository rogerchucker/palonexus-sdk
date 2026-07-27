# SPDX-License-Identifier: MIT
"""Secure, explicit key-store boundary contracts."""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import gc
import inspect
import multiprocessing
import os
import pickle
import traceback
import weakref
from collections.abc import Mapping
from typing import Any, cast

import palonexus
import pytest
from palonexus import (
    EphemeralKeyStore,
    InvalidKeyIdentifier,
    InvalidKeyMaterial,
    KeyNotFound,
    KeyStore,
    KeyStoreClosed,
    KeyStoreCorrupt,
    KeyStoreError,
    KeyStoreUnavailable,
)
from palonexus.keystore import (
    _BUILTIN_BACKEND_SPECS,
    _require_production_key_store,
    _validated_backend_methods,
    _ValidatedKeyStore,
)

SECRET = b"synthetic-key-material-9fG2kP7mQ4vX8zL1"
OTHER_SECRET = b"synthetic-other-material-3mN8rT6wY2pK5jH9"
TENANT = "tenant-01J5ABCDEFGHJKMNPQRSTVWXY0"
KEY_ID = "agent-signing-key.v1"


def _load_bytes(store: KeyStore, *, tenant_id: str, key_id: str) -> bytes:
    with store.load(tenant_id=tenant_id, key_id=key_id) as value:
        return value.copy_bytes()


def _store_and_load(
    store: EphemeralKeyStore,
    tenant_id: str,
    key_id: str,
    value: bytes,
) -> bytes:
    owned = bytearray(value)
    store.store(tenant_id=tenant_id, key_id=key_id, value=owned)
    assert owned == bytearray(len(value))
    return _load_bytes(store, tenant_id=tenant_id, key_id=key_id)


def _fork_child_probe(store: EphemeralKeyStore, connection: Any) -> None:
    try:
        store.load(tenant_id=TENANT, key_id=KEY_ID)
    except KeyNotFound:
        connection.send(("cleared", repr(store)))
    except Exception as exc:  # pragma: no cover - reported to the parent
        connection.send(("unsafe", type(exc).__name__))
    else:  # pragma: no cover - reported to the parent
        connection.send(("retained", "unexpected"))
    finally:
        connection.close()


def _fork_child_lease_probe(lease: Any, connection: Any) -> None:
    initially_closed = lease.closed
    try:
        lease.copy_bytes()
    except KeyStoreClosed:
        connection.send(("closed", initially_closed, repr(lease)))
    except Exception as exc:  # pragma: no cover - reported to the parent
        connection.send(("unsafe", initially_closed, type(exc).__name__))
    else:  # pragma: no cover - reported to the parent
        connection.send(("readable", initially_closed, "unexpected"))
    finally:
        connection.close()


class _RawBackend:
    """Synthetic raw backend used only through the direct test mediator."""

    def __init__(self, *, mode: str = "ok") -> None:
        self.mode = mode
        self.stored: dict[tuple[str, str], bytearray] = {}
        self.last_input: bytearray | None = None

    def load(self, *, tenant_id: str, key_id: str) -> bytearray:
        if self.mode == "wrong_load_type":
            return cast(Any, bytes(SECRET))
        try:
            return bytearray(self.stored[(tenant_id, key_id)])
        except KeyError:
            raise KeyNotFound() from None

    def store(
        self,
        *,
        tenant_id: str,
        key_id: str,
        value: bytearray,
    ) -> None:
        self.last_input = value
        if self.mode == "false_success":
            return cast(Any, "success")
        if self.mode == "partial_failure":
            value[0] = 0
            raise RuntimeError(SECRET.decode())
        self.stored[(tenant_id, key_id)] = bytearray(value)

    def delete(self, *, tenant_id: str, key_id: str) -> None:
        try:
            value = self.stored.pop((tenant_id, key_id))
        except KeyError:
            raise KeyNotFound() from None
        for index in range(len(value)):
            value[index] = 0


class _AsyncRawBackend:
    async def load(self, *, tenant_id: str, key_id: str) -> bytearray:
        del tenant_id, key_id
        return bytearray(SECRET)

    async def store(
        self,
        *,
        tenant_id: str,
        key_id: str,
        value: bytearray,
    ) -> None:
        del tenant_id, key_id, value

    async def delete(self, *, tenant_id: str, key_id: str) -> None:
        del tenant_id, key_id


class _WrongSignatureBackend:
    def load(self, tenant_id: str, key_id: str) -> bytearray:
        del tenant_id, key_id
        return bytearray(SECRET)

    def store(self, tenant_id: str, key_id: str, value: bytearray) -> None:
        del tenant_id, key_id, value

    def delete(self, tenant_id: str, key_id: str) -> None:
        del tenant_id, key_id


class _VariadicBackend:
    def load(self, *args: object, **kwargs: object) -> bytearray:
        del args, kwargs
        return bytearray(SECRET)

    def store(self, *args: object, **kwargs: object) -> None:
        del args, kwargs

    def delete(self, *args: object, **kwargs: object) -> None:
        del args, kwargs


class _MissingMethodBackend:
    def load(self, *, tenant_id: str, key_id: str) -> bytearray:
        del tenant_id, key_id
        return bytearray(SECRET)

    def store(
        self,
        *,
        tenant_id: str,
        key_id: str,
        value: bytearray,
    ) -> None:
        del tenant_id, key_id, value


class _HostileAnnotation:
    def __eq__(self, other: object) -> bool:
        del other
        raise RuntimeError(SECRET.decode())


class _HostileAnnotationBackend(_RawBackend):
    def load(self, *, tenant_id: str, key_id: str) -> bytearray:
        return super().load(tenant_id=tenant_id, key_id=key_id)


_HostileAnnotationBackend.load.__annotations__["return"] = _HostileAnnotation()


class _ExplosiveDescriptor:
    calls = 0

    def __get__(self, instance: object, owner: type[object]) -> object:
        del instance, owner
        type(self).calls += 1
        raise RuntimeError(SECRET.decode())


class _DescriptorBackend:
    load = _ExplosiveDescriptor()

    def store(
        self,
        *,
        tenant_id: str,
        key_id: str,
        value: bytearray,
    ) -> None:
        del tenant_id, key_id, value

    def delete(self, *, tenant_id: str, key_id: str) -> None:
        del tenant_id, key_id


def _mediated_backend(
    backend_type: type[Any],
    /,
    *args: object,
    **kwargs: object,
) -> tuple[Any, Any]:
    backend = backend_type(*args, **kwargs)
    methods = _validated_backend_methods(backend)
    assert methods is not None
    mediated = _ValidatedKeyStore(
        backend,
        backend_id=f"test-{backend_type.__name__.lower()}",
        methods=methods,
        owner_pid=os.getpid(),
    )
    return backend, mediated


def _key_store_traceback_locals(exc: BaseException) -> str:
    diagnostics: list[str] = []
    for frame, _ in traceback.walk_tb(exc.__traceback__):
        if frame.f_code.co_filename.endswith("/palonexus/keystore.py"):
            for value in frame.f_locals.values():
                try:
                    diagnostics.append(repr(value))
                except Exception:
                    diagnostics.append("[UNPRINTABLE]")
    return " ".join(diagnostics)


def test_public_api_exports_only_the_approved_key_store_boundary() -> None:
    approved = {
        "EphemeralKeyStore",
        "InvalidKeyIdentifier",
        "InvalidKeyMaterial",
        "KeyNotFound",
        "KeyStore",
        "KeyStoreClosed",
        "KeyStoreCorrupt",
        "KeyStoreError",
        "KeyStoreUnavailable",
    }

    assert approved <= set(palonexus.__all__)
    assert not hasattr(palonexus, "AsyncKeyStore")
    assert not hasattr(palonexus, "default_key_store")
    assert not hasattr(palonexus, "SecretValue")


def test_key_store_is_a_static_synchronous_protocol() -> None:
    store: KeyStore = EphemeralKeyStore(testing_only=True)

    with pytest.raises(TypeError):
        isinstance(store, KeyStore)
    assert not inspect.iscoroutinefunction(KeyStore.load)
    assert not inspect.iscoroutinefunction(KeyStore.store)
    assert not inspect.iscoroutinefunction(KeyStore.delete)
    assert list(inspect.signature(KeyStore.load).parameters) == [
        "self",
        "tenant_id",
        "key_id",
    ]
    assert list(inspect.signature(KeyStore.store).parameters) == [
        "self",
        "tenant_id",
        "key_id",
        "value",
    ]


def test_ephemeral_store_requires_an_explicit_testing_only_opt_in() -> None:
    for value in (None, False, 1, "true"):
        kwargs = {} if value is None else {"testing_only": value}
        with pytest.raises(KeyStoreUnavailable) as caught:
            EphemeralKeyStore(**kwargs)  # type: ignore[arg-type]
        assert caught.value.code == "key_store_unavailable"
        assert caught.value.__cause__ is None

    store = EphemeralKeyStore(testing_only=True)
    assert repr(store) == "EphemeralKeyStore(testing_only=True, closed=False)"
    assert str(store) == "EphemeralKeyStore(testing_only=True)"


def test_capabilities_identify_a_process_local_nonproduction_backend() -> None:
    store = EphemeralKeyStore(testing_only=True)
    capabilities = store.capabilities

    assert isinstance(capabilities, Mapping)
    assert capabilities == {
        "backend": "ephemeral-memory",
        "fork_behavior": "clear",
        "os_backed": False,
        "persistent": False,
        "process_local": True,
        "production_ready": False,
        "testing_only": True,
    }
    with pytest.raises(TypeError):
        capabilities["production_ready"] = True  # type: ignore[index]


def test_store_transfers_ownership_and_load_returns_an_opaque_lease() -> None:
    store = EphemeralKeyStore(testing_only=True)
    source = bytearray(SECRET)

    store.store(tenant_id=TENANT, key_id=KEY_ID, value=source)

    assert source == bytearray(len(SECRET))
    lease = store.load(tenant_id=TENANT, key_id=KEY_ID)
    diagnostics = f"{lease!s} {lease!r}"
    assert SECRET.decode() not in diagnostics
    assert TENANT not in diagnostics
    assert KEY_ID not in diagnostics
    assert not isinstance(lease, memoryview)
    assert not hasattr(lease, "obj")
    assert not hasattr(lease, "__bytes__")
    for operation in (
        lambda: copy.copy(lease),
        lambda: copy.deepcopy(lease),
        lambda: pickle.dumps(lease),
    ):
        with pytest.raises(TypeError):
            operation()

    internal = lease._buffer  # noqa: SLF001
    with lease as opened:
        assert opened is lease
        copied = opened.copy_bytes()
        assert type(copied) is bytes
        assert copied == SECRET
        with pytest.raises(TypeError):
            copied[0] = 0  # type: ignore[index]
    assert internal == bytearray(len(SECRET))
    del copied
    with pytest.raises(KeyStoreClosed):
        lease.__enter__()
    with pytest.raises(KeyStoreClosed):
        lease.copy_bytes()


def test_tenant_scope_prevents_identical_key_ids_from_colliding() -> None:
    store = EphemeralKeyStore(testing_only=True)

    assert _store_and_load(store, "tenant-alpha", KEY_ID, SECRET) == SECRET
    assert _store_and_load(store, "tenant-beta", KEY_ID, OTHER_SECRET) == OTHER_SECRET
    assert _load_bytes(store, tenant_id="tenant-alpha", key_id=KEY_ID) == SECRET


@pytest.mark.parametrize(
    ("tenant_id", "key_id"),
    [
        ("", KEY_ID),
        (" tenant", KEY_ID),
        ("tenant/other", KEY_ID),
        ("tenant..other", KEY_ID),
        ("tenant\u202eother", KEY_ID),
        ("a" * 129, KEY_ID),
        (TENANT, ""),
        (TENANT, "../private"),
        (TENANT, "key/name"),
        (TENANT, "key..name"),
        (TENANT, "key\nname"),
        (TENANT, "a" * 129),
        (1, KEY_ID),
        (TENANT, 1),
    ],
)
def test_identifiers_are_bounded_ascii_and_path_safe(
    tenant_id: object,
    key_id: object,
) -> None:
    store = EphemeralKeyStore(testing_only=True)
    source = bytearray(SECRET)

    with pytest.raises(InvalidKeyIdentifier) as caught:
        store.store(  # type: ignore[arg-type]
            tenant_id=tenant_id,
            key_id=key_id,
            value=source,
        )

    assert source == bytearray(len(SECRET))
    assert caught.value.code == "invalid_key_identifier"
    assert SECRET.decode() not in str(caught.value)
    assert repr(tenant_id) not in str(caught.value)
    assert caught.value.__cause__ is None


@pytest.mark.parametrize(
    "value",
    [
        b"immutable",
        memoryview(b"view"),
        bytearray(),
        bytearray(65_537),
        "text",
        None,
    ],
)
def test_key_material_is_mutable_nonempty_and_bounded(value: object) -> None:
    store = EphemeralKeyStore(testing_only=True)

    with pytest.raises(InvalidKeyMaterial) as caught:
        store.store(  # type: ignore[arg-type]
            tenant_id=TENANT,
            key_id=KEY_ID,
            value=value,
        )

    assert caught.value.code == "invalid_key_material"
    assert SECRET.decode() not in str(caught.value)
    if type(value) is bytearray:
        assert value == bytearray(len(value))  # type: ignore[arg-type]


def test_missing_unavailable_and_corrupt_are_distinct_safe_failures() -> None:
    missing_store = EphemeralKeyStore(testing_only=True)
    with pytest.raises(KeyNotFound) as missing:
        missing_store.load(tenant_id=TENANT, key_id=KEY_ID)

    corrupt_store = EphemeralKeyStore(testing_only=True)
    _store_and_load(corrupt_store, TENANT, KEY_ID, SECRET)
    corrupt_buffer = corrupt_store._entries[(TENANT, KEY_ID)]  # noqa: SLF001
    corrupt_buffer.clear()
    with pytest.raises(KeyStoreCorrupt) as corrupt:
        corrupt_store.load(tenant_id=TENANT, key_id=KEY_ID)

    with pytest.raises(KeyStoreUnavailable) as unavailable:
        _require_production_key_store(None)

    failures = [missing.value, corrupt.value, unavailable.value]
    assert all(isinstance(failure, KeyStoreError) for failure in failures)
    assert [failure.code for failure in failures] == [
        "key_not_found",
        "key_store_corrupt",
        "key_store_unavailable",
    ]
    assert len({type(failure) for failure in failures}) == 3
    for failure in failures:
        diagnostics = f"{failure!s} {failure!r}"
        assert TENANT not in diagnostics
        assert KEY_ID not in diagnostics
        assert SECRET.decode() not in diagnostics
        assert failure.__cause__ is None


def test_failed_operations_do_not_retain_secrets_in_traceback_frames() -> None:
    immutable_secret = bytes(SECRET)
    store = EphemeralKeyStore(testing_only=True)
    with pytest.raises(InvalidKeyMaterial) as immutable:
        store.store(
            tenant_id=TENANT,
            key_id=KEY_ID,
            value=immutable_secret,  # type: ignore[arg-type]
        )

    malformed_identifier = f"../{SECRET.decode()}"
    transferred = bytearray(OTHER_SECRET)
    with pytest.raises(InvalidKeyIdentifier) as invalid:
        store.store(
            tenant_id=malformed_identifier,
            key_id=KEY_ID,
            value=transferred,
        )
    assert transferred == bytearray(len(OTHER_SECRET))

    store._entries[(TENANT, KEY_ID)] = bytes(SECRET)  # type: ignore[assignment]  # noqa: SLF001
    with pytest.raises(KeyStoreCorrupt) as corrupt:
        store.load(tenant_id=TENANT, key_id=KEY_ID)

    for caught in (immutable, invalid, corrupt):
        diagnostics = _key_store_traceback_locals(caught.value)
        assert SECRET.decode() not in diagnostics
        assert OTHER_SECRET.decode() not in diagnostics


def test_production_resolution_has_no_plaintext_or_ephemeral_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise AssertionError("production key-store resolution touched ambient state")

    monkeypatch.setattr("builtins.open", forbidden)
    monkeypatch.setattr(os, "getenv", forbidden)

    with pytest.raises(KeyStoreUnavailable):
        _require_production_key_store(None)
    with pytest.raises(KeyStoreUnavailable):
        _require_production_key_store(EphemeralKeyStore(testing_only=True))

    assert "open" not in inspect.getsource(_require_production_key_store)
    assert "environ" not in inspect.getsource(_require_production_key_store)
    assert "getenv" not in inspect.getsource(_require_production_key_store)
    assert "generate" not in inspect.getsource(_require_production_key_store)


def test_production_resolution_rejects_forged_capabilities_and_raw_instances() -> None:
    class ForgedStore(_RawBackend):
        capabilities = {
            "backend": "forged-os-keychain",
            "fork_behavior": "reopen",
            "os_backed": True,
            "persistent": True,
            "process_local": False,
            "production_ready": True,
            "testing_only": False,
        }

    with pytest.raises(KeyStoreUnavailable):
        _require_production_key_store(ForgedStore())

    with pytest.raises(KeyStoreUnavailable):
        _require_production_key_store(_RawBackend())


def test_production_backend_allowlist_is_closed_empty_and_immutable() -> None:
    assert _BUILTIN_BACKEND_SPECS == {}
    with pytest.raises(TypeError):
        _BUILTIN_BACKEND_SPECS[_RawBackend] = object()  # type: ignore[index]
    assert "same-process" in inspect.getdoc(KeyStore).lower()
    assert "source-reviewed" in inspect.getdoc(_require_production_key_store).lower()


@pytest.mark.parametrize(
    "backend_type",
    [
        _AsyncRawBackend,
        _WrongSignatureBackend,
        _VariadicBackend,
        _MissingMethodBackend,
        _HostileAnnotationBackend,
    ],
)
def test_production_resolution_rejects_async_and_deceptive_signatures(
    backend_type: type[Any],
) -> None:
    constructed = backend_type()
    assert _validated_backend_methods(constructed) is None
    with pytest.raises(KeyStoreUnavailable) as caught:
        _require_production_key_store(constructed)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_signature_validation_does_not_execute_untrusted_descriptors() -> None:
    _ExplosiveDescriptor.calls = 0
    constructed = _DescriptorBackend()
    assert _validated_backend_methods(constructed) is None
    assert _ExplosiveDescriptor.calls == 0
    with pytest.raises(KeyStoreUnavailable):
        _require_production_key_store(constructed)


def test_production_mediator_is_owner_process_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, store = _mediated_backend(_RawBackend)
    owner_pid = os.getpid()
    monkeypatch.setattr("palonexus.keystore.os.getpid", lambda: owner_pid + 1)
    source = bytearray(SECRET)
    with pytest.raises(KeyStoreUnavailable):
        store.store(tenant_id=TENANT, key_id=KEY_ID, value=source)
    assert source == bytearray(len(SECRET))


def test_mediated_production_store_enforces_types_and_ownership_transfer() -> None:
    raw, store = _mediated_backend(_RawBackend)
    source = bytearray(SECRET)
    store.store(tenant_id=TENANT, key_id=KEY_ID, value=source)
    assert source == bytearray(len(SECRET))
    assert raw.last_input == bytearray(len(SECRET))
    assert _load_bytes(store, tenant_id=TENANT, key_id=KEY_ID) == SECRET
    store.delete(tenant_id=TENANT, key_id=KEY_ID)
    with pytest.raises(KeyNotFound):
        store.load(tenant_id=TENANT, key_id=KEY_ID)


@pytest.mark.parametrize(
    ("mode", "expected_error"),
    [
        ("false_success", KeyStoreCorrupt),
        ("partial_failure", KeyStoreUnavailable),
    ],
)
def test_mediated_store_wipes_backend_input_on_false_success_or_partial_failure(
    mode: str,
    expected_error: type[KeyStoreError],
) -> None:
    raw, store = _mediated_backend(_RawBackend, mode=mode)
    source = bytearray(SECRET)
    with pytest.raises(expected_error) as caught:
        store.store(tenant_id=TENANT, key_id=KEY_ID, value=source)

    assert source == bytearray(len(SECRET))
    assert raw.last_input == bytearray(len(SECRET))
    diagnostics = f"{caught.value!s} {caught.value!r}"
    assert SECRET.decode() not in diagnostics
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_mediated_load_rejects_nonmutable_backend_results() -> None:
    _, store = _mediated_backend(_RawBackend, mode="wrong_load_type")
    with pytest.raises(KeyStoreCorrupt) as caught:
        store.load(tenant_id=TENANT, key_id=KEY_ID)
    assert SECRET.decode() not in str(caught.value)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None


def test_replace_delete_and_close_zeroize_internal_buffers() -> None:
    store = EphemeralKeyStore(testing_only=True)
    first_source = bytearray(SECRET)
    store.store(tenant_id=TENANT, key_id=KEY_ID, value=first_source)
    first_internal = store._entries[(TENANT, KEY_ID)]  # noqa: SLF001

    second_source = bytearray(OTHER_SECRET)
    store.store(tenant_id=TENANT, key_id=KEY_ID, value=second_source)
    second_internal = store._entries[(TENANT, KEY_ID)]  # noqa: SLF001
    assert first_internal == bytearray(len(SECRET))
    assert _load_bytes(store, tenant_id=TENANT, key_id=KEY_ID) == OTHER_SECRET

    store.delete(tenant_id=TENANT, key_id=KEY_ID)
    assert second_internal == bytearray(len(OTHER_SECRET))
    with pytest.raises(KeyNotFound):
        store.delete(tenant_id=TENANT, key_id=KEY_ID)

    third_source = bytearray(SECRET)
    store.store(tenant_id=TENANT, key_id=KEY_ID, value=third_source)
    third_internal = store._entries[(TENANT, KEY_ID)]  # noqa: SLF001
    store.close()
    assert third_internal == bytearray(len(SECRET))
    assert store.closed
    assert repr(store) == "EphemeralKeyStore(testing_only=True, closed=True)"
    store.close()


def test_closed_store_fails_safely_and_still_wipes_transferred_input() -> None:
    store = EphemeralKeyStore(testing_only=True)
    store.close()
    source = bytearray(SECRET)

    with pytest.raises(KeyStoreClosed):
        store.store(tenant_id=TENANT, key_id=KEY_ID, value=source)
    assert source == bytearray(len(SECRET))
    with pytest.raises(KeyStoreClosed):
        store.load(tenant_id=TENANT, key_id=KEY_ID)
    with pytest.raises(KeyStoreClosed):
        store.delete(tenant_id=TENANT, key_id=KEY_ID)


def test_closing_store_invalidates_every_active_lease() -> None:
    store = EphemeralKeyStore(testing_only=True)
    _store_and_load(store, TENANT, KEY_ID, SECRET)
    first = store.load(tenant_id=TENANT, key_id=KEY_ID)
    second = store.load(tenant_id=TENANT, key_id=KEY_ID)
    first_internal = first._buffer  # noqa: SLF001
    second_internal = second._buffer  # noqa: SLF001

    store.close()

    assert first.closed and second.closed
    assert first_internal == bytearray(len(SECRET))
    assert second_internal == bytearray(len(SECRET))
    with pytest.raises(KeyStoreClosed):
        first.copy_bytes()
    with pytest.raises(KeyStoreClosed):
        second.copy_bytes()


@pytest.mark.parametrize(
    "error_type",
    [
        KeyStoreError,
        InvalidKeyIdentifier,
        InvalidKeyMaterial,
        KeyNotFound,
        KeyStoreUnavailable,
        KeyStoreCorrupt,
        KeyStoreClosed,
    ],
)
def test_key_store_errors_are_immutable_copy_and_pickle_safe(
    error_type: type[KeyStoreError],
) -> None:
    error = error_type()

    restored = pickle.loads(pickle.dumps(error))

    assert type(restored) is error_type
    assert restored.code == error.code
    assert restored.message == error.message
    assert restored.args == (error.code, error.message)
    assert error.__cause__ is None
    assert error.__context__ is None
    assert restored.__cause__ is None
    assert restored.__context__ is None
    assert copy.copy(error) is error
    assert copy.deepcopy(error) is error
    for name, value in (
        ("code", SECRET.decode()),
        ("message", SECRET.decode()),
        ("args", (SECRET.decode(),)),
        ("provider", SECRET.decode()),
    ):
        with pytest.raises(AttributeError):
            setattr(error, name, value)
    diagnostics = f"{restored!s} {restored!r} {restored.args!r}"
    assert SECRET.decode() not in diagnostics


def test_store_is_not_copyable_or_serializable() -> None:
    store = EphemeralKeyStore(testing_only=True)
    _store_and_load(store, TENANT, KEY_ID, SECRET)

    for operation in (
        lambda: copy.copy(store),
        lambda: copy.deepcopy(store),
        lambda: pickle.dumps(store),
    ):
        with pytest.raises(TypeError) as caught:
            operation()
        assert SECRET.decode() not in str(caught.value)


def test_store_is_thread_safe() -> None:
    store = EphemeralKeyStore(testing_only=True)
    inputs = [
        (f"tenant-{index}", f"key-{index}", f"secret-{index}".encode())
        for index in range(64)
    ]

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda item: _store_and_load(store, *item),
                inputs,
            )
        )

    assert results == [item[2] for item in inputs]


def test_sync_store_has_an_explicit_safe_async_boundary() -> None:
    store = EphemeralKeyStore(testing_only=True)

    async def exercise() -> list[bytes]:
        coroutines = [
            asyncio.to_thread(
                _store_and_load,
                store,
                f"async-tenant-{index}",
                f"key-{index}",
                f"async-secret-{index}".encode(),
            )
            for index in range(32)
        ]
        return await asyncio.gather(*coroutines)

    assert asyncio.run(exercise()) == [
        f"async-secret-{index}".encode() for index in range(32)
    ]


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
def test_forked_child_clears_inherited_secrets_without_affecting_parent() -> None:
    store = EphemeralKeyStore(testing_only=True)
    _store_and_load(store, TENANT, KEY_ID, SECRET)
    context = multiprocessing.get_context("fork")
    parent_connection, child_connection = context.Pipe(duplex=False)
    process = context.Process(
        target=_fork_child_probe,
        args=(store, child_connection),
    )

    process.start()
    child_connection.close()
    outcome, diagnostics = parent_connection.recv()
    process.join(10)

    assert process.exitcode == 0
    assert outcome == "cleared"
    assert SECRET.decode() not in diagnostics
    assert _load_bytes(store, tenant_id=TENANT, key_id=KEY_ID) == SECRET


@pytest.mark.skipif(not hasattr(os, "fork"), reason="requires POSIX fork")
def test_forked_child_immediately_invalidates_open_leases() -> None:
    store = EphemeralKeyStore(testing_only=True)
    _store_and_load(store, TENANT, KEY_ID, SECRET)
    lease = store.load(tenant_id=TENANT, key_id=KEY_ID)
    assert lease.__enter__() is lease
    context = multiprocessing.get_context("fork")
    parent_connection, child_connection = context.Pipe(duplex=False)
    process = context.Process(
        target=_fork_child_lease_probe,
        args=(lease, child_connection),
    )

    process.start()
    child_connection.close()
    outcome, initially_closed, diagnostics = parent_connection.recv()
    process.join(10)

    assert process.exitcode == 0
    assert outcome == "closed"
    assert initially_closed is True
    assert SECRET.decode() not in diagnostics
    assert lease.copy_bytes() == SECRET
    lease.close()


def test_fork_registration_does_not_keep_stores_or_leases_alive() -> None:
    store = EphemeralKeyStore(testing_only=True)
    _store_and_load(store, TENANT, KEY_ID, SECRET)
    lease = store.load(tenant_id=TENANT, key_id=KEY_ID)
    store_reference = weakref.ref(store)
    lease_reference = weakref.ref(lease)

    del lease, store
    gc.collect()

    assert lease_reference() is None
    assert store_reference() is None


def test_context_manager_closes_and_erases_the_store() -> None:
    with EphemeralKeyStore(testing_only=True) as store:
        _store_and_load(store, TENANT, KEY_ID, SECRET)
        internal = store._entries[(TENANT, KEY_ID)]  # noqa: SLF001

    assert internal == bytearray(len(SECRET))
    assert store.closed
