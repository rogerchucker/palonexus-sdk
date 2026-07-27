# SPDX-License-Identifier: MIT
"""Fail-closed, traceback-safe credential acquisition boundaries."""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import math
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any, Protocol, Self, SupportsIndex, cast

from .errors import AuthenticationFailed

_MAX_TOKEN_BYTES = 8192


def _wall_now() -> datetime:
    """Trusted production wall clock; tests may monkeypatch this private seam."""

    return datetime.now(UTC)


def _monotonic_now() -> float:
    """Trusted production monotonic clock; tests may monkeypatch privately."""

    return time.monotonic()


class CredentialUnavailable(Exception):
    """No current credential could be acquired from the configured provider."""

    code = "credential_unavailable"

    def __init__(self) -> None:
        super().__init__(self.code, "A current credential is unavailable.")

    def __str__(self) -> str:
        return f"{self.code}: A current credential is unavailable."

    def __repr__(self) -> str:
        return "CredentialUnavailable()"


class CredentialAcquisitionCancelled(Exception):
    """Credential acquisition ended before a usable identity existed."""

    code = "credential_acquisition_cancelled"

    def __init__(self) -> None:
        super().__init__(self.code, "Credential acquisition was cancelled.")

    def __str__(self) -> str:
        return f"{self.code}: Credential acquisition was cancelled."

    def __repr__(self) -> str:
        return "CredentialAcquisitionCancelled()"


class InvalidCredentialDeadline(Exception):
    """The acquisition deadline is malformed or non-finite."""

    code = "invalid_deadline"

    def __init__(self) -> None:
        super().__init__(self.code, "The credential deadline is invalid.")

    def __str__(self) -> str:
        return f"{self.code}: The credential deadline is invalid."

    def __repr__(self) -> str:
        return "InvalidCredentialDeadline()"


def _seal_token(
    token: object,
    expires_at: object,
) -> tuple[bytearray, datetime] | None:
    """Validate raw credential input behind a non-propagating frame."""

    try:
        if type(token) is not str or type(expires_at) is not datetime:
            return None
        encoded = token.encode("ascii", errors="strict")
        if (
            not encoded
            or len(encoded) > _MAX_TOKEN_BYTES
            or any(byte <= 0x20 or byte >= 0x7F for byte in encoded)
            or expires_at.tzinfo is None
        ):
            return None
        normalized_expiry = expires_at.astimezone(UTC)
        return bytearray(encoded), normalized_expiry
    except Exception:
        return None


class Credential:
    """A short-lived bearer token with deliberately opaque diagnostics."""

    __slots__ = ("_closed", "_expires_at", "_token")

    _token: bytearray
    _expires_at: datetime
    _closed: bool

    def __init__(self, token: str, *, expires_at: datetime) -> None:
        sealed = _seal_token(token, expires_at)
        del token, expires_at
        if sealed is None:
            raise AuthenticationFailed() from None
        token_buffer, normalized_expiry = sealed
        del sealed
        object.__setattr__(self, "_token", token_buffer)
        object.__setattr__(self, "_expires_at", normalized_expiry)
        object.__setattr__(self, "_closed", False)

    @property
    def expires_at(self) -> datetime:
        """Return the non-secret UTC expiry time."""

        return self._expires_at

    @property
    def closed(self) -> bool:
        """Whether the secret buffer was erased."""

        return self._closed

    def authorization_header(self) -> str:
        """Unseal a current bearer header for immediate transport use."""

        failed = False
        try:
            failed = self._closed or _wall_now() >= self._expires_at
        except Exception:
            failed = True
        if failed:
            self.close()
            raise AuthenticationFailed() from None

        value = ""
        try:
            value = self._token.decode("ascii", errors="strict")
        except Exception:
            pass
        if not value:
            self.close()
            raise AuthenticationFailed() from None
        return f"Bearer {value}"

    def close(self) -> None:
        """Best-effort erase the mutable token buffer."""

        try:
            if self._closed:
                return
            for index in range(len(self._token)):
                self._token[index] = 0
            object.__setattr__(self, "_closed", True)
        except Exception:
            # A partially constructed object has no usable token to expose.
            pass

    def __enter__(self) -> Self:
        if self._closed:
            raise AuthenticationFailed() from None
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        del exc_type, exc_value, traceback
        self.close()

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("Credential state is immutable.")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("Credential state is immutable.")

    def __str__(self) -> str:
        return "Credential(token=[REDACTED])"

    def __repr__(self) -> str:
        expiry = "[UNAVAILABLE]"
        try:
            expiry = self._expires_at.isoformat()
        except Exception:
            pass
        return f"Credential(expires_at={expiry!r}, token='[REDACTED]')"

    def __copy__(self) -> Self:
        raise TypeError("Credentials cannot be copied.")

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        raise TypeError("Credentials cannot be copied.")

    def __reduce__(self) -> str | tuple[Any, ...]:
        raise TypeError("Credentials cannot be serialized.")

    def __reduce_ex__(self, protocol: SupportsIndex) -> str | tuple[Any, ...]:
        del protocol
        raise TypeError("Credentials cannot be serialized.")

    def __getstate__(self) -> object:
        raise TypeError("Credentials cannot be serialized.")

    def __del__(self) -> None:
        self.close()


class SyncCredentialProvider(Protocol):
    """Static contract for synchronous credential providers."""

    def get_credential(
        self,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> Credential | None:
        """Return a current credential, or ``None``."""


class AsyncCredentialProvider(Protocol):
    """Static contract for asynchronous credential providers."""

    async def get_credential(
        self,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> Credential | None:
        """Return a current credential, or ``None``."""


class _CancellationBoundary:
    """Opaque wrapper preventing callback repr from entering tracebacks."""

    __slots__ = ("_checker",)

    _checker: Callable[[], bool] | None

    def __init__(self, checker: Callable[[], bool] | None) -> None:
        object.__setattr__(self, "_checker", checker)

    def requested(self) -> bool:
        try:
            return self._checker is not None and bool(self._checker())
        except Exception:
            return True

    def __repr__(self) -> str:
        return "_CancellationBoundary([REDACTED])"


class _AcquisitionRequest:
    """Safe provider arguments and trusted cancellation/deadline checks."""

    __slots__ = ("_cancellation", "deadline", "invalid_deadline")

    deadline: float | None
    invalid_deadline: bool
    _cancellation: _CancellationBoundary

    def __init__(
        self,
        *,
        deadline: object,
        cancelled: Callable[[], bool] | None,
    ) -> None:
        normalized: float | None = None
        invalid = False
        try:
            if isinstance(deadline, bool):
                invalid = True
            elif deadline is not None:
                normalized = float(cast(Any, deadline))
                if not math.isfinite(normalized):
                    invalid = True
        except (KeyboardInterrupt, SystemExit, asyncio.CancelledError):
            raise
        except BaseException:
            invalid = True
        object.__setattr__(self, "deadline", normalized)
        object.__setattr__(self, "invalid_deadline", invalid)
        object.__setattr__(self, "_cancellation", _CancellationBoundary(cancelled))

    def cancelled(self) -> bool:
        try:
            if self._cancellation.requested():
                return True
            return self.deadline is not None and _monotonic_now() >= self.deadline
        except Exception:
            return True

    def __repr__(self) -> str:
        return (
            "_AcquisitionRequest("
            f"deadline={self.deadline!r}, "
            f"invalid_deadline={self.invalid_deadline!r}, "
            "cancelled=[REDACTED])"
        )


class _CredentialOutcome:
    """Opaque ownership capsule for a value returned by untrusted code."""

    __slots__ = ("_value", "cancellation", "failed")

    failed: bool
    cancellation: str | None
    _value: object

    def __init__(
        self,
        value: object = None,
        *,
        failed: bool = False,
        cancellation: str | None = None,
    ) -> None:
        object.__setattr__(self, "_value", value)
        object.__setattr__(self, "failed", failed)
        object.__setattr__(self, "cancellation", cancellation)

    def current(self) -> bool:
        value = self._value
        if type(value) is not Credential:
            return False
        try:
            return not value.closed and _wall_now() < value.expires_at
        except Exception:
            return False

    def take(self) -> Credential | None:
        value = self._value
        object.__setattr__(self, "_value", None)
        return value if type(value) is Credential else None

    def close(self) -> None:
        value = self._value
        object.__setattr__(self, "_value", None)
        if type(value) is Credential:
            value.close()
            return
        if inspect.iscoroutine(value):
            try:
                value.close()
            except Exception:
                pass
        elif isinstance(value, asyncio.Future):
            value.cancel()

    def __repr__(self) -> str:
        return (
            "_CredentialOutcome("
            f"failed={self.failed!r}, "
            f"cancellation={self.cancellation!r}, "
            "value=[REDACTED])"
        )


class _SyncProviderBoundary:
    """Invoke an arbitrary provider without propagating its exception."""

    __slots__ = ("_provider",)

    _provider: Any

    def __init__(self, provider: object) -> None:
        object.__setattr__(self, "_provider", provider)

    def invoke(self, request: _AcquisitionRequest) -> _CredentialOutcome:
        try:
            value = self._provider.get_credential(
                deadline=request.deadline,
                cancelled=request.cancelled,
            )
        except asyncio.CancelledError:
            return _CredentialOutcome(cancellation="asyncio")
        except concurrent.futures.CancelledError:
            return _CredentialOutcome(cancellation="concurrent")
        except Exception:
            return _CredentialOutcome(failed=True)
        outcome = _CredentialOutcome(value)
        if inspect.isawaitable(value):
            outcome.close()
            return _CredentialOutcome(failed=True)
        return outcome

    def __repr__(self) -> str:
        return "_SyncProviderBoundary(provider=[REDACTED])"


class _AsyncProviderBoundary:
    """Invoke and await an arbitrary provider behind an opaque task frame."""

    __slots__ = ("_provider",)

    _provider: Any

    def __init__(self, provider: object) -> None:
        object.__setattr__(self, "_provider", provider)

    async def invoke(self, request: _AcquisitionRequest) -> _CredentialOutcome:
        try:
            pending = self._provider.get_credential(
                deadline=request.deadline,
                cancelled=request.cancelled,
            )
        except asyncio.CancelledError:
            return _CredentialOutcome(cancellation="asyncio")
        except concurrent.futures.CancelledError:
            return _CredentialOutcome(cancellation="concurrent")
        except Exception:
            return _CredentialOutcome(failed=True)
        if not inspect.isawaitable(pending):
            outcome = _CredentialOutcome(pending)
            outcome.close()
            return _CredentialOutcome(failed=True)
        try:
            value = await pending
        except asyncio.CancelledError:
            return _CredentialOutcome(cancellation="asyncio")
        except concurrent.futures.CancelledError:
            return _CredentialOutcome(cancellation="concurrent")
        except Exception:
            return _CredentialOutcome(failed=True)
        return _CredentialOutcome(value)

    def __repr__(self) -> str:
        return "_AsyncProviderBoundary(provider=[REDACTED])"


def _current_task_cancelling() -> bool:
    try:
        current = asyncio.current_task()
        return current is not None and current.cancelling() > 0
    except Exception:
        return True


def _drain_provider_task(task: asyncio.Task[_CredentialOutcome]) -> None:
    """Consume a detached provider task and wipe any eventual credential."""

    try:
        outcome = task.result()
    except BaseException:
        return
    outcome.close()


def _raise_provider_cancellation(kind: str) -> None:
    if kind == "asyncio":
        raise asyncio.CancelledError
    raise concurrent.futures.CancelledError


def acquire_credential(
    provider: SyncCredentialProvider,
    *,
    deadline: float | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> Credential:
    """Acquire a current sync credential without a fallback identity."""

    boundary = _SyncProviderBoundary(provider)
    request = _AcquisitionRequest(deadline=deadline, cancelled=cancelled)
    del provider, cancelled, deadline
    if request.invalid_deadline:
        raise InvalidCredentialDeadline() from None
    if request.cancelled():
        raise CredentialAcquisitionCancelled() from None

    outcome = boundary.invoke(request)
    if outcome.cancellation is not None:
        _raise_provider_cancellation(outcome.cancellation)
    if request.cancelled():
        outcome.close()
        raise CredentialAcquisitionCancelled() from None
    if outcome.failed or not outcome.current():
        outcome.close()
        raise CredentialUnavailable() from None
    credential = outcome.take()
    if credential is None:
        raise CredentialUnavailable() from None
    return credential


async def acquire_credential_async(
    provider: AsyncCredentialProvider,
    *,
    deadline: float | None = None,
    cancelled: Callable[[], bool] | None = None,
) -> Credential:
    """Acquire a current async credential in a controlled provider task."""

    boundary = _AsyncProviderBoundary(provider)
    request = _AcquisitionRequest(deadline=deadline, cancelled=cancelled)
    del provider, cancelled, deadline
    if request.invalid_deadline:
        raise InvalidCredentialDeadline() from None
    if request.cancelled():
        raise CredentialAcquisitionCancelled() from None

    provider_task = asyncio.create_task(boundary.invoke(request))
    outcome: _CredentialOutcome | None = None
    try:
        outcome = await asyncio.shield(provider_task)
    except asyncio.CancelledError:
        provider_task.cancel()
        provider_task.add_done_callback(_drain_provider_task)
        raise

    if outcome.cancellation is not None:
        _raise_provider_cancellation(outcome.cancellation)
    if _current_task_cancelling():
        outcome.close()
        raise asyncio.CancelledError
    if request.cancelled():
        outcome.close()
        raise CredentialAcquisitionCancelled() from None
    if outcome.failed or not outcome.current():
        outcome.close()
        raise CredentialUnavailable() from None
    credential = outcome.take()
    if credential is None:
        raise CredentialUnavailable() from None
    return credential


__all__ = [
    "AsyncCredentialProvider",
    "Credential",
    "CredentialAcquisitionCancelled",
    "CredentialUnavailable",
    "InvalidCredentialDeadline",
    "SyncCredentialProvider",
    "acquire_credential",
    "acquire_credential_async",
]
