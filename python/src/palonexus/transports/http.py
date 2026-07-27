# SPDX-License-Identifier: MIT
"""Fail-closed HTTP transports for PaloNexus authorization decisions."""

from __future__ import annotations

import asyncio
import concurrent.futures
import hmac
import ipaddress
import math
import re
import threading
import time
from collections.abc import Awaitable, Callable, Iterator
from dataclasses import dataclass
from datetime import date
from itertools import zip_longest
from typing import Final, Literal, Never, Self, cast
from urllib.parse import unquote, urlsplit

import httpx

from .. import _canonicalize
from .._generated import protocol as _protocol
from ..credentials import (
    AsyncCredentialProvider,
    CredentialAcquisitionCancelled,
    CredentialUnavailable,
    InvalidCredentialDeadline,
    SyncCredentialProvider,
    acquire_credential,
    acquire_credential_async,
)
from ..errors import (
    AuthenticationFailed,
    AuthorizationUnavailable,
    InvalidDecision,
    InvalidRequest,
    PaloNexusError,
)
from ..retry import CompletionState, RetryFailure, RetryPolicy

_DEFAULT_DECISION_PATH: Final[str] = "/v1/authorization/decisions"
_MAX_TIMEOUT_SECONDS: Final[float] = 60.0
_SLEEP_QUANTUM_SECONDS: Final[float] = 0.05
_RFC3339: Final[re.Pattern[str]] = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_UNIX_EPOCH_ORDINAL: Final[int] = 719163
_TRANSIENT_STATUS: Final[frozenset[int]] = frozenset({408, 425, 429, *range(500, 600)})
_REDIRECT_STATUS: Final[frozenset[int]] = frozenset(
    {300, 301, 302, 303, 304, 305, 306, 307, 308}
)
_LOCAL_TEST_CAPABILITY: Final[object] = object()

type _Timestamp = tuple[int, str]
type _AsyncSleep = Callable[[float], Awaitable[None]]


def _raise_invalid_request() -> Never:
    raise InvalidRequest() from None


def _safe_request_id(request: object) -> object | None:
    try:
        return cast(object | None, getattr(request, "request_id"))
    except Exception:
        return None


def _safe_correlation_id(request: object) -> object | None:
    try:
        return cast(object | None, getattr(request, "correlation_id"))
    except Exception:
        return None


def _invalid_decision(request: object) -> InvalidDecision:
    return InvalidDecision(
        request_id=_safe_request_id(request),
        correlation_id=_safe_correlation_id(request),
    )


def _unavailable(request: object) -> AuthorizationUnavailable:
    return AuthorizationUnavailable(
        request_id=_safe_request_id(request),
        correlation_id=_safe_correlation_id(request),
    )


def _normalize_timeout(value: object) -> float | None:
    try:
        if isinstance(value, bool):
            return None
        normalized = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError, OverflowError):
        return None
    if (
        not math.isfinite(normalized)
        or normalized <= 0
        or normalized > _MAX_TIMEOUT_SECONDS
    ):
        return None
    return normalized


@dataclass(frozen=True, slots=True, init=False)
class TransportTimeouts:
    """Bounded connect, read, write, and connection-pool timeouts."""

    connect: float
    read: float
    write: float
    pool: float

    def __init__(
        self,
        *,
        connect: float = 3.0,
        read: float = 5.0,
        write: float = 5.0,
        pool: float = 3.0,
    ) -> None:
        values = tuple(
            _normalize_timeout(value) for value in (connect, read, write, pool)
        )
        if any(value is None for value in values):
            _raise_invalid_request()
        normalized_connect, normalized_read, normalized_write, normalized_pool = values
        object.__setattr__(self, "connect", normalized_connect)
        object.__setattr__(self, "read", normalized_read)
        object.__setattr__(self, "write", normalized_write)
        object.__setattr__(self, "pool", normalized_pool)

    def _as_httpx(self) -> httpx.Timeout:
        return httpx.Timeout(
            connect=self.connect,
            read=self.read,
            write=self.write,
            pool=self.pool,
        )


def _validate_origin(
    origin: object,
    *,
    allow_local_http: bool,
) -> str:
    failed = False
    normalized = ""
    try:
        if type(origin) is not str or not origin or origin != origin.strip():
            raise ValueError
        if any(
            ord(character) <= 0x20 or ord(character) == 0x7F for character in origin
        ):
            raise ValueError
        if "\\" in origin:
            raise ValueError
        parts = urlsplit(origin)
        if (
            not parts.netloc
            or parts.path not in {"", "/"}
            or parts.query
            or parts.fragment
            or parts.username is not None
            or parts.password is not None
            or "@" in parts.netloc
            or "%" in parts.netloc
        ):
            raise ValueError
        scheme = parts.scheme.lower()
        if scheme not in {"https", "http"} or scheme != parts.scheme:
            raise ValueError
        hostname = parts.hostname
        if hostname is None or not hostname:
            raise ValueError
        # Accessing port rejects malformed and out-of-range values.
        parts.port
        if scheme == "http":
            if not allow_local_http:
                raise ValueError
            address = ipaddress.ip_address(hostname)
            if not address.is_loopback:
                raise ValueError
        elif allow_local_http:
            # Test-only configuration must not silently become production TLS.
            raise ValueError
        parsed = httpx.URL(origin)
        if parsed.scheme != scheme:
            raise ValueError
        normalized = str(parsed.copy_with(raw_path=b"/")).rstrip("/")
    except Exception:
        failed = True
    if failed or not normalized:
        _raise_invalid_request()
    return normalized


def _validate_decision_path(value: object) -> str:
    failed = False
    normalized = ""
    try:
        if (
            type(value) is not str
            or not value
            or value != value.strip()
            or not value.startswith("/")
            or value.startswith("//")
            or "\\" in value
            or any(ord(character) <= 0x20 for character in value)
        ):
            raise ValueError
        parts = urlsplit(value)
        if parts.scheme or parts.netloc or parts.query or parts.fragment:
            raise ValueError
        decoded = unquote(value)
        if "\\" in decoded or decoded.startswith("//"):
            raise ValueError
        segments = decoded.split("/")
        if any(segment in {".", ".."} for segment in segments):
            raise ValueError
        lowered = value.lower()
        if any(encoded in lowered for encoded in ("%2f", "%5c", "%2e")):
            raise ValueError
        parsed = httpx.URL(value)
        if parsed.is_absolute_url or parsed.query:
            raise ValueError
        normalized = value
    except Exception:
        failed = True
    if failed or not normalized:
        _raise_invalid_request()
    return normalized


@dataclass(frozen=True, slots=True, init=False)
class HTTPTransportConfig:
    """Immutable network policy for a decision-service HTTP transport.

    Normal construction is HTTPS-only. Insecure HTTP can only be constructed
    through ``for_local_testing`` and only for an IP-literal loopback origin.
    """

    _endpoint: str
    _local_testing: bool
    max_response_bytes: int
    timeouts: TransportTimeouts

    def __init__(
        self,
        *,
        origin: str,
        decision_path: str = _DEFAULT_DECISION_PATH,
        timeouts: TransportTimeouts | None = None,
        max_response_bytes: int = _protocol.MAX_WIRE_BYTES,
        _capability: object | None = None,
    ) -> None:
        local_testing = _capability is _LOCAL_TEST_CAPABILITY
        normalized_origin = _validate_origin(
            origin,
            allow_local_http=local_testing,
        )
        normalized_path = _validate_decision_path(decision_path)
        selected_timeouts = TransportTimeouts() if timeouts is None else timeouts
        if type(selected_timeouts) is not TransportTimeouts:
            _raise_invalid_request()
        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or max_response_bytes < 1
            or max_response_bytes > _protocol.MAX_WIRE_BYTES
        ):
            _raise_invalid_request()
        endpoint = f"{normalized_origin}{normalized_path}"
        parsed_endpoint = httpx.URL(endpoint)
        if str(parsed_endpoint) != endpoint:
            _raise_invalid_request()
        object.__setattr__(self, "_endpoint", endpoint)
        object.__setattr__(self, "_local_testing", local_testing)
        object.__setattr__(self, "timeouts", selected_timeouts)
        object.__setattr__(self, "max_response_bytes", max_response_bytes)

    @classmethod
    def for_local_testing(
        cls,
        *,
        origin: str,
        testing_only: Literal[True],
        decision_path: str = _DEFAULT_DECISION_PATH,
        timeouts: TransportTimeouts | None = None,
        max_response_bytes: int = _protocol.MAX_WIRE_BYTES,
    ) -> Self:
        """Create explicit loopback-only HTTP configuration for tests."""

        if testing_only is not True:
            _raise_invalid_request()
        return cls(
            origin=origin,
            decision_path=decision_path,
            timeouts=timeouts,
            max_response_bytes=max_response_bytes,
            _capability=_LOCAL_TEST_CAPABILITY,
        )

    def __repr__(self) -> str:
        mode = "local_testing" if self._local_testing else "production"
        return (
            "HTTPTransportConfig("
            f"mode={mode!r}, "
            f"max_response_bytes={self.max_response_bytes!r}, "
            f"timeouts={self.timeouts!r}, "
            "endpoint='[REDACTED]')"
        )


@dataclass(frozen=True, slots=True)
class _Attempt:
    request: _protocol.ActionRequest
    body: bytes
    client_scope_hash: str
    request_id: str
    correlation_id: str
    action_id: str
    idempotency_key: str
    side_effect: str


@dataclass(frozen=True, slots=True)
class _HTTPResponse:
    status_code: int
    body: bytes
    retry_after: str | None


@dataclass(frozen=True, slots=True)
class _RetryableFailure:
    failure: RetryFailure
    completion: CompletionState
    retry_after: str | None = None


def _prepare_attempt(
    request: object,
    client_scope_hash: object,
) -> _Attempt:
    failed = False
    attempt: _Attempt | None = None
    try:
        if type(request) is not _protocol.ActionRequest:
            raise TypeError
        request.validate_structural()
        body = request.to_json_bytes()
        canonical_scope_hash = _canonicalize.client_scope_hash(request.to_dict())
        if type(client_scope_hash) is not str:
            raise TypeError
        supplied_scope_hash = str(_protocol.SHA256Digest(client_scope_hash))
        if not hmac.compare_digest(canonical_scope_hash, supplied_scope_hash):
            raise ValueError
        attempt = _Attempt(
            request=request,
            body=body,
            client_scope_hash=canonical_scope_hash,
            request_id=str(request.request_id),
            correlation_id=str(request.correlation_id),
            action_id=str(request.action_id),
            idempotency_key=str(request.idempotency_key),
            side_effect=str(request.side_effect),
        )
    except Exception:
        failed = True
    if failed or attempt is None:
        _raise_invalid_request()
    return attempt


def _parse_rfc3339(value: object) -> _Timestamp:
    failed = False
    timestamp: _Timestamp | None = None
    try:
        if type(value) is not str:
            raise ValueError
        match = _RFC3339.fullmatch(value)
        if match is None:
            raise ValueError
        base, _fraction_with_dot, fraction, zone = match.groups()
        parsed = time.strptime(base, "%Y-%m-%dT%H:%M:%S")
        # strptime accepts neither leap seconds nor invalid calendar values.
        offset_seconds = 0
        if zone != "Z":
            offset_hour = int(zone[1:3])
            offset_minute = int(zone[4:6])
            if offset_hour > 23 or offset_minute > 59:
                raise ValueError
            offset_seconds = (offset_hour * 60 + offset_minute) * 60
            if zone[0] == "-":
                offset_seconds = -offset_seconds
        local_seconds = (
            (
                date(parsed.tm_year, parsed.tm_mon, parsed.tm_mday).toordinal()
                - _UNIX_EPOCH_ORDINAL
            )
            * 86_400
            + parsed.tm_hour * 3_600
            + parsed.tm_min * 60
            + parsed.tm_sec
        )
        timestamp = (local_seconds - offset_seconds, fraction or "")
    except Exception:
        failed = True
    if failed or timestamp is None:
        raise ValueError("invalid timestamp") from None
    return timestamp


def _timestamp_order(left: _Timestamp, right: _Timestamp) -> int:
    if left[0] != right[0]:
        return -1 if left[0] < right[0] else 1
    for left_digit, right_digit in zip_longest(
        left[1],
        right[1],
        fillvalue="0",
    ):
        if left_digit != right_digit:
            return -1 if left_digit < right_digit else 1
    return 0


def _parse_decision(
    body: bytes,
    attempt: _Attempt,
) -> _protocol.AuthorizationDecision:
    failed = False
    decision: _protocol.AuthorizationDecision | None = None
    try:
        decision = _protocol.parse_decision_json(body)
        server_time = _parse_rfc3339(str(decision.server_time))
        expires_at = _parse_rfc3339(str(decision.expires_at))
        if _timestamp_order(expires_at, server_time) <= 0:
            raise ValueError
        if (
            not hmac.compare_digest(str(decision.request_id), attempt.request_id)
            or not hmac.compare_digest(
                str(decision.correlation_id),
                attempt.correlation_id,
            )
            or not hmac.compare_digest(
                str(decision.client_scope_hash),
                attempt.client_scope_hash,
            )
        ):
            raise ValueError
        # Structural parsing proves authoritativeScopeHash came from the
        # authenticated peer response. It is deliberately not caller input and
        # cannot be recomputed by this client.
        _protocol.SHA256Digest(str(decision.authoritative_scope_hash))
    except Exception:
        failed = True
    if failed or decision is None:
        raise _invalid_decision(attempt.request) from None
    return decision


def _parse_protocol_error(
    body: bytes,
    attempt: _Attempt,
) -> PaloNexusError | None:
    failed = False
    mapped: PaloNexusError | None = None
    try:
        value = _protocol.parse_error_json(body)
        if value.action_id is not None and not hmac.compare_digest(
            str(value.action_id), attempt.action_id
        ):
            raise ValueError
        if value.request_id is not None and not hmac.compare_digest(
            str(value.request_id), attempt.request_id
        ):
            raise ValueError
        if value.correlation_id is not None and not hmac.compare_digest(
            str(value.correlation_id),
            attempt.correlation_id,
        ):
            raise ValueError
        mapped = PaloNexusError.from_protocol(value)
        if (
            str(value.safe_message) != mapped.message
            or value.retryable is not mapped.retryable
        ):
            raise ValueError
    except Exception:
        failed = True
    return None if failed else mapped


def _header_value(
    headers: httpx.Headers,
    name: str,
    *,
    maximum: int,
) -> str | None:
    try:
        values = headers.get_list(name)
        if len(values) != 1:
            return None
        value = values[0]
        if (
            not value
            or len(value) > maximum
            or value != value.strip()
            or any(
                ord(character) < 0x20 or ord(character) == 0x7F for character in value
            )
        ):
            return None
        return value
    except Exception:
        return None


def _validate_response_headers(
    response: httpx.Response,
    *,
    maximum: int,
) -> str | None:
    headers = response.headers
    content_types = headers.get_list("content-type")
    if len(content_types) != 1:
        raise ValueError
    parts = [part.strip().lower() for part in content_types[0].split(";")]
    if not parts or parts[0] != "application/json":
        raise ValueError
    if len(parts) > 2 or (
        len(parts) == 2 and parts[1] not in {"charset=utf-8", 'charset="utf-8"'}
    ):
        raise ValueError

    encodings = headers.get_list("content-encoding")
    if len(encodings) > 1 or (encodings and encodings[0].strip().lower() != "identity"):
        raise ValueError

    lengths = headers.get_list("content-length")
    if len(lengths) > 1:
        raise ValueError
    if lengths:
        value = lengths[0]
        if (
            not value.isascii()
            or not value.isdecimal()
            or len(value) > 12
            or int(value, 10) > maximum
        ):
            raise ValueError
    return _header_value(headers, "retry-after", maximum=128)


def _read_response_sync(
    response: httpx.Response,
    *,
    maximum: int,
) -> _HTTPResponse:
    result: _HTTPResponse | None = None
    transient = False
    invalid = False
    try:
        retry_after = _validate_response_headers(response, maximum=maximum)
        body = bytearray()
        chunks: Iterator[bytes] | tuple[bytes, ...]
        if response.is_stream_consumed:
            chunks = (response.content,)
        else:
            chunks = response.iter_raw()
        for chunk in chunks:
            if len(body) + len(chunk) > maximum:
                raise ValueError
            body.extend(chunk)
        result = _HTTPResponse(
            status_code=response.status_code,
            body=bytes(body),
            retry_after=retry_after,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        if response.status_code in _TRANSIENT_STATUS:
            transient = True
        else:
            invalid = True
    if transient:
        raise _TransientResponseError(response.status_code) from None
    if invalid or result is None:
        raise ValueError("invalid response") from None
    return result


async def _read_response_async(
    response: httpx.Response,
    *,
    maximum: int,
) -> _HTTPResponse:
    result: _HTTPResponse | None = None
    transient = False
    invalid = False
    try:
        retry_after = _validate_response_headers(response, maximum=maximum)
        body = bytearray()
        if response.is_stream_consumed:
            chunks = (response.content,)
            for chunk in chunks:
                if len(body) + len(chunk) > maximum:
                    raise ValueError
                body.extend(chunk)
        else:
            async for chunk in response.aiter_raw():
                if len(body) + len(chunk) > maximum:
                    raise ValueError
                body.extend(chunk)
        result = _HTTPResponse(
            status_code=response.status_code,
            body=bytes(body),
            retry_after=retry_after,
        )
    except asyncio.CancelledError:
        raise
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        if response.status_code in _TRANSIENT_STATUS:
            transient = True
        else:
            invalid = True
    if transient:
        raise _TransientResponseError(response.status_code) from None
    if invalid or result is None:
        raise ValueError("invalid response") from None
    return result


class _TransientResponseError(Exception):
    """Internal status-only failure that retains no response content."""

    __slots__ = ("status_code",)

    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        super().__init__("transient authorization response")


def _response_result(
    response: _HTTPResponse,
    attempt: _Attempt,
) -> _protocol.AuthorizationDecision | PaloNexusError | _RetryableFailure:
    if response.status_code == 200:
        return _parse_decision(response.body, attempt)
    if response.status_code in _REDIRECT_STATUS:
        return _invalid_decision(attempt.request)

    protocol_error = _parse_protocol_error(response.body, attempt)
    if protocol_error is not None:
        if isinstance(protocol_error, AuthorizationUnavailable):
            return _RetryableFailure(
                failure=RetryFailure.UNAVAILABLE,
                completion=CompletionState.AUTHORIZATION_AMBIGUOUS,
                retry_after=response.retry_after,
            )
        return protocol_error
    if response.status_code in _TRANSIENT_STATUS:
        if response.status_code == 408:
            failure = RetryFailure.TIMEOUT
        elif response.status_code == 429:
            failure = RetryFailure.RATE_LIMITED
        else:
            failure = RetryFailure.UNAVAILABLE
        return _RetryableFailure(
            failure=failure,
            completion=CompletionState.AUTHORIZATION_AMBIGUOUS,
            retry_after=response.retry_after,
        )
    return _invalid_decision(attempt.request)


def _exception_failure(error: httpx.RequestError) -> _RetryableFailure:
    if isinstance(error, httpx.TimeoutException):
        failure = RetryFailure.TIMEOUT
    elif isinstance(error, httpx.NetworkError):
        failure = RetryFailure.CONNECTION
    else:
        failure = RetryFailure.UNAVAILABLE
    completion = (
        CompletionState.NOT_EXECUTED
        if isinstance(
            error,
            (httpx.ConnectError, httpx.ConnectTimeout, httpx.PoolTimeout),
        )
        else CompletionState.AUTHORIZATION_AMBIGUOUS
    )
    return _RetryableFailure(failure=failure, completion=completion)


def _status_failure(status_code: int) -> _RetryableFailure:
    if status_code == 408:
        failure = RetryFailure.TIMEOUT
    elif status_code == 429:
        failure = RetryFailure.RATE_LIMITED
    else:
        failure = RetryFailure.UNAVAILABLE
    return _RetryableFailure(
        failure=failure,
        completion=CompletionState.AUTHORIZATION_AMBIGUOUS,
    )


def _cancel_requested(cancelled: Callable[[], bool] | None) -> bool:
    if cancelled is None:
        return False
    try:
        return bool(cancelled())
    except Exception:
        return True


def _normalize_deadline(deadline: object) -> float | None:
    if deadline is None:
        return None
    try:
        if isinstance(deadline, bool):
            raise ValueError
        normalized = float(deadline)  # type: ignore[arg-type]
        if not math.isfinite(normalized):
            raise ValueError
        return normalized
    except Exception:
        _raise_invalid_request()


def _request_timeout(
    timeouts: TransportTimeouts,
    deadline_remaining: float | None,
) -> httpx.Timeout:
    if deadline_remaining is None:
        return timeouts._as_httpx()
    if not math.isfinite(deadline_remaining) or deadline_remaining <= 0:
        _raise_invalid_request()
    return httpx.Timeout(
        connect=min(timeouts.connect, deadline_remaining),
        read=min(timeouts.read, deadline_remaining),
        write=min(timeouts.write, deadline_remaining),
        pool=min(timeouts.pool, deadline_remaining),
    )


def _raise_sync_cancelled() -> Never:
    raise concurrent.futures.CancelledError


def _sync_authorization_header(
    provider: SyncCredentialProvider,
    *,
    attempt: _Attempt,
    deadline: float | None,
    cancelled: Callable[[], bool] | None,
) -> str:
    credential = None
    failure: Literal["authentication", "invalid", "cancelled"] | None = None
    try:
        credential = acquire_credential(
            provider,
            deadline=deadline,
            cancelled=cancelled,
        )
    except (CredentialUnavailable, AuthenticationFailed):
        failure = "authentication"
    except InvalidCredentialDeadline:
        failure = "invalid"
    except CredentialAcquisitionCancelled:
        failure = "cancelled"
    if failure == "authentication":
        raise AuthenticationFailed(
            request_id=attempt.request_id,
            correlation_id=attempt.correlation_id,
        ) from None
    if failure == "invalid":
        raise InvalidRequest(
            request_id=attempt.request_id,
            correlation_id=attempt.correlation_id,
        ) from None
    if failure == "cancelled":
        _raise_sync_cancelled()
    if credential is None:
        raise AuthenticationFailed(
            request_id=attempt.request_id,
            correlation_id=attempt.correlation_id,
        ) from None

    header = ""
    try:
        header = credential.authorization_header()
    except AuthenticationFailed:
        pass
    finally:
        credential.close()
    if not header:
        raise AuthenticationFailed(
            request_id=attempt.request_id,
            correlation_id=attempt.correlation_id,
        ) from None
    return header


async def _async_authorization_header(
    provider: AsyncCredentialProvider,
    *,
    attempt: _Attempt,
    deadline: float | None,
    cancelled: Callable[[], bool] | None,
) -> str:
    credential = None
    failure: Literal["authentication", "invalid", "cancelled"] | None = None
    try:
        credential = await acquire_credential_async(
            provider,
            deadline=deadline,
            cancelled=cancelled,
        )
    except asyncio.CancelledError:
        raise
    except (CredentialUnavailable, AuthenticationFailed):
        failure = "authentication"
    except InvalidCredentialDeadline:
        failure = "invalid"
    except CredentialAcquisitionCancelled:
        failure = "cancelled"
    if failure == "authentication":
        raise AuthenticationFailed(
            request_id=attempt.request_id,
            correlation_id=attempt.correlation_id,
        ) from None
    if failure == "invalid":
        raise InvalidRequest(
            request_id=attempt.request_id,
            correlation_id=attempt.correlation_id,
        ) from None
    if failure == "cancelled":
        raise asyncio.CancelledError
    if credential is None:
        raise AuthenticationFailed(
            request_id=attempt.request_id,
            correlation_id=attempt.correlation_id,
        ) from None

    header = ""
    try:
        header = credential.authorization_header()
    except AuthenticationFailed:
        pass
    finally:
        credential.close()
    if not header:
        raise AuthenticationFailed(
            request_id=attempt.request_id,
            correlation_id=attempt.correlation_id,
        ) from None
    return header


def _sync_sleep(
    delay: float,
    *,
    cancelled: Callable[[], bool] | None,
    sleeper: Callable[[float], None],
    injected: bool,
) -> None:
    if injected:
        if _cancel_requested(cancelled):
            _raise_sync_cancelled()
        sleeper(delay)
        if _cancel_requested(cancelled):
            _raise_sync_cancelled()
        return
    remaining = delay
    while remaining > 0:
        if _cancel_requested(cancelled):
            _raise_sync_cancelled()
        quantum = min(remaining, _SLEEP_QUANTUM_SECONDS)
        sleeper(quantum)
        remaining -= quantum


async def _async_sleep(
    delay: float,
    *,
    cancelled: Callable[[], bool] | None,
    sleeper: _AsyncSleep,
) -> None:
    if _cancel_requested(cancelled):
        raise asyncio.CancelledError
    await sleeper(delay)
    if _cancel_requested(cancelled):
        raise asyncio.CancelledError


class HTTPAuthorizationTransport:
    """Synchronous, HTTPS-only PaloNexus decision transport."""

    _client: httpx.Client
    _closed: bool
    _config: HTTPTransportConfig
    _credential_provider: SyncCredentialProvider
    _injected_sleep: bool
    _lock: threading.RLock
    _monotonic: Callable[[], float]
    _retry_policy: RetryPolicy
    _sleep: Callable[[float], None]

    __slots__ = (
        "_client",
        "_closed",
        "_config",
        "_credential_provider",
        "_injected_sleep",
        "_lock",
        "_monotonic",
        "_retry_policy",
        "_sleep",
    )

    def __init__(
        self,
        *,
        config: HTTPTransportConfig,
        credential_provider: SyncCredentialProvider,
        retry_policy: RetryPolicy,
    ) -> None:
        if (
            type(config) is not HTTPTransportConfig
            or type(retry_policy) is not RetryPolicy
        ):
            _raise_invalid_request()
        self._initialize(
            config=config,
            credential_provider=credential_provider,
            retry_policy=retry_policy,
            client=httpx.Client(
                verify=True,
                timeout=config.timeouts._as_httpx(),
                follow_redirects=False,
                trust_env=False,
            ),
            sleep=time.sleep,
            monotonic=time.monotonic,
            injected_sleep=False,
        )

    def _initialize(
        self,
        *,
        config: HTTPTransportConfig,
        credential_provider: SyncCredentialProvider,
        retry_policy: RetryPolicy,
        client: httpx.Client,
        sleep: Callable[[float], None],
        monotonic: Callable[[], float],
        injected_sleep: bool,
    ) -> None:
        object.__setattr__(self, "_config", config)
        object.__setattr__(self, "_credential_provider", credential_provider)
        object.__setattr__(self, "_retry_policy", retry_policy)
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_sleep", sleep)
        object.__setattr__(self, "_monotonic", monotonic)
        object.__setattr__(self, "_injected_sleep", injected_sleep)
        object.__setattr__(self, "_lock", threading.RLock())
        object.__setattr__(self, "_closed", False)

    @classmethod
    def _for_testing(
        cls,
        *,
        config: HTTPTransportConfig,
        credential_provider: SyncCredentialProvider,
        retry_policy: RetryPolicy,
        client: httpx.Client,
        sleep: Callable[[float], None] | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Self:
        """Private dependency seam for deterministic, network-free tests."""

        instance = cls.__new__(cls)
        instance._initialize(
            config=config,
            credential_provider=credential_provider,
            retry_policy=retry_policy,
            client=client,
            sleep=(lambda _delay: None) if sleep is None else sleep,
            monotonic=monotonic,
            injected_sleep=True,
        )
        return instance

    def _ensure_open(self, request: object) -> None:
        with self._lock:
            if self._closed:
                raise _unavailable(request) from None

    def _send(
        self,
        attempt: _Attempt,
        authorization_header: str,
        timeout: httpx.Timeout,
    ) -> _HTTPResponse:
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Authorization": authorization_header,
            "Content-Type": "application/json",
            "Idempotency-Key": attempt.idempotency_key,
            "X-PaloNexus-Protocol-Version": "1",
        }
        outbound = self._client.build_request(
            "POST",
            self._config._endpoint,
            headers=headers,
            content=attempt.body,
            timeout=timeout,
        )
        # Decision-service cookies are never identity. Removing Cookie after
        # client request construction prevents a prior Set-Cookie response
        # from becoming an implicit fallback caller on a retry.
        outbound.headers.pop("cookie", None)
        response = self._client.send(
            outbound,
            stream=True,
            follow_redirects=False,
        )
        try:
            return _read_response_sync(
                response,
                maximum=self._config.max_response_bytes,
            )
        finally:
            response.close()

    def decide(
        self,
        request: _protocol.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _protocol.AuthorizationDecision:
        """Send one idempotent authorization attempt, never application work."""

        attempt = _prepare_attempt(request, client_scope_hash)
        normalized_deadline = _normalize_deadline(deadline)
        self._ensure_open(request)
        if _cancel_requested(cancelled):
            _raise_sync_cancelled()
        start = self._monotonic()
        if normalized_deadline is not None and start >= normalized_deadline:
            _raise_sync_cancelled()

        authorization_header = _sync_authorization_header(
            self._credential_provider,
            attempt=attempt,
            deadline=normalized_deadline,
            cancelled=cancelled,
        )

        attempt_number = 1
        while True:
            self._ensure_open(request)
            if _cancel_requested(cancelled):
                _raise_sync_cancelled()
            now = self._monotonic()
            if normalized_deadline is not None and now >= normalized_deadline:
                _raise_sync_cancelled()
            remaining_before_io = (
                None if normalized_deadline is None else normalized_deadline - now
            )
            failure: _RetryableFailure
            invalid_response = False
            try:
                response = self._send(
                    attempt,
                    authorization_header,
                    _request_timeout(
                        self._config.timeouts,
                        remaining_before_io,
                    ),
                )
                if _cancel_requested(cancelled):
                    _raise_sync_cancelled()
                if (
                    normalized_deadline is not None
                    and self._monotonic() >= normalized_deadline
                ):
                    _raise_sync_cancelled()
                result = _response_result(response, attempt)
                if isinstance(result, _protocol.AuthorizationDecision):
                    return result
                if isinstance(result, PaloNexusError):
                    raise result from None
                failure = result
            except _TransientResponseError as error:
                failure = _status_failure(error.status_code)
            except httpx.DecodingError:
                invalid_response = True
            except httpx.RequestError as error:
                failure = _exception_failure(error)
            except ValueError:
                invalid_response = True
            if invalid_response:
                raise _invalid_decision(request) from None

            now = self._monotonic()
            elapsed = max(0.0, now - start)
            remaining = (
                None if normalized_deadline is None else normalized_deadline - now
            )
            retry = self._retry_policy.authorization_retry(
                attempt=attempt_number,
                elapsed=elapsed,
                side_effect=attempt.side_effect,
                failure=failure.failure,
                completion=failure.completion,
                authorization_idempotency_key=attempt.idempotency_key,
                retry_after=failure.retry_after,
                cancelled=_cancel_requested(cancelled),
                deadline_remaining=remaining,
            )
            if not retry.should_retry or retry.delay is None:
                raise _unavailable(request) from None
            _sync_sleep(
                retry.delay,
                cancelled=cancelled,
                sleeper=self._sleep,
                injected=self._injected_sleep,
            )
            attempt_number += 1

    def close(self) -> None:
        """Idempotently close the owned HTTP client."""

        with self._lock:
            if self._closed:
                return
            object.__setattr__(self, "_closed", True)
            try:
                self._client.close()
            except Exception:
                pass

    def __enter__(self) -> Self:
        self._ensure_open(None)
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> Literal[False]:
        del exc_type, exc_value, traceback
        self.close()
        return False

    def __repr__(self) -> str:
        return (
            "HTTPAuthorizationTransport("
            f"closed={self._closed!r}, endpoint='[REDACTED]')"
        )


class AsyncHTTPAuthorizationTransport:
    """Asynchronous equivalent of ``HTTPAuthorizationTransport``."""

    _client: httpx.AsyncClient
    _closed: bool
    _config: HTTPTransportConfig
    _credential_provider: AsyncCredentialProvider
    _lock: threading.RLock
    _monotonic: Callable[[], float]
    _retry_policy: RetryPolicy
    _sleep: _AsyncSleep

    __slots__ = (
        "_client",
        "_closed",
        "_config",
        "_credential_provider",
        "_lock",
        "_monotonic",
        "_retry_policy",
        "_sleep",
    )

    def __init__(
        self,
        *,
        config: HTTPTransportConfig,
        credential_provider: AsyncCredentialProvider,
        retry_policy: RetryPolicy,
    ) -> None:
        if (
            type(config) is not HTTPTransportConfig
            or type(retry_policy) is not RetryPolicy
        ):
            _raise_invalid_request()
        self._initialize(
            config=config,
            credential_provider=credential_provider,
            retry_policy=retry_policy,
            client=httpx.AsyncClient(
                verify=True,
                timeout=config.timeouts._as_httpx(),
                follow_redirects=False,
                trust_env=False,
            ),
            sleep=asyncio.sleep,
            monotonic=time.monotonic,
        )

    def _initialize(
        self,
        *,
        config: HTTPTransportConfig,
        credential_provider: AsyncCredentialProvider,
        retry_policy: RetryPolicy,
        client: httpx.AsyncClient,
        sleep: _AsyncSleep,
        monotonic: Callable[[], float],
    ) -> None:
        object.__setattr__(self, "_config", config)
        object.__setattr__(self, "_credential_provider", credential_provider)
        object.__setattr__(self, "_retry_policy", retry_policy)
        object.__setattr__(self, "_client", client)
        object.__setattr__(self, "_sleep", sleep)
        object.__setattr__(self, "_monotonic", monotonic)
        object.__setattr__(self, "_lock", threading.RLock())
        object.__setattr__(self, "_closed", False)

    @classmethod
    def _for_testing(
        cls,
        *,
        config: HTTPTransportConfig,
        credential_provider: AsyncCredentialProvider,
        retry_policy: RetryPolicy,
        client: httpx.AsyncClient,
        sleep: _AsyncSleep | None = None,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> Self:
        """Private dependency seam for deterministic, network-free tests."""

        async def no_sleep(_delay: float) -> None:
            return None

        instance = cls.__new__(cls)
        instance._initialize(
            config=config,
            credential_provider=credential_provider,
            retry_policy=retry_policy,
            client=client,
            sleep=no_sleep if sleep is None else sleep,
            monotonic=monotonic,
        )
        return instance

    def _ensure_open(self, request: object) -> None:
        with self._lock:
            if self._closed:
                raise _unavailable(request) from None

    async def _send(
        self,
        attempt: _Attempt,
        authorization_header: str,
        timeout: httpx.Timeout,
    ) -> _HTTPResponse:
        headers = {
            "Accept": "application/json",
            "Accept-Encoding": "identity",
            "Authorization": authorization_header,
            "Content-Type": "application/json",
            "Idempotency-Key": attempt.idempotency_key,
            "X-PaloNexus-Protocol-Version": "1",
        }
        outbound = self._client.build_request(
            "POST",
            self._config._endpoint,
            headers=headers,
            content=attempt.body,
            timeout=timeout,
        )
        outbound.headers.pop("cookie", None)
        response = await self._client.send(
            outbound,
            stream=True,
            follow_redirects=False,
        )
        try:
            return await _read_response_async(
                response,
                maximum=self._config.max_response_bytes,
            )
        finally:
            await response.aclose()

    async def decide(
        self,
        request: _protocol.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _protocol.AuthorizationDecision:
        """Send one cancellable authorization attempt, never application work."""

        attempt = _prepare_attempt(request, client_scope_hash)
        normalized_deadline = _normalize_deadline(deadline)
        self._ensure_open(request)
        if _cancel_requested(cancelled):
            raise asyncio.CancelledError
        start = self._monotonic()
        if normalized_deadline is not None and start >= normalized_deadline:
            raise asyncio.CancelledError

        authorization_header = await _async_authorization_header(
            self._credential_provider,
            attempt=attempt,
            deadline=normalized_deadline,
            cancelled=cancelled,
        )

        attempt_number = 1
        while True:
            self._ensure_open(request)
            if _cancel_requested(cancelled):
                raise asyncio.CancelledError
            now = self._monotonic()
            if normalized_deadline is not None and now >= normalized_deadline:
                raise asyncio.CancelledError
            remaining_before_io = (
                None if normalized_deadline is None else normalized_deadline - now
            )
            failure: _RetryableFailure
            invalid_response = False
            try:
                response = await self._send(
                    attempt,
                    authorization_header,
                    _request_timeout(
                        self._config.timeouts,
                        remaining_before_io,
                    ),
                )
                if _cancel_requested(cancelled):
                    raise asyncio.CancelledError
                if (
                    normalized_deadline is not None
                    and self._monotonic() >= normalized_deadline
                ):
                    raise asyncio.CancelledError
                result = _response_result(response, attempt)
                if isinstance(result, _protocol.AuthorizationDecision):
                    return result
                if isinstance(result, PaloNexusError):
                    raise result from None
                failure = result
            except asyncio.CancelledError:
                raise
            except _TransientResponseError as error:
                failure = _status_failure(error.status_code)
            except httpx.DecodingError:
                invalid_response = True
            except httpx.RequestError as error:
                failure = _exception_failure(error)
            except ValueError:
                invalid_response = True
            if invalid_response:
                raise _invalid_decision(request) from None

            now = self._monotonic()
            elapsed = max(0.0, now - start)
            remaining = (
                None if normalized_deadline is None else normalized_deadline - now
            )
            retry = self._retry_policy.authorization_retry(
                attempt=attempt_number,
                elapsed=elapsed,
                side_effect=attempt.side_effect,
                failure=failure.failure,
                completion=failure.completion,
                authorization_idempotency_key=attempt.idempotency_key,
                retry_after=failure.retry_after,
                cancelled=_cancel_requested(cancelled),
                deadline_remaining=remaining,
            )
            if not retry.should_retry or retry.delay is None:
                raise _unavailable(request) from None
            await _async_sleep(
                retry.delay,
                cancelled=cancelled,
                sleeper=self._sleep,
            )
            attempt_number += 1

    async def aclose(self) -> None:
        """Idempotently close the owned async HTTP client."""

        with self._lock:
            if self._closed:
                return
            object.__setattr__(self, "_closed", True)
        try:
            await self._client.aclose()
        except Exception:
            pass

    async def __aenter__(self) -> Self:
        self._ensure_open(None)
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> Literal[False]:
        del exc_type, exc_value, traceback
        await self.aclose()
        return False

    def __repr__(self) -> str:
        return (
            "AsyncHTTPAuthorizationTransport("
            f"closed={self._closed!r}, endpoint='[REDACTED]')"
        )


__all__ = [
    "AsyncHTTPAuthorizationTransport",
    "HTTPAuthorizationTransport",
    "HTTPTransportConfig",
    "TransportTimeouts",
]
