# SPDX-License-Identifier: MIT
"""Contract and security tests for the HTTP authorization transports."""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
import json
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import httpx
import pytest
from palonexus import (
    AuthenticationFailed,
    AuthorizationUnavailable,
    InvalidDecision,
    InvalidRequest,
    RetryPolicy,
    _canonicalize,
)
from palonexus._generated import protocol as wire
from palonexus.credentials import Credential
from palonexus.transports import (
    AsyncAuthorizationTransport,
    AsyncHTTPAuthorizationTransport,
    AuthorizationTransport,
    HTTPAuthorizationTransport,
    HTTPTransportConfig,
    TransportTimeouts,
)

ROOT = Path(__file__).parents[2]
ACTION_VECTOR = ROOT / "protocol/test-vectors/action/valid/file-write.json"
DECISION_VECTOR = ROOT / "protocol/test-vectors/decision/valid/allow.json"
ERROR_VECTOR = ROOT / "protocol/test-vectors/error/valid/authorization-unavailable.json"


class _SyncProvider:
    def __init__(
        self,
        token: str = "transport-secret",
        *,
        failure: BaseException | None = None,
    ) -> None:
        self.calls = 0
        self.token = token
        self.failure = failure

    def get_credential(
        self,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> Credential | None:
        del deadline, cancelled
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return Credential(
            self.token,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


class _AsyncProvider:
    def __init__(
        self,
        token: str = "async-transport-secret",
        *,
        failure: BaseException | None = None,
    ) -> None:
        self.calls = 0
        self.token = token
        self.failure = failure

    async def get_credential(
        self,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> Credential | None:
        del deadline, cancelled
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return Credential(
            self.token,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


class _SlowAsyncStream(httpx.AsyncByteStream):
    """Async raw stream with cancellation-visible cleanup."""

    def __init__(self, body: bytes, *, chunks: int, interval: float) -> None:
        chunk_size = max(1, (len(body) + chunks - 1) // chunks)
        self._parts = tuple(
            body[index : index + chunk_size]
            for index in range(0, len(body), chunk_size)
        )
        self._interval = interval
        self.closed = asyncio.Event()
        self.emitted = 0

    async def __aiter__(self) -> Any:
        for part in self._parts:
            await asyncio.sleep(self._interval)
            self.emitted += 1
            yield part

    async def aclose(self) -> None:
        self.closed.set()


def _request() -> wire.ActionRequest:
    return wire.parse_action_json(ACTION_VECTOR.read_bytes())


def _scope_hash(request: wire.ActionRequest) -> str:
    return _canonicalize.client_scope_hash(request.to_dict())


def _decision_document(request: wire.ActionRequest) -> dict[str, Any]:
    document = json.loads(DECISION_VECTOR.read_text(encoding="utf-8"))
    document["requestId"] = str(request.request_id)
    document["correlationId"] = str(request.correlation_id)
    document["clientScopeHash"] = _scope_hash(request)
    return document


def _decision_bytes(request: wire.ActionRequest) -> bytes:
    return json.dumps(
        _decision_document(request),
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()


def _ok_response(request: wire.ActionRequest) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json"},
        content=_decision_bytes(request),
    )


def _config() -> HTTPTransportConfig:
    return HTTPTransportConfig.for_local_testing(
        origin="http://127.0.0.1:9191",
        testing_only=True,
    )


def _sync_transport(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    provider: _SyncProvider | None = None,
    retry_policy: RetryPolicy | None = None,
    sleep: Callable[[float], None] | None = None,
    config: HTTPTransportConfig | None = None,
) -> HTTPAuthorizationTransport:
    async def async_handler(request: httpx.Request) -> httpx.Response:
        return handler(request)

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(async_handler),
        follow_redirects=False,
        trust_env=False,
    )
    return HTTPAuthorizationTransport._for_testing(
        config=config or _config(),
        credential_provider=provider or _SyncProvider(),
        retry_policy=retry_policy or RetryPolicy(max_attempts=1),
        client=client,
        sleep=sleep,
    )


def _async_transport(
    handler: Callable[[httpx.Request], httpx.Response] | Callable[[httpx.Request], Any],
    *,
    provider: _AsyncProvider | None = None,
    retry_policy: RetryPolicy | None = None,
    sleep: Callable[[float], Any] | None = None,
    config: HTTPTransportConfig | None = None,
) -> AsyncHTTPAuthorizationTransport:
    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )
    return AsyncHTTPAuthorizationTransport._for_testing(
        config=config or _config(),
        credential_provider=provider or _AsyncProvider(),
        retry_policy=retry_policy or RetryPolicy(max_attempts=1),
        client=client,
        sleep=sleep,
    )


def test_transport_protocols_are_explicit_and_runtime_checkable() -> None:
    sync = _sync_transport(lambda request: _ok_response(_request()))
    async_transport = _async_transport(lambda request: _ok_response(_request()))
    try:
        assert isinstance(sync, AuthorizationTransport)
        assert isinstance(async_transport, AsyncAuthorizationTransport)
        assert "client" not in inspect.signature(HTTPAuthorizationTransport).parameters
        assert (
            "client"
            not in inspect.signature(AsyncHTTPAuthorizationTransport).parameters
        )
    finally:
        sync.close()
        asyncio.run(async_transport.aclose())


@pytest.mark.parametrize(
    "origin",
    [
        "http://decision.example.test",
        "https://user:password@decision.example.test",
        "https://decision.example.test?next=https://evil.test",
        "https://decision.example.test#secret",
        "https://decision.example.test/a/path",
        "ftp://decision.example.test",
        "https://decision.example.test\\@evil.test",
        "https://decision.example.test:99999",
    ],
)
def test_production_config_rejects_unsafe_origins(origin: str) -> None:
    with pytest.raises(InvalidRequest):
        HTTPTransportConfig(origin=origin)


@pytest.mark.parametrize(
    "origin",
    [
        "http://decision.example.test",
        "http://192.0.2.1",
        "https://127.0.0.1",
    ],
)
def test_local_http_mode_is_explicit_and_loopback_only(origin: str) -> None:
    with pytest.raises(InvalidRequest):
        HTTPTransportConfig.for_local_testing(
            origin=origin,
            testing_only=True,
        )
    with pytest.raises(InvalidRequest):
        HTTPTransportConfig.for_local_testing(
            origin="http://127.0.0.1",
            testing_only=False,
        )


@pytest.mark.parametrize(
    "path",
    [
        "v1/authorization/decisions",
        "//evil.test/decisions",
        "/v1/../admin",
        "/v1/%2e%2e/admin",
        "/v1/%2F%2Fevil.test",
        "/v1/decisions?next=evil",
        "/v1/decisions#fragment",
        "/v1\\decisions",
    ],
)
def test_decision_path_cannot_escape_the_configured_origin(path: str) -> None:
    with pytest.raises(InvalidRequest):
        HTTPTransportConfig(
            origin="https://decision.example.test",
            decision_path=path,
        )


def test_sync_request_owns_auth_headers_body_url_and_timeouts() -> None:
    request = _request()
    seen: list[httpx.Request] = []
    config = HTTPTransportConfig.for_local_testing(
        origin="http://127.0.0.1:9191",
        testing_only=True,
        timeouts=TransportTimeouts(
            connect=1.0,
            read=2.0,
            write=3.0,
            pool=4.0,
        ),
    )

    def handler(incoming: httpx.Request) -> httpx.Response:
        seen.append(incoming)
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json; charset=utf-8"},
            content=_decision_bytes(request),
        )

    transport = _sync_transport(handler, config=config)
    try:
        decision = transport.decide(
            request,
            client_scope_hash=_scope_hash(request),
        )
    finally:
        transport.close()

    assert decision.outcome is wire.DecisionOutcome.ALLOW
    assert len(seen) == 1
    incoming = seen[0]
    assert str(incoming.url) == ("http://127.0.0.1:9191/v1/authorization/decisions")
    assert incoming.method == "POST"
    assert incoming.content == request.to_json_bytes()
    assert incoming.headers["authorization"] == "Bearer transport-secret"
    assert incoming.headers["idempotency-key"] == str(request.idempotency_key)
    assert incoming.headers["content-type"] == "application/json"
    assert incoming.headers["accept"] == "application/json"
    assert incoming.headers["accept-encoding"] == "identity"
    assert incoming.extensions["timeout"] == {
        "connect": 1.0,
        "read": 2.0,
        "write": 3.0,
        "pool": 4.0,
    }


def test_async_request_matches_sync_request_exactly() -> None:
    request = _request()
    sync_seen: list[tuple[str, bytes, dict[str, str]]] = []
    async_seen: list[tuple[str, bytes, dict[str, str]]] = []

    def sync_handler(incoming: httpx.Request) -> httpx.Response:
        sync_seen.append(
            (
                str(incoming.url),
                incoming.content,
                dict(incoming.headers),
            )
        )
        return _ok_response(request)

    async def async_handler(incoming: httpx.Request) -> httpx.Response:
        async_seen.append(
            (
                str(incoming.url),
                incoming.content,
                dict(incoming.headers),
            )
        )
        return _ok_response(request)

    sync = _sync_transport(sync_handler, provider=_SyncProvider("same-token"))
    async_transport = _async_transport(
        async_handler,
        provider=_AsyncProvider("same-token"),
    )
    try:
        sync_decision = sync.decide(
            request,
            client_scope_hash=_scope_hash(request),
        )
        async_decision = asyncio.run(
            async_transport.decide(
                request,
                client_scope_hash=_scope_hash(request),
            )
        )
    finally:
        sync.close()
        asyncio.run(async_transport.aclose())

    assert sync_decision.to_json_bytes() == async_decision.to_json_bytes()
    assert sync_seen == async_seen


@pytest.mark.parametrize(
    ("mutation", "body"),
    [
        ("malformed", b"{not-json"),
        (
            "duplicate",
            b'{"schemaVersion":"1","schemaVersion":"1"}',
        ),
        ("utf8", b"\xff"),
        ("depth", b"[" * 40 + b"]" * 40),
        ("size", b"{" + b" " * wire.MAX_WIRE_BYTES + b"}"),
    ],
)
def test_invalid_response_documents_fail_closed_without_leaks(
    mutation: str,
    body: bytes,
) -> None:
    del mutation
    request = _request()
    secret = "transport-secret"
    url = "http://127.0.0.1:9191/v1/authorization/decisions"
    transport = _sync_transport(
        lambda incoming: httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=body,
        ),
        provider=_SyncProvider(secret),
    )
    try:
        with pytest.raises(InvalidDecision) as captured:
            transport.decide(request, client_scope_hash=_scope_hash(request))
    finally:
        transport.close()
    rendered = f"{captured.value!s} {captured.value!r}"
    assert secret not in rendered
    assert url not in rendered
    body_excerpt = body[:20].decode("utf-8", errors="ignore")
    if body_excerpt:
        assert body_excerpt not in rendered
    assert captured.value.__cause__ is None


@pytest.mark.parametrize(
    ("header_name", "header_value"),
    [
        ("Content-Type", "text/plain"),
        ("Content-Type", "application/problem+json"),
        ("Content-Encoding", "gzip"),
        ("Content-Encoding", "br"),
        ("Content-Length", str(wire.MAX_WIRE_BYTES + 1)),
    ],
)
def test_response_metadata_cannot_bypass_wire_bounds(
    header_name: str,
    header_value: str,
) -> None:
    request = _request()
    headers = {
        "Content-Type": "application/json",
        header_name: header_value,
    }
    transport = _sync_transport(
        lambda incoming: httpx.Response(
            200,
            headers=headers,
            content=_decision_bytes(request),
        )
    )
    try:
        with pytest.raises(InvalidDecision) as captured:
            transport.decide(request, client_scope_hash=_scope_hash(request))
    finally:
        transport.close()
    assert captured.value.__context__ is None


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("requestId", "req_01J5ABCDEFGHJKMNPQRSTVWXY9"),
        ("correlationId", "corr_01J5ABCDEFGHJKMNPQRSTVWXY9"),
        (
            "clientScopeHash",
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
        ),
        ("serverTime", "2026-07-25T20:05:00Z"),
        ("serverTime", "2026-02-30T20:00:00Z"),
    ],
)
def test_decision_is_bound_to_request_scope_and_valid_time_order(
    field: str,
    value: str,
) -> None:
    request = _request()
    document = _decision_document(request)
    document[field] = value
    transport = _sync_transport(lambda incoming: httpx.Response(200, json=document))
    try:
        with pytest.raises(InvalidDecision):
            transport.decide(request, client_scope_hash=_scope_hash(request))
    finally:
        transport.close()


def test_caller_scope_hash_must_itself_match_the_action() -> None:
    request = _request()
    wrong_hash = (
        "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
    )
    calls = 0

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _ok_response(request)

    transport = _sync_transport(handler)
    try:
        with pytest.raises(InvalidRequest):
            transport.decide(request, client_scope_hash=wrong_hash)
    finally:
        transport.close()
    assert calls == 0


def test_trusted_authoritative_hash_is_returned_but_never_caller_selected() -> None:
    request = _request()
    document = _decision_document(request)
    authority_hash = document["authoritativeScopeHash"]
    transport = _sync_transport(lambda incoming: httpx.Response(200, json=document))
    try:
        decision = transport.decide(
            request,
            client_scope_hash=_scope_hash(request),
        )
    finally:
        transport.close()
    assert str(decision.authoritative_scope_hash) == authority_hash
    assert (
        "authoritative_scope_hash" not in inspect.signature(transport.decide).parameters
    )


def test_credential_failure_never_falls_back_or_calls_the_network() -> None:
    request = _request()
    calls = 0
    provider = _SyncProvider(failure=RuntimeError("provider-secret"))

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _ok_response(request)

    transport = _sync_transport(handler, provider=provider)
    try:
        with pytest.raises(AuthenticationFailed) as captured:
            transport.decide(request, client_scope_hash=_scope_hash(request))
    finally:
        transport.close()
    assert calls == 0
    assert provider.calls == 1
    assert "provider-secret" not in str(captured.value)
    assert captured.value.__context__ is None


def test_authorization_retry_reuses_exact_attempt_bytes_and_identity() -> None:
    request = _request()
    attempts: list[tuple[bytes, str, str, str | None]] = []
    sleeps: list[float] = []
    provider = _SyncProvider()
    retry = RetryPolicy._for_testing(
        random_source=lambda: 0.5,
        max_attempts=2,
        initial_delay=0.0,
    )

    def handler(incoming: httpx.Request) -> httpx.Response:
        attempts.append(
            (
                incoming.content,
                incoming.headers["idempotency-key"],
                incoming.headers["authorization"],
                incoming.headers.get("cookie"),
            )
        )
        if len(attempts) == 1:
            return httpx.Response(
                503,
                headers={
                    "Content-Type": "application/json",
                    "Retry-After": "0",
                    "Set-Cookie": "fallback_identity=server-selected",
                },
                content=b'{"not":"a trusted protocol error"}',
            )
        return _ok_response(request)

    transport = _sync_transport(
        handler,
        provider=provider,
        retry_policy=retry,
        sleep=sleeps.append,
    )
    try:
        decision = transport.decide(
            request,
            client_scope_hash=_scope_hash(request),
        )
    finally:
        transport.close()
    assert decision.outcome is wire.DecisionOutcome.ALLOW
    assert attempts == [attempts[0], attempts[0]]
    assert provider.calls == 1
    assert sleeps == [0.0]


def test_valid_nonretryable_protocol_error_maps_to_safe_typed_error() -> None:
    request = _request()
    document = json.loads(ERROR_VECTOR.read_text(encoding="utf-8"))
    document.update(
        {
            "code": "authentication_failed",
            "safeMessage": "Authentication failed.",
            "retryable": False,
            "actionId": str(request.action_id),
            "requestId": str(request.request_id),
            "correlationId": str(request.correlation_id),
        }
    )
    transport = _sync_transport(lambda incoming: httpx.Response(401, json=document))
    try:
        with pytest.raises(AuthenticationFailed) as captured:
            transport.decide(request, client_scope_hash=_scope_hash(request))
    finally:
        transport.close()
    assert captured.value.request_id == str(request.request_id)
    assert captured.value.correlation_id == str(request.correlation_id)


def test_mismatched_or_semantically_invalid_protocol_error_is_rejected() -> None:
    request = _request()
    document = json.loads(ERROR_VECTOR.read_text(encoding="utf-8"))
    document.update(
        {
            "requestId": "req_01J5ABCDEFGHJKMNPQRSTVWXY9",
            "correlationId": str(request.correlation_id),
            "safeMessage": "server body secret",
        }
    )
    transport = _sync_transport(lambda incoming: httpx.Response(503, json=document))
    try:
        with pytest.raises(AuthorizationUnavailable) as captured:
            transport.decide(request, client_scope_hash=_scope_hash(request))
    finally:
        transport.close()
    assert "server body secret" not in str(captured.value)


def test_redirect_is_not_followed_even_when_it_targets_https_or_http() -> None:
    request = _request()
    calls: list[str] = []

    def handler(incoming: httpx.Request) -> httpx.Response:
        calls.append(str(incoming.url))
        return httpx.Response(
            307,
            headers={"Location": "http://evil.test/stolen"},
        )

    transport = _sync_transport(handler)
    try:
        with pytest.raises(InvalidDecision):
            transport.decide(request, client_scope_hash=_scope_hash(request))
    finally:
        transport.close()
    assert calls == ["http://127.0.0.1:9191/v1/authorization/decisions"]


@pytest.mark.parametrize(
    "failure",
    [
        httpx.ConnectError("secret https://internal.test"),
        httpx.ReadTimeout("secret https://internal.test"),
        httpx.RemoteProtocolError("server-secret"),
    ],
)
def test_network_failures_become_safe_authorization_unavailable(
    failure: httpx.RequestError,
) -> None:
    request = _request()

    def handler(incoming: httpx.Request) -> httpx.Response:
        raise failure

    transport = _sync_transport(handler)
    try:
        with pytest.raises(AuthorizationUnavailable) as captured:
            transport.decide(request, client_scope_hash=_scope_hash(request))
    finally:
        transport.close()
    rendered = f"{captured.value!s} {captured.value!r}"
    assert "internal.test" not in rendered
    assert "server-secret" not in rendered
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


@pytest.mark.parametrize(
    ("body", "headers"),
    [
        (b"{not-json", {"Content-Type": "application/json"}),
        (
            b'{"schemaVersion":"1","schemaVersion":"1"}',
            {"Content-Type": "application/json"},
        ),
        (b"\xff", {"Content-Type": "application/json"}),
        (_decision_bytes(_request()), {"Content-Type": "text/plain"}),
        (
            _decision_bytes(_request()),
            {"Content-Type": "application/json", "Content-Encoding": "gzip"},
        ),
        (
            _decision_bytes(_request()),
            {
                "Content-Type": "application/json",
                "Content-Length": str(wire.MAX_WIRE_BYTES + 1),
            },
        ),
    ],
)
def test_async_malformed_oversize_and_metadata_fail_closed(
    body: bytes,
    headers: dict[str, str],
) -> None:
    request = _request()

    async def exercise() -> None:
        async def handler(incoming: httpx.Request) -> httpx.Response:
            del incoming
            return httpx.Response(200, headers=headers, content=body)

        transport = _async_transport(handler)
        try:
            with pytest.raises(InvalidDecision) as captured:
                await transport.decide(
                    request,
                    client_scope_hash=_scope_hash(request),
                )
        finally:
            await transport.aclose()
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None

    asyncio.run(exercise())


@pytest.mark.parametrize(
    ("kind", "expected"),
    [
        ("binding", InvalidDecision),
        ("redirect", InvalidDecision),
        ("network", AuthorizationUnavailable),
    ],
)
def test_async_binding_redirect_and_network_fail_closed(
    kind: str,
    expected: type[Exception],
) -> None:
    request = _request()

    async def exercise() -> None:
        async def handler(incoming: httpx.Request) -> httpx.Response:
            del incoming
            if kind == "binding":
                document = _decision_document(request)
                document["requestId"] = "req_01J5ABCDEFGHJKMNPQRSTVWXY9"
                return httpx.Response(200, json=document)
            if kind == "redirect":
                return httpx.Response(
                    307,
                    headers={"Location": "http://evil.test/stolen"},
                )
            raise httpx.ReadTimeout("secret https://internal.test")

        transport = _async_transport(handler)
        try:
            with pytest.raises(expected) as captured:
                await transport.decide(
                    request,
                    client_scope_hash=_scope_hash(request),
                )
        finally:
            await transport.aclose()
        rendered = f"{captured.value!s} {captured.value!r}"
        assert "internal.test" not in rendered
        assert "evil.test" not in rendered
        assert captured.value.__cause__ is None
        assert captured.value.__context__ is None

    asyncio.run(exercise())


def test_async_credential_failure_makes_no_request_and_retry_reuses_attempt() -> None:
    request = _request()

    async def exercise() -> None:
        calls = 0

        async def forbidden(incoming: httpx.Request) -> httpx.Response:
            nonlocal calls
            del incoming
            calls += 1
            return _ok_response(request)

        failed = _async_transport(
            forbidden,
            provider=_AsyncProvider(failure=RuntimeError("provider-secret")),
        )
        try:
            with pytest.raises(AuthenticationFailed) as captured:
                await failed.decide(
                    request,
                    client_scope_hash=_scope_hash(request),
                )
        finally:
            await failed.aclose()
        assert calls == 0
        assert "provider-secret" not in str(captured.value)
        assert captured.value.__context__ is None

        attempts: list[tuple[bytes, str, str | None]] = []

        async def retrying(incoming: httpx.Request) -> httpx.Response:
            attempts.append(
                (
                    incoming.content,
                    incoming.headers["idempotency-key"],
                    incoming.headers.get("cookie"),
                )
            )
            if len(attempts) == 1:
                return httpx.Response(
                    503,
                    headers={"Retry-After": "0", "Set-Cookie": "identity=bad"},
                )
            return _ok_response(request)

        retry = RetryPolicy._for_testing(
            random_source=lambda: 0.5,
            max_attempts=2,
            initial_delay=0.0,
        )
        transport = _async_transport(retrying, retry_policy=retry)
        try:
            decision = await transport.decide(
                request,
                client_scope_hash=_scope_hash(request),
            )
        finally:
            await transport.aclose()
        assert decision.outcome is wire.DecisionOutcome.ALLOW
        assert attempts == [attempts[0], attempts[0]]

    asyncio.run(exercise())


def test_async_protocol_error_binding_maps_only_a_valid_safe_error() -> None:
    request = _request()

    async def exercise() -> None:
        document = json.loads(ERROR_VECTOR.read_text(encoding="utf-8"))
        document.update(
            {
                "code": "authentication_failed",
                "safeMessage": "Authentication failed.",
                "retryable": False,
                "actionId": str(request.action_id),
                "requestId": str(request.request_id),
                "correlationId": str(request.correlation_id),
            }
        )

        async def handler(incoming: httpx.Request) -> httpx.Response:
            del incoming
            return httpx.Response(401, json=document)

        transport = _async_transport(handler)
        try:
            with pytest.raises(AuthenticationFailed) as captured:
                await transport.decide(
                    request,
                    client_scope_hash=_scope_hash(request),
                )
        finally:
            await transport.aclose()
        assert captured.value.request_id == str(request.request_id)
        assert captured.value.correlation_id == str(request.correlation_id)
        assert captured.value.__context__ is None

    asyncio.run(exercise())


def test_sync_cancellation_stops_before_credentials_or_network() -> None:
    request = _request()
    provider = _SyncProvider()
    calls = 0

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return _ok_response(request)

    transport = _sync_transport(handler, provider=provider)
    try:
        with pytest.raises(concurrent.futures.CancelledError):
            transport.decide(
                request,
                client_scope_hash=_scope_hash(request),
                cancelled=lambda: True,
            )
    finally:
        transport.close()
    assert provider.calls == 0
    assert calls == 0


def test_sync_cancellation_after_response_cannot_release_a_decision() -> None:
    request = _request()
    cancellation = False

    def handler(incoming: httpx.Request) -> httpx.Response:
        nonlocal cancellation
        cancellation = True
        return _ok_response(request)

    transport = _sync_transport(handler)
    try:
        with pytest.raises(concurrent.futures.CancelledError):
            transport.decide(
                request,
                client_scope_hash=_scope_hash(request),
                cancelled=lambda: cancellation,
            )
    finally:
        transport.close()


def test_deadline_bounds_each_http_timeout_and_is_rechecked_after_io() -> None:
    request = _request()
    seen_timeout: dict[str, float] = {}
    start = time.monotonic()
    clock_values = iter((start, start, start + 2.0))

    def handler(incoming: httpx.Request) -> httpx.Response:
        seen_timeout.update(incoming.extensions["timeout"])
        return _ok_response(request)

    async def async_handler(incoming: httpx.Request) -> httpx.Response:
        return handler(incoming)

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(async_handler),
        follow_redirects=False,
        trust_env=False,
    )
    transport = HTTPAuthorizationTransport._for_testing(
        config=_config(),
        credential_provider=_SyncProvider(),
        retry_policy=RetryPolicy(max_attempts=1),
        client=client,
        monotonic=lambda: next(clock_values),
    )
    try:
        with pytest.raises(concurrent.futures.CancelledError):
            transport.decide(
                request,
                client_scope_hash=_scope_hash(request),
                deadline=start + 1.0,
            )
    finally:
        transport.close()
    assert seen_timeout == {
        "connect": 1.0,
        "read": 1.0,
        "write": 1.0,
        "pool": 1.0,
    }


def test_sync_absolute_deadline_stops_a_trickled_body_and_closes_stream() -> None:
    request = _request()
    body = _decision_bytes(request)
    stream = _SlowAsyncStream(body, chunks=20, interval=0.015)

    def handler(incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
        )

    transport = _sync_transport(handler)
    started = time.monotonic()
    try:
        with pytest.raises(concurrent.futures.CancelledError):
            transport.decide(
                request,
                client_scope_hash=_scope_hash(request),
                deadline=started + 0.04,
            )
    finally:
        transport.close()
    elapsed = time.monotonic() - started
    assert elapsed < 0.15
    assert stream.emitted < 20
    assert stream.closed.is_set()


def test_sync_deadline_cancels_slow_headers_and_close_joins_runtime_thread() -> None:
    request = _request()
    handler_cancelled = threading.Event()

    async def handler(incoming: httpx.Request) -> httpx.Response:
        del incoming
        try:
            await asyncio.Event().wait()
        finally:
            handler_cancelled.set()
        return _ok_response(request)

    client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
        trust_env=False,
    )
    transport = HTTPAuthorizationTransport._for_testing(
        config=_config(),
        credential_provider=_SyncProvider(),
        retry_policy=RetryPolicy(max_attempts=1),
        client=client,
    )
    runtime_thread = transport._runtime._thread
    started = time.monotonic()
    try:
        with pytest.raises(concurrent.futures.CancelledError):
            transport.decide(
                request,
                client_scope_hash=_scope_hash(request),
                deadline=started + 0.03,
            )
        assert handler_cancelled.wait(timeout=0.05)
    finally:
        transport.close()
    assert time.monotonic() - started < 0.15
    assert not runtime_thread.is_alive()


def test_async_task_cancellation_propagates_promptly() -> None:
    request = _request()
    started = asyncio.Event()

    async def handler(incoming: httpx.Request) -> httpx.Response:
        started.set()
        await asyncio.sleep(60)
        return _ok_response(request)

    async def exercise() -> None:
        transport = _async_transport(handler)
        try:
            pending = asyncio.create_task(
                transport.decide(
                    request,
                    client_scope_hash=_scope_hash(request),
                )
            )
            await asyncio.wait_for(started.wait(), timeout=1)
            pending.cancel()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(pending, timeout=1)
        finally:
            await transport.aclose()

    asyncio.run(exercise())


def test_async_absolute_deadline_cancels_slow_headers_and_drains_handler() -> None:
    request = _request()
    handler_started = asyncio.Event()
    handler_cancelled = asyncio.Event()

    async def handler(incoming: httpx.Request) -> httpx.Response:
        handler_started.set()
        try:
            await asyncio.Event().wait()
        finally:
            handler_cancelled.set()
        return _ok_response(request)

    async def exercise() -> None:
        transport = _async_transport(handler)
        started = time.monotonic()
        try:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(
                    transport.decide(
                        request,
                        client_scope_hash=_scope_hash(request),
                        deadline=started + 0.03,
                    ),
                    timeout=0.2,
                )
            await asyncio.wait_for(handler_cancelled.wait(), timeout=0.05)
            assert time.monotonic() - started < 0.12
        finally:
            await transport.aclose()

    asyncio.run(exercise())


def test_async_absolute_deadline_stops_trickle_and_closes_stream() -> None:
    request = _request()
    stream = _SlowAsyncStream(
        _decision_bytes(request),
        chunks=20,
        interval=0.015,
    )

    async def handler(incoming: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            stream=stream,
        )

    async def exercise() -> None:
        transport = _async_transport(handler)
        started = time.monotonic()
        try:
            with pytest.raises(asyncio.CancelledError):
                await transport.decide(
                    request,
                    client_scope_hash=_scope_hash(request),
                    deadline=started + 0.04,
                )
        finally:
            await transport.aclose()
        assert time.monotonic() - started < 0.15
        assert stream.emitted < 20
        assert stream.closed.is_set()

    asyncio.run(exercise())


def test_async_callback_cancels_inflight_headers_and_drains_handler() -> None:
    request = _request()

    async def exercise() -> None:
        handler_started = asyncio.Event()
        handler_cancelled = asyncio.Event()
        cancellation = False

        async def handler(incoming: httpx.Request) -> httpx.Response:
            del incoming
            handler_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                handler_cancelled.set()
            return _ok_response(request)

        transport = _async_transport(handler)
        pending = asyncio.create_task(
            transport.decide(
                request,
                client_scope_hash=_scope_hash(request),
                cancelled=lambda: cancellation,
            )
        )
        try:
            await asyncio.wait_for(handler_started.wait(), timeout=0.1)
            cancellation = True
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(pending, timeout=0.15)
            await asyncio.wait_for(handler_cancelled.wait(), timeout=0.05)
        finally:
            pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
            await transport.aclose()

    asyncio.run(exercise())


def test_sync_close_and_context_management_are_idempotent_and_fail_closed() -> None:
    request = _request()
    transport = _sync_transport(lambda incoming: _ok_response(request))
    with transport as entered:
        assert entered is transport
    transport.close()
    with pytest.raises(AuthorizationUnavailable):
        transport.decide(request, client_scope_hash=_scope_hash(request))


def test_async_close_and_context_management_are_idempotent_and_fail_closed() -> None:
    request = _request()

    async def exercise() -> None:
        transport = _async_transport(
            lambda incoming: httpx.Response(
                200,
                content=_decision_bytes(request),
            )
        )
        async with transport as entered:
            assert entered is transport
        await transport.aclose()
        with pytest.raises(AuthorizationUnavailable):
            await transport.decide(
                request,
                client_scope_hash=_scope_hash(request),
            )

    asyncio.run(exercise())


def test_public_clients_force_tls_verification_and_ignore_proxy_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured_clients: list[dict[str, Any]] = []
    real_async = httpx.AsyncClient

    def forbidden_sync_factory(**kwargs: Any) -> Any:
        del kwargs
        raise AssertionError("sync HTTPX cannot enforce a total deadline")

    def async_factory(**kwargs: Any) -> httpx.AsyncClient:
        captured_clients.append(dict(kwargs))
        return real_async(
            transport=httpx.MockTransport(lambda request: httpx.Response(500)),
            trust_env=False,
        )

    monkeypatch.setattr(
        "palonexus.transports.http.httpx.Client",
        forbidden_sync_factory,
    )
    monkeypatch.setattr(
        "palonexus.transports.http.httpx.AsyncClient",
        async_factory,
    )
    sync = HTTPAuthorizationTransport(
        config=HTTPTransportConfig(
            origin="https://decision.example.test",
        ),
        credential_provider=_SyncProvider(),
        retry_policy=RetryPolicy(max_attempts=1),
    )
    async_transport = AsyncHTTPAuthorizationTransport(
        config=HTTPTransportConfig(
            origin="https://decision.example.test",
        ),
        credential_provider=_AsyncProvider(),
        retry_policy=RetryPolicy(max_attempts=1),
    )
    sync.close()
    asyncio.run(async_transport.aclose())
    assert len(captured_clients) == 2
    for captured in captured_clients:
        assert captured["verify"] is True
        assert captured["trust_env"] is False
        assert captured["follow_redirects"] is False
        assert "proxy" not in captured
