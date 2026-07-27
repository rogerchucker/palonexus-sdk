# SPDX-License-Identifier: MIT
"""Shared behavioral contract for synchronous and asynchronous clients."""

from __future__ import annotations

import asyncio
import concurrent.futures
import copy
import json
import pickle
import threading
import time
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import httpx
import pytest
from palonexus import (
    ApprovalRequired,
    AsyncAuthorizationClient,
    AuthorizationClient,
    AuthorizationDecision,
    AuthorizationUnavailable,
    DecisionOutcome,
    InvalidDecision,
    PolicyDenied,
    RetryPolicy,
    _canonicalize,
)
from palonexus._generated import protocol as wire
from palonexus.credentials import Credential
from palonexus.transports import (
    AsyncHTTPAuthorizationTransport,
    HTTPAuthorizationTransport,
    HTTPTransportConfig,
)

ROOT = Path(__file__).parents[2]
ACTION_VECTOR = ROOT / "protocol/test-vectors/action/valid/file-write.json"
DECISION_VECTOR = ROOT / "protocol/test-vectors/decision/valid/allow.json"


@dataclass(frozen=True)
class _Attempt:
    request: wire.ActionRequest
    client_scope_hash: str


class _SyncTransport:
    def __init__(
        self,
        result: wire.AuthorizationDecision | BaseException | object,
    ) -> None:
        self.result = result
        self.calls: list[tuple[bytes, str, float | None, bool]] = []
        self.close_calls = 0

    def decide(
        self,
        request: wire.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Any = None,
    ) -> wire.AuthorizationDecision:
        self.calls.append(
            (
                request.to_json_bytes(),
                client_scope_hash,
                deadline,
                cancelled is not None,
            )
        )
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result  # type: ignore[return-value]

    def close(self) -> None:
        self.close_calls += 1


class _AsyncTransport:
    def __init__(
        self,
        result: wire.AuthorizationDecision | BaseException | object,
    ) -> None:
        self.result = result
        self.calls: list[tuple[bytes, str, float | None, bool]] = []
        self.close_calls = 0

    async def decide(
        self,
        request: wire.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Any = None,
    ) -> wire.AuthorizationDecision:
        self.calls.append(
            (
                request.to_json_bytes(),
                client_scope_hash,
                deadline,
                cancelled is not None,
            )
        )
        if isinstance(self.result, BaseException):
            raise self.result
        return self.result  # type: ignore[return-value]

    async def aclose(self) -> None:
        self.close_calls += 1


class _SyncCredentialProvider:
    def get_credential(
        self,
        *,
        deadline: float | None = None,
        cancelled: Any = None,
    ) -> Credential:
        del deadline, cancelled
        return Credential(
            "real-retry-credential",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


class _AsyncCredentialProvider:
    async def get_credential(
        self,
        *,
        deadline: float | None = None,
        cancelled: Any = None,
    ) -> Credential:
        del deadline, cancelled
        return Credential(
            "real-retry-credential",
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )


type _HTTPAttempt = tuple[bytes, str, str, str | None, str]


class _CountingSyncHTTPTransport:
    def __init__(self, transport: HTTPAuthorizationTransport) -> None:
        self._transport = transport
        self.calls: list[tuple[bytes, str, float | None, bool]] = []

    def decide(
        self,
        request: wire.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Any = None,
    ) -> wire.AuthorizationDecision:
        self.calls.append(
            (
                request.to_json_bytes(),
                client_scope_hash,
                deadline,
                cancelled is not None,
            )
        )
        return self._transport.decide(
            request,
            client_scope_hash=client_scope_hash,
            deadline=deadline,
            cancelled=cancelled,
        )

    def close(self) -> None:
        self._transport.close()


class _CountingAsyncHTTPTransport:
    def __init__(self, transport: AsyncHTTPAuthorizationTransport) -> None:
        self._transport = transport
        self.calls: list[tuple[bytes, str, float | None, bool]] = []

    async def decide(
        self,
        request: wire.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Any = None,
    ) -> wire.AuthorizationDecision:
        self.calls.append(
            (
                request.to_json_bytes(),
                client_scope_hash,
                deadline,
                cancelled is not None,
            )
        )
        return await self._transport.decide(
            request,
            client_scope_hash=client_scope_hash,
            deadline=deadline,
            cancelled=cancelled,
        )

    async def aclose(self) -> None:
        await self._transport.aclose()


def _http_trace(request: httpx.Request) -> _HTTPAttempt:
    return (
        request.content,
        request.headers["idempotency-key"],
        request.headers["authorization"],
        request.headers.get("cookie"),
        request.headers["x-palonexus-protocol-version"],
    )


def _real_retry_transports() -> tuple[
    _CountingSyncHTTPTransport,
    _CountingAsyncHTTPTransport,
    list[_HTTPAttempt],
    list[_HTTPAttempt],
]:
    sync_attempts: list[_HTTPAttempt] = []
    async_attempts: list[_HTTPAttempt] = []

    async def sync_handler(request: httpx.Request) -> httpx.Response:
        sync_attempts.append(_http_trace(request))
        if len(sync_attempts) == 1:
            return httpx.Response(
                503,
                headers={"Retry-After": "0"},
                content=b'{"transient":true}',
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=_decision("allow").to_json_bytes(),
        )

    async def async_handler(request: httpx.Request) -> httpx.Response:
        async_attempts.append(_http_trace(request))
        if len(async_attempts) == 1:
            return httpx.Response(
                503,
                headers={"Retry-After": "0"},
                content=b'{"transient":true}',
            )
        return httpx.Response(
            200,
            headers={"Content-Type": "application/json"},
            content=_decision("allow").to_json_bytes(),
        )

    config = HTTPTransportConfig.for_local_testing(
        origin="http://127.0.0.1:9191",
        testing_only=True,
    )
    retry = RetryPolicy._for_testing(
        random_source=lambda: 0.5,
        max_attempts=2,
        initial_delay=0.0,
    )
    sync_http = HTTPAuthorizationTransport._for_testing(
        config=config,
        credential_provider=_SyncCredentialProvider(),
        retry_policy=retry,
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(sync_handler),
            follow_redirects=False,
            trust_env=False,
        ),
    )
    async_http = AsyncHTTPAuthorizationTransport._for_testing(
        config=config,
        credential_provider=_AsyncCredentialProvider(),
        retry_policy=retry,
        client=httpx.AsyncClient(
            transport=httpx.MockTransport(async_handler),
            follow_redirects=False,
            trust_env=False,
        ),
    )
    return (
        _CountingSyncHTTPTransport(sync_http),
        _CountingAsyncHTTPTransport(async_http),
        sync_attempts,
        async_attempts,
    )


def _attempt() -> _Attempt:
    request = wire.parse_action_json(ACTION_VECTOR.read_bytes())
    return _Attempt(
        request=request,
        client_scope_hash=_canonicalize.client_scope_hash(request.to_dict()),
    )


def _decision(
    outcome: Literal["allow", "deny", "approval_required"] = "allow",
) -> wire.AuthorizationDecision:
    attempt = _attempt()
    document = json.loads(DECISION_VECTOR.read_text(encoding="utf-8"))
    document["requestId"] = str(attempt.request.request_id)
    document["correlationId"] = str(attempt.request.correlation_id)
    document["clientScopeHash"] = attempt.client_scope_hash
    document["outcome"] = outcome
    if outcome == "approval_required":
        document["approval"] = {
            "approvalId": f"apr_{'1' * 26}",
            "status": "pending",
            "expiresAt": document["expiresAt"],
        }
    else:
        document.pop("approval", None)
    return wire.parse_decision(document)


async def _async_decide(
    result: object,
) -> tuple[AuthorizationDecision, _AsyncTransport]:
    transport = _AsyncTransport(result)
    client = AsyncAuthorizationClient(transport)
    return await client.decide(_attempt()), transport


def _sync_decide(result: object) -> tuple[AuthorizationDecision, _SyncTransport]:
    transport = _SyncTransport(result)
    client = AuthorizationClient(transport)
    return client.decide(_attempt()), transport


@pytest.mark.parametrize("outcome", ["allow", "deny", "approval_required"])
def test_decide_has_sync_async_parity_and_byte_equivalent_requests(
    outcome: Literal["allow", "deny", "approval_required"],
) -> None:
    raw = _decision(outcome)
    sync_decision, sync_transport = _sync_decide(raw)
    async_decision, async_transport = asyncio.run(_async_decide(raw))

    assert sync_decision == async_decision
    assert sync_decision.outcome is DecisionOutcome(outcome)
    assert sync_transport.calls == async_transport.calls
    assert sync_transport.calls[0][0] == _attempt().request.to_json_bytes()
    with pytest.raises((AttributeError, TypeError)):
        sync_decision.outcome = DecisionOutcome.DENY  # type: ignore[misc]


@pytest.mark.parametrize(
    ("outcome", "error_type"),
    [
        ("deny", PolicyDenied),
        ("approval_required", ApprovalRequired),
    ],
)
def test_authorize_fails_closed_with_equivalent_typed_outcome_errors(
    outcome: Literal["deny", "approval_required"],
    error_type: type[BaseException],
) -> None:
    raw = _decision(outcome)
    sync_transport = _SyncTransport(raw)
    async_transport = _AsyncTransport(raw)

    with pytest.raises(error_type) as sync_error:
        AuthorizationClient(sync_transport).authorize(_attempt())

    async def run() -> None:
        with pytest.raises(error_type) as async_error:
            await AsyncAuthorizationClient(async_transport).authorize(_attempt())
        assert type(sync_error.value) is type(async_error.value)
        assert str(sync_error.value) == str(async_error.value)

    asyncio.run(run())
    assert len(sync_transport.calls) == len(async_transport.calls) == 1


def test_authorize_returns_only_an_allow_decision() -> None:
    raw = _decision()
    sync, _ = _sync_decide(raw)
    transport = _SyncTransport(raw)
    assert AuthorizationClient(transport).authorize(_attempt()) == sync


@pytest.mark.parametrize(
    "failure",
    [
        InvalidDecision(request_id=f"req_{'1' * 26}"),
        AuthorizationUnavailable(request_id=f"req_{'1' * 26}"),
    ],
)
def test_transport_failures_are_preserved_without_client_retry(
    failure: BaseException,
) -> None:
    sync_transport = _SyncTransport(failure)
    async_transport = _AsyncTransport(failure)
    with pytest.raises(type(failure)) as sync_error:
        AuthorizationClient(sync_transport).decide(_attempt())

    async def run() -> None:
        with pytest.raises(type(failure)) as async_error:
            await AsyncAuthorizationClient(async_transport).decide(_attempt())
        assert async_error.value is failure

    asyncio.run(run())
    assert sync_error.value is failure
    assert len(sync_transport.calls) == len(async_transport.calls) == 1


def test_malformed_transport_result_fails_closed_without_leaking_it() -> None:
    secret = "transport-secret-that-must-not-leak"
    malformed = {"secret": secret}
    with pytest.raises(InvalidDecision) as sync_error:
        _sync_decide(malformed)
    with pytest.raises(InvalidDecision) as async_error:
        asyncio.run(_async_decide(malformed))
    assert secret not in str(sync_error.value)
    assert str(sync_error.value) == str(async_error.value)


def test_cancellation_is_never_translated_or_retried() -> None:
    sync_cancel = concurrent.futures.CancelledError()
    sync_transport = _SyncTransport(sync_cancel)
    with pytest.raises(concurrent.futures.CancelledError) as caught:
        AuthorizationClient(sync_transport).decide(_attempt())
    assert caught.value is sync_cancel

    async def run() -> None:
        async_cancel = asyncio.CancelledError()
        transport = _AsyncTransport(async_cancel)
        with pytest.raises(asyncio.CancelledError) as async_caught:
            await AsyncAuthorizationClient(transport).decide(_attempt())
        assert async_caught.value is async_cancel
        assert len(transport.calls) == 1

    asyncio.run(run())
    assert len(sync_transport.calls) == 1


def test_context_management_and_ownership_are_explicit_and_idempotent() -> None:
    borrowed_sync = _SyncTransport(_decision())
    with AuthorizationClient(borrowed_sync):
        pass
    assert borrowed_sync.close_calls == 0
    owned_sync = _SyncTransport(_decision())
    client = AuthorizationClient(owned_sync, owns_transport=True)
    with client:
        pass
    client.close()
    assert owned_sync.close_calls == 1
    with pytest.raises(AuthorizationUnavailable):
        client.decide(_attempt())

    async def run() -> None:
        borrowed_async = _AsyncTransport(_decision())
        async with AsyncAuthorizationClient(borrowed_async):
            pass
        assert borrowed_async.close_calls == 0
        owned_async = _AsyncTransport(_decision())
        client = AsyncAuthorizationClient(owned_async, owns_transport=True)
        async with client:
            pass
        await client.aclose()
        assert owned_async.close_calls == 1
        with pytest.raises(AuthorizationUnavailable):
            await client.decide(_attempt())

    asyncio.run(run())


def test_deadline_and_cancellation_hook_are_forwarded_without_mutation() -> None:
    attempt = _attempt()

    def cancelled() -> bool:
        return False

    sync_transport = _SyncTransport(_decision())
    AuthorizationClient(sync_transport).decide(
        attempt,
        deadline=42.5,
        cancelled=cancelled,
    )

    async def run() -> _AsyncTransport:
        transport = _AsyncTransport(_decision())
        await AsyncAuthorizationClient(transport).decide(
            attempt,
            deadline=42.5,
            cancelled=cancelled,
        )
        return transport

    async_transport = asyncio.run(run())
    assert sync_transport.calls == async_transport.calls


def test_public_exports_include_clients_and_decision_only() -> None:
    import palonexus

    assert "AuthorizationClient" in palonexus.__all__
    assert "AsyncAuthorizationClient" in palonexus.__all__
    assert "AuthorizationDecision" in palonexus.__all__


@pytest.mark.parametrize(
    "scenario",
    [
        "allow",
        "deny",
        "approval",
        "malformed",
        "outage",
        "retry_success",
        "close",
        "cancellation",
    ],
)
def test_shared_sync_async_scenario_matrix(scenario: str) -> None:
    """One harness proves the required public sync/async behavior matrix."""

    attempt = _attempt()
    if scenario == "allow":
        result: object = _decision("allow")
        operation = "decide"
    elif scenario == "deny":
        result = _decision("deny")
        operation = "authorize"
    elif scenario == "approval":
        result = _decision("approval_required")
        operation = "authorize"
    elif scenario == "malformed":
        result = object()
        operation = "decide"
    elif scenario == "outage":
        result = AuthorizationUnavailable(request_id=attempt.request.request_id)
        operation = "decide"
    elif scenario == "cancellation":
        result = concurrent.futures.CancelledError()
        operation = "decide"
    else:
        result = _decision("allow")
        operation = "decide"

    sync_transport: Any
    async_transport: Any
    if scenario == "retry_success":
        (
            sync_transport,
            async_transport,
            sync_http_attempts,
            async_http_attempts,
        ) = _real_retry_transports()
    else:
        sync_transport = _SyncTransport(result)
        async_transport = _AsyncTransport(
            asyncio.CancelledError() if scenario == "cancellation" else result
        )
    sync_client = AuthorizationClient(
        sync_transport,
        owns_transport=scenario == "close",
    )
    async_client = AsyncAuthorizationClient(
        async_transport,
        owns_transport=scenario == "close",
    )

    sync_value: AuthorizationDecision | None = None
    sync_failure: BaseException | None = None
    try:
        sync_value = getattr(sync_client, operation)(attempt)
    except BaseException as error:
        sync_failure = error
    if scenario == "retry_success":
        sync_transport.close()
    if scenario == "close":
        sync_client.close()
        sync_client.close()

    async def run() -> tuple[AuthorizationDecision | None, BaseException | None]:
        value: AuthorizationDecision | None = None
        failure: BaseException | None = None
        try:
            value = await getattr(async_client, operation)(attempt)
        except BaseException as error:
            failure = error
        if scenario == "close":
            await async_client.aclose()
            await async_client.aclose()
        if scenario == "retry_success":
            await async_transport.aclose()
        return value, failure

    async_value, async_failure = asyncio.run(run())
    assert sync_value == async_value
    if sync_failure is not None or async_failure is not None:
        assert sync_failure is not None and async_failure is not None
        if scenario == "cancellation":
            assert isinstance(sync_failure, concurrent.futures.CancelledError)
            assert isinstance(async_failure, asyncio.CancelledError)
        else:
            assert type(sync_failure) is type(async_failure)
            assert str(sync_failure) == str(async_failure)
    assert sync_transport.calls == async_transport.calls
    if scenario == "retry_success":
        assert len(sync_transport.calls) == len(async_transport.calls) == 1
        assert len(sync_http_attempts) == len(async_http_attempts) == 2
        assert sync_http_attempts == async_http_attempts
        assert sync_http_attempts == [sync_http_attempts[0], sync_http_attempts[0]]
    if scenario == "close":
        assert sync_transport.close_calls == async_transport.close_calls == 1


def test_public_decisions_cannot_be_forged_copied_or_unpickled() -> None:
    trusted, _ = _sync_decide(_decision())
    with pytest.raises(TypeError):
        AuthorizationDecision(  # type: ignore[call-arg]
            request_id=trusted.request_id,
            decision_id=trusted.decision_id,
            correlation_id=trusted.correlation_id,
            outcome=DecisionOutcome.ALLOW,
            reason_code="allow",
            client_scope_hash=trusted.client_scope_hash,
            authoritative_scope_hash=trusted.authoritative_scope_hash,
            policy_revision=trusted.policy_revision,
            server_time=trusted.server_time,
            expires_at=trusted.expires_at,
            audit_ref=trusted.audit_ref,
        )
    assert copy.copy(trusted) is trusted
    assert copy.deepcopy(trusted) is trusted
    with pytest.raises(TypeError):
        pickle.dumps(trusted)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda allow, approval: replace(allow, approval=approval.approval),
        lambda allow, approval: replace(approval, approval=None),
        lambda allow, approval: replace(
            approval,
            approval=replace(
                approval.approval,
                status=wire.ApprovalStatus.APPROVED,
            ),
        ),
        lambda allow, approval: replace(
            allow,
            expires_at=allow.server_time,
        ),
    ],
)
def test_impossible_transport_decisions_fail_closed_without_context(
    mutate: Any,
) -> None:
    malformed = mutate(_decision("allow"), _decision("approval_required"))
    secret = "must-not-appear-in-decision-error"
    object.__setattr__(malformed, "reason_code", secret)
    with pytest.raises(InvalidDecision) as failure:
        _sync_decide(malformed)
    assert secret not in str(failure.value)
    assert failure.value.__context__ is None


@pytest.mark.parametrize("binding", ["request", "correlation", "scope"])
def test_decision_binding_mismatch_fails_closed(binding: str) -> None:
    decision = _decision()
    if binding == "request":
        decision = replace(
            decision,
            request_id=wire.RequestID(f"req_{'7' * 26}"),
        )
    elif binding == "correlation":
        decision = replace(
            decision,
            correlation_id=wire.CorrelationID(f"corr_{'7' * 26}"),
        )
    else:
        decision = replace(
            decision,
            client_scope_hash=wire.SHA256Digest(f"sha256:{'9' * 64}"),
        )
    with pytest.raises(InvalidDecision):
        _sync_decide(decision)


@pytest.mark.parametrize(
    ("outcome", "server_time", "expires_at"),
    [
        (
            "allow",
            "2026-07-25T22:00:01+02:00",
            "2026-07-25T22:05:00+02:00",
        ),
        (
            "allow",
            "2026-07-25T15:00:01-05:00",
            "2026-07-25T15:05:00-05:00",
        ),
        (
            "approval_required",
            "2026-07-25T22:00:01+02:00",
            "2026-07-25T15:05:00-05:00",
        ),
        (
            "approval_required",
            "2026-07-25T15:00:01-05:00",
            "2026-07-25T22:05:00+02:00",
        ),
    ],
)
def test_public_conversion_and_authorize_accept_numeric_offsets(
    outcome: Literal["allow", "approval_required"],
    server_time: str,
    expires_at: str,
) -> None:
    decision = _decision(outcome)
    approval = decision.approval
    if approval is not None:
        approval = replace(
            approval,
            expires_at=wire.RFC3339Timestamp(expires_at),
        )
    decision = replace(
        decision,
        server_time=wire.RFC3339Timestamp(server_time),
        expires_at=wire.RFC3339Timestamp(expires_at),
        approval=approval,
    )
    converted, _ = _sync_decide(decision)
    async_converted, _ = asyncio.run(_async_decide(decision))
    assert converted == async_converted
    assert converted.server_time == server_time
    assert converted.expires_at == expires_at
    client = AuthorizationClient(_SyncTransport(decision))
    async_client = AsyncAuthorizationClient(_AsyncTransport(decision))

    async def authorize_async() -> AuthorizationDecision:
        return await async_client.authorize(_attempt())

    if outcome == "allow":
        assert client.authorize(_attempt()) == converted
        assert asyncio.run(authorize_async()) == converted
    else:
        with pytest.raises(ApprovalRequired):
            client.authorize(_attempt())
        with pytest.raises(ApprovalRequired):
            asyncio.run(authorize_async())


@pytest.mark.parametrize(
    ("server_time", "expires_at"),
    [
        ("2026-07-25T20:00:01Z", "2026-07-25T22:00:01+02:00"),
        ("2026-07-25T15:00:01-05:00", "2026-07-25T20:00:01Z"),
    ],
)
def test_equivalent_offset_instants_fail_expiry_ordering(
    server_time: str,
    expires_at: str,
) -> None:
    decision = replace(
        _decision(),
        server_time=wire.RFC3339Timestamp(server_time),
        expires_at=wire.RFC3339Timestamp(expires_at),
    )
    with pytest.raises(InvalidDecision):
        _sync_decide(decision)


class _BlockingSyncTransport(_SyncTransport):
    def __init__(
        self,
        result: wire.AuthorizationDecision,
        *,
        close_failure: BaseException | None = None,
    ) -> None:
        super().__init__(result)
        self.entered = threading.Event()
        self.release = threading.Event()
        self.close_failure = close_failure

    def decide(self, *args: Any, **kwargs: Any) -> wire.AuthorizationDecision:
        self.entered.set()
        assert self.release.wait(timeout=5)
        return super().decide(*args, **kwargs)

    def close(self) -> None:
        super().close()
        if self.close_failure is not None:
            raise self.close_failure


class _BlockingAsyncTransport(_AsyncTransport):
    def __init__(
        self,
        result: wire.AuthorizationDecision,
        *,
        close_failure: BaseException | None = None,
    ) -> None:
        super().__init__(result)
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.close_failure = close_failure

    async def decide(self, *args: Any, **kwargs: Any) -> wire.AuthorizationDecision:
        self.entered.set()
        await self.release.wait()
        return await super().decide(*args, **kwargs)

    async def aclose(self) -> None:
        self.close_calls += 1
        await asyncio.sleep(0)
        if self.close_failure is not None:
            raise self.close_failure


def test_sync_close_waits_for_active_operation_and_rejects_new_work() -> None:
    transport = _BlockingSyncTransport(_decision())
    client = AuthorizationClient(transport, owns_transport=True)
    operation = concurrent.futures.ThreadPoolExecutor(max_workers=3)
    try:
        decision_future = operation.submit(client.decide, _attempt())
        assert transport.entered.wait(timeout=5)
        close_one = operation.submit(client.close)
        deadline = time.monotonic() + 5
        while not close_one.running() and time.monotonic() < deadline:
            time.sleep(0.001)
        with pytest.raises(AuthorizationUnavailable):
            client.decide(_attempt())
        close_two = operation.submit(client.close)
        assert not close_one.done()
        assert not close_two.done()
        assert transport.close_calls == 0
        transport.release.set()
        assert decision_future.result(timeout=5).outcome is DecisionOutcome.ALLOW
        close_one.result(timeout=5)
        close_two.result(timeout=5)
        assert transport.close_calls == 1
    finally:
        transport.release.set()
        operation.shutdown(wait=True)


def test_sync_concurrent_closers_observe_same_safe_close_failure() -> None:
    secret = "owned-transport-close-secret"
    transport = _BlockingSyncTransport(
        _decision(),
        close_failure=RuntimeError(secret),
    )
    transport.release.set()
    client = AuthorizationClient(transport, owns_transport=True)
    barrier = threading.Barrier(3)

    def close() -> BaseException:
        barrier.wait()
        try:
            client.close()
        except BaseException as error:
            return error
        raise AssertionError("close unexpectedly succeeded")

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(close)
        second = executor.submit(close)
        barrier.wait()
        failures = (first.result(timeout=5), second.result(timeout=5))
    assert all(type(error) is AuthorizationUnavailable for error in failures)
    assert str(failures[0]) == str(failures[1])
    assert secret not in str(failures)
    assert transport.close_calls == 1
    with pytest.raises(AuthorizationUnavailable):
        client.close()


def test_async_close_waits_for_active_operation_and_rejects_new_work() -> None:
    async def run() -> None:
        transport = _BlockingAsyncTransport(_decision())
        client = AsyncAuthorizationClient(transport, owns_transport=True)
        decision_task = asyncio.create_task(client.decide(_attempt()))
        await transport.entered.wait()
        close_one = asyncio.create_task(client.aclose())
        await asyncio.sleep(0)
        with pytest.raises(AuthorizationUnavailable):
            await client.decide(_attempt())
        close_two = asyncio.create_task(client.aclose())
        await asyncio.sleep(0)
        assert not close_one.done()
        assert not close_two.done()
        assert transport.close_calls == 0
        transport.release.set()
        assert (await decision_task).outcome is DecisionOutcome.ALLOW
        await asyncio.gather(close_one, close_two)
        assert transport.close_calls == 1

    asyncio.run(run())


def test_async_concurrent_closers_share_failure_and_cancellation_is_local() -> None:
    async def run() -> None:
        secret = "async-owned-transport-close-secret"
        transport = _BlockingAsyncTransport(
            _decision(),
            close_failure=RuntimeError(secret),
        )
        transport.release.set()
        client = AsyncAuthorizationClient(transport, owns_transport=True)
        cancelled_closer = asyncio.create_task(client.aclose())
        waiting_closers = [
            asyncio.create_task(client.aclose()),
            asyncio.create_task(client.aclose()),
        ]
        cancelled_closer.cancel()
        with pytest.raises(asyncio.CancelledError):
            await cancelled_closer
        failures = await asyncio.gather(*waiting_closers, return_exceptions=True)
        assert all(type(failure) is AuthorizationUnavailable for failure in failures)
        assert str(failures[0]) == str(failures[1])
        assert secret not in str(failures)
        with pytest.raises(AuthorizationUnavailable) as repeated:
            await client.aclose()
        assert str(failures[0]) == str(repeated.value)
        assert transport.close_calls == 1

    asyncio.run(run())


def test_async_reentrant_transport_close_is_a_harmless_noop() -> None:
    class ReentrantTransport(_AsyncTransport):
        client: AsyncAuthorizationClient

        async def aclose(self) -> None:
            self.close_calls += 1
            await self.client.aclose()

    async def run() -> None:
        transport = ReentrantTransport(_decision())
        client = AsyncAuthorizationClient(transport, owns_transport=True)
        transport.client = client
        await client.aclose()
        await client.aclose()
        assert transport.close_calls == 1

    asyncio.run(run())


def test_sync_reentrant_transport_close_is_a_harmless_noop() -> None:
    class ReentrantTransport(_SyncTransport):
        client: AuthorizationClient

        def close(self) -> None:
            self.close_calls += 1
            self.client.close()

    transport = ReentrantTransport(_decision())
    client = AuthorizationClient(transport, owns_transport=True)
    transport.client = client
    client.close()
    client.close()
    assert transport.close_calls == 1
