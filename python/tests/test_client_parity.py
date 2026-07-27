# SPDX-License-Identifier: MIT
"""Shared behavioral contract for synchronous and asynchronous clients."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

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
    _canonicalize,
)
from palonexus._generated import protocol as wire

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
