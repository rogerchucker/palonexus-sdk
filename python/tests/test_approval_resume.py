# SPDX-License-Identifier: MIT
"""Approval lifecycle and fail-closed resume behavior."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
import threading
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from palonexus import (
    ActionRequestBuilder,
    ApprovalExpired,
    ApprovalScopeMismatch,
    ApprovalStatus,
    AsyncAuthorizationClient,
    AuthorizationClient,
    AuthorizationDecision,
    AuthorizationUnavailable,
    InvalidDecision,
    InvalidRequest,
    PolicyDenied,
    TaskContext,
)
from palonexus._generated import protocol as wire
from palonexus.approvals import (
    ApprovalRecord,
    ApprovalTransport,
    AsyncApprovalTransport,
)

ROOT = Path(__file__).parents[2]
VECTORS = ROOT / "protocol/test-vectors"
TRUSTED_NOW = "2026-07-25T20:05:00Z"


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _builder() -> ActionRequestBuilder:
    return ActionRequestBuilder(
        adapter_id="python-sdk",
        adapter_version="0.2.0",
        host_version="1.0.0",
    )


def _prepared(builder: ActionRequestBuilder, path: str = "deploy/prod.yaml") -> Any:
    target = builder.prepare_path_target(
        service="workspace",
        path=path,
        cwd="/workspace",
    )
    intent = builder.new(
        action="file:write",
        target=target,
        side_effect="write",
        task_context=TaskContext(
            task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
            session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
        ),
        action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY2",
        correlation_id="corr_01J5ABCDEFGHJKMNPQRSTVWXY2",
    )
    return builder.build(intent, prepared_target=target)


def _current(
    builder: ActionRequestBuilder,
    original: Any,
    *,
    path: str = "deploy/prod.yaml",
) -> Any:
    target = builder.prepare_path_target(
        service="workspace",
        path=path,
        cwd="/workspace",
    )
    return builder.build(
        builder.new(
            action="file:write",
            target=target,
            side_effect="write",
            task_context=TaskContext(
                task_id=str(original.request.task.task_id),
                session_id=str(original.request.task.session_id),
            ),
            action_id=str(original.request.action_id),
            correlation_id=str(original.request.correlation_id),
        ),
        prepared_target=target,
    )


def _decision(
    attempt: Any,
    outcome: str,
    *,
    authoritative_scope_hash: str | None = None,
) -> wire.AuthorizationDecision:
    name = "approval-required" if outcome == "approval_required" else outcome
    document = _json(VECTORS / f"decision/valid/{name}.json")
    document["requestId"] = str(attempt.request.request_id)
    document["correlationId"] = str(attempt.request.correlation_id)
    document["clientScopeHash"] = attempt.client_scope_hash
    if authoritative_scope_hash is not None:
        document["authoritativeScopeHash"] = authoritative_scope_hash
    if outcome == "approval_required":
        document["approval"]["approvalId"] = "apr_01J5ABCDEFGHJKMNPQRSTVWXY2"
    return wire.parse_decision(document)


def _approval(status: str, original: Any, prior: Any) -> wire.ApprovalRecord:
    document = _json(VECTORS / f"approval/valid/{status}.json")
    document["actionId"] = str(original.request.action_id)
    document["correlationId"] = str(original.request.correlation_id)
    document["authoritativeScopeHash"] = prior.authoritative_scope_hash
    document["authorizationDecisionId"] = prior.decision_id
    document["creationAuditRef"] = prior.audit_ref
    return wire.parse_approval(document)


class _SyncTransport:
    def __init__(self, outcome: str = "approval_required") -> None:
        self.outcome = outcome
        self.decision_calls: list[Any] = []
        self.authoritative_scope_hash: str | None = None

    def decide(self, request: Any, *, client_scope_hash: str, **_: Any) -> Any:
        attempt = type(
            "Attempt",
            (),
            {
                "request": request,
                "client_scope_hash": client_scope_hash,
            },
        )()
        self.decision_calls.append(attempt)
        result = _decision(
            attempt,
            self.outcome,
            authoritative_scope_hash=self.authoritative_scope_hash,
        )
        self.authoritative_scope_hash = str(result.authoritative_scope_hash)
        return result

    def close(self) -> None:
        pass


class _AsyncTransport:
    def __init__(self, outcome: str = "approval_required") -> None:
        self.outcome = outcome
        self.decision_calls: list[Any] = []
        self.authoritative_scope_hash: str | None = None

    async def decide(self, request: Any, *, client_scope_hash: str, **_: Any) -> Any:
        attempt = type(
            "Attempt",
            (),
            {
                "request": request,
                "client_scope_hash": client_scope_hash,
            },
        )()
        self.decision_calls.append(attempt)
        result = _decision(
            attempt,
            self.outcome,
            authoritative_scope_hash=self.authoritative_scope_hash,
        )
        self.authoritative_scope_hash = str(result.authoritative_scope_hash)
        return result

    async def aclose(self) -> None:
        pass


class _SyncApprovals:
    def __init__(self, records: list[wire.ApprovalRecord]) -> None:
        self.records = records
        self.create_keys: list[str] = []
        self.get_calls = 0
        self.close_calls = 0
        self.close_error: BaseException | None = None

    def request_approval(
        self,
        request: Any,
        *,
        decision_id: str,
        authoritative_scope_hash: str,
        approval_id: str,
        **_: Any,
    ) -> wire.ApprovalRecord:
        del decision_id, authoritative_scope_hash, approval_id
        self.create_keys.append(str(request.idempotency_key))
        return self.records[0]

    def get_approval(self, approval_id: str, **_: Any) -> wire.ApprovalRecord:
        del approval_id
        index = min(self.get_calls, len(self.records) - 1)
        self.get_calls += 1
        return self.records[index]

    def close(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class _AsyncApprovals:
    def __init__(self, records: list[wire.ApprovalRecord]) -> None:
        self.records = records
        self.create_keys: list[str] = []
        self.get_calls = 0
        self.close_calls = 0
        self.close_error: BaseException | None = None

    async def request_approval(
        self, request: Any, **kwargs: Any
    ) -> wire.ApprovalRecord:
        del kwargs
        self.create_keys.append(str(request.idempotency_key))
        return self.records[0]

    async def get_approval(self, approval_id: str, **_: Any) -> wire.ApprovalRecord:
        del approval_id
        index = min(self.get_calls, len(self.records) - 1)
        self.get_calls += 1
        return self.records[index]

    async def aclose(self) -> None:
        self.close_calls += 1
        if self.close_error is not None:
            raise self.close_error


class _CompositeSync(_SyncTransport, _SyncApprovals):
    def __init__(self) -> None:
        _SyncTransport.__init__(self)
        _SyncApprovals.__init__(self, [])

    def close(self) -> None:
        _SyncApprovals.close(self)


class _CompositeAsync(_AsyncTransport, _AsyncApprovals):
    def __init__(self) -> None:
        _AsyncTransport.__init__(self)
        _AsyncApprovals.__init__(self, [])

    async def aclose(self) -> None:
        await _AsyncApprovals.aclose(self)


def test_approval_transport_boundaries_are_runtime_checkable() -> None:
    assert isinstance(_SyncApprovals([]), ApprovalTransport)
    assert isinstance(_AsyncApprovals([]), AsyncApprovalTransport)


def test_owned_distinct_and_shared_approval_transports_close_exactly_once() -> None:
    auth = _SyncTransport()
    approvals = _SyncApprovals([])
    client = AuthorizationClient(
        auth,
        approval_transport=approvals,
        owns_transport=True,
        owns_approval_transport=True,
    )
    client.close()
    client.close()
    assert auth.decision_calls == []
    assert approvals.close_calls == 1

    shared = _CompositeSync()
    shared_client = AuthorizationClient(
        shared,
        approval_transport=shared,
        owns_transport=True,
        owns_approval_transport=True,
    )
    shared_client.close()
    assert shared.close_calls == 1


def test_approval_transport_close_failure_is_normalized_and_not_retried() -> None:
    approvals = _SyncApprovals([])
    approvals.close_error = RuntimeError("secret approval close failure")
    client = AuthorizationClient(
        _SyncTransport(),
        approval_transport=approvals,
        owns_approval_transport=True,
    )
    for _ in range(2):
        with pytest.raises(AuthorizationUnavailable) as captured:
            client.close()
        assert "secret" not in str(captured.value)
    assert approvals.close_calls == 1


def test_async_owned_approval_transport_close_and_shared_deduplication() -> None:
    async def run() -> None:
        approvals = _AsyncApprovals([])
        client = AsyncAuthorizationClient(
            _AsyncTransport(),
            approval_transport=approvals,
            owns_approval_transport=True,
        )
        await client.aclose()
        await client.aclose()
        assert approvals.close_calls == 1

        shared = _CompositeAsync()
        shared_client = AsyncAuthorizationClient(
            shared,
            approval_transport=shared,
            owns_transport=True,
            owns_approval_transport=True,
        )
        await shared_client.aclose()
        assert shared.close_calls == 1

    asyncio.run(run())


def test_request_approval_is_idempotently_bound_and_returns_immutable_record() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    prior = AuthorizationClient(auth).decide(original)
    approvals = _SyncApprovals([_approval("pending", original, prior)])
    client = AuthorizationClient(auth, approval_transport=approvals)

    first = client.request_approval(original, prior)
    second = client.request_approval(original, prior)

    assert first is not second
    assert first == second
    assert approvals.create_keys == [
        str(original.request.idempotency_key),
        str(original.request.idempotency_key),
    ]
    assert first.status is ApprovalStatus.PENDING
    with pytest.raises(AttributeError):
        first.status = ApprovalStatus.APPROVED  # type: ignore[misc]
    with pytest.raises(TypeError):
        ApprovalRecord()  # type: ignore[call-arg]


def test_request_approval_rejects_record_outside_original_scope() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    prior = AuthorizationClient(auth).decide(original)
    malformed = _approval("pending", original, prior)
    malformed = replace(
        malformed,
        action_id=wire.ActionID("act_01J5ABCDEFGHJKMNPQRSTVWXY9"),
    )
    client = AuthorizationClient(
        auth,
        approval_transport=_SyncApprovals([malformed]),
    )
    with pytest.raises(ApprovalScopeMismatch):
        client.request_approval(original, prior)


def test_approval_expiry_is_exactly_bound_to_prior_decision_summary() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    prior = AuthorizationClient(auth).decide(original)
    changed = replace(
        _approval("pending", original, prior),
        expires_at=wire.RFC3339Timestamp("2026-07-25T20:17:01.0Z"),
    )
    client = AuthorizationClient(auth, approval_transport=_SyncApprovals([changed]))

    with pytest.raises(ApprovalScopeMismatch):
        client.request_approval(original, prior)


@pytest.mark.parametrize(
    ("status", "requested_at", "decided_at", "expires_at"),
    (
        ("pending", "2026-07-25T20:18:01Z", None, "2026-07-25T20:17:01Z"),
        (
            "approved",
            "2026-07-25T20:02:01Z",
            "2026-07-25T20:01:59.999999999999999999Z",
            "2026-07-25T20:17:01Z",
        ),
        (
            "approved",
            "2026-07-25T20:02:01Z",
            "2026-07-25T20:17:01Z",
            "2026-07-25T20:17:01Z",
        ),
    ),
)
def test_public_approval_record_enforces_cross_field_time_invariants(
    status: str,
    requested_at: str,
    decided_at: str | None,
    expires_at: str,
) -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    prior = AuthorizationClient(auth).decide(original)
    value = _approval(status, original, prior)
    value = replace(
        value,
        requested_at=wire.RFC3339Timestamp(requested_at),
        decided_at=(None if decided_at is None else wire.RFC3339Timestamp(decided_at)),
        expires_at=wire.RFC3339Timestamp(expires_at),
    )
    with pytest.raises(InvalidDecision):
        ApprovalRecord._from_protocol(value)


def test_resume_uses_exact_trusted_time_with_arbitrary_fractional_precision() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    initial = AuthorizationClient(auth).decide(original)
    value = replace(
        _approval("approved", original, initial),
        decided_at=wire.RFC3339Timestamp("2026-07-25T20:04:01.123456789123456789Z"),
    )
    approval = ApprovalRecord._from_protocol(value)

    future_client = AuthorizationClient(
        auth,
        trusted_clock=lambda: "2026-07-25T20:04:01.123456789123456788Z",
    )
    with pytest.raises(InvalidDecision):
        future_client.resume(
            builder,
            original,
            _current(builder, original),
            initial,
            approval,
        )
    assert original.request.action_id

    expired_client = AuthorizationClient(
        auth,
        trusted_clock=lambda: approval.expires_at,
    )
    with pytest.raises(ApprovalExpired):
        expired_client.resume(
            builder,
            original,
            _current(builder, original),
            initial,
            approval,
        )
    assert original.consume() == "/workspace/deploy/prod.yaml"


def test_decision_approval_expiry_comparison_preserves_submicrosecond_order() -> None:
    builder = _builder()
    original = _prepared(builder)
    value = _decision(original, "approval_required")
    assert value.approval is not None
    value = replace(
        value,
        server_time=wire.RFC3339Timestamp("2026-07-25T20:02:01.1234567889Z"),
        expires_at=wire.RFC3339Timestamp("2026-07-25T20:02:02Z"),
        approval=replace(
            value.approval,
            expires_at=wire.RFC3339Timestamp("2026-07-25T20:02:01.1234567890Z"),
        ),
    )

    assert AuthorizationDecision._from_protocol(value).approval_id


def test_wait_returns_every_terminal_outcome_without_busy_loop() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    prior = AuthorizationClient(auth).decide(original)
    for status in ("approved", "denied", "expired", "cancelled"):
        pending = _approval("pending", original, prior)
        terminal = _approval(status, original, prior)
        approvals = _SyncApprovals([pending, terminal])
        client = AuthorizationClient(auth, approval_transport=approvals)
        before = time.monotonic()
        result = client.wait_for_approval(
            ApprovalRecord._from_protocol(pending),
            deadline=before + 0.2,
            poll_interval=0.001,
        )
        assert result.status.value == status
        assert approvals.get_calls == 2
        assert time.monotonic() >= before


def test_wait_requires_bounded_deadline_and_honors_cancellation() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    prior = AuthorizationClient(auth).decide(original)
    pending = _approval("pending", original, prior)
    client = AuthorizationClient(
        auth,
        approval_transport=_SyncApprovals([pending]),
    )
    with pytest.raises(TypeError):
        client.wait_for_approval(  # type: ignore[call-arg]
            ApprovalRecord._from_protocol(pending)
        )
    with pytest.raises(AuthorizationUnavailable):
        client.wait_for_approval(
            ApprovalRecord._from_protocol(pending),
            deadline=time.monotonic(),
        )
    with pytest.raises(concurrent.futures.CancelledError):
        client.wait_for_approval(
            ApprovalRecord._from_protocol(pending),
            deadline=time.monotonic() + 1,
            cancelled=lambda: True,
        )


def test_poll_chain_rejects_immutable_record_substitution() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    prior = AuthorizationClient(auth).decide(original)
    pending = _approval("pending", original, prior)
    replacement = replace(
        _approval("approved", original, prior),
        action_id=wire.ActionID("act_01J5ABCDEFGHJKMNPQRSTVWXY9"),
    )
    client = AuthorizationClient(
        auth,
        approval_transport=_SyncApprovals([replacement]),
    )

    with pytest.raises(ApprovalScopeMismatch):
        client.wait_for_approval(
            ApprovalRecord._from_protocol(pending),
            deadline=time.monotonic() + 0.1,
            poll_interval=0.001,
        )


def test_read_rejects_terminal_regression_and_conflicting_terminal() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    prior = AuthorizationClient(auth).decide(original)
    approved = ApprovalRecord._from_protocol(_approval("approved", original, prior))
    for fetched in (
        _approval("pending", original, prior),
        _approval("denied", original, prior),
    ):
        client = AuthorizationClient(
            auth,
            approval_transport=_SyncApprovals([fetched]),
        )
        with pytest.raises(InvalidDecision):
            client.get_approval(approved.approval_id, expected=approved)


def test_async_poll_chain_rejects_replacement() -> None:
    async def run() -> None:
        builder = _builder()
        original = _prepared(builder)
        auth = _AsyncTransport()
        prior = await AsyncAuthorizationClient(auth).decide(original)
        pending = _approval("pending", original, prior)
        replacement = replace(
            _approval("approved", original, prior),
            correlation_id=wire.CorrelationID("corr_01J5ABCDEFGHJKMNPQRSTVWXY9"),
        )
        client = AsyncAuthorizationClient(
            auth,
            approval_transport=_AsyncApprovals([replacement]),
        )
        with pytest.raises(ApprovalScopeMismatch):
            await client.wait_for_approval(
                ApprovalRecord._from_protocol(pending),
                deadline=time.monotonic() + 0.1,
                poll_interval=0.001,
            )

    asyncio.run(run())


def test_sync_wait_observes_delayed_cancellation_independent_of_poll_interval() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    prior = AuthorizationClient(auth).decide(original)
    pending = ApprovalRecord._from_protocol(_approval("pending", original, prior))
    cancelled = threading.Event()
    client = AuthorizationClient(
        auth,
        approval_transport=_SyncApprovals([_approval("pending", original, prior)]),
    )
    timer = threading.Timer(0.03, cancelled.set)
    timer.start()
    started = time.monotonic()
    try:
        with pytest.raises(concurrent.futures.CancelledError):
            client.wait_for_approval(
                pending,
                deadline=started + 2,
                cancelled=cancelled.is_set,
                poll_interval=60,
            )
    finally:
        timer.cancel()
    assert time.monotonic() - started < 0.2


def test_async_wait_observes_delayed_cancellation_independent_of_interval() -> None:
    async def run() -> None:
        builder = _builder()
        original = _prepared(builder)
        auth = _AsyncTransport()
        prior = await AsyncAuthorizationClient(auth).decide(original)
        pending_wire = _approval("pending", original, prior)
        pending = ApprovalRecord._from_protocol(pending_wire)
        cancelled = False
        client = AsyncAuthorizationClient(
            auth,
            approval_transport=_AsyncApprovals([pending_wire]),
        )

        async def cancel_later() -> None:
            nonlocal cancelled
            await asyncio.sleep(0.03)
            cancelled = True

        timer = asyncio.create_task(cancel_later())
        started = time.monotonic()
        with pytest.raises(asyncio.CancelledError):
            await client.wait_for_approval(
                pending,
                deadline=started + 2,
                cancelled=lambda: cancelled,
                poll_interval=60,
            )
        await timer
        assert time.monotonic() - started < 0.2

    asyncio.run(run())


@pytest.mark.parametrize(
    ("status", "error"),
    (
        ("denied", PolicyDenied),
        ("expired", ApprovalExpired),
        ("cancelled", PolicyDenied),
    ),
)
def test_resume_terminal_failure_does_not_consume_original(
    status: str,
    error: type[Exception],
) -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    initial = AuthorizationClient(auth).decide(original)
    approval = ApprovalRecord._from_protocol(_approval(status, original, initial))
    client = AuthorizationClient(auth)
    with pytest.raises(error):
        client.resume(
            builder,
            original,
            _current(builder, original),
            initial,
            approval,
        )
    assert original.consume() == "/workspace/deploy/prod.yaml"


def test_resume_reauthorizes_fresh_scope_and_executes_only_after_allow() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    first_client = AuthorizationClient(auth, trusted_clock=lambda: TRUSTED_NOW)
    initial = first_client.decide(original)
    approval = ApprovalRecord._from_protocol(_approval("approved", original, initial))

    auth.outcome = "allow"
    resumed = first_client.resume(
        builder,
        original,
        _current(builder, original),
        initial,
        approval,
    )

    assert len(auth.decision_calls) == 2
    fresh = auth.decision_calls[-1]
    assert fresh.request.action_id == original.request.action_id
    assert fresh.request.correlation_id == original.request.correlation_id
    assert fresh.request.task == original.request.task
    assert fresh.request.request_id != original.request.request_id
    assert fresh.request.idempotency_key != original.request.idempotency_key
    assert fresh.request.resume_from_approval_id == approval.approval_id
    assert fresh.request.causation_id == initial.decision_id
    assert resumed.consume() == "/workspace/deploy/prod.yaml"
    with pytest.raises(Exception):
        resumed.consume()
    with pytest.raises(Exception):
        original.consume()


def test_fresh_policy_or_revocation_denial_never_consumes_or_invokes_work() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    client = AuthorizationClient(auth, trusted_clock=lambda: TRUSTED_NOW)
    initial = client.decide(original)
    approval = ApprovalRecord._from_protocol(_approval("approved", original, initial))
    auth.outcome = "deny"
    invoked = 0

    def application_work() -> None:
        nonlocal invoked
        invoked += 1

    with pytest.raises(PolicyDenied):
        client.resume(
            builder,
            original,
            _current(builder, original),
            initial,
            approval,
        )
    assert invoked == 0
    assert original.consume() == "/workspace/deploy/prod.yaml"
    application_work()
    assert invoked == 1


def test_fresh_allow_with_changed_authoritative_scope_fails_closed() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    client = AuthorizationClient(auth, trusted_clock=lambda: TRUSTED_NOW)
    initial = client.decide(original)
    approval = ApprovalRecord._from_protocol(_approval("approved", original, initial))
    auth.outcome = "allow"
    auth.authoritative_scope_hash = f"sha256:{'f' * 64}"

    with pytest.raises(ApprovalScopeMismatch):
        client.resume(
            builder,
            original,
            _current(builder, original),
            initial,
            approval,
        )
    assert original.consume() == "/workspace/deploy/prod.yaml"


def test_resume_rejects_stale_serialized_action_projection() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    client = AuthorizationClient(auth, trusted_clock=lambda: TRUSTED_NOW)
    initial = client.decide(original)
    approval = ApprovalRecord._from_protocol(_approval("approved", original, initial))
    target = builder.prepare_path_target(
        service="workspace",
        path="deploy/prod.yaml",
        cwd="/workspace",
    )
    stale_projection = builder.new(
        action="file:write",
        target=target,
        side_effect="write",
        task_context=TaskContext(
            task_id=str(original.request.task.task_id),
            session_id=str(original.request.task.session_id),
        ),
        action_id=str(original.request.action_id),
        correlation_id=str(original.request.correlation_id),
    )

    with pytest.raises(InvalidRequest):
        client.resume(  # type: ignore[arg-type]
            builder,
            original,
            stale_projection,
            initial,
            approval,
        )
    target.close()
    assert original.consume() == "/workspace/deploy/prod.yaml"


def test_resume_rejects_resource_or_task_scope_change_before_transport() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    client = AuthorizationClient(auth, trusted_clock=lambda: TRUSTED_NOW)
    initial = client.decide(original)
    approval = ApprovalRecord._from_protocol(_approval("approved", original, initial))
    calls = len(auth.decision_calls)
    with pytest.raises(ApprovalScopeMismatch):
        client.resume(
            builder,
            original,
            _current(builder, original, path="deploy/other.yaml"),
            initial,
            approval,
        )
    assert len(auth.decision_calls) == calls
    assert original.consume() == "/workspace/deploy/prod.yaml"


def test_async_approval_wait_and_resume_have_sync_parity() -> None:
    async def run() -> None:
        builder = _builder()
        original = _prepared(builder)
        auth = _AsyncTransport()
        provisional = AsyncAuthorizationClient(auth)
        initial = await provisional.decide(original)
        pending = _approval("pending", original, initial)
        approved = _approval("approved", original, initial)
        approvals = _AsyncApprovals([pending, approved])
        client = AsyncAuthorizationClient(
            auth,
            approval_transport=approvals,
            trusted_clock=lambda: TRUSTED_NOW,
        )

        created = await client.request_approval(original, initial)
        assert created.status is ApprovalStatus.PENDING
        waited = await client.wait_for_approval(
            created,
            deadline=time.monotonic() + 0.2,
            poll_interval=0.001,
        )
        assert waited.status is ApprovalStatus.APPROVED

        auth.outcome = "allow"
        resumed = await client.resume(
            builder,
            original,
            _current(builder, original),
            initial,
            waited,
        )
        assert resumed.consume() == "/workspace/deploy/prod.yaml"

    asyncio.run(run())
