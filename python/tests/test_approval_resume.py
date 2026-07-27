# SPDX-License-Identifier: MIT
"""Approval lifecycle and fail-closed resume behavior."""

from __future__ import annotations

import asyncio
import concurrent.futures
import json
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
    AuthorizationUnavailable,
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


def _current(original: Any, *, path: str = "deploy/prod.yaml") -> Any:
    builder = _builder()
    target = builder.prepare_path_target(
        service="workspace",
        path=path,
        cwd="/workspace",
    )
    return builder.new(
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


class _AsyncApprovals:
    def __init__(self, records: list[wire.ApprovalRecord]) -> None:
        self.records = records
        self.create_keys: list[str] = []
        self.get_calls = 0

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


def test_approval_transport_boundaries_are_runtime_checkable() -> None:
    assert isinstance(_SyncApprovals([]), ApprovalTransport)
    assert isinstance(_AsyncApprovals([]), AsyncApprovalTransport)


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
            str(pending.approval_id),
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
        client.wait_for_approval(str(pending.approval_id))  # type: ignore[call-arg]
    with pytest.raises(AuthorizationUnavailable):
        client.wait_for_approval(
            str(pending.approval_id),
            deadline=time.monotonic(),
        )
    with pytest.raises(concurrent.futures.CancelledError):
        client.wait_for_approval(
            str(pending.approval_id),
            deadline=time.monotonic() + 1,
            cancelled=lambda: True,
        )


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
        client.resume(builder, original, _current(original), initial, approval)
    assert original.consume() == "/workspace/deploy/prod.yaml"


def test_resume_reauthorizes_fresh_scope_and_executes_only_after_allow() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    first_client = AuthorizationClient(auth)
    initial = first_client.decide(original)
    approval = ApprovalRecord._from_protocol(_approval("approved", original, initial))

    auth.outcome = "allow"
    resumed = first_client.resume(
        builder,
        original,
        _current(original),
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
    client = AuthorizationClient(auth)
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
            _current(original),
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
    client = AuthorizationClient(auth)
    initial = client.decide(original)
    approval = ApprovalRecord._from_protocol(_approval("approved", original, initial))
    auth.outcome = "allow"
    auth.authoritative_scope_hash = f"sha256:{'f' * 64}"

    with pytest.raises(ApprovalScopeMismatch):
        client.resume(
            builder,
            original,
            _current(original),
            initial,
            approval,
        )
    assert original.consume() == "/workspace/deploy/prod.yaml"


def test_resume_rejects_resource_or_task_scope_change_before_transport() -> None:
    builder = _builder()
    original = _prepared(builder)
    auth = _SyncTransport()
    client = AuthorizationClient(auth)
    initial = client.decide(original)
    approval = ApprovalRecord._from_protocol(_approval("approved", original, initial))
    calls = len(auth.decision_calls)
    with pytest.raises(ApprovalScopeMismatch):
        client.resume(
            builder,
            original,
            _current(original, path="deploy/other.yaml"),
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
        client = AsyncAuthorizationClient(auth, approval_transport=approvals)

        created = await client.request_approval(original, initial)
        assert created.status is ApprovalStatus.PENDING
        waited = await client.wait_for_approval(
            created.approval_id,
            deadline=time.monotonic() + 0.2,
            poll_interval=0.001,
        )
        assert waited.status is ApprovalStatus.APPROVED

        auth.outcome = "allow"
        resumed = await client.resume(
            builder,
            original,
            _current(original),
            initial,
            waited,
        )
        assert resumed.consume() == "/workspace/deploy/prod.yaml"

    asyncio.run(run())
