# SPDX-License-Identifier: MIT
"""Run a complete synchronous authorization lifecycle without a network."""

from __future__ import annotations

from typing import Any

from palonexus import (
    ActionRequestBuilder,
    AuthorizationClient,
    InvalidRequest,
    PolicyDenied,
    TaskContext,
)
from palonexus.testing import FakeTransport, ScriptedEngine

TASK = TaskContext(
    task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
    session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
)
CORRELATION_ID = "corr_01J5ABCDEFGHJKMNPQRSTVWXY8"
INVENTORY_PATH = "inventory/items/42.json"


def prepare(
    builder: ActionRequestBuilder,
    *,
    action_id: str,
) -> Any:
    target = builder.prepare_path_target(
        service="synthetic-inventory",
        path=INVENTORY_PATH,
        cwd="/example",
    )
    intent = builder.new(
        action="file:write",
        target=target,
        side_effect="write",
        task_context=TASK,
        action_id=action_id,
        correlation_id=CORRELATION_ID,
    )
    return builder.build(intent, prepared_target=target)


def main() -> None:
    engine = ScriptedEngine(
        ScriptedEngine.deny(),
        ScriptedEngine.approval_required(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    transport = FakeTransport(engine, testing_only=True)
    client = AuthorizationClient(
        transport,
        approval_transport=transport,
    )
    builder = ActionRequestBuilder(
        adapter_id="python-basic-example",
        adapter_version="0.2.0",
        host_version="1.0.0",
    )
    executions: list[str] = []

    denied = prepare(
        builder,
        action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY2",
    )
    try:
        client.authorize(denied)
    except PolicyDenied:
        assert executions == []
        print("DENIED_EXECUTED_ZERO")
    finally:
        denied.close()

    original = prepare(
        builder,
        action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY3",
    )
    prior = client.decide(original)
    pending = client.request_approval(original, prior)
    assert executions == []
    print("APPROVAL_REQUIRED_EXECUTED_ZERO")

    engine.resolve_approval(
        pending.approval_id,
        status="approved",
        reviewer_ref="subject:synthetic-reviewer",
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )
    approved = client.get_approval(pending.approval_id, expected=pending)
    assert approved.authorization_decision_id == prior.decision_id
    assert approved.action_id == str(original.request.action_id)
    assert approved.correlation_id == prior.correlation_id
    assert approved.authoritative_scope_hash == prior.authoritative_scope_hash
    assert approved.creation_audit_ref == prior.audit_ref
    print("APPROVAL_APPROVED")

    current = prepare(
        builder,
        action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY3",
    )
    resumed = client.resume(builder, original, current, prior, approved)
    calls = engine.recorded_calls
    assert tuple(call.operation for call in calls) == (
        "decide",
        "decide",
        "request_approval",
        "get_approval",
        "decide",
    )
    original_request = calls[1].request
    resume_request = calls[4].request
    assert resume_request["causationId"] == prior.decision_id
    assert resume_request["resumeFromApprovalId"] == approved.approval_id
    for field in (
        "actionId",
        "correlationId",
        "action",
        "target",
        "task",
        "sideEffect",
    ):
        assert resume_request[field] == original_request[field]
    assert resume_request["requestId"] != original_request["requestId"]
    assert resume_request["idempotencyKey"] != original_request["idempotencyKey"]
    assert calls[4].client_scope_hash == calls[1].client_scope_hash
    print("RESUMED_ALLOW")

    executable_path = resumed.consume()
    executions.append(str(executable_path))
    assert executions == ["/example/inventory/items/42.json"]
    print("EXECUTED_ONCE")
    try:
        resumed.consume()
    except InvalidRequest:
        print("REPLAY_BLOCKED")
    else:
        raise RuntimeError("prepared action execution replayed")

    assert prior.correlation_id == approved.correlation_id == CORRELATION_ID
    assert approved.resolution_audit_ref is not None
    print("AUDIT_CORRELATED")


if __name__ == "__main__":
    main()
