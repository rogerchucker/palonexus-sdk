# SPDX-License-Identifier: MIT
"""Run a complete asynchronous authorization lifecycle without a network."""

from __future__ import annotations

import asyncio
from typing import Any

from palonexus import (
    ActionRequestBuilder,
    AsyncAuthorizationClient,
    PolicyDenied,
    TaskContext,
)
from palonexus.testing import AsyncFakeTransport, ScriptedEngine

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


async def run() -> None:
    engine = ScriptedEngine(
        ScriptedEngine.deny(),
        ScriptedEngine.approval_required(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    transport = AsyncFakeTransport(engine, testing_only=True)
    client = AsyncAuthorizationClient(
        transport,
        approval_transport=transport,
    )
    builder = ActionRequestBuilder(
        adapter_id="python-async-example",
        adapter_version="0.2.0",
        host_version="1.0.0",
    )
    executions: list[str] = []

    denied = prepare(
        builder,
        action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY2",
    )
    try:
        await client.authorize(denied)
    except PolicyDenied:
        assert executions == []
        print("DENIED_EXECUTED_ZERO")
    finally:
        denied.close()

    original = prepare(
        builder,
        action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY3",
    )
    prior = await client.decide(original)
    pending = await client.request_approval(original, prior)
    assert executions == []
    print("APPROVAL_REQUIRED_EXECUTED_ZERO")

    engine.resolve_approval(
        pending.approval_id,
        status="approved",
        reviewer_ref="subject:synthetic-reviewer",
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )
    approved = await client.get_approval(pending.approval_id, expected=pending)
    print("APPROVAL_APPROVED")

    current = prepare(
        builder,
        action_id="act_01J5ABCDEFGHJKMNPQRSTVWXY3",
    )
    resumed = await client.resume(builder, original, current, prior, approved)
    print("RESUMED_ALLOW")

    executable_path = resumed.consume()
    executions.append(str(executable_path))
    assert executions == ["/example/inventory/items/42.json"]
    print("EXECUTED_ONCE")

    assert prior.correlation_id == approved.correlation_id == CORRELATION_ID
    assert approved.creation_audit_ref == prior.audit_ref
    assert approved.resolution_audit_ref is not None
    print("AUDIT_CORRELATED")


if __name__ == "__main__":
    asyncio.run(run())
