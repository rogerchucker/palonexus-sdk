# SPDX-License-Identifier: MIT
"""Contract tests for the provider-neutral LangGraph 1.x integration."""

from __future__ import annotations

import asyncio
import json
from typing import Any, TypedDict

import pytest
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command
from palonexus import (
    ActionRequestBuilder,
    ApprovalExpired,
    ApprovalScopeMismatch,
    AsyncAuthorizationClient,
    AuthorizationClient,
    AuthorizationUnavailable,
    CredentialRevoked,
    InvalidDecision,
    PolicyDenied,
    TaskContext,
)
from palonexus.integrations.langgraph import (
    LANGGRAPH_SCOPE_KEY,
    LangGraphPolicyDenied,
    PaloNexusLangGraphNode,
)
from palonexus.testing import (
    AsyncFakeTransport,
    FakeTransport,
    FrozenClock,
    ScriptedEngine,
)

TASK = TaskContext(
    task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
    session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
)
CORRELATION = "corr_01J5ABCDEFGHJKMNPQRSTVWXY8"


class State(TypedDict, total=False):
    path: str
    calls: int
    marker: str
    palonexus_scope: str


def _builder() -> ActionRequestBuilder:
    return ActionRequestBuilder(
        adapter_id="langgraph",
        adapter_version="0.2.0",
        host_version="1.0.0",
    )


def _target(builder: ActionRequestBuilder, state: State) -> Any:
    return builder.prepare_path_target(
        service="workspace",
        path=state["path"],
        cwd="/workspace",
    )


def _graph(node: PaloNexusLangGraphNode, *, checkpointer: Any = None) -> Any:
    graph = StateGraph(State)
    graph.add_node("authorize", node.authorize)
    graph.add_node("wait", node.wait_for_approval)
    graph.add_node("execute", node.execute)
    graph.add_edge(START, "authorize")
    graph.add_conditional_edges(
        "authorize",
        node.route_after_authorization,
        {"wait": "wait", "execute": "execute"},
    )
    graph.add_edge("wait", "execute")
    graph.add_edge("execute", END)
    return graph.compile(checkpointer=checkpointer)


def _node(
    engine: ScriptedEngine,
    calls: list[str],
    *,
    checkpointer: Any = None,
) -> PaloNexusLangGraphNode:
    transport = FakeTransport(engine, testing_only=True)
    client = AuthorizationClient(
        transport,
        approval_transport=transport,
    )

    def handler(state: State) -> dict[str, object]:
        calls.append(state["path"])
        return {"calls": len(calls)}

    return PaloNexusLangGraphNode(
        builder=_builder(),
        client=client,
        target_projector=_target,
        handler=handler,
        task_context=TASK,
        correlation_id=CORRELATION,
        tenant_ref="tenant:example",
        actor_ref="subject:example",
        action="file:write",
        side_effect="write",
        checkpointer=checkpointer,
    )


def test_allow_executes_exactly_once_and_checkpoints_only_json_scope() -> None:
    calls: list[str] = []
    graph = _graph(
        _node(ScriptedEngine(ScriptedEngine.allow(), testing_only=True), calls)
    )
    result = graph.invoke({"path": "deploy/prod.yaml", "calls": 0})

    assert calls == ["deploy/prod.yaml"]
    assert result["calls"] == 1
    assert result["marker"] == "APPROVED_EXECUTED"
    descriptor = result[LANGGRAPH_SCOPE_KEY]
    assert type(descriptor) is str
    scope = json.loads(descriptor)
    assert scope["taskId"] == TASK.task_id
    assert scope["tenantRef"] == "tenant:example"
    assert scope["actorRef"] == "subject:example"
    assert scope["action"] == "file:write"
    assert scope["sideEffect"] == "write"
    assert scope["resource"]["service"] == "workspace"
    assert scope["clientScopeHash"].startswith("sha256:")
    assert "callable" not in descriptor.lower()


@pytest.mark.parametrize(
    "outcome,error",
    [
        (ScriptedEngine.deny(), PolicyDenied),
        (ScriptedEngine.outage(), AuthorizationUnavailable),
        (ScriptedEngine.error(InvalidDecision()), InvalidDecision),
    ],
)
def test_non_allow_or_untrusted_response_never_executes(
    outcome: Any,
    error: type[BaseException],
) -> None:
    calls: list[str] = []
    graph = _graph(_node(ScriptedEngine(outcome, testing_only=True), calls))
    with pytest.raises(error):
        graph.invoke({"path": "deploy/prod.yaml", "calls": 0})
    assert calls == []


def test_approval_interrupt_resume_reauthorizes_and_executes_once() -> None:
    calls: list[str] = []
    engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    saver = InMemorySaver()
    node = _node(engine, calls, checkpointer=saver)
    graph = _graph(node, checkpointer=saver)
    config = {"configurable": {"thread_id": "thread-a"}}

    paused = graph.invoke({"path": "deploy/prod.yaml", "calls": 0}, config)
    assert calls == []
    assert paused["marker"] == "INTERRUPTED"
    assert len(paused["__interrupt__"]) == 1
    assert paused["__interrupt__"][0].value == {
        "kind": "palonexus_approval",
        "message": "Trusted approval status must be refreshed before execution.",
    }
    approval_id = json.loads(paused[LANGGRAPH_SCOPE_KEY])["approvalId"]
    engine.resolve_approval(
        approval_id,
        status="approved",
        reviewer_ref="subject:reviewer",
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )

    result = graph.invoke(
        Command(resume={"approved": False, "secret": "ignored"}), config
    )
    assert result["marker"] == "APPROVED_EXECUTED"
    assert calls == ["deploy/prod.yaml"]
    assert len(engine.recorded_calls) == 4
    assert [call.operation for call in engine.recorded_calls] == [
        "decide",
        "request_approval",
        "get_approval",
        "decide",
    ]

    replay = graph.invoke(None, config)
    assert replay["marker"] == "APPROVED_EXECUTED"
    assert calls == ["deploy/prod.yaml"]

    before_execute = next(
        snapshot
        for snapshot in graph.get_state_history(config)
        if snapshot.next == ("execute",)
    )
    restarted_calls: list[str] = []
    restarted_graph = _graph(
        _node(engine, restarted_calls, checkpointer=saver),
        checkpointer=saver,
    )
    replayed_event = restarted_graph.invoke(None, before_execute.config)
    assert replayed_event["marker"] == "REPLAY_BLOCKED"
    assert calls == ["deploy/prod.yaml"]
    assert restarted_calls == []


def test_checkpoint_scope_or_current_target_mutation_fails_closed() -> None:
    calls: list[str] = []
    engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    saver = InMemorySaver()
    graph = _graph(_node(engine, calls, checkpointer=saver), checkpointer=saver)
    config = {"configurable": {"thread_id": "thread-mutation"}}
    paused = graph.invoke({"path": "deploy/prod.yaml", "calls": 0}, config)
    approval_id = json.loads(paused[LANGGRAPH_SCOPE_KEY])["approvalId"]
    engine.resolve_approval(
        approval_id,
        status="approved",
        reviewer_ref="subject:reviewer",
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )

    graph.update_state(config, {"path": "deploy/other.yaml"})
    with pytest.raises(ApprovalScopeMismatch):
        graph.invoke(Command(resume=True), config)
    assert calls == []

    corrupt_engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        testing_only=True,
    )
    saver2 = InMemorySaver()
    graph2 = _graph(
        _node(corrupt_engine, calls, checkpointer=saver2), checkpointer=saver2
    )
    config2 = {"configurable": {"thread_id": "thread-corrupt"}}
    paused2 = graph2.invoke({"path": "deploy/prod.yaml", "calls": 0}, config2)
    corrupt = json.loads(paused2[LANGGRAPH_SCOPE_KEY])
    corrupt["actorRef"] = "subject:attacker"
    graph2.update_state(
        config2,
        {
            LANGGRAPH_SCOPE_KEY: json.dumps(
                corrupt, sort_keys=True, separators=(",", ":")
            )
        },
    )
    with pytest.raises(ApprovalScopeMismatch):
        graph2.invoke(Command(resume=True), config2)
    assert calls == []


@pytest.mark.parametrize(
    "config",
    [
        None,
        {"configurable": {"thread_id": "thread-without-checkpointer"}},
    ],
)
def test_approval_requires_thread_id_and_checkpointer(config: Any) -> None:
    calls: list[str] = []
    engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        testing_only=True,
    )
    graph = _graph(_node(engine, calls))
    with pytest.raises(AuthorizationUnavailable):
        graph.invoke({"path": "deploy/prod.yaml", "calls": 0}, config)
    assert calls == []


def test_async_nodes_authorize_resume_and_execute_once() -> None:
    async def run() -> None:
        calls: list[str] = []
        engine = ScriptedEngine(
            ScriptedEngine.approval_required(),
            ScriptedEngine.allow(),
            testing_only=True,
        )
        transport = AsyncFakeTransport(engine, testing_only=True)
        client = AsyncAuthorizationClient(
            transport,
            approval_transport=transport,
        )

        async def handler(state: State) -> dict[str, object]:
            calls.append(state["path"])
            return {"calls": len(calls)}

        checkpointer = InMemorySaver()
        node = PaloNexusLangGraphNode(
            builder=_builder(),
            async_client=client,
            target_projector=_target,
            async_handler=handler,
            task_context=TASK,
            correlation_id=CORRELATION,
            tenant_ref="tenant:example",
            actor_ref="subject:example",
            action="file:write",
            side_effect="write",
            checkpointer=checkpointer,
        )
        graph_builder = StateGraph(State)
        graph_builder.add_node("authorize", node.aauthorize)
        graph_builder.add_node("wait", node.await_for_approval)
        graph_builder.add_node("execute", node.aexecute)
        graph_builder.add_edge(START, "authorize")
        graph_builder.add_conditional_edges(
            "authorize",
            node.route_after_authorization,
            {"wait": "wait", "execute": "execute"},
        )
        graph_builder.add_edge("wait", "execute")
        graph_builder.add_edge("execute", END)
        graph = graph_builder.compile(checkpointer=checkpointer)
        config = {"configurable": {"thread_id": "async-thread"}}
        paused = await graph.ainvoke({"path": "deploy/prod.yaml", "calls": 0}, config)
        approval_id = json.loads(paused[LANGGRAPH_SCOPE_KEY])["approvalId"]
        engine.resolve_approval(
            approval_id,
            status="approved",
            reviewer_ref="subject:reviewer",
            resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
        )
        result = await graph.ainvoke(Command(resume="wake"), config)
        assert result["marker"] == "APPROVED_EXECUTED"
        assert calls == ["deploy/prod.yaml"]

    asyncio.run(run())


def test_process_restart_reconstructs_authorization_without_execution_checkpoint() -> (
    None
):
    calls: list[str] = []
    engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    transport = FakeTransport(engine, testing_only=True)
    saver = InMemorySaver()
    first_client = AuthorizationClient(transport, approval_transport=transport)
    first = PaloNexusLangGraphNode(
        builder=_builder(),
        client=first_client,
        target_projector=_target,
        handler=lambda state: {"calls": 999},
        task_context=TASK,
        correlation_id=CORRELATION,
        tenant_ref="tenant:example",
        actor_ref="subject:example",
        action="file:write",
        side_effect="write",
        checkpointer=saver,
    )
    config = {"configurable": {"thread_id": "restart-thread"}}
    paused = _graph(first, checkpointer=saver).invoke(
        {"path": "deploy/prod.yaml", "calls": 0},
        config,
    )
    approval_id = json.loads(paused[LANGGRAPH_SCOPE_KEY])["approvalId"]
    engine.resolve_approval(
        approval_id,
        status="approved",
        reviewer_ref="subject:reviewer",
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )

    def restarted_handler(state: State) -> dict[str, object]:
        calls.append(state["path"])
        return {"calls": len(calls)}

    restarted = PaloNexusLangGraphNode(
        builder=_builder(),
        client=AuthorizationClient(transport, approval_transport=transport),
        target_projector=_target,
        handler=restarted_handler,
        task_context=TASK,
        correlation_id=CORRELATION,
        tenant_ref="tenant:example",
        actor_ref="subject:example",
        action="file:write",
        side_effect="write",
        checkpointer=saver,
    )
    result = _graph(restarted, checkpointer=saver).invoke(
        Command(resume="wake-only"),
        config,
    )
    assert result["marker"] == "APPROVED_EXECUTED"
    assert calls == ["deploy/prod.yaml"]


@pytest.mark.parametrize("status", ["denied", "cancelled"])
def test_terminal_non_approval_never_executes(status: str) -> None:
    calls: list[str] = []
    engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        testing_only=True,
    )
    saver = InMemorySaver()
    graph = _graph(_node(engine, calls, checkpointer=saver), checkpointer=saver)
    config = {"configurable": {"thread_id": f"terminal-{status}"}}
    paused = graph.invoke({"path": "deploy/prod.yaml", "calls": 0}, config)
    approval_id = json.loads(paused[LANGGRAPH_SCOPE_KEY])["approvalId"]
    engine.resolve_approval(
        approval_id,
        status=status,  # type: ignore[arg-type]
        reviewer_ref=("subject:reviewer" if status == "denied" else None),
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )
    with pytest.raises(PolicyDenied):
        graph.invoke(Command(resume=True), config)
    assert calls == []


def test_fresh_policy_denial_after_approval_never_executes() -> None:
    calls: list[str] = []
    engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        ScriptedEngine.deny(reason_code="testing_policy_changed"),
        testing_only=True,
    )
    saver = InMemorySaver()
    graph = _graph(_node(engine, calls, checkpointer=saver), checkpointer=saver)
    config = {"configurable": {"thread_id": "policy-change"}}
    paused = graph.invoke({"path": "deploy/prod.yaml", "calls": 0}, config)
    approval_id = json.loads(paused[LANGGRAPH_SCOPE_KEY])["approvalId"]
    engine.resolve_approval(
        approval_id,
        status="approved",
        reviewer_ref="subject:reviewer",
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )
    with pytest.raises(PolicyDenied):
        graph.invoke(Command(resume="wake"), config)
    assert calls == []


def test_expired_approval_never_executes() -> None:
    calls: list[str] = []
    clock = FrozenClock("2026-07-27T12:00:00Z")
    engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        testing_only=True,
        clock=clock,
    )
    transport = FakeTransport(engine, testing_only=True)
    saver = InMemorySaver()
    client = AuthorizationClient(
        transport,
        approval_transport=transport,
        trusted_clock=lambda: (
            clock().isoformat(timespec="seconds").replace("+00:00", "Z")
        ),
    )
    node = PaloNexusLangGraphNode(
        builder=_builder(),
        client=client,
        target_projector=_target,
        handler=lambda state: {"calls": 1},
        task_context=TASK,
        correlation_id=CORRELATION,
        tenant_ref="tenant:example",
        actor_ref="subject:example",
        action="file:write",
        side_effect="write",
        checkpointer=saver,
    )
    graph = _graph(node, checkpointer=saver)
    config = {"configurable": {"thread_id": "expired"}}
    graph.invoke({"path": "deploy/prod.yaml", "calls": 0}, config)
    clock.advance(901)
    with pytest.raises(ApprovalExpired):
        graph.invoke(Command(resume="wake"), config)
    assert calls == []


def test_revoked_credential_on_fresh_resume_never_executes() -> None:
    calls: list[str] = []
    engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        ScriptedEngine.error(CredentialRevoked()),
        testing_only=True,
    )
    saver = InMemorySaver()
    graph = _graph(_node(engine, calls, checkpointer=saver), checkpointer=saver)
    config = {"configurable": {"thread_id": "revoked"}}
    paused = graph.invoke({"path": "deploy/prod.yaml", "calls": 0}, config)
    approval_id = json.loads(paused[LANGGRAPH_SCOPE_KEY])["approvalId"]
    engine.resolve_approval(
        approval_id,
        status="approved",
        reviewer_ref="subject:reviewer",
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )
    with pytest.raises(CredentialRevoked):
        graph.invoke(Command(resume="wake"), config)
    assert calls == []


def test_framework_notes_are_ignored_without_retaining_host_text() -> None:
    error = LangGraphPolicyDenied(correlation_id=CORRELATION)
    error.add_note("HOST-SECRET")
    assert "HOST-SECRET" not in repr(error)
    assert getattr(error, "__notes__", None) is None
