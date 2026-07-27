# SPDX-License-Identifier: MIT
"""Offline LangGraph approval and mutation-blocking example."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.types import Command
from palonexus import ActionRequestBuilder, AuthorizationClient, TaskContext
from palonexus.errors import ApprovalScopeMismatch
from palonexus.integrations.langgraph import (
    LANGGRAPH_SCOPE_KEY,
    PaloNexusLangGraphNode,
    SQLiteExecutionLedger,
)
from palonexus.testing import FakeTransport, ScriptedEngine


class State(TypedDict, total=False):
    path: str
    mutations: int
    marker: str
    palonexus_scope: str


def target(builder: ActionRequestBuilder, state: State) -> Any:
    return builder.prepare_path_target(
        service="workspace",
        path=state["path"],
        cwd="/workspace",
    )


def build_graph(node: PaloNexusLangGraphNode, saver: SqliteSaver) -> Any:
    builder = StateGraph(State)
    builder.add_node("authorize", node.authorize)
    builder.add_node("wait", node.wait_for_approval)
    builder.add_node("execute", node.execute)
    builder.add_edge(START, "authorize")
    builder.add_conditional_edges(
        "authorize",
        node.route_after_authorization,
        {"wait": "wait", "execute": "execute"},
    )
    builder.add_edge("wait", "execute")
    builder.add_edge("execute", END)
    return builder.compile(checkpointer=saver)


def main() -> None:
    engine = ScriptedEngine(
        ScriptedEngine.approval_required(),
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    transport = FakeTransport(engine, testing_only=True)
    client = AuthorizationClient(transport, approval_transport=transport)
    request_builder = ActionRequestBuilder(
        adapter_id="langgraph",
        adapter_version="0.2.0",
        host_version="1.0.0",
    )
    mutations: list[str] = []

    def mutate(state: State) -> dict[str, object]:
        mutations.append(state["path"])
        return {"mutations": len(mutations)}

    temporary = TemporaryDirectory()
    root = Path(temporary.name)
    checkpoint_path = str(root / "checkpoints.sqlite3")
    ledger_path = root / "executions.sqlite3"
    ledger = SQLiteExecutionLedger(ledger_path)
    config = {"configurable": {"thread_id": "offline-langgraph-example"}}
    with SqliteSaver.from_conn_string(checkpoint_path) as saver:
        node = PaloNexusLangGraphNode(
            builder=request_builder,
            client=client,
            target_projector=target,
            handler=mutate,
            task_context=TaskContext(
                task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
                session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
            ),
            correlation_id="corr_01J5ABCDEFGHJKMNPQRSTVWXY8",
            tenant_ref="tenant:offline-example",
            actor_ref="subject:offline-example",
            action="file:write",
            side_effect="write",
            checkpointer=saver,
            execution_ledger=ledger,
        )
        graph = build_graph(node, saver)
        paused = graph.invoke({"path": "deploy/prod.yaml", "mutations": 0}, config)
    ledger.close()
    print(paused["marker"])
    approval_id = json.loads(paused[LANGGRAPH_SCOPE_KEY])["approvalId"]
    engine.resolve_approval(
        approval_id,
        status="approved",
        reviewer_ref="subject:offline-reviewer",
        resolution_idempotency_key="approval_01J5ABCDEFGHJKMNPQRSTVWXY4",
    )
    restarted_ledger = SQLiteExecutionLedger(ledger_path)
    with SqliteSaver.from_conn_string(checkpoint_path) as saver:
        restarted = PaloNexusLangGraphNode(
            builder=request_builder,
            client=client,
            target_projector=target,
            handler=mutate,
            task_context=TaskContext(
                task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
                session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
            ),
            correlation_id="corr_01J5ABCDEFGHJKMNPQRSTVWXY8",
            tenant_ref="tenant:offline-example",
            actor_ref="subject:offline-example",
            action="file:write",
            side_effect="write",
            checkpointer=saver,
            execution_ledger=restarted_ledger,
        )
        approved = build_graph(restarted, saver).invoke(
            Command(resume="wake-only"), config
        )
    print(approved["marker"])

    corrupted = json.loads(approved[LANGGRAPH_SCOPE_KEY])
    corrupted["actorRef"] = "subject:untrusted-mutation"
    try:
        restarted.execute(
            {
                **approved,
                LANGGRAPH_SCOPE_KEY: json.dumps(
                    corrupted, sort_keys=True, separators=(",", ":")
                ),
            },
            config,
        )
    except ApprovalScopeMismatch:
        print("MUTATION_BLOCKED")
    restarted_ledger.close()
    temporary.cleanup()


if __name__ == "__main__":
    main()
