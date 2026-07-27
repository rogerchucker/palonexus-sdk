# SPDX-License-Identifier: MIT
"""Deterministic offline Deep Agents middleware example."""

from __future__ import annotations

from typing import Any

from langchain.tools.tool_node import ToolCallRequest
from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from langgraph.prebuilt.tool_node import ToolRuntime
from palonexus import AuthorizationClient, PolicyDenied, TaskContext
from palonexus.integrations.deepagents import (
    DeepAgentsAuthorizationContext,
    PaloNexusDeepAgentsMiddleware,
)
from palonexus.integrations.langchain import (
    LangChainActionPolicy,
    LangChainApprovalRequired,
    LangChainAuthorizationContext,
    PaloNexusLangChainMiddleware,
)
from palonexus.testing import FakeTransport, ScriptedEngine

ACTOR = "agent:offline-coordinator"
AGENTS = {
    "coordinator": ACTOR,
    "inventory-worker": ACTOR,
}


@tool
def inventory_write(item_id: str) -> str:
    """Update one synthetic inventory item."""

    return f"updated:{item_id}"


def request(agent_name: str, context: DeepAgentsAuthorizationContext) -> Any:
    runtime = ToolRuntime(
        state={},
        context=context,
        config=RunnableConfig(metadata={"lc_agent_name": agent_name}),
        stream_writer=lambda _: None,
        tool_call_id=f"call-{agent_name}",
        store=None,
        tools=[inventory_write],
    )
    return ToolCallRequest(
        tool_call={
            "name": "inventory_write",
            "args": {"item_id": "42"},
            "id": f"call-{agent_name}",
            "type": "tool_call",
        },
        tool=inventory_write,
        state={},
        runtime=runtime,
    )


def main() -> None:
    engine = ScriptedEngine(
        ScriptedEngine.allow(),
        ScriptedEngine.deny(),
        ScriptedEngine.approval_required(),
        testing_only=True,
    )
    delegate = PaloNexusLangChainMiddleware(
        client=AuthorizationClient(
            FakeTransport(engine, testing_only=True),
        ),
        async_client=None,
        tool_policies={
            "inventory_write": LangChainActionPolicy(
                service="inventory",
                side_effect="write",
            )
        },
        model_policies={},
        tool_bindings={"inventory_write": inventory_write},
    )
    middleware = PaloNexusDeepAgentsMiddleware(
        authorization=delegate,
        accountable_actors=AGENTS,
    )
    context = DeepAgentsAuthorizationContext(
        authorization=LangChainAuthorizationContext(
            task=TaskContext(
                task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
                session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
            ),
            correlation_id="corr_01J5ABCDEFGHJKMNPQRSTVWXY8",
            model_policy_key="offline-model",
            actor_ref=ACTOR,
        ),
        accountable_actors=AGENTS,
    )
    parent_calls = 0
    child_calls = 0

    def denied_child(value: ToolCallRequest) -> ToolMessage:
        del value
        nonlocal child_calls
        child_calls += 1
        raise AssertionError("denied child executed")

    def parent(value: ToolCallRequest) -> ToolMessage:
        nonlocal parent_calls
        parent_calls += 1
        try:
            middleware.wrap_tool_call(
                request("inventory-worker", context),
                denied_child,
            )
        except PolicyDenied:
            print("NESTED_DENIED")
        return ToolMessage(content="parent-ok", tool_call_id=value.tool_call["id"])

    middleware.wrap_tool_call(request("coordinator", context), parent)
    assert parent_calls == 1 and child_calls == 0
    print("CORRELATED")

    try:
        middleware.wrap_tool_call(
            request("coordinator", context),
            lambda value: ToolMessage(
                content="must-not-run",
                tool_call_id=value.tool_call["id"],
            ),
        )
    except LangChainApprovalRequired:
        print("APPROVAL_PROPAGATED")


if __name__ == "__main__":
    main()
