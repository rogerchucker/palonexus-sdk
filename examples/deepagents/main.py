# SPDX-License-Identifier: MIT
"""Deterministic offline Deep Agents delegation example."""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from langchain_core.tools import tool
from palonexus import AuthorizationClient, PolicyDenied, TaskContext
from palonexus.integrations.deepagents import (
    DeepAgentsAuthorizationContext,
    PaloNexusDeepAgentsMiddleware,
    create_authorized_deep_agent,
)
from palonexus.integrations.langchain import (
    LangChainActionPolicy,
    LangChainApprovalRequired,
    LangChainAuthorizationContext,
    PaloNexusLangChainMiddleware,
)
from palonexus.testing import FakeTransport, ScriptedEngine

ACTOR = "agent:offline-coordinator"
ACTORS = {
    "coordinator": ACTOR,
    "inventory-worker": ACTOR,
    "general-purpose": ACTOR,
}


class ToolCapableFakeModel(FakeMessagesListChatModel):
    """Offline scripted model that accepts the host's public tool binding."""

    def bind_tools(
        self,
        tools: Any,
        *,
        tool_choice: str | None = None,
        **kwargs: Any,
    ) -> Any:
        del tools, tool_choice, kwargs
        return self


def build(outcome: object) -> tuple[object, list[str], DeepAgentsAuthorizationContext]:
    model = ToolCapableFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "task",
                        "args": {
                            "description": "update synthetic inventory",
                            "subagent_type": "inventory-worker",
                        },
                        "id": "call-task",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "inventory_write",
                        "args": {"item_id": "42"},
                        "id": "call-write",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="child complete"),
            AIMessage(content="parent complete"),
        ],
        name="offline-deep-agent-model",
    )
    engine = ScriptedEngine(
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        outcome,
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    executions: list[str] = []

    @tool("inventory_write")
    def inventory_write(item_id: str) -> str:
        """Update one synthetic inventory item."""

        executions.append(item_id)
        return f"updated:{item_id}"

    delegate = PaloNexusLangChainMiddleware(
        client=AuthorizationClient(FakeTransport(engine, testing_only=True)),
        async_client=None,
        tool_policies={
            "inventory_write": LangChainActionPolicy(
                service="inventory",
                side_effect="write",
            )
        },
        model_policies={
            "offline-deep-agent-model": LangChainActionPolicy(
                service="model-runtime",
                side_effect="external",
            )
        },
        model_bindings={"offline-deep-agent-model": model},
        tool_bindings={"inventory_write": inventory_write},
    )
    authorization = PaloNexusDeepAgentsMiddleware(
        authorization=delegate,
        accountable_actors=ACTORS,
    )
    graph = create_authorized_deep_agent(
        model=model,
        tools=[inventory_write],
        authorization=authorization,
        name="coordinator",
        subagents=[
            {
                "name": "inventory-worker",
                "description": "Updates synthetic inventory.",
                "system_prompt": "Call inventory_write exactly once.",
                "tools": [inventory_write],
            }
        ],
    )
    context = DeepAgentsAuthorizationContext(
        authorization=LangChainAuthorizationContext(
            task=TaskContext(
                task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
                session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
            ),
            correlation_id="corr_01J5ABCDEFGHJKMNPQRSTVWXY8",
            model_policy_key="offline-deep-agent-model",
            actor_ref=ACTOR,
        ),
        accountable_actors=ACTORS,
    )
    return graph, executions, context


def invoke(graph: Any, context: DeepAgentsAuthorizationContext) -> object:
    return graph.invoke(
        {"messages": [{"role": "user", "content": "delegate"}]},
        context=context,
    )


def main() -> None:
    allowed, executions, context = build(ScriptedEngine.allow())
    invoke(allowed, context)
    assert executions == ["42"]
    print("DECLARATIVE_SUBAGENT_GOVERNED")

    denied, executions, context = build(ScriptedEngine.deny())
    try:
        invoke(denied, context)
    except PolicyDenied:
        assert executions == []
        print("NESTED_DENIED")

    pending, executions, context = build(ScriptedEngine.approval_required())
    try:
        invoke(pending, context)
    except LangChainApprovalRequired:
        assert executions == []
        print("APPROVAL_PROPAGATED")


if __name__ == "__main__":
    main()
