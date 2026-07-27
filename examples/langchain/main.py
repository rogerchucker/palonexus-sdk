# SPDX-License-Identifier: MIT
"""Offline LangChain 1.x example using PaloNexus scripted authorization."""

from __future__ import annotations

from typing import Any

from langchain_core.language_models.fake_chat_models import (
    FakeMessagesListChatModel,
)
from langchain_core.messages import AIMessage
from langchain_core.runnables import Runnable
from langchain_core.tools import tool
from palonexus import AuthorizationClient, PolicyDenied, TaskContext
from palonexus.integrations.langchain import (
    LangChainActionPolicy,
    LangChainApprovalRequired,
    LangChainAuthorizationContext,
    PaloNexusLangChainMiddleware,
    create_authorized_agent,
)
from palonexus.testing import FakeTransport, ScriptedEngine


class OfflineToolModel(FakeMessagesListChatModel):
    """LangChain's offline fake with the tool-binding capability declared."""

    def bind_tools(
        self,
        tools: Any,
        *,
        tool_choice: str | None = None,
        **kwargs: Any,
    ) -> Runnable[Any, AIMessage]:
        del tools, tool_choice, kwargs
        return self


TASK_CONTEXT = LangChainAuthorizationContext(
    task=TaskContext(
        task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
        session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
    ),
    correlation_id="corr_01J5ABCDEFGHJKMNPQRSTVWXY8",
    model_policy_key="offline-model",
)


def middleware(
    engine: ScriptedEngine,
    *,
    include_tool: bool,
) -> PaloNexusLangChainMiddleware:
    return PaloNexusLangChainMiddleware(
        client=AuthorizationClient(FakeTransport(engine, testing_only=True)),
        async_client=None,
        tool_policies=(
            {
                "read_inventory": LangChainActionPolicy(
                    service="inventory",
                    side_effect="read_only",
                )
            }
            if include_tool
            else {}
        ),
        model_policies={
            "offline-model": LangChainActionPolicy(
                service="offline-model",
                side_effect="external",
            )
        },
    )


def main() -> None:
    executions = 0

    @tool
    def read_inventory(item_id: str) -> str:
        """Read a synthetic inventory item."""

        nonlocal executions
        executions += 1
        return f"inventory:{item_id}"

    allowed = ScriptedEngine(
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    agent = create_authorized_agent(
        model=OfflineToolModel(
            name="offline-model",
            responses=[
                AIMessage(
                    content="",
                    tool_calls=[
                        {
                            "name": "read_inventory",
                            "args": {"item_id": "42"},
                            "id": "offline-call",
                            "type": "tool_call",
                        }
                    ],
                ),
                AIMessage(content="done"),
            ],
        ),
        model_policy_key="offline-model",
        tools=[read_inventory],
        authorization=middleware(allowed, include_tool=True),
        context_schema=LangChainAuthorizationContext,
    )
    agent.invoke(
        {"messages": [{"role": "user", "content": "Read item 42"}]},
        context=TASK_CONTEXT,
    )
    if executions != 1:
        raise RuntimeError("allow path did not execute exactly once")
    print("LANGCHAIN_ALLOW_EXECUTED_ONCE")

    denied = ScriptedEngine(ScriptedEngine.deny(), testing_only=True)
    denied_agent = create_authorized_agent(
        model=OfflineToolModel(
            responses=[AIMessage(content="unreachable")],
            name="offline-model",
        ),
        model_policy_key="offline-model",
        tools=[],
        authorization=middleware(denied, include_tool=False),
        context_schema=LangChainAuthorizationContext,
    )
    try:
        denied_agent.invoke(
            {"messages": [{"role": "user", "content": "blocked"}]},
            context=TASK_CONTEXT,
        )
    except PolicyDenied:
        print("LANGCHAIN_DENY_EXECUTED_ZERO")
    else:
        raise RuntimeError("deny path did not fail closed")

    approval = ScriptedEngine(
        ScriptedEngine.approval_required(),
        testing_only=True,
    )
    approval_agent = create_authorized_agent(
        model=OfflineToolModel(
            responses=[AIMessage(content="unreachable")],
            name="offline-model",
        ),
        model_policy_key="offline-model",
        tools=[],
        authorization=middleware(approval, include_tool=False),
        context_schema=LangChainAuthorizationContext,
    )
    try:
        approval_agent.invoke(
            {"messages": [{"role": "user", "content": "approval"}]},
            context=TASK_CONTEXT,
        )
    except LangChainApprovalRequired:
        print("LANGCHAIN_APPROVAL_EXECUTED_ZERO")
    else:
        raise RuntimeError("approval path did not stop before execution")


if __name__ == "__main__":
    main()
