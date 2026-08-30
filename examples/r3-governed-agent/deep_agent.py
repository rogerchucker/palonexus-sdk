"""Public Deep Agents wiring for the governed subagent scenario."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.tools import BaseTool
from palonexus.integrations.deepagents import (
    PaloNexusDeepAgentsMiddleware,
    create_authorized_deep_agent,
)
from palonexus.integrations.langchain import PaloNexusLangChainMiddleware


def create_r3_agent(
    *,
    model: object,
    tools: Sequence[BaseTool],
    delegate: PaloNexusLangChainMiddleware,
    spawn_runtime: Any,
    subagents: Sequence[Mapping[str, object]],
    middleware: Sequence[AgentMiddleware[Any, Any]] = (),
) -> object:
    """Bind Deep Agents' ``task`` tool to PaloNexus before child execution."""

    governed = PaloNexusDeepAgentsMiddleware(
        authorization=delegate,
        accountable_actors={
            "release-risk-reviewer-r3": "agent:release-risk-reviewer-r3",
            "release-retry-worker": "agent:release-risk-reviewer-r3",
        },
        spawn_runtime=spawn_runtime,
    )
    return create_authorized_deep_agent(
        model=model,
        tools=tools,
        authorization=governed,
        name="release-risk-reviewer-r3",
        subagents=subagents,
        middleware=middleware,
    )
