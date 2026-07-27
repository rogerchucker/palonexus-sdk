# SPDX-License-Identifier: MIT
"""Contract tests for the public Deep Agents middleware seam."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from langchain.tools.tool_node import ToolCallRequest
from langchain_core.messages import ToolMessage
from langchain_core.runnables import RunnableConfig
from langchain_core.tools import tool
from langgraph.prebuilt.tool_node import ToolRuntime
from palonexus import (
    AsyncAuthorizationClient,
    AuthorizationClient,
    InvalidRequest,
    PolicyDenied,
    TaskContext,
)
from palonexus.integrations.deepagents import (
    DeepAgentsAuthorizationContext,
    MissingDeepAgentsDependency,
    PaloNexusDeepAgentsMiddleware,
    create_authorized_deep_agent,
)
from palonexus.integrations.langchain import (
    LangChainActionPolicy,
    LangChainApprovalRequired,
    LangChainAuthorizationContext,
    PaloNexusLangChainMiddleware,
)
from palonexus.testing import AsyncFakeTransport, FakeTransport, ScriptedEngine

TASK = TaskContext(
    task_id="task_01J5ABCDEFGHJKMNPQRSTVWXY2",
    session_id="session_01J5ABCDEFGHJKMNPQRSTVWXY2",
)
CORRELATION = "corr_01J5ABCDEFGHJKMNPQRSTVWXY8"


@tool
def inventory_write(item_id: str) -> str:
    """Update one inventory item."""

    return f"updated:{item_id}"


def _authorization(
    *outcomes: Any,
) -> tuple[PaloNexusDeepAgentsMiddleware, ScriptedEngine]:
    engine = ScriptedEngine(*outcomes, testing_only=True)
    delegate = PaloNexusLangChainMiddleware(
        client=AuthorizationClient(FakeTransport(engine, testing_only=True)),
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
    return (
        PaloNexusDeepAgentsMiddleware(
            authorization=delegate,
            accountable_actors={
                "coordinator": "agent:coordinator",
                "inventory-worker": "agent:coordinator",
            },
        ),
        engine,
    )


def _context() -> DeepAgentsAuthorizationContext:
    return DeepAgentsAuthorizationContext(
        authorization=LangChainAuthorizationContext(
            task=TASK,
            correlation_id=CORRELATION,
            model_policy_key="unused",
            actor_ref="agent:coordinator",
        ),
        accountable_actors={
            "coordinator": "agent:coordinator",
            "inventory-worker": "agent:coordinator",
        },
    )


def _request(
    agent_name: str | None,
    *,
    context: object | None = None,
    item_id: str = "42",
) -> ToolCallRequest:
    metadata = {} if agent_name is None else {"lc_agent_name": agent_name}
    runtime = ToolRuntime(
        state={},
        context=_context() if context is None else context,
        config=RunnableConfig(metadata=metadata),
        stream_writer=lambda _: None,
        tool_call_id=f"call-{item_id}",
        store=None,
        tools=[inventory_write],
    )
    return ToolCallRequest(
        tool_call={
            "name": "inventory_write",
            "args": {"item_id": item_id},
            "id": f"call-{item_id}",
            "type": "tool_call",
        },
        tool=inventory_write,
        state={},
        runtime=runtime,
    )


def test_parent_child_share_task_and_correlation_with_causation() -> None:
    middleware, engine = _authorization(
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
    )

    def child_handler(request: ToolCallRequest) -> ToolMessage:
        return ToolMessage(content="child-ok", tool_call_id=request.tool_call["id"])

    def parent_handler(request: ToolCallRequest) -> ToolMessage:
        middleware.wrap_tool_call(
            _request("inventory-worker", item_id="child"),
            child_handler,
        )
        return ToolMessage(content="parent-ok", tool_call_id=request.tool_call["id"])

    result = middleware.wrap_tool_call(
        _request("coordinator", item_id="parent"),
        parent_handler,
    )

    assert result.content == "parent-ok"
    parent, child = (call.request for call in engine.recorded_calls)
    assert (
        parent["task"]
        == child["task"]
        == {
            "taskId": TASK.task_id,
            "sessionId": TASK.session_id,
        }
    )
    assert parent["correlationId"] == child["correlationId"] == CORRELATION
    assert "causationId" not in parent
    assert child["causationId"] == parent["actionId"]


def test_accountable_actor_must_match_trusted_agent_binding() -> None:
    middleware, _ = _authorization(ScriptedEngine.allow())
    mismatched = DeepAgentsAuthorizationContext(
        authorization=LangChainAuthorizationContext(
            task=TASK,
            correlation_id=CORRELATION,
            model_policy_key="unused",
            actor_ref="agent:inventory-worker",
        ),
        accountable_actors={
            "coordinator": "agent:coordinator",
            "inventory-worker": "agent:coordinator",
        },
    )
    with pytest.raises(InvalidRequest):
        middleware.wrap_tool_call(
            _request("inventory-worker", context=mismatched),
            lambda request: ToolMessage(
                content="must-not-run",
                tool_call_id=request.tool_call["id"],
            ),
        )

    result = middleware.wrap_tool_call(
        _request("inventory-worker"),
        lambda request: ToolMessage(
            content="accountable",
            tool_call_id=request.tool_call["id"],
        ),
    )
    assert result.content == "accountable"


def test_nested_denial_never_invokes_child_handler() -> None:
    middleware, _ = _authorization(
        ScriptedEngine.allow(),
        ScriptedEngine.deny(),
    )
    child_calls = 0

    def child_handler(request: ToolCallRequest) -> ToolMessage:
        del request
        nonlocal child_calls
        child_calls += 1
        raise AssertionError("denied child must not execute")

    def parent_handler(request: ToolCallRequest) -> ToolMessage:
        child_context = DeepAgentsAuthorizationContext(
            authorization=LangChainAuthorizationContext(
                task=TASK,
                correlation_id=CORRELATION,
                model_policy_key="unused",
                actor_ref="agent:coordinator",
            ),
            accountable_actors=_context().accountable_actors,
        )
        middleware.wrap_tool_call(
            _request("inventory-worker", context=child_context),
            child_handler,
        )
        return ToolMessage(content="bad", tool_call_id=request.tool_call["id"])

    with pytest.raises(PolicyDenied):
        middleware.wrap_tool_call(_request("coordinator"), parent_handler)
    assert child_calls == 0


def test_approval_signal_propagates_without_execution_or_secret_state() -> None:
    middleware, _ = _authorization(ScriptedEngine.approval_required())
    calls = 0

    def handler(request: ToolCallRequest) -> ToolMessage:
        del request
        nonlocal calls
        calls += 1
        raise AssertionError("approval-pending action must not execute")

    with pytest.raises(LangChainApprovalRequired) as raised:
        middleware.wrap_tool_call(_request("coordinator"), handler)
    assert calls == 0
    assert raised.value.correlation_id == CORRELATION
    assert "42" not in str(raised.value)
    assert not hasattr(raised.value, "action")


def test_async_nested_denial_never_invokes_handler() -> None:
    async def scenario() -> None:
        engine = ScriptedEngine(ScriptedEngine.deny(), testing_only=True)
        delegate = PaloNexusLangChainMiddleware(
            client=None,
            async_client=AsyncAuthorizationClient(
                AsyncFakeTransport(engine, testing_only=True)
            ),
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
            accountable_actors=_context().accountable_actors,
        )
        calls = 0

        async def handler(request: ToolCallRequest) -> ToolMessage:
            del request
            nonlocal calls
            calls += 1
            raise AssertionError("denied async child must not execute")

        with pytest.raises(PolicyDenied):
            await middleware.awrap_tool_call(
                _request("inventory-worker"),
                handler,
            )
        assert calls == 0

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "context",
    [
        {},
        {"palonexus": "not-a-context"},
    ],
)
def test_missing_runtime_metadata_or_context_fails_closed(context: object) -> None:
    middleware, _ = _authorization(ScriptedEngine.allow())
    with pytest.raises(InvalidRequest):
        middleware.wrap_tool_call(
            _request(None, context=context),
            lambda request: ToolMessage(
                content="must-not-run",
                tool_call_id=request.tool_call["id"],
            ),
        )


def test_factory_rejects_hosts_without_public_middleware_hooks() -> None:
    middleware, _ = _authorization(ScriptedEngine.allow())

    def unsupported_factory(*, model: object, tools: object) -> object:
        return model, tools

    with pytest.raises(MissingDeepAgentsDependency):
        create_authorized_deep_agent(
            model=object(),
            tools=[inventory_write],
            authorization=middleware,
            deep_agent_factory=unsupported_factory,
        )


def test_factory_uses_only_documented_public_hooks() -> None:
    middleware, _ = _authorization(ScriptedEngine.allow())
    captured: dict[str, object] = {}

    def supported_factory(
        *,
        model: object,
        tools: object,
        middleware: object,
        context_schema: object,
    ) -> object:
        captured.update(
            model=model,
            tools=tools,
            middleware=middleware,
            context_schema=context_schema,
        )
        return "agent"

    result = create_authorized_deep_agent(
        model="offline:model",
        tools=[inventory_write],
        authorization=middleware,
        deep_agent_factory=supported_factory,
    )
    assert result == "agent"
    assert captured == {
        "model": "offline:model",
        "tools": (inventory_write,),
        "middleware": (middleware,),
        "context_schema": DeepAgentsAuthorizationContext,
    }
