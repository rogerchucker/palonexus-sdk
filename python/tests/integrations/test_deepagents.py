# SPDX-License-Identifier: MIT
"""Contract tests for the public Deep Agents middleware seam."""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from langchain.tools.tool_node import ToolCallRequest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, ToolMessage
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
ROOT = Path(__file__).parents[3]


class _ToolCapableFakeModel(FakeMessagesListChatModel):
    def bind_tools(
        self,
        tools: Any,
        *,
        tool_choice: str | None = None,
        **kwargs: Any,
    ) -> Any:
        del tools, tool_choice, kwargs
        return self


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
                "general-purpose": "agent:coordinator",
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
            "general-purpose": "agent:coordinator",
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


@tool("task")
def task_tool(description: str, subagent_type: str) -> str:
    """Delegate a task to a configured subagent."""

    return f"{subagent_type}:{description}"


def _task_request() -> ToolCallRequest:
    runtime = ToolRuntime(
        state={},
        context=_context(),
        config=RunnableConfig(metadata={"lc_agent_name": "coordinator"}),
        stream_writer=lambda _: None,
        tool_call_id="call-task",
        store=None,
        tools=[task_tool],
    )
    return ToolCallRequest(
        tool_call={
            "name": "task",
            "args": {
                "description": "retry the denied operation",
                "subagent_type": "inventory-worker",
            },
            "id": "call-task",
            "type": "tool_call",
        },
        tool=task_tool,
        state={},
        runtime=runtime,
    )


def test_governed_spawn_denial_never_calls_deep_agents_task_handler() -> None:
    class DeniedSpawn:
        def request(self, **_: str) -> dict[str, object]:
            return {
                "status": "spawn_denied",
                "spawn_request_id": "spawn-a",
                "reason_codes": ["HUMAN_APPROVAL_DENIED"],
            }

    middleware, engine = _authorization()
    governed = PaloNexusDeepAgentsMiddleware(
        authorization=middleware._authorization,
        accountable_actors=middleware.accountable_actors,
        spawn_runtime=DeniedSpawn(),
    )._for_factory(frozenset({"inventory-worker"}), "coordinator")
    called = False

    def handler(request: ToolCallRequest) -> ToolMessage:
        nonlocal called
        called = True
        return ToolMessage(content="must-not-run", tool_call_id=request.tool_call["id"])

    result = governed.wrap_tool_call(_task_request(), handler)

    assert called is False
    assert isinstance(result, ToolMessage)
    assert "spawn_denied" in str(result.content)
    assert not engine.recorded_calls


def test_governed_active_spawn_runs_task_only_with_bound_child_identity() -> None:
    class ActiveSpawn:
        def request(self, **_: str) -> dict[str, object]:
            return {
                "status": "active",
                "spawn_request_id": "spawn-a",
                "reason_codes": [],
                "child_agent_id": "child-a",
                "child_agent_generation": 1,
                "child_run_id": "run-child-a",
                "identity_lease_id": "lease-child-a",
            }

    middleware, _engine = _authorization()
    governed = PaloNexusDeepAgentsMiddleware(
        authorization=middleware._authorization,
        accountable_actors=middleware.accountable_actors,
        spawn_runtime=ActiveSpawn(),
    )._for_factory(frozenset({"inventory-worker"}), "coordinator")
    called = False

    def handler(request: ToolCallRequest) -> ToolMessage:
        nonlocal called
        called = True
        return ToolMessage(content="child-ran", tool_call_id=request.tool_call["id"])

    result = governed.wrap_tool_call(_task_request(), handler)

    assert called is True
    assert isinstance(result, ToolMessage)
    assert result.content == "child-ran"


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
    secret_item_id = "private-item-value-must-not-escape"

    def handler(request: ToolCallRequest) -> ToolMessage:
        del request
        nonlocal calls
        calls += 1
        raise AssertionError("approval-pending action must not execute")

    with pytest.raises(LangChainApprovalRequired) as raised:
        middleware.wrap_tool_call(
            _request("coordinator", item_id=secret_item_id), handler
        )
    assert calls == 0
    assert raised.value.correlation_id == CORRELATION
    assert secret_item_id not in str(raised.value)
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
            name="coordinator",
            subagents=[
                {
                    "name": "inventory-worker",
                    "description": "Worker.",
                    "system_prompt": "Work.",
                }
            ],
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
        name: object,
        subagents: object,
    ) -> object:
        captured.update(
            model=model,
            tools=tools,
            middleware=middleware,
            context_schema=context_schema,
            name=name,
            subagents=subagents,
        )
        return "agent"

    result = create_authorized_deep_agent(
        model="offline:model",
        tools=[inventory_write],
        authorization=middleware,
        name="coordinator",
        subagents=[
            {
                "name": "inventory-worker",
                "description": "Worker.",
                "system_prompt": "Work.",
            }
        ],
        deep_agent_factory=supported_factory,
    )
    assert result == "agent"
    assert captured["model"] == "offline:model"
    assert captured["tools"] == (inventory_write,)
    assert captured["context_schema"] is DeepAgentsAuthorizationContext
    assert captured["name"] == "coordinator"
    installed = captured["middleware"]
    assert isinstance(installed, tuple) and len(installed) == 1
    prepared = captured["subagents"]
    assert isinstance(prepared, tuple)
    assert [value["name"] for value in prepared] == [
        "inventory-worker",
        "general-purpose",
    ]


@pytest.mark.parametrize("exclusion_form", ["class", "string"])
def test_real_harness_profile_exclusion_fails_closed_in_subprocess(
    exclusion_form: str,
) -> None:
    exclusion = (
        "PaloNexusDeepAgentsMiddleware"
        if exclusion_form == "class"
        else '"PaloNexusDeepAgentsMiddleware"'
    )
    code = f"""
from deepagents import HarnessProfile, create_deep_agent, register_harness_profile
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage
from palonexus import AuthorizationClient, AuthorizationUnavailable
from palonexus.integrations.deepagents import (
    PaloNexusDeepAgentsMiddleware,
    create_authorized_deep_agent,
)
from palonexus.integrations.langchain import (
    LangChainActionPolicy,
    PaloNexusLangChainMiddleware,
)
from palonexus.testing import FakeTransport, ScriptedEngine

model = FakeMessagesListChatModel(
    responses=[AIMessage(content="done")],
    name="profile-test-model",
)
engine = ScriptedEngine(ScriptedEngine.allow(), testing_only=True)
delegate = PaloNexusLangChainMiddleware(
    client=AuthorizationClient(FakeTransport(engine, testing_only=True)),
    async_client=None,
    tool_policies={{}},
    model_policies={{
        "profile-test-model": LangChainActionPolicy(
            service="model-runtime",
            side_effect="external",
        )
    }},
    model_bindings={{"profile-test-model": model}},
)
authorization = PaloNexusDeepAgentsMiddleware(
    authorization=delegate,
    accountable_actors={{
        "coordinator": "agent:coordinator",
        "general-purpose": "agent:coordinator",
    }},
)
register_harness_profile(
    "fakemessageslistchatmodel",
    HarnessProfile(excluded_middleware=frozenset({{{exclusion}}})),
)

# Prove the real profile is active: the unbound public middleware is stripped
# and the naive graph silently constructs.
create_deep_agent(model=model, middleware=[authorization], name="naive")
print("NAIVE_STRIPPED")

try:
    create_authorized_deep_agent(
        model=model,
        tools=[],
        authorization=authorization,
        name="coordinator",
    )
except AuthorizationUnavailable:
    print("FACTORY_FAILED_CLOSED")
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [
        "NAIVE_STRIPPED",
        "FACTORY_FAILED_CLOSED",
    ]


def _real_graph(
    tool_outcome: object,
) -> tuple[object, ScriptedEngine, list[str], DeepAgentsAuthorizationContext]:
    responses = [
        AIMessage(
            content="",
            tool_calls=[
                {
                    "name": "task",
                    "args": {
                        "description": "update inventory",
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
    ]
    model = _ToolCapableFakeModel(
        responses=responses,
        name="offline-deep-agent-model",
    )
    engine = ScriptedEngine(
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        tool_outcome,
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    executions: list[str] = []

    @tool("inventory_write")
    def recorded_write(item_id: str) -> str:
        """Update one inventory item."""

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
        tool_bindings={"inventory_write": recorded_write},
    )
    middleware = PaloNexusDeepAgentsMiddleware(
        authorization=delegate,
        accountable_actors={
            "coordinator": "agent:coordinator",
            "inventory-worker": "agent:coordinator",
            "general-purpose": "agent:coordinator",
        },
    )
    graph = create_authorized_deep_agent(
        model=model,
        tools=[recorded_write],
        authorization=middleware,
        name="coordinator",
        subagents=[
            {
                "name": "inventory-worker",
                "description": "Updates inventory.",
                "system_prompt": "Use inventory_write exactly once.",
                "tools": [recorded_write],
            }
        ],
    )
    context = DeepAgentsAuthorizationContext(
        authorization=LangChainAuthorizationContext(
            task=TASK,
            correlation_id=CORRELATION,
            model_policy_key="offline-deep-agent-model",
            actor_ref="agent:coordinator",
        ),
        accountable_actors={
            "coordinator": "agent:coordinator",
            "inventory-worker": "agent:coordinator",
            "general-purpose": "agent:coordinator",
        },
    )
    return graph, engine, executions, context


def test_real_graph_intercepts_actual_declarative_subagent_tool() -> None:
    graph, engine, executions, context = _real_graph(ScriptedEngine.allow())
    result = graph.invoke(
        {"messages": [{"role": "user", "content": "delegate"}]},
        context=context,
    )

    assert result["messages"][-1].content == "parent complete"
    assert executions == ["42"]
    calls = [call.request for call in engine.recorded_calls]
    assert len(calls) == 6
    assert all(call["task"]["taskId"] == TASK.task_id for call in calls)
    assert all(call["correlationId"] == CORRELATION for call in calls)
    assert [call["target"]["service"] for call in calls].count("inventory") == 1
    delegation = calls[1]
    assert delegation["target"]["service"] == "deep-agent-inventory-worker"
    assert delegation["action"] == "tool:invoke"
    assert "causationId" not in delegation
    assert all(call["causationId"] == delegation["actionId"] for call in calls[2:5])
    assert "causationId" not in calls[5]


@pytest.mark.parametrize(
    ("outcome", "error_type"),
    [
        (ScriptedEngine.deny(), PolicyDenied),
        (ScriptedEngine.approval_required(), LangChainApprovalRequired),
    ],
)
def test_real_graph_child_denial_or_approval_propagates_without_execution(
    outcome: object,
    error_type: type[BaseException],
) -> None:
    graph, _, executions, context = _real_graph(outcome)
    with pytest.raises(error_type):
        graph.invoke(
            {"messages": [{"role": "user", "content": "delegate"}]},
            context=context,
        )
    assert executions == []


def test_real_graph_rejects_actor_mismatch_before_any_execution() -> None:
    graph, engine, executions, _ = _real_graph(ScriptedEngine.allow())
    mismatched = DeepAgentsAuthorizationContext(
        authorization=LangChainAuthorizationContext(
            task=TASK,
            correlation_id=CORRELATION,
            model_policy_key="offline-deep-agent-model",
            actor_ref="agent:unaccountable",
        ),
        accountable_actors={
            "coordinator": "agent:coordinator",
            "inventory-worker": "agent:coordinator",
            "general-purpose": "agent:coordinator",
        },
    )
    with pytest.raises(InvalidRequest):
        graph.invoke(
            {"messages": [{"role": "user", "content": "delegate"}]},
            context=mismatched,
        )
    assert engine.recorded_calls == ()
    assert executions == []


def test_factory_rejects_compiled_and_remote_subagents() -> None:
    middleware, _ = _authorization(ScriptedEngine.allow())
    for unsupported in (
        {"name": "compiled", "description": "x", "runnable": object()},
        {"name": "remote", "description": "x", "graph_id": "graph-1"},
    ):
        with pytest.raises(InvalidRequest):
            create_authorized_deep_agent(
                model=object(),
                tools=[inventory_write],
                authorization=middleware,
                name="coordinator",
                subagents=[unsupported],
                deep_agent_factory=lambda **kwargs: kwargs,
            )


def test_factory_rejects_user_tools_shadowing_host_builtins() -> None:
    middleware = PaloNexusDeepAgentsMiddleware(
        authorization=PaloNexusLangChainMiddleware(
            client=AuthorizationClient(
                FakeTransport(
                    ScriptedEngine(ScriptedEngine.allow(), testing_only=True),
                    testing_only=True,
                )
            ),
            async_client=None,
            tool_policies={},
            model_policies={},
        ),
        accountable_actors={
            "coordinator": "agent:coordinator",
            "general-purpose": "agent:coordinator",
        },
    )

    @tool("task")
    def shadow_task(description: str, subagent_type: str) -> str:
        """Attempt to shadow the host delegation primitive."""

        return f"{description}:{subagent_type}"

    with pytest.raises(InvalidRequest):
        create_authorized_deep_agent(
            model=object(),
            tools=[shadow_task],
            authorization=middleware,
            name="coordinator",
            deep_agent_factory=lambda **kwargs: kwargs,
        )


def test_real_graph_effectful_filesystem_builtin_fails_closed() -> None:
    model = _ToolCapableFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "write_file",
                        "args": {"file_path": "/blocked.txt", "content": "blocked"},
                        "id": "call-write-file",
                        "type": "tool_call",
                    }
                ],
            )
        ],
        name="offline-deep-agent-model",
    )
    engine = ScriptedEngine(ScriptedEngine.allow(), testing_only=True)
    delegate = PaloNexusLangChainMiddleware(
        client=AuthorizationClient(FakeTransport(engine, testing_only=True)),
        async_client=None,
        tool_policies={},
        model_policies={
            "offline-deep-agent-model": LangChainActionPolicy(
                service="model-runtime",
                side_effect="external",
            )
        },
        model_bindings={"offline-deep-agent-model": model},
    )
    middleware = PaloNexusDeepAgentsMiddleware(
        authorization=delegate,
        accountable_actors={
            "coordinator": "agent:coordinator",
            "general-purpose": "agent:coordinator",
        },
    )
    graph = create_authorized_deep_agent(
        model=model,
        tools=[],
        authorization=middleware,
        name="coordinator",
    )
    context = DeepAgentsAuthorizationContext(
        authorization=LangChainAuthorizationContext(
            task=TASK,
            correlation_id=CORRELATION,
            model_policy_key="offline-deep-agent-model",
            actor_ref="agent:coordinator",
        ),
        accountable_actors=middleware.accountable_actors,
    )
    with pytest.raises(InvalidRequest):
        graph.invoke(
            {"messages": [{"role": "user", "content": "write"}]},
            context=context,
        )
    assert len(engine.recorded_calls) == 1


def test_optional_import_normalizes_missing_framework_dependency() -> None:
    code = """
import builtins
import sys
import palonexus.integrations
real_import = builtins.__import__
def blocked(name, *args, **kwargs):
    if name == "langchain" or name.startswith("langchain."):
        raise ModuleNotFoundError(name)
    return real_import(name, *args, **kwargs)
builtins.__import__ = blocked
for name in tuple(sys.modules):
    if name.startswith("palonexus.integrations.deepagents"):
        del sys.modules[name]
try:
    import palonexus.integrations.deepagents
except Exception as error:
    print(type(error).__name__)
"""
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "MissingDeepAgentsDependency"
