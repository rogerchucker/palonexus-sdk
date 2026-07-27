# SPDX-License-Identifier: MIT
"""Contract tests for the provider-neutral LangChain 1.x middleware."""

from __future__ import annotations

import asyncio
import concurrent.futures
import os
import subprocess
import sys
import time
from pathlib import Path
from types import MappingProxyType
from typing import Any

import pytest
from langchain.agents import create_agent
from langchain.agents.middleware import ModelRequest, ModelResponse
from langchain.tools.tool_node import ToolCallRequest
from langchain_core.language_models.fake_chat_models import (
    FakeListChatModel,
    FakeMessagesListChatModel,
)
from langchain_core.messages import AIMessage, ToolMessage
from langchain_core.runnables import Runnable, RunnableConfig
from langchain_core.tools import tool
from langgraph.prebuilt.tool_node import ToolRuntime
from langgraph.runtime import Runtime
from palonexus import (
    ApprovalRequired,
    AsyncAuthorizationClient,
    AuthorizationClient,
    AuthorizationUnavailable,
    InvalidRequest,
    PolicyDenied,
    TaskContext,
)
from palonexus.integrations.langchain import (
    LangChainActionPolicy,
    LangChainApprovalRequired,
    LangChainAuthorizationContext,
    MissingIntegrationDependency,
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
    ) -> Runnable[Any, AIMessage]:
        del tools, tool_choice, kwargs
        return self


@tool
def inventory_read(item_id: str, api_token: str) -> str:
    """Read an inventory item."""

    return f"item:{item_id}:{len(api_token)}"


def _context(
    *,
    task: TaskContext = TASK,
    correlation_id: str = CORRELATION,
    deadline: float | None = None,
) -> LangChainAuthorizationContext:
    return LangChainAuthorizationContext(
        task=task,
        correlation_id=correlation_id,
        tenant_ref="tenant-not-authoritative",
        actor_ref="actor-not-authoritative",
        deadline=deadline,
    )


def _middleware(
    outcome: Any,
    *,
    tool_policies: dict[str, LangChainActionPolicy] | None = None,
    model_policies: dict[str, LangChainActionPolicy] | None = None,
) -> tuple[PaloNexusLangChainMiddleware, ScriptedEngine]:
    engine = ScriptedEngine(outcome, testing_only=True)
    client = AuthorizationClient(FakeTransport(engine, testing_only=True))
    return (
        PaloNexusLangChainMiddleware(
            client=client,
            async_client=None,
            tool_policies=tool_policies
            or {
                "inventory_read": LangChainActionPolicy(
                    service="inventory",
                    side_effect="read_only",
                )
            },
            model_policies=model_policies
            or {
                "fake-list-chat-model": LangChainActionPolicy(
                    service="model-runtime",
                    side_effect="external",
                )
            },
        ),
        engine,
    )


def _async_middleware(
    outcome: Any,
) -> tuple[PaloNexusLangChainMiddleware, ScriptedEngine]:
    engine = ScriptedEngine(outcome, testing_only=True)
    client = AsyncAuthorizationClient(AsyncFakeTransport(engine, testing_only=True))
    return (
        PaloNexusLangChainMiddleware(
            client=None,
            async_client=client,
            tool_policies={
                "inventory_read": LangChainActionPolicy(
                    service="inventory",
                    side_effect="read_only",
                )
            },
            model_policies={
                "fake-list-chat-model": LangChainActionPolicy(
                    service="model-runtime",
                    side_effect="external",
                )
            },
        ),
        engine,
    )


def _tool_request(
    *,
    context: LangChainAuthorizationContext | None = None,
    args: dict[str, Any] | None = None,
    config: RunnableConfig | None = None,
) -> ToolCallRequest:
    runtime = ToolRuntime(
        state={},
        context=context,
        config=config or {},
        stream_writer=lambda _: None,
        tool_call_id="call-1",
        store=None,
        tools=[inventory_read],
    )
    return ToolCallRequest(
        tool_call={
            "name": "inventory_read",
            "args": args or {"item_id": "42", "api_token": "TOP-SECRET"},
            "id": "call-1",
            "type": "tool_call",
        },
        tool=inventory_read,
        state={},
        runtime=runtime,
    )


def _model_request(
    *,
    context: LangChainAuthorizationContext | None = None,
) -> ModelRequest[Any]:
    return ModelRequest(
        model=FakeListChatModel(responses=["ok"]),
        messages=[],
        runtime=Runtime(context=context),
    )


def test_sync_tool_allow_authorizes_before_exactly_one_handler_call() -> None:
    middleware, engine = _middleware(ScriptedEngine.allow())
    calls = 0

    def handler(request: ToolCallRequest) -> ToolMessage:
        nonlocal calls
        calls += 1
        assert len(engine.recorded_calls) == 1
        return ToolMessage(content="ok", tool_call_id=request.tool_call["id"])

    result = middleware.wrap_tool_call(_tool_request(context=_context()), handler)

    assert result.content == "ok"
    assert calls == 1
    recorded = engine.recorded_calls[0].request
    assert recorded["action"] == "tool:invoke"
    assert recorded["sideEffect"] == "read_only"
    assert recorded["task"] == {
        "taskId": TASK.task_id,
        "sessionId": TASK.session_id,
    }
    assert recorded["correlationId"] == CORRELATION
    assert "TOP-SECRET" not in repr(recorded)
    assert "tenant-not-authoritative" not in repr(recorded)
    assert "actor-not-authoritative" not in repr(recorded)


@pytest.mark.parametrize(
    ("outcome", "error_type"),
    [
        (ScriptedEngine.deny(), PolicyDenied),
        (ScriptedEngine.approval_required(), LangChainApprovalRequired),
        (ScriptedEngine.outage(), AuthorizationUnavailable),
    ],
)
def test_sync_tool_non_allow_never_invokes_handler(
    outcome: Any,
    error_type: type[BaseException],
) -> None:
    middleware, _ = _middleware(outcome)
    calls = 0

    def handler(request: ToolCallRequest) -> ToolMessage:
        del request
        nonlocal calls
        calls += 1
        raise AssertionError("must not execute")

    with pytest.raises(error_type):
        middleware.wrap_tool_call(_tool_request(context=_context()), handler)
    assert calls == 0


def test_sync_model_allow_gates_handler_without_serializing_prompts() -> None:
    middleware, engine = _middleware(ScriptedEngine.allow())
    request = _model_request(context=_context())
    request.messages.append(AIMessage(content="PROMPT-SECRET"))
    calls = 0

    def handler(value: ModelRequest[Any]) -> ModelResponse[Any]:
        nonlocal calls
        calls += 1
        assert len(engine.recorded_calls) == 1
        return ModelResponse(result=[AIMessage(content="ok")])

    response = middleware.wrap_model_call(request, handler)

    assert isinstance(response, ModelResponse)
    assert calls == 1
    recorded = engine.recorded_calls[0].request
    assert recorded["target"]["service"] == "model-runtime"
    assert "PROMPT-SECRET" not in repr(recorded)


def test_unknown_tool_model_and_malformed_context_fail_closed() -> None:
    middleware, _ = _middleware(ScriptedEngine.allow())
    unknown = _tool_request(context=_context())
    unknown.tool_call["name"] = "unknown"
    with pytest.raises(InvalidRequest):
        middleware.wrap_tool_call(unknown, lambda value: ToolMessage(content="bad"))
    with pytest.raises(InvalidRequest):
        middleware.wrap_model_call(
            _model_request(context=None),
            lambda value: ModelResponse(result=[AIMessage(content="bad")]),
        )


def test_absolute_deadline_is_bounded_and_expiry_executes_nothing() -> None:
    middleware, _ = _middleware(ScriptedEngine.allow())
    calls = 0

    def handler(request: ToolCallRequest) -> ToolMessage:
        del request
        nonlocal calls
        calls += 1
        return ToolMessage(content="bad")

    with pytest.raises(AuthorizationUnavailable):
        middleware.wrap_tool_call(
            _tool_request(context=_context(deadline=time.monotonic() - 1)),
            handler,
        )
    assert calls == 0
    with pytest.raises(InvalidRequest):
        middleware.wrap_tool_call(
            _tool_request(context=_context(deadline=time.monotonic() + 86_400)),
            handler,
        )


def test_tool_context_can_be_supplied_through_runnable_config() -> None:
    middleware, engine = _middleware(ScriptedEngine.allow())
    request = _tool_request(
        config={"configurable": {"palonexus": _context()}},
    )

    middleware.wrap_tool_call(
        request,
        lambda value: ToolMessage(
            content="ok",
            tool_call_id=value.tool_call["id"],
        ),
    )

    assert engine.recorded_calls[0].request["correlationId"] == CORRELATION


def test_authorization_timeout_never_enters_tool_handler() -> None:
    middleware, _ = _middleware(ScriptedEngine.delay(0.2, ScriptedEngine.allow()))
    calls = 0

    def handler(request: ToolCallRequest) -> ToolMessage:
        del request
        nonlocal calls
        calls += 1
        return ToolMessage(content="bad")

    with pytest.raises(AuthorizationUnavailable):
        middleware.wrap_tool_call(
            _tool_request(context=_context(deadline=time.monotonic() + 0.02)),
            handler,
        )
    assert calls == 0


def test_nested_calls_derive_causation_without_cross_thread_context_bleed() -> None:
    engine = ScriptedEngine(
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    middleware = PaloNexusLangChainMiddleware(
        client=AuthorizationClient(FakeTransport(engine, testing_only=True)),
        async_client=None,
        tool_policies={
            "inventory_read": LangChainActionPolicy(
                service="inventory",
                side_effect="read_only",
            )
        },
        model_policies={},
    )

    def invoke(correlation: str) -> None:
        context = _context(
            task=TaskContext(
                task_id=f"task_{correlation.removeprefix('corr_')}",
                session_id=TASK.session_id,
            ),
            correlation_id=correlation,
        )

        def outer(_: ToolCallRequest) -> ToolMessage:
            return middleware.wrap_tool_call(
                _tool_request(context=context),
                lambda request: ToolMessage(
                    content="inner",
                    tool_call_id=request.tool_call["id"],
                ),
            )

        middleware.wrap_tool_call(_tool_request(context=context), outer)

    correlations = (
        "corr_01J5ABCDEFGHJKMNPQRSTVWXY8",
        "corr_01J5ABCDEFGHJKMNPQRSTVWXY9",
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        list(pool.map(invoke, correlations))

    grouped: dict[str, list[dict[str, Any]]] = {value: [] for value in correlations}
    for call in engine.recorded_calls:
        grouped[str(call.request["correlationId"])].append(dict(call.request))
    assert all(len(values) == 2 for values in grouped.values())
    for values in grouped.values():
        roots = [value for value in values if value.get("causationId") is None]
        children = [value for value in values if value.get("causationId") is not None]
        assert len(roots) == len(children) == 1
        assert children[0]["causationId"] == roots[0]["actionId"]


def test_async_tool_and_model_allow_and_cancellation_preserve_boundaries() -> None:
    async def scenario() -> None:
        middleware, engine = _async_middleware(
            ScriptedEngine.delay(0.2, ScriptedEngine.allow())
        )
        calls = 0

        async def handler(request: ToolCallRequest) -> ToolMessage:
            del request
            nonlocal calls
            calls += 1
            return ToolMessage(content="bad")

        pending = asyncio.create_task(
            middleware.awrap_tool_call(_tool_request(context=_context()), handler)
        )
        await asyncio.sleep(0.02)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert calls == 0

        engine.enqueue(ScriptedEngine.allow(), ScriptedEngine.allow())
        tool_result = await middleware.awrap_tool_call(
            _tool_request(context=_context()),
            lambda request: asyncio.sleep(
                0,
                result=ToolMessage(
                    content="tool-ok",
                    tool_call_id=request.tool_call["id"],
                ),
            ),
        )
        model_result = await middleware.awrap_model_call(
            _model_request(context=_context()),
            lambda request: asyncio.sleep(
                0,
                result=ModelResponse(result=[AIMessage(content="model-ok")]),
            ),
        )
        assert tool_result.content == "tool-ok"
        assert isinstance(model_result, ModelResponse)

    asyncio.run(scenario())


def test_async_non_allow_never_invokes_tool_or_model_handlers() -> None:
    async def scenario() -> None:
        middleware, engine = _async_middleware(ScriptedEngine.deny())
        tool_calls = 0
        model_calls = 0

        async def tool_handler(request: ToolCallRequest) -> ToolMessage:
            del request
            nonlocal tool_calls
            tool_calls += 1
            return ToolMessage(content="bad")

        with pytest.raises(PolicyDenied):
            await middleware.awrap_tool_call(
                _tool_request(context=_context()),
                tool_handler,
            )
        engine.enqueue(ScriptedEngine.approval_required())

        async def model_handler(
            request: ModelRequest[Any],
        ) -> ModelResponse[Any]:
            del request
            nonlocal model_calls
            model_calls += 1
            return ModelResponse(result=[AIMessage(content="bad")])

        with pytest.raises(LangChainApprovalRequired):
            await middleware.awrap_model_call(
                _model_request(context=_context()),
                model_handler,
            )
        assert (tool_calls, model_calls) == (0, 0)

    asyncio.run(scenario())


def test_async_cancellation_after_allow_finalizes_handler() -> None:
    async def scenario() -> None:
        middleware, _ = _async_middleware(ScriptedEngine.allow())
        started = asyncio.Event()
        finalized = asyncio.Event()

        async def handler(request: ToolCallRequest) -> ToolMessage:
            del request
            started.set()
            try:
                await asyncio.Future()
            finally:
                finalized.set()
            raise AssertionError("unreachable")

        pending = asyncio.create_task(
            middleware.awrap_tool_call(
                _tool_request(context=_context()),
                handler,
            )
        )
        await asyncio.wait_for(started.wait(), timeout=1)
        pending.cancel()
        with pytest.raises(asyncio.CancelledError):
            await pending
        assert finalized.is_set()

    asyncio.run(scenario())


def test_real_langchain_agent_and_stream_are_gated_before_execution() -> None:
    executed = 0

    @tool
    def counted_inventory(item_id: str) -> str:
        """Read one inventory item."""

        nonlocal executed
        executed += 1
        return f"item:{item_id}"

    engine = ScriptedEngine(
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        ScriptedEngine.allow(),
        testing_only=True,
    )
    middleware = PaloNexusLangChainMiddleware(
        client=AuthorizationClient(FakeTransport(engine, testing_only=True)),
        async_client=None,
        tool_policies={
            "counted_inventory": LangChainActionPolicy(
                service="inventory",
                side_effect="read_only",
            )
        },
        model_policies={
            "fake-messages-list-chat-model": LangChainActionPolicy(
                service="model-runtime",
                side_effect="external",
            )
        },
    )
    model = _ToolCapableFakeModel(
        responses=[
            AIMessage(
                content="",
                tool_calls=[
                    {
                        "name": "counted_inventory",
                        "args": {"item_id": "42"},
                        "id": "call-real",
                        "type": "tool_call",
                    }
                ],
            ),
            AIMessage(content="done"),
        ]
    )
    agent = create_agent(
        model=model,
        tools=[counted_inventory],
        middleware=[middleware],
        context_schema=LangChainAuthorizationContext,
    )

    chunks = list(
        agent.stream(
            {"messages": [{"role": "user", "content": "read 42"}]},
            context=_context(),
        )
    )

    assert chunks
    assert executed == 1
    assert [call.request["action"] for call in engine.recorded_calls] == [
        "tool:invoke",
        "tool:invoke",
        "tool:invoke",
    ]

    denied_engine = ScriptedEngine(ScriptedEngine.deny(), testing_only=True)
    denied_middleware = PaloNexusLangChainMiddleware(
        client=AuthorizationClient(FakeTransport(denied_engine, testing_only=True)),
        async_client=None,
        tool_policies={},
        model_policies={
            "fake-messages-list-chat-model": LangChainActionPolicy(
                service="model-runtime",
                side_effect="external",
            )
        },
    )
    denied_agent = create_agent(
        model=FakeMessagesListChatModel(
            responses=[AIMessage(content="must-not-stream")]
        ),
        tools=[],
        middleware=[denied_middleware],
        context_schema=LangChainAuthorizationContext,
    )
    with pytest.raises(PolicyDenied):
        list(
            denied_agent.stream(
                {"messages": [{"role": "user", "content": "blocked"}]},
                context=_context(),
            )
        )


def test_policy_and_context_are_immutable_and_validate_side_effects() -> None:
    policy = LangChainActionPolicy(service="inventory", side_effect="write")
    assert policy.side_effect == "write"
    with pytest.raises(Exception):
        policy.side_effect = "read_only"  # type: ignore[misc]
    with pytest.raises(InvalidRequest):
        LangChainActionPolicy(service="inventory", side_effect="unknown")  # type: ignore[arg-type]
    with pytest.raises(InvalidRequest):
        PaloNexusLangChainMiddleware(
            client=object(),  # type: ignore[arg-type]
            async_client=None,
            tool_policies=MappingProxyType({}),
            model_policies={},
        )


def test_exception_rendering_never_retains_raw_tool_or_prompt_values() -> None:
    middleware, _ = _middleware(ScriptedEngine.deny())
    secret = "VERY-SECRET-TOOL-ARG"
    with pytest.raises(PolicyDenied) as captured:
        middleware.wrap_tool_call(
            _tool_request(
                context=_context(),
                args={"item_id": "42", "api_token": secret},
            ),
            lambda value: ToolMessage(content="bad"),
        )
    rendered = f"{captured.value!s} {captured.value!r}"
    assert secret not in rendered


def test_langchain_version_and_public_api_smoke() -> None:
    import langchain
    import langchain_core

    assert 1 <= int(langchain.__version__.split(".", 1)[0]) < 2
    assert 1 <= int(langchain_core.__version__.split(".", 1)[0]) < 2
    assert issubclass(PaloNexusLangChainMiddleware, object)
    assert issubclass(LangChainApprovalRequired, ApprovalRequired)
    assert issubclass(MissingIntegrationDependency, InvalidRequest)


def test_offline_example_runs_with_expected_markers() -> None:
    environment = {
        "PATH": os.environ["PATH"],
        "PYTHONPATH": str(ROOT / "python" / "src"),
    }
    completed = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "langchain" / "main.py")],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.splitlines() == [
        "LANGCHAIN_ALLOW_EXECUTED_ONCE",
        "LANGCHAIN_DENY_EXECUTED_ZERO",
        "LANGCHAIN_APPROVAL_EXECUTED_ZERO",
    ]
