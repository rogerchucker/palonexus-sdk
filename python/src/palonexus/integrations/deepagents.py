# SPDX-License-Identifier: MIT
"""Fail-closed Deep Agents integration over documented middleware hooks.

Deep Agents propagates runtime context to subagents and identifies the active
agent with ``runtime.config.metadata["lc_agent_name"]``. This adapter validates
both values before delegating authorization to the public PaloNexus LangChain
middleware. The LangChain adapter remains the sole owner of request creation,
authorization, approval signaling, and parent/child causation.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import inspect
from collections.abc import Awaitable, Callable, Iterator, Mapping, Sequence
from types import MappingProxyType
from typing import Any, Never, cast

from langchain.agents.middleware import AgentMiddleware
from langchain.tools.tool_node import ToolCallRequest
from langchain_core.messages import ToolMessage
from langchain_core.tools import BaseTool
from langgraph.types import Command

from ..errors import AuthorizationUnavailable, InvalidRequest, PaloNexusError
from . import MissingIntegrationDependency
from .langchain import (
    LangChainAuthorizationContext,
    PaloNexusLangChainMiddleware,
)

_CONTROL_FLOW_ERRORS = (
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
    concurrent.futures.CancelledError,
    asyncio.CancelledError,
)


class MissingDeepAgentsDependency(MissingIntegrationDependency):
    """Deep Agents is absent or lacks the required public middleware hooks."""

    canonical_message = (
        "The Deep Agents integration requires the 'palonexus[deepagents]' extra "
        "and a host with public middleware and context_schema hooks."
    )


def _invalid() -> Never:
    raise InvalidRequest() from None


def _checked_actor_map(value: object) -> Mapping[str, str]:
    if not isinstance(value, Mapping):
        _invalid()
    checked: dict[str, str] = {}
    try:
        for agent_name, actor_ref in value.items():
            if (
                type(agent_name) is not str
                or not agent_name
                or len(agent_name.encode("utf-8")) > 128
                or type(actor_ref) is not str
                or not actor_ref
                or len(actor_ref.encode("utf-8")) > 256
                or agent_name in checked
            ):
                raise ValueError
            checked[agent_name] = actor_ref
    except Exception:
        _invalid()
    if not checked:
        _invalid()
    return MappingProxyType(checked)


class DeepAgentsAuthorizationContext(Mapping[str, object]):
    """Immutable runtime context propagated by Deep Agents to every subagent.

    ``accountable_actors`` binds each configured Deep Agent name to the actor
    continuity assertion expected by the SDK. The transport-authenticated
    principal remains authoritative; this mapping cannot create authority.

    The mapping surface intentionally exposes only the ``palonexus`` key so the
    existing public LangChain middleware can consume the authorization context
    without private APIs or duplicated decision logic.
    """

    __slots__ = ("_accountable_actors", "_authorization")

    def __init__(
        self,
        *,
        authorization: LangChainAuthorizationContext,
        accountable_actors: Mapping[str, str],
    ) -> None:
        if type(authorization) is not LangChainAuthorizationContext:
            _invalid()
        checked = _checked_actor_map(accountable_actors)
        self._authorization = authorization
        self._accountable_actors = checked

    @property
    def authorization(self) -> LangChainAuthorizationContext:
        """The Task 10 authorization context consumed by nested middleware."""

        return self._authorization

    @property
    def accountable_actors(self) -> Mapping[str, str]:
        """Immutable agent-name to actor-continuity bindings."""

        return self._accountable_actors

    def __getitem__(self, key: str) -> object:
        if key == "palonexus":
            return self._authorization
        raise KeyError(key)

    def __iter__(self) -> Iterator[str]:
        yield "palonexus"

    def __len__(self) -> int:
        return 1

    def __repr__(self) -> str:
        return (
            "DeepAgentsAuthorizationContext("
            f"authorization={self._authorization!r}, "
            f"agents={tuple(sorted(self._accountable_actors))!r})"
        )


def _runtime_context(request: object) -> DeepAgentsAuthorizationContext:
    try:
        runtime = getattr(request, "runtime")
        context = getattr(runtime, "context")
    except Exception:
        _invalid()
    if type(context) is not DeepAgentsAuthorizationContext:
        _invalid()
    return context


def _agent_name(request: object) -> str:
    try:
        runtime = getattr(request, "runtime")
        config = getattr(runtime, "config")
        if not isinstance(config, Mapping):
            raise TypeError
        metadata = config.get("metadata")
        if not isinstance(metadata, Mapping):
            raise TypeError
        name = metadata.get("lc_agent_name")
        if type(name) is not str or not name or len(name.encode("utf-8")) > 128:
            raise TypeError
        return name
    except Exception:
        _invalid()
    raise AssertionError("unreachable")


class PaloNexusDeepAgentsMiddleware(AgentMiddleware[Any, Any]):
    """Validate Deep Agents provenance, then reuse Task 10 authorization."""

    __slots__ = ("_accountable_actors", "_authorization")

    def __init__(
        self,
        *,
        authorization: PaloNexusLangChainMiddleware,
        accountable_actors: Mapping[str, str],
    ) -> None:
        if type(authorization) is not PaloNexusLangChainMiddleware:
            _invalid()
        self._authorization = authorization
        self._accountable_actors = _checked_actor_map(accountable_actors)

    def _validate(self, request: object) -> None:
        context = _runtime_context(request)
        agent_name = _agent_name(request)
        if context.accountable_actors != self._accountable_actors:
            _invalid()
        expected_actor = self._accountable_actors.get(agent_name)
        if expected_actor is None or context.authorization.actor_ref != expected_actor:
            _invalid()

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        self._validate(request)
        return self._authorization.wrap_tool_call(request, handler)

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[
            [ToolCallRequest],
            Awaitable[ToolMessage | Command[Any]],
        ],
    ) -> ToolMessage | Command[Any]:
        self._validate(request)
        return await self._authorization.awrap_tool_call(request, handler)


def _factory_supports_public_hooks(factory: Callable[..., object]) -> bool:
    try:
        parameters = inspect.signature(factory).parameters
    except (TypeError, ValueError):
        return False
    return {"model", "tools", "middleware", "context_schema"} <= set(parameters)


def _installed_factory() -> Callable[..., object]:
    try:
        from deepagents import create_deep_agent
    except ImportError:
        raise MissingDeepAgentsDependency() from None
    if not callable(create_deep_agent):
        raise MissingDeepAgentsDependency() from None
    return cast(Callable[..., object], create_deep_agent)


def create_authorized_deep_agent(
    *,
    model: object,
    tools: Sequence[BaseTool],
    authorization: PaloNexusDeepAgentsMiddleware,
    middleware: Sequence[AgentMiddleware[Any, Any]] = (),
    deep_agent_factory: Callable[..., object] | None = None,
    **kwargs: object,
) -> object:
    """Create a Deep Agent using only its documented customization arguments."""

    if (
        type(authorization) is not PaloNexusDeepAgentsMiddleware
        or not isinstance(tools, Sequence)
        or any(not isinstance(tool, BaseTool) for tool in tools)
        or not isinstance(middleware, Sequence)
        or any(not isinstance(item, AgentMiddleware) for item in middleware)
        or any(
            isinstance(
                item,
                (PaloNexusDeepAgentsMiddleware, PaloNexusLangChainMiddleware),
            )
            for item in middleware
        )
        or {"model", "tools", "middleware", "context_schema"} & set(kwargs)
    ):
        _invalid()
    factory = _installed_factory() if deep_agent_factory is None else deep_agent_factory
    if not callable(factory) or not _factory_supports_public_hooks(factory):
        raise MissingDeepAgentsDependency() from None
    try:
        return factory(
            model=model,
            tools=tuple(tools),
            middleware=(*middleware, authorization),
            context_schema=DeepAgentsAuthorizationContext,
            **kwargs,
        )
    except BaseException as error:
        if isinstance(error, _CONTROL_FLOW_ERRORS):
            raise
        if isinstance(error, PaloNexusError):
            raise error from None
        raise AuthorizationUnavailable() from None


__all__ = [
    "DeepAgentsAuthorizationContext",
    "MissingDeepAgentsDependency",
    "PaloNexusDeepAgentsMiddleware",
    "create_authorized_deep_agent",
]
