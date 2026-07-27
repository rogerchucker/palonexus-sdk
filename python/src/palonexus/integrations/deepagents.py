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

from ..errors import AuthorizationUnavailable, PaloNexusError
from . import MissingIntegrationDependency

_CONTROL_FLOW_ERRORS = (
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
    concurrent.futures.CancelledError,
    asyncio.CancelledError,
)
_HOST_BUILTINS = frozenset(
    {
        "edit_file",
        "execute",
        "glob",
        "grep",
        "ls",
        "read_file",
        "task",
        "write_file",
        "write_todos",
    }
)


class MissingDeepAgentsDependency(MissingIntegrationDependency):
    """Deep Agents is absent or lacks the required public middleware hooks."""

    canonical_message = (
        "The Deep Agents integration requires the 'palonexus[deepagents]' extra "
        "and a host with public middleware and context_schema hooks."
    )


try:
    from langchain.agents.middleware import (
        AgentMiddleware,
        ModelRequest,
        ModelResponse,
    )
    from langchain.tools.tool_node import ToolCallRequest
    from langchain_core.messages import AIMessage, ToolMessage
    from langchain_core.tools import BaseTool
    from langgraph.types import Command

    from .langchain import (
        LangChainActionPolicy,
        LangChainAuthorizationContext,
        LangChainInvalidRequest,
        PaloNexusLangChainMiddleware,
    )
except ImportError:
    raise MissingDeepAgentsDependency() from None


def _invalid() -> Never:
    raise LangChainInvalidRequest() from None


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


def _checked_user_middleware(value: object) -> tuple[AgentMiddleware[Any, Any], ...]:
    if not isinstance(value, Sequence):
        _invalid()
    checked: list[AgentMiddleware[Any, Any]] = []
    try:
        for item in value:
            if not isinstance(item, AgentMiddleware) or isinstance(
                item,
                (PaloNexusDeepAgentsMiddleware, PaloNexusLangChainMiddleware),
            ):
                raise TypeError
            injected = item.tools
            if any(
                not isinstance(tool, BaseTool) or tool.name in _HOST_BUILTINS
                for tool in injected
            ):
                raise TypeError
            checked.append(item)
    except Exception:
        _invalid()
    return tuple(checked)


def _checked_user_tools(value: object) -> tuple[BaseTool, ...]:
    if not isinstance(value, Sequence):
        _invalid()
    checked: list[BaseTool] = []
    names: set[str] = set()
    try:
        for tool in value:
            if (
                not isinstance(tool, BaseTool)
                or tool.name in _HOST_BUILTINS
                or tool.name in names
            ):
                raise TypeError
            names.add(tool.name)
            checked.append(tool)
    except Exception:
        _invalid()
    return tuple(checked)


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


def _agent_name(request: object) -> str | None:
    try:
        runtime = getattr(request, "runtime")
        config = getattr(runtime, "config", None)
        if config is None:
            return None
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

    __slots__ = (
        "_accountable_actors",
        "_authorization",
        "_bound_agent_name",
        "_governed_subagents",
        "_orchestration_builtins",
    )

    def __init__(
        self,
        *,
        authorization: PaloNexusLangChainMiddleware,
        accountable_actors: Mapping[str, str],
        _bound_agent_name: str | None = None,
        _governed_subagents: frozenset[str] = frozenset(),
        _orchestration_builtins: bool = False,
    ) -> None:
        if type(authorization) is not PaloNexusLangChainMiddleware:
            _invalid()
        self._authorization = authorization
        self._accountable_actors = _checked_actor_map(accountable_actors)
        self._bound_agent_name = _bound_agent_name
        self._governed_subagents = _governed_subagents
        self._orchestration_builtins = _orchestration_builtins

    @property
    def accountable_actors(self) -> Mapping[str, str]:
        """The immutable bindings required in runtime context."""

        return self._accountable_actors

    def _for_factory(
        self,
        governed_subagents: frozenset[str],
        bound_agent_name: str,
    ) -> PaloNexusDeepAgentsMiddleware:
        if not governed_subagents or bound_agent_name not in self._accountable_actors:
            _invalid()
        return _FactoryBoundPaloNexusMiddleware(
            authorization=self._authorization,
            accountable_actors=self._accountable_actors,
            _bound_agent_name=bound_agent_name,
            _governed_subagents=governed_subagents,
            _orchestration_builtins=True,
        )

    def _validate(self, request: object) -> None:
        context = _runtime_context(request)
        observed = _agent_name(request)
        agent_name = self._bound_agent_name
        if agent_name is None:
            if observed is None:
                _invalid()
            agent_name = observed
        elif observed is not None and observed != agent_name:
            _invalid()
        if context.accountable_actors != self._accountable_actors:
            _invalid()
        expected_actor = self._accountable_actors.get(agent_name)
        if expected_actor is None or context.authorization.actor_ref != expected_actor:
            _invalid()

    def _orchestration_tool(self, request: ToolCallRequest) -> str | None:
        if not self._orchestration_builtins:
            return None
        try:
            name = request.tool_call["name"]
            arguments = request.tool_call["args"]
            if (
                type(name) is not str
                or not isinstance(arguments, Mapping)
                or request.tool is None
                or request.tool.name != name
            ):
                raise TypeError
            if name == "write_todos":
                if frozenset(arguments) != {"todos"} or not isinstance(
                    arguments["todos"], list
                ):
                    raise TypeError
                return "write_todos"
            if name != "task":
                return None
            if frozenset(arguments) != {"description", "subagent_type"}:
                raise TypeError
            description = arguments["description"]
            subagent_type = arguments["subagent_type"]
            if (
                type(description) is not str
                or not description
                or type(subagent_type) is not str
                or subagent_type not in self._governed_subagents
            ):
                raise TypeError
            return subagent_type
        except Exception:
            _invalid()
        raise AssertionError("unreachable")

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        self._validate(request)
        orchestration = self._orchestration_tool(request)
        if orchestration == "write_todos":
            return handler(request)
        if orchestration is not None:
            if request.tool is None:
                _invalid()
            bound = self._authorization.with_tool_binding(
                tool=request.tool,
                policy=LangChainActionPolicy(
                    service=f"deep-agent-{orchestration}",
                    side_effect="external",
                ),
            )
            return bound.wrap_tool_call(request, handler)
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
        orchestration = self._orchestration_tool(request)
        if orchestration == "write_todos":
            return await handler(request)
        if orchestration is not None:
            if request.tool is None:
                _invalid()
            bound = self._authorization.with_tool_binding(
                tool=request.tool,
                policy=LangChainActionPolicy(
                    service=f"deep-agent-{orchestration}",
                    side_effect="external",
                ),
            )
            return await bound.awrap_tool_call(request, handler)
        return await self._authorization.awrap_tool_call(request, handler)

    def wrap_model_call(
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], ModelResponse[Any]],
    ) -> ModelResponse[Any] | AIMessage:
        self._validate(request)
        return self._authorization.wrap_model_call(request, handler)

    async def awrap_model_call(
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], Awaitable[ModelResponse[Any]]],
    ) -> ModelResponse[Any] | AIMessage:
        self._validate(request)
        return await self._authorization.awrap_model_call(request, handler)


class _FactoryBoundPaloNexusMiddleware(PaloNexusDeepAgentsMiddleware):
    """Profile-resistant bound middleware.

    Deep Agents matches excluded middleware classes by exact type and string
    entries by the public ``name`` alias. A factory-local subtype prevents an
    exclusion of the public configurable class from matching. A public-name
    string exclusion likewise matches nothing, which Deep Agents rejects
    through its documented exclusion-coverage validation instead of silently
    constructing an unguarded graph.
    """

    __slots__ = ()


def _factory_supports_public_hooks(factory: Callable[..., object]) -> bool:
    try:
        parameters = inspect.signature(factory).parameters
    except (TypeError, ValueError):
        return False
    return {
        "model",
        "tools",
        "middleware",
        "context_schema",
        "name",
        "subagents",
    } <= set(parameters)


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
    name: str,
    subagents: Sequence[Mapping[str, object]] = (),
    middleware: Sequence[AgentMiddleware[Any, Any]] = (),
    deep_agent_factory: Callable[..., object] | None = None,
    **kwargs: object,
) -> object:
    """Create a Deep Agent using only its documented customization arguments."""

    if (
        type(authorization) is not PaloNexusDeepAgentsMiddleware
        or type(name) is not str
        or not name
        or len(name.encode("utf-8")) > 128
        or not isinstance(subagents, Sequence)
        or {"model", "tools", "middleware", "context_schema", "name", "subagents"}
        & set(kwargs)
    ):
        _invalid()
    checked_tools = _checked_user_tools(tools)
    checked_middleware = _checked_user_middleware(middleware)
    allowed_keys = frozenset(
        {
            "name",
            "description",
            "system_prompt",
            "tools",
            "middleware",
            "interrupt_on",
            "skills",
            "permissions",
            "response_format",
        }
    )
    prepared: list[dict[str, object]] = []
    names: set[str] = set()
    for raw in subagents:
        if not isinstance(raw, Mapping) or not frozenset(raw) <= allowed_keys:
            _invalid()
        try:
            agent_name = raw["name"]
            description = raw["description"]
            system_prompt = raw["system_prompt"]
        except Exception:
            _invalid()
        if (
            type(agent_name) is not str
            or not agent_name
            or len(agent_name.encode("utf-8")) > 128
            or agent_name in names
            or agent_name == name
            or type(description) is not str
            or not description
            or type(system_prompt) is not str
            or not system_prompt
        ):
            _invalid()
        selected_tools = _checked_user_tools(raw.get("tools", checked_tools))
        selected_middleware = raw.get("middleware", ())
        checked_subagent_middleware = _checked_user_middleware(selected_middleware)
        names.add(agent_name)
        copied = dict(raw)
        copied["tools"] = selected_tools
        copied["middleware"] = checked_subagent_middleware
        prepared.append(copied)
    if "general-purpose" not in names:
        names.add("general-purpose")
        prepared.append(
            {
                "name": "general-purpose",
                "description": "Governed general-purpose delegated work.",
                "system_prompt": (
                    "Complete only the delegated task using governed tools."
                ),
                "tools": checked_tools,
            }
        )
    expected_actors = {name, *names}
    if set(authorization.accountable_actors) != expected_actors:
        _invalid()
    governed_names = frozenset(names)
    governed = authorization._for_factory(governed_names, name)
    for spec in prepared:
        existing = spec.get("middleware", ())
        if not isinstance(existing, Sequence):
            _invalid()
        subagent_name = spec["name"]
        if type(subagent_name) is not str:
            _invalid()
        spec["middleware"] = [
            *existing,
            authorization._for_factory(governed_names, subagent_name),
        ]
    factory = _installed_factory() if deep_agent_factory is None else deep_agent_factory
    if not callable(factory) or not _factory_supports_public_hooks(factory):
        raise MissingDeepAgentsDependency() from None
    try:
        return factory(
            model=model,
            tools=checked_tools,
            middleware=(*checked_middleware, governed),
            context_schema=DeepAgentsAuthorizationContext,
            name=name,
            subagents=tuple(prepared),
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
