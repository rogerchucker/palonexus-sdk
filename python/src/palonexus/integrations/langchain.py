# SPDX-License-Identifier: MIT
"""Fail-closed LangChain 1.x model and tool authorization middleware.

The adapter gates each handler invocation through the public PaloNexus client
and request-builder contracts. It does not implement durable approval resume;
compose it with LangChain HITL only to collect a human decision, and use the
PaloNexus LangGraph integration for checkpointed resume semantics.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import inspect
import math
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, Protocol, TypeVar, cast, runtime_checkable

from ..client import AuthorizationDecision
from ..errors import (
    ApprovalRequired,
    AuthorizationUnavailable,
    InvalidRequest,
    PaloNexusError,
    PolicyDenied,
)
from ..models import ActionTarget, DecisionOutcome, TaskContext
from ..protocol import ActionRequestBuilder
from . import MissingIntegrationDependency

try:
    import langchain
    from langchain.agents import create_agent
    from langchain.agents.middleware import (
        AgentMiddleware,
        ModelRequest,
        ModelResponse,
    )
    from langchain.tools.tool_node import ToolCallRequest
    from langchain_core.language_models.chat_models import BaseChatModel
    from langchain_core.messages import AIMessage, ToolMessage
    from langchain_core.tools import BaseTool
    from langgraph.types import Command
except ImportError:
    raise MissingIntegrationDependency() from None

type SideEffect = Literal["read_only", "write", "destructive", "external"]
_ResultT = TypeVar("_ResultT")
_MAX_DEADLINE_HORIZON_SECONDS = 3600.0
_SIDE_EFFECTS = frozenset({"read_only", "write", "destructive", "external"})
_CONTROL_FLOW_ERRORS = (
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
    concurrent.futures.CancelledError,
    asyncio.CancelledError,
)


def _discard_exception_graph(error: BaseException) -> None:
    """Sever an untrusted exception graph before raising a safe replacement."""

    pending = [error]
    seen: set[int] = set()
    while pending:
        current = pending.pop()
        identity = id(current)
        if identity in seen:
            continue
        seen.add(identity)
        cause = current.__cause__
        context = current.__context__
        if cause is not None:
            pending.append(cause)
        if context is not None:
            pending.append(context)
        if isinstance(current, BaseExceptionGroup):
            pending.extend(current.exceptions)
        try:
            current.__traceback__ = None
            current.__cause__ = None
            current.__context__ = None
        except Exception:
            pass


def _dispose_malformed_awaitable(value: object) -> None:
    """Best-effort cleanup without trusting close/cancel implementations."""

    methods = ("close",) if inspect.iscoroutine(value) else ("cancel", "close")
    for name in methods:
        method = getattr(value, name, None)
        if not callable(method):
            continue
        try:
            method()
        except BaseException as error:
            if isinstance(error, _CONTROL_FLOW_ERRORS):
                raise
            _discard_exception_graph(error)


class _LangChainCompatible:
    """Permit framework annotation without retaining framework-provided text."""

    def add_note(self, note: str) -> None:
        del note


class LangChainInvalidRequest(_LangChainCompatible, InvalidRequest):
    """LangChain-compatible invalid integration input."""


class LangChainPolicyDenied(_LangChainCompatible, PolicyDenied):
    """LangChain-compatible pre-execution policy denial."""


class LangChainAuthorizationUnavailable(
    _LangChainCompatible,
    AuthorizationUnavailable,
):
    """LangChain-compatible fail-closed authorization outage."""


class LangChainApprovalRequired(_LangChainCompatible, ApprovalRequired):
    """LangChain pre-execution signal for PaloNexus approval.

    This exception is intentionally safe and contains only validated decision
    identifiers. No prompt, tool argument, or model response is retained.
    """


@runtime_checkable
class SyncAuthorizationClientProtocol(Protocol):
    """Public client surface consumed by synchronous middleware."""

    @property
    def authorization_client_kind(self) -> Literal["sync"]: ...

    def authorize(
        self,
        attempt: Any,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> AuthorizationDecision: ...


@runtime_checkable
class AsyncAuthorizationClientProtocol(Protocol):
    """Public client surface consumed by asynchronous middleware."""

    @property
    def authorization_client_kind(self) -> Literal["async"]: ...

    async def authorize(
        self,
        attempt: Any,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> AuthorizationDecision: ...


@dataclass(frozen=True, slots=True)
class LangChainActionPolicy:
    """Trusted, application-owned classification for one model or tool."""

    service: str
    side_effect: SideEffect

    def __post_init__(self) -> None:
        if (
            type(self.service) is not str
            or not self.service
            or len(self.service) > 128
            or type(self.side_effect) is not str
            or self.side_effect not in _SIDE_EFFECTS
        ):
            raise InvalidRequest() from None


@dataclass(frozen=True, slots=True, repr=False)
class LangChainAuthorizationContext:
    """Explicit run-scoped authorization data supplied through LangChain.

    ``tenant_ref`` and ``actor_ref`` are continuity assertions only. They are
    deliberately not serialized into the action request and cannot replace the
    authenticated tenant/actor established by the PaloNexus transport.
    """

    task: TaskContext
    correlation_id: str
    model_policy_key: str
    tenant_ref: str | None = None
    actor_ref: str | None = None
    deadline: float | None = None
    cancelled: Callable[[], bool] | None = None

    def __post_init__(self) -> None:
        try:
            checked_task = TaskContext.model_validate(
                {
                    "task_id": self.task.task_id,
                    "session_id": self.task.session_id,
                }
            )
        except Exception:
            raise InvalidRequest() from None
        if checked_task != self.task:
            raise InvalidRequest() from None
        if type(self.correlation_id) is not str:
            raise InvalidRequest() from None
        if (
            type(self.model_policy_key) is not str
            or not self.model_policy_key
            or len(self.model_policy_key) > 128
        ):
            raise InvalidRequest() from None
        for value in (self.tenant_ref, self.actor_ref):
            if value is not None and (
                type(value) is not str or not value or len(value) > 256
            ):
                raise InvalidRequest() from None
        if self.deadline is not None and (
            isinstance(self.deadline, bool)
            or not isinstance(self.deadline, (int, float))
            or not math.isfinite(self.deadline)
        ):
            raise InvalidRequest() from None
        if self.cancelled is not None and not callable(self.cancelled):
            raise InvalidRequest() from None

    def __repr__(self) -> str:
        return (
            "LangChainAuthorizationContext("
            f"task={self.task!r}, correlation_id={self.correlation_id!r}, "
            f"model_policy_key={self.model_policy_key!r}, "
            f"deadline={self.deadline!r})"
        )


@dataclass(frozen=True, slots=True)
class _CallFrame:
    task: TaskContext
    correlation_id: str
    action_id: str
    tenant_ref: str | None
    actor_ref: str | None
    model_policy_key: str
    deadline: float | None
    cancelled: Callable[[], bool] | None


_CURRENT_CALL: contextvars.ContextVar[_CallFrame | None] = contextvars.ContextVar(
    "palonexus_langchain_current_call",
    default=None,
)


def _immutable_policies(
    value: Mapping[str, LangChainActionPolicy],
) -> Mapping[str, LangChainActionPolicy]:
    if not isinstance(value, Mapping):
        raise InvalidRequest() from None
    result: dict[str, LangChainActionPolicy] = {}
    try:
        for key, policy in value.items():
            if (
                type(key) is not str
                or not key
                or type(policy) is not LangChainActionPolicy
            ):
                raise TypeError
            result[key] = policy
    except Exception:
        raise InvalidRequest() from None
    return MappingProxyType(result)


def _context_from_value(value: object) -> LangChainAuthorizationContext | None:
    if type(value) is LangChainAuthorizationContext:
        return value
    if isinstance(value, Mapping):
        nested = value.get("palonexus")
        if type(nested) is LangChainAuthorizationContext:
            return nested
    return None


def _request_context(request: object) -> LangChainAuthorizationContext:
    runtime = getattr(request, "runtime", None)
    explicit = _context_from_value(getattr(runtime, "context", None))
    if explicit is None:
        config = getattr(runtime, "config", None)
        if isinstance(config, Mapping):
            configurable = config.get("configurable")
            explicit = _context_from_value(configurable)
    if explicit is None:
        frame = _CURRENT_CALL.get()
        if frame is not None:
            return LangChainAuthorizationContext(
                task=frame.task,
                correlation_id=frame.correlation_id,
                model_policy_key=frame.model_policy_key,
                tenant_ref=frame.tenant_ref,
                actor_ref=frame.actor_ref,
                deadline=frame.deadline,
                cancelled=frame.cancelled,
            )
        raise InvalidRequest() from None
    return explicit


def _checked_deadline(value: float | None) -> float | None:
    if value is None:
        return None
    now = time.monotonic()
    if value <= now:
        raise AuthorizationUnavailable() from None
    if value - now > _MAX_DEADLINE_HORIZON_SECONDS:
        raise InvalidRequest() from None
    return float(value)


def _cancelled(callback: Callable[[], bool] | None) -> bool:
    if callback is None:
        return False
    try:
        return callback() is not False
    except BaseException:
        return True


def _combined_cancelled(
    parent: Callable[[], bool] | None,
    child: Callable[[], bool] | None,
) -> Callable[[], bool] | None:
    if parent is None:
        return child
    if child is None or child is parent:
        return parent

    def combined() -> bool:
        return _cancelled(parent) or _cancelled(child)

    return combined


def _tool_name(request: ToolCallRequest) -> str:
    try:
        name = request.tool_call["name"]
        if type(name) is not str or not name:
            raise TypeError
        tool = request.tool
        if tool is None or getattr(tool, "name", None) != name:
            raise TypeError
        return name
    except Exception:
        raise InvalidRequest() from None


def _tool_arguments(request: ToolCallRequest) -> object:
    try:
        arguments = request.tool_call["args"]
        if not isinstance(arguments, Mapping):
            raise TypeError
        return dict(arguments)
    except Exception:
        raise InvalidRequest() from None


class PaloNexusLangChainMiddleware(AgentMiddleware[Any, Any]):
    """Authorize LangChain tool/model handlers before any execution starts."""

    __slots__ = (
        "_async_client",
        "_builder",
        "_client",
        "_model_bindings",
        "_model_policies",
        "_tool_bindings",
        "_tool_policies",
    )

    def __init__(
        self,
        *,
        client: SyncAuthorizationClientProtocol | None,
        async_client: AsyncAuthorizationClientProtocol | None,
        tool_policies: Mapping[str, LangChainActionPolicy],
        model_policies: Mapping[str, LangChainActionPolicy],
        model_bindings: Mapping[str, BaseChatModel] | None = None,
        tool_bindings: Mapping[str, BaseTool] | None = None,
    ) -> None:
        if client is not None and (
            not isinstance(client, SyncAuthorizationClientProtocol)
            or client.authorization_client_kind != "sync"
        ):
            raise InvalidRequest() from None
        if async_client is not None and (
            not isinstance(async_client, AsyncAuthorizationClientProtocol)
            or async_client.authorization_client_kind != "async"
        ):
            raise InvalidRequest() from None
        if client is not None and inspect.iscoroutinefunction(client.authorize):
            raise InvalidRequest() from None
        if client is None and async_client is None:
            raise InvalidRequest() from None
        self._client = client
        self._async_client = async_client
        self._tool_policies = _immutable_policies(tool_policies)
        self._model_policies = _immutable_policies(model_policies)
        bindings = {} if model_bindings is None else dict(model_bindings)
        if any(
            type(key) is not str or not key or not isinstance(model, BaseChatModel)
            for key, model in bindings.items()
        ):
            raise InvalidRequest() from None
        self._model_bindings = MappingProxyType(bindings)
        bound_tools = {} if tool_bindings is None else dict(tool_bindings)
        if any(
            type(key) is not str
            or not key
            or not isinstance(bound_tool, BaseTool)
            or bound_tool.name != key
            for key, bound_tool in bound_tools.items()
        ):
            raise InvalidRequest() from None
        self._tool_bindings = MappingProxyType(bound_tools)
        self._builder = ActionRequestBuilder(
            adapter_id="palonexus-langchain",
            adapter_version="0.2.0",
            host_version=str(langchain.__version__),
        )

    def _with_agent_bindings(
        self,
        policy_key: str,
        model: BaseChatModel,
        tools: Sequence[BaseTool],
    ) -> PaloNexusLangChainMiddleware:
        if policy_key not in self._model_policies:
            raise InvalidRequest() from None
        bindings = dict(self._model_bindings)
        existing = bindings.get(policy_key)
        if existing is not None and existing is not model:
            raise InvalidRequest() from None
        bindings[policy_key] = model
        tool_bindings: dict[str, BaseTool] = {}
        for bound_tool in tools:
            if not isinstance(bound_tool, BaseTool) or bound_tool.name in tool_bindings:
                raise InvalidRequest() from None
            tool_bindings[bound_tool.name] = bound_tool
        if set(tool_bindings) != set(self._tool_policies):
            raise InvalidRequest() from None
        return PaloNexusLangChainMiddleware(
            client=self._client,
            async_client=self._async_client,
            tool_policies=self._tool_policies,
            model_policies=self._model_policies,
            model_bindings=bindings,
            tool_bindings=tool_bindings,
        )

    def with_tool_binding(
        self,
        *,
        tool: BaseTool,
        policy: LangChainActionPolicy,
    ) -> PaloNexusLangChainMiddleware:
        """Return a copy bound to one exact host-created public tool object.

        Host integrations use this only after validating a framework-generated
        tool and its immutable target. The exact object binding preserves the
        same substitution resistance as statically configured tools.
        """

        if not isinstance(tool, BaseTool) or type(policy) is not LangChainActionPolicy:
            raise InvalidRequest() from None
        name = tool.name
        existing_tool = self._tool_bindings.get(name)
        existing_policy = self._tool_policies.get(name)
        if (existing_tool is not None and existing_tool is not tool) or (
            existing_policy is not None and existing_policy != policy
        ):
            raise InvalidRequest() from None
        tools = dict(self._tool_bindings)
        policies = dict(self._tool_policies)
        tools[name] = tool
        policies[name] = policy
        return PaloNexusLangChainMiddleware(
            client=self._client,
            async_client=self._async_client,
            tool_policies=policies,
            model_policies=self._model_policies,
            model_bindings=self._model_bindings,
            tool_bindings=tools,
        )

    def _prepare(
        self,
        *,
        request: object,
        name: str,
        arguments: object,
        policies: Mapping[str, LangChainActionPolicy],
    ) -> tuple[object, LangChainAuthorizationContext, _CallFrame]:
        context = _request_context(request)
        deadline = _checked_deadline(context.deadline)
        del deadline
        policy = policies.get(name)
        if policy is None:
            raise InvalidRequest() from None
        del arguments
        target = self._builder.prepare_generic_target(
            ActionTarget(
                kind="tool",
                service=policy.service,
                resource=f"tool:{policy.service}/{name}",
            )
        )
        parent = _CURRENT_CALL.get()
        if parent is not None and (
            context.task != parent.task
            or context.correlation_id != parent.correlation_id
            or context.tenant_ref != parent.tenant_ref
            or context.actor_ref != parent.actor_ref
            or context.model_policy_key != parent.model_policy_key
        ):
            raise InvalidRequest() from None
        if parent is not None:
            deadlines = tuple(
                value
                for value in (parent.deadline, context.deadline)
                if value is not None
            )
            context = LangChainAuthorizationContext(
                task=context.task,
                correlation_id=context.correlation_id,
                model_policy_key=context.model_policy_key,
                tenant_ref=context.tenant_ref,
                actor_ref=context.actor_ref,
                deadline=min(deadlines) if deadlines else None,
                cancelled=_combined_cancelled(
                    parent.cancelled,
                    context.cancelled,
                ),
            )
        causation_id = None if parent is None else parent.action_id
        intent = self._builder.new(
            action="tool:invoke",
            target=target,
            side_effect=policy.side_effect,
            task_context=context.task,
            correlation_id=context.correlation_id,
            causation_id=causation_id,
        )
        attempt = self._builder.build(
            intent,
            prepared_target=target,
            tool_name=name,
            safe_display=f"LangChain {name}",
        )
        frame = _CallFrame(
            task=context.task,
            correlation_id=context.correlation_id,
            action_id=str(attempt.request.action_id),
            tenant_ref=context.tenant_ref,
            actor_ref=context.actor_ref,
            model_policy_key=context.model_policy_key,
            deadline=context.deadline,
            cancelled=context.cancelled,
        )
        return attempt, context, frame

    @staticmethod
    def _compatible(error: PaloNexusError) -> PaloNexusError:
        identifiers = {
            "request_id": error.request_id,
            "decision_id": error.decision_id,
            "correlation_id": error.correlation_id,
        }
        if isinstance(error, LangChainApprovalRequired):
            return error
        if isinstance(error, ApprovalRequired):
            return LangChainApprovalRequired(**identifiers)
        if isinstance(error, PolicyDenied):
            return LangChainPolicyDenied(**identifiers)
        if isinstance(error, AuthorizationUnavailable):
            return LangChainAuthorizationUnavailable(**identifiers)
        if isinstance(error, InvalidRequest):
            return LangChainInvalidRequest(**identifiers)
        return LangChainInvalidRequest(**identifiers)

    def _raise_client_error(self, error: BaseException) -> None:
        if isinstance(error, _CONTROL_FLOW_ERRORS):
            raise error
        replacement: PaloNexusError
        if isinstance(error, PaloNexusError):
            replacement = self._compatible(error)
        else:
            replacement = LangChainAuthorizationUnavailable()
        _discard_exception_graph(error)
        raise replacement from None

    def _authorize(
        self,
        attempt: Any,
        context: LangChainAuthorizationContext,
    ) -> None:
        if self._client is None:
            raise InvalidRequest() from None
        try:
            if _cancelled(context.cancelled):
                raise concurrent.futures.CancelledError
            result = self._client.authorize(
                attempt,
                deadline=_checked_deadline(context.deadline),
                cancelled=context.cancelled,
            )
            if inspect.isawaitable(result):
                _dispose_malformed_awaitable(result)
                raise InvalidRequest() from None
            if (
                type(result) is not AuthorizationDecision
                or result.outcome is not DecisionOutcome.ALLOW
                or result.request_id != str(attempt.request.request_id)
                or result.correlation_id != str(attempt.request.correlation_id)
                or result.client_scope_hash != attempt.client_scope_hash
            ):
                raise InvalidRequest() from None
        except BaseException as error:
            self._raise_client_error(error)
        finally:
            attempt.close()

    async def _aauthorize(
        self,
        attempt: Any,
        context: LangChainAuthorizationContext,
    ) -> None:
        if self._async_client is None:
            raise InvalidRequest() from None
        try:
            if _cancelled(context.cancelled):
                raise asyncio.CancelledError
            pending = self._async_client.authorize(
                attempt,
                deadline=_checked_deadline(context.deadline),
                cancelled=context.cancelled,
            )
            if not inspect.isawaitable(pending):
                raise InvalidRequest() from None
            result = await pending
            if (
                type(result) is not AuthorizationDecision
                or result.outcome is not DecisionOutcome.ALLOW
                or result.request_id != str(attempt.request.request_id)
                or result.correlation_id != str(attempt.request.correlation_id)
                or result.client_scope_hash != attempt.client_scope_hash
            ):
                raise InvalidRequest() from None
        except BaseException as error:
            self._raise_client_error(error)
        finally:
            attempt.close()

    @staticmethod
    def _call_with_frame(
        frame: _CallFrame,
        handler: Callable[[_ResultT], Any],
        request: _ResultT,
    ) -> Any:
        token = _CURRENT_CALL.set(frame)
        try:
            return handler(request)
        finally:
            _CURRENT_CALL.reset(token)

    @staticmethod
    async def _acall_with_frame(
        frame: _CallFrame,
        handler: Callable[[_ResultT], Awaitable[Any]],
        request: _ResultT,
    ) -> Any:
        token = _CURRENT_CALL.set(frame)
        try:
            return await handler(request)
        finally:
            _CURRENT_CALL.reset(token)

    def wrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[[ToolCallRequest], ToolMessage | Command[Any]],
    ) -> ToolMessage | Command[Any]:
        try:
            name = _tool_name(request)
            if self._tool_bindings.get(name) is not request.tool:
                raise InvalidRequest() from None
            attempt, context, frame = self._prepare(
                request=request,
                name=name,
                arguments=_tool_arguments(request),
                policies=self._tool_policies,
            )
            self._authorize(attempt, context)
        except PaloNexusError as error:
            raise self._compatible(error) from None
        return cast(
            ToolMessage | Command[Any],
            self._call_with_frame(frame, handler, request),
        )

    async def awrap_tool_call(
        self,
        request: ToolCallRequest,
        handler: Callable[
            [ToolCallRequest],
            Awaitable[ToolMessage | Command[Any]],
        ],
    ) -> ToolMessage | Command[Any]:
        try:
            name = _tool_name(request)
            if self._tool_bindings.get(name) is not request.tool:
                raise InvalidRequest() from None
            attempt, context, frame = self._prepare(
                request=request,
                name=name,
                arguments=_tool_arguments(request),
                policies=self._tool_policies,
            )
            await self._aauthorize(attempt, context)
        except PaloNexusError as error:
            raise self._compatible(error) from None
        return cast(
            ToolMessage | Command[Any],
            await self._acall_with_frame(frame, handler, request),
        )

    def wrap_model_call(
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], ModelResponse[Any]],
    ) -> ModelResponse[Any] | AIMessage:
        try:
            selected = _request_context(request)
            name = selected.model_policy_key
            policy = self._model_policies.get(name)
            if policy is None or self._model_bindings.get(name) is not request.model:
                raise InvalidRequest() from None
            attempt, context, frame = self._prepare(
                request=request,
                name=name,
                arguments={},
                policies=self._model_policies,
            )
            self._authorize(attempt, context)
        except PaloNexusError as error:
            raise self._compatible(error) from None
        return cast(
            ModelResponse[Any] | AIMessage,
            self._call_with_frame(frame, handler, request),
        )

    async def awrap_model_call(
        self,
        request: ModelRequest[Any],
        handler: Callable[[ModelRequest[Any]], Awaitable[ModelResponse[Any]]],
    ) -> ModelResponse[Any] | AIMessage:
        try:
            selected = _request_context(request)
            name = selected.model_policy_key
            policy = self._model_policies.get(name)
            if policy is None or self._model_bindings.get(name) is not request.model:
                raise InvalidRequest() from None
            attempt, context, frame = self._prepare(
                request=request,
                name=name,
                arguments={},
                policies=self._model_policies,
            )
            await self._aauthorize(attempt, context)
        except PaloNexusError as error:
            raise self._compatible(error) from None
        return cast(
            ModelResponse[Any] | AIMessage,
            await self._acall_with_frame(frame, handler, request),
        )


def validate_authorized_middleware_stack(
    middleware: Sequence[AgentMiddleware[Any, Any]],
) -> tuple[AgentMiddleware[Any, Any], ...]:
    """Require exactly one PaloNexus middleware in the innermost position."""

    if not isinstance(middleware, Sequence):
        raise InvalidRequest() from None
    checked = tuple(middleware)
    matches = [
        index
        for index, item in enumerate(checked)
        if type(item) is PaloNexusLangChainMiddleware
    ]
    if matches != [len(checked) - 1]:
        raise InvalidRequest() from None
    return checked


def authorized_middleware_stack(
    middleware: Sequence[AgentMiddleware[Any, Any]],
    authorization: PaloNexusLangChainMiddleware,
) -> tuple[AgentMiddleware[Any, Any], ...]:
    """Place PaloNexus last, which LangChain executes as the inner layer."""

    if type(authorization) is not PaloNexusLangChainMiddleware:
        raise InvalidRequest() from None
    if any(type(item) is PaloNexusLangChainMiddleware for item in middleware):
        raise InvalidRequest() from None
    return validate_authorized_middleware_stack((*middleware, authorization))


def create_authorized_agent(
    *,
    model: BaseChatModel,
    model_policy_key: str,
    tools: Sequence[BaseTool],
    authorization: PaloNexusLangChainMiddleware,
    middleware: Sequence[AgentMiddleware[Any, Any]] = (),
    **kwargs: Any,
) -> Any:
    """Create an agent whose final effective model/tool target is authorized."""

    if any(not isinstance(bound_tool, BaseTool) for bound_tool in tools):
        raise InvalidRequest() from None
    normalized_tools = tuple(tools)
    bound = authorization._with_agent_bindings(
        model_policy_key,
        model,
        normalized_tools,
    )
    return create_agent(
        model=model,
        tools=normalized_tools,
        middleware=authorized_middleware_stack(middleware, bound),
        **kwargs,
    )


__all__ = [
    "AsyncAuthorizationClientProtocol",
    "LangChainActionPolicy",
    "LangChainApprovalRequired",
    "LangChainAuthorizationUnavailable",
    "LangChainAuthorizationContext",
    "LangChainInvalidRequest",
    "LangChainPolicyDenied",
    "MissingIntegrationDependency",
    "PaloNexusLangChainMiddleware",
    "SyncAuthorizationClientProtocol",
    "authorized_middleware_stack",
    "create_authorized_agent",
    "validate_authorized_middleware_stack",
]
