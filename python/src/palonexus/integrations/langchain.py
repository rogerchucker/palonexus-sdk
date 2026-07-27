# SPDX-License-Identifier: MIT
"""Fail-closed LangChain 1.x model and tool authorization middleware.

The adapter gates each handler invocation through the public PaloNexus client
and request-builder contracts. It does not implement durable approval resume;
compose it with LangChain HITL only to collect a human decision, and use the
PaloNexus LangGraph integration for checkpointed resume semantics.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import math
import time
from collections.abc import Awaitable, Callable, Mapping
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
from ..models import ActionTarget, TaskContext
from ..protocol import ActionRequestBuilder
from ..redaction import Redactor
from . import MissingIntegrationDependency

try:
    import langchain
    from langchain.agents.middleware import (
        AgentMiddleware,
        ModelRequest,
        ModelResponse,
    )
    from langchain.tools.tool_node import ToolCallRequest
    from langchain_core.messages import AIMessage, ToolMessage
    from langgraph.types import Command
except ImportError:
    raise MissingIntegrationDependency() from None

type SideEffect = Literal["read_only", "write", "destructive", "external"]
_ResultT = TypeVar("_ResultT")
_MAX_DEADLINE_HORIZON_SECONDS = 3600.0
_SIDE_EFFECTS = frozenset({"read_only", "write", "destructive", "external"})


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
            f"deadline={self.deadline!r})"
        )


@dataclass(frozen=True, slots=True)
class _CallFrame:
    task: TaskContext
    correlation_id: str
    action_id: str
    tenant_ref: str | None
    actor_ref: str | None


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
                tenant_ref=frame.tenant_ref,
                actor_ref=frame.actor_ref,
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


def _model_name(request: ModelRequest[Any]) -> str:
    try:
        name = request.model._llm_type  # noqa: SLF001 - public LangChain model hook
        if type(name) is not str or not name or len(name) > 128:
            raise TypeError
        return name
    except Exception:
        raise InvalidRequest() from None


class PaloNexusLangChainMiddleware(AgentMiddleware[Any, Any]):
    """Authorize LangChain tool/model handlers before any execution starts."""

    __slots__ = (
        "_async_client",
        "_builder",
        "_client",
        "_model_policies",
        "_redactor",
        "_tool_policies",
    )

    def __init__(
        self,
        *,
        client: SyncAuthorizationClientProtocol | None,
        async_client: AsyncAuthorizationClientProtocol | None,
        tool_policies: Mapping[str, LangChainActionPolicy],
        model_policies: Mapping[str, LangChainActionPolicy],
    ) -> None:
        if client is not None and not isinstance(
            client, SyncAuthorizationClientProtocol
        ):
            raise InvalidRequest() from None
        if async_client is not None and not isinstance(
            async_client, AsyncAuthorizationClientProtocol
        ):
            raise InvalidRequest() from None
        if client is None and async_client is None:
            raise InvalidRequest() from None
        self._client = client
        self._async_client = async_client
        self._tool_policies = _immutable_policies(tool_policies)
        self._model_policies = _immutable_policies(model_policies)
        self._redactor = Redactor()
        self._builder = ActionRequestBuilder(
            adapter_id="palonexus-langchain",
            adapter_version="0.2.0",
            host_version=str(langchain.__version__),
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
        try:
            safe_arguments = self._redactor.redact(arguments)
            normalized = json.dumps(
                safe_arguments,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
                allow_nan=False,
            ).encode("utf-8")
        except Exception:
            raise InvalidRequest() from None
        arguments_hash = hashlib.sha256(normalized).hexdigest()
        target = self._builder.prepare_generic_target(
            ActionTarget(
                kind="tool",
                service=policy.service,
                resource=(
                    f"tool:{policy.service}/{name}#arguments-sha256:{arguments_hash}"
                ),
            )
        )
        parent = _CURRENT_CALL.get()
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
        )
        return attempt, context, frame

    @staticmethod
    def _approval(error: ApprovalRequired) -> LangChainApprovalRequired:
        return LangChainApprovalRequired(
            request_id=error.request_id,
            decision_id=error.decision_id,
            correlation_id=error.correlation_id,
        )

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

    def _authorize(
        self,
        attempt: Any,
        context: LangChainAuthorizationContext,
    ) -> None:
        if self._client is None:
            raise InvalidRequest() from None
        try:
            self._client.authorize(
                attempt,
                deadline=_checked_deadline(context.deadline),
                cancelled=context.cancelled,
            )
        except ApprovalRequired as error:
            raise self._approval(error) from None
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
            await self._async_client.authorize(
                attempt,
                deadline=_checked_deadline(context.deadline),
                cancelled=context.cancelled,
            )
        except ApprovalRequired as error:
            raise self._approval(error) from None
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
            name = _model_name(request)
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
            name = _model_name(request)
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
]
