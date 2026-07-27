# SPDX-License-Identifier: MIT
"""Fail-closed governed nodes for the public LangGraph 1.x Graph API.

The integration deliberately separates authorization, approval waiting, and
execution. LangGraph restarts an interrupted node from its first line, so the
wait nodes call :func:`interrupt` before performing any other operation.

Execution de-duplication is guaranteed for one adapter process and for normal
checkpoint continuation. A process crash concurrent with an external side
effect is inherently ambiguous: durable exactly-once behavior requires the
wrapped node to use the checkpointed ``eventId`` as an idempotency key or to
commit it transactionally with its side effect.
"""

from __future__ import annotations

import inspect
import json
import threading
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from typing import Any, Literal, Protocol, cast, runtime_checkable

from ..approvals import ApprovalRecord
from ..async_client import AsyncAuthorizationClient
from ..client import AuthorizationClient, AuthorizationDecision
from ..errors import (
    ApprovalExpired,
    ApprovalRequired,
    ApprovalScopeMismatch,
    AuthorizationUnavailable,
    CredentialRevoked,
    InvalidDecision,
    InvalidRequest,
    PolicyDenied,
)
from ..models import DecisionOutcome, TaskContext
from ..protocol import ActionRequestBuilder
from . import MissingIntegrationDependency

try:
    from langchain_core.runnables import RunnableConfig
except ImportError:
    RunnableConfig = dict[str, Any]  # type: ignore[misc,assignment]

LANGGRAPH_SCOPE_KEY = "palonexus_scope"
_MARKER_KEY = "marker"
_INTERRUPT_PAYLOAD = {
    "kind": "palonexus_approval",
    "message": "Trusted approval status must be refreshed before execution.",
}
_DESCRIPTOR_KEYS = frozenset(
    {
        "schemaVersion",
        "status",
        "eventId",
        "taskId",
        "sessionId",
        "tenantRef",
        "actorRef",
        "correlationId",
        "action",
        "actionId",
        "requestId",
        "decisionId",
        "approvalId",
        "clientScopeHash",
        "authoritativeScopeHash",
        "resource",
        "sideEffect",
        "expiresAt",
        "originalRequest",
        "priorDecision",
        "pendingApproval",
    }
)


def _langgraph_interrupt(value: object) -> object:
    try:
        from langgraph.types import interrupt
    except ImportError:
        raise MissingIntegrationDependency() from None
    return interrupt(value)


def _checkpointer(value: object | None) -> object | None:
    if value is None:
        return None
    try:
        from langgraph.checkpoint.base import BaseCheckpointSaver
    except ImportError:
        raise MissingIntegrationDependency() from None
    if not isinstance(value, BaseCheckpointSaver):
        raise InvalidRequest() from None
    return value


def _canonical(value: Mapping[str, object]) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    except (TypeError, ValueError, OverflowError):
        raise ApprovalScopeMismatch() from None


def _parse_descriptor(value: object) -> dict[str, Any]:
    failed = False
    result: dict[str, Any] = {}
    try:
        if type(value) is not str:
            raise TypeError
        loaded = json.loads(value)
        if (
            not isinstance(loaded, dict)
            or frozenset(loaded) != _DESCRIPTOR_KEYS
            or _canonical(loaded) != value
        ):
            raise ValueError
        result = cast(dict[str, Any], loaded)
        strings = _DESCRIPTOR_KEYS - {
            "approvalId",
            "originalRequest",
            "priorDecision",
            "pendingApproval",
            "resource",
        }
        if any(type(result[name]) is not str or not result[name] for name in strings):
            raise TypeError
        if result["schemaVersion"] != "1" or result["status"] not in {
            "approval_pending",
            "executable",
            "executed",
            "consumed",
        }:
            raise ValueError
        if result["approvalId"] is not None and (
            type(result["approvalId"]) is not str or not result["approvalId"]
        ):
            raise TypeError
        if not isinstance(result["resource"], dict) or frozenset(
            result["resource"]
        ) != {"kind", "service", "resource", "resourceHash"}:
            raise ValueError
        if any(
            type(result["resource"][name]) is not str or not result["resource"][name]
            for name in result["resource"]
        ):
            raise TypeError
        for name in ("originalRequest", "priorDecision"):
            if not isinstance(result[name], dict):
                raise TypeError
        if result["pendingApproval"] is not None and not isinstance(
            result["pendingApproval"], dict
        ):
            raise TypeError
        request = result["originalRequest"]
        decision = result["priorDecision"]
        target = request.get("target")
        if (
            request.get("actionId") != result["actionId"]
            or request.get("requestId") != result["requestId"]
            or request.get("correlationId") != result["correlationId"]
            or request.get("action") != result["action"]
            or request.get("sideEffect") != result["sideEffect"]
            or request.get("task")
            != {
                "taskId": result["taskId"],
                "sessionId": result["sessionId"],
            }
            or target != result["resource"]
            or decision.get("requestId") != result["requestId"]
            or decision.get("decisionId") != result["decisionId"]
            or decision.get("correlationId") != result["correlationId"]
            or decision.get("clientScopeHash") != result["clientScopeHash"]
            or decision.get("authoritativeScopeHash")
            != result["authoritativeScopeHash"]
        ):
            raise ValueError
        pending = result["pendingApproval"]
        if result["status"] == "approval_pending":
            if (
                result["approvalId"] is None
                or not isinstance(pending, dict)
                or pending.get("approvalId") != result["approvalId"]
                or pending.get("actionId") != result["actionId"]
                or pending.get("correlationId") != result["correlationId"]
                or pending.get("authorizationDecisionId") != result["decisionId"]
                or pending.get("authoritativeScopeHash")
                != result["authoritativeScopeHash"]
            ):
                raise ValueError
        return result
    except Exception:
        failed = True
    if failed:
        raise ApprovalScopeMismatch() from None
    return result


def _thread_namespace(config: object) -> str | None:
    try:
        if not isinstance(config, Mapping):
            return None
        configurable = config.get("configurable")
        if not isinstance(configurable, Mapping):
            return None
        thread_id = configurable.get("thread_id")
        if type(thread_id) is not str or not thread_id:
            return None
        return thread_id
    except Exception:
        return None


def _decision_document(decision: AuthorizationDecision) -> dict[str, object]:
    document: dict[str, object] = {
        "schemaVersion": "1",
        "requestId": decision.request_id,
        "decisionId": decision.decision_id,
        "correlationId": decision.correlation_id,
        "outcome": decision.outcome.value,
        "reasonCode": decision.reason_code,
        "displayReason": "PaloNexus governed graph decision.",
        "clientScopeHash": decision.client_scope_hash,
        "authoritativeScopeHash": decision.authoritative_scope_hash,
        "policyRevision": decision.policy_revision,
        "serverTime": decision.server_time,
        "expiresAt": decision.expires_at,
        "auditRef": decision.audit_ref,
        "cache": {"cacheable": False},
    }
    if decision.approval_id is not None:
        document["approval"] = {
            "approvalId": decision.approval_id,
            "status": decision.approval_status,
            "expiresAt": decision.approval_expires_at,
        }
    return document


def _approval_document(approval: ApprovalRecord) -> dict[str, object]:
    return {
        "schemaVersion": "1",
        "approvalId": approval.approval_id,
        "actionId": approval.action_id,
        "correlationId": approval.correlation_id,
        "status": approval.status.value,
        "authoritativeScopeHash": approval.authoritative_scope_hash,
        "requestedAt": approval.requested_at,
        "expiresAt": approval.expires_at,
        "requesterRef": approval.requester_ref,
        "authorizationDecisionId": approval.authorization_decision_id,
        "creationAuditRef": approval.creation_audit_ref,
    }


@runtime_checkable
class _TargetProjector(Protocol):
    def __call__(
        self, builder: ActionRequestBuilder, state: Mapping[str, object]
    ) -> object: ...


@dataclass(slots=True)
class _Execution:
    status: Literal["executable", "running", "executed", "consumed"]
    envelope: _Closable


class _Closable(Protocol):
    def close(self) -> None: ...


class _LangGraphCompatible:
    def add_note(self, note: str) -> None:
        del note


class LangGraphPolicyDenied(_LangGraphCompatible, PolicyDenied):
    """LangGraph-compatible policy denial."""


class LangGraphAuthorizationUnavailable(_LangGraphCompatible, AuthorizationUnavailable):
    """LangGraph-compatible authorization outage."""


class LangGraphInvalidDecision(_LangGraphCompatible, InvalidDecision):
    """LangGraph-compatible invalid decision."""


class LangGraphApprovalScopeMismatch(_LangGraphCompatible, ApprovalScopeMismatch):
    """LangGraph-compatible approval binding mismatch."""


class LangGraphApprovalExpired(_LangGraphCompatible, ApprovalExpired):
    """LangGraph-compatible expired approval."""


class LangGraphApprovalRequired(_LangGraphCompatible, ApprovalRequired):
    """LangGraph-compatible still-pending approval."""


class LangGraphCredentialRevoked(_LangGraphCompatible, CredentialRevoked):
    """LangGraph-compatible revoked credential or delegation."""


def _graph_error(error: BaseException) -> BaseException:
    fields = {
        "request_id": getattr(error, "request_id", None),
        "decision_id": getattr(error, "decision_id", None),
        "correlation_id": getattr(error, "correlation_id", None),
    }
    if isinstance(error, ApprovalScopeMismatch):
        return LangGraphApprovalScopeMismatch(**fields)
    if isinstance(error, ApprovalExpired):
        return LangGraphApprovalExpired(**fields)
    if isinstance(error, ApprovalRequired):
        return LangGraphApprovalRequired(**fields)
    if isinstance(error, CredentialRevoked):
        return LangGraphCredentialRevoked(**fields)
    if isinstance(error, InvalidDecision):
        return LangGraphInvalidDecision(**fields)
    if isinstance(error, AuthorizationUnavailable):
        return LangGraphAuthorizationUnavailable(**fields)
    if isinstance(error, PolicyDenied):
        return LangGraphPolicyDenied(**fields)
    return error


class PaloNexusLangGraphNode:
    """A sync/async governed node set wired with public LangGraph APIs."""

    def __init__(
        self,
        *,
        builder: ActionRequestBuilder,
        target_projector: _TargetProjector,
        task_context: TaskContext,
        correlation_id: str,
        tenant_ref: str,
        actor_ref: str,
        action: str,
        side_effect: str,
        client: AuthorizationClient | None = None,
        async_client: AsyncAuthorizationClient | None = None,
        handler: Callable[[Mapping[str, object]], Mapping[str, object]] | None = None,
        async_handler: Callable[[Mapping[str, object]], Awaitable[Mapping[str, object]]]
        | None = None,
        checkpointer: object | None = None,
        state_key: str = LANGGRAPH_SCOPE_KEY,
    ) -> None:
        if (
            type(builder) is not ActionRequestBuilder
            or not callable(target_projector)
            or type(task_context) is not TaskContext
            or any(
                type(value) is not str or not value
                for value in (
                    correlation_id,
                    tenant_ref,
                    actor_ref,
                    action,
                    side_effect,
                    state_key,
                )
            )
            or (client is None) != (handler is None)
            or (async_client is None) != (async_handler is None)
            or (client is None and async_client is None)
        ):
            raise InvalidRequest() from None
        self._builder = builder
        self._target_projector = target_projector
        self._task = task_context
        self._correlation_id = correlation_id
        self._tenant_ref = tenant_ref
        self._actor_ref = actor_ref
        self._action = action
        self._side_effect = side_effect
        self._client = client
        self._async_client = async_client
        self._handler = handler
        self._async_handler = async_handler
        self._state_key = state_key
        self._checkpointer = _checkpointer(checkpointer)
        self._lock = threading.RLock()
        self._executions: dict[tuple[str, str], _Execution] = {}

    def _prepare(
        self, state: Mapping[str, object], *, action_id: str | None = None
    ) -> Any:
        try:
            target = self._target_projector(self._builder, state)
            intent = self._builder.new(
                action=cast(Any, self._action),
                target=target,  # type: ignore[arg-type]
                side_effect=cast(Any, self._side_effect),
                task_context=self._task,
                action_id=action_id,
                correlation_id=self._correlation_id,
            )
            return self._builder.build(intent, prepared_target=target)  # type: ignore[arg-type]
        except ApprovalScopeMismatch:
            raise
        except Exception:
            raise InvalidRequest() from None

    def _descriptor(
        self,
        attempt: Any,
        decision: AuthorizationDecision,
        approval: ApprovalRecord | None,
        *,
        status: str,
    ) -> str:
        request = attempt.request.to_dict()
        target = request["target"]
        event_id = str(request["actionId"])
        value: dict[str, object] = {
            "schemaVersion": "1",
            "status": status,
            "eventId": event_id,
            "taskId": self._task.task_id,
            "sessionId": self._task.session_id,
            "tenantRef": self._tenant_ref,
            "actorRef": self._actor_ref,
            "correlationId": self._correlation_id,
            "action": self._action,
            "actionId": event_id,
            "requestId": decision.request_id,
            "decisionId": decision.decision_id,
            "approvalId": decision.approval_id,
            "clientScopeHash": decision.client_scope_hash,
            "authoritativeScopeHash": decision.authoritative_scope_hash,
            "resource": target,
            "sideEffect": self._side_effect,
            "expiresAt": (
                decision.approval_expires_at
                if decision.approval_expires_at is not None
                else decision.expires_at
            ),
            "originalRequest": request,
            "priorDecision": _decision_document(decision),
            "pendingApproval": (
                None if approval is None else _approval_document(approval)
            ),
        }
        result = _canonical(value)
        _parse_descriptor(result)
        return result

    def _checked_state(
        self, state: object
    ) -> tuple[Mapping[str, object], dict[str, Any]]:
        if not isinstance(state, Mapping):
            raise ApprovalScopeMismatch() from None
        descriptor = _parse_descriptor(state.get(self._state_key))
        if (
            descriptor["taskId"] != self._task.task_id
            or descriptor["sessionId"] != self._task.session_id
            or descriptor["tenantRef"] != self._tenant_ref
            or descriptor["actorRef"] != self._actor_ref
            or descriptor["correlationId"] != self._correlation_id
            or descriptor["action"] != self._action
            or descriptor["sideEffect"] != self._side_effect
        ):
            raise LangGraphApprovalScopeMismatch() from None
        return state, descriptor

    def authorize(
        self, state: Mapping[str, object], config: RunnableConfig
    ) -> dict[str, object]:
        if self._client is None:
            raise InvalidRequest() from None
        if self._state_key in state:
            descriptor = _parse_descriptor(state[self._state_key])
            return {
                self._state_key: state[self._state_key],
                _MARKER_KEY: (
                    "INTERRUPTED"
                    if descriptor["status"] == "approval_pending"
                    else "AUTHORIZED"
                ),
            }
        attempt = self._prepare(state)
        try:
            decision = self._client.decide(attempt)
        except BaseException as error:
            raise _graph_error(error) from None
        if decision.outcome is DecisionOutcome.DENY:
            attempt.close()
            raise LangGraphPolicyDenied(
                request_id=decision.request_id,
                decision_id=decision.decision_id,
                correlation_id=decision.correlation_id,
            ) from None
        if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED:
            if _thread_namespace(config) is None or self._checkpointer is None:
                attempt.close()
                raise LangGraphAuthorizationUnavailable(
                    request_id=decision.request_id,
                    decision_id=decision.decision_id,
                    correlation_id=decision.correlation_id,
                ) from None
            try:
                approval = self._client.request_approval(attempt, decision)
            except BaseException as error:
                attempt.close()
                raise _graph_error(error) from None
            return {
                self._state_key: self._descriptor(
                    attempt, decision, approval, status="approval_pending"
                ),
                _MARKER_KEY: "INTERRUPTED",
            }
        rendered_descriptor = self._descriptor(
            attempt, decision, None, status="executable"
        )
        namespace = _thread_namespace(config) or "__ephemeral__"
        with self._lock:
            self._executions[(namespace, str(attempt.request.action_id))] = _Execution(
                "executable", attempt
            )
        return {self._state_key: rendered_descriptor, _MARKER_KEY: "AUTHORIZED"}

    async def aauthorize(
        self, state: Mapping[str, object], config: RunnableConfig
    ) -> dict[str, object]:
        if self._async_client is None:
            raise InvalidRequest() from None
        if self._state_key in state:
            descriptor = _parse_descriptor(state[self._state_key])
            return {
                self._state_key: state[self._state_key],
                _MARKER_KEY: (
                    "INTERRUPTED"
                    if descriptor["status"] == "approval_pending"
                    else "AUTHORIZED"
                ),
            }
        attempt = self._prepare(state)
        try:
            decision = await self._async_client.decide(attempt)
        except BaseException as error:
            raise _graph_error(error) from None
        if decision.outcome is DecisionOutcome.DENY:
            attempt.close()
            raise LangGraphPolicyDenied(
                request_id=decision.request_id,
                decision_id=decision.decision_id,
                correlation_id=decision.correlation_id,
            ) from None
        if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED:
            if _thread_namespace(config) is None or self._checkpointer is None:
                attempt.close()
                raise LangGraphAuthorizationUnavailable(
                    request_id=decision.request_id,
                    decision_id=decision.decision_id,
                    correlation_id=decision.correlation_id,
                ) from None
            try:
                approval = await self._async_client.request_approval(attempt, decision)
            except BaseException as error:
                attempt.close()
                raise _graph_error(error) from None
            return {
                self._state_key: self._descriptor(
                    attempt, decision, approval, status="approval_pending"
                ),
                _MARKER_KEY: "INTERRUPTED",
            }
        rendered_descriptor = self._descriptor(
            attempt, decision, None, status="executable"
        )
        namespace = _thread_namespace(config) or "__ephemeral__"
        with self._lock:
            self._executions[(namespace, str(attempt.request.action_id))] = _Execution(
                "executable", attempt
            )
        return {self._state_key: rendered_descriptor, _MARKER_KEY: "AUTHORIZED"}

    def route_after_authorization(self, state: Mapping[str, object]) -> str:
        descriptor = _parse_descriptor(state.get(self._state_key))
        return "wait" if descriptor["status"] == "approval_pending" else "execute"

    def wait_for_approval(
        self, state: Mapping[str, object], config: RunnableConfig
    ) -> dict[str, object]:
        _wake = _langgraph_interrupt(_INTERRUPT_PAYLOAD)
        del _wake
        return self._resume_after_wake(state, config)

    async def await_for_approval(
        self, state: Mapping[str, object], config: RunnableConfig
    ) -> dict[str, object]:
        _wake = _langgraph_interrupt(_INTERRUPT_PAYLOAD)
        del _wake
        return await self._aresume_after_wake(state, config)

    def _resume_after_wake(
        self, state: Mapping[str, object], config: object
    ) -> dict[str, object]:
        if self._client is None:
            raise InvalidRequest() from None
        state, descriptor = self._checked_state(state)
        namespace = _thread_namespace(config)
        if namespace is None:
            raise AuthorizationUnavailable() from None
        current = self._prepare(state, action_id=descriptor["actionId"])
        try:
            resumed = self._client.resume_checkpoint(
                self._builder,
                current,
                original_request=descriptor["originalRequest"],
                client_scope_hash=descriptor["clientScopeHash"],
                prior_decision=descriptor["priorDecision"],
                pending_approval=descriptor["pendingApproval"],
            )
        except Exception as error:
            current.close()
            raise _graph_error(error) from None
        descriptor["status"] = "executable"
        rendered = _canonical(descriptor)
        with self._lock:
            self._executions[(namespace, descriptor["eventId"])] = _Execution(
                "executable", resumed
            )
        return {self._state_key: rendered, _MARKER_KEY: "AUTHORIZED"}

    async def _aresume_after_wake(
        self, state: Mapping[str, object], config: object
    ) -> dict[str, object]:
        if self._async_client is None:
            raise InvalidRequest() from None
        state, descriptor = self._checked_state(state)
        namespace = _thread_namespace(config)
        if namespace is None:
            raise AuthorizationUnavailable() from None
        current = self._prepare(state, action_id=descriptor["actionId"])
        try:
            resumed = await self._async_client.resume_checkpoint(
                self._builder,
                current,
                original_request=descriptor["originalRequest"],
                client_scope_hash=descriptor["clientScopeHash"],
                prior_decision=descriptor["priorDecision"],
                pending_approval=descriptor["pendingApproval"],
            )
        except Exception as error:
            current.close()
            raise _graph_error(error) from None
        descriptor["status"] = "executable"
        rendered = _canonical(descriptor)
        with self._lock:
            self._executions[(namespace, descriptor["eventId"])] = _Execution(
                "executable", resumed
            )
        return {self._state_key: rendered, _MARKER_KEY: "AUTHORIZED"}

    def _claim(
        self, state: Mapping[str, object], config: object
    ) -> tuple[dict[str, Any], tuple[str, str], _Execution | None]:
        _, descriptor = self._checked_state(state)
        namespace = _thread_namespace(config) or "__ephemeral__"
        key = (namespace, descriptor["eventId"])
        if self._durably_consumed(namespace, descriptor["eventId"]):
            return descriptor, key, None
        with self._lock:
            execution = self._executions.get(key)
            if descriptor["status"] in {"executed", "consumed"}:
                return descriptor, key, None
            if execution is not None and execution.status in {"executed", "consumed"}:
                return descriptor, key, None
            if execution is None or execution.status != "executable":
                raise AuthorizationUnavailable() from None
            execution.status = "running"
        return descriptor, key, execution

    def _durably_consumed(self, thread_id: str, event_id: str) -> bool:
        checkpointer = self._checkpointer
        if checkpointer is None or thread_id == "__ephemeral__":
            return False
        try:
            root_config = {
                "configurable": {"thread_id": thread_id, "checkpoint_ns": ""}
            }
            for index, checkpoint_tuple in enumerate(
                cast(Any, checkpointer).list(root_config)
            ):
                if index >= 10_000:
                    raise AuthorizationUnavailable() from None
                values = checkpoint_tuple.checkpoint.get("channel_values", {})
                if not isinstance(values, Mapping):
                    raise ApprovalScopeMismatch() from None
                value = values.get(self._state_key)
                if value is None:
                    continue
                descriptor = _parse_descriptor(value)
                if descriptor["eventId"] == event_id and descriptor["status"] in {
                    "executed",
                    "consumed",
                }:
                    return True
            return False
        except (ApprovalScopeMismatch, AuthorizationUnavailable):
            raise
        except Exception:
            raise AuthorizationUnavailable() from None

    def _restore_executable(
        self,
        state: Mapping[str, object],
        config: RunnableConfig,
    ) -> None:
        if self._client is None:
            return
        _, descriptor = self._checked_state(state)
        namespace = _thread_namespace(config) or "__ephemeral__"
        key = (namespace, descriptor["eventId"])
        if self._durably_consumed(namespace, descriptor["eventId"]):
            return
        with self._lock:
            if key in self._executions or descriptor["status"] != "executable":
                return
        current = self._prepare(state, action_id=descriptor["actionId"])
        try:
            decision = self._client.authorize(current)
            if (
                decision.authoritative_scope_hash
                != descriptor["authoritativeScopeHash"]
                or decision.client_scope_hash != descriptor["clientScopeHash"]
            ):
                raise ApprovalScopeMismatch() from None
        except BaseException as error:
            current.close()
            raise _graph_error(error) from None
        with self._lock:
            prior = self._executions.setdefault(key, _Execution("executable", current))
        if prior.envelope is not current:
            current.close()

    async def _arestore_executable(
        self,
        state: Mapping[str, object],
        config: RunnableConfig,
    ) -> None:
        if self._async_client is None:
            return
        _, descriptor = self._checked_state(state)
        namespace = _thread_namespace(config) or "__ephemeral__"
        key = (namespace, descriptor["eventId"])
        if self._durably_consumed(namespace, descriptor["eventId"]):
            return
        with self._lock:
            if key in self._executions or descriptor["status"] != "executable":
                return
        current = self._prepare(state, action_id=descriptor["actionId"])
        try:
            decision = await self._async_client.authorize(current)
            if (
                decision.authoritative_scope_hash
                != descriptor["authoritativeScopeHash"]
                or decision.client_scope_hash != descriptor["clientScopeHash"]
            ):
                raise ApprovalScopeMismatch() from None
        except BaseException as error:
            current.close()
            raise _graph_error(error) from None
        with self._lock:
            prior = self._executions.setdefault(key, _Execution("executable", current))
        if prior.envelope is not current:
            current.close()

    def execute(
        self, state: Mapping[str, object], config: RunnableConfig
    ) -> dict[str, object]:
        if self._handler is None:
            raise InvalidRequest() from None
        self._restore_executable(state, config)
        descriptor, key, execution = self._claim(state, config)
        if execution is None:
            return {
                self._state_key: _canonical(descriptor),
                _MARKER_KEY: "REPLAY_BLOCKED",
            }
        try:
            result = self._handler(state)
            if inspect.isawaitable(result) or not isinstance(result, Mapping):
                raise InvalidRequest() from None
            if self._state_key in result or _MARKER_KEY in result:
                raise InvalidRequest() from None
        except BaseException:
            with self._lock:
                execution.status = "consumed"
            try:
                execution.envelope.close()
            except BaseException:
                pass
            raise
        with self._lock:
            execution.status = "executed"
        try:
            execution.envelope.close()
        except BaseException:
            pass
        descriptor["status"] = "executed"
        return {
            **dict(result),
            self._state_key: _canonical(descriptor),
            _MARKER_KEY: "APPROVED_EXECUTED",
        }

    async def aexecute(
        self, state: Mapping[str, object], config: RunnableConfig
    ) -> dict[str, object]:
        if self._async_handler is None:
            raise InvalidRequest() from None
        await self._arestore_executable(state, config)
        descriptor, key, execution = self._claim(state, config)
        if execution is None:
            return {
                self._state_key: _canonical(descriptor),
                _MARKER_KEY: "REPLAY_BLOCKED",
            }
        try:
            result = await self._async_handler(state)
            if not isinstance(result, Mapping):
                raise InvalidRequest() from None
            if self._state_key in result or _MARKER_KEY in result:
                raise InvalidRequest() from None
        except BaseException:
            with self._lock:
                execution.status = "consumed"
            try:
                execution.envelope.close()
            except BaseException:
                pass
            raise
        with self._lock:
            execution.status = "executed"
        try:
            execution.envelope.close()
        except BaseException:
            pass
        descriptor["status"] = "executed"
        return {
            **dict(result),
            self._state_key: _canonical(descriptor),
            _MARKER_KEY: "APPROVED_EXECUTED",
        }


__all__ = [
    "LANGGRAPH_SCOPE_KEY",
    "LangGraphApprovalExpired",
    "LangGraphApprovalRequired",
    "LangGraphApprovalScopeMismatch",
    "LangGraphAuthorizationUnavailable",
    "LangGraphInvalidDecision",
    "LangGraphPolicyDenied",
    "LangGraphCredentialRevoked",
    "PaloNexusLangGraphNode",
]
