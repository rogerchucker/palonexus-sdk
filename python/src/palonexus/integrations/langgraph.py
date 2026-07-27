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

import asyncio
import hashlib
import inspect
import json
import os
import sqlite3
import threading
from collections.abc import Awaitable, Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, Protocol, cast, runtime_checkable

from ..approvals import ApprovalRecord
from ..client import AuthorizationDecision
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


class MissingLangGraphDependency(MissingIntegrationDependency):
    """The LangGraph optional dependency set is not installed."""

    canonical_message = (
        "The LangGraph integration requires the 'palonexus[langgraph]' extra."
    )


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
        raise MissingLangGraphDependency() from None
    return interrupt(value)


def _checkpointer(value: object | None) -> object | None:
    if value is None:
        return None
    try:
        from langgraph.checkpoint.base import BaseCheckpointSaver
    except ImportError:
        raise MissingLangGraphDependency() from None
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


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_fresh(expires_at: object, trusted_clock: Callable[[], str]) -> None:
    try:
        if type(expires_at) is not str:
            raise TypeError
        now = trusted_clock()
        if type(now) is not str:
            raise TypeError
        parsed_expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        parsed_now = datetime.fromisoformat(now.replace("Z", "+00:00"))
        if (
            parsed_expiry.tzinfo is None
            or parsed_now.tzinfo is None
            or parsed_now >= parsed_expiry
        ):
            raise ApprovalExpired() from None
    except ApprovalExpired:
        raise
    except Exception:
        raise InvalidDecision() from None


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


type LedgerStatus = Literal["unclaimed", "claimed", "completed", "failed"]


@runtime_checkable
class ExecutionLedger(Protocol):
    """Atomic durable execution-claim boundary for synchronous nodes."""

    def claim(self, event_key: str, descriptor_hash: str) -> bool: ...

    def complete(self, event_key: str, descriptor_hash: str) -> None: ...

    def fail(self, event_key: str, descriptor_hash: str) -> None: ...

    def query(self, event_key: str) -> LedgerStatus: ...


@runtime_checkable
class AsyncExecutionLedger(Protocol):
    """Atomic durable execution-claim boundary for asynchronous nodes."""

    async def claim(self, event_key: str, descriptor_hash: str) -> bool: ...

    async def complete(self, event_key: str, descriptor_hash: str) -> None: ...

    async def fail(self, event_key: str, descriptor_hash: str) -> None: ...

    async def query(self, event_key: str) -> LedgerStatus: ...


def _checked_ledger_key(value: object) -> str:
    if type(value) is not str or not value or len(value.encode("utf-8")) > 1024:
        raise InvalidRequest() from None
    return value


def _checked_descriptor_hash(value: object) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise InvalidRequest() from None
    return value


class InMemoryExecutionLedger:
    """Testing-only process-local ledger."""

    def __init__(self, *, testing_only: Literal[True]) -> None:
        if testing_only is not True:
            raise ValueError("testing_only=True is required")
        self._lock = threading.Lock()
        self._entries: dict[str, tuple[str, LedgerStatus]] = {}

    def claim(self, event_key: str, descriptor_hash: str) -> bool:
        key = _checked_ledger_key(event_key)
        binding = _checked_descriptor_hash(descriptor_hash)
        with self._lock:
            existing = self._entries.get(key)
            if existing is None:
                self._entries[key] = (binding, "claimed")
                return True
            if existing[0] != binding:
                raise ApprovalScopeMismatch() from None
            return False

    def _transition(
        self,
        event_key: str,
        descriptor_hash: str,
        status: Literal["completed", "failed"],
    ) -> None:
        key = _checked_ledger_key(event_key)
        binding = _checked_descriptor_hash(descriptor_hash)
        with self._lock:
            existing = self._entries.get(key)
            if existing is None or existing[0] != binding:
                raise ApprovalScopeMismatch() from None
            if existing[1] == status:
                return
            if existing[1] != "claimed":
                raise ApprovalScopeMismatch() from None
            self._entries[key] = (binding, status)

    def complete(self, event_key: str, descriptor_hash: str) -> None:
        self._transition(event_key, descriptor_hash, "completed")

    def fail(self, event_key: str, descriptor_hash: str) -> None:
        self._transition(event_key, descriptor_hash, "failed")

    def query(self, event_key: str) -> LedgerStatus:
        key = _checked_ledger_key(event_key)
        with self._lock:
            entry = self._entries.get(key)
            return "unclaimed" if entry is None else entry[1]


class AsyncInMemoryExecutionLedger:
    """Testing-only asynchronous ledger."""

    def __init__(self, *, testing_only: Literal[True]) -> None:
        if testing_only is not True:
            raise ValueError("testing_only=True is required")
        self._ledger = InMemoryExecutionLedger(testing_only=True)

    async def claim(self, event_key: str, descriptor_hash: str) -> bool:
        return self._ledger.claim(event_key, descriptor_hash)

    async def complete(self, event_key: str, descriptor_hash: str) -> None:
        self._ledger.complete(event_key, descriptor_hash)

    async def fail(self, event_key: str, descriptor_hash: str) -> None:
        self._ledger.fail(event_key, descriptor_hash)

    async def query(self, event_key: str) -> LedgerStatus:
        return self._ledger.query(event_key)


class SQLiteExecutionLedger:
    """File-backed atomic execution ledger using SQLite transactions."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        try:
            checked = Path(path).expanduser().resolve(strict=False)
            checked.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            connection = sqlite3.connect(
                checked,
                timeout=5.0,
                isolation_level=None,
                check_same_thread=False,
            )
            os.chmod(checked, 0o600)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA busy_timeout=5000")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS palonexus_execution_ledger (
                    event_key TEXT PRIMARY KEY,
                    descriptor_hash TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (
                        status IN ('claimed', 'completed', 'failed')
                    )
                )
                """
            )
        except (OSError, sqlite3.Error, TypeError, ValueError):
            raise AuthorizationUnavailable() from None
        self._connection = connection
        self._lock = threading.Lock()
        self._closed = False

    def _transaction(self, operation: Callable[[sqlite3.Connection], Any]) -> Any:
        with self._lock:
            if self._closed:
                raise AuthorizationUnavailable() from None
            try:
                self._connection.execute("BEGIN IMMEDIATE")
                value = operation(self._connection)
                self._connection.execute("COMMIT")
                return value
            except BaseException:
                try:
                    self._connection.execute("ROLLBACK")
                except sqlite3.Error:
                    pass
                raise

    def claim(self, event_key: str, descriptor_hash: str) -> bool:
        key = _checked_ledger_key(event_key)
        binding = _checked_descriptor_hash(descriptor_hash)

        def operation(connection: sqlite3.Connection) -> bool:
            row = connection.execute(
                "SELECT descriptor_hash FROM palonexus_execution_ledger "
                "WHERE event_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                connection.execute(
                    "INSERT INTO palonexus_execution_ledger "
                    "(event_key, descriptor_hash, status) VALUES (?, ?, 'claimed')",
                    (key, binding),
                )
                return True
            if row[0] != binding:
                raise ApprovalScopeMismatch() from None
            return False

        try:
            return bool(self._transaction(operation))
        except ApprovalScopeMismatch:
            raise
        except (sqlite3.Error, OSError):
            raise AuthorizationUnavailable() from None

    def _transition(
        self,
        event_key: str,
        descriptor_hash: str,
        status: Literal["completed", "failed"],
    ) -> None:
        key = _checked_ledger_key(event_key)
        binding = _checked_descriptor_hash(descriptor_hash)

        def operation(connection: sqlite3.Connection) -> None:
            row = connection.execute(
                "SELECT descriptor_hash, status "
                "FROM palonexus_execution_ledger WHERE event_key = ?",
                (key,),
            ).fetchone()
            if row is None or row[0] != binding:
                raise ApprovalScopeMismatch() from None
            if row[1] == status:
                return
            if row[1] != "claimed":
                raise ApprovalScopeMismatch() from None
            connection.execute(
                "UPDATE palonexus_execution_ledger SET status = ? WHERE event_key = ?",
                (status, key),
            )

        try:
            self._transaction(operation)
        except ApprovalScopeMismatch:
            raise
        except (sqlite3.Error, OSError):
            raise AuthorizationUnavailable() from None

    def complete(self, event_key: str, descriptor_hash: str) -> None:
        self._transition(event_key, descriptor_hash, "completed")

    def fail(self, event_key: str, descriptor_hash: str) -> None:
        self._transition(event_key, descriptor_hash, "failed")

    def query(self, event_key: str) -> LedgerStatus:
        key = _checked_ledger_key(event_key)

        def operation(connection: sqlite3.Connection) -> LedgerStatus:
            row = connection.execute(
                "SELECT status FROM palonexus_execution_ledger WHERE event_key = ?",
                (key,),
            ).fetchone()
            if row is None:
                return "unclaimed"
            if row[0] not in {"claimed", "completed", "failed"}:
                raise ApprovalScopeMismatch() from None
            return cast(LedgerStatus, row[0])

        try:
            return cast(LedgerStatus, self._transaction(operation))
        except ApprovalScopeMismatch:
            raise
        except (sqlite3.Error, OSError):
            raise AuthorizationUnavailable() from None

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            try:
                self._connection.close()
            except sqlite3.Error:
                raise AuthorizationUnavailable() from None


class AsyncSQLiteExecutionLedger:
    """Async facade over the transactional SQLite execution ledger."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._ledger = SQLiteExecutionLedger(path)

    async def claim(self, event_key: str, descriptor_hash: str) -> bool:
        return await asyncio.to_thread(self._ledger.claim, event_key, descriptor_hash)

    async def complete(self, event_key: str, descriptor_hash: str) -> None:
        await asyncio.to_thread(self._ledger.complete, event_key, descriptor_hash)

    async def fail(self, event_key: str, descriptor_hash: str) -> None:
        await asyncio.to_thread(self._ledger.fail, event_key, descriptor_hash)

    async def query(self, event_key: str) -> LedgerStatus:
        return await asyncio.to_thread(self._ledger.query, event_key)

    async def aclose(self) -> None:
        await asyncio.to_thread(self._ledger.close)


@runtime_checkable
class SyncLangGraphAuthorizationClient(Protocol):
    @property
    def authorization_client_kind(self) -> Literal["sync"]: ...

    def decide(self, attempt: Any, **kwargs: Any) -> AuthorizationDecision: ...

    def authorize(self, attempt: Any, **kwargs: Any) -> AuthorizationDecision: ...

    def request_approval(
        self, attempt: Any, decision: AuthorizationDecision, **kwargs: Any
    ) -> ApprovalRecord: ...

    def get_approval(self, approval_id: str) -> ApprovalRecord: ...

    def wait_for_approval(self, approval_id: str, **kwargs: Any) -> ApprovalRecord: ...

    def resume_checkpoint(self, *args: Any, **kwargs: Any) -> Any: ...


@runtime_checkable
class AsyncLangGraphAuthorizationClient(Protocol):
    @property
    def authorization_client_kind(self) -> Literal["async"]: ...

    async def decide(self, attempt: Any, **kwargs: Any) -> AuthorizationDecision: ...

    async def authorize(self, attempt: Any, **kwargs: Any) -> AuthorizationDecision: ...

    async def request_approval(
        self, attempt: Any, decision: AuthorizationDecision, **kwargs: Any
    ) -> ApprovalRecord: ...

    async def get_approval(self, approval_id: str) -> ApprovalRecord: ...

    async def wait_for_approval(
        self, approval_id: str, **kwargs: Any
    ) -> ApprovalRecord: ...

    async def resume_checkpoint(self, *args: Any, **kwargs: Any) -> Any: ...


@runtime_checkable
class _TargetProjector(Protocol):
    def __call__(
        self, builder: ActionRequestBuilder, state: Mapping[str, object]
    ) -> object: ...


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


class LangGraphInvalidRequest(_LangGraphCompatible, InvalidRequest):
    """LangGraph-compatible invalid host input."""


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
    if isinstance(error, InvalidRequest):
        return LangGraphInvalidRequest(**fields)
    if isinstance(
        error,
        (KeyboardInterrupt, SystemExit, GeneratorExit, asyncio.CancelledError),
    ):
        return error
    return LangGraphAuthorizationUnavailable(**fields)


class PaloNexusLangGraphNode:
    """One sync or async governed node set wired with public LangGraph APIs.

    Applications exposing both entry modes must create separate nodes backed by
    the same durable SQLite execution-ledger file.
    """

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
        client: SyncLangGraphAuthorizationClient | None = None,
        async_client: AsyncLangGraphAuthorizationClient | None = None,
        handler: Callable[[Mapping[str, object]], Mapping[str, object]] | None = None,
        async_handler: Callable[[Mapping[str, object]], Awaitable[Mapping[str, object]]]
        | None = None,
        execution_ledger: ExecutionLedger | None = None,
        async_execution_ledger: AsyncExecutionLedger | None = None,
        checkpointer: object | None = None,
        trusted_clock: Callable[[], str] | None = None,
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
            or (client is not None and async_client is not None)
            or (client is None) != (execution_ledger is None)
            or (async_client is None) != (async_execution_ledger is None)
            or (
                client is not None
                and not isinstance(client, SyncLangGraphAuthorizationClient)
            )
            or (
                async_client is not None
                and not isinstance(
                    async_client,
                    AsyncLangGraphAuthorizationClient,
                )
            )
            or (
                execution_ledger is not None
                and not isinstance(execution_ledger, ExecutionLedger)
            )
            or (
                async_execution_ledger is not None
                and not isinstance(async_execution_ledger, AsyncExecutionLedger)
            )
            or (trusted_clock is not None and not callable(trusted_clock))
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
        self._execution_ledger = execution_ledger
        self._async_execution_ledger = async_execution_ledger
        self._trusted_clock = trusted_clock or _utc_now
        self._state_key = state_key
        self._checkpointer = _checkpointer(checkpointer)

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
            if type(decision) is not AuthorizationDecision:
                raise InvalidDecision() from None
        except BaseException as error:
            attempt.close()
            raise _graph_error(error) from None
        try:
            if decision.outcome is DecisionOutcome.DENY:
                raise LangGraphPolicyDenied(
                    request_id=decision.request_id,
                    decision_id=decision.decision_id,
                    correlation_id=decision.correlation_id,
                ) from None
            if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED:
                if _thread_namespace(config) is None or self._checkpointer is None:
                    raise LangGraphAuthorizationUnavailable(
                        request_id=decision.request_id,
                        decision_id=decision.decision_id,
                        correlation_id=decision.correlation_id,
                    ) from None
                try:
                    approval = self._client.request_approval(attempt, decision)
                    if type(approval) is not ApprovalRecord:
                        raise InvalidDecision() from None
                except BaseException as error:
                    raise _graph_error(error) from None
                rendered = self._descriptor(
                    attempt, decision, approval, status="approval_pending"
                )
                return {
                    self._state_key: rendered,
                    _MARKER_KEY: "INTERRUPTED",
                }
            rendered_descriptor = self._descriptor(
                attempt, decision, None, status="executable"
            )
            return {
                self._state_key: rendered_descriptor,
                _MARKER_KEY: "AUTHORIZED",
            }
        finally:
            attempt.close()

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
            if type(decision) is not AuthorizationDecision:
                raise InvalidDecision() from None
        except BaseException as error:
            attempt.close()
            raise _graph_error(error) from None
        try:
            if decision.outcome is DecisionOutcome.DENY:
                raise LangGraphPolicyDenied(
                    request_id=decision.request_id,
                    decision_id=decision.decision_id,
                    correlation_id=decision.correlation_id,
                ) from None
            if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED:
                if _thread_namespace(config) is None or self._checkpointer is None:
                    raise LangGraphAuthorizationUnavailable(
                        request_id=decision.request_id,
                        decision_id=decision.decision_id,
                        correlation_id=decision.correlation_id,
                    ) from None
                try:
                    approval = await self._async_client.request_approval(
                        attempt, decision
                    )
                    if type(approval) is not ApprovalRecord:
                        raise InvalidDecision() from None
                except BaseException as error:
                    raise _graph_error(error) from None
                rendered = self._descriptor(
                    attempt, decision, approval, status="approval_pending"
                )
                return {
                    self._state_key: rendered,
                    _MARKER_KEY: "INTERRUPTED",
                }
            rendered_descriptor = self._descriptor(
                attempt, decision, None, status="executable"
            )
            return {
                self._state_key: rendered_descriptor,
                _MARKER_KEY: "AUTHORIZED",
            }
        finally:
            attempt.close()

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
        resumed: Any = None
        try:
            resumed = self._client.resume_checkpoint(
                self._builder,
                current,
                original_request=descriptor["originalRequest"],
                client_scope_hash=descriptor["clientScopeHash"],
                prior_decision=descriptor["priorDecision"],
                pending_approval=descriptor["pendingApproval"],
            )
        except BaseException as error:
            raise _graph_error(error) from None
        finally:
            current.close()
        try:
            descriptor["status"] = "executable"
            rendered = _canonical(descriptor)
            return {self._state_key: rendered, _MARKER_KEY: "AUTHORIZED"}
        finally:
            resumed.close()

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
        resumed: Any = None
        try:
            resumed = await self._async_client.resume_checkpoint(
                self._builder,
                current,
                original_request=descriptor["originalRequest"],
                client_scope_hash=descriptor["clientScopeHash"],
                prior_decision=descriptor["priorDecision"],
                pending_approval=descriptor["pendingApproval"],
            )
        except BaseException as error:
            raise _graph_error(error) from None
        finally:
            current.close()
        try:
            descriptor["status"] = "executable"
            rendered = _canonical(descriptor)
            return {self._state_key: rendered, _MARKER_KEY: "AUTHORIZED"}
        finally:
            resumed.close()

    def _history_consumed(self, thread_id: str, event_id: str) -> bool:
        """Checkpoint history is replay evidence, never the execution lock."""

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

    async def _ahistory_consumed(self, thread_id: str, event_id: str) -> bool:
        """Async checkpoint evidence using only the saver's async iterator."""

        checkpointer = self._checkpointer
        if checkpointer is None or thread_id == "__ephemeral__":
            return False
        try:
            root_config = {
                "configurable": {"thread_id": thread_id, "checkpoint_ns": ""}
            }
            index = 0
            async for checkpoint_tuple in cast(Any, checkpointer).alist(root_config):
                if index >= 10_000:
                    raise AuthorizationUnavailable() from None
                index += 1
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

    @staticmethod
    def _ledger_binding(descriptor: Mapping[str, object]) -> tuple[str, str]:
        binding = dict(descriptor)
        binding["status"] = "binding"
        rendered = _canonical(binding)
        digest = "sha256:" + hashlib.sha256(rendered.encode("utf-8")).hexdigest()
        return f"{descriptor['tenantRef']}\0{descriptor['eventId']}", digest

    def _validate_execution(
        self,
        state: Mapping[str, object],
    ) -> tuple[dict[str, Any], Any]:
        if self._client is None:
            raise InvalidRequest() from None
        _, descriptor = self._checked_state(state)
        if descriptor["status"] in {"executed", "consumed"}:
            return descriptor, None
        if descriptor["status"] != "executable":
            raise ApprovalRequired() from None
        _require_fresh(descriptor["expiresAt"], self._trusted_clock)
        current = self._prepare(state, action_id=descriptor["actionId"])
        try:
            request = current.request.to_dict()
            if (
                request["target"] != descriptor["resource"]
                or request["actionId"] != descriptor["actionId"]
                or request["correlationId"] != descriptor["correlationId"]
                or request["task"]
                != {
                    "taskId": descriptor["taskId"],
                    "sessionId": descriptor["sessionId"],
                }
                or request["action"] != descriptor["action"]
                or request["sideEffect"] != descriptor["sideEffect"]
                or current.client_scope_hash != descriptor["clientScopeHash"]
            ):
                raise ApprovalScopeMismatch() from None
            decision = self._client.authorize(current)
            if type(decision) is not AuthorizationDecision or (
                decision.authoritative_scope_hash
                != descriptor["authoritativeScopeHash"]
                or decision.client_scope_hash != descriptor["clientScopeHash"]
            ):
                raise ApprovalScopeMismatch() from None
            _require_fresh(decision.expires_at, self._trusted_clock)
        except BaseException as error:
            current.close()
            raise _graph_error(error) from None
        return descriptor, current

    async def _avalidate_execution(
        self,
        state: Mapping[str, object],
    ) -> tuple[dict[str, Any], Any]:
        if self._async_client is None:
            raise InvalidRequest() from None
        _, descriptor = self._checked_state(state)
        if descriptor["status"] in {"executed", "consumed"}:
            return descriptor, None
        if descriptor["status"] != "executable":
            raise ApprovalRequired() from None
        _require_fresh(descriptor["expiresAt"], self._trusted_clock)
        current = self._prepare(state, action_id=descriptor["actionId"])
        try:
            request = current.request.to_dict()
            if (
                request["target"] != descriptor["resource"]
                or request["actionId"] != descriptor["actionId"]
                or request["correlationId"] != descriptor["correlationId"]
                or request["task"]
                != {
                    "taskId": descriptor["taskId"],
                    "sessionId": descriptor["sessionId"],
                }
                or request["action"] != descriptor["action"]
                or request["sideEffect"] != descriptor["sideEffect"]
                or current.client_scope_hash != descriptor["clientScopeHash"]
            ):
                raise ApprovalScopeMismatch() from None
            decision = await self._async_client.authorize(current)
            if type(decision) is not AuthorizationDecision or (
                decision.authoritative_scope_hash
                != descriptor["authoritativeScopeHash"]
                or decision.client_scope_hash != descriptor["clientScopeHash"]
            ):
                raise ApprovalScopeMismatch() from None
            _require_fresh(decision.expires_at, self._trusted_clock)
        except BaseException as error:
            current.close()
            raise _graph_error(error) from None
        return descriptor, current

    def execute(
        self, state: Mapping[str, object], config: RunnableConfig
    ) -> dict[str, object]:
        if self._handler is None or self._execution_ledger is None:
            raise InvalidRequest() from None
        try:
            _, persisted = self._checked_state(state)
            event_key, binding = self._ledger_binding(persisted)
            if self._execution_ledger.query(event_key) != "unclaimed":
                thread_id = _thread_namespace(config) or "__ephemeral__"
                self._history_consumed(thread_id, persisted["eventId"])
                return {
                    self._state_key: _canonical(persisted),
                    _MARKER_KEY: "REPLAY_BLOCKED",
                }
            descriptor, current = self._validate_execution(state)
            event_key, binding = self._ledger_binding(descriptor)
            claimed = self._execution_ledger.claim(event_key, binding)
        except BaseException as error:
            raise _graph_error(error) from None
        if current is None or not claimed:
            thread_id = _thread_namespace(config) or "__ephemeral__"
            self._history_consumed(thread_id, descriptor["eventId"])
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
        except BaseException as error:
            try:
                self._execution_ledger.fail(event_key, binding)
            except BaseException:
                pass
            current.close()
            raise _graph_error(error) from None
        try:
            self._execution_ledger.complete(event_key, binding)
        except BaseException as error:
            current.close()
            raise _graph_error(error) from None
        current.close()
        descriptor["status"] = "executed"
        return {
            **dict(result),
            self._state_key: _canonical(descriptor),
            _MARKER_KEY: "APPROVED_EXECUTED",
        }

    async def aexecute(
        self, state: Mapping[str, object], config: RunnableConfig
    ) -> dict[str, object]:
        if self._async_handler is None or self._async_execution_ledger is None:
            raise InvalidRequest() from None
        try:
            _, persisted = self._checked_state(state)
            event_key, binding = self._ledger_binding(persisted)
            if await self._async_execution_ledger.query(event_key) != "unclaimed":
                thread_id = _thread_namespace(config) or "__ephemeral__"
                await self._ahistory_consumed(thread_id, persisted["eventId"])
                return {
                    self._state_key: _canonical(persisted),
                    _MARKER_KEY: "REPLAY_BLOCKED",
                }
            descriptor, current = await self._avalidate_execution(state)
            event_key, binding = self._ledger_binding(descriptor)
            claimed = await self._async_execution_ledger.claim(event_key, binding)
        except BaseException as error:
            raise _graph_error(error) from None
        if current is None or not claimed:
            thread_id = _thread_namespace(config) or "__ephemeral__"
            await self._ahistory_consumed(thread_id, descriptor["eventId"])
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
        except BaseException as error:
            try:
                await self._async_execution_ledger.fail(event_key, binding)
            except BaseException:
                pass
            current.close()
            raise _graph_error(error) from None
        try:
            await self._async_execution_ledger.complete(event_key, binding)
        except BaseException as error:
            current.close()
            raise _graph_error(error) from None
        current.close()
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
    "LangGraphInvalidRequest",
    "ExecutionLedger",
    "AsyncExecutionLedger",
    "InMemoryExecutionLedger",
    "AsyncInMemoryExecutionLedger",
    "SQLiteExecutionLedger",
    "AsyncSQLiteExecutionLedger",
    "SyncLangGraphAuthorizationClient",
    "AsyncLangGraphAuthorizationClient",
    "MissingLangGraphDependency",
    "PaloNexusLangGraphNode",
]
