# SPDX-License-Identifier: MIT
"""Explicitly testing-only scripted authorization and approval transports."""

from __future__ import annotations

import asyncio
import concurrent.futures
import hashlib
import math
import threading
import time
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import partial
from types import MappingProxyType
from typing import Any, Final, Literal, Never, cast

from .. import _canonicalize
from .._generated import protocol as wire
from ..errors import (
    ApprovalExpired,
    AuthorizationUnavailable,
    IdempotencyConflict,
    InvalidRequest,
    PaloNexusError,
)

_MAX_DELAY: Final[float] = 60.0
_POLL: Final[float] = 0.01


def _invalid() -> Never:
    raise InvalidRequest() from None


class FrozenClock:
    """Thread-safe, caller-controlled RFC3339 clock for deterministic tests."""

    __slots__ = ("_lock", "_now")

    def __init__(self, now: str) -> None:
        failed = False
        parsed: datetime | None = None
        try:
            if type(now) is not str:
                raise ValueError
            parsed = datetime.fromisoformat(now.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
        except Exception:
            failed = True
        del now
        if failed or parsed is None:
            _invalid()
        self._now = parsed.astimezone(UTC)
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, seconds: float) -> None:
        failed = (
            isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not math.isfinite(seconds)
            or seconds < 0
        )
        checked = 0.0 if failed else float(seconds)
        del seconds
        if failed:
            _invalid()
        with self._lock:
            self._now += timedelta(seconds=checked)


def _frozen(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType(
            {str(key): _frozen(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_frozen(item) for item in value)
    return value


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class RecordedCall:
    """Immutable, secret-free snapshot of a scripted transport call."""

    operation: str
    request: Mapping[str, Any]
    canonical_request_hash: str
    client_scope_hash: str


@dataclass(frozen=True, slots=True)
class _Outcome:
    kind: str
    reason_code: str = ""
    value: object | None = None
    delay_seconds: float = 0.0
    nested: _Outcome | None = None


@dataclass(slots=True)
class _IdempotencyEntry:
    request_hash: str
    result: wire.AuthorizationDecision
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class _ApprovalBinding:
    request_hash: str
    action_id: str
    request_id: str
    correlation_id: str
    client_scope_hash: str
    authoritative_scope_hash: str
    decision_id: str
    approval_id: str
    approval_expires_at: datetime


@dataclass(frozen=True, slots=True)
class _ResolutionBinding:
    approval_id: str
    status: str
    reviewer_ref: str | None
    result: wire.ApprovalRecord


@dataclass(frozen=True, slots=True)
class _WorkerOutcome:
    state: Literal["NOT_COMMITTED_CANCELLED", "COMMITTED"]
    result: object | None = None


class _CommitGate:
    __slots__ = ("_lock", "_outcome", "_state")

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._state: Literal["OPEN", "CANCELLED", "COMMITTING", "COMMITTED"] = "OPEN"
        self._outcome: _WorkerOutcome | None = None

    def cancel(self) -> bool:
        if not self._lock.acquire(blocking=False):
            return False
        try:
            if self._state != "OPEN":
                return False
            self._state = "CANCELLED"
            return True
        finally:
            self._lock.release()

    @property
    def cancelled(self) -> bool:
        return self._state == "CANCELLED"

    def begin_commit(self) -> None:
        with self._lock:
            if self._state == "CANCELLED":
                raise concurrent.futures.CancelledError from None
            if self._state != "OPEN":
                raise AuthorizationUnavailable() from None
            self._state = "COMMITTING"

    def publish_committed(self, result: object) -> None:
        with self._lock:
            self._outcome = _WorkerOutcome("COMMITTED", result)
            self._state = "COMMITTED"

    @property
    def outcome(self) -> _WorkerOutcome | None:
        return self._outcome


_CONTROL_EXCEPTIONS = (
    KeyboardInterrupt,
    SystemExit,
    GeneratorExit,
    concurrent.futures.CancelledError,
    asyncio.CancelledError,
)


def _clean_control(error: BaseException) -> BaseException:
    error.__traceback__ = None
    error.__cause__ = None
    error.__context__ = None
    return error


def _safe_failure(error: BaseException) -> BaseException:
    if isinstance(error, _CONTROL_EXCEPTIONS):
        return _clean_control(error)
    if isinstance(error, PaloNexusError):
        safe = type(error)(
            request_id=error.request_id,
            decision_id=error.decision_id,
            correlation_id=error.correlation_id,
        )
    else:
        safe = AuthorizationUnavailable()
    _clean_control(error)
    return safe


class ScriptedEngine:
    """Exact-outcome engine with no policy or condition evaluation.

    Every outcome must be queued by test code. Exhaustion, storage pressure,
    malformed inputs, cancellation, and deadlines fail closed.
    """

    __slots__ = (
        "_approvals",
        "_after_commit",
        "_before_commit",
        "_calls",
        "_clock",
        "_closed",
        "_decision_bindings",
        "_id_source",
        "_idempotency",
        "_idempotency_capacity",
        "_idempotency_ttl",
        "_lock",
        "_outcomes",
        "_resolution_idempotency",
        "_sequence",
        "_version",
    )

    def __init__(
        self,
        *outcomes: _Outcome,
        testing_only: Literal[True],
        clock: Callable[[], datetime] | None = None,
        id_source: Callable[[], str] | None = None,
        idempotency_capacity: int = 256,
        idempotency_ttl: float = 300.0,
        before_commit: Callable[[str], None] | None = None,
        after_commit: Callable[[str], None] | None = None,
    ) -> None:
        if testing_only is not True:
            raise ValueError("testing_only=True is required")
        if (
            isinstance(idempotency_capacity, bool)
            or idempotency_capacity < 1
            or isinstance(idempotency_ttl, bool)
            or not isinstance(idempotency_ttl, (int, float))
            or not math.isfinite(idempotency_ttl)
            or idempotency_ttl <= 0
        ):
            _invalid()
        self._clock = clock or (lambda: datetime.now(UTC))
        self._before_commit = before_commit
        self._after_commit = after_commit
        self._id_source = id_source
        self._idempotency_capacity = idempotency_capacity
        self._idempotency_ttl = idempotency_ttl
        self._outcomes = deque(outcomes)
        self._idempotency: dict[str, _IdempotencyEntry] = {}
        self._approvals: dict[str, wire.ApprovalRecord] = {}
        self._decision_bindings: dict[str, _ApprovalBinding] = {}
        self._resolution_idempotency: dict[str, _ResolutionBinding] = {}
        self._calls: list[RecordedCall] = []
        self._lock = threading.RLock()
        self._sequence = 0
        self._version = 0
        self._closed = False

    def _commit(
        self,
        operation: str,
        mutation: Callable[[], object],
        gate: _CommitGate | None,
    ) -> object:
        if self._before_commit is not None:
            self._before_commit(operation)
        if gate is not None:
            gate.begin_commit()
        result = mutation()
        if gate is not None:
            gate.publish_committed(result)
        if self._after_commit is not None:
            try:
                self._after_commit(operation)
            except BaseException as error:
                _clean_control(error)
        return result

    @staticmethod
    def allow(*, reason_code: str = "testing_scripted_allow") -> _Outcome:
        return _Outcome("allow", reason_code=reason_code)

    @staticmethod
    def deny(*, reason_code: str = "testing_scripted_deny") -> _Outcome:
        return _Outcome("deny", reason_code=reason_code)

    @staticmethod
    def approval_required(
        *, reason_code: str = "testing_scripted_approval"
    ) -> _Outcome:
        return _Outcome("approval_required", reason_code=reason_code)

    @staticmethod
    def outage() -> _Outcome:
        return _Outcome("outage")

    @staticmethod
    def error(error: BaseException) -> _Outcome:
        """Queue an error without making an unsafe exception part of SDK state.

        Safe ``PaloNexusError`` instances remain typed. Interpreter control-flow
        exceptions retain identity after their graph is cleared. Every other
        ``BaseException`` is discarded immediately and later surfaces as the
        canonical ``AuthorizationUnavailable`` failure.
        """

        if isinstance(error, PaloNexusError) or isinstance(error, _CONTROL_EXCEPTIONS):
            return _Outcome("error", value=_clean_control(error))
        return _Outcome("unsafe_error")

    @staticmethod
    def delay(seconds: float, outcome: _Outcome) -> _Outcome:
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not math.isfinite(seconds)
            or seconds < 0
            or seconds > _MAX_DELAY
            or type(outcome) is not _Outcome
        ):
            _invalid()
        return _Outcome("delay", delay_seconds=float(seconds), nested=outcome)

    def enqueue(self, *outcomes: _Outcome) -> None:
        if any(type(outcome) is not _Outcome for outcome in outcomes):
            _invalid()
        with self._lock:
            self._outcomes.extend(outcomes)
            self._version += 1

    @property
    def recorded_calls(self) -> tuple[RecordedCall, ...]:
        with self._lock:
            return tuple(self._calls)

    def _now(self) -> datetime:
        failed = False
        control: BaseException | None = None
        value: object = None
        try:
            value = self._clock()
        except BaseException as error:
            if isinstance(error, _CONTROL_EXCEPTIONS):
                control = _clean_control(error)
            else:
                failed = True
        if control is not None:
            raise control
        if failed:
            _invalid()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _invalid()
        return value.astimezone(UTC)

    def _new_id(self, prefix: str) -> str:
        next_sequence = self._sequence + 1
        if self._id_source is not None:
            failed = False
            control: BaseException | None = None
            supplied: object = None
            try:
                supplied = self._id_source()
            except BaseException as error:
                if isinstance(error, _CONTROL_EXCEPTIONS):
                    control = _clean_control(error)
                else:
                    failed = True
            if control is not None:
                raise control
            if failed:
                _invalid()
            if type(supplied) is not str:
                _invalid()
            suffix = supplied.split("_", 1)[-1]
        else:
            suffix = f"01J5ABCDEFGHJKMNPQRST{next_sequence:06X}"[-26:]
        value = f"{prefix}_{suffix}"
        validators: dict[str, Callable[[str], str]] = {
            "dec": wire.DecisionID,
            "audit": wire.AuditRef,
            "apr": wire.ApprovalID,
            "approval": wire.ApprovalResolutionIdempotencyKey,
        }
        try:
            checked = str(validators[prefix](value))
        except (KeyError, TypeError, ValueError):
            _invalid()
        self._sequence = next_sequence
        return checked

    @staticmethod
    def _hash(request: wire.ActionRequest) -> str:
        return (
            "sha256:"
            + hashlib.sha256(
                _canonicalize.canonical_json(request.to_dict())
            ).hexdigest()
        )

    def _purge_expired(self, now: datetime) -> None:
        expired = [
            key for key, entry in self._idempotency.items() if entry.expires_at <= now
        ]
        for key in expired:
            del self._idempotency[key]
        if expired:
            self._version += 1

    def _prepared_call(
        self, request: wire.ActionRequest, client_scope_hash: str, request_hash: str
    ) -> RecordedCall:
        document = request.to_dict()
        target = document.get("target")
        safe_target: dict[str, Any] = {}
        if isinstance(target, dict):
            for name in ("kind", "service", "resourceHash"):
                if name in target:
                    safe_target[name] = target[name]
        # Keep identifiers and hashes required to assert binding, but never retain
        # context parameters, extension values, raw resources, or credentials.
        document = {
            name: document[name]
            for name in (
                "schemaVersion",
                "actionId",
                "requestId",
                "correlationId",
                "idempotencyKey",
                "adapter",
                "task",
                "action",
                "sideEffect",
                "occurredAt",
                "causationId",
                "resumeFromApprovalId",
            )
            if name in document
        }
        document["target"] = safe_target
        document["context"] = {"parameters": None}
        return RecordedCall(
            operation="decide",
            request=cast(Mapping[str, Any], _frozen(document)),
            canonical_request_hash=request_hash,
            client_scope_hash=client_scope_hash,
        )

    def _record(
        self, request: wire.ActionRequest, client_scope_hash: str, request_hash: str
    ) -> None:
        self._calls.append(
            self._prepared_call(request, client_scope_hash, request_hash)
        )

    @staticmethod
    def _check_control(
        *, deadline: float | None, cancelled: Callable[[], bool] | None
    ) -> None:
        if cancelled is not None:
            requested = False
            try:
                requested = bool(cancelled())
            except BaseException as error:
                if isinstance(error, _CONTROL_EXCEPTIONS):
                    raise _clean_control(error)
                requested = True
            if requested:
                raise concurrent.futures.CancelledError from None
        if deadline is not None and time.monotonic() >= deadline:
            raise AuthorizationUnavailable() from None

    def _sleep(
        self,
        seconds: float,
        *,
        deadline: float | None,
        cancelled: Callable[[], bool] | None,
    ) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self._check_control(deadline=deadline, cancelled=cancelled)
            time.sleep(min(_POLL, end - time.monotonic()))

    def _decision(
        self,
        outcome: _Outcome,
        request: wire.ActionRequest,
        client_scope_hash: str,
        now: datetime,
    ) -> wire.AuthorizationDecision:
        if outcome.kind == "error":
            assert isinstance(outcome.value, BaseException)
            raise _clean_control(outcome.value)
        if outcome.kind in {"outage", "unsafe_error"}:
            raise AuthorizationUnavailable(
                request_id=request.request_id,
                correlation_id=request.correlation_id,
            ) from None
        if outcome.kind not in {"allow", "deny", "approval_required"}:
            _invalid()
        decision_id = self._new_id("dec")
        audit_ref = self._new_id("audit")
        authoritative_hash = client_scope_hash
        document: dict[str, Any] = {
            "schemaVersion": "1",
            "requestId": str(request.request_id),
            "decisionId": decision_id,
            "correlationId": str(request.correlation_id),
            "outcome": outcome.kind,
            "reasonCode": outcome.reason_code,
            "displayReason": "Scripted testing outcome.",
            "clientScopeHash": client_scope_hash,
            "authoritativeScopeHash": authoritative_hash,
            "policyRevision": "policy_testing-script-v1",
            "serverTime": _timestamp(now),
            "expiresAt": _timestamp(now + timedelta(minutes=5)),
            "auditRef": audit_ref,
            "cache": {"cacheable": False},
        }
        if outcome.kind == "approval_required":
            document["approval"] = {
                "approvalId": self._new_id("apr"),
                "status": "pending",
                "expiresAt": _timestamp(now + timedelta(minutes=15)),
            }
        return wire.parse_decision(document)

    def decide(
        self,
        request: wire.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
        _commit_gate: _CommitGate | None = None,
    ) -> wire.AuthorizationDecision:
        failure: BaseException | None = None
        try:
            return self._decide(
                request,
                client_scope_hash=client_scope_hash,
                deadline=deadline,
                cancelled=cancelled,
                _commit_gate=_commit_gate,
            )
        except BaseException as error:
            failure = _safe_failure(error)
        del request, client_scope_hash, deadline, cancelled, _commit_gate
        assert failure is not None
        raise failure from None

    def _decide(
        self,
        request: wire.ActionRequest,
        *,
        client_scope_hash: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
        _commit_gate: _CommitGate | None = None,
    ) -> wire.AuthorizationDecision:
        self._check_control(deadline=deadline, cancelled=cancelled)
        try:
            request.validate_structural()
            expected_scope = _canonicalize.client_scope_hash(request.to_dict())
            if client_scope_hash != expected_scope:
                raise ValueError
        except Exception:
            _invalid()
        request_hash = self._hash(request)
        key = str(request.idempotency_key)
        with self._lock:
            self._check_control(deadline=deadline, cancelled=cancelled)
            if self._closed:
                raise AuthorizationUnavailable() from None
            start_now = self._now()
            self._purge_expired(start_now)
            expected_version = self._version
            prior = self._idempotency.get(key)
            if prior is not None:
                if prior.request_hash != request_hash:
                    raise IdempotencyConflict(
                        request_id=request.request_id,
                        correlation_id=request.correlation_id,
                    ) from None

                replay_call = self._prepared_call(
                    request, client_scope_hash, request_hash
                )

                def replay() -> object:
                    if (
                        self._version != expected_version
                        or self._idempotency.get(key) is not prior
                    ):
                        raise AuthorizationUnavailable() from None
                    self._calls.append(replay_call)
                    self._version += 1
                    return prior.result

                return cast(
                    wire.AuthorizationDecision,
                    self._commit("decide", replay, _commit_gate),
                )
            if len(self._idempotency) >= self._idempotency_capacity:
                raise AuthorizationUnavailable(
                    request_id=request.request_id,
                    correlation_id=request.correlation_id,
                ) from None
            if not self._outcomes:
                raise AuthorizationUnavailable(
                    request_id=request.request_id,
                    correlation_id=request.correlation_id,
                ) from None
            scripted_outcome = self._outcomes[0]
            outcome = scripted_outcome
            # Serialize scripted consumption and insertion so concurrent reuse of
            # one idempotency key cannot consume two outcomes.
            while outcome.kind == "delay":
                self._sleep(
                    outcome.delay_seconds, deadline=deadline, cancelled=cancelled
                )
                assert outcome.nested is not None
                outcome = outcome.nested
            completion_now = self._now()

            def commit_decision() -> object:
                if (
                    self._version != expected_version
                    or not self._outcomes
                    or self._outcomes[0] is not scripted_outcome
                    or key in self._idempotency
                ):
                    raise AuthorizationUnavailable() from None
                result = self._decision(
                    outcome, request, client_scope_hash, completion_now
                )
                if (
                    result.approval is not None
                    and len(self._decision_bindings) >= self._idempotency_capacity
                ):
                    raise AuthorizationUnavailable(
                        request_id=request.request_id,
                        correlation_id=request.correlation_id,
                    ) from None
                recorded_call = self._prepared_call(
                    request, client_scope_hash, request_hash
                )
                idempotency_entry = _IdempotencyEntry(
                    request_hash=request_hash,
                    result=result,
                    expires_at=completion_now
                    + timedelta(seconds=self._idempotency_ttl),
                )
                decision_binding: _ApprovalBinding | None = None
                if result.approval is not None:
                    decision_binding = _ApprovalBinding(
                        request_hash=request_hash,
                        action_id=str(request.action_id),
                        request_id=str(request.request_id),
                        correlation_id=str(request.correlation_id),
                        client_scope_hash=client_scope_hash,
                        authoritative_scope_hash=str(result.authoritative_scope_hash),
                        decision_id=str(result.decision_id),
                        approval_id=str(result.approval.approval_id),
                        approval_expires_at=datetime.fromisoformat(
                            str(result.approval.expires_at).replace("Z", "+00:00")
                        ),
                    )
                self._outcomes.popleft()
                self._calls.append(recorded_call)
                self._idempotency[key] = idempotency_entry
                if decision_binding is not None:
                    self._decision_bindings[str(result.decision_id)] = decision_binding
                self._version += 1
                return result

            return cast(
                wire.AuthorizationDecision,
                self._commit("decide", commit_decision, _commit_gate),
            )

    def request_approval(
        self,
        request: wire.ActionRequest,
        *,
        decision_id: str,
        authoritative_scope_hash: str,
        approval_id: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
        _commit_gate: _CommitGate | None = None,
    ) -> wire.ApprovalRecord:
        failure: BaseException | None = None
        try:
            return self._request_approval(
                request,
                decision_id=decision_id,
                authoritative_scope_hash=authoritative_scope_hash,
                approval_id=approval_id,
                deadline=deadline,
                cancelled=cancelled,
                _commit_gate=_commit_gate,
            )
        except BaseException as error:
            failure = _safe_failure(error)
        del (
            request,
            decision_id,
            authoritative_scope_hash,
            approval_id,
            deadline,
            cancelled,
            _commit_gate,
        )
        assert failure is not None
        raise failure from None

    def _request_approval(
        self,
        request: wire.ActionRequest,
        *,
        decision_id: str,
        authoritative_scope_hash: str,
        approval_id: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
        _commit_gate: _CommitGate | None = None,
    ) -> wire.ApprovalRecord:
        self._check_control(deadline=deadline, cancelled=cancelled)
        failed = False
        try:
            request.validate_structural()
            checked_decision_id = str(wire.DecisionID(decision_id))
            checked_scope = str(wire.SHA256Digest(authoritative_scope_hash))
            checked_approval_id = str(wire.ApprovalID(approval_id))
            request_hash = self._hash(request)
            current_scope = _canonicalize.client_scope_hash(request.to_dict())
        except Exception:
            failed = True
            checked_decision_id = checked_scope = checked_approval_id = ""
            request_hash = current_scope = ""
        if failed:
            raise InvalidRequest() from None
        with self._lock:
            self._check_control(deadline=deadline, cancelled=cancelled)
            if self._closed:
                raise AuthorizationUnavailable() from None
            expected_version = self._version
            binding = self._decision_bindings.get(checked_decision_id)
            mismatch = (
                binding is None
                or binding.request_hash != request_hash
                or binding.action_id != str(request.action_id)
                or binding.request_id != str(request.request_id)
                or binding.correlation_id != str(request.correlation_id)
                or binding.client_scope_hash != current_scope
                or binding.authoritative_scope_hash != checked_scope
                or binding.approval_id != checked_approval_id
            )
            if mismatch:
                raise IdempotencyConflict(
                    request_id=request.request_id,
                    decision_id=checked_decision_id,
                    correlation_id=request.correlation_id,
                ) from None
            assert binding is not None
            existing = self._approvals.get(checked_approval_id)
            if existing is not None:
                replay_call = self._prepared_call(
                    request, binding.client_scope_hash, request_hash
                )
                replay_call = RecordedCall(
                    operation="request_approval",
                    request=replay_call.request,
                    canonical_request_hash=request_hash,
                    client_scope_hash=binding.client_scope_hash,
                )

                def replay_approval() -> object:
                    if (
                        self._version != expected_version
                        or self._approvals.get(checked_approval_id) is not existing
                    ):
                        raise AuthorizationUnavailable() from None
                    self._calls.append(replay_call)
                    self._version += 1
                    return existing

                return cast(
                    wire.ApprovalRecord,
                    self._commit(
                        "request_approval",
                        replay_approval,
                        _commit_gate,
                    ),
                )
            now = self._now()
            self._check_control(deadline=deadline, cancelled=cancelled)
            if binding.approval_expires_at <= now:
                raise ApprovalExpired(
                    request_id=request.request_id,
                    decision_id=checked_decision_id,
                    correlation_id=request.correlation_id,
                ) from None
            if len(self._approvals) >= self._idempotency_capacity:
                raise AuthorizationUnavailable(
                    request_id=request.request_id,
                    correlation_id=request.correlation_id,
                ) from None

            def commit_approval() -> object:
                if (
                    self._version != expected_version
                    or self._decision_bindings.get(checked_decision_id) is not binding
                    or checked_approval_id in self._approvals
                ):
                    raise AuthorizationUnavailable() from None
                document: dict[str, wire.JSONValue] = {
                    "schemaVersion": "1",
                    "approvalId": binding.approval_id,
                    "actionId": binding.action_id,
                    "correlationId": binding.correlation_id,
                    "authoritativeScopeHash": binding.authoritative_scope_hash,
                    "status": "pending",
                    "requestedAt": _timestamp(now),
                    "expiresAt": _timestamp(binding.approval_expires_at),
                    "requesterRef": "subject:testing-requester",
                    "authorizationDecisionId": binding.decision_id,
                    "creationAuditRef": self._new_id("audit"),
                }
                record = wire.parse_approval(document)
                approval_call = self._prepared_call(
                    request, binding.client_scope_hash, request_hash
                )
                approval_call = RecordedCall(
                    operation="request_approval",
                    request=approval_call.request,
                    canonical_request_hash=request_hash,
                    client_scope_hash=binding.client_scope_hash,
                )
                self._calls.append(approval_call)
                self._approvals[checked_approval_id] = record
                self._version += 1
                return record

            return cast(
                wire.ApprovalRecord,
                self._commit(
                    "request_approval",
                    commit_approval,
                    _commit_gate,
                ),
            )

    def get_approval(
        self,
        approval_id: str,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
        _commit_gate: _CommitGate | None = None,
    ) -> wire.ApprovalRecord:
        failure: BaseException | None = None
        try:
            return self._get_approval(
                approval_id,
                deadline=deadline,
                cancelled=cancelled,
                _commit_gate=_commit_gate,
            )
        except BaseException as error:
            failure = _safe_failure(error)
        del approval_id, deadline, cancelled, _commit_gate
        assert failure is not None
        raise failure from None

    def _get_approval(
        self,
        approval_id: str,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
        _commit_gate: _CommitGate | None = None,
    ) -> wire.ApprovalRecord:
        self._check_control(deadline=deadline, cancelled=cancelled)
        with self._lock:
            self._check_control(deadline=deadline, cancelled=cancelled)
            expected_version = self._version
            try:
                record = self._approvals[approval_id]
            except KeyError:
                raise AuthorizationUnavailable() from None
            now = self._now()
            self._check_control(deadline=deadline, cancelled=cancelled)
            expiry = datetime.fromisoformat(
                str(record.expires_at).replace("Z", "+00:00")
            )
            approval_hash = (
                "sha256:" + hashlib.sha256(approval_id.encode("utf-8")).hexdigest()
            )
            observed_call = RecordedCall(
                operation="get_approval",
                request=MappingProxyType({"approvalId": approval_id}),
                canonical_request_hash=approval_hash,
                client_scope_hash="",
            )

            def commit_get() -> object:
                if (
                    self._version != expected_version
                    or self._approvals.get(approval_id) is not record
                ):
                    raise AuthorizationUnavailable() from None
                prepared = record
                expiry_key: str | None = None
                expiry_binding: _ResolutionBinding | None = None
                if str(record.status) == "pending" and now >= expiry:
                    expiry_key = self._new_id("approval")
                    if expiry_key in self._resolution_idempotency:
                        raise AuthorizationUnavailable() from None
                    prepared = self._resolve(
                        record,
                        status="expired",
                        reviewer_ref=None,
                        resolution_idempotency_key=expiry_key,
                        now=now,
                    )
                    expiry_binding = _ResolutionBinding(
                        approval_id=approval_id,
                        status="expired",
                        reviewer_ref=None,
                        result=prepared,
                    )
                if expiry_key is not None:
                    assert expiry_binding is not None
                    self._approvals[approval_id] = prepared
                    self._resolution_idempotency[expiry_key] = expiry_binding
                self._calls.append(observed_call)
                self._version += 1
                return prepared

            return cast(
                wire.ApprovalRecord,
                self._commit("get_approval", commit_get, _commit_gate),
            )

    def _resolve(
        self,
        record: wire.ApprovalRecord,
        *,
        status: str,
        reviewer_ref: str | None,
        resolution_idempotency_key: str,
        now: datetime,
    ) -> wire.ApprovalRecord:
        document = record.to_dict()
        if status == "expired":
            expiry = datetime.fromisoformat(
                str(record.expires_at).replace("Z", "+00:00")
            )
            if now < expiry:
                now = expiry
        document.update(
            {
                "status": status,
                "decidedAt": _timestamp(now),
                "resolutionAuditRef": self._new_id("audit"),
                "resolutionDecisionId": self._new_id("dec"),
                "resolutionReasonCode": f"testing_{status}",
                "resolutionIdempotencyKey": resolution_idempotency_key,
            }
        )
        if reviewer_ref is not None:
            document["reviewerRef"] = reviewer_ref
        return wire.parse_approval(document)

    def _transition_locked(
        self,
        record: wire.ApprovalRecord,
        *,
        status: str,
        reviewer_ref: str | None,
        resolution_idempotency_key: str,
        now: datetime,
    ) -> wire.ApprovalRecord:
        if resolution_idempotency_key in self._resolution_idempotency:
            raise IdempotencyConflict() from None
        resolved = self._resolve(
            record,
            status=status,
            reviewer_ref=reviewer_ref,
            resolution_idempotency_key=resolution_idempotency_key,
            now=now,
        )
        approval_id = str(record.approval_id)
        resolution_binding = _ResolutionBinding(
            approval_id=approval_id,
            status=status,
            reviewer_ref=reviewer_ref,
            result=resolved,
        )
        self._approvals[approval_id] = resolved
        self._resolution_idempotency[resolution_idempotency_key] = resolution_binding
        self._version += 1
        return resolved

    def _expire_locked(
        self, record: wire.ApprovalRecord, *, now: datetime
    ) -> wire.ApprovalRecord:
        key = self._new_id("approval")
        if key in self._resolution_idempotency:
            raise AuthorizationUnavailable() from None
        return self._transition_locked(
            record,
            status="expired",
            reviewer_ref=None,
            resolution_idempotency_key=key,
            now=now,
        )

    def resolve_approval(
        self,
        approval_id: str,
        *,
        status: Literal["approved", "denied", "expired", "cancelled"],
        reviewer_ref: str | None,
        resolution_idempotency_key: str,
    ) -> wire.ApprovalRecord:
        failure: BaseException | None = None
        try:
            return self._resolve_approval(
                approval_id,
                status=status,
                reviewer_ref=reviewer_ref,
                resolution_idempotency_key=resolution_idempotency_key,
            )
        except BaseException as error:
            failure = _safe_failure(error)
        del approval_id, status, reviewer_ref, resolution_idempotency_key
        assert failure is not None
        raise failure from None

    def _resolve_approval(
        self,
        approval_id: str,
        *,
        status: Literal["approved", "denied", "expired", "cancelled"],
        reviewer_ref: str | None,
        resolution_idempotency_key: str,
    ) -> wire.ApprovalRecord:
        failed = False
        try:
            checked_approval_id = str(wire.ApprovalID(approval_id))
            checked_key = str(
                wire.ApprovalResolutionIdempotencyKey(resolution_idempotency_key)
            )
            if status not in {"approved", "denied", "expired", "cancelled"}:
                raise ValueError
            checked_reviewer = (
                None if reviewer_ref is None else str(wire.PrincipalRef(reviewer_ref))
            )
        except Exception:
            failed = True
            checked_approval_id = ""
            checked_key = ""
            checked_reviewer = None
        if failed:
            raise InvalidRequest() from None
        with self._lock:
            prior_resolution = self._resolution_idempotency.get(checked_key)
            if prior_resolution is not None:
                if (
                    prior_resolution.approval_id == checked_approval_id
                    and prior_resolution.status == status
                    and prior_resolution.reviewer_ref == checked_reviewer
                ):
                    return prior_resolution.result
                raise IdempotencyConflict() from None
            record = self._approvals.get(checked_approval_id)
            if record is None:
                raise IdempotencyConflict() from None
            if str(record.status) != "pending":
                if str(record.status) == "expired":
                    raise ApprovalExpired(
                        decision_id=record.resolution_decision_id,
                        correlation_id=record.correlation_id,
                    ) from None
                raise IdempotencyConflict(
                    decision_id=record.resolution_decision_id,
                    correlation_id=record.correlation_id,
                ) from None
            if status in {"approved", "denied"} and checked_reviewer is None:
                raise InvalidRequest() from None
            now = self._now()
            expiry = datetime.fromisoformat(
                str(record.expires_at).replace("Z", "+00:00")
            )
            if now >= expiry:
                self._expire_locked(record, now=now)
                raise ApprovalExpired(
                    correlation_id=record.correlation_id,
                ) from None
            resolved = self._transition_locked(
                record,
                status=status,
                reviewer_ref=checked_reviewer,
                resolution_idempotency_key=checked_key,
                now=now,
            )
            return resolved

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._version += 1


class FakeTransport:
    """Synchronous testing transport backed by a :class:`ScriptedEngine`."""

    __slots__ = ("_engine",)

    def __init__(self, engine: ScriptedEngine, *, testing_only: Literal[True]) -> None:
        if testing_only is not True or type(engine) is not ScriptedEngine:
            raise ValueError("testing_only=True and a ScriptedEngine are required")
        self._engine = engine

    def decide(
        self, request: wire.ActionRequest, **kwargs: Any
    ) -> wire.AuthorizationDecision:
        failure: BaseException | None = None
        try:
            return self._engine.decide(request, **kwargs)
        except BaseException as error:
            failure = _safe_failure(error)
        del request, kwargs
        assert failure is not None
        raise failure from None

    def request_approval(
        self, request: wire.ActionRequest, **kwargs: Any
    ) -> wire.ApprovalRecord:
        failure: BaseException | None = None
        try:
            return self._engine.request_approval(request, **kwargs)
        except BaseException as error:
            failure = _safe_failure(error)
        del request, kwargs
        assert failure is not None
        raise failure from None

    def get_approval(self, approval_id: str, **kwargs: Any) -> wire.ApprovalRecord:
        failure: BaseException | None = None
        try:
            return self._engine.get_approval(approval_id, **kwargs)
        except BaseException as error:
            failure = _safe_failure(error)
        del approval_id, kwargs
        assert failure is not None
        raise failure from None

    def close(self) -> None:
        """Borrowed engine lifecycle is intentionally unchanged."""


class AsyncFakeTransport:
    """Async testing transport with cancellation-safe worker cleanup."""

    __slots__ = ("_engine",)

    def __init__(self, engine: ScriptedEngine, *, testing_only: Literal[True]) -> None:
        if testing_only is not True or type(engine) is not ScriptedEngine:
            raise ValueError("testing_only=True and a ScriptedEngine are required")
        self._engine = engine

    @staticmethod
    async def _run_linearized(
        call: Callable[[], object],
        gate: _CommitGate,
        cancel_signal: Callable[[], None],
    ) -> object:
        def worker_call() -> _WorkerOutcome:
            try:
                result = call()
            except concurrent.futures.CancelledError:
                return gate.outcome or _WorkerOutcome("NOT_COMMITTED_CANCELLED")
            except BaseException:
                if gate.cancelled:
                    return _WorkerOutcome("NOT_COMMITTED_CANCELLED")
                raise
            return gate.outcome or _WorkerOutcome("COMMITTED", result)

        worker = asyncio.create_task(asyncio.to_thread(worker_call))
        cancellation: asyncio.CancelledError | None = None
        try:
            outcome = await asyncio.shield(worker)
        except asyncio.CancelledError as error:
            cancellation = error
            cancel_signal()
            gate.cancel()
            current = asyncio.current_task()
            if current is not None:
                current.uncancel()
            while True:
                try:
                    outcome = await asyncio.shield(worker)
                    break
                except asyncio.CancelledError:
                    cancel_signal()
                    gate.cancel()
                    if current is not None:
                        current.uncancel()
        if outcome.state == "COMMITTED":
            return outcome.result
        if cancellation is None:
            cancellation = asyncio.CancelledError()
        raise _clean_control(cancellation)

    async def decide(
        self, request: wire.ActionRequest, **kwargs: Any
    ) -> wire.AuthorizationDecision:
        stop = threading.Event()
        caller_cancelled = kwargs.get("cancelled")

        def cancelled() -> bool:
            if stop.is_set():
                return True
            if caller_cancelled is None:
                return False
            return bool(caller_cancelled())

        kwargs["cancelled"] = cancelled
        gate = _CommitGate()
        kwargs["_commit_gate"] = gate
        failure: BaseException | None = None
        try:
            return cast(
                wire.AuthorizationDecision,
                await self._run_linearized(
                    partial(
                        FakeTransport(self._engine, testing_only=True).decide,
                        request,
                        **kwargs,
                    ),
                    gate,
                    stop.set,
                ),
            )
        except asyncio.CancelledError as error:
            stop.set()
            failure = _clean_control(error)
        except BaseException as error:
            failure = _safe_failure(error)
        del request, kwargs, gate
        assert failure is not None
        raise failure from None

    async def request_approval(
        self, request: wire.ActionRequest, **kwargs: Any
    ) -> wire.ApprovalRecord:
        stop = threading.Event()
        caller_cancelled = kwargs.get("cancelled")

        def cancelled() -> bool:
            if stop.is_set():
                return True
            if caller_cancelled is None:
                return False
            return bool(caller_cancelled())

        kwargs["cancelled"] = cancelled
        gate = _CommitGate()
        kwargs["_commit_gate"] = gate
        failure: BaseException | None = None
        try:
            return cast(
                wire.ApprovalRecord,
                await self._run_linearized(
                    partial(
                        FakeTransport(self._engine, testing_only=True).request_approval,
                        request,
                        **kwargs,
                    ),
                    gate,
                    stop.set,
                ),
            )
        except asyncio.CancelledError as error:
            stop.set()
            failure = _clean_control(error)
        except BaseException as error:
            failure = _safe_failure(error)
        del request, kwargs, gate
        assert failure is not None
        raise failure from None

    async def get_approval(
        self, approval_id: str, **kwargs: Any
    ) -> wire.ApprovalRecord:
        stop = threading.Event()
        caller_cancelled = kwargs.get("cancelled")

        def cancelled() -> bool:
            if stop.is_set():
                return True
            if caller_cancelled is None:
                return False
            return bool(caller_cancelled())

        kwargs["cancelled"] = cancelled
        gate = _CommitGate()
        kwargs["_commit_gate"] = gate
        failure: BaseException | None = None
        try:
            return cast(
                wire.ApprovalRecord,
                await self._run_linearized(
                    partial(
                        FakeTransport(self._engine, testing_only=True).get_approval,
                        approval_id,
                        **kwargs,
                    ),
                    gate,
                    stop.set,
                ),
            )
        except asyncio.CancelledError as error:
            stop.set()
            failure = _clean_control(error)
        except BaseException as error:
            failure = _safe_failure(error)
        del approval_id, kwargs, gate
        assert failure is not None
        raise failure from None

    async def aclose(self) -> None:
        """Borrowed engine lifecycle is intentionally unchanged."""


__all__ = [
    "AsyncFakeTransport",
    "FakeTransport",
    "FrozenClock",
    "RecordedCall",
    "ScriptedEngine",
]
