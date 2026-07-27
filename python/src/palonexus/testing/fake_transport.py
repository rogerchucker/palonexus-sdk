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
from types import MappingProxyType
from typing import Any, Final, Literal, Never, cast

from .. import _canonicalize
from .._generated import protocol as wire
from ..errors import AuthorizationUnavailable, IdempotencyConflict, InvalidRequest

_MAX_DELAY: Final[float] = 60.0
_POLL: Final[float] = 0.01


def _invalid() -> Never:
    raise InvalidRequest() from None


class FrozenClock:
    """Thread-safe, caller-controlled RFC3339 clock for deterministic tests."""

    __slots__ = ("_lock", "_now")

    def __init__(self, now: str) -> None:
        try:
            parsed = datetime.fromisoformat(now.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                raise ValueError
        except Exception:
            _invalid()
        self._now = parsed.astimezone(UTC)
        self._lock = threading.Lock()

    def __call__(self) -> datetime:
        with self._lock:
            return self._now

    def advance(self, seconds: float) -> None:
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not math.isfinite(seconds)
            or seconds < 0
        ):
            _invalid()
        with self._lock:
            self._now += timedelta(seconds=seconds)


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


class ScriptedEngine:
    """Exact-outcome engine with no policy or condition evaluation.

    Every outcome must be queued by test code. Exhaustion, storage pressure,
    malformed inputs, cancellation, and deadlines fail closed.
    """

    __slots__ = (
        "_approvals",
        "_calls",
        "_clock",
        "_closed",
        "_id_source",
        "_idempotency",
        "_idempotency_capacity",
        "_idempotency_ttl",
        "_lock",
        "_outcomes",
        "_sequence",
    )

    def __init__(
        self,
        *outcomes: _Outcome,
        testing_only: Literal[True],
        clock: Callable[[], datetime] | None = None,
        id_source: Callable[[], str] | None = None,
        idempotency_capacity: int = 256,
        idempotency_ttl: float = 300.0,
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
        self._id_source = id_source
        self._idempotency_capacity = idempotency_capacity
        self._idempotency_ttl = idempotency_ttl
        self._outcomes = deque(outcomes)
        self._idempotency: dict[str, _IdempotencyEntry] = {}
        self._approvals: dict[str, wire.ApprovalRecord] = {}
        self._calls: list[RecordedCall] = []
        self._lock = threading.RLock()
        self._sequence = 0
        self._closed = False

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
        return _Outcome("error", value=error)

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

    @property
    def recorded_calls(self) -> tuple[RecordedCall, ...]:
        with self._lock:
            return tuple(self._calls)

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            _invalid()
        return value.astimezone(UTC)

    def _new_id(self, prefix: str) -> str:
        self._sequence += 1
        if self._id_source is not None:
            supplied = self._id_source()
            if type(supplied) is not str:
                _invalid()
            suffix = supplied.split("_", 1)[-1]
        else:
            suffix = f"01J5ABCDEFGHJKMNPQRST{self._sequence:06X}"[-26:]
        value = f"{prefix}_{suffix}"
        validators: dict[str, Callable[[str], str]] = {
            "dec": wire.DecisionID,
            "audit": wire.AuditRef,
            "apr": wire.ApprovalID,
            "approval": wire.ApprovalResolutionIdempotencyKey,
        }
        try:
            return str(validators[prefix](value))
        except (KeyError, TypeError, ValueError):
            _invalid()

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

    def _record(
        self, request: wire.ActionRequest, client_scope_hash: str, request_hash: str
    ) -> None:
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
        self._calls.append(
            RecordedCall(
                operation="decide",
                request=cast(Mapping[str, Any], _frozen(document)),
                canonical_request_hash=request_hash,
                client_scope_hash=client_scope_hash,
            )
        )

    @staticmethod
    def _check_control(
        *, deadline: float | None, cancelled: Callable[[], bool] | None
    ) -> None:
        if cancelled is not None:
            try:
                if cancelled():
                    raise concurrent.futures.CancelledError
            except concurrent.futures.CancelledError:
                raise
            except Exception:
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
            raise outcome.value
        if outcome.kind == "outage":
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
            now = self._now()
            self._purge_expired(now)
            prior = self._idempotency.get(key)
            self._record(request, client_scope_hash, request_hash)
            if prior is not None:
                if prior.request_hash != request_hash:
                    raise IdempotencyConflict(
                        request_id=request.request_id,
                        correlation_id=request.correlation_id,
                    ) from None
                return prior.result
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
            outcome = self._outcomes.popleft()
            # Serialize scripted consumption and insertion so concurrent reuse of
            # one idempotency key cannot consume two outcomes.
            while outcome.kind == "delay":
                self._sleep(
                    outcome.delay_seconds, deadline=deadline, cancelled=cancelled
                )
                assert outcome.nested is not None
                outcome = outcome.nested
            result = self._decision(outcome, request, client_scope_hash, now)
            self._idempotency[key] = _IdempotencyEntry(
                request_hash=request_hash,
                result=result,
                expires_at=now + timedelta(seconds=self._idempotency_ttl),
            )
            return result

    def request_approval(
        self,
        request: wire.ActionRequest,
        *,
        decision_id: str,
        authoritative_scope_hash: str,
        approval_id: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> wire.ApprovalRecord:
        self._check_control(deadline=deadline, cancelled=cancelled)
        with self._lock:
            self._check_control(deadline=deadline, cancelled=cancelled)
            request_hash = self._hash(request)
            self._record(
                request,
                authoritative_scope_hash,
                request_hash,
            )
            self._calls[-1] = RecordedCall(
                operation="request_approval",
                request=self._calls[-1].request,
                canonical_request_hash=request_hash,
                client_scope_hash=authoritative_scope_hash,
            )
            existing = self._approvals.get(approval_id)
            if existing is not None:
                return existing
            if len(self._approvals) >= self._idempotency_capacity:
                raise AuthorizationUnavailable(
                    request_id=request.request_id,
                    correlation_id=request.correlation_id,
                ) from None
            now = self._now()
            document: dict[str, wire.JSONValue] = {
                "schemaVersion": "1",
                "approvalId": approval_id,
                "actionId": str(request.action_id),
                "correlationId": str(request.correlation_id),
                "authoritativeScopeHash": authoritative_scope_hash,
                "status": "pending",
                "requestedAt": _timestamp(now),
                "expiresAt": _timestamp(now + timedelta(minutes=15)),
                "requesterRef": "subject:testing-requester",
                "authorizationDecisionId": decision_id,
                "creationAuditRef": self._new_id("audit"),
            }
            record = wire.parse_approval(document)
            self._approvals[approval_id] = record
            return record

    def get_approval(
        self,
        approval_id: str,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> wire.ApprovalRecord:
        self._check_control(deadline=deadline, cancelled=cancelled)
        with self._lock:
            self._check_control(deadline=deadline, cancelled=cancelled)
            approval_hash = (
                "sha256:" + hashlib.sha256(approval_id.encode("utf-8")).hexdigest()
            )
            self._calls.append(
                RecordedCall(
                    operation="get_approval",
                    request=MappingProxyType({"approvalId": approval_id}),
                    canonical_request_hash=approval_hash,
                    client_scope_hash="",
                )
            )
            try:
                record = self._approvals[approval_id]
            except KeyError:
                raise AuthorizationUnavailable() from None
            expiry = datetime.fromisoformat(
                str(record.expires_at).replace("Z", "+00:00")
            )
            if str(record.status) == "pending" and self._now() >= expiry:
                record = self._resolve(
                    record,
                    status="expired",
                    reviewer_ref=None,
                    resolution_idempotency_key=self._new_id("approval"),
                )
                self._approvals[approval_id] = record
            return record

    def _resolve(
        self,
        record: wire.ApprovalRecord,
        *,
        status: str,
        reviewer_ref: str | None,
        resolution_idempotency_key: str,
    ) -> wire.ApprovalRecord:
        document = record.to_dict()
        now = self._now()
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

    def resolve_approval(
        self,
        approval_id: str,
        *,
        status: Literal["approved", "denied", "expired", "cancelled"],
        reviewer_ref: str | None,
        resolution_idempotency_key: str,
    ) -> wire.ApprovalRecord:
        with self._lock:
            record = self._approvals.get(approval_id)
            if record is None or str(record.status) != "pending":
                raise ValueError("approval is absent or terminal")
            if status in {"approved", "denied"} and reviewer_ref is None:
                raise ValueError("reviewer_ref is required")
            resolved = self._resolve(
                record,
                status=status,
                reviewer_ref=reviewer_ref,
                resolution_idempotency_key=resolution_idempotency_key,
            )
            self._approvals[approval_id] = resolved
            return resolved

    def close(self) -> None:
        with self._lock:
            self._closed = True


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
        return self._engine.decide(request, **kwargs)

    def request_approval(
        self, request: wire.ActionRequest, **kwargs: Any
    ) -> wire.ApprovalRecord:
        return self._engine.request_approval(request, **kwargs)

    def get_approval(self, approval_id: str, **kwargs: Any) -> wire.ApprovalRecord:
        return self._engine.get_approval(approval_id, **kwargs)

    def close(self) -> None:
        """Borrowed engine lifecycle is intentionally unchanged."""


class AsyncFakeTransport:
    """Async testing transport with cancellation-safe worker cleanup."""

    __slots__ = ("_engine",)

    def __init__(self, engine: ScriptedEngine, *, testing_only: Literal[True]) -> None:
        if testing_only is not True or type(engine) is not ScriptedEngine:
            raise ValueError("testing_only=True and a ScriptedEngine are required")
        self._engine = engine

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
        worker = asyncio.create_task(
            asyncio.to_thread(self._engine.decide, request, **kwargs)
        )
        try:
            return await asyncio.shield(worker)
        except asyncio.CancelledError:
            stop.set()
            try:
                await worker
            except BaseException:
                pass
            raise

    async def request_approval(
        self, request: wire.ActionRequest, **kwargs: Any
    ) -> wire.ApprovalRecord:
        return await asyncio.to_thread(self._engine.request_approval, request, **kwargs)

    async def get_approval(
        self, approval_id: str, **kwargs: Any
    ) -> wire.ApprovalRecord:
        return await asyncio.to_thread(self._engine.get_approval, approval_id, **kwargs)

    async def aclose(self) -> None:
        """Borrowed engine lifecycle is intentionally unchanged."""


__all__ = [
    "AsyncFakeTransport",
    "FakeTransport",
    "FrozenClock",
    "RecordedCall",
    "ScriptedEngine",
]
