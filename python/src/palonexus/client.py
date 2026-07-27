# SPDX-License-Identifier: MIT
"""Synchronous PaloNexus authorization client."""

from __future__ import annotations

import concurrent.futures
import math
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal, Never, Protocol, Self

from ._generated import protocol as _wire
from .approvals import (
    ApprovalRecord,
    ApprovalStatus,
    ApprovalTransport,
    _validate_transition,
)
from .approvals import (
    _parse_timestamp as _parse_approval_timestamp,
)
from .approvals import (
    _timestamp_order as _approval_timestamp_order,
)
from .errors import (
    ApprovalExpired,
    ApprovalRequired,
    ApprovalScopeMismatch,
    AuthorizationUnavailable,
    InvalidDecision,
    InvalidRequest,
    PolicyDenied,
)
from .models import DecisionOutcome
from .protocol import ActionRequestBuilder, _PreparedAction
from .transports import AuthorizationTransport

_MAX_CANCELLATION_LATENCY_SECONDS = 0.05


class _AuthorizationAttempt(Protocol):
    @property
    def request(self) -> _wire.ActionRequest: ...

    @property
    def client_scope_hash(self) -> str: ...


class AuthorizationDecision:
    """Immutable package-created view of a transport-validated decision.

    Applications can inspect and compare decisions, but cannot forge one and
    accidentally pass an untrusted allow through SDK integrations.
    """

    __slots__ = (
        "approval_expires_at",
        "approval_id",
        "approval_status",
        "audit_ref",
        "authoritative_scope_hash",
        "client_scope_hash",
        "correlation_id",
        "decision_id",
        "expires_at",
        "outcome",
        "policy_revision",
        "reason_code",
        "request_id",
        "server_time",
    )
    request_id: str
    decision_id: str
    correlation_id: str
    outcome: DecisionOutcome
    reason_code: str
    client_scope_hash: str
    authoritative_scope_hash: str
    policy_revision: str
    server_time: str
    expires_at: str
    audit_ref: str
    approval_id: str | None
    approval_status: str | None
    approval_expires_at: str | None

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("authorization decisions are created by the SDK")

    @classmethod
    def _from_protocol(cls, value: _wire.AuthorizationDecision) -> Self:
        value.validate_structural()
        approval = value.approval
        outcome = DecisionOutcome(str(value.outcome))
        if outcome in {DecisionOutcome.ALLOW, DecisionOutcome.DENY}:
            if approval is not None:
                raise ValueError
        elif (
            approval is None
            or str(approval.status) != "pending"
            or _approval_timestamp_order(
                _parse_approval_timestamp(str(approval.expires_at)),
                _parse_approval_timestamp(str(value.server_time)),
            )
            <= 0
        ):
            raise ValueError
        if (
            _approval_timestamp_order(
                _parse_approval_timestamp(str(value.expires_at)),
                _parse_approval_timestamp(str(value.server_time)),
            )
            <= 0
        ):
            raise ValueError

        instance = object.__new__(cls)
        fields: dict[str, object] = {
            "request_id": str(value.request_id),
            "decision_id": str(value.decision_id),
            "correlation_id": str(value.correlation_id),
            "outcome": outcome,
            "reason_code": value.reason_code,
            "client_scope_hash": str(value.client_scope_hash),
            "authoritative_scope_hash": str(value.authoritative_scope_hash),
            "policy_revision": value.policy_revision,
            "server_time": str(value.server_time),
            "expires_at": str(value.expires_at),
            "audit_ref": str(value.audit_ref),
            "approval_id": None if approval is None else str(approval.approval_id),
            "approval_status": None if approval is None else str(approval.status),
            "approval_expires_at": (
                None if approval is None else str(approval.expires_at)
            ),
        }
        for name, field_value in fields.items():
            object.__setattr__(instance, name, field_value)
        return instance

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("authorization decisions are immutable")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("authorization decisions are immutable")

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self

    def __reduce__(self) -> Never:
        raise TypeError("authorization decisions cannot be serialized")

    def __reduce_ex__(self, protocol: object) -> Never:
        del protocol
        raise TypeError("authorization decisions cannot be serialized")

    def __eq__(self, other: object) -> bool:
        if type(other) is not type(self):
            return False
        return all(
            getattr(self, name) == getattr(other, name) for name in self.__slots__
        )

    def __hash__(self) -> int:
        return hash(tuple(getattr(self, name) for name in self.__slots__))

    def __repr__(self) -> str:
        return (
            "AuthorizationDecision("
            f"outcome={self.outcome!r}, "
            f"request_id={self.request_id!r}, "
            f"decision_id={self.decision_id!r}, "
            f"correlation_id={self.correlation_id!r})"
        )


def _attempt_parts(
    attempt: object,
) -> tuple[_wire.ActionRequest, str]:
    try:
        request = getattr(attempt, "request")
        scope_hash = getattr(attempt, "client_scope_hash")
        if type(request) is not _wire.ActionRequest or type(scope_hash) is not str:
            raise TypeError
    except Exception:
        raise InvalidRequest() from None
    return request, scope_hash


def _safe_request_identifiers(
    request: object,
) -> tuple[object | None, object | None]:
    try:
        return getattr(request, "request_id"), getattr(request, "correlation_id")
    except Exception:
        return None, None


def _public_decision(
    value: object,
    *,
    request: object,
    client_scope_hash: str,
) -> AuthorizationDecision:
    failed = False
    decision: AuthorizationDecision | None = None
    try:
        if type(value) is not _wire.AuthorizationDecision:
            raise TypeError
        decision = AuthorizationDecision._from_protocol(value)
        if (
            decision.request_id != str(getattr(request, "request_id"))
            or decision.correlation_id != str(getattr(request, "correlation_id"))
            or decision.client_scope_hash != client_scope_hash
        ):
            raise ValueError
    except Exception:
        failed = True
    if failed or decision is None:
        request_id, correlation_id = _safe_request_identifiers(request)
        raise InvalidDecision(
            request_id=request_id,
            correlation_id=correlation_id,
        ) from None
    return decision


def _require_allow(decision: AuthorizationDecision) -> AuthorizationDecision:
    identifiers = {
        "request_id": decision.request_id,
        "decision_id": decision.decision_id,
        "correlation_id": decision.correlation_id,
    }
    if decision.outcome is DecisionOutcome.ALLOW:
        return decision
    if decision.outcome is DecisionOutcome.APPROVAL_REQUIRED:
        raise ApprovalRequired(**identifiers) from None
    raise PolicyDenied(**identifiers) from None


class AuthorizationClient:
    """Thin synchronous client over an injected authorization transport.

    Injected transports are borrowed by default. Set ``owns_transport=True``
    when transferring responsibility for closing the transport to the client.
    Close waits for active decisions. A transport-close failure is normalized
    to ``AuthorizationUnavailable`` and remembered for every concurrent or
    later closer; it is not retried because completion may be ambiguous.
    """

    __slots__ = (
        "_active",
        "_approval_transport",
        "_close_failure",
        "_closing_thread_id",
        "_condition",
        "_operation_local",
        "_owns_transport",
        "_owns_approval_transport",
        "_state",
        "_transport",
        "_trusted_clock",
    )

    def __init__(
        self,
        transport: AuthorizationTransport,
        *,
        approval_transport: ApprovalTransport | None = None,
        owns_transport: bool = False,
        owns_approval_transport: bool = False,
        trusted_clock: Callable[[], str] | None = None,
    ) -> None:
        if not isinstance(transport, AuthorizationTransport):
            raise InvalidRequest() from None
        if type(owns_transport) is not bool:
            raise InvalidRequest() from None
        if type(owns_approval_transport) is not bool:
            raise InvalidRequest() from None
        if approval_transport is not None and not isinstance(
            approval_transport, ApprovalTransport
        ):
            raise InvalidRequest() from None
        if owns_approval_transport and approval_transport is None:
            raise InvalidRequest() from None
        if trusted_clock is not None and not callable(trusted_clock):
            raise InvalidRequest() from None
        self._transport = transport
        self._approval_transport = approval_transport
        self._owns_transport = owns_transport
        self._owns_approval_transport = owns_approval_transport
        self._trusted_clock = trusted_clock or _utc_now
        self._state = "OPEN"
        self._active = 0
        self._close_failure: AuthorizationUnavailable | None = None
        self._closing_thread_id: int | None = None
        self._condition = threading.Condition(threading.RLock())
        self._operation_local = threading.local()

    @property
    def authorization_client_kind(self) -> Literal["sync"]:
        """Nominal marker used by public framework client protocols."""

        return "sync"

    def _ensure_open(self, request: object | None = None) -> None:
        with self._condition:
            if self._state == "OPEN":
                return
        request_id, correlation_id = _safe_request_identifiers(request)
        raise AuthorizationUnavailable(
            request_id=request_id,
            correlation_id=correlation_id,
        ) from None

    def _begin_operation(self, request: object) -> None:
        with self._condition:
            if self._state != "OPEN":
                request_id, correlation_id = _safe_request_identifiers(request)
                raise AuthorizationUnavailable(
                    request_id=request_id,
                    correlation_id=correlation_id,
                ) from None
            self._active += 1
            depth = getattr(self._operation_local, "depth", 0)
            self._operation_local.depth = depth + 1

    def _end_operation(self) -> None:
        with self._condition:
            self._active -= 1
            self._operation_local.depth -= 1
            if self._active == 0:
                self._condition.notify_all()

    def decide(
        self,
        attempt: _AuthorizationAttempt,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> AuthorizationDecision:
        """Obtain a decision without executing the proposed application work."""

        request, scope_hash = _attempt_parts(attempt)
        self._begin_operation(request)
        try:
            value = self._transport.decide(
                request,
                client_scope_hash=scope_hash,
                deadline=deadline,
                cancelled=cancelled,
            )
            return _public_decision(
                value,
                request=request,
                client_scope_hash=scope_hash,
            )
        finally:
            self._end_operation()

    def authorize(
        self,
        attempt: _AuthorizationAttempt,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> AuthorizationDecision:
        """Return only an allow; deny and approval outcomes raise typed errors."""

        return _require_allow(
            self.decide(
                attempt,
                deadline=deadline,
                cancelled=cancelled,
            )
        )

    def _approvals(self) -> ApprovalTransport:
        if self._approval_transport is None:
            raise AuthorizationUnavailable() from None
        return self._approval_transport

    def request_approval(
        self,
        attempt: _AuthorizationAttempt,
        decision: AuthorizationDecision,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ApprovalRecord:
        """Create or return the approval bound to one immutable attempt."""

        request, scope_hash = _attempt_parts(attempt)
        if (
            type(decision) is not AuthorizationDecision
            or decision.outcome is not DecisionOutcome.APPROVAL_REQUIRED
            or decision.approval_id is None
            or decision.request_id != str(request.request_id)
            or decision.correlation_id != str(request.correlation_id)
            or decision.client_scope_hash != scope_hash
        ):
            raise ApprovalScopeMismatch(
                request_id=request.request_id,
                decision_id=getattr(decision, "decision_id", None),
                correlation_id=request.correlation_id,
            ) from None
        self._begin_operation(request)
        try:
            value = self._approvals().request_approval(
                request,
                decision_id=decision.decision_id,
                authoritative_scope_hash=decision.authoritative_scope_hash,
                approval_id=decision.approval_id,
                deadline=deadline,
                cancelled=cancelled,
            )
            record = ApprovalRecord._from_protocol(value)
            _bind_approval(record, request=request, decision=decision)
            return record
        finally:
            self._end_operation()

    def get_approval(
        self,
        approval_id: str,
        *,
        expected: ApprovalRecord,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> ApprovalRecord:
        """Read one validated approval record."""

        try:
            checked_id = str(_wire.ApprovalID(approval_id))
        except (TypeError, ValueError):
            raise InvalidRequest() from None
        self._begin_operation(None)
        try:
            record = ApprovalRecord._from_protocol(
                self._approvals().get_approval(
                    checked_id,
                    deadline=deadline,
                    cancelled=cancelled,
                )
            )
            if record.approval_id != checked_id:
                raise InvalidDecision() from None
            _validate_transition(expected, record)
            return record
        finally:
            self._end_operation()

    def wait_for_approval(
        self,
        approval: ApprovalRecord,
        *,
        deadline: float,
        cancelled: Callable[[], bool] | None = None,
        poll_interval: float = 0.25,
    ) -> ApprovalRecord:
        """Poll until terminal, checking cancellation at least every 50 ms."""

        checked_deadline, checked_interval = _poll_parameters(deadline, poll_interval)
        if type(approval) is not ApprovalRecord:
            raise InvalidRequest() from None
        observed = approval
        while True:
            if cancelled is not None and cancelled():
                raise _cancelled()
            now = time.monotonic()
            if now >= checked_deadline:
                raise AuthorizationUnavailable() from None
            record = self.get_approval(
                approval.approval_id,
                expected=observed,
                deadline=checked_deadline,
                cancelled=cancelled,
            )
            if record.status is not ApprovalStatus.PENDING:
                return record
            observed = record
            remaining = checked_deadline - time.monotonic()
            if remaining <= 0:
                raise AuthorizationUnavailable() from None
            threading.Event().wait(
                min(
                    checked_interval,
                    remaining,
                    _MAX_CANCELLATION_LATENCY_SECONDS,
                )
            )

    def resume(
        self,
        builder: ActionRequestBuilder,
        original: _PreparedAction,
        current: _PreparedAction,
        prior_decision: AuthorizationDecision,
        approval: ApprovalRecord,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _PreparedAction:
        """Reauthorize a sealed resume candidate, then transfer execution."""

        _require_resumable(
            original,
            prior_decision,
            approval,
            trusted_now=_trusted_now(self._trusted_clock),
        )
        candidate: _PreparedAction | None = None
        committed = False
        try:
            candidate = builder._prepare_resume(  # noqa: SLF001
                original,
                current,
                prior_decision_id=prior_decision.decision_id,
                approval_id=approval.approval_id,
            )
            fresh_decision = self.authorize(
                candidate,
                deadline=deadline,
                cancelled=cancelled,
            )
            if (
                fresh_decision.authoritative_scope_hash
                != approval.authoritative_scope_hash
            ):
                raise ApprovalScopeMismatch(
                    request_id=fresh_decision.request_id,
                    decision_id=fresh_decision.decision_id,
                    correlation_id=fresh_decision.correlation_id,
                ) from None
            builder._commit_resume(original, current, candidate)  # noqa: SLF001
            committed = True
            return candidate
        finally:
            if candidate is not None and not committed:
                try:
                    candidate.close()
                except BaseException:
                    pass

    def resume_checkpoint(
        self,
        builder: ActionRequestBuilder,
        current: _PreparedAction,
        *,
        original_request: object,
        client_scope_hash: str,
        prior_decision: object,
        pending_approval: object,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _PreparedAction:
        """Resume a validated durable framework checkpoint.

        The checkpoint contains authorization protocol data only. The current
        executable target must be freshly projected and sealed by ``builder``.
        Approval status is always fetched from the trusted approval transport;
        checkpoint or human-provided status is never treated as authority.
        """

        original: _PreparedAction | None = None
        try:
            if not isinstance(prior_decision, dict) or not isinstance(
                pending_approval, dict
            ):
                raise TypeError
            original = builder._restore_original_for_resume(  # noqa: SLF001
                original_request,
                client_scope_hash=client_scope_hash,
            )
            decision = AuthorizationDecision._from_protocol(
                _wire.parse_decision(prior_decision)
            )
            expected = ApprovalRecord._from_protocol(
                _wire.parse_approval(pending_approval)
            )
        except Exception:
            if original is not None:
                original.close()
            raise ApprovalScopeMismatch() from None
        try:
            approval = self.get_approval(
                expected.approval_id,
                expected=expected,
                deadline=deadline,
                cancelled=cancelled,
            )
            return self.resume(
                builder,
                original,
                current,
                decision,
                approval,
                deadline=deadline,
                cancelled=cancelled,
            )
        finally:
            try:
                original.close()
            except BaseException:
                pass

    def close(self) -> None:
        """Wait for active calls, then close an owned transport exactly once."""

        if getattr(self._operation_local, "depth", 0):
            raise AuthorizationUnavailable() from None
        owner = False
        with self._condition:
            if self._state == "OPEN":
                self._state = "CLOSING"
                self._closing_thread_id = threading.get_ident()
                owner = True
            elif self._state == "CLOSING":
                if self._closing_thread_id == threading.get_ident():
                    return
                while self._state == "CLOSING":
                    self._condition.wait()
            if not owner:
                if self._close_failure is not None:
                    raise self._close_failure from None
                return
            while self._active:
                self._condition.wait()

        failure: AuthorizationUnavailable | None = None
        close_targets: list[Callable[[], None]] = []
        if self._owns_transport:
            close_targets.append(self._transport.close)
        approval_transport = self._approval_transport
        if (
            self._owns_approval_transport
            and approval_transport is not None
            and id(approval_transport) != id(self._transport)
        ):
            close_targets.append(approval_transport.close)
        elif (
            self._owns_approval_transport
            and approval_transport is not None
            and id(approval_transport) == id(self._transport)
            and not close_targets
        ):
            close_targets.append(approval_transport.close)
        for close_target in close_targets:
            try:
                close_target()
            except BaseException:
                failure = AuthorizationUnavailable()
        with self._condition:
            self._close_failure = failure
            self._closing_thread_id = None
            self._state = "CLOSED"
            self._condition.notify_all()
        if failure is not None:
            raise failure from None

    def __enter__(self) -> Self:
        self._ensure_open()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object | None,
    ) -> Literal[False]:
        self.close()
        return False


__all__ = ["AuthorizationClient", "AuthorizationDecision"]


def _bind_approval(
    record: ApprovalRecord,
    *,
    request: _wire.ActionRequest,
    decision: AuthorizationDecision,
) -> None:
    if (
        record.approval_id != decision.approval_id
        or record.action_id != str(request.action_id)
        or record.correlation_id != str(request.correlation_id)
        or record.authorization_decision_id != decision.decision_id
        or record.authoritative_scope_hash != decision.authoritative_scope_hash
        or record.creation_audit_ref != decision.audit_ref
        or record.expires_at != decision.approval_expires_at
    ):
        raise ApprovalScopeMismatch(
            request_id=request.request_id,
            decision_id=decision.decision_id,
            correlation_id=request.correlation_id,
        ) from None


def _poll_parameters(deadline: object, interval: object) -> tuple[float, float]:
    if (
        isinstance(deadline, bool)
        or not isinstance(deadline, (int, float))
        or not math.isfinite(deadline)
        or isinstance(interval, bool)
        or not isinstance(interval, (int, float))
        or not math.isfinite(interval)
        or interval <= 0
        or interval > 60
    ):
        raise InvalidRequest() from None
    return float(deadline), float(interval)


def _cancelled() -> BaseException:
    return concurrent.futures.CancelledError()


def _require_resumable(
    original: _PreparedAction,
    prior: AuthorizationDecision,
    approval: ApprovalRecord,
    *,
    trusted_now: str,
) -> None:
    try:
        request = getattr(original, "request")
        scope_hash = getattr(original, "client_scope_hash")
        if (
            type(prior) is not AuthorizationDecision
            or type(approval) is not ApprovalRecord
            or prior.outcome is not DecisionOutcome.APPROVAL_REQUIRED
            or prior.approval_id != approval.approval_id
            or prior.request_id != str(request.request_id)
            or prior.correlation_id != str(request.correlation_id)
            or prior.client_scope_hash != scope_hash
            or prior.authoritative_scope_hash != approval.authoritative_scope_hash
            or prior.decision_id != approval.authorization_decision_id
            or prior.audit_ref != approval.creation_audit_ref
            or prior.approval_expires_at != approval.expires_at
            or approval.action_id != str(request.action_id)
            or approval.correlation_id != str(request.correlation_id)
        ):
            raise ValueError
    except Exception:
        raise ApprovalScopeMismatch() from None
    identifiers = {
        "request_id": prior.request_id,
        "decision_id": prior.decision_id,
        "correlation_id": prior.correlation_id,
    }
    if approval.status is ApprovalStatus.APPROVED:
        try:
            now = _parse_approval_timestamp(trusted_now)
            decided = _parse_approval_timestamp(approval.decided_at)
            expires = _parse_approval_timestamp(approval.expires_at)
        except (TypeError, ValueError):
            raise InvalidDecision(
                request_id=prior.request_id,
                decision_id=prior.decision_id,
                correlation_id=prior.correlation_id,
            ) from None
        if _approval_timestamp_order(decided, now) > 0:
            raise InvalidDecision(**identifiers) from None
        if _approval_timestamp_order(now, expires) >= 0:
            raise ApprovalExpired(**identifiers) from None
        return
    if approval.status is ApprovalStatus.EXPIRED:
        raise ApprovalExpired(**identifiers) from None
    if approval.status is ApprovalStatus.PENDING:
        raise ApprovalRequired(**identifiers) from None
    raise PolicyDenied(**identifiers) from None


def _utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _trusted_now(clock: Callable[[], str]) -> str:
    try:
        value = clock()
        _parse_approval_timestamp(value)
        return value
    except (KeyboardInterrupt, SystemExit, concurrent.futures.CancelledError):
        raise
    except BaseException:
        raise InvalidDecision() from None
