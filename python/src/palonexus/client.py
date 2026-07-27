# SPDX-License-Identifier: MIT
"""Synchronous PaloNexus authorization client."""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime
from typing import Literal, Never, Protocol, Self

from ._generated import protocol as _wire
from .errors import (
    ApprovalRequired,
    AuthorizationUnavailable,
    InvalidDecision,
    InvalidRequest,
    PolicyDenied,
)
from .models import DecisionOutcome
from .transports import AuthorizationTransport


class _AuthorizationAttempt(Protocol):
    request: _wire.ActionRequest
    client_scope_hash: str


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
            or _parse_timestamp(approval.expires_at)
            <= _parse_timestamp(value.server_time)
        ):
            raise ValueError
        if _parse_timestamp(value.expires_at) <= _parse_timestamp(value.server_time):
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


def _parse_timestamp(value: object) -> datetime:
    rendered = str(value)
    if rendered.endswith("Z"):
        rendered = f"{rendered[:-1]}+00:00"
    return datetime.fromisoformat(rendered)


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
        "_close_failure",
        "_closing_thread_id",
        "_condition",
        "_operation_local",
        "_owns_transport",
        "_state",
        "_transport",
    )

    def __init__(
        self,
        transport: AuthorizationTransport,
        *,
        owns_transport: bool = False,
    ) -> None:
        if not isinstance(transport, AuthorizationTransport):
            raise InvalidRequest() from None
        if type(owns_transport) is not bool:
            raise InvalidRequest() from None
        self._transport = transport
        self._owns_transport = owns_transport
        self._state = "OPEN"
        self._active = 0
        self._close_failure: AuthorizationUnavailable | None = None
        self._closing_thread_id: int | None = None
        self._condition = threading.Condition(threading.RLock())
        self._operation_local = threading.local()

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
        if self._owns_transport:
            try:
                self._transport.close()
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
