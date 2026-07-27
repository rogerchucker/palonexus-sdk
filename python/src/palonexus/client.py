# SPDX-License-Identifier: MIT
"""Synchronous PaloNexus authorization client."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, Self

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


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    """Immutable, public view of a transport-validated decision."""

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
    approval_id: str | None = None
    approval_status: str | None = None
    approval_expires_at: str | None = None


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
) -> AuthorizationDecision:
    try:
        if type(value) is not _wire.AuthorizationDecision:
            raise TypeError
        value.validate_structural()
        approval = value.approval
        return AuthorizationDecision(
            request_id=str(value.request_id),
            decision_id=str(value.decision_id),
            correlation_id=str(value.correlation_id),
            outcome=DecisionOutcome(str(value.outcome)),
            reason_code=value.reason_code,
            client_scope_hash=str(value.client_scope_hash),
            authoritative_scope_hash=str(value.authoritative_scope_hash),
            policy_revision=value.policy_revision,
            server_time=str(value.server_time),
            expires_at=str(value.expires_at),
            audit_ref=str(value.audit_ref),
            approval_id=None if approval is None else str(approval.approval_id),
            approval_status=None if approval is None else str(approval.status),
            approval_expires_at=(
                None if approval is None else str(approval.expires_at)
            ),
        )
    except Exception:
        request_id, correlation_id = _safe_request_identifiers(request)
        raise InvalidDecision(
            request_id=request_id,
            correlation_id=correlation_id,
        ) from None


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
    Closing the client itself is always idempotent.
    """

    __slots__ = ("_closed", "_lock", "_owns_transport", "_transport")

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
        self._closed = False
        self._lock = threading.RLock()

    def _ensure_open(self, request: object | None = None) -> None:
        with self._lock:
            if not self._closed:
                return
        request_id, correlation_id = _safe_request_identifiers(request)
        raise AuthorizationUnavailable(
            request_id=request_id,
            correlation_id=correlation_id,
        ) from None

    def decide(
        self,
        attempt: _AuthorizationAttempt,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> AuthorizationDecision:
        """Obtain a decision without executing the proposed application work."""

        request, scope_hash = _attempt_parts(attempt)
        self._ensure_open(request)
        value = self._transport.decide(
            request,
            client_scope_hash=scope_hash,
            deadline=deadline,
            cancelled=cancelled,
        )
        return _public_decision(value, request=request)

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
        """Close this client and, when owned, its transport exactly once."""

        should_close = False
        with self._lock:
            if not self._closed:
                self._closed = True
                should_close = self._owns_transport
        if should_close:
            self._transport.close()

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
