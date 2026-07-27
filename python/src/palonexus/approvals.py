# SPDX-License-Identifier: MIT
"""Typed approval records and transport-neutral approval boundaries."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from typing import Never, Protocol, Self, runtime_checkable

from ._generated import protocol as _wire
from .errors import InvalidDecision


class ApprovalStatus(StrEnum):
    """Terminal and non-terminal approval lifecycle states."""

    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalRecord:
    """Immutable package-created view of a validated approval record."""

    __slots__ = (
        "action_id",
        "approval_id",
        "authorization_decision_id",
        "authoritative_scope_hash",
        "correlation_id",
        "creation_audit_ref",
        "decided_at",
        "expires_at",
        "requested_at",
        "requester_ref",
        "resolution_audit_ref",
        "resolution_decision_id",
        "resolution_idempotency_key",
        "resolution_reason_code",
        "reviewer_ref",
        "status",
    )

    action_id: str
    approval_id: str
    authorization_decision_id: str
    authoritative_scope_hash: str
    correlation_id: str
    creation_audit_ref: str
    decided_at: str | None
    expires_at: str
    requested_at: str
    requester_ref: str
    resolution_audit_ref: str | None
    resolution_decision_id: str | None
    resolution_idempotency_key: str | None
    resolution_reason_code: str | None
    reviewer_ref: str | None
    status: ApprovalStatus

    def __init__(self, *args: object, **kwargs: object) -> None:
        del args, kwargs
        raise TypeError("approval records are created by the SDK")

    @classmethod
    def _from_protocol(cls, value: _wire.ApprovalRecord) -> Self:
        try:
            if type(value) is not _wire.ApprovalRecord:
                raise TypeError
            value.validate_structural()
            instance = object.__new__(cls)
            fields: dict[str, object] = {
                "action_id": str(value.action_id),
                "approval_id": str(value.approval_id),
                "authorization_decision_id": str(value.authorization_decision_id),
                "authoritative_scope_hash": str(value.authoritative_scope_hash),
                "correlation_id": str(value.correlation_id),
                "creation_audit_ref": str(value.creation_audit_ref),
                "decided_at": (
                    None if value.decided_at is None else str(value.decided_at)
                ),
                "expires_at": str(value.expires_at),
                "requested_at": str(value.requested_at),
                "requester_ref": value.requester_ref,
                "resolution_audit_ref": (
                    None
                    if value.resolution_audit_ref is None
                    else str(value.resolution_audit_ref)
                ),
                "resolution_decision_id": (
                    None
                    if value.resolution_decision_id is None
                    else str(value.resolution_decision_id)
                ),
                "resolution_idempotency_key": (
                    None
                    if value.resolution_idempotency_key is None
                    else str(value.resolution_idempotency_key)
                ),
                "resolution_reason_code": value.resolution_reason_code,
                "reviewer_ref": value.reviewer_ref,
                "status": ApprovalStatus(str(value.status)),
            }
            for name, field_value in fields.items():
                object.__setattr__(instance, name, field_value)
            return instance
        except Exception:
            raise InvalidDecision() from None

    def __setattr__(self, name: str, value: object) -> None:
        del name, value
        raise AttributeError("approval records are immutable")

    def __delattr__(self, name: str) -> None:
        del name
        raise AttributeError("approval records are immutable")

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        del memo
        return self

    def __reduce__(self) -> Never:
        raise TypeError("approval records cannot be serialized")

    def __reduce_ex__(self, protocol: object) -> Never:
        del protocol
        raise TypeError("approval records cannot be serialized")

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
            "ApprovalRecord("
            f"approval_id={self.approval_id!r}, "
            f"action_id={self.action_id!r}, "
            f"correlation_id={self.correlation_id!r}, "
            f"status={self.status!r})"
        )


@runtime_checkable
class ApprovalTransport(Protocol):
    """Synchronous transport for approval creation and observation."""

    def request_approval(
        self,
        request: _wire.ActionRequest,
        *,
        decision_id: str,
        authoritative_scope_hash: str,
        approval_id: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _wire.ApprovalRecord: ...

    def get_approval(
        self,
        approval_id: str,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _wire.ApprovalRecord: ...


@runtime_checkable
class AsyncApprovalTransport(Protocol):
    """Asynchronous transport equivalent of :class:`ApprovalTransport`."""

    async def request_approval(
        self,
        request: _wire.ActionRequest,
        *,
        decision_id: str,
        authoritative_scope_hash: str,
        approval_id: str,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _wire.ApprovalRecord: ...

    async def get_approval(
        self,
        approval_id: str,
        *,
        deadline: float | None = None,
        cancelled: Callable[[], bool] | None = None,
    ) -> _wire.ApprovalRecord: ...


__all__ = [
    "ApprovalRecord",
    "ApprovalStatus",
    "ApprovalTransport",
    "AsyncApprovalTransport",
]
