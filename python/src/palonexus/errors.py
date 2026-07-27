# SPDX-License-Identifier: MIT
"""Safe, typed PaloNexus SDK exceptions.

SDK factories discard lower-layer exceptions and raise their safe replacement
outside the active handler with ``from None``. Their rendered tracebacks
therefore contain only canonical messages and validated identifiers. Python
still permits application code to attach an arbitrary cause explicitly; that
caller-controlled behavior is outside the SDK invariant.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from types import MappingProxyType
from typing import ClassVar, Final, Self

from ._generated import protocol as _protocol


def _safe_identifier(
    value: object | None,
    validator: Callable[[str], str],
) -> str | None:
    """Return only an identifier proven safe by its generated schema type."""

    if not isinstance(value, str):
        return None
    try:
        return str(validator(value))
    except (TypeError, ValueError):
        return None


class PaloNexusError(Exception):
    """Base class whose rendered forms contain only canonical safe fields."""

    error_code: ClassVar[str] = "invalid_request"
    canonical_message: ClassVar[str] = "The request is invalid."
    default_retryable: ClassVar[bool] = False

    code: str
    message: str
    request_id: str | None
    decision_id: str | None
    correlation_id: str | None
    retryable: bool

    def __init__(
        self,
        *,
        request_id: object | None = None,
        decision_id: object | None = None,
        correlation_id: object | None = None,
    ) -> None:
        Exception.__init__(self, self.error_code, self.canonical_message)
        self.code = self.error_code
        self.message = self.canonical_message
        self.request_id = _safe_identifier(request_id, _protocol.RequestID)
        self.decision_id = _safe_identifier(decision_id, _protocol.DecisionID)
        self.correlation_id = _safe_identifier(correlation_id, _protocol.CorrelationID)
        self.retryable = self.default_retryable

    def __setattr__(self, name: str, value: object) -> None:
        contract_fields = {
            "code",
            "message",
            "request_id",
            "decision_id",
            "correlation_id",
            "retryable",
        }
        runtime_fields = {
            "__traceback__",
            "__cause__",
            "__context__",
            "__suppress_context__",
        }
        if name in contract_fields:
            if hasattr(self, name):
                raise AttributeError(f"{name} is immutable")
        elif hasattr(self, "code") and name not in runtime_fields:
            raise AttributeError("PaloNexus errors do not accept arbitrary state")
        Exception.__setattr__(self, name, value)

    @staticmethod
    def from_protocol(value: _protocol.ProtocolError) -> PaloNexusError:
        """Map a structural protocol error without retaining its raw message."""

        failed = False
        try:
            value.validate_structural()
            code = _protocol.ProtocolErrorCode(str(value.code))
            error_type = _ERROR_TYPES[code]
        except (AttributeError, KeyError, TypeError, ValueError):
            failed = True
        if failed:
            raise ModelValidationError() from None
        return error_type(
            request_id=value.request_id,
            decision_id=value.decision_id,
            correlation_id=value.correlation_id,
        )

    def __copy__(self) -> Self:
        return self

    def __deepcopy__(self, memo: dict[int, object] | None = None) -> Self:
        return self

    def __reduce__(
        self,
    ) -> tuple[
        Callable[..., PaloNexusError],
        tuple[type[PaloNexusError], str | None, str | None, str | None],
    ]:
        return (
            _restore_error,
            (
                type(self),
                self.request_id,
                self.decision_id,
                self.correlation_id,
            ),
        )

    def __str__(self) -> str:
        identifiers = (
            ("request_id", self.request_id),
            ("decision_id", self.decision_id),
            ("correlation_id", self.correlation_id),
        )
        present = ", ".join(
            f"{name}={value}" for name, value in identifiers if value is not None
        )
        suffix = f" ({present})" if present else ""
        return f"{self.code}: {self.message}{suffix}"

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}("
            f"code={self.code!r}, "
            f"message={self.message!r}, "
            f"request_id={self.request_id!r}, "
            f"decision_id={self.decision_id!r}, "
            f"correlation_id={self.correlation_id!r}, "
            f"retryable={self.retryable!r})"
        )


class InvalidRequest(PaloNexusError):
    """The request does not satisfy the supported protocol contract."""


class ModelValidationError(InvalidRequest):
    """Public model input failed closed without retaining the rejected value."""


class MissingIdentity(PaloNexusError):
    """No verified caller identity was available."""

    error_code = "missing_identity"
    canonical_message = "Identity is required."


class UnsupportedProtocol(PaloNexusError):
    """The peer does not support the requested protocol version."""

    error_code = "unsupported_protocol"
    canonical_message = "The protocol version is unsupported."


class AuthenticationFailed(PaloNexusError):
    """The supplied identity could not be authenticated."""

    error_code = "authentication_failed"
    canonical_message = "Authentication failed."


class AuthorizationUnavailable(PaloNexusError):
    """The authorization service could not return a trustworthy decision."""

    error_code = "authorization_unavailable"
    canonical_message = "Authorization is temporarily unavailable."
    default_retryable = True


class InvalidDecision(PaloNexusError):
    """A response could not be validated as an authorization decision."""

    error_code = "invalid_decision"
    canonical_message = "The authorization decision is invalid."


class IdempotencyConflict(PaloNexusError):
    """An idempotency key was reused for different canonical content."""

    error_code = "idempotency_conflict"
    canonical_message = "The idempotency key conflicts with an earlier request."


class ApprovalExpired(PaloNexusError):
    """The referenced approval is no longer valid."""

    error_code = "approval_expired"
    canonical_message = "The approval has expired."


class ApprovalScopeMismatch(PaloNexusError):
    """The approved scope does not match the current action scope."""

    error_code = "approval_scope_mismatch"
    canonical_message = "The action no longer matches the approved scope."


class CredentialRevoked(PaloNexusError):
    """A credential required for authorization has been revoked."""

    error_code = "credential_revoked"
    canonical_message = "The credential has been revoked."


class PolicyDenied(PaloNexusError):
    """Current policy denied the proposed action."""

    error_code = "policy_denied"
    canonical_message = "Current policy denies this action."


class ApprovalRequired(PaloNexusError):
    """The proposed action requires a fresh human approval."""

    error_code = "approval_required"
    canonical_message = "Approval is required before this action can proceed."


def _restore_error(
    error_type: type[PaloNexusError],
    request_id: str | None,
    decision_id: str | None,
    correlation_id: str | None,
) -> PaloNexusError:
    return error_type(
        request_id=request_id,
        decision_id=decision_id,
        correlation_id=correlation_id,
    )


_ERROR_TYPES: Final[
    Mapping[
        _protocol.ProtocolErrorCode,
        type[PaloNexusError],
    ]
] = MappingProxyType(
    {
        _protocol.ProtocolErrorCode.INVALID_REQUEST: InvalidRequest,
        _protocol.ProtocolErrorCode.MISSING_IDENTITY: MissingIdentity,
        _protocol.ProtocolErrorCode.UNSUPPORTED_PROTOCOL: UnsupportedProtocol,
        _protocol.ProtocolErrorCode.AUTHENTICATION_FAILED: AuthenticationFailed,
        _protocol.ProtocolErrorCode.AUTHORIZATION_UNAVAILABLE: (
            AuthorizationUnavailable
        ),
        _protocol.ProtocolErrorCode.INVALID_DECISION: InvalidDecision,
        _protocol.ProtocolErrorCode.IDEMPOTENCY_CONFLICT: IdempotencyConflict,
        _protocol.ProtocolErrorCode.APPROVAL_EXPIRED: ApprovalExpired,
        _protocol.ProtocolErrorCode.APPROVAL_SCOPE_MISMATCH: ApprovalScopeMismatch,
        _protocol.ProtocolErrorCode.CREDENTIAL_REVOKED: CredentialRevoked,
        _protocol.ProtocolErrorCode.POLICY_DENIED: PolicyDenied,
    }
)

__all__ = [
    "ApprovalExpired",
    "ApprovalRequired",
    "ApprovalScopeMismatch",
    "AuthenticationFailed",
    "AuthorizationUnavailable",
    "CredentialRevoked",
    "IdempotencyConflict",
    "InvalidDecision",
    "InvalidRequest",
    "MissingIdentity",
    "ModelValidationError",
    "PaloNexusError",
    "PolicyDenied",
    "UnsupportedProtocol",
]
