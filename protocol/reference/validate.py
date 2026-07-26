"""Minimal reference validation for draft PaloNexus protocol version 1."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections.abc import Mapping
from copy import deepcopy
from datetime import datetime
from functools import lru_cache
from itertools import zip_longest
from pathlib import Path
from types import MappingProxyType
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

PROTOCOL_ROOT = Path(__file__).parents[1]
SCHEMA_ROOT = PROTOCOL_ROOT / "schemas"
_RFC3339 = re.compile(
    r"^([0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2})"
    r"(\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})\Z"
)
_EXTENSION_NUMBER_LIMIT = 1e308
_UNIX_EPOCH_ORDINAL = datetime(1970, 1, 1).toordinal()
ERROR_SAFE_MESSAGES: Mapping[str, str] = MappingProxyType(
    {
        "invalid_request": "The request is invalid.",
        "missing_identity": "Identity is required.",
        "unsupported_protocol": "The protocol version is unsupported.",
        "authentication_failed": "Authentication failed.",
        "authorization_unavailable": "Authorization is temporarily unavailable.",
        "invalid_decision": "The authorization decision is invalid.",
        "idempotency_conflict": (
            "The idempotency key conflicts with an earlier request."
        ),
        "approval_expired": "The approval has expired.",
        "approval_scope_mismatch": ("The action no longer matches the approved scope."),
        "credential_revoked": "The credential has been revoked.",
        "policy_denied": "Current policy denies this action.",
    }
)


class ProtocolValidationError(ValueError):
    """Safe failure containing a stable code and no raw protocol value."""

    def __init__(self, code: str, detail: str = "") -> None:
        self.code = code
        super().__init__(code if not detail else f"{code}: {detail}")


def loads_json_strict(document: str) -> Any:
    """Parse standards-compliant JSON with unique object keys."""

    def reject_constant(_value: str) -> None:
        raise ProtocolValidationError("invalid_json_number")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ProtocolValidationError("duplicate_json_key")
            result[key] = value
        return result

    try:
        return json.loads(
            document,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except ProtocolValidationError:
        raise
    except (json.JSONDecodeError, RecursionError, UnicodeError) as exc:
        raise ProtocolValidationError("invalid_json") from exc


def _read_document(path: Path) -> dict[str, Any]:
    try:
        value = loads_json_strict(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ProtocolValidationError("input_unavailable") from exc
    if not isinstance(value, dict):
        raise ProtocolValidationError("schema_invalid")
    return value


@lru_cache(maxsize=4)
def _validator(kind: str) -> Draft202012Validator:
    common = _read_document(SCHEMA_ROOT / "common-v1.schema.json")
    schema = _read_document(SCHEMA_ROOT / f"{kind}-v1.schema.json")
    registry = Registry().with_resource(
        common["$id"],
        Resource.from_contents(common),
    )
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, registry=registry)


def _validate_structure(kind: str, document: dict[str, Any]) -> None:
    try:
        errors = sorted(
            _validator(kind).iter_errors(document),
            key=lambda error: tuple(str(part) for part in error.absolute_path),
        )
    except RecursionError as exc:
        raise ProtocolValidationError("schema_nesting_exceeded") from exc
    if errors:
        path = ".".join(str(part) for part in errors[0].absolute_path) or "$"
        raise ProtocolValidationError("schema_invalid", f"{kind}.{path}")


def _parse_rfc3339(value: Any) -> tuple[int, str]:
    if not isinstance(value, str):
        raise ProtocolValidationError("timestamp_invalid")
    match = _RFC3339.fullmatch(value)
    if match is None:
        raise ProtocolValidationError("timestamp_invalid")
    base, _fraction_with_dot, fraction, zone = match.groups()
    try:
        parsed = datetime.fromisoformat(base)
    except ValueError as exc:
        raise ProtocolValidationError("timestamp_invalid") from exc
    offset_seconds = 0
    if zone != "Z":
        offset_hour = int(zone[1:3])
        offset_minute = int(zone[4:6])
        if offset_hour > 23 or offset_minute > 59:
            raise ProtocolValidationError("timestamp_invalid")
        offset_seconds = (offset_hour * 60 + offset_minute) * 60
        if zone[0] == "-":
            offset_seconds = -offset_seconds
    local_seconds = (
        (parsed.toordinal() - _UNIX_EPOCH_ORDINAL) * 86_400
        + parsed.hour * 3_600
        + parsed.minute * 60
        + parsed.second
    )
    return local_seconds - offset_seconds, fraction or ""


def _timestamp_order(left: tuple[int, str], right: tuple[int, str]) -> int:
    if left[0] != right[0]:
        return -1 if left[0] < right[0] else 1
    for left_digit, right_digit in zip_longest(
        left[1],
        right[1],
        fillvalue="0",
    ):
        if left_digit != right_digit:
            return -1 if left_digit < right_digit else 1
    return 0


def _validate_extension_numbers(document: dict[str, Any]) -> None:
    containers: list[Any] = [document]
    extension_values: list[Any] = []
    while containers:
        value = containers.pop()
        if isinstance(value, dict):
            for key, child in value.items():
                if key == "extensions":
                    extension_values.append(child)
                elif isinstance(child, (dict, list)):
                    containers.append(child)
        elif isinstance(value, list):
            containers.extend(value)

    while extension_values:
        value = extension_values.pop()
        if isinstance(value, dict):
            extension_values.extend(value.values())
        elif isinstance(value, list):
            extension_values.extend(value)
        elif isinstance(value, float) and not math.isfinite(value):
            raise ProtocolValidationError("extension_number_invalid")
        elif (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and (value < -_EXTENSION_NUMBER_LIMIT or value > _EXTENSION_NUMBER_LIMIT)
        ):
            raise ProtocolValidationError("extension_number_invalid")


def validate_action_document(document: dict[str, Any]) -> None:
    """Validate the Task 5 structural action contract."""

    if not isinstance(document, dict):
        raise ProtocolValidationError("schema_invalid")
    _validate_structure("action", document)
    _parse_rfc3339(document["occurredAt"])
    _validate_extension_numbers(document)


def validate_decision_document(document: dict[str, Any]) -> None:
    """Validate decision structure and the Task 5 expiry-order invariant."""

    if not isinstance(document, dict):
        raise ProtocolValidationError("schema_invalid")
    _validate_structure("decision", document)
    server_time = _parse_rfc3339(document["serverTime"])
    expires_at = _parse_rfc3339(document["expiresAt"])
    if "approval" in document:
        _parse_rfc3339(document["approval"]["expiresAt"])
    if _timestamp_order(expires_at, server_time) <= 0:
        raise ProtocolValidationError("decision_expiry_order")
    _validate_extension_numbers(document)


def _validate_approval_structure_and_timestamps(
    document: dict[str, Any],
) -> tuple[tuple[int, str], tuple[int, str], tuple[int, str] | None]:
    if not isinstance(document, dict):
        raise ProtocolValidationError("schema_invalid")
    _validate_structure("approval", document)
    requested_at = _parse_rfc3339(document["requestedAt"])
    expires_at = _parse_rfc3339(document["expiresAt"])
    decided_at = (
        _parse_rfc3339(document["decidedAt"])
        if document["status"] != "pending"
        else None
    )
    _validate_extension_numbers(document)
    return requested_at, expires_at, decided_at


def validate_approval_document(document: dict[str, Any]) -> None:
    """Validate one approval record, including its timestamp invariants."""

    requested_at, expires_at, decided_at = _validate_approval_structure_and_timestamps(
        document
    )
    if _timestamp_order(expires_at, requested_at) <= 0:
        raise ProtocolValidationError("approval_expiry_order")

    status = document["status"]
    if decided_at is not None:
        if status == "expired":
            if _timestamp_order(decided_at, expires_at) < 0:
                raise ProtocolValidationError("approval_expiry_order")
        elif (
            _timestamp_order(decided_at, requested_at) < 0
            or _timestamp_order(decided_at, expires_at) >= 0
        ):
            raise ProtocolValidationError("approval_expired")


def validate_error_document(document: dict[str, Any]) -> None:
    """Validate a closed-code error with its canonical public message."""

    if not isinstance(document, dict):
        raise ProtocolValidationError("schema_invalid")
    _validate_structure("error", document)
    if document["safeMessage"] != ERROR_SAFE_MESSAGES[document["code"]]:
        raise ProtocolValidationError("schema_invalid", "error.safeMessage")
    _validate_extension_numbers(document)


_APPROVAL_IMMUTABLE_FIELDS = (
    "schemaVersion",
    "approvalId",
    "actionId",
    "correlationId",
    "authoritativeScopeHash",
    "requestedAt",
    "expiresAt",
    "requesterRef",
    "authorizationDecisionId",
    "creationAuditRef",
)
_APPROVAL_TERMINAL_IDENTITY_FIELDS = (
    "status",
    "resolutionDecisionId",
    "resolutionReasonCode",
    "resolutionIdempotencyKey",
)
_APPROVAL_CREATION_IDENTITY_FIELDS = (
    "schemaVersion",
    "authorizationDecisionId",
    "actionId",
    "correlationId",
    "authoritativeScopeHash",
    "requesterRef",
)


def approval_state_digest(document: dict[str, Any]) -> str:
    """Return the canonical CAS revision for a validated approval record."""

    from protocol.reference import canonicalize

    validate_approval_document(document)
    return canonicalize.canonical_hash(document)


def resolve_duplicate_approval_creation(
    existing: dict[str, Any],
    proposed: dict[str, Any],
) -> dict[str, Any]:
    """Return the existing pending record for the same creation identity.

    The authorization decision, not a requestId or a newly generated
    approvalId, is the idempotency anchor.
    """

    validate_approval_document(existing)
    validate_approval_document(proposed)
    if existing["status"] != "pending" or proposed["status"] != "pending":
        raise ProtocolValidationError("idempotency_conflict")
    same_creation = all(
        existing[field] == proposed[field]
        for field in _APPROVAL_CREATION_IDENTITY_FIELDS
    ) and existing.get("extensions") == proposed.get("extensions")
    if not same_creation:
        raise ProtocolValidationError("idempotency_conflict")
    return deepcopy(existing)


def validate_approval_transition(
    current: dict[str, Any],
    proposed: dict[str, Any],
    *,
    expected_state_digest: str,
    now: str,
) -> str:
    """Validate an atomic compare-and-swap approval transition.

    The store must read ``current`` and compare ``expected_state_digest`` in
    the same atomic transaction that persists ``proposed``. A semantically
    identical terminal retry is idempotent even if decidedAt or audit metadata
    was regenerated; a different terminal identity conflicts.
    """

    validate_approval_document(current)
    _validate_approval_structure_and_timestamps(proposed)
    if any(
        current[field] != proposed[field] for field in _APPROVAL_IMMUTABLE_FIELDS
    ) or current.get("extensions") != proposed.get("extensions"):
        raise ProtocolValidationError("idempotency_conflict")
    if expected_state_digest != approval_state_digest(current):
        raise ProtocolValidationError("idempotency_conflict")
    if current["status"] != "pending":
        same_terminal_identity = all(
            current.get(field) == proposed.get(field)
            for field in _APPROVAL_TERMINAL_IDENTITY_FIELDS
        ) and current.get("reviewerRef") == proposed.get("reviewerRef")
        if same_terminal_identity:
            return "idempotent"
        try:
            validate_approval_document(proposed)
        except ProtocolValidationError as exc:
            raise ProtocolValidationError("idempotency_conflict") from exc
        raise ProtocolValidationError("idempotency_conflict")
    validate_approval_document(proposed)
    if current == proposed:
        return "idempotent"
    if proposed["status"] == "pending":
        raise ProtocolValidationError("idempotency_conflict")
    trusted_now = _parse_rfc3339(now)
    decided_at = _parse_rfc3339(proposed["decidedAt"])
    expires_at = _parse_rfc3339(proposed["expiresAt"])
    if _timestamp_order(decided_at, trusted_now) > 0:
        raise ProtocolValidationError("invalid_decision")
    if proposed["status"] == "expired":
        if _timestamp_order(trusted_now, expires_at) < 0:
            raise ProtocolValidationError("invalid_decision")
    elif _timestamp_order(trusted_now, expires_at) >= 0:
        raise ProtocolValidationError("approval_expired")
    return "applied"


_RESUME_STABLE_FIELDS = (
    "actionId",
    "correlationId",
    "task",
    "action",
    "target",
    "sideEffect",
)


def validate_resume_attempt(
    original_action: dict[str, Any],
    prior_decision: dict[str, Any],
    approval: dict[str, Any],
    resumed_action: dict[str, Any],
    *,
    trusted_context: Mapping[str, Any],
    now: str,
) -> None:
    """Validate a fresh post-approval authorization attempt.

    This reference function validates protocol linkage and immutable scope. It
    does not authorize or execute the application action.
    """

    from protocol.reference import canonicalize

    validate_action_document(original_action)
    validate_decision_document(prior_decision)
    validate_approval_document(approval)
    validate_action_document(resumed_action)
    trusted_now = _parse_rfc3339(now)
    try:
        original_client_scope_hash = canonicalize.client_scope_hash(original_action)
        trusted_authoritative_scope_hash = canonicalize.authoritative_scope_hash(
            original_action,
            trusted_context,
        )
    except canonicalize.CanonicalizationError as exc:
        raise ProtocolValidationError("approval_scope_mismatch") from exc
    try:
        resumed_client_scope_hash = canonicalize.client_scope_hash(resumed_action)
        resumed_authoritative_scope_hash = canonicalize.authoritative_scope_hash(
            resumed_action,
            trusted_context,
        )
    except canonicalize.CanonicalizationError as exc:
        raise ProtocolValidationError("approval_scope_mismatch") from exc

    if (
        prior_decision["outcome"] != "approval_required"
        or original_action["requestId"] != prior_decision["requestId"]
        or approval["authorizationDecisionId"] != prior_decision["decisionId"]
        or approval["creationAuditRef"] != prior_decision["auditRef"]
        or approval["approvalId"] != prior_decision["approval"]["approvalId"]
        or approval["expiresAt"] != prior_decision["approval"]["expiresAt"]
    ):
        raise ProtocolValidationError("invalid_request")
    if (
        original_action["correlationId"] != prior_decision["correlationId"]
        or approval["actionId"] != original_action["actionId"]
        or approval["correlationId"] != original_action["correlationId"]
        or original_client_scope_hash != prior_decision["clientScopeHash"]
        or trusted_authoritative_scope_hash != prior_decision["authoritativeScopeHash"]
        or approval["authoritativeScopeHash"]
        != prior_decision["authoritativeScopeHash"]
    ):
        raise ProtocolValidationError("approval_scope_mismatch")
    if approval["status"] != "approved":
        if approval["status"] == "expired":
            raise ProtocolValidationError("approval_expired")
        raise ProtocolValidationError("policy_denied")
    if (
        resumed_action.get("causationId") != prior_decision["decisionId"]
        or resumed_action.get("resumeFromApprovalId") != approval["approvalId"]
        or resumed_action["requestId"] == original_action["requestId"]
        or resumed_action["idempotencyKey"] == original_action["idempotencyKey"]
    ):
        raise ProtocolValidationError("invalid_request")
    if (
        any(
            resumed_action[field] != original_action[field]
            for field in _RESUME_STABLE_FIELDS
        )
        or resumed_client_scope_hash != original_client_scope_hash
        or resumed_authoritative_scope_hash != trusted_authoritative_scope_hash
    ):
        raise ProtocolValidationError("approval_scope_mismatch")

    decided_at = _parse_rfc3339(approval["decidedAt"])
    if _timestamp_order(decided_at, trusted_now) > 0:
        raise ProtocolValidationError("invalid_decision")
    expires_at = _parse_rfc3339(approval["expiresAt"])
    if _timestamp_order(trusted_now, expires_at) >= 0:
        raise ProtocolValidationError("approval_expired")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="palonexus-protocol-validate")
    subparsers = parser.add_subparsers(dest="command", required=True)
    action = subparsers.add_parser("action")
    action.add_argument("document")
    decision = subparsers.add_parser("decision")
    decision.add_argument("document")
    approval = subparsers.add_parser("approval")
    approval.add_argument("document")
    error = subparsers.add_parser("error")
    error.add_argument("document")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        document = _read_document(Path(args.document))
        if args.command == "action":
            validate_action_document(document)
        elif args.command == "decision":
            validate_decision_document(document)
        elif args.command == "approval":
            validate_approval_document(document)
        else:
            validate_error_document(document)
    except ProtocolValidationError as exc:
        print(f"validation failed: {exc.code}", file=sys.stderr)
        return 2
    print("valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
