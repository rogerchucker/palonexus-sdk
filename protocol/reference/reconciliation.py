"""Reference state machine for protocol-v1 reconciliation.

The queue contract provides durable at-least-once delivery of safe guard
evidence. Retries can therefore upload the same evidence more than once.
Receipt binding and idempotent reconciliation identifiers make those uploads
safe to deduplicate, but this mechanism does not provide distributed exactly-once
execution for application effects.

Every state change requires a compare-and-swap digest. A durable store must
compare that digest and persist the proposed record in one atomic transaction.
The functions here validate that boundary; they do not implement storage,
authenticate a server transport, or execute application work.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any, Final

from protocol.reference import canonicalize, validate

_IMMUTABLE_EVIDENCE_FIELDS: Final = (
    "schemaVersion",
    "reconciliationId",
    "actionId",
    "requestId",
    "decisionId",
    "correlationId",
    "authorizationIdempotencyKey",
    "clientId",
    "action",
    "targetKind",
    "clientScopeHash",
    "authoritativeScopeHash",
    "outcome",
    "reasonCode",
    "observedAt",
    "batchId",
    "batchSequence",
    "deliveryPolicy",
    "extensions",
)
_TERMINAL_STATES: Final = frozenset({"acknowledged", "discarded"})
_MANUAL_REASON: Final = "attempt_limit_reached"


class ReconciliationError(ValueError):
    """Safe reconciliation failure with a stable code and no record contents."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class RecordPartition:
    """Authoritative store metadata kept outside public evidence."""

    tenant_partition: str
    owner_subject: str


@dataclass(frozen=True, slots=True)
class TrustedStoreContext:
    """Authenticated context for records loaded from an external partition.

    Tenant and subject values are deliberately not serialized into public
    evidence. The queue/store adapter constructs this object from its
    authoritative partition metadata and authenticated session. Callers must
    never derive it from the reconciliation document.
    """

    record_partitions: Mapping[str, RecordPartition]
    authenticated_tenant: str
    authenticated_subject: str
    organization_retention_authority: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "record_partitions",
            MappingProxyType(dict(self.record_partitions)),
        )


@dataclass(frozen=True, slots=True)
class TrustedBatchCheckpoint:
    """Authoritative completed-prefix checkpoint supplied by the durable store."""

    batch_id: str
    expected_next_sequence: int
    completed_prefix: Mapping[int, str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "completed_prefix",
            MappingProxyType(dict(self.completed_prefix)),
        )


@dataclass(frozen=True, slots=True)
class AuthenticatedServerReceipt:
    """Receipt plus trusted transport bindings absent from public evidence."""

    receipt_id: str
    reconciliation_id: str
    evidence_hash: str
    acknowledged_at: str
    tenant_partition: str
    client_id: str

    def public_acknowledgement(self) -> dict[str, str]:
        """Return only the safe fields persisted in reconciliation evidence."""

        return {
            "receiptId": self.receipt_id,
            "reconciliationId": self.reconciliation_id,
            "evidenceHash": self.evidence_hash,
            "acknowledgedAt": self.acknowledged_at,
        }


def _parse_timestamp(value: Any) -> tuple[int, str]:
    try:
        return validate._parse_rfc3339(value)  # noqa: SLF001
    except validate.ProtocolValidationError as exc:
        raise ReconciliationError(exc.code) from exc


def _compare_timestamps(left: tuple[int, str], right: tuple[int, str]) -> int:
    return validate._timestamp_order(left, right)  # noqa: SLF001


def _same_instant(left: Any, right: Any) -> bool:
    return _compare_timestamps(_parse_timestamp(left), _parse_timestamp(right)) == 0


def _add_seconds(value: str, seconds: int) -> str:
    epoch_seconds, fraction = _parse_timestamp(value)
    try:
        rendered = datetime.fromtimestamp(
            epoch_seconds + seconds,
            tz=UTC,
        ).strftime("%Y-%m-%dT%H:%M:%S")
    except (OverflowError, OSError, ValueError) as exc:
        raise ReconciliationError("timestamp_range_invalid") from exc
    if fraction:
        rendered = f"{rendered}.{fraction}"
    return f"{rendered}Z"


def _evidence_body(document: Mapping[str, Any]) -> dict[str, Any]:
    return {
        field: deepcopy(document[field])
        for field in _IMMUTABLE_EVIDENCE_FIELDS
        if field in document
    }


def _body_hash_unchecked(document: Mapping[str, Any]) -> str:
    try:
        return canonicalize.canonical_hash(_evidence_body(document))
    except canonicalize.CanonicalizationError as exc:
        raise ReconciliationError("evidence_invalid") from exc


def _validate_schema(document: dict[str, Any]) -> None:
    try:
        validate._validate_structure("reconciliation", document)  # noqa: SLF001
        validate._validate_extension_numbers(document)  # noqa: SLF001
    except validate.ProtocolValidationError as exc:
        raise ReconciliationError(exc.code) from exc


def _validate_record_size(document: dict[str, Any]) -> None:
    try:
        canonicalize.canonical_json(document)
    except canonicalize.CanonicalizationError as exc:
        code = (
            "record_too_large"
            if exc.code in {"input_too_large", "string_too_large"}
            else "record_invalid"
        )
        raise ReconciliationError(code) from exc


def validate_reconciliation_document(document: dict[str, Any]) -> None:
    """Validate one durable reconciliation record and cross-field invariants."""

    if not isinstance(document, dict):
        raise ReconciliationError("schema_invalid")
    _validate_record_size(document)
    _validate_schema(document)

    observed_at = _parse_timestamp(document["observedAt"])
    last_attempt_at = (
        _parse_timestamp(document["lastAttemptAt"])
        if "lastAttemptAt" in document
        else None
    )
    next_attempt_at = (
        _parse_timestamp(document["nextAttemptAt"])
        if "nextAttemptAt" in document
        else None
    )
    acknowledged_at = (
        _parse_timestamp(document["acknowledgedAt"])
        if "acknowledgedAt" in document
        else None
    )
    discarded_at = (
        _parse_timestamp(document["discardedAt"]) if "discardedAt" in document else None
    )

    policy = document["deliveryPolicy"]
    if (
        policy["baseDelaySeconds"] > policy["maxDelaySeconds"]
        or policy["maxTotalAttempts"] < policy["maxAttempts"]
    ):
        raise ReconciliationError("retry_policy_invalid")
    attempt_count = document["attemptCount"]
    if attempt_count > policy["maxTotalAttempts"]:
        raise ReconciliationError("attempt_limit_exceeded")
    disposition = document["deliveryDisposition"]
    if disposition == "automatic" and attempt_count > policy["maxAttempts"]:
        raise ReconciliationError("automatic_attempt_limit_exceeded")
    if disposition == "manual_intervention" and attempt_count < policy["maxAttempts"]:
        raise ReconciliationError("manual_state_invalid")
    if (
        disposition == "automatic"
        and document["state"] == "pending"
        and attempt_count >= policy["maxAttempts"]
    ):
        raise ReconciliationError("manual_intervention_required")
    if document["state"] == "retry_wait" and attempt_count >= policy["maxAttempts"]:
        raise ReconciliationError("manual_intervention_required")
    if (attempt_count == 0) == (last_attempt_at is not None):
        raise ReconciliationError("attempt_state_invalid")
    if (
        last_attempt_at is not None
        and _compare_timestamps(last_attempt_at, observed_at) < 0
    ):
        raise ReconciliationError("timestamp_order_invalid")
    if (
        next_attempt_at is not None
        and last_attempt_at is not None
        and _compare_timestamps(next_attempt_at, last_attempt_at) <= 0
    ):
        raise ReconciliationError("timestamp_order_invalid")
    if (
        acknowledged_at is not None
        and last_attempt_at is not None
        and _compare_timestamps(acknowledged_at, last_attempt_at) < 0
    ):
        raise ReconciliationError("timestamp_order_invalid")
    if discarded_at is not None and _compare_timestamps(discarded_at, observed_at) < 0:
        raise ReconciliationError("timestamp_order_invalid")

    if document["state"] == "acknowledged":
        acknowledgement = document["acknowledgement"]
        _parse_timestamp(acknowledgement["acknowledgedAt"])
        if (
            acknowledgement["reconciliationId"] != document["reconciliationId"]
            or acknowledgement["evidenceHash"] != _body_hash_unchecked(document)
            or not _same_instant(
                acknowledgement["acknowledgedAt"],
                document["acknowledgedAt"],
            )
        ):
            raise ReconciliationError("acknowledgement_invalid")


def reconciliation_body_hash(document: dict[str, Any]) -> str:
    """Return the stable hash used for upload deduplication and receipts."""

    validate_reconciliation_document(document)
    return _body_hash_unchecked(document)


def reconciliation_state_digest(document: dict[str, Any]) -> str:
    """Return the full-record digest used as a compare-and-swap revision."""

    validate_reconciliation_document(document)
    try:
        return canonicalize.canonical_hash(document)
    except canonicalize.CanonicalizationError as exc:
        raise ReconciliationError("state_invalid") from exc


def _record_partition(
    document: dict[str, Any],
    trusted_context: TrustedStoreContext,
) -> RecordPartition:
    if not isinstance(trusted_context, TrustedStoreContext):
        raise ReconciliationError("trusted_context_required")
    partition = trusted_context.record_partitions.get(document["reconciliationId"])
    if not isinstance(partition, RecordPartition):
        raise ReconciliationError("record_context_mismatch")
    if trusted_context.authenticated_tenant != partition.tenant_partition:
        raise ReconciliationError("tenant_context_mismatch")
    return partition


def _require_owner_context(
    document: dict[str, Any],
    trusted_context: TrustedStoreContext,
) -> RecordPartition:
    partition = _record_partition(document, trusted_context)
    if trusted_context.authenticated_subject != partition.owner_subject:
        raise ReconciliationError("subject_context_mismatch")
    return partition


def _require_user_or_organization_authority(
    document: dict[str, Any],
    trusted_context: TrustedStoreContext,
    *,
    authority_type: str,
    failure_code: str,
) -> RecordPartition:
    partition = _record_partition(document, trusted_context)
    if authority_type == "authenticated_user":
        if trusted_context.authenticated_subject != partition.owner_subject:
            raise ReconciliationError(failure_code)
    elif authority_type == "organization_retention_policy":
        if not trusted_context.organization_retention_authority:
            raise ReconciliationError(failure_code)
    else:
        raise ReconciliationError(failure_code)
    return partition


def resolve_duplicate_reconciliation(
    existing: dict[str, Any],
    proposed: dict[str, Any],
    *,
    trusted_context: TrustedStoreContext,
) -> dict[str, Any]:
    """Resolve same-ID evidence creation without replacing durable state."""

    validate_reconciliation_document(existing)
    validate_reconciliation_document(proposed)
    _require_owner_context(existing, trusted_context)
    if existing["reconciliationId"] != proposed[
        "reconciliationId"
    ] or _body_hash_unchecked(existing) != _body_hash_unchecked(proposed):
        raise ReconciliationError("idempotency_conflict")
    return deepcopy(existing)


def retry_delay_seconds(
    *,
    attempt_count: int,
    policy: Mapping[str, int],
) -> int:
    """Calculate bounded exponential backoff after a failed attempt."""

    if (
        isinstance(attempt_count, bool)
        or not isinstance(attempt_count, int)
        or attempt_count < 1
    ):
        raise ReconciliationError("retry_policy_invalid")
    try:
        base = policy["baseDelaySeconds"]
        maximum = policy["maxDelaySeconds"]
        max_attempts = policy["maxAttempts"]
        max_total_attempts = policy["maxTotalAttempts"]
    except (KeyError, TypeError) as exc:
        raise ReconciliationError("retry_policy_invalid") from exc
    if (
        any(
            isinstance(value, bool) or not isinstance(value, int)
            for value in (base, maximum, max_attempts, max_total_attempts)
        )
        or base < 1
        or maximum < base
        or base > 3_600
        or maximum > 86_400
        or max_attempts < 1
        or max_attempts > 100
        or max_total_attempts < max_attempts
        or max_total_attempts > 100
        or attempt_count > max_total_attempts
    ):
        raise ReconciliationError("retry_policy_invalid")
    exponent = min(attempt_count - 1, 63)
    return min(base * (2**exponent), maximum)


def _validated_retry_policy(
    *,
    attempt_count: Any,
    policy: Any,
) -> tuple[int, Mapping[str, int]]:
    """Validate retry inputs before callers perform comparisons or arithmetic."""

    retry_delay_seconds(attempt_count=attempt_count, policy=policy)
    return attempt_count, policy


def next_attempt_at(
    *,
    failed_at: str,
    attempt_count: int,
    policy: Mapping[str, int],
) -> str:
    """Return the exact bounded retry deadline with stable range failures."""

    attempt_count, policy = _validated_retry_policy(
        attempt_count=attempt_count,
        policy=policy,
    )
    max_attempts = policy["maxAttempts"]
    if attempt_count >= max_attempts:
        raise ReconciliationError("manual_intervention_required")
    return _add_seconds(
        failed_at,
        retry_delay_seconds(
            attempt_count=attempt_count,
            policy=policy,
        ),
    )


def _require_same_evidence(
    current: dict[str, Any],
    proposed: dict[str, Any],
) -> None:
    if current["reconciliationId"] != proposed[
        "reconciliationId"
    ] or _body_hash_unchecked(current) != _body_hash_unchecked(proposed):
        raise ReconciliationError("transition_invalid")


def _same_attempt_history(
    current: Mapping[str, Any],
    proposed: Mapping[str, Any],
) -> bool:
    current_last = current.get("lastAttemptAt")
    proposed_last = proposed.get("lastAttemptAt")
    same_last = (
        current_last is None
        and proposed_last is None
        or current_last is not None
        and proposed_last is not None
        and _same_instant(current_last, proposed_last)
    )
    return (
        proposed["attemptCount"] == current["attemptCount"]
        and same_last
        and proposed["deliveryDisposition"] == current["deliveryDisposition"]
        and proposed.get("manualReasonCode") == current.get("manualReasonCode")
    )


def _require_same_attempt_history(
    current: Mapping[str, Any],
    proposed: Mapping[str, Any],
) -> None:
    if not _same_attempt_history(current, proposed):
        raise ReconciliationError("transition_history_invalid")


def _validate_send_transition(
    current: dict[str, Any],
    proposed: dict[str, Any],
    *,
    now: str,
) -> None:
    if current["deliveryDisposition"] != "automatic":
        raise ReconciliationError("manual_retry_required")
    if current["attemptCount"] >= current["deliveryPolicy"]["maxAttempts"]:
        raise ReconciliationError("attempt_limit_reached")
    if (
        "lastAttemptAt" in current
        and _compare_timestamps(
            _parse_timestamp(now),
            _parse_timestamp(current["lastAttemptAt"]),
        )
        < 0
    ):
        raise ReconciliationError("timestamp_order_invalid")
    if (
        current["state"] == "retry_wait"
        and _compare_timestamps(
            _parse_timestamp(now),
            _parse_timestamp(current["nextAttemptAt"]),
        )
        < 0
    ):
        raise ReconciliationError("retry_not_due")
    if proposed["attemptCount"] != current["attemptCount"] + 1:
        raise ReconciliationError("transition_invalid")
    if proposed["deliveryDisposition"] != "automatic" or "manualReasonCode" in proposed:
        raise ReconciliationError("transition_history_invalid")
    if not _same_instant(proposed["lastAttemptAt"], now):
        raise ReconciliationError("transition_invalid")


def _validate_retry_transition(
    current: dict[str, Any],
    proposed: dict[str, Any],
    *,
    now: str,
) -> None:
    if current["attemptCount"] >= current["deliveryPolicy"]["maxAttempts"]:
        raise ReconciliationError("manual_intervention_required")
    if (
        _compare_timestamps(
            _parse_timestamp(now),
            _parse_timestamp(current["lastAttemptAt"]),
        )
        < 0
    ):
        raise ReconciliationError("timestamp_order_invalid")
    _require_same_attempt_history(current, proposed)
    expected = next_attempt_at(
        failed_at=now,
        attempt_count=current["attemptCount"],
        policy=current["deliveryPolicy"],
    )
    if not _same_instant(proposed["nextAttemptAt"], expected):
        raise ReconciliationError("retry_schedule_invalid")


def _validate_acknowledgement_transition(
    current: dict[str, Any],
    proposed: dict[str, Any],
    *,
    now: str,
    server_receipt: AuthenticatedServerReceipt | None,
    partition: RecordPartition,
) -> None:
    if not isinstance(server_receipt, AuthenticatedServerReceipt):
        raise ReconciliationError("server_acknowledgement_required")
    if proposed["acknowledgement"] != server_receipt.public_acknowledgement():
        raise ReconciliationError("acknowledgement_invalid")
    if (
        server_receipt.tenant_partition != partition.tenant_partition
        or server_receipt.client_id != current["clientId"]
    ):
        raise ReconciliationError("receipt_context_mismatch")
    acknowledgement = proposed["acknowledgement"]
    _require_same_attempt_history(current, proposed)
    if (
        acknowledgement["reconciliationId"] != current["reconciliationId"]
        or acknowledgement["evidenceHash"] != _body_hash_unchecked(current)
        or not _same_instant(
            proposed["acknowledgedAt"],
            acknowledgement["acknowledgedAt"],
        )
        or _compare_timestamps(
            _parse_timestamp(proposed["acknowledgedAt"]),
            _parse_timestamp(now),
        )
        > 0
    ):
        raise ReconciliationError("acknowledgement_invalid")


def _validate_discard_transition(
    current: dict[str, Any],
    proposed: dict[str, Any],
    *,
    now: str,
) -> None:
    _require_same_attempt_history(current, proposed)
    if (
        "lastAttemptAt" in current
        and _compare_timestamps(
            _parse_timestamp(proposed["discardedAt"]),
            _parse_timestamp(current["lastAttemptAt"]),
        )
        < 0
    ):
        raise ReconciliationError("timestamp_order_invalid")
    if (
        _compare_timestamps(
            _parse_timestamp(proposed["discardedAt"]),
            _parse_timestamp(now),
        )
        > 0
    ):
        raise ReconciliationError("discard_authorization_invalid")


def _validate_exhaustion_transition(
    current: dict[str, Any],
    proposed: dict[str, Any],
    *,
    now: str,
) -> None:
    if current["attemptCount"] < current["deliveryPolicy"]["maxAttempts"]:
        raise ReconciliationError("transition_invalid")
    if (
        proposed["attemptCount"] != current["attemptCount"]
        or not _same_instant(proposed["lastAttemptAt"], current["lastAttemptAt"])
        or proposed["deliveryDisposition"] != "manual_intervention"
        or proposed.get("manualReasonCode") != _MANUAL_REASON
    ):
        raise ReconciliationError("transition_history_invalid")
    if (
        _compare_timestamps(
            _parse_timestamp(now),
            _parse_timestamp(current["lastAttemptAt"]),
        )
        < 0
    ):
        raise ReconciliationError("timestamp_order_invalid")


def validate_reconciliation_transition(
    current: dict[str, Any],
    proposed: dict[str, Any],
    *,
    expected_state_digest: str,
    now: str,
    trusted_context: TrustedStoreContext,
    server_receipt: AuthenticatedServerReceipt | None = None,
) -> str:
    """Validate one atomic reconciliation state transition.

    ``trusted_context`` comes from the external authenticated store/session
    boundary. ``server_receipt`` comes from the authenticated server transport.
    """

    validate_reconciliation_document(current)
    partition = _record_partition(current, trusted_context)
    if current["state"] in _TERMINAL_STATES:
        if current["state"] == "discarded":
            _require_user_or_organization_authority(
                current,
                trusted_context,
                authority_type=current["discard"]["authorityType"],
                failure_code="discard_authorization_required",
            )
        else:
            _require_owner_context(current, trusted_context)
        if expected_state_digest != reconciliation_state_digest(current):
            raise ReconciliationError("concurrent_transition")
        if current == proposed:
            return "idempotent"
        raise ReconciliationError("terminal_state")

    validate_reconciliation_document(proposed)
    if current["state"] == "pending" and proposed["state"] == "discarded":
        _require_user_or_organization_authority(
            current,
            trusted_context,
            authority_type=proposed["discard"]["authorityType"],
            failure_code="discard_authorization_required",
        )
    else:
        _require_owner_context(current, trusted_context)
    if expected_state_digest != reconciliation_state_digest(current):
        raise ReconciliationError("concurrent_transition")
    if current == proposed:
        return "idempotent"

    _parse_timestamp(now)
    _require_same_evidence(current, proposed)
    transition = (current["state"], proposed["state"])

    if transition in {("pending", "sending"), ("retry_wait", "sending")}:
        _validate_send_transition(current, proposed, now=now)
    elif transition == ("sending", "retry_wait"):
        _validate_retry_transition(current, proposed, now=now)
    elif transition == ("sending", "pending"):
        if proposed["deliveryDisposition"] == "manual_intervention":
            _validate_exhaustion_transition(current, proposed, now=now)
        else:
            if (
                _compare_timestamps(
                    _parse_timestamp(now),
                    _parse_timestamp(current["lastAttemptAt"]),
                )
                < 0
            ):
                raise ReconciliationError("timestamp_order_invalid")
            _require_same_attempt_history(current, proposed)
    elif transition == ("sending", "acknowledged"):
        _validate_acknowledgement_transition(
            current,
            proposed,
            now=now,
            server_receipt=server_receipt,
            partition=partition,
        )
    elif transition == ("pending", "discarded"):
        _validate_discard_transition(
            current,
            proposed,
            now=now,
        )
    else:
        raise ReconciliationError("transition_invalid")
    return "applied"


def validate_manual_retry_transition(
    current: dict[str, Any],
    proposed: dict[str, Any],
    *,
    expected_state_digest: str,
    now: str,
    trusted_context: TrustedStoreContext,
) -> str:
    """Validate an explicit authenticated retry of manual-intervention state."""

    validate_reconciliation_document(current)
    partition = _record_partition(current, trusted_context)
    if (
        trusted_context.authenticated_subject != partition.owner_subject
        and not trusted_context.organization_retention_authority
    ):
        raise ReconciliationError("manual_retry_authorization_required")
    if expected_state_digest != reconciliation_state_digest(current):
        raise ReconciliationError("concurrent_transition")
    if (
        current["state"] != "pending"
        or current["deliveryDisposition"] != "manual_intervention"
    ):
        raise ReconciliationError("manual_retry_required")
    if current["attemptCount"] >= current["deliveryPolicy"]["maxTotalAttempts"]:
        raise ReconciliationError("attempt_limit_reached")
    validate_reconciliation_document(proposed)
    _require_same_evidence(current, proposed)
    if (
        proposed["state"] != "sending"
        or proposed["deliveryDisposition"] != "manual_intervention"
        or proposed.get("manualReasonCode") != current.get("manualReasonCode")
        or proposed["attemptCount"] != current["attemptCount"] + 1
        or not _same_instant(proposed["lastAttemptAt"], now)
    ):
        raise ReconciliationError("transition_history_invalid")
    if (
        "lastAttemptAt" in current
        and _compare_timestamps(
            _parse_timestamp(now),
            _parse_timestamp(current["lastAttemptAt"]),
        )
        < 0
    ):
        raise ReconciliationError("timestamp_order_invalid")
    return "applied"


def recover_after_restart(
    current: dict[str, Any],
    *,
    expected_state_digest: str,
    now: str,
    trusted_context: TrustedStoreContext,
) -> dict[str, Any]:
    """Recover an unacknowledged sending record to durable pending state."""

    validate_reconciliation_document(current)
    _require_owner_context(current, trusted_context)
    if expected_state_digest != reconciliation_state_digest(current):
        raise ReconciliationError("concurrent_transition")
    if current["state"] != "sending":
        raise ReconciliationError("transition_invalid")
    proposed = deepcopy(current)
    proposed["state"] = "pending"
    if (
        current["deliveryDisposition"] == "manual_intervention"
        or current["attemptCount"] >= current["deliveryPolicy"]["maxAttempts"]
    ):
        proposed["deliveryDisposition"] = "manual_intervention"
        proposed["manualReasonCode"] = _MANUAL_REASON
    validate_reconciliation_transition(
        current,
        proposed,
        expected_state_digest=expected_state_digest,
        now=now,
        trusted_context=trusted_context,
    )
    return proposed


def ordered_batch_resume(
    records: Sequence[dict[str, Any]],
    *,
    now: str,
    limit: int,
    trusted_context: TrustedStoreContext,
    checkpoint: TrustedBatchCheckpoint | None = None,
) -> list[dict[str, Any]]:
    """Select a contiguous due prefix from one durable ordered batch.

    Terminal records are already complete and are skipped. An in-flight,
    not-yet-due, or attempt-exhausted record blocks every later sequence so a
    restart cannot reorder delivery.
    """

    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ReconciliationError("batch_invalid")
    if len(records) > limit:
        raise ReconciliationError("batch_limit_exceeded")
    if not isinstance(checkpoint, TrustedBatchCheckpoint):
        raise ReconciliationError("batch_checkpoint_required")
    if (
        not isinstance(checkpoint.batch_id, str)
        or isinstance(checkpoint.expected_next_sequence, bool)
        or not isinstance(checkpoint.expected_next_sequence, int)
        or checkpoint.expected_next_sequence < 0
        or any(
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 0
            or sequence >= checkpoint.expected_next_sequence
            or not isinstance(reconciliation_id, str)
            for sequence, reconciliation_id in checkpoint.completed_prefix.items()
        )
    ):
        raise ReconciliationError("batch_checkpoint_mismatch")
    _parse_timestamp(now)
    if not records:
        return []
    for record in records:
        validate_reconciliation_document(record)
        _require_owner_context(record, trusted_context)
    batch_ids = {record["batchId"] for record in records}
    reconciliation_ids = {record["reconciliationId"] for record in records}
    sequences = [record["batchSequence"] for record in records]
    if (
        len(batch_ids) != 1
        or checkpoint.batch_id not in batch_ids
        or len(reconciliation_ids) != len(records)
        or len(set(sequences)) != len(records)
        or sequences != sorted(sequences)
        or sequences != list(range(sequences[0], sequences[0] + len(sequences)))
    ):
        raise ReconciliationError("batch_invalid")

    selected: list[dict[str, Any]] = []
    trusted_now = _parse_timestamp(now)
    active_seen = False
    for record in records:
        state = record["state"]
        if state in _TERMINAL_STATES:
            if (
                active_seen
                or state != "acknowledged"
                or record["batchSequence"] >= checkpoint.expected_next_sequence
                or checkpoint.completed_prefix.get(record["batchSequence"])
                != record["reconciliationId"]
            ):
                raise ReconciliationError("batch_checkpoint_mismatch")
            continue
        if (
            not active_seen
            and record["batchSequence"] != checkpoint.expected_next_sequence
        ):
            raise ReconciliationError("batch_checkpoint_mismatch")
        active_seen = True
        if record["deliveryDisposition"] == "manual_intervention":
            break
        if state == "sending":
            break
        if (
            state == "retry_wait"
            and _compare_timestamps(
                trusted_now,
                _parse_timestamp(record["nextAttemptAt"]),
            )
            < 0
        ):
            break
        selected.append(deepcopy(record))
        if len(selected) == limit:
            break
    return selected
