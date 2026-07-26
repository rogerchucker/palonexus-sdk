from __future__ import annotations

import importlib
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from protocol.reference import validate

PROTOCOL = Path(__file__).parents[1]
SCHEMAS = PROTOCOL / "schemas"
VECTORS = PROTOCOL / "test-vectors" / "reconciliation"
COMMON_SCHEMA = SCHEMAS / "common-v1.schema.json"
RECONCILIATION_SCHEMA = SCHEMAS / "reconciliation-v1.schema.json"
RECONCILIATION_RULES = PROTOCOL / "reconciliation-v1.md"
NOW = "2026-07-25T20:00:03Z"
TENANT_PARTITION = "tenant-internal-a"
OWNER_SUBJECT = "subject-internal-a"
ORG_RETENTION_AUTHORITY = "org-retention-internal-a"


def _module() -> Any:
    return importlib.import_module("protocol.reference.reconciliation")


def _json(path: Path) -> dict[str, Any]:
    value = validate.loads_json_strict(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _record(name: str) -> dict[str, Any]:
    return _json(VECTORS / "valid" / f"{name}.json")


def _context(
    *records: dict[str, Any],
    partition_tenant: str = TENANT_PARTITION,
    owner_subject: str = OWNER_SUBJECT,
    authenticated_tenant: str = TENANT_PARTITION,
    authenticated_subject: str = OWNER_SUBJECT,
    organization_retention_authority: str | None = None,
) -> Any:
    reconciliation = _module()
    return reconciliation.TrustedStoreContext(
        record_partitions={
            record["reconciliationId"]: reconciliation.RecordPartition(
                tenant_partition=partition_tenant,
                owner_subject=owner_subject,
            )
            for record in records
        },
        authenticated_tenant=authenticated_tenant,
        authenticated_subject=authenticated_subject,
        organization_retention_authority=organization_retention_authority,
    )


def _receipt(
    record: dict[str, Any],
    *,
    tenant_partition: str = TENANT_PARTITION,
    client_id: str | None = None,
) -> Any:
    acknowledgement = record["acknowledgement"]
    return _module().AuthenticatedServerReceipt(
        receipt_id=acknowledgement["receiptId"],
        reconciliation_id=acknowledgement["reconciliationId"],
        evidence_hash=acknowledgement["evidenceHash"],
        acknowledged_at=acknowledgement["acknowledgedAt"],
        tenant_partition=tenant_partition,
        client_id=client_id or record["clientId"],
    )


def _batch_checkpoint(
    records: list[dict[str, Any]],
    *,
    expected_next_sequence: int,
) -> Any:
    reconciliation = _module()
    return reconciliation.TrustedBatchCheckpoint(
        batch_id=records[0]["batchId"],
        expected_next_sequence=expected_next_sequence,
        completed_prefix={
            record["batchSequence"]: record["reconciliationId"]
            for record in records
            if record["batchSequence"] < expected_next_sequence
        },
    )


def _validator() -> Draft202012Validator:
    common = _json(COMMON_SCHEMA)
    schema = _json(RECONCILIATION_SCHEMA)
    registry = Registry().with_resource(
        common["$id"],
        Resource.from_contents(common),
    )
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(
        schema,
        registry=registry,
        format_checker=FormatChecker(),
    )


def _errors(
    validator: Draft202012Validator,
    instance: dict[str, Any],
) -> list[str]:
    return [
        error.message
        for error in sorted(
            validator.iter_errors(instance),
            key=lambda item: list(item.path),
        )
    ]


def _transition(
    current: dict[str, Any],
    proposed: dict[str, Any],
    *,
    now: str,
    server_receipt: Any = None,
    trusted_context: Any = None,
) -> str:
    reconciliation = _module()
    return reconciliation.validate_reconciliation_transition(
        current,
        proposed,
        expected_state_digest=reconciliation.reconciliation_state_digest(current),
        now=now,
        server_receipt=server_receipt,
        trusted_context=trusted_context or _context(current),
    )


def test_task8_artifacts_exist() -> None:
    assert RECONCILIATION_SCHEMA.is_file()
    assert RECONCILIATION_RULES.is_file()
    assert (PROTOCOL / "reference" / "reconciliation.py").is_file()
    assert sorted((VECTORS / "valid").glob("*.json"))
    assert sorted((VECTORS / "invalid").glob("*.json"))
    assert (VECTORS / "ordered-batch-resume.json").is_file()


def test_schema_is_strict_json_schema_2020_12() -> None:
    schema = _json(RECONCILIATION_SCHEMA)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    assert schema["additionalProperties"] is False
    Draft202012Validator.check_schema(schema)


def test_rules_document_external_partition_and_delivery_boundaries() -> None:
    text = " ".join(RECONCILIATION_RULES.read_text(encoding="utf-8").lower().split())
    for phrase in (
        "external authoritative partition",
        "record tenant",
        "owner subject",
        "authenticated server receipt",
        "manual_intervention",
        "at-least-once",
        "does not provide distributed exactly-once",
        "64 kib",
        "no registered reconciliation extension keys",
    ):
        assert phrase in text


def test_committed_record_vectors_have_expected_validity() -> None:
    validator = _validator()
    for path in sorted((VECTORS / "valid").glob("*.json")):
        assert _errors(validator, _json(path)) == [], path
    for path in sorted((VECTORS / "invalid").glob("*.json")):
        assert _errors(validator, _json(path)), path


@pytest.mark.parametrize(
    "name",
    (
        "pending",
        "sending",
        "retry-wait",
        "acknowledged",
        "discarded-user",
        "discarded-policy",
    ),
)
def test_public_validator_accepts_every_local_state(name: str) -> None:
    _module().validate_reconciliation_document(_record(name))


def test_error_evidence_reuses_task7_stable_error_codes() -> None:
    reconciliation = _module()
    error_record = _record("error-pending")
    assert error_record["outcome"] == "error"
    assert error_record["reasonCode"] in validate.ERROR_SAFE_MESSAGES
    reconciliation.validate_reconciliation_document(error_record)

    unknown = deepcopy(error_record)
    unknown["reasonCode"] = "new_unregistered_error"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="schema_invalid",
    ):
        reconciliation.validate_reconciliation_document(unknown)


def test_evidence_identity_is_stable_across_local_delivery_states() -> None:
    reconciliation = _module()
    records = [
        _record("pending"),
        _record("sending"),
        _record("retry-wait"),
        _record("acknowledged"),
    ]
    assert (
        len({reconciliation.reconciliation_body_hash(record) for record in records})
        == 1
    )
    for record in records:
        assert record["reconciliationId"] == records[0]["reconciliationId"]
        assert record["actionId"] == records[0]["actionId"]
        assert record["correlationId"] == records[0]["correlationId"]
        assert (
            record["authorizationIdempotencyKey"]
            == records[0]["authorizationIdempotencyKey"]
        )


def test_duplicate_upload_is_idempotent_but_changed_evidence_conflicts() -> None:
    reconciliation = _module()
    existing = _record("sending")
    duplicate = _record("pending")
    assert (
        reconciliation.resolve_duplicate_reconciliation(
            existing,
            duplicate,
            trusted_context=_context(existing),
        )
        == existing
    )

    conflicting = deepcopy(duplicate)
    conflicting["reasonCode"] = "different_reason"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="idempotency_conflict",
    ):
        reconciliation.resolve_duplicate_reconciliation(
            existing,
            conflicting,
            trusted_context=_context(existing),
        )


def test_pending_claims_sending_with_one_atomic_attempt_increment() -> None:
    pending = _record("pending")
    sending = _record("sending")
    assert _transition(pending, sending, now=NOW) == "applied"

    stale = "sha256:" + ("f" * 64)
    with pytest.raises(
        _module().ReconciliationError,
        match="concurrent_transition",
    ):
        _module().validate_reconciliation_transition(
            pending,
            sending,
            expected_state_digest=stale,
            now=NOW,
            trusted_context=_context(pending),
        )


def test_retry_wait_persists_bounded_exponential_next_attempt() -> None:
    reconciliation = _module()
    sending = _record("sending")
    retry_wait = _record("retry-wait")
    assert retry_wait["nextAttemptAt"] == "2026-07-25T20:00:09Z"
    assert (
        reconciliation.retry_delay_seconds(
            attempt_count=retry_wait["attemptCount"],
            policy=retry_wait["deliveryPolicy"],
        )
        == 5
    )
    assert (
        _transition(
            sending,
            retry_wait,
            now="2026-07-25T20:00:04Z",
        )
        == "applied"
    )

    bad_schedule = deepcopy(retry_wait)
    bad_schedule["nextAttemptAt"] = "2026-07-25T20:00:10Z"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="retry_schedule_invalid",
    ):
        _transition(
            sending,
            bad_schedule,
            now="2026-07-25T20:00:04Z",
        )

    capped_policy = {
        "maxAttempts": 100,
        "maxTotalAttempts": 100,
        "baseDelaySeconds": 30,
        "maxDelaySeconds": 60,
    }
    assert (
        reconciliation.retry_delay_seconds(
            attempt_count=100,
            policy=capped_policy,
        )
        == 60
    )


def test_retry_wait_honors_due_time() -> None:
    reconciliation = _module()
    retry_wait = _record("retry-wait")
    second_send = deepcopy(_record("sending"))
    second_send["attemptCount"] = 2
    second_send["lastAttemptAt"] = retry_wait["nextAttemptAt"]

    with pytest.raises(
        reconciliation.ReconciliationError,
        match="retry_not_due",
    ):
        _transition(
            retry_wait,
            second_send,
            now="2026-07-25T20:00:08.999999999Z",
        )
    assert (
        _transition(
            retry_wait,
            second_send,
            now=retry_wait["nextAttemptAt"],
        )
        == "applied"
    )


def test_exhausted_retry_enters_manual_pending_and_never_auto_resends() -> None:
    reconciliation = _module()
    sending = _record("sending")
    sending["attemptCount"] = sending["deliveryPolicy"]["maxAttempts"]
    exhausted = _record("exhausted-pending")

    assert (
        _transition(
            sending,
            exhausted,
            now="2026-07-25T20:00:04Z",
        )
        == "applied"
    )
    assert exhausted["state"] == "pending"
    assert exhausted["deliveryDisposition"] == "manual_intervention"
    assert exhausted["manualReasonCode"] == "attempt_limit_reached"
    assert "nextAttemptAt" not in exhausted
    assert (
        reconciliation.ordered_batch_resume(
            [exhausted],
            now="2026-07-25T21:00:00Z",
            limit=1,
            trusted_context=_context(exhausted),
            checkpoint=_batch_checkpoint([exhausted], expected_next_sequence=0),
        )
        == []
    )

    manual_send = deepcopy(exhausted)
    manual_send["state"] = "sending"
    manual_send["attemptCount"] += 1
    manual_send["lastAttemptAt"] = "2026-07-25T21:00:01Z"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="manual_retry_required",
    ):
        _transition(
            exhausted,
            manual_send,
            now=manual_send["lastAttemptAt"],
        )
    assert (
        reconciliation.validate_manual_retry_transition(
            exhausted,
            manual_send,
            expected_state_digest=reconciliation.reconciliation_state_digest(exhausted),
            now=manual_send["lastAttemptAt"],
            trusted_context=_context(exhausted),
        )
        == "applied"
    )
    assert (
        reconciliation.validate_manual_retry_transition(
            exhausted,
            manual_send,
            expected_state_digest=reconciliation.reconciliation_state_digest(exhausted),
            now=manual_send["lastAttemptAt"],
            trusted_context=_context(
                exhausted,
                authenticated_subject="retention-service-internal",
                organization_retention_authority=ORG_RETENTION_AUTHORITY,
            ),
        )
        == "applied"
    )

    discarded = deepcopy(exhausted)
    discarded["state"] = "discarded"
    discarded["discardedAt"] = "2026-07-25T21:00:02Z"
    discarded["discard"] = {
        "authorityType": "authenticated_user",
        "reasonCode": "user_retention_request",
    }
    assert (
        _transition(
            exhausted,
            discarded,
            now=discarded["discardedAt"],
        )
        == "applied"
    )


def test_exhausted_attempt_cannot_enter_dead_retry_wait() -> None:
    reconciliation = _module()
    sending = _record("sending")
    sending["attemptCount"] = sending["deliveryPolicy"]["maxAttempts"]
    retry_wait = _record("retry-wait")
    retry_wait["attemptCount"] = sending["attemptCount"]
    retry_wait["nextAttemptAt"] = "2026-07-25T20:00:09Z"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="manual_intervention_required",
    ):
        _transition(
            sending,
            retry_wait,
            now="2026-07-25T20:00:04Z",
        )


def test_restart_recovers_sending_without_new_identity() -> None:
    reconciliation = _module()
    sending = _record("sending")
    recovered = reconciliation.recover_after_restart(
        sending,
        expected_state_digest=reconciliation.reconciliation_state_digest(sending),
        now="2026-07-25T20:00:04Z",
        trusted_context=_context(sending),
    )
    assert recovered["state"] == "pending"
    assert recovered["attemptCount"] == sending["attemptCount"]
    assert recovered["lastAttemptAt"] == sending["lastAttemptAt"]
    assert "nextAttemptAt" not in recovered
    assert reconciliation.reconciliation_body_hash(
        recovered
    ) == reconciliation.reconciliation_body_hash(sending)


def test_restart_recovery_is_cas_protected_and_only_applies_to_sending() -> None:
    reconciliation = _module()
    sending = _record("sending")
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="concurrent_transition",
    ):
        reconciliation.recover_after_restart(
            sending,
            expected_state_digest="sha256:" + ("f" * 64),
            now="2026-07-25T20:00:04Z",
            trusted_context=_context(sending),
        )
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="transition_invalid",
    ):
        reconciliation.recover_after_restart(
            _record("pending"),
            expected_state_digest=reconciliation.reconciliation_state_digest(
                _record("pending")
            ),
            now="2026-07-25T20:00:04Z",
            trusted_context=_context(_record("pending")),
        )


def test_retry_and_restart_recovery_cannot_precede_last_attempt() -> None:
    reconciliation = _module()
    sending = _record("sending")
    retry_wait = _record("retry-wait")
    retry_wait["nextAttemptAt"] = "2026-07-25T20:00:07Z"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="timestamp_order_invalid",
    ):
        _transition(
            sending,
            retry_wait,
            now="2026-07-25T20:00:02Z",
        )

    with pytest.raises(
        reconciliation.ReconciliationError,
        match="timestamp_order_invalid",
    ):
        reconciliation.recover_after_restart(
            sending,
            expected_state_digest=reconciliation.reconciliation_state_digest(sending),
            now="2026-07-25T20:00:02Z",
            trusted_context=_context(sending),
        )


def test_only_authenticated_server_receipt_may_acknowledge() -> None:
    sending = _record("sending")
    acknowledged = _record("acknowledged")
    receipt = _receipt(acknowledged)
    assert {
        "tenantId",
        "tenantPartition",
        "subjectId",
        "ownerSubject",
        "clientId",
    }.isdisjoint(acknowledged["acknowledgement"])

    with pytest.raises(
        _module().ReconciliationError,
        match="server_acknowledgement_required",
    ):
        _transition(
            sending,
            acknowledged,
            now=acknowledged["acknowledgedAt"],
        )
    assert (
        _transition(
            sending,
            acknowledged,
            now=acknowledged["acknowledgedAt"],
            server_receipt=receipt,
        )
        == "applied"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("reconciliationId", "recon_01J5ABCDEFGHJKMNPQRSTVWXY9"),
        ("evidenceHash", "sha256:" + ("f" * 64)),
    ),
)
def test_receipt_is_bound_to_reconciliation_identity_and_body(
    field: str,
    value: str,
) -> None:
    sending = _record("sending")
    acknowledged = _record("acknowledged")
    forged = deepcopy(acknowledged["acknowledgement"])
    forged[field] = value
    proposed = deepcopy(acknowledged)
    proposed["acknowledgement"] = forged
    with pytest.raises(
        _module().ReconciliationError,
        match="acknowledgement_invalid",
    ):
        _transition(
            sending,
            proposed,
            now=acknowledged["acknowledgedAt"],
            server_receipt=_receipt(proposed),
        )


def test_ack_loss_reuploads_same_evidence_and_accepts_receipt() -> None:
    reconciliation = _module()
    sending = _record("sending")
    retry_wait = _record("retry-wait")
    second_send = deepcopy(sending)
    second_send["attemptCount"] = 2
    second_send["lastAttemptAt"] = retry_wait["nextAttemptAt"]
    acknowledged = deepcopy(_record("acknowledged"))
    acknowledged["attemptCount"] = 2
    acknowledged["lastAttemptAt"] = second_send["lastAttemptAt"]
    acknowledged["acknowledgedAt"] = "2026-07-25T20:00:10Z"
    acknowledged["acknowledgement"]["acknowledgedAt"] = acknowledged["acknowledgedAt"]

    assert (
        _transition(
            sending,
            retry_wait,
            now="2026-07-25T20:00:04Z",
        )
        == "applied"
    )
    assert (
        _transition(
            retry_wait,
            second_send,
            now=retry_wait["nextAttemptAt"],
        )
        == "applied"
    )
    assert reconciliation.reconciliation_body_hash(
        second_send
    ) == reconciliation.reconciliation_body_hash(sending)
    assert (
        _transition(
            second_send,
            acknowledged,
            now=acknowledged["acknowledgedAt"],
            server_receipt=_receipt(acknowledged),
        )
        == "applied"
    )


def test_terminal_states_allow_only_exact_idempotent_retry() -> None:
    reconciliation = _module()
    for terminal_name in ("acknowledged", "discarded-user"):
        terminal = _record(terminal_name)
        assert (
            _transition(
                terminal,
                deepcopy(terminal),
                now=(terminal.get("acknowledgedAt") or terminal["discardedAt"]),
                server_receipt=(
                    _receipt(terminal) if "acknowledgement" in terminal else None
                ),
            )
            == "idempotent"
        )
        changed = deepcopy(terminal)
        changed["reasonCode"] = "changed_reason"
        with pytest.raises(
            reconciliation.ReconciliationError,
            match="terminal_state",
        ):
            _transition(
                terminal,
                changed,
                now=(terminal.get("acknowledgedAt") or terminal["discardedAt"]),
                server_receipt=(
                    _receipt(terminal) if "acknowledgement" in terminal else None
                ),
            )


def test_discard_requires_trusted_authenticated_user_authority() -> None:
    reconciliation = _module()
    pending = _record("pending")
    discarded = _record("discarded-user")

    with pytest.raises(
        reconciliation.ReconciliationError,
        match="discard_authorization_required",
    ):
        _transition(
            pending,
            discarded,
            now=discarded["discardedAt"],
            trusted_context=_context(
                pending,
                authenticated_subject="different-subject-internal",
            ),
        )
    assert (
        _transition(
            pending,
            discarded,
            now=discarded["discardedAt"],
        )
        == "applied"
    )


def test_discard_requires_verified_organization_retention_policy_authority() -> None:
    reconciliation = _module()
    pending = _record("pending")
    discarded = _record("discarded-policy")
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="discard_authorization_required",
    ):
        _transition(
            pending,
            discarded,
            now=discarded["discardedAt"],
            trusted_context=_context(
                pending,
                authenticated_subject="retention-service-internal",
            ),
        )

    assert (
        _transition(
            pending,
            discarded,
            now=discarded["discardedAt"],
            trusted_context=_context(
                pending,
                authenticated_subject="retention-service-internal",
                organization_retention_authority=ORG_RETENTION_AUTHORITY,
            ),
        )
        == "applied"
    )


def test_only_pending_may_be_discarded() -> None:
    reconciliation = _module()
    sending = _record("sending")
    discarded = _record("discarded-user")
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="transition_invalid",
    ):
        _transition(
            sending,
            discarded,
            now=discarded["discardedAt"],
        )


def test_discard_preserves_attempt_history_and_cannot_erase_or_forge_it() -> None:
    reconciliation = _module()
    sending = _record("sending")
    recovered = reconciliation.recover_after_restart(
        sending,
        expected_state_digest=reconciliation.reconciliation_state_digest(sending),
        now="2026-07-25T20:00:04Z",
        trusted_context=_context(sending),
    )
    discarded = deepcopy(recovered)
    discarded["state"] = "discarded"
    discarded["discardedAt"] = "2026-07-25T20:10:00Z"
    discarded["discard"] = {
        "authorityType": "authenticated_user",
        "reasonCode": "user_retention_request",
    }
    assert (
        _transition(
            recovered,
            discarded,
            now=discarded["discardedAt"],
        )
        == "applied"
    )

    forged = deepcopy(discarded)
    forged["attemptCount"] = 0
    forged.pop("lastAttemptAt")
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="transition_history_invalid",
    ):
        _transition(
            recovered,
            forged,
            now=forged["discardedAt"],
        )


def test_ordered_batch_resume_skips_terminal_prefix_and_preserves_sequence() -> None:
    reconciliation = _module()
    vector = _json(VECTORS / "ordered-batch-resume.json")
    records = vector["records"]
    selected = reconciliation.ordered_batch_resume(
        records,
        now=vector["now"],
        limit=vector["limit"],
        trusted_context=_context(*records),
        checkpoint=_batch_checkpoint(records, expected_next_sequence=1),
    )
    assert [record["batchSequence"] for record in selected] == vector[
        "expectedSequences"
    ]
    assert [record["reconciliationId"] for record in selected] == vector[
        "expectedReconciliationIds"
    ]


def test_ordered_batch_resume_stops_at_not_due_or_in_flight_record() -> None:
    reconciliation = _module()
    pending = _record("pending")
    pending["reconciliationId"] = "recon_01J5ABCDEFGHJKMNPQRSTVWXY2"
    pending["batchSequence"] = 2
    retry_wait = _record("retry-wait")
    retry_wait["reconciliationId"] = "recon_01J5ABCDEFGHJKMNPQRSTVWXY1"
    retry_wait["batchSequence"] = 1
    acknowledged = _record("acknowledged")
    acknowledged["batchSequence"] = 0

    assert (
        reconciliation.ordered_batch_resume(
            [acknowledged, retry_wait, pending],
            now="2026-07-25T20:00:08Z",
            limit=10,
            trusted_context=_context(pending, retry_wait, acknowledged),
            checkpoint=_batch_checkpoint(
                [acknowledged, retry_wait, pending],
                expected_next_sequence=1,
            ),
        )
        == []
    )
    in_flight = deepcopy(retry_wait)
    in_flight["state"] = "sending"
    in_flight.pop("nextAttemptAt")
    assert (
        reconciliation.ordered_batch_resume(
            [acknowledged, in_flight, pending],
            now="2026-07-25T20:00:09Z",
            limit=10,
            trusted_context=_context(pending, in_flight, acknowledged),
            checkpoint=_batch_checkpoint(
                [acknowledged, in_flight, pending],
                expected_next_sequence=1,
            ),
        )
        == []
    )


def test_ordered_batch_resume_rejects_gaps_duplicates_and_mixed_batches() -> None:
    reconciliation = _module()
    first = _record("pending")
    second = deepcopy(first)
    second["reconciliationId"] = "recon_01J5ABCDEFGHJKMNPQRSTVWXY1"
    second["batchSequence"] = 1

    for records in (
        [first, deepcopy(first)],
        [first, {**second, "batchSequence": 2}],
        [first, {**second, "batchId": "batch_01J5ABCDEFGHJKMNPQRSTVWXY1"}],
    ):
        with pytest.raises(
            reconciliation.ReconciliationError,
            match="batch_invalid",
        ):
            reconciliation.ordered_batch_resume(
                records,
                now="2026-07-25T20:00:09Z",
                limit=10,
                trusted_context=_context(*records),
                checkpoint=_batch_checkpoint(records, expected_next_sequence=0),
            )


def test_ordered_batch_resume_accepts_pruned_contiguous_tail_but_not_reordering() -> (
    None
):
    reconciliation = _module()
    first = _record("pending")
    first["reconciliationId"] = "recon_01J5ABCDEFGHJKMNPQRSTVWXY5"
    first["batchSequence"] = 5
    second = deepcopy(first)
    second["reconciliationId"] = "recon_01J5ABCDEFGHJKMNPQRSTVWXY6"
    second["batchSequence"] = 6

    assert [
        record["batchSequence"]
        for record in reconciliation.ordered_batch_resume(
            [first, second],
            now="2026-07-25T20:00:09Z",
            limit=10,
            trusted_context=_context(first, second),
            checkpoint=_batch_checkpoint(
                [first, second],
                expected_next_sequence=5,
            ),
        )
    ] == [5, 6]
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="batch_invalid",
    ):
        reconciliation.ordered_batch_resume(
            [second, first],
            now="2026-07-25T20:00:09Z",
            limit=10,
            trusted_context=_context(first, second),
            checkpoint=_batch_checkpoint(
                [first, second],
                expected_next_sequence=5,
            ),
        )


def test_trusted_store_context_rejects_tenant_actor_and_record_swaps() -> None:
    reconciliation = _module()
    pending = _record("pending")
    sending = _record("sending")

    with pytest.raises(
        reconciliation.ReconciliationError,
        match="tenant_context_mismatch",
    ):
        _transition(
            pending,
            sending,
            now=NOW,
            trusted_context=_context(
                pending,
                authenticated_tenant="tenant-internal-b",
            ),
        )
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="subject_context_mismatch",
    ):
        _transition(
            pending,
            sending,
            now=NOW,
            trusted_context=_context(
                pending,
                authenticated_subject="subject-internal-b",
            ),
        )

    other = deepcopy(pending)
    other["reconciliationId"] = "recon_01J5ABCDEFGHJKMNPQRSTVWXY9"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="record_context_mismatch",
    ):
        _transition(
            pending,
            sending,
            now=NOW,
            trusted_context=_context(other),
        )

    acknowledged = _record("acknowledged")
    changed_terminal = deepcopy(acknowledged)
    changed_terminal["reasonCode"] = "different_reason"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="subject_context_mismatch",
    ):
        _transition(
            acknowledged,
            changed_terminal,
            now=acknowledged["acknowledgedAt"],
            trusted_context=_context(
                acknowledged,
                authenticated_subject="subject-internal-b",
            ),
            server_receipt=_receipt(acknowledged),
        )


@pytest.mark.parametrize(
    ("tenant_partition", "client_id"),
    (
        ("tenant-internal-b", "registered-codex"),
        (TENANT_PARTITION, "different-registered-client"),
    ),
)
def test_server_receipt_is_bound_to_trusted_tenant_and_client(
    tenant_partition: str,
    client_id: str,
) -> None:
    reconciliation = _module()
    sending = _record("sending")
    acknowledged = _record("acknowledged")
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="receipt_context_mismatch",
    ):
        _transition(
            sending,
            acknowledged,
            now=acknowledged["acknowledgedAt"],
            server_receipt=_receipt(
                acknowledged,
                tenant_partition=tenant_partition,
                client_id=client_id,
            ),
        )


def test_cross_tenant_organization_discard_fails_closed() -> None:
    reconciliation = _module()
    pending = _record("pending")
    discarded = _record("discarded-policy")
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="tenant_context_mismatch",
    ):
        _transition(
            pending,
            discarded,
            now=discarded["discardedAt"],
            trusted_context=_context(
                pending,
                authenticated_tenant="tenant-internal-b",
                authenticated_subject="retention-service-internal",
                organization_retention_authority=ORG_RETENTION_AUTHORITY,
            ),
        )


def test_timestamp_order_and_attempt_policy_fail_closed_semantically() -> None:
    reconciliation = _module()
    bad_order = deepcopy(_record("retry-wait"))
    bad_order["nextAttemptAt"] = bad_order["lastAttemptAt"]
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="timestamp_order_invalid",
    ):
        reconciliation.validate_reconciliation_document(bad_order)

    bad_policy = deepcopy(_record("pending"))
    bad_policy["deliveryPolicy"]["maxDelaySeconds"] = 1
    bad_policy["deliveryPolicy"]["baseDelaySeconds"] = 2
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="retry_policy_invalid",
    ):
        reconciliation.validate_reconciliation_document(bad_policy)

    over_limit = deepcopy(_record("pending"))
    over_limit["attemptCount"] = over_limit["deliveryPolicy"]["maxTotalAttempts"] + 1
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="attempt_limit_exceeded",
    ):
        reconciliation.validate_reconciliation_document(over_limit)


def test_timestamp_precision_is_exact_but_wire_length_is_bounded() -> None:
    reconciliation = _module()
    record = _record("pending")
    record["observedAt"] = f"2026-07-25T20:00:02.{'1' * 80}Z"
    reconciliation.validate_reconciliation_document(record)

    too_long = deepcopy(record)
    too_long["observedAt"] = f"2026-07-25T20:00:02.{'1' * 110}Z"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="schema_invalid",
    ):
        reconciliation.validate_reconciliation_document(too_long)


def test_timestamp_range_failures_have_stable_safe_errors() -> None:
    reconciliation = _module()
    invalid_offset = _record("pending")
    invalid_offset["observedAt"] = "2026-07-25T20:00:02+24:00"
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="timestamp_invalid",
    ):
        reconciliation.validate_reconciliation_document(invalid_offset)

    with pytest.raises(
        reconciliation.ReconciliationError,
        match="timestamp_range_invalid",
    ):
        reconciliation.next_attempt_at(
            failed_at="9999-12-31T23:59:59Z",
            attempt_count=1,
            policy=_record("pending")["deliveryPolicy"],
        )


def test_reconciliation_record_is_bounded_before_persistence_or_digest() -> None:
    reconciliation = _module()
    oversized = _record("pending")
    oversized["unknown"] = "x" * 70_000
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="record_too_large",
    ):
        reconciliation.validate_reconciliation_document(oversized)
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="record_too_large",
    ):
        reconciliation.reconciliation_state_digest(oversized)


@pytest.mark.parametrize("state_name", ("sending", "retry-wait", "acknowledged"))
def test_automatic_attempts_may_not_exceed_automatic_bound(state_name: str) -> None:
    reconciliation = _module()
    record = deepcopy(_record(state_name))
    record["attemptCount"] = record["deliveryPolicy"]["maxAttempts"] + 1
    assert _errors(_validator(), record) == []
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="automatic_attempt_limit_exceeded",
    ):
        reconciliation.validate_reconciliation_document(record)


def test_authenticated_manual_acknowledgement_preserves_manual_provenance() -> None:
    reconciliation = _module()
    sending = deepcopy(_record("sending"))
    sending["attemptCount"] = sending["deliveryPolicy"]["maxAttempts"] + 1
    sending["deliveryDisposition"] = "manual_intervention"
    sending["manualReasonCode"] = "attempt_limit_reached"
    sending["lastAttemptAt"] = "2026-07-25T20:00:06Z"

    acknowledged = deepcopy(_record("acknowledged"))
    acknowledged["attemptCount"] = sending["attemptCount"]
    acknowledged["deliveryDisposition"] = sending["deliveryDisposition"]
    acknowledged["manualReasonCode"] = sending["manualReasonCode"]
    acknowledged["lastAttemptAt"] = sending["lastAttemptAt"]
    acknowledged["acknowledgedAt"] = "2026-07-25T20:00:07Z"
    acknowledged["acknowledgement"]["acknowledgedAt"] = acknowledged["acknowledgedAt"]

    reconciliation.validate_reconciliation_document(sending)
    reconciliation.validate_reconciliation_document(acknowledged)
    assert (
        _transition(
            sending,
            acknowledged,
            now=acknowledged["acknowledgedAt"],
            server_receipt=_receipt(acknowledged),
            trusted_context=_context(sending),
        )
        == "applied"
    )


def test_ordered_batch_resume_requires_authoritative_completed_prefix() -> None:
    reconciliation = _module()
    fifth = _record("pending")
    fifth["reconciliationId"] = "recon_01J5ABCDEFGHJKMNPQRSTVWXY5"
    fifth["batchSequence"] = 5
    sixth = deepcopy(fifth)
    sixth["reconciliationId"] = "recon_01J5ABCDEFGHJKMNPQRSTVWXY6"
    sixth["batchSequence"] = 6

    with pytest.raises(
        reconciliation.ReconciliationError,
        match="batch_checkpoint_required",
    ):
        reconciliation.ordered_batch_resume(
            [fifth, sixth],
            now=NOW,
            limit=2,
            trusted_context=_context(fifth, sixth),
        )

    checkpoint = _batch_checkpoint([fifth, sixth], expected_next_sequence=5)
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="batch_checkpoint_mismatch",
    ):
        reconciliation.ordered_batch_resume(
            [sixth],
            now=NOW,
            limit=1,
            trusted_context=_context(sixth),
            checkpoint=checkpoint,
        )


def test_retained_acknowledgement_must_match_authoritative_checkpoint() -> None:
    reconciliation = _module()
    acknowledged = _record("acknowledged")
    pending = _record("pending")
    pending["reconciliationId"] = "recon_01J5ABCDEFGHJKMNPQRSTVWXY1"
    pending["batchSequence"] = 1
    checkpoint = reconciliation.TrustedBatchCheckpoint(
        batch_id=acknowledged["batchId"],
        expected_next_sequence=1,
        completed_prefix={0: "recon_01J5ABCDEFGHJKMNPQRSTVWXY9"},
    )
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="batch_checkpoint_mismatch",
    ):
        reconciliation.ordered_batch_resume(
            [acknowledged, pending],
            now=NOW,
            limit=2,
            trusted_context=_context(acknowledged, pending),
            checkpoint=checkpoint,
        )


def test_ordered_batch_resume_checks_input_bound_before_record_iteration() -> None:
    reconciliation = _module()
    invalid = {"not": "a reconciliation record"}
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="batch_limit_exceeded",
    ):
        reconciliation.ordered_batch_resume(
            [invalid, invalid],
            now=NOW,
            limit=1,
            trusted_context=_context(),
            checkpoint=None,
        )


@pytest.mark.parametrize(
    ("attempt_count", "policy"),
    (
        (
            True,
            {
                "maxAttempts": 3,
                "maxTotalAttempts": 5,
                "baseDelaySeconds": 5,
                "maxDelaySeconds": 60,
            },
        ),
        (
            "1",
            {
                "maxAttempts": 3,
                "maxTotalAttempts": 5,
                "baseDelaySeconds": 5,
                "maxDelaySeconds": 60,
            },
        ),
        (
            1.0,
            {
                "maxAttempts": 3,
                "maxTotalAttempts": 5,
                "baseDelaySeconds": 5,
                "maxDelaySeconds": 60,
            },
        ),
        (
            -1,
            {
                "maxAttempts": 3,
                "maxTotalAttempts": 5,
                "baseDelaySeconds": 5,
                "maxDelaySeconds": 60,
            },
        ),
        (1, {"maxTotalAttempts": 5, "baseDelaySeconds": 5, "maxDelaySeconds": 60}),
        (
            1,
            {
                "maxAttempts": True,
                "maxTotalAttempts": 5,
                "baseDelaySeconds": 5,
                "maxDelaySeconds": 60,
            },
        ),
        (
            1,
            {
                "maxAttempts": "3",
                "maxTotalAttempts": 5,
                "baseDelaySeconds": 5,
                "maxDelaySeconds": 60,
            },
        ),
        (
            1,
            {
                "maxAttempts": 3.0,
                "maxTotalAttempts": 5,
                "baseDelaySeconds": 5,
                "maxDelaySeconds": 60,
            },
        ),
        (
            1,
            {
                "maxAttempts": 3,
                "maxTotalAttempts": 5,
                "baseDelaySeconds": -1,
                "maxDelaySeconds": 60,
            },
        ),
    ),
)
def test_next_attempt_at_rejects_malformed_policy_without_runtime_errors(
    attempt_count: Any,
    policy: Any,
) -> None:
    reconciliation = _module()
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="retry_policy_invalid",
    ):
        reconciliation.next_attempt_at(
            failed_at=NOW,
            attempt_count=attempt_count,
            policy=policy,
        )


@pytest.mark.parametrize(
    "unsafe_value",
    (
        "Bearer secret-value",
        "raw prompt that must not enter reconciliation",
    ),
)
def test_v1_reconciliation_extensions_have_no_registered_keys(
    unsafe_value: str,
) -> None:
    reconciliation = _module()
    record = _record("pending")
    record["extensions"] = {}
    reconciliation.validate_reconciliation_document(record)
    reconciliation.reconciliation_state_digest(record)

    record["extensions"] = {"dev.palonexus.unregistered.v1": {"note": unsafe_value}}
    with pytest.raises(
        reconciliation.ReconciliationError,
        match="schema_invalid",
    ):
        reconciliation.validate_reconciliation_document(record)


def test_reconciliation_contains_only_safe_metadata_not_raw_resources() -> None:
    forbidden_keys = {
        "arguments",
        "authorityref",
        "command",
        "credential",
        "email",
        "owner",
        "password",
        "prompt",
        "resource",
        "subject",
        "tenant",
        "token",
    }
    stack: list[Any] = []
    for path in sorted(VECTORS.rglob("*.json")):
        stack.append(_json(path))
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            assert forbidden_keys.isdisjoint(key.lower() for key in value)
            stack.extend(value.values())
        elif isinstance(value, list):
            stack.extend(value)
        elif isinstance(value, str):
            assert "@" not in value
            assert "bearer " not in value.lower()


def test_reference_contract_states_at_least_once_not_exactly_once() -> None:
    module_text = (
        (PROTOCOL / "reference" / "reconciliation.py")
        .read_text(encoding="utf-8")
        .lower()
    )
    assert "at-least-once" in module_text
    assert "does not provide distributed exactly-once" in module_text
