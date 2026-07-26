from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from protocol.reference import validate

PROTOCOL = Path(__file__).parents[1]
SCHEMAS = PROTOCOL / "schemas"
VECTORS = PROTOCOL / "test-vectors"
COMMON_SCHEMA = SCHEMAS / "common-v1.schema.json"
APPROVAL_SCHEMA = SCHEMAS / "approval-v1.schema.json"
ERROR_SCHEMA = SCHEMAS / "error-v1.schema.json"
ERROR_SAFETY = PROTOCOL / "error-safety-v1.md"
ERROR_MESSAGE_VECTOR = VECTORS / "error" / "code-message-v1.json"
TRUSTED_CONTEXT = {
    "tenantId": "tenant_example",
    "actorId": "subject_example",
    "agentId": "agent_example",
    "delegationId": "delegation_example",
    "clientId": "registered-codex",
}
RESUME_NOW = "2026-07-25T20:05:02Z"


def _json(path: Path) -> dict[str, Any]:
    value = validate.loads_json_strict(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _validator(path: Path) -> Draft202012Validator:
    common = _json(COMMON_SCHEMA)
    schema = _json(path)
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


def _approval(name: str) -> dict[str, Any]:
    return _json(VECTORS / "approval" / "valid" / f"{name}.json")


def _error(name: str) -> dict[str, Any]:
    return _json(VECTORS / "error" / "valid" / f"{name}.json")


def _action(name: str = "file-write") -> dict[str, Any]:
    return _json(VECTORS / "action" / "valid" / f"{name}.json")


def _resume_action(name: str) -> dict[str, Any]:
    return _json(VECTORS / "approval" / "resume" / f"{name}.json")


def _decision(name: str) -> dict[str, Any]:
    return _json(VECTORS / "decision" / "valid" / f"{name}.json")


def _resume(
    original: dict[str, Any],
    prior: dict[str, Any],
    approval: dict[str, Any],
    resumed: dict[str, Any],
    *,
    trusted_context: dict[str, str] | None = None,
    now: str = RESUME_NOW,
) -> None:
    validate.validate_resume_attempt(
        original,
        prior,
        approval,
        resumed,
        trusted_context=trusted_context or TRUSTED_CONTEXT,
        now=now,
    )


@pytest.fixture(scope="module")
def approval_validator() -> Draft202012Validator:
    return _validator(APPROVAL_SCHEMA)


@pytest.fixture(scope="module")
def error_validator() -> Draft202012Validator:
    return _validator(ERROR_SCHEMA)


def test_approval_and_error_schemas_are_strict_draft_2020_12() -> None:
    for path in (APPROVAL_SCHEMA, ERROR_SCHEMA):
        schema = _json(path)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False
        Draft202012Validator.check_schema(schema)


def test_committed_approval_vectors_have_expected_validity(
    approval_validator: Draft202012Validator,
) -> None:
    valid = sorted((VECTORS / "approval" / "valid").glob("*.json"))
    invalid = sorted((VECTORS / "approval" / "invalid").glob("*.json"))
    assert valid
    assert invalid
    for path in valid:
        assert _errors(approval_validator, _json(path)) == [], path
    for path in invalid:
        assert _errors(approval_validator, _json(path)), path


def test_committed_error_vectors_have_expected_validity(
    error_validator: Draft202012Validator,
) -> None:
    valid = sorted((VECTORS / "error" / "valid").glob("*.json"))
    invalid = sorted((VECTORS / "error" / "invalid").glob("*.json"))
    assert valid
    assert invalid
    for path in valid:
        assert _errors(error_validator, _json(path)) == [], path
    for path in invalid:
        assert _errors(error_validator, _json(path)), path


def test_approval_id_is_not_an_authorization_request_id(
    approval_validator: Draft202012Validator,
) -> None:
    approval = _approval("pending")
    approval["approvalId"] = "req_01J5ABCDEFGHJKMNPQRSTVWXY2"
    assert _errors(approval_validator, approval)


@pytest.mark.parametrize("status", ("approved", "denied", "expired", "cancelled"))
def test_pending_may_transition_to_each_terminal_status(status: str) -> None:
    previous = _approval("pending")
    proposed = _approval(status)
    revision = validate.approval_state_digest(previous)
    assert (
        validate.validate_approval_transition(
            previous,
            proposed,
            expected_state_digest=revision,
            now=(
                proposed["decidedAt"] if status == "expired" else "2026-07-25T20:05:00Z"
            ),
        )
        == "applied"
    )


def test_terminal_approval_decisions_are_idempotent_or_conflicting() -> None:
    terminal = _approval("approved")
    duplicate = deepcopy(terminal)
    duplicate["decidedAt"] = "2026-07-25T20:04:02Z"
    duplicate["resolutionAuditRef"] = "audit_01J5ABCDEFGHJKMNPQRSTVWXY8"
    assert (
        validate.validate_approval_transition(
            terminal,
            duplicate,
            expected_state_digest=validate.approval_state_digest(terminal),
            now="2026-07-25T20:18:01Z",
        )
        == "idempotent"
    )

    for field, value in (
        ("status", "denied"),
        ("reviewerRef", "subject:reviewer-8"),
        ("resolutionDecisionId", "dec_01J5ABCDEFGHJKMNPQRSTVWXY8"),
        ("resolutionReasonCode", "different_reason"),
        (
            "resolutionIdempotencyKey",
            "approval_01J5ABCDEFGHJKMNPQRSTVWXY8",
        ),
        (
            "extensions",
            {"dev.palonexus.test.v1": {"note": "Changed metadata."}},
        ),
    ):
        conflict = deepcopy(terminal)
        conflict[field] = value
        with pytest.raises(
            validate.ProtocolValidationError,
            match="idempotency_conflict",
        ):
            validate.validate_approval_transition(
                terminal,
                conflict,
                expected_state_digest=validate.approval_state_digest(terminal),
                now="2026-07-25T20:18:01Z",
            )


def test_pending_transition_requires_atomic_compare_and_swap_precondition() -> None:
    pending = _approval("pending")
    approved = _approval("approved")
    denied = _approval("denied")
    pending_revision = validate.approval_state_digest(pending)

    with pytest.raises(
        validate.ProtocolValidationError,
        match="idempotency_conflict",
    ):
        validate.validate_approval_transition(
            pending,
            approved,
            expected_state_digest=(
                "sha256:ffffffffffffffffffffffffffffffff"
                "ffffffffffffffffffffffffffffffff"
            ),
            now="2026-07-25T20:05:00Z",
        )

    assert (
        validate.validate_approval_transition(
            pending,
            approved,
            expected_state_digest=pending_revision,
            now="2026-07-25T20:05:00Z",
        )
        == "applied"
    )
    with pytest.raises(
        validate.ProtocolValidationError,
        match="idempotency_conflict",
    ):
        validate.validate_approval_transition(
            approved,
            denied,
            expected_state_digest=validate.approval_state_digest(approved),
            now="2026-07-25T20:18:01Z",
        )


def test_terminal_duplicate_is_idempotent_after_expiry_but_conflict_is_not() -> None:
    approved = _approval("approved")
    duplicate = deepcopy(approved)
    duplicate["decidedAt"] = "2026-07-25T21:00:00.123456789123456789Z"
    duplicate["resolutionAuditRef"] = "audit_01J5ABCDEFGHJKMNPQRSTVWXY8"
    revision = validate.approval_state_digest(approved)

    assert (
        validate.validate_approval_transition(
            approved,
            duplicate,
            expected_state_digest=revision,
            now="2026-07-25T21:00:00Z",
        )
        == "idempotent"
    )
    conflicting = deepcopy(duplicate)
    conflicting["resolutionReasonCode"] = "different_reason"
    with pytest.raises(
        validate.ProtocolValidationError,
        match="idempotency_conflict",
    ):
        validate.validate_approval_transition(
            approved,
            conflicting,
            expected_state_digest=revision,
            now="2026-07-25T21:00:00Z",
        )


def test_duplicate_pending_creation_returns_existing_approval_identity() -> None:
    existing = _approval("pending")
    proposed = deepcopy(existing)
    proposed["approvalId"] = "apr_01J5ABCDEFGHJKMNPQRSTVWXY8"

    resolved = validate.resolve_duplicate_approval_creation(existing, proposed)
    assert resolved == existing
    assert resolved["approvalId"] == existing["approvalId"]
    assert resolved["approvalId"] != proposed["approvalId"]


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("authorizationDecisionId", "dec_01J5ABCDEFGHJKMNPQRSTVWXY8"),
        ("actionId", "act_01J5ABCDEFGHJKMNPQRSTVWXY8"),
        ("correlationId", "corr_01J5ABCDEFGHJKMNPQRSTVWXY8"),
        (
            "authoritativeScopeHash",
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ),
        ("requesterRef", "subject:requester-8"),
    ),
)
def test_duplicate_pending_creation_conflicts_on_identity_change(
    field: str,
    replacement: str,
) -> None:
    existing = _approval("pending")
    proposed = deepcopy(existing)
    proposed["approvalId"] = "apr_01J5ABCDEFGHJKMNPQRSTVWXY8"
    proposed[field] = replacement

    with pytest.raises(
        validate.ProtocolValidationError,
        match="idempotency_conflict",
    ):
        validate.resolve_duplicate_approval_creation(existing, proposed)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("creationAuditRef", "audit_01J5ABCDEFGHJKMNPQRSTVWXY8"),
        ("requestedAt", "2026-07-25T20:02:02Z"),
        ("expiresAt", "2026-07-25T20:18:01Z"),
    ),
)
def test_duplicate_creation_ignores_regenerated_server_metadata(
    field: str,
    replacement: str,
) -> None:
    existing = _approval("pending")
    proposed = deepcopy(existing)
    proposed["approvalId"] = "apr_01J5ABCDEFGHJKMNPQRSTVWXY8"
    proposed[field] = replacement

    resolved = validate.resolve_duplicate_approval_creation(existing, proposed)
    assert resolved == existing
    assert resolved[field] == existing[field]
    assert resolved["approvalId"] == existing["approvalId"]


def test_duplicate_creation_cannot_bypass_approval_id_or_status_validation() -> None:
    existing = _approval("pending")
    malformed = deepcopy(existing)
    malformed["approvalId"] = "req_01J5ABCDEFGHJKMNPQRSTVWXY8"
    terminal = _approval("approved")

    with pytest.raises(validate.ProtocolValidationError, match="schema_invalid"):
        validate.resolve_duplicate_approval_creation(existing, malformed)
    with pytest.raises(validate.ProtocolValidationError, match="idempotency_conflict"):
        validate.resolve_duplicate_approval_creation(existing, terminal)


def test_approval_expiry_order_and_terminal_time_are_enforced() -> None:
    invalid = _approval("approved")
    invalid["decidedAt"] = invalid["expiresAt"]
    with pytest.raises(
        validate.ProtocolValidationError,
        match="approval_expired",
    ):
        validate.validate_approval_document(invalid)

    expired = _approval("expired")
    validate.validate_approval_document(expired)


def test_approval_vector_preserves_arbitrary_fractional_precision() -> None:
    precision = _approval("approved-arbitrary-precision")
    assert precision["decidedAt"].endswith("123456789123456789Z")
    validate.validate_approval_document(precision)


def test_resume_uses_new_attempt_ids_and_stable_action_ids() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")

    _resume(original, prior, approval, resumed)

    for field in ("requestId", "idempotencyKey"):
        same_attempt = deepcopy(resumed)
        same_attempt[field] = original[field]
        with pytest.raises(
            validate.ProtocolValidationError,
            match="invalid_request",
        ):
            _resume(original, prior, approval, same_attempt)


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("actionId",), "act_01J5ABCDEFGHJKMNPQRSTVWXY9"),
        (("correlationId",), "corr_01J5ABCDEFGHJKMNPQRSTVWXY9"),
        (("action",), "file:delete"),
        (("sideEffect",), "destructive"),
        (("adapter", "id"), "claude-code"),
        (("task", "taskId"), "task_01J5ABCDEFGHJKMNPQRSTVWXY9"),
        (
            ("target", "resource"),
            "path:/workspace/deploy/different-production.yaml",
        ),
    ),
)
def test_resume_rejects_action_mutation(
    path: tuple[str, ...],
    replacement: str,
) -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")
    current: dict[str, Any] = resumed
    for part in path[:-1]:
        child = current[part]
        assert isinstance(child, dict)
        current = child
    current[path[-1]] = replacement

    with pytest.raises(
        validate.ProtocolValidationError,
        match="approval_scope_mismatch",
    ):
        _resume(original, prior, approval, resumed)


def test_resume_requires_prior_decision_causation_and_approval_reference() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")

    resumed["causationId"] = "dec_01J5ABCDEFGHJKMNPQRSTVWXY9"
    with pytest.raises(validate.ProtocolValidationError, match="invalid_request"):
        _resume(original, prior, approval, resumed)

    resumed = _resume_action("valid")
    resumed["resumeFromApprovalId"] = "apr_01J5ABCDEFGHJKMNPQRSTVWXY9"
    with pytest.raises(validate.ProtocolValidationError, match="invalid_request"):
        _resume(original, prior, approval, resumed)


@pytest.mark.parametrize(
    ("path", "replacement", "error_code"),
    (
        (("requestId",), "req_01J5ABCDEFGHJKMNPQRSTVWXY9", "invalid_request"),
        (
            ("correlationId",),
            "corr_01J5ABCDEFGHJKMNPQRSTVWXY9",
            "approval_scope_mismatch",
        ),
        (
            ("approval", "approvalId"),
            "apr_01J5ABCDEFGHJKMNPQRSTVWXY9",
            "invalid_request",
        ),
        (("approval", "expiresAt"), "2026-07-25T20:18:01Z", "invalid_request"),
    ),
)
def test_resume_binds_prior_decision_and_approval_summary(
    path: tuple[str, ...],
    replacement: str,
    error_code: str,
) -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")
    current: dict[str, Any] = prior
    for part in path[:-1]:
        child = current[part]
        assert isinstance(child, dict)
        current = child
    current[path[-1]] = replacement

    with pytest.raises(validate.ProtocolValidationError, match=error_code):
        _resume(original, prior, approval, resumed)


def test_resume_rejects_cross_tenant_or_identity_scope_mutation() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")

    for field in ("tenantId", "actorId", "agentId", "delegationId", "clientId"):
        changed = dict(TRUSTED_CONTEXT)
        changed[field] = f"changed_{field}"
        with pytest.raises(
            validate.ProtocolValidationError,
            match="approval_scope_mismatch",
        ):
            _resume(
                original,
                prior,
                approval,
                resumed,
                trusted_context=changed,
            )


def test_resume_rejects_a_whole_action_swap_even_when_both_documents_match() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")
    for action in (original, resumed):
        action["action"] = "file:delete"
        action["sideEffect"] = "destructive"

    with pytest.raises(
        validate.ProtocolValidationError,
        match="approval_scope_mismatch",
    ):
        _resume(original, prior, approval, resumed)


def test_resume_binds_prior_client_and_authoritative_scope_hashes() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")

    for document, field in (
        (prior, "clientScopeHash"),
        (prior, "authoritativeScopeHash"),
        (approval, "authoritativeScopeHash"),
    ):
        changed = deepcopy(document)
        changed[field] = (
            "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        )
        changed_prior = changed if document is prior else prior
        changed_approval = changed if document is approval else approval
        with pytest.raises(
            validate.ProtocolValidationError,
            match="approval_scope_mismatch",
        ):
            _resume(
                original,
                changed_prior,
                changed_approval,
                resumed,
            )


def test_resume_cannot_extend_the_approval_summary_expiry() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")
    approval["expiresAt"] = "2026-07-25T20:18:01Z"

    with pytest.raises(validate.ProtocolValidationError, match="invalid_request"):
        _resume(original, prior, approval, resumed)


def test_resume_binds_creation_audit_to_prior_decision() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")
    approval["creationAuditRef"] = "audit_01J5ABCDEFGHJKMNPQRSTVWXY8"

    with pytest.raises(validate.ProtocolValidationError, match="invalid_request"):
        _resume(original, prior, approval, resumed)


def test_resume_rejects_an_approval_decided_in_trusted_times_future() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")

    with pytest.raises(validate.ProtocolValidationError, match="invalid_decision"):
        _resume(
            original,
            prior,
            approval,
            resumed,
            now="2026-07-25T20:04:00.999999999999999999Z",
        )

    _resume(
        original,
        prior,
        approval,
        resumed,
        now=approval["decidedAt"],
    )


def test_resume_expiry_uses_trusted_now_and_occurred_at_is_audit_only() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")
    resumed["occurredAt"] = "2026-07-25T20:18:01Z"

    _resume(original, prior, approval, resumed, now="2026-07-25T20:17:00Z")

    with pytest.raises(validate.ProtocolValidationError, match="approval_expired"):
        _resume(original, prior, approval, resumed, now=approval["expiresAt"])


def test_resume_trusted_now_uses_exact_arbitrary_fractional_precision() -> None:
    original = _resume_action("original")
    prior = _decision("approval-required")
    approval = _approval("approved")
    resumed = _resume_action("valid")
    approval["expiresAt"] = "2026-07-25T20:17:01.123456789123456789Z"
    prior["approval"]["expiresAt"] = approval["expiresAt"]

    _resume(
        original,
        prior,
        approval,
        resumed,
        now="2026-07-25T20:17:01.123456789123456788Z",
    )
    with pytest.raises(validate.ProtocolValidationError, match="approval_expired"):
        _resume(
            original,
            prior,
            approval,
            resumed,
            now="2026-07-25T20:17:01.123456789123456789Z",
        )
    with pytest.raises(validate.ProtocolValidationError, match="timestamp_invalid"):
        _resume(original, prior, approval, resumed, now="not-server-time")


def test_error_codes_and_retryability_are_stable(
    error_validator: Draft202012Validator,
) -> None:
    expected_codes = {
        "invalid_request",
        "missing_identity",
        "unsupported_protocol",
        "authentication_failed",
        "authorization_unavailable",
        "invalid_decision",
        "idempotency_conflict",
        "approval_expired",
        "approval_scope_mismatch",
        "credential_revoked",
        "policy_denied",
    }
    assert set(error_validator.schema["properties"]["code"]["enum"]) == expected_codes
    assert set(validate.ERROR_SAFE_MESSAGES) == expected_codes
    for code in expected_codes:
        error = {
            "schemaVersion": "1",
            "code": code,
            "safeMessage": validate.ERROR_SAFE_MESSAGES[code],
            "retryable": code == "authorization_unavailable",
        }
        assert _errors(error_validator, error) == []
        error["safeMessage"] = "A caller-selected message."
        assert _errors(error_validator, error)

    unavailable = _error("authorization-unavailable")
    assert unavailable["code"] == "authorization_unavailable"
    assert unavailable["retryable"] is True

    mismatch = _error("approval-scope-mismatch")
    assert mismatch["code"] == "approval_scope_mismatch"
    assert mismatch["retryable"] is False

    mismatch["retryable"] = True
    assert _errors(error_validator, mismatch)


def test_cross_language_error_message_vector_matches_public_registry() -> None:
    vector = _json(ERROR_MESSAGE_VECTOR)
    assert vector["schemaVersion"] == "1"
    assert vector["registeredExtensionKeys"] == []
    assert vector["messages"] == dict(validate.ERROR_SAFE_MESSAGES)


def test_error_and_approval_references_never_accept_email_or_token_fields(
    approval_validator: Draft202012Validator,
    error_validator: Draft202012Validator,
) -> None:
    approval = _approval("approved")
    approval["reviewerRef"] = "reviewer@example.com"
    assert _errors(approval_validator, approval)
    approval = _approval("approved")
    approval["reviewerEmail"] = "reviewer@example.com"
    assert _errors(approval_validator, approval)

    error = _error("authorization-unavailable")
    error["token"] = "secret"
    assert _errors(error_validator, error)


@pytest.mark.parametrize(
    "unsafe_value",
    (
        "reviewer" + chr(64) + "example.test",
        "Bearer " + ("A" * 48),
        "api" + "_key=" + ("B" * 48),
        "sk" + "_" + ("C" * 48),
        "https://user:password" + chr(64) + "example.test/resource",
        "curl https://example.test/resource",
        "eyJ" + ("A" * 36) + "." + ("B" * 36) + "." + ("C" * 36),
        "".join(
            [chr(code) for code in range(ord("0"), ord("9") + 1)]
            + [chr(code) for code in range(ord("A"), ord("Z") + 1)]
            + [chr(code) for code in range(ord("a"), ord("z") + 1)]
        ),
        "safe" + "\u202e" + "hidden",
    ),
)
def test_error_safe_message_and_extensions_reject_sensitive_values(
    unsafe_value: str,
) -> None:
    for location in ("safeMessage", "extensions"):
        error = _error("authorization-unavailable")
        if location == "safeMessage":
            error["safeMessage"] = unsafe_value
        else:
            error["extensions"] = {"dev.palonexus.test.v1": {"detail": unsafe_value}}
        with pytest.raises(validate.ProtocolValidationError):
            validate.validate_error_document(error)


def test_error_extensions_reject_deep_unregistered_content() -> None:
    error = _error("authorization-unavailable")
    root: dict[str, Any] = {}
    current = root
    for index in range(40):
        child: dict[str, Any] = {}
        current[f"level{index}"] = child
        current = child
    current["detail"] = "Unavailable."
    error["extensions"] = {"dev.palonexus.test.v1": root}

    with pytest.raises(
        validate.ProtocolValidationError,
        match="schema_invalid",
    ):
        validate.validate_error_document(error)


def test_error_extensions_reject_sensitive_property_names() -> None:
    error = _error("authorization-unavailable")
    sensitive_key = "api" + "Key"
    error["extensions"] = {"dev.palonexus.test.v1": {sensitive_key: "Redacted."}}

    with pytest.raises(
        validate.ProtocolValidationError,
        match="schema_invalid",
    ):
        validate.validate_error_document(error)


def test_error_extensions_reject_even_safe_freeform_fields_in_v1() -> None:
    error = _error("authorization-unavailable")
    error["extensions"] = {
        "dev.palonexus.test.v1": {"status": "temporarily_unavailable"}
    }

    with pytest.raises(
        validate.ProtocolValidationError,
        match="schema_invalid",
    ):
        validate.validate_error_document(error)


def test_error_renderer_contract_requires_context_appropriate_escaping() -> None:
    text = " ".join(ERROR_SAFETY.read_text(encoding="utf-8").lower().split())
    for phrase in (
        "safeMessage",
        "html escape",
        "terminal",
        "never evaluate",
        "exact fractional digits",
        "time.time",
        "atomic compare-and-swap",
        "canonical safe message registry",
        "no registered error extension keys",
        "schema and version review",
    ):
        assert phrase.lower() in text


def test_public_approval_and_error_vectors_contain_no_email_or_token_values() -> None:
    forbidden_keys = {"credential", "email", "password", "token"}
    stack: list[Any] = []
    for family in ("approval", "error"):
        for path in sorted((VECTORS / family).rglob("*.json")):
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


def test_public_validators_cover_approval_and_error_documents() -> None:
    validate.validate_approval_document(_approval("pending"))
    validate.validate_error_document(_error("authorization-unavailable"))
