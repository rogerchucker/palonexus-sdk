from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource

from protocol.reference import canonicalize

ROOT = Path(__file__).parents[1]
SCHEMAS = ROOT / "schemas"
VECTORS = ROOT / "test-vectors"
COMMON_SCHEMA = SCHEMAS / "common-v1.schema.json"
ACTION_SCHEMA = SCHEMAS / "action-v1.schema.json"
DECISION_SCHEMA = SCHEMAS / "decision-v1.schema.json"


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict), path
    return value


def _validator(path: Path) -> Draft202012Validator:
    common = _read_json(COMMON_SCHEMA)
    schema = _read_json(path)
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


@pytest.fixture(scope="module")
def action_validator() -> Draft202012Validator:
    return _validator(ACTION_SCHEMA)


@pytest.fixture(scope="module")
def decision_validator() -> Draft202012Validator:
    return _validator(DECISION_SCHEMA)


def test_schemas_are_strict_json_schema_2020_12_documents() -> None:
    for path in (COMMON_SCHEMA, ACTION_SCHEMA, DECISION_SCHEMA):
        schema = _read_json(path)
        assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        assert schema["additionalProperties"] is False
        Draft202012Validator.check_schema(schema)


def test_all_valid_action_vectors_conform(
    action_validator: Draft202012Validator,
) -> None:
    vectors = sorted((VECTORS / "action" / "valid").glob("*.json"))
    assert vectors
    for path in vectors:
        assert _errors(action_validator, _read_json(path)) == [], path


def test_all_invalid_action_vectors_fail_closed(
    action_validator: Draft202012Validator,
) -> None:
    vectors = sorted((VECTORS / "action" / "invalid").glob("*.json"))
    assert vectors
    for path in vectors:
        assert _errors(action_validator, _read_json(path)), path


@pytest.mark.parametrize("action_name", ("file:read", "file:write", "file:delete"))
@pytest.mark.parametrize(
    "resource",
    (
        "workspace:/deploy/../secret",
        "path:/workspace\\secret",
        "path:/workspace/./secret",
        "path:/workspace/deploy/../secret",
    ),
)
def test_file_actions_reject_noncanonical_path_resources_even_with_matching_hash(
    action_validator: Draft202012Validator,
    action_name: str,
    resource: str,
) -> None:
    action = _read_json(VECTORS / "action" / "valid" / "file-write.json")
    action["action"] = action_name
    target = action["target"]
    assert isinstance(target, dict)
    target["resource"] = resource
    target["resourceHash"] = canonicalize.computed_resource_hash(target)

    assert _errors(action_validator, action)


@pytest.mark.parametrize("action_name", ("file:read", "file:write", "file:delete"))
def test_file_actions_accept_canonical_path_resources(
    action_validator: Draft202012Validator,
    action_name: str,
) -> None:
    action = _read_json(VECTORS / "action" / "valid" / "file-write.json")
    action["action"] = action_name

    assert _errors(action_validator, action) == []


def test_shell_action_accepts_backslash_resource(
    action_validator: Draft202012Validator,
) -> None:
    action = _read_json(VECTORS / "action" / "valid" / "file-write.json")
    action["action"] = "shell:exec"
    prepared = canonicalize.prepare_shell_resource('echo "a\\q"')
    target = action["target"]
    assert isinstance(target, dict)
    target["resource"] = prepared.resource
    target["resourceHash"] = canonicalize.computed_resource_hash(target)

    assert _errors(action_validator, action) == []


def test_all_valid_decision_vectors_conform(
    decision_validator: Draft202012Validator,
) -> None:
    vectors = sorted((VECTORS / "decision" / "valid").glob("*.json"))
    assert vectors
    for path in vectors:
        assert _errors(decision_validator, _read_json(path)) == [], path


def test_all_invalid_decision_vectors_fail_closed(
    decision_validator: Draft202012Validator,
) -> None:
    vectors = sorted((VECTORS / "decision" / "invalid").glob("*.json"))
    assert vectors
    for path in vectors:
        assert _errors(decision_validator, _read_json(path)), path


@pytest.mark.parametrize(
    "field",
    (
        "actionId",
        "requestId",
        "correlationId",
        "idempotencyKey",
        "adapter",
        "task",
        "action",
        "target",
        "sideEffect",
        "occurredAt",
        "context",
    ),
)
def test_action_requires_its_security_relevant_fields(
    action_validator: Draft202012Validator,
    field: str,
) -> None:
    action = _read_json(VECTORS / "action" / "valid" / "file-write.json")
    action.pop(field)
    assert _errors(action_validator, action)


def test_adapter_label_is_diagnostic_and_cannot_select_trusted_identity(
    action_validator: Draft202012Validator,
) -> None:
    action = _read_json(VECTORS / "action" / "valid" / "file-write.json")
    assert (
        "diagnostic"
        in action_validator.schema["properties"]["adapter"]["description"].lower()
    )
    assert (
        "non-authoritative"
        in action_validator.schema["properties"]["adapter"]["description"].lower()
    )

    action["adapter"]["clientId"] = "privileged-client"
    assert _errors(action_validator, action)
    action["clientId"] = "privileged-client"
    assert _errors(action_validator, action)


@pytest.mark.parametrize(
    ("action_name", "target_kind"),
    (
        ("shell:exec", "local-action"),
        ("file:read", "local-action"),
        ("file:write", "local-action"),
        ("file:delete", "local-action"),
        ("web:fetch", "local-action"),
        ("mcp:call", "mcp-tool"),
        ("tool:invoke", "tool"),
    ),
)
def test_initial_action_taxonomy_binds_target_kind(
    action_validator: Draft202012Validator,
    action_name: str,
    target_kind: str,
) -> None:
    action = _read_json(VECTORS / "action" / "valid" / "file-write.json")
    action["action"] = action_name
    action["target"]["kind"] = target_kind
    assert _errors(action_validator, action) == []

    action["target"]["kind"] = "tool" if target_kind != "tool" else "local-action"
    assert _errors(action_validator, action)


@pytest.mark.parametrize("field", ("clientScopeHash", "authoritativeScopeHash"))
def test_decision_requires_both_scope_hash_fields(
    decision_validator: Draft202012Validator,
    field: str,
) -> None:
    decision = _read_json(VECTORS / "decision" / "valid" / "allow.json")
    decision.pop(field)
    assert _errors(decision_validator, decision)


def test_missing_authenticated_identity_is_a_fail_closed_deny(
    decision_validator: Draft202012Validator,
) -> None:
    decision = _read_json(VECTORS / "decision" / "valid" / "deny-missing-identity.json")
    assert decision["outcome"] == "deny"
    assert decision["reasonCode"] == "missing_identity"
    assert _errors(decision_validator, decision) == []


def test_decision_time_format_is_structurally_enforced(
    decision_validator: Draft202012Validator,
) -> None:
    decision = _read_json(VECTORS / "decision" / "valid" / "allow.json")
    decision["serverTime"] = "not-a-time"
    assert _errors(decision_validator, decision)


@pytest.mark.parametrize("outcome", ("allow", "deny"))
def test_only_approval_required_may_include_approval(
    decision_validator: Draft202012Validator,
    outcome: str,
) -> None:
    decision = _read_json(VECTORS / "decision" / "valid" / "approval-required.json")
    decision["outcome"] = outcome
    assert _errors(decision_validator, decision)

    without_approval = deepcopy(decision)
    without_approval.pop("approval")
    assert _errors(decision_validator, without_approval) == []


def test_public_v1_decisions_never_authorize_from_an_offline_allow_cache(
    decision_validator: Draft202012Validator,
) -> None:
    decision = _read_json(VECTORS / "decision" / "valid" / "allow.json")
    decision["cache"]["cacheable"] = True
    assert _errors(decision_validator, decision)


def test_unknown_top_level_security_fields_are_rejected(
    action_validator: Draft202012Validator,
    decision_validator: Draft202012Validator,
) -> None:
    action = _read_json(VECTORS / "action" / "valid" / "file-write.json")
    action["tenant"] = "caller-selected"
    assert _errors(action_validator, action)

    decision = _read_json(VECTORS / "decision" / "valid" / "allow.json")
    decision["effectiveClientId"] = "caller-selected"
    assert _errors(decision_validator, decision)
