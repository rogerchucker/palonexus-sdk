# SPDX-License-Identifier: MIT
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from palonexus.developer import (
    CapabilityCeilingRequest,
    CreateActionRequest,
    DeveloperAction,
    DeveloperAgentRegistration,
    ExactActionLeafAuthority,
    developer_canonical_json_bytes,
    developer_payload_sha256,
)
from palonexus.errors import ModelValidationError

FIXTURE = Path(__file__).parent / "fixtures/developer-api-v1.json"
SCHEMA = Path(__file__).parents[2] / "contracts/developer/v1.schema.json"


def _fixture() -> dict[str, object]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _reject(model: type, value: object) -> None:
    with pytest.raises(ModelValidationError):
        model.model_validate(value)


def test_canonical_platform_vector_validates_without_platform_imports() -> None:
    fixture = _fixture()
    for key, model in {
        "developer_agent_registration": DeveloperAgentRegistration,
        "capability_ceiling_request": CapabilityCeilingRequest,
        "create_action_request": CreateActionRequest,
        "developer_action": DeveloperAction,
        "exact_action_leaf_authority_v3": ExactActionLeafAuthority,
    }.items():
        value = fixture[key]
        assert model.model_validate(value).model_dump(mode="json") == value


def test_contracts_are_immutable_strict_and_closed() -> None:
    fixture = _fixture()
    registration = DeveloperAgentRegistration.model_validate(
        fixture["developer_agent_registration"]
    )
    with pytest.raises(ModelValidationError):
        registration.name = "changed"

    for key, model in {
        "developer_agent_registration": DeveloperAgentRegistration,
        "capability_ceiling_request": CapabilityCeilingRequest,
        "create_action_request": CreateActionRequest,
        "developer_action": DeveloperAction,
        "exact_action_leaf_authority_v3": ExactActionLeafAuthority,
    }.items():
        value = copy.deepcopy(fixture[key])
        value["unknown"] = True
        _reject(model, value)


def test_public_jwk_and_detached_proof_are_bounded_and_non_authoritative() -> None:
    original = _fixture()["developer_agent_registration"]
    for container, field, replacement in (
        ("public_key_jwk", "kty", "EC"),
        ("public_key_jwk", "crv", "X25519"),
        ("public_key_jwk", "x", "not-base64"),
        ("public_key_jwk", "d", "private"),
        ("public_key_jwk", "jku", "https://caller.example/jwks"),
        ("proof", "signature", "short"),
        ("proof", "audience", "agent-idp"),
        ("proof", "endpoint", "https://caller.example"),
    ):
        value = copy.deepcopy(original)
        value[container][field] = replacement
        _reject(DeveloperAgentRegistration, value)


def test_ceiling_rules_reject_duplicates_and_routing_authority() -> None:
    original = _fixture()["capability_ceiling_request"]
    duplicate = copy.deepcopy(original)
    duplicate["rules"].append(copy.deepcopy(duplicate["rules"][0]))
    _reject(CapabilityCeilingRequest, duplicate)
    for field in (
        "tenant_id",
        "endpoint",
        "audience",
        "scope",
        "profile_id",
        "routing",
    ):
        value = copy.deepcopy(original)
        value["rules"][0][field] = "caller-owned"
        _reject(CapabilityCeilingRequest, value)


def test_action_request_cannot_supply_server_ids_or_routing_authority() -> None:
    original = _fixture()["create_action_request"]
    for field in (
        "run_id",
        "root_action_id",
        "action_id",
        "tenant_id",
        "endpoint",
        "audience",
        "scope",
        "profile_id",
        "target_version",
        "routing",
    ):
        value = copy.deepcopy(original)
        value[field] = "caller-owned"
        _reject(CreateActionRequest, value)
    action = DeveloperAction.model_validate(_fixture()["developer_action"])
    assert action.run_id == "run-demo-1"
    assert action.request.model_dump(mode="json") == original


def test_ids_digests_and_canonical_json_fail_closed() -> None:
    original = _fixture()["create_action_request"]
    for field, replacement in (
        ("agent_id", " agent-demo-1"),
        ("lease_id", "lease/demo"),
        ("idempotency_key", "x" * 129),
        ("descriptor_digest", "A" * 64),
        ("input_digest", "0" * 63),
        ("payload_digest", "f" * 64),
        ("canonical_action", "Release.Publish"),
    ):
        value = copy.deepcopy(original)
        value[field] = replacement
        _reject(CreateActionRequest, value)
    nonfinite = copy.deepcopy(original)
    nonfinite["payload"] = {"score": float("nan")}
    _reject(CreateActionRequest, nonfinite)


def test_exact_action_v2_rejects_v1_downgrade_and_wrong_profile() -> None:
    fixture = _fixture()
    _reject(ExactActionLeafAuthority, fixture["exact_leaf_authority_v1"])
    original = fixture["exact_action_leaf_authority_v3"]
    for field, replacement in (
        ("schema_version", "1"),
        ("authority_profile", "customer-runtime-v1"),
        ("action_id", " action-demo-1"),
        ("payload_digest", "A" * 64),
        ("effect_idempotency_key", "x" * 129),
        ("agent_generation", 0),
        ("proxy_proof_key_thumbprint", "not-a-digest"),
    ):
        value = copy.deepcopy(original)
        value[field] = replacement
        _reject(ExactActionLeafAuthority, value)


def test_exact_action_v2_validates_all_shared_v1_leaf_fields() -> None:
    original = _fixture()["exact_action_leaf_authority_v3"]
    for field, replacement in (
        ("delegation_id", ""),
        ("tenant_id", ""),
        ("action_approver", ""),
        ("approval_ref", ""),
    ):
        value = copy.deepcopy(original)
        value[field] = replacement
        _reject(ExactActionLeafAuthority, value)

    target_mismatch = copy.deepcopy(original)
    target_mismatch["target"]["canonical_action"] = "release.assessment.read"
    _reject(ExactActionLeafAuthority, target_mismatch)

    reversed_expiry = copy.deepcopy(original)
    reversed_expiry["expires_at"] = reversed_expiry["issued_at"]
    _reject(ExactActionLeafAuthority, reversed_expiry)

    optional_absent = copy.deepcopy(original)
    optional_absent["action_approver"] = None
    optional_absent["approval_ref"] = None
    assert ExactActionLeafAuthority.model_validate(optional_absent).approval_ref is None


def test_ceiling_rule_and_constraint_cardinality_boundaries() -> None:
    original = _fixture()["capability_ceiling_request"]
    at_rule_limit = copy.deepcopy(original)
    at_rule_limit["rules"] = []
    for index in range(1024):
        rule = copy.deepcopy(original["rules"][0])
        rule["resource"] = f"release/r{index}"
        at_rule_limit["rules"].append(rule)
    assert len(CapabilityCeilingRequest.model_validate(at_rule_limit).rules) == 1024

    over_rule_limit = copy.deepcopy(at_rule_limit)
    extra = copy.deepcopy(original["rules"][0])
    extra["resource"] = "release/r1024"
    over_rule_limit["rules"].append(extra)
    _reject(CapabilityCeilingRequest, over_rule_limit)

    at_constraint_limit = copy.deepcopy(original)
    at_constraint_limit["rules"][0]["constraints"] = {
        f"constraint_{index}": index for index in range(1024)
    }
    assert (
        len(
            CapabilityCeilingRequest.model_validate(at_constraint_limit)
            .rules[0]
            .constraints
        )
        == 1024
    )
    over_constraint_limit = copy.deepcopy(at_constraint_limit)
    over_constraint_limit["rules"][0]["constraints"]["constraint_1024"] = 1024
    _reject(CapabilityCeilingRequest, over_constraint_limit)


def test_json_processable_byte_boundary_matches_platform() -> None:
    fixture = _fixture()
    max_bytes = 1_048_576
    at_limit = {"x": "a" * (max_bytes - 8)}
    over_limit = {"x": "a" * (max_bytes - 7)}

    ceiling = copy.deepcopy(fixture["capability_ceiling_request"])
    ceiling["rules"][0]["constraints"] = at_limit
    assert CapabilityCeilingRequest.model_validate(ceiling)
    ceiling["rules"][0]["constraints"] = over_limit
    _reject(CapabilityCeilingRequest, ceiling)

    action = copy.deepcopy(fixture["create_action_request"])
    action["payload"] = at_limit
    action["payload_digest"] = hashlib.sha256(
        json.dumps(at_limit, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    assert CreateActionRequest.model_validate(action)
    action["payload"] = over_limit
    action["payload_digest"] = hashlib.sha256(
        json.dumps(over_limit, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    _reject(CreateActionRequest, action)


def test_exact_action_target_registration_matches_platform_contract() -> None:
    original = _fixture()["exact_action_leaf_authority_v3"]
    for field in (
        "registration_id",
        "target",
        "canonical_action",
        "audience",
        "downstream_scope",
    ):
        for replacement in ("", " padded"):
            value = copy.deepcopy(original)
            value["target"][field] = replacement
            _reject(ExactActionLeafAuthority, value)
    for field, replacement in (
        ("target_kind", " artifact"),
        ("version", 0),
        ("mapping_hash", "A" * 64),
        ("endpoint", "https://caller.example"),
    ):
        value = copy.deepcopy(original)
        value["target"][field] = replacement
        _reject(ExactActionLeafAuthority, value)


def test_rfc8785_canonical_vectors_and_interoperable_number_domain() -> None:
    fixture = _fixture()
    for vector in fixture["canonical_json_vectors"]:
        canonical = developer_canonical_json_bytes(vector["value"])
        assert canonical.decode("utf-8") == vector["canonical_utf8"]
        assert hashlib.sha256(canonical).hexdigest() == vector["sha256"]
        assert developer_payload_sha256(vector["value"]) == vector["sha256"]

    action = copy.deepcopy(fixture["create_action_request"])
    for invalid in (9_007_199_254_740_992, float("nan"), float("inf")):
        action["payload"] = {"value": invalid}
        action["payload_digest"] = "0" * 64
        _reject(CreateActionRequest, action)


def test_public_json_entry_points_reject_duplicates_with_typed_errors() -> None:
    raw = json.dumps(_fixture()["developer_agent_registration"])
    for invalid in (
        raw[:-1] + ',"name":"other"}',
        raw.replace('"kty": "OKP"', '"kty": "OKP", "kty": "OKP"', 1),
    ):
        with pytest.raises(ModelValidationError):
            DeveloperAgentRegistration.model_validate_json(invalid)

    with pytest.raises(ModelValidationError):
        DeveloperAgentRegistration.model_validate_strings({"unknown": "value"})


def test_runtime_and_schema_reject_wire_coercions_and_bad_timestamps() -> None:
    fixture = _fixture()
    validator = Draft202012Validator(
        json.loads(SCHEMA.read_text(encoding="utf-8")),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    corpus = []
    bytes_id = copy.deepcopy(fixture["create_action_request"])
    bytes_id["agent_id"] = b"agent-demo-1"
    corpus.append((CreateActionRequest, bytes_id))
    integer_time = copy.deepcopy(fixture["exact_action_leaf_authority_v3"])
    integer_time["issued_at"] = 1_660_000_000
    corpus.append((ExactActionLeafAuthority, integer_time))
    invalid_time = copy.deepcopy(fixture["exact_action_leaf_authority_v3"])
    invalid_time["expires_at"] = "not-a-time"
    corpus.append((ExactActionLeafAuthority, invalid_time))
    for model, value in corpus:
        _reject(model, value)
        assert not validator.is_valid(value)


def test_ed25519_base64url_requires_canonical_unpadded_encoding() -> None:
    original = _fixture()["developer_agent_registration"]
    for container, field in (("public_key_jwk", "x"), ("proof", "signature")):
        canonical = original[container][field]
        for alias in (canonical + "=", canonical[:-1] + "B"):
            value = copy.deepcopy(original)
            value[container][field] = alias
            _reject(DeveloperAgentRegistration, value)


def test_exact_action_timestamps_match_schema_rfc3339_grammar() -> None:
    fixture = _fixture()
    validator = Draft202012Validator(
        json.loads(SCHEMA.read_text(encoding="utf-8")),
        format_checker=Draft202012Validator.FORMAT_CHECKER,
    )
    original = fixture["exact_action_leaf_authority_v3"]
    for timestamp in fixture["timestamp_vectors"]["valid"]:
        value = copy.deepcopy(original)
        value["issued_at"] = timestamp
        value["expires_at"] = "2027-08-12T12:00:00Z"
        assert ExactActionLeafAuthority.model_validate(value)
        assert validator.is_valid(value)
    for timestamp in fixture["timestamp_vectors"]["invalid"]:
        value = copy.deepcopy(original)
        value["issued_at"] = timestamp
        _reject(ExactActionLeafAuthority, value)
        assert not validator.is_valid(value)


def test_developer_copy_apis_validate_and_preserve_frozen_json() -> None:
    original = CreateActionRequest.model_validate(_fixture()["create_action_request"])
    shallow = copy.copy(original)
    deep = copy.deepcopy(original)
    updated = original.model_copy(update={"idempotency_key": "effect-copy-1"})
    legacy = original.copy(update={"idempotency_key": "effect-copy-2"})
    expected_payload = original.model_dump(mode="json")["payload"]

    for candidate in (shallow, deep, updated, legacy):
        assert candidate.model_dump(mode="json")["payload"] == expected_payload
        with pytest.raises(TypeError):
            candidate.payload["assessment"] = "changed"
    assert (
        original.idempotency_key
        == _fixture()["create_action_request"]["idempotency_key"]
    )
    assert updated.idempotency_key == "effect-copy-1"
    assert legacy.idempotency_key == "effect-copy-2"
    with pytest.raises(ModelValidationError):
        original.model_copy(update={"payload_digest": "bad"})
