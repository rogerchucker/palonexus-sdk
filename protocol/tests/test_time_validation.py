from __future__ import annotations

import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any

import pytest

from protocol.reference import validate

PROTOCOL = Path(__file__).parents[1]
ROOT = PROTOCOL.parent
VECTORS = PROTOCOL / "test-vectors"
RULES = PROTOCOL / "validation-v1.md"


def _json(path: Path) -> dict[str, Any]:
    value = validate.loads_json_strict(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _action() -> dict[str, Any]:
    return _json(VECTORS / "action" / "valid" / "file-write.json")


def _decision() -> dict[str, Any]:
    return _json(VECTORS / "decision" / "valid" / "allow.json")


def _schema_patterns(value: Any) -> list[str]:
    patterns: list[str] = []
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if key == "pattern":
                    assert isinstance(child, str)
                    patterns.append(child)
                else:
                    stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
    return patterns


def test_public_validator_has_task5_document_api() -> None:
    validate.validate_action_document(_action())
    validate.validate_decision_document(_decision())


def test_invalid_time_order_is_rejected_by_public_validator() -> None:
    decision = _json(
        VECTORS / "decision" / "semantic-invalid" / "invalid-time-order.json"
    )

    with pytest.raises(validate.ProtocolValidationError, match="decision_expiry_order"):
        validate.validate_decision_document(decision)


@pytest.mark.parametrize(
    ("server_time", "expires_at"),
    (
        ("2026-07-25T20:00:00Z", "2026-07-25T20:00:01Z"),
        ("2026-07-25T20:00:00.123Z", "2026-07-25T20:00:01.123Z"),
        ("2026-07-25T20:00:00+05:30", "2026-07-25T20:00:01+05:30"),
    ),
)
def test_strict_rfc3339_z_and_offset_forms_are_accepted(
    server_time: str, expires_at: str
) -> None:
    decision = _decision()
    decision["serverTime"] = server_time
    decision["expiresAt"] = expires_at

    validate.validate_decision_document(decision)


@pytest.mark.parametrize(
    "timestamp",
    (
        "2026-02-30T20:00:00Z",
        "2026-07-25 20:00:00Z",
        "2026-07-25t20:00:00z",
        "2026-07-25T20:00:00",
        "2026-07-25T20:00:00+2400",
        "2026-07-25T20:00:00+24:00",
        "2026-07-25T20:00:00+00:60",
        "2026-07-25T20:00:00Z\n",
    ),
)
def test_invalid_rfc3339_values_fail_closed(timestamp: str) -> None:
    decision = _decision()
    decision["serverTime"] = timestamp

    with pytest.raises(validate.ProtocolValidationError):
        validate.validate_decision_document(decision)


def test_every_task5_timestamp_is_strictly_parsed() -> None:
    action = _action()
    action["occurredAt"] = "2026-02-30T20:00:00Z"
    with pytest.raises(validate.ProtocolValidationError, match="timestamp_invalid"):
        validate.validate_action_document(action)

    decision = _decision()
    decision["expiresAt"] = "2026-02-30T20:00:01Z"
    with pytest.raises(validate.ProtocolValidationError, match="timestamp_invalid"):
        validate.validate_decision_document(decision)

    decision = _json(VECTORS / "decision" / "valid" / "approval-required.json")
    decision["approval"]["expiresAt"] = "2026-02-30T20:17:01Z"
    with pytest.raises(validate.ProtocolValidationError, match="timestamp_invalid"):
        validate.validate_decision_document(decision)


@pytest.mark.parametrize(
    ("server_time", "expires_at"),
    (
        (
            "2026-07-25T20:00:00.123456789123Z",
            "2026-07-25T20:00:00.123456789124Z",
        ),
        (
            "2026-07-25T20:00:00.999999999+01:00",
            "2026-07-25T19:00:01.000000000Z",
        ),
    ),
)
def test_arbitrary_fractional_precision_is_compared_exactly(
    server_time: str,
    expires_at: str,
) -> None:
    decision = _decision()
    decision["serverTime"] = server_time
    decision["expiresAt"] = expires_at
    validate.validate_decision_document(decision)


def test_action_accepts_arbitrary_fractional_precision() -> None:
    action = _action()
    action["occurredAt"] = "2026-07-25T20:00:00.123456789123456789Z"
    validate.validate_action_document(action)


@pytest.mark.parametrize(
    ("server_time", "expires_at"),
    (
        (
            "2026-07-25T20:00:00.123456789123Z",
            "2026-07-25T20:00:00.123456789123Z",
        ),
        ("2026-07-25T20:00:00.1Z", "2026-07-25T20:00:00.100000000Z"),
        ("2026-07-25T20:00:00.2Z", "2026-07-25T20:00:00.1999999999Z"),
    ),
)
def test_arbitrary_fractional_equality_or_reverse_order_is_rejected(
    server_time: str,
    expires_at: str,
) -> None:
    decision = _decision()
    decision["serverTime"] = server_time
    decision["expiresAt"] = expires_at
    with pytest.raises(validate.ProtocolValidationError, match="decision_expiry_order"):
        validate.validate_decision_document(decision)


def test_structural_invalid_vectors_fail_closed() -> None:
    for path in sorted((VECTORS / "action" / "invalid").glob("*.json")):
        with pytest.raises(validate.ProtocolValidationError):
            validate.validate_action_document(_json(path))
    for path in sorted((VECTORS / "decision" / "invalid").glob("*.json")):
        with pytest.raises(validate.ProtocolValidationError):
            validate.validate_decision_document(_json(path))


@pytest.mark.parametrize(
    ("document_kind", "path", "value"),
    (
        ("action", "actionId", "act_01J5ABCDEFGHJKMNPQRSTVWXY0\n"),
        ("action", "target.service", "../admin"),
        ("action", "adapter.version", "1.0.0-01"),
        ("action", "context.safeDisplay", "safe\u202ehidden"),
        ("action", "context.safeDisplay", "safe\u2028hidden"),
        ("decision", "displayReason", "safe\u0085hidden"),
        ("decision", "displayReason", "safe\u2029hidden"),
        ("decision", "reasonCode", "policy_allowed\u001b"),
    ),
)
def test_controls_traversal_and_ambiguous_strings_are_rejected(
    document_kind: str, path: str, value: str
) -> None:
    document = _action() if document_kind == "action" else _decision()
    current = document
    parts = path.split(".")
    for part in parts[:-1]:
        nested = current[part]
        assert isinstance(nested, dict)
        current = nested
    current[parts[-1]] = value

    validator = (
        validate.validate_action_document
        if document_kind == "action"
        else validate.validate_decision_document
    )
    with pytest.raises(validate.ProtocolValidationError, match="schema_invalid"):
        validator(document)


@pytest.mark.parametrize("property_name", ("bad key", "x" * 129))
def test_recursive_extension_property_names_are_bounded_and_safe(
    property_name: str,
) -> None:
    action = _action()
    action["extensions"]["dev.palonexus.example.v1"] = {
        "valid": {"nested": {property_name: "value"}}
    }

    with pytest.raises(validate.ProtocolValidationError, match="schema_invalid"):
        validate.validate_action_document(action)


@pytest.mark.parametrize("value", (float("inf"), float("-inf"), float("nan")))
def test_in_memory_non_finite_extension_numbers_fail_closed(value: float) -> None:
    action = _action()
    action["extensions"]["dev.palonexus.example.v1"] = {"nested": {"value": value}}

    with pytest.raises(validate.ProtocolValidationError):
        validate.validate_action_document(action)


def test_overflowing_json_exponent_fails_extension_validation() -> None:
    action = _action()
    action["extensions"]["dev.palonexus.example.v1"] = {"value": 0}
    wire = json.dumps(action).replace('"value": 0', '"value": 1e1000000')
    action = validate.loads_json_strict(wire)
    with pytest.raises(validate.ProtocolValidationError):
        validate.validate_action_document(action)


@pytest.mark.parametrize("value", (-1e308, 1e308))
def test_documented_extension_numeric_bounds_are_accepted(value: float) -> None:
    action = _action()
    action["extensions"]["dev.palonexus.example.v1"] = {"value": value}
    validate.validate_action_document(action)


@pytest.mark.parametrize("value", (-1.1e308, 1.1e308, 10**309))
def test_extension_numbers_outside_portable_bounds_fail(value: int | float) -> None:
    action = _action()
    action["extensions"]["dev.palonexus.example.v1"] = {"value": value}
    with pytest.raises(validate.ProtocolValidationError):
        validate.validate_action_document(action)


def test_schema_patterns_use_an_ecmascript_and_go_re2_subset() -> None:
    for path in sorted((PROTOCOL / "schemas").glob("*.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        for pattern in _schema_patterns(schema):
            assert "(?" not in pattern, (path, pattern)
            re.compile(pattern)


def test_strict_json_parser_rejects_non_json_numbers_and_duplicate_keys() -> None:
    for document in (
        '{"value": NaN}',
        '{"value": Infinity}',
        '{"value": -Infinity}',
        '{"value": 1, "value": 2}',
    ):
        with pytest.raises(validate.ProtocolValidationError):
            validate.loads_json_strict(document)


def test_validation_document_is_explicitly_task5_only() -> None:
    text = " ".join(RULES.read_text(encoding="utf-8").lower().split())
    for phrase in (
        "sole cross-field semantic",
        "expiresat > servertime",
        "structural",
        "consumer obligation",
        "[-1e308, 1e308]",
        "task 6",
        "task 7",
        "draft",
    ):
        assert phrase in text
    for forbidden in (
        "five minutes",
        "current-time",
        "side-effect ordering",
        "accountable owner",
    ):
        assert forbidden not in text


def test_cli_rejects_invalid_time_order_without_echoing_payload() -> None:
    decision_path = (
        VECTORS / "decision" / "semantic-invalid" / "invalid-time-order.json"
    )
    decision = _json(decision_path)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "protocol.reference.validate",
            "decision",
            str(decision_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 2
    assert "decision_expiry_order" in result.stderr
    assert decision["displayReason"] not in result.stderr


def test_default_pytest_configuration_includes_protocol_tests() -> None:
    config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "protocol/tests" in config["tool"]["pytest"]["ini_options"]["testpaths"]
