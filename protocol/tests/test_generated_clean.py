from __future__ import annotations

import importlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from dataclasses import FrozenInstanceError, replace
from decimal import Decimal
from pathlib import Path
from typing import Any, cast

import pytest

from protocol.reference import validate

ROOT = Path(__file__).parents[2]
GENERATOR = ROOT / "scripts" / "generate_protocol.py"
SCHEMAS = ROOT / "protocol" / "schemas"
PYTHON_OUTPUT = Path("python/src/palonexus/_generated/protocol.py")
GO_OUTPUT = Path("guard/pkg/protocol/generated.go")
OUTPUTS = (PYTHON_OUTPUT, GO_OUTPUT)
HEADER_DIGEST = re.compile(r"Schema digest: ([0-9a-f]{64})")


def _run_generator(
    *arguments: str,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GENERATOR), *arguments],
        cwd=cwd or ROOT,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )


def _json(path: Path) -> dict[str, Any]:
    value = validate.loads_json_strict(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _generated() -> Any:
    python_source = str(ROOT / "python" / "src")
    if python_source not in sys.path:
        sys.path.insert(0, python_source)
    return importlib.import_module("palonexus._generated.protocol")


def test_generator_recreates_committed_outputs_byte_for_byte(tmp_path: Path) -> None:
    before = {path: (ROOT / path).read_bytes() for path in OUTPUTS}
    env = os.environ.copy()
    env.update({"LC_ALL": "C", "LANG": "C", "TZ": "Pacific/Auckland"})

    result = _run_generator(
        "--output-root",
        str(tmp_path),
        cwd=tmp_path,
        env=env,
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert {path: (tmp_path / path).read_bytes() for path in OUTPUTS} == before
    for contents in before.values():
        text = contents.decode("utf-8")
        match = HEADER_DIGEST.search(text)
        assert match
        assert "Generator version: 2" in text
        assert "SPDX-License-Identifier: MIT" in text
        assert "Generated at" not in text
        assert str(ROOT) not in text


def test_generation_tool_metadata_pins_contract_inputs_and_outputs() -> None:
    root_metadata = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    generation = root_metadata["tool"]["palonexus"]["protocol-generation"]

    assert generation == {
        "generator-version": "2",
        "schemas": [
            "protocol/schemas/common-v1.schema.json",
            "protocol/schemas/action-v1.schema.json",
            "protocol/schemas/decision-v1.schema.json",
            "protocol/schemas/approval-v1.schema.json",
            "protocol/schemas/error-v1.schema.json",
            "protocol/schemas/reconciliation-v1.schema.json",
        ],
        "outputs": [PYTHON_OUTPUT.as_posix(), GO_OUTPUT.as_posix()],
    }
    go_mod = (ROOT / "go.mod").read_text(encoding="utf-8")
    assert "module github.com/rogerchucker/palonexus-sdk" in go_mod
    assert re.search(r"^go 1\.25(?:\.0)?$", go_mod, re.MULTILINE)
    assert re.search(r"^toolchain go1\.25\.12$", go_mod, re.MULTILINE)


def test_check_mode_reports_stale_output_without_rewriting_it(tmp_path: Path) -> None:
    result = _run_generator("--output-root", str(tmp_path))
    assert result.returncode == 0, result.stdout + result.stderr
    stale = tmp_path / PYTHON_OUTPUT
    stale.write_text(stale.read_text(encoding="utf-8") + "# stale\n", encoding="utf-8")
    before = stale.read_bytes()

    result = _run_generator("--check", "--output-root", str(tmp_path))

    assert result.returncode == 1
    assert PYTHON_OUTPUT.as_posix() in result.stderr
    assert "stale" in result.stderr.lower()
    assert stale.read_bytes() == before


def test_schema_change_updates_digest_and_generated_contract(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline"
    changed = tmp_path / "changed"
    changed_schemas = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, changed_schemas)
    result = _run_generator("--output-root", str(baseline))
    assert result.returncode == 0, result.stdout + result.stderr

    action_schema = changed_schemas / "action-v1.schema.json"
    action = _json(action_schema)
    action["properties"]["action"]["enum"].append("database:query")
    action_schema.write_text(
        json.dumps(action, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    result = _run_generator(
        "--schema-root",
        str(changed_schemas),
        "--output-root",
        str(changed),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    for path in OUTPUTS:
        baseline_text = (baseline / path).read_text(encoding="utf-8")
        changed_text = (changed / path).read_text(encoding="utf-8")
        assert baseline_text != changed_text
        baseline_digest = HEADER_DIGEST.search(baseline_text)
        changed_digest = HEADER_DIGEST.search(changed_text)
        assert baseline_digest and changed_digest
        assert baseline_digest.group(1) != changed_digest.group(1)
        assert "database:query" in changed_text


@pytest.mark.parametrize(
    ("kind", "directory"),
    (
        ("action", "action"),
        ("decision", "decision"),
        ("approval", "approval"),
        ("error", "error"),
        ("reconciliation", "reconciliation"),
    ),
)
def test_python_structural_dtos_round_trip_valid_vectors(
    kind: str,
    directory: str,
) -> None:
    generated = _generated()
    parse = generated.STRUCTURAL_PARSERS[kind]
    vectors = sorted(
        (ROOT / "protocol" / "test-vectors" / directory / "valid").glob("*.json")
    )
    assert vectors

    for path in vectors:
        document = _json(path)
        model = parse(document)
        assert model.to_dict() == document, path
        wire_model = getattr(generated, f"parse_{kind}_json")(path.read_bytes())
        round_trip = generated._strict_loads_json(wire_model.to_json_bytes())
        expected = generated._strict_loads_json(path.read_bytes())
        assert round_trip == expected, path


@pytest.mark.parametrize(
    ("kind", "directory"),
    (
        ("action", "action"),
        ("decision", "decision"),
        ("approval", "approval"),
        ("error", "error"),
        ("reconciliation", "reconciliation"),
    ),
)
def test_python_structural_parsers_reject_invalid_vectors(
    kind: str,
    directory: str,
) -> None:
    generated = _generated()
    parse = generated.STRUCTURAL_PARSERS[kind]
    vectors = sorted(
        (ROOT / "protocol" / "test-vectors" / directory / "invalid").glob("*.json")
    )
    assert vectors

    for path in vectors:
        with pytest.raises(generated.ProtocolStructureError):
            parse(_json(path))


def test_generated_dtos_are_explicitly_structural_not_semantic() -> None:
    generated = _generated()
    document = _json(
        ROOT
        / "protocol"
        / "test-vectors"
        / "decision"
        / "semantic-invalid"
        / "invalid-time-order.json"
    )

    assert generated.parse_decision(document).to_dict() == document
    with pytest.raises(validate.ProtocolValidationError):
        validate.validate_decision_document(document)
    assert "does not perform semantic validation" in generated.__doc__.lower()
    assert generated.semantic_validation_reference() == (
        "protocol.reference.validate (repository conformance only)"
    )


def test_generated_types_preserve_wire_safe_values_and_closed_extensions() -> None:
    generated = _generated()
    decision = generated.parse_decision(
        _json(ROOT / "protocol" / "test-vectors" / "decision" / "valid" / "allow.json")
    )
    action = generated.parse_action(
        _json(
            ROOT / "protocol" / "test-vectors" / "action" / "valid" / "file-write.json"
        )
    )

    assert isinstance(decision.server_time, generated.RFC3339Timestamp)
    assert isinstance(decision.client_scope_hash, generated.SHA256Digest)
    assert isinstance(action.action_id, generated.ActionID)
    assert action.action is generated.ActionName.FILE_WRITE
    assert action.side_effect is generated.SideEffect.WRITE
    assert action.extensions is not None

    invalid = action.to_dict()
    invalid["extensions"]["unversioned"] = {"value": True}
    with pytest.raises(generated.ProtocolStructureError):
        generated.parse_action(invalid)


def test_python_and_go_outputs_share_schema_digest_and_enum_values() -> None:
    generated = _generated()
    python_text = (ROOT / PYTHON_OUTPUT).read_text(encoding="utf-8")
    go_text = (ROOT / GO_OUTPUT).read_text(encoding="utf-8")
    python_digest = HEADER_DIGEST.search(python_text)
    go_digest = HEADER_DIGEST.search(go_text)

    assert python_digest and go_digest
    assert python_digest.group(1) == go_digest.group(1) == generated.SCHEMA_DIGEST
    for value in generated.ActionName:
        assert json.dumps(value.value) in go_text
    for value in generated.ProtocolErrorCode:
        assert json.dumps(value.value) in go_text


def test_go_generated_protocol_compiles_and_passes_vector_tests() -> None:
    result = subprocess.run(
        ["go", "test", "./guard/pkg/protocol"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_python_preserves_absent_and_present_empty_optional_objects() -> None:
    generated = _generated()
    document = _json(ROOT / "protocol/test-vectors/action/valid/file-write.json")
    document["extensions"] = {}
    for field in ("adapter", "task", "target", "context"):
        document[field]["extensions"] = {}

    model = generated.parse_action(document)

    assert model.to_dict() == document
    assert (
        generated.parse_action(
            _json(ROOT / "protocol/test-vectors/action/valid/mcp-call.json")
        ).extensions
        is None
    )

    cases = (
        ("decision", "decision/valid/approval-required.json", ("approval",)),
        ("approval", "approval/valid/pending.json", ()),
        ("error", "error/valid/authorization-unavailable.json", ()),
        ("reconciliation", "reconciliation/valid/pending.json", ()),
    )
    for kind, relative, nested_fields in cases:
        document = _json(ROOT / "protocol/test-vectors" / relative)
        document["extensions"] = {}
        for field in nested_fields:
            document[field]["extensions"] = {}
        parsed = generated.STRUCTURAL_PARSERS[kind](document)
        assert parsed.to_dict() == document


def test_python_integer_wire_numbers_are_exactly_normalized() -> None:
    generated = _generated()
    source = (
        ROOT / "protocol/test-vectors/reconciliation/valid/pending.json"
    ).read_text(encoding="utf-8")
    source = source.replace('"batchSequence": 0', '"batchSequence": 0e0')
    source = source.replace('"attemptCount": 0', '"attemptCount": 0.0')
    source = source.replace('"maxAttempts": 3', '"maxAttempts": 3.0')

    model = generated.parse_reconciliation_json(source)
    encoded = model.to_json_bytes()

    assert model.batch_sequence == 0
    assert model.attempt_count == 0
    assert model.delivery_policy.max_attempts == 3
    assert b'"batchSequence":0' in encoded
    assert b'"attemptCount":0' in encoded
    assert b'"maxAttempts":3' in encoded

    invalid = source.replace('"batchSequence": 0e0', '"batchSequence": 0.5')
    with pytest.raises(generated.ProtocolStructureError, match="type"):
        generated.parse_reconciliation_json(invalid)


def test_python_preserves_large_and_long_decimal_extension_numbers_exactly() -> None:
    generated = _generated()
    source = (ROOT / "protocol/test-vectors/action/valid/file-write.json").read_text(
        encoding="utf-8"
    )
    source = source.replace(
        '"ticket": "EXAMPLE-42"',
        '"large": 9007199254740993, '
        '"decimal": 0.123456789012345678901234567890123456789',
    )

    model = generated.parse_action_json(source)
    extension = model.extensions["dev.palonexus.example.v1"]

    assert extension["large"] == 9007199254740993
    assert extension["decimal"] == Decimal("0.123456789012345678901234567890123456789")
    encoded = model.to_json_bytes()
    assert b"9007199254740993" in encoded
    assert b"0.123456789012345678901234567890123456789" in encoded


@pytest.mark.parametrize(
    ("payload", "code"),
    (
        (
            b'{"schemaVersion":"1","schemaVersion":"1"}',
            "duplicate_json_key",
        ),
        (
            b'{"schemaVersion":"1","adapter":{"id":"a","id":"b"}}',
            "duplicate_json_key",
        ),
        (b'{"schemaVersion":"' + bytes([0xFF]) + b'"}', "invalid_utf8"),
        (b'{"schemaVersion":"\\ud800"}', "invalid_utf8"),
        (
            b'{"schemaVersion":"1","extensions":'
            + b'{"dev.test.v1":'
            + (b"[" * 40)
            + b"0"
            + (b"]" * 40)
            + b"}}",
            "nesting_too_deep",
        ),
        (
            b'{"schemaVersion":"1","extensions":{"dev.test.v1":' + (b"9" * 513) + b"}}",
            "numeric_token_too_long",
        ),
        (
            b'{"schemaVersion":"1","extensions":{"dev.test.v1":['
            + b",".join([b"0"] * 1025)
            + b"]}}",
            "collection_limit_exceeded",
        ),
        (
            b'{"schemaVersion":"1","extensions":{"dev.test.v1":{'
            + b",".join(f'"k{index}":0'.encode() for index in range(1025))
            + b"}}}",
            "collection_limit_exceeded",
        ),
        (
            b'{"schemaVersion":"1","extensions":{"dev.test.v1":"'
            + (b"x" * 8193)
            + b'"}}',
            "string_too_large",
        ),
        (
            b'{"schemaVersion":"1","extensions":{"dev.test.v1":['
            + b",".join([b"[0,0,0,0]"] * 1024)
            + b"]}}",
            "node_limit_exceeded",
        ),
        (b" " * 65537, "wire_too_large"),
    ),
)
def test_python_strict_wire_preflight_fails_closed(
    payload: bytes,
    code: str,
) -> None:
    generated = _generated()

    with pytest.raises(generated.ProtocolStructureError, match=code):
        generated.parse_action_json(payload)


def test_python_models_are_frozen_and_revalidate_serialization() -> None:
    generated = _generated()
    model = generated.parse_action(
        _json(ROOT / "protocol/test-vectors/action/valid/file-write.json")
    )

    with pytest.raises(FrozenInstanceError):
        model.action = generated.ActionName.FILE_READ

    invalid = replace(model, action=cast(Any, "not:registered"))
    with pytest.raises(generated.ProtocolStructureError):
        invalid.to_dict()
    model.extensions["unversioned"] = {"value": True}
    with pytest.raises(generated.ProtocolStructureError):
        model.to_json_bytes()


def test_timestamp_structure_follows_accepted_task5_schema() -> None:
    generated = _generated()
    source = (ROOT / "protocol/test-vectors/action/valid/file-write.json").read_text(
        encoding="utf-8"
    )
    precise = source.replace(
        "2026-07-25T20:00:00Z",
        "2026-07-25T20:00:59.123456789123456789+23:59",
    )
    assert generated.parse_action_json(precise)

    assert generated.parse_action_json(
        source.replace("2026-07-25T20:00:00Z", "2026-07-25T20:00:60Z")
    )

    for timestamp in ("2026-02-30T20:00:00Z", "2026-07-25T20:00:00+24:00"):
        with pytest.raises(generated.ProtocolStructureError):
            generated.parse_action_json(
                source.replace("2026-07-25T20:00:00Z", timestamp)
            )


def test_extreme_exponent_is_rejected_with_stable_structure_error() -> None:
    generated = _generated()
    source = (ROOT / "protocol/test-vectors/action/valid/file-write.json").read_text(
        encoding="utf-8"
    )
    hostile = source.replace(
        '"ticket": "EXAMPLE-42"',
        '"ticket": "EXAMPLE-42", "extreme": 1e999999999999999999999999999999999999',
    )

    with pytest.raises(generated.ProtocolStructureError, match="^invalid_json_number$"):
        generated.parse_action_json(hostile)


@pytest.mark.parametrize(
    ("mutation", "error_text"),
    (
        ("duplicate", "duplicate"),
        ("external-ref", "reference"),
        ("invalid-schema", "schema"),
        ("enum-collision", "collision"),
        ("unsafe-property", "property"),
    ),
)
def test_generator_rejects_hostile_schema_inputs_deterministically(
    tmp_path: Path,
    mutation: str,
    error_text: str,
) -> None:
    schema_root = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, schema_root)
    action_path = schema_root / "action-v1.schema.json"
    if mutation == "duplicate":
        text = action_path.read_text(encoding="utf-8")
        action_path.write_text(
            text.replace(
                '"$schema":',
                '"$schema":"https://json-schema.org/draft/2020-12/schema","$schema":',
                1,
            ),
            encoding="utf-8",
        )
    else:
        action = _json(action_path)
        if mutation == "external-ref":
            action["properties"]["actionId"]["$ref"] = (
                "https://attacker.invalid/schema.json#/$defs/id"
            )
        elif mutation == "invalid-schema":
            action["properties"]["action"]["type"] = "not-a-json-schema-type"
        elif mutation == "enum-collision":
            action["properties"]["action"]["enum"].append("file-write")
        elif mutation == "unsafe-property":
            action["properties"]['bad"`\nproperty'] = {"type": "string"}
        action_path.write_text(json.dumps(action), encoding="utf-8")

    first = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(tmp_path / "one"),
    )
    second = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(tmp_path / "two"),
    )

    assert first.returncode == second.returncode == 1
    assert first.stderr == second.stderr
    assert error_text in first.stderr.lower()


def test_generator_quotes_hostile_enum_wire_values(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    output_root = tmp_path / "output"
    shutil.copytree(SCHEMAS, schema_root)
    action_path = schema_root / "action-v1.schema.json"
    action = _json(action_path)
    hostile = 'tool:"quoted`\nvalue😀'
    action["properties"]["action"]["enum"].append(hostile)
    action["properties"]["action"]["description"] = "Property 😀"
    action["description"] = "Unicode 😀\u2028safe"
    action_path.write_text(json.dumps(action), encoding="utf-8")

    result = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(output_root),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    python_source = (output_root / PYTHON_OUTPUT).read_text(encoding="utf-8")
    go_source = (output_root / GO_OUTPUT).read_text(encoding="utf-8")
    compile(python_source, PYTHON_OUTPUT.as_posix(), "exec")
    assert "\\ud83d\\ude00" not in go_source
    assert "\\U0001f600" in go_source
    assert "\\u2028" in go_source
    subprocess.run(
        ["gofmt", "-d", str(output_root / GO_OUTPUT)],
        check=True,
        capture_output=True,
        text=True,
    )


def test_generator_rejects_cyclic_refs_with_deterministic_path(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, schema_root)
    action_path = schema_root / "action-v1.schema.json"
    action = _json(action_path)
    action["$defs"] = {
        "cycleA": {"$ref": "#/$defs/cycleB"},
        "cycleB": {"$ref": "#/$defs/cycleA"},
        "shared": {"type": "string"},
    }
    action["properties"]["actionId"] = {"$ref": "#/$defs/shared"}
    action["properties"]["requestId"] = {"$ref": "#/$defs/shared"}
    action_path.write_text(json.dumps(action), encoding="utf-8")

    result = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(tmp_path / "output"),
    )

    assert result.returncode == 1
    assert "non-consuming schema reference cycle" in result.stderr.lower()
    assert "/$defs/cycleA -> /$defs/cycleB -> /$defs/cycleA" in result.stderr


@pytest.mark.parametrize("applicator", ("allOf", "anyOf"))
def test_generator_rejects_composition_ref_cycles(
    tmp_path: Path, applicator: str
) -> None:
    schema_root = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, schema_root)
    action_path = schema_root / "action-v1.schema.json"
    action = _json(action_path)
    action["$defs"] = {
        "cycleA": {applicator: [{"$ref": "#/$defs/cycleB"}]},
        "cycleB": {"$ref": "#/$defs/cycleA"},
    }
    action_path.write_text(json.dumps(action), encoding="utf-8")

    result = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(tmp_path / "output"),
    )

    assert result.returncode == 1
    assert "non-consuming schema reference cycle" in result.stderr.lower()
    assert "/$defs/cycleA" in result.stderr
    assert "/$defs/cycleB" in result.stderr


@pytest.mark.parametrize(
    "definition",
    (
        {
            "type": "object",
            "properties": {"next": {"$ref": "#/$defs/productive"}},
            "additionalProperties": False,
            "maxProperties": 1,
        },
        {
            "type": "array",
            "items": {"$ref": "#/$defs/productive"},
            "maxItems": 2,
        },
    ),
)
def test_generator_allows_productive_bounded_recursive_refs(
    tmp_path: Path, definition: dict[str, Any]
) -> None:
    schema_root = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, schema_root)
    action_path = schema_root / "action-v1.schema.json"
    action = _json(action_path)
    action["$defs"] = {"productive": definition}
    action_path.write_text(json.dumps(action), encoding="utf-8")

    result = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(tmp_path / "output"),
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_generator_allows_repeated_acyclic_refs(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, schema_root)
    action_path = schema_root / "action-v1.schema.json"
    action = _json(action_path)
    action["$defs"] = {"shared": {"type": "string"}}
    action["properties"]["actionId"] = {"$ref": "#/$defs/shared"}
    action["properties"]["requestId"] = {"$ref": "#/$defs/shared"}
    action_path.write_text(json.dumps(action), encoding="utf-8")

    result = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(tmp_path / "output"),
    )

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    "pattern",
    (
        "(?=a)a",
        r"(a)\1",
        "(?P<name>a)",
        "(?(1)a|b)",
        r"\C",
        "(a+)+$",
        "(a|aa)+$",
        "(?:a+)+$",
        "(?:a|aa)+$",
        "(a?)+$",
        "(a|aa){1,}$",
        "(a{1,}){1,}$",
        "(a|aa){1,8192}$",
        "^(a|b)$",
        "^a{1,}$",
        "^a{8193}$",
        "^a{2,1}$",
        "^a{999999999999999999999999999999999999}$",
        "^a{1,2",
        "^a{}$",
        r"^\w+$",
        r"^\W+$",
        r"^\d+$",
        r"^\D+$",
        r"^\s+$",
        r"^\S+$",
        r"^\bword\B$",
        r"^\u0061$",
        r"^\p{L}+$",
        r"^[[:alpha:]]+$",
        "(?i)^ascii$",
        "a" * 513,
    ),
)
def test_generator_rejects_nonportable_or_complex_regex(
    tmp_path: Path, pattern: str
) -> None:
    schema_root = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, schema_root)
    action_path = schema_root / "action-v1.schema.json"
    action = _json(action_path)
    action["properties"]["action"]["pattern"] = pattern
    action_path.write_text(json.dumps(action), encoding="utf-8")

    result = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(tmp_path / "output"),
    )

    assert result.returncode == 1
    assert "unsafe schema pattern" in result.stderr.lower()


def test_generator_requires_runtime_bounded_pattern_strings(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, schema_root)
    action_path = schema_root / "action-v1.schema.json"
    action = _json(action_path)
    action["properties"]["action"]["pattern"] = "^[A-Z]{1,8}$"
    action["properties"]["action"]["maxLength"] = 9_000
    action_path.write_text(json.dumps(action), encoding="utf-8")

    result = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(tmp_path / "output"),
    )

    assert result.returncode == 1
    assert "pattern maxLength exceeds runtime bound" in result.stderr


def test_generator_allows_simple_unreviewed_bounded_pattern(tmp_path: Path) -> None:
    schema_root = tmp_path / "schemas"
    shutil.copytree(SCHEMAS, schema_root)
    action_path = schema_root / "action-v1.schema.json"
    action = _json(action_path)
    action["properties"]["action"]["pattern"] = r"^[A-Z._-]{1,8}$"
    action["properties"]["action"]["maxLength"] = 8
    action_path.write_text(json.dumps(action), encoding="utf-8")

    result = _run_generator(
        "--schema-root",
        str(schema_root),
        "--output-root",
        str(tmp_path / "output"),
    )

    assert result.returncode == 0, result.stdout + result.stderr


def test_all_accepted_patterns_compile_in_python_and_go(tmp_path: Path) -> None:
    patterns = sorted(
        {
            node["pattern"]
            for schema_path in SCHEMAS.glob("*.json")
            for node in _walk_test_schema(_json(schema_path))
            if isinstance(node.get("pattern"), str)
        }
    )
    for pattern in patterns:
        re.compile(pattern)

    source = "\n".join(
        [
            "package main",
            'import "regexp"',
            "func main() {",
            *[
                f"regexp.MustCompile({json.dumps(pattern, ensure_ascii=False)})"
                for pattern in patterns
            ],
            "}",
        ]
    )
    source_path = tmp_path / "patterns.go"
    source_path.write_text(source, encoding="utf-8")
    result = subprocess.run(
        ["go", "run", source_path],
        capture_output=True,
        check=False,
        text=True,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def _walk_test_schema(value: Any) -> list[dict[str, Any]]:
    nodes: list[dict[str, Any]] = []
    pending = [value]
    while pending:
        child = pending.pop()
        if isinstance(child, dict):
            nodes.append(child)
            pending.extend(child.values())
        elif isinstance(child, list):
            pending.extend(child)
    return nodes
