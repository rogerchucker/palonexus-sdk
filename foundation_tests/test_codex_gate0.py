from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
FIXTURES = ROOT / "plugins" / "codex" / "tests" / "fixtures"
CAPTURE_SPEC = importlib.util.spec_from_file_location(
    "capture_codex_fixtures", ROOT / "scripts" / "capture_codex_fixtures.py"
)
assert CAPTURE_SPEC and CAPTURE_SPEC.loader
CAPTURE = importlib.util.module_from_spec(CAPTURE_SPEC)
CAPTURE_SPEC.loader.exec_module(CAPTURE)

sanitize_pretooluse = CAPTURE.sanitize_pretooluse
canonical_sha256 = CAPTURE.canonical_sha256
docker_capture_command = CAPTURE.docker_capture_command
safe_environment = CAPTURE._safe_environment

REQUIRED_FAMILIES = {
    "bash": "Bash",
    "apply_patch": "apply_patch",
    "mcp": "mcp__palonexus_fixture__write_sentinel",
}
REQUIRED_SCENARIOS = {
    "structured_deny",
    "exit_2",
    "guard_failure",
    "approval_required",
}
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_fixture_reference(reference: str) -> dict[str, object]:
    path = FIXTURES / reference
    assert path.is_file(), f"missing fixture evidence: {reference}"
    return _load_json(path)


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _write_ndjson(path: Path, values: list[object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(value, sort_keys=True) + "\n" for value in values),
        encoding="utf-8",
    )


def _synthetic_bash_deny_receipts(root: Path) -> dict[str, object]:
    nonce = "g0-fixture-bash-structured-deny-01"
    invocation_binding = canonical_sha256(
        {
            "family": "bash",
            "nonce": nonce,
            "scenario": "structured_deny",
            "version": "0.145.0",
        }
    )
    tool_input = {
        "command": (
            f"echo '{invocation_binding}' >> /output/tool-invocations && "
            f"touch sentinel-{nonce}"
        )
    }
    prompt = (
        "Use the Bash tool exactly once with this exact command: "
        f"{tool_input['command']}\n"
        "Do not use any other tool. Do not retry. After the one tool result, stop."
    )
    call_id = "sha256:" + "a" * 64
    item_id = "sha256:" + "b" * 64
    reason = f"PaloNexus fixture denial {nonce}"
    hook_payload = {
        "cwd": "<fixture-root>/work",
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.6-sol",
        "permission_mode": "bypassPermissions",
        "session_id": "sha256:" + "c" * 64,
        "tool_input": tool_input,
        "tool_name": "Bash",
        "tool_use_id": call_id,
        "transcript_path": None,
        "turn_id": "sha256:" + "d" * 64,
    }
    hook_output = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    request = {
        "schemaVersion": 1,
        "version": "0.145.0",
        "family": "bash",
        "scenario": "structured_deny",
        "attempt": 1,
        "nonce": nonce,
        "prompt": prompt,
        "toolName": "Bash",
        "toolInput": tool_input,
        "invocationBinding": invocation_binding,
        "sentinelPath": f"<fixture-root>/work/sentinel-{nonce}",
        "withPreToolHook": True,
        "approvalPolicy": "never",
    }
    _write_json(root / "request.json", request)
    _write_json(
        root / "process.json",
        {
            "exitCode": 0,
            "prompt": prompt,
            "approvalPolicy": "never",
            "sandbox": "danger-full-access",
        },
    )
    _write_ndjson(
        root / "codex-events.ndjson",
        [
            {"type": "thread.started", "thread_id": "sha256:" + "e" * 64},
            {"type": "turn.started"},
            {
                "type": "item.started",
                "item": {
                    "id": item_id,
                    "type": "command_execution",
                    "command": tool_input["command"],
                    "aggregated_output": "",
                    "exit_code": None,
                    "status": "in_progress",
                },
            },
            {
                "type": "item.completed",
                "item": {
                    "id": item_id,
                    "type": "command_execution",
                    "command": tool_input["command"],
                    "aggregated_output": (
                        "Command blocked by PreToolUse hook: "
                        f"{reason}. Command: {tool_input['command']}"
                    ),
                    "exit_code": 1,
                    "status": "failed",
                },
            },
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 1,
                    "cached_input_tokens": 0,
                    "output_tokens": 1,
                },
            },
        ],
    )
    _write_ndjson(root / "hook-input.ndjson", [hook_payload])
    _write_ndjson(
        root / "hook-run.ndjson",
        [
            {
                "toolUseId": call_id,
                "exitCode": 0,
                "stdout": json.dumps(hook_output, sort_keys=True) + "\n",
                "stderr": "",
            }
        ],
    )
    _write_ndjson(root / "guard.ndjson", [])
    _write_ndjson(root / "mcp.ndjson", [])
    _write_json(
        root / "effect.json",
        {
            "sentinelExistsAfter": False,
            "sentinelContentFingerprint": None,
            "toolInvocationReceipts": [],
        },
    )
    return request


def test_receipt_parser_is_the_only_cell_trust_boundary() -> None:
    parser = getattr(CAPTURE, "derive_cell_from_receipts", None)

    assert callable(parser), "cell evidence must be derived from persisted raw receipts"


def test_receipt_parser_derives_correlated_bash_denial(tmp_path: Path) -> None:
    request = _synthetic_bash_deny_receipts(tmp_path)

    evidence = CAPTURE.derive_cell_from_receipts(tmp_path)

    assert evidence["trusted"] is True
    assert evidence["version"] == "0.145.0"
    assert evidence["family"] == "bash"
    assert evidence["scenario"] == "structured_deny"
    assert evidence["nonce"] == request["nonce"]
    assert evidence["promptFingerprint"] == CAPTURE._sha256_bytes(
        request["prompt"].encode()
    )
    assert evidence["inputFingerprint"] == canonical_sha256(request["toolInput"])
    assert evidence["toolUseId"] == "sha256:" + "a" * 64
    assert evidence["hostItemId"] == "sha256:" + "b" * 64
    assert evidence["hostToolCallCount"] == 1
    assert evidence["hookInvocationCount"] == 1
    assert evidence["hookExitCode"] == 0
    assert evidence["hostRenderedEvidence"]["eventType"] == "item.completed"
    assert evidence["sentinelExistsAfter"] is False
    assert evidence["toolExecuted"] is False


def test_receipt_parser_rejects_uncorrelated_hook_call_id(tmp_path: Path) -> None:
    _synthetic_bash_deny_receipts(tmp_path)
    hook_run = _load_json(tmp_path / "hook-run.ndjson")
    hook_run["toolUseId"] = "sha256:" + "f" * 64
    _write_ndjson(tmp_path / "hook-run.ndjson", [hook_run])

    with pytest.raises(ValueError, match="tool use id"):
        CAPTURE.derive_cell_from_receipts(tmp_path)


def test_receipt_parser_rejects_text_without_structural_denial(
    tmp_path: Path,
) -> None:
    _synthetic_bash_deny_receipts(tmp_path)
    events = [
        json.loads(line)
        for line in (tmp_path / "codex-events.ndjson").read_text().splitlines()
    ]
    completed = next(event for event in events if event["type"] == "item.completed")
    completed["item"]["status"] = "completed"
    _write_ndjson(tmp_path / "codex-events.ndjson", events)

    with pytest.raises(ValueError, match="structural host denial"):
        CAPTURE.derive_cell_from_receipts(tmp_path)


def test_receipt_parser_rejects_self_attested_summary(tmp_path: Path) -> None:
    _write_json(tmp_path / "summary.json", {"trusted": True})

    with pytest.raises(ValueError, match="receipt bundle is incomplete"):
        CAPTURE.derive_cell_from_receipts(tmp_path)


def test_receipt_parser_recomputes_prompt_and_invocation_binding(
    tmp_path: Path,
) -> None:
    _synthetic_bash_deny_receipts(tmp_path)
    request = _load_json(tmp_path / "request.json")
    process = _load_json(tmp_path / "process.json")
    request["prompt"] += "\nself-attested drift"
    process["prompt"] = request["prompt"]
    _write_json(tmp_path / "request.json", request)
    _write_json(tmp_path / "process.json", process)

    with pytest.raises(ValueError, match="deterministic prompt"):
        CAPTURE.derive_cell_from_receipts(tmp_path)


def _synthetic_host_receipts(root: Path) -> None:
    archive_digest = base64.b64encode(
        hashlib.sha512(b"fixture archive").digest()
    ).decode()
    _write_json(
        root / "npm-metadata.json",
        {
            "name": "@openai/codex",
            "version": "0.145.0",
            "dist": {
                "tarball": (
                    "https://registry.npmjs.org/@openai/codex/-/codex-0.145.0.tgz"
                ),
                "integrity": f"sha512-{archive_digest}",
            },
        },
    )
    _write_json(
        root / "npm-artifact.json",
        {
            "tarballUrl": (
                "https://registry.npmjs.org/@openai/codex/-/codex-0.145.0.tgz"
            ),
            "sha512": f"sha512-{archive_digest}",
            "size": len(b"fixture archive"),
        },
    )
    release_url = (
        "https://github.com/openai/codex/releases/download/"
        "rust-v0.145.0/codex-aarch64-unknown-linux-musl.tar.gz"
    )
    _write_json(
        root / "release-metadata.json",
        {
            "tagName": "rust-v0.145.0",
            "publishedAt": "2026-07-21T18:21:04Z",
            "asset": {
                "name": "codex-aarch64-unknown-linux-musl.tar.gz",
                "url": release_url,
                "digest": "sha256:" + "3" * 64,
                "size": 100,
            },
        },
    )
    _write_json(
        root / "artifact.json",
        {
            "tarballUrl": release_url,
            "sha256": "sha256:" + "3" * 64,
            "size": 100,
            "executableSha256": "sha256:" + "1" * 64,
        },
    )
    _write_json(
        root / "version-process.json",
        {
            "exitCode": 0,
            "stdout": "codex-cli 0.145.0\n",
            "stderr": "",
        },
    )
    _write_json(
        root / "runtime-canary.json",
        {
            "dockerArgv": [
                "docker",
                "run",
                "--user",
                "10001:10001",
                "--read-only",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--cpus",
                "1",
                "--memory",
                "1g",
                "--pids-limit",
                "128",
                "--mount",
                "type=bind,src=<host-temp>,dst=/usr/local/bin/codex,readonly",
                "--mount",
                "type=bind,src=<host-temp>,dst=/fixture,readonly",
                "--mount",
                "type=bind,src=<host-temp>,dst=/output",
                "--mount",
                "type=bind,src=<host-temp>,dst=/work",
                "--mount",
                "type=bind,src=<host-temp>,dst=/fixture-auth.json,readonly",
                CAPTURE.BASE_IMAGE,
            ],
            "imageId": "sha256:" + "2" * 64,
            "exitCode": 0,
            "observations": {
                "uid": 10001,
                "rootWriteDenied": True,
                "authWriteDenied": True,
                "sourceWorkspaceAbsent": True,
                "workWritable": True,
                "outputWritable": True,
            },
        },
    )
    _write_json(
        root / "mcp-registration.json",
        {
            "exitCode": 0,
            "stdout": (
                "palonexus_fixture /usr/local/bin/python3 "
                "/fixture/mcp_server.py enabled\n"
            ),
            "stderr": "",
        },
    )


def test_host_receipt_parser_derives_integrity_and_isolation(tmp_path: Path) -> None:
    _synthetic_host_receipts(tmp_path)
    parser = getattr(CAPTURE, "derive_host_from_receipts", None)

    assert callable(parser), "host facts must be derived from raw receipts"
    evidence = parser(tmp_path)

    assert evidence["trusted"] is True
    assert evidence["version"] == "0.145.0"
    assert evidence["npmIntegrityVerified"] is True
    assert evidence["releaseArtifactIntegrityVerified"] is True
    assert evidence["executableSha256"] == "sha256:" + "1" * 64
    assert evidence["baseImage"] == CAPTURE.BASE_IMAGE
    assert evidence["baseImageId"] == "sha256:" + "2" * 64
    assert evidence["containerUser"] == "10001:10001"
    assert evidence["readOnlyRoot"] is True
    assert evidence["authMountReadOnly"] is True
    assert evidence["sourceWorkspaceMounted"] is False
    assert evidence["mcpRegistered"] is True


def test_host_receipt_parser_rejects_runtime_self_attestation(
    tmp_path: Path,
) -> None:
    _synthetic_host_receipts(tmp_path)
    runtime = _load_json(tmp_path / "runtime-canary.json")
    runtime["dockerArgv"].remove("--read-only")
    _write_json(tmp_path / "runtime-canary.json", runtime)

    with pytest.raises(ValueError, match="hardened Docker invocation"):
        CAPTURE.derive_host_from_receipts(tmp_path)


def test_host_receipt_parser_rejects_release_artifact_digest_drift(
    tmp_path: Path,
) -> None:
    _synthetic_host_receipts(tmp_path)
    artifact = _load_json(tmp_path / "artifact.json")
    artifact["sha256"] = "sha256:" + "9" * 64
    _write_json(tmp_path / "artifact.json", artifact)

    with pytest.raises(ValueError, match="release artifact integrity"):
        CAPTURE.derive_host_from_receipts(tmp_path)


def test_host_receipt_parser_rejects_writable_auth_mount(tmp_path: Path) -> None:
    _synthetic_host_receipts(tmp_path)
    runtime = _load_json(tmp_path / "runtime-canary.json")
    auth_mount = "type=bind,src=<host-temp>,dst=/fixture-auth.json,readonly"
    runtime["dockerArgv"][runtime["dockerArgv"].index(auth_mount)] = (
        "type=bind,src=<host-temp>,dst=/fixture-auth.json"
    )
    _write_json(tmp_path / "runtime-canary.json", runtime)

    with pytest.raises(ValueError, match="hardened Docker invocation"):
        CAPTURE.derive_host_from_receipts(tmp_path)


def test_codex_jsonl_sanitizer_preserves_structural_correlation() -> None:
    request = {
        "family": "bash",
        "scenario": "structured_deny",
        "nonce": "g0-jsonl-sanitizer-01",
        "toolName": "Bash",
        "toolInput": {"command": "touch sentinel-g0-jsonl-sanitizer-01"},
    }
    raw = "\n".join(
        json.dumps(value)
        for value in (
            {"type": "thread.started", "thread_id": "private-thread-id"},
            {"type": "turn.started"},
            {
                "type": "item.started",
                "item": {
                    "id": "private-item-id",
                    "type": "command_execution",
                    "command": request["toolInput"]["command"],
                    "aggregated_output": "",
                    "exit_code": None,
                    "status": "in_progress",
                },
            },
            {
                "type": "item.completed",
                "item": {
                    "id": "private-item-id",
                    "type": "command_execution",
                    "command": request["toolInput"]["command"],
                    "aggregated_output": (
                        "Command blocked by PreToolUse hook: "
                        "PaloNexus fixture denial g0-jsonl-sanitizer-01"
                    ),
                    "exit_code": 1,
                    "status": "failed",
                },
            },
            {
                "type": "item.completed",
                "item": {
                    "id": "private-message-id",
                    "type": "agent_message",
                    "text": "synthetic completion prose",
                },
            },
            {
                "type": "turn.completed",
                "usage": {
                    "input_tokens": 10,
                    "cached_input_tokens": 2,
                    "output_tokens": 3,
                    "reasoning_output_tokens": 1,
                },
            },
        )
    )
    sanitizer = getattr(CAPTURE, "sanitize_codex_jsonl", None)

    assert callable(sanitizer), "raw Codex JSONL must be sanitized structurally"
    events = sanitizer(raw + "\n", request)

    serialized = json.dumps(events)
    assert "private-thread-id" not in serialized
    assert "private-item-id" not in serialized
    started = next(event for event in events if event["type"] == "item.started")
    completed = next(
        event
        for event in events
        if event["type"] == "item.completed"
        and event["item"]["type"] == "command_execution"
    )
    assert started["item"]["id"] == completed["item"]["id"]
    assert SHA256.fullmatch(started["item"]["id"])
    message = next(
        event
        for event in events
        if event["type"] == "item.completed"
        and event["item"]["type"] == "agent_message"
    )
    assert "text" not in message["item"]
    assert SHA256.fullmatch(message["item"]["textFingerprint"])


def test_hook_receipt_sanitizer_hashes_ids_and_keeps_exact_input() -> None:
    raw = {
        "cwd": "/work",
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.6-sol",
        "permission_mode": "bypassPermissions",
        "session_id": "private-session",
        "tool_input": {"nonce": "g0-hook-sanitizer-01"},
        "tool_name": "mcp__palonexus_fixture__write_sentinel",
        "tool_use_id": "private-call-id",
        "transcript_path": None,
        "turn_id": "private-turn",
    }
    sanitizer = getattr(CAPTURE, "sanitize_hook_receipt", None)

    assert callable(sanitizer), "hook receipts must preserve pseudonymous correlation"
    receipt = sanitizer(
        raw,
        expected_tool_name="mcp__palonexus_fixture__write_sentinel",
        expected_tool_input={"nonce": "g0-hook-sanitizer-01"},
    )

    assert receipt["tool_input"] == raw["tool_input"]
    assert receipt["tool_use_id"] == CAPTURE._sha256_bytes(b"private-call-id")
    assert receipt["session_id"] == CAPTURE._sha256_bytes(b"private-session")
    assert receipt["turn_id"] == CAPTURE._sha256_bytes(b"private-turn")
    assert "private-" not in json.dumps(receipt)


def test_every_persisted_cell_is_rederived_from_hashed_receipts() -> None:
    cells = sorted((FIXTURES / "cells").glob("*/*/*.json"))
    assert cells

    for path in cells:
        cell = _load_json(path)
        assert cell["receiptDerived"] is True
        receipt_path = FIXTURES / cell["receipt"]
        assert receipt_path.is_dir()
        derived = CAPTURE.derive_cell_from_receipts(receipt_path)
        for field, value in derived.items():
            assert cell[field] == value, f"{path}: derived field {field} drifted"
        receipt_files = cell["receiptFiles"]
        assert set(receipt_files) == {
            "request.json",
            "process.json",
            "codex-events.ndjson",
            "hook-input.ndjson",
            "hook-run.ndjson",
            "guard.ndjson",
            "mcp.ndjson",
            "effect.json",
        }
        for name, digest in receipt_files.items():
            assert digest == CAPTURE._sha256_file(receipt_path / name)
        host_path = FIXTURES / cell["hostReceipt"]
        host = CAPTURE.derive_host_from_receipts(host_path)
        assert host["version"] == cell["version"]
        assert canonical_sha256(host) == cell["hostEvidenceFingerprint"]


def test_only_receipt_accepted_payload_shapes_are_published() -> None:
    payload_dir = FIXTURES / "pretooluse"
    observed = {path.stem for path in payload_dir.glob("*.json")}
    assert observed == {"mcp"}

    fixture = _load_json(payload_dir / "mcp.json")
    assert fixture["hook_event_name"] == "PreToolUse"
    assert fixture["tool_name"] == REQUIRED_FAMILIES["mcp"]
    assert isinstance(fixture["tool_input"], dict)
    assert fixture["capture"]["receiptDerived"] is True
    assert SHA256.fullmatch(fixture["capture"]["inputFingerprint"])
    cell = _load_fixture_reference(fixture["capture"]["cell"])
    assert cell["receipt"] == fixture["capture"]["receipt"]
    assert cell["hookPayload"]["tool_input"] == fixture["tool_input"]
    serialized = json.dumps(fixture)
    assert "/Users/" not in serialized
    assert "/home/" not in serialized
    assert "prompt" not in serialized.lower()
    assert "secret" not in serialized.lower()


def test_incomplete_capture_limits_capability_claims_to_trusted_cells() -> None:
    capabilities = _load_json(FIXTURES / "expected-capabilities.json")
    host = _load_json(FIXTURES / "host-version.json")
    payloads = list((FIXTURES / "pretooluse").glob("*.json"))

    assert capabilities["gateComplete"] is False
    assert host["gateComplete"] is False
    assert capabilities["claimedToolFamilies"] == []
    assert set(path.stem for path in payloads) == {"mcp"}
    assert capabilities["exactMinimum"] is None
    assert capabilities["attemptedVersions"] == [
        "0.124.0",
        "0.125.0",
        "0.145.0",
    ]
    assert capabilities["receiptDerivedObservedCells"] == {
        version: {"mcp": ["noop"]} for version in capabilities["attemptedVersions"]
    }
    assert host["minimumSupported"]["status"] == "unresolved"
    assert host["latestStable"]["coverageComplete"] is False


def test_blocking_attempts_are_not_promoted_without_host_tool_events() -> None:
    capabilities = _load_json(FIXTURES / "expected-capabilities.json")
    assert capabilities["unsupportedToolFamilies"], (
        "hosted and specialized tool exclusions must be explicit"
    )
    correlated_by_scenario = {scenario: 0 for scenario in REQUIRED_SCENARIOS}
    for version in capabilities["attemptedVersions"]:
        for scenario in REQUIRED_SCENARIOS:
            scenario_dir = FIXTURES / "receipts" / "cells" / version / "mcp" / scenario
            attempts = sorted(scenario_dir.glob("attempt-*"))
            assert len(attempts) == 2
            assert all(
                _load_json(path / "classification.json")["accepted"] is False
                for path in attempts
            )
            correlated_hook_attempts = [
                path
                for path in attempts
                if (path / "hook-input.ndjson").is_file()
                and (path / "hook-input.ndjson").read_text()
            ]
            correlated_by_scenario[scenario] += len(correlated_hook_attempts)
            for path in correlated_hook_attempts:
                with pytest.raises(
                    ValueError,
                    match="structurally matching host tool event",
                ):
                    CAPTURE.derive_cell_from_receipts(path)
    assert all(count > 0 for count in correlated_by_scenario.values())


def test_codex_mcp_partial_evidence_is_bounded_and_honest() -> None:
    capabilities = _load_json(FIXTURES / "expected-capabilities.json")
    for version in capabilities["attemptedVersions"]:
        noop = _load_fixture_reference(f"cells/observed-{version}/mcp/noop.json")
        assert noop["trusted"] is True
        assert noop["receiptDerived"] is True
        assert noop["hookInvocationCount"] == 1
        assert noop["hostToolCallCount"] == 1
        assert noop["toolExecuted"] is True
        assert noop["sentinelExistsAfter"] is True


def test_native_permission_preservation_remains_unresolved() -> None:
    capabilities = _load_json(FIXTURES / "expected-capabilities.json")
    assert capabilities["claimedToolFamilies"] == []
    assert all(
        "bash" not in families
        for families in capabilities["receiptDerivedObservedCells"].values()
    )


def test_codex_gate0_is_complete() -> None:
    capabilities = _load_json(FIXTURES / "expected-capabilities.json")

    assert capabilities["gateComplete"] is True, capabilities["limitation"]


def test_host_and_contract_evidence_is_immutable_and_reproducible() -> None:
    host = _load_json(FIXTURES / "host-version.json")
    assert host["gateComplete"] is False
    assert host["minimumSupported"]["version"] is None
    assert host["latestStable"]["version"] == "0.145.0"
    assert host["latestStable"]["coverageComplete"] is False
    assert set(host["testedHosts"]) == {"0.124.0", "0.125.0", "0.145.0"}
    for version, recorded in host["testedHosts"].items():
        receipt_dir = FIXTURES / recorded["receipt"]
        derived = CAPTURE.derive_host_from_receipts(receipt_dir)
        assert derived["version"] == version
        assert derived["npmIntegrityVerified"] is True
        assert derived["releaseArtifactIntegrityVerified"] is True
        assert derived["authMountReadOnly"] is True
        assert derived["sourceWorkspaceMounted"] is False
        assert derived["readOnlyRoot"] is True
        for name, digest in recorded["receiptFiles"].items():
            assert digest == CAPTURE._sha256_file(receipt_dir / name)

    contract = _load_json(FIXTURES / "official-contract.json")
    assert contract["url"] == "https://developers.openai.com/codex/hooks"
    assert contract["retrievedAt"]
    assert SHA256.fullmatch(contract["sha256"])
    assert re.fullmatch(r"[0-9a-f]{40}", contract["sourceCommit"])
    assert contract["sourceCommit"] in contract["immutableSchemaUrl"]
    assert SHA256.fullmatch(contract["immutableSchemaSha256"])
    assert contract["releaseEvidence"]["minimumVersion"] is None
    assert contract["releaseEvidence"]["minimumTested"] is False
    assert contract["blockingSemantics"] == {
        "noopPreservesNativePermissions": False,
        "structuredDeny": False,
        "exit2": False,
        "approvalRequiredRenderedAsDeny": False,
    }
    assert "MCP no-op cells" in contract["verifiedScope"]
    assert "compare SHA-256" in contract["reproduction"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("unexpected", "value"),
        ("cwd", "/Users/alice/project"),
        ("cwd", "/home/alice/project"),
        ("cwd", r"C:\Users\alice\project"),
        ("cwd", r"\\server\share\project"),
        ("tool_input", {"command": "echo bearer sk-secretvalue1234567890"}),
        ("tool_input", {"command": "alice@example.com"}),
        ("tool_input", {"command": "A" * 80}),
        ("permission_mode", "alice"),
        ("model", "secret-model-prose"),
    ],
)
def test_strict_sanitizer_rejects_unexpected_or_sensitive_data(
    field: str, value: object
) -> None:
    root = Path("/fixture")
    expected_input = {"command": "printf gate0-bash-nonce"}
    payload: dict[str, object] = {
        "session_id": "session-id",
        "transcript_path": "/fixture/transcript.jsonl",
        "cwd": "/fixture/work",
        "permission_mode": "dontAsk",
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.6-codex",
        "turn_id": "turn-id",
        "tool_name": "Bash",
        "tool_input": expected_input,
        "tool_use_id": "tool-use-id",
    }
    payload[field] = value

    with pytest.raises(ValueError):
        sanitize_pretooluse(
            payload,
            fixture_root=root,
            expected_tool_name="Bash",
            expected_tool_input=expected_input,
        )


@pytest.mark.parametrize(
    ("tool_name", "tool_input"),
    [
        ("Bash", {"command": "printf gate0-bash-nonce"}),
        (
            "apply_patch",
            {
                "command": (
                    "*** Begin Patch\n"
                    "*** Add File: gate0-patch-nonce\n"
                    "+gate0-patch-nonce\n"
                    "*** End Patch\n"
                )
            },
        ),
        (
            "mcp__palonexus_fixture__write_sentinel",
            {"nonce": "gate0-mcp-nonce"},
        ),
    ],
)
def test_strict_sanitizer_accepts_only_exact_control_inputs(
    tool_name: str, tool_input: dict[str, object]
) -> None:
    payload = {
        "session_id": "session-id",
        "transcript_path": "/fixture/transcript.jsonl",
        "cwd": "/fixture/work",
        "permission_mode": "dontAsk",
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.6-codex",
        "turn_id": "turn-id",
        "tool_name": tool_name,
        "tool_input": tool_input,
        "tool_use_id": "tool-use-id",
    }

    sanitized = sanitize_pretooluse(
        payload,
        fixture_root=Path("/fixture"),
        expected_tool_name=tool_name,
        expected_tool_input=tool_input,
    )

    assert sanitized["cwd"] == "<fixture-root>/work"
    assert sanitized["transcript_path"] == "<fixture-root>/transcript.jsonl"
    assert sanitized["tool_input"] == tool_input
    assert canonical_sha256(sanitized["tool_input"]) == canonical_sha256(tool_input)


def test_strict_sanitizer_rejects_tool_input_drift() -> None:
    payload = {
        "session_id": "session-id",
        "transcript_path": "/fixture/transcript.jsonl",
        "cwd": "/fixture/work",
        "permission_mode": "dontAsk",
        "hook_event_name": "PreToolUse",
        "model": "gpt-5.6-codex",
        "turn_id": "turn-id",
        "tool_name": "Bash",
        "tool_input": {"command": "printf wrong"},
        "tool_use_id": "tool-use-id",
    }

    with pytest.raises(ValueError, match="exact control input"):
        sanitize_pretooluse(
            payload,
            fixture_root=Path("/fixture"),
            expected_tool_name="Bash",
            expected_tool_input={"command": "printf gate0-bash-nonce"},
        )


def test_capture_environment_drops_credentials_proxies_and_cloud_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "secret")
    monkeypatch.setenv("CODEX_API_KEY", "secret")
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.invalid")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "secret")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", "/tmp/cloud.json")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")

    env = safe_environment(tmp_path / "home", tmp_path)

    assert env["PATH"] == "/usr/bin:/bin"
    assert env["HOME"] == str(tmp_path / "home")
    assert not any(
        re.search(
            r"(?i)(token|secret|credential|api_key|proxy|aws|azure|google|gcp)",
            key,
        )
        for key in env
    )


def test_docker_capture_envelope_is_pinned_and_least_privilege(
    tmp_path: Path,
) -> None:
    for name in ("binary", "fixture", "output", "work"):
        path = tmp_path / name
        if name == "binary":
            path.write_bytes(b"codex")
        else:
            path.mkdir()
    auth = tmp_path / "auth.json"
    auth.write_text("{}")
    image = "docker.io/library/python@sha256:" + "a" * 64

    command = docker_capture_command(
        image=image,
        binary=tmp_path / "binary",
        fixture_bundle=tmp_path / "fixture",
        output=tmp_path / "output",
        workspace=tmp_path / "work",
        auth=auth,
        network="bridge",
        command=["codex", "--version"],
    )
    rendered = " ".join(command)

    for required in (
        "--user 10001:10001",
        "--read-only",
        "--network bridge",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--cpus 1",
        "--memory 1g",
        "--pids-limit 128",
        "/home/fixture:rw,noexec,nosuid,nodev,size=128m,mode=1777",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "dst=/usr/local/bin/codex,readonly",
        "dst=/fixture,readonly",
        "dst=/output",
        "dst=/work",
        "dst=/fixture-auth.json,readonly",
    ):
        assert required in rendered
    assert command.count("--mount") == 5
    assert image in command


def test_docker_capture_rejects_mutable_image_or_unsafe_network(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "binary"
    binary.write_bytes(b"codex")
    auth = tmp_path / "auth.json"
    auth.write_text("{}")
    directories = []
    for name in ("fixture", "output", "work"):
        path = tmp_path / name
        path.mkdir()
        directories.append(path)

    with pytest.raises(ValueError, match="pinned by digest"):
        docker_capture_command(
            image="python:3.12",
            binary=binary,
            fixture_bundle=directories[0],
            output=directories[1],
            workspace=directories[2],
            auth=auth,
            network="bridge",
            command=[],
        )
    with pytest.raises(ValueError, match="explicitly bridge or none"):
        docker_capture_command(
            image="python@sha256:" + "a" * 64,
            binary=binary,
            fixture_bundle=directories[0],
            output=directories[1],
            workspace=directories[2],
            auth=auth,
            network="host",
            command=[],
        )


def test_capture_has_no_unsafe_fallback_or_source_workspace_mount() -> None:
    source = (ROOT / "scripts" / "capture_codex_fixtures.py").read_text()

    assert "--dangerously-bypass-approvals-and-sandbox" not in source
    assert "no unsafe fallback exists" in source
    assert "source workspace is never mounted" in source
    assert "fixture harness rejected unexpected tool input" in source
    assert "--dangerously-bypass-hook-trust" in source


def test_codex_compatibility_document_is_complete_and_honest() -> None:
    compatibility = (ROOT / "docs" / "compatibility.md").read_text(encoding="utf-8")
    for required in (
        "0.124.0",
        "0.145.0",
        "Gate 0",
        "Bash",
        "apply_patch",
        "MCP",
        "hosted",
        "specialized",
        "not a complete enforcement boundary",
    ):
        assert required in compatibility
