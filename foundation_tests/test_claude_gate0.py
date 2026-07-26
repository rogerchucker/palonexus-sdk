from __future__ import annotations

import importlib.util
import json
import re
import shutil
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
CAPTURE_SPEC = importlib.util.spec_from_file_location(
    "capture_claude_fixtures", ROOT / "scripts" / "capture_claude_fixtures.py"
)
assert CAPTURE_SPEC and CAPTURE_SPEC.loader
CAPTURE = importlib.util.module_from_spec(CAPTURE_SPEC)
CAPTURE_SPEC.loader.exec_module(CAPTURE)
sanitize_pretooluse = CAPTURE.sanitize_pretooluse
validate_evidence = CAPTURE.validate_evidence
safe_environment = CAPTURE._safe_environment
docker_capture_command = CAPTURE.docker_capture_command
FIXTURES = ROOT / "plugins" / "claude-code" / "tests" / "fixtures"
REQUIRED_TOOL_FAMILIES = {
    "bash",
    "read",
    "edit",
    "write",
    "webfetch",
    "websearch",
    "mcp",
}
REQUIRED_BLOCKING_SCENARIOS = {
    "structured_deny",
    "exit_2",
    "guard_failure",
    "approval_required",
    "stable_deny",
}
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_claude_gate0_fixture_is_complete_and_sanitized() -> None:
    payload_dir = FIXTURES / "pretooluse"
    observed = {path.stem for path in payload_dir.glob("*.json")}
    assert REQUIRED_TOOL_FAMILIES <= observed, (
        f"missing Claude PreToolUse families: "
        f"{sorted(REQUIRED_TOOL_FAMILIES - observed)}"
    )

    for family in REQUIRED_TOOL_FAMILIES:
        fixture = _load_json(payload_dir / f"{family}.json")
        assert fixture["hook_event_name"] == "PreToolUse"
        assert isinstance(fixture["tool_name"], str)
        assert isinstance(fixture["tool_input"], dict)
        serialized = json.dumps(fixture)
        assert "/Users/" not in serialized
        assert "prompt" not in serialized.lower()
        assert "token" not in serialized.lower()
        assert fixture["tool_name"] == {
            "bash": "Bash",
            "read": "Read",
            "edit": "Edit",
            "write": "Write",
            "webfetch": "WebFetch",
            "websearch": "WebSearch",
            "mcp": "mcp__fixture__ping",
        }[family]


def test_claude_gate0_records_host_and_official_contract_evidence() -> None:
    host = _load_json(FIXTURES / "host-version.json")
    assert host["candidate"]["version"]
    assert host["candidate"]["tested"] in {True, False}
    assert host["candidate"]["origin"]
    assert SHA256.fullmatch(host["candidate"]["sha256"])
    assert host["candidate"]["os"]
    assert host["candidate"]["arch"]
    assert host["latestStable"]["version"]
    assert host["latestStable"]["tested"] in {True, False}
    if not host["candidate"]["tested"] or not host["latestStable"]["tested"]:
        assert host["gateComplete"] is False
    container_attempt = host["containerAttempts"][-1]
    assert SHA256.fullmatch(container_attempt["derivedImageId"])
    assert "@sha256:" in container_attempt["baseImage"]
    assert container_attempt["network"] == "none"
    assert container_attempt["toolInvocationReached"] is False
    assert container_attempt["failureStage"] == "authentication"
    assert container_attempt["authMountDigestVerified"] is True
    assert container_attempt["authMountReadOnly"] is True
    assert container_attempt["workspaceMounted"] is False
    assert host["minimumSupported"]["status"] in {"established", "unresolved"}
    if host["minimumSupported"]["status"] == "established":
        assert host["minimumSupported"]["version"]
        assert host["minimumSupported"]["tested"] is True
    else:
        assert host["gateComplete"] is False

    contract = _load_json(FIXTURES / "official-contract.json")
    assert str(contract["url"]).startswith("https://code.claude.com/")
    assert contract["retrievedAt"]
    assert str(contract["sha256"]).startswith("sha256:")
    assert re.fullmatch(r"[0-9a-f]{40}", contract["changelog"]["commit"])
    assert contract["changelog"]["commit"] in contract["changelog"]["immutableUrl"]
    assert SHA256.fullmatch(contract["changelog"]["sha256"])
    assert "compare SHA-256" in contract["reproduction"]
    assert contract["documentedVersionEvidence"]["minimumVersion"] is None
    assert contract["blockingSemantics"]["structuredDeny"] is True
    assert contract["blockingSemantics"]["exit2"] is True
    assert contract["blockingSemantics"]["noopPreservesNativePermissions"] is True


def test_claim_excluded_legacy_evidence_makes_no_capability_claims() -> None:
    capabilities = _load_json(FIXTURES / "expected-capabilities.json")
    assert capabilities["scenarios"] == {}
    assert set(capabilities["legacyEvidenceFiles"]) == {
        f"legacy-scenarios/{scenario}.json"
        for scenario in REQUIRED_BLOCKING_SCENARIOS
    }
    for scenario in REQUIRED_BLOCKING_SCENARIOS:
        raw = _load_json(FIXTURES / f"legacy-scenarios/{scenario}.json")
        assert raw["evidenceStatus"] == "superseded-untrusted"
        assert raw["claimExcluded"] is True
        for result_field in (
            "guardExitCode",
            "hookExitCode",
            "hookInvocationCount",
            "hostRenderedEvidence",
            "nonce",
            "sentinelExistsAfter",
        ):
            assert raw.get(result_field) is None
        assert raw["limitation"]

    preservation = capabilities["nativePermissionPreservation"]
    for mode in ("nativeAllow", "nativeDeny"):
        assert preservation[mode]["status"] == "unresolved"
        assert preservation[mode]["limitation"]
        assert "baseline" not in preservation[mode]
        assert "noopHook" not in preservation[mode]


@pytest.mark.parametrize(
    "field,value",
    [
        ("unexpected", "value"),
        ("cwd", "/Users/alice/project"),
        ("cwd", "/home/alice/project"),
        ("cwd", r"C:\Users\alice\project"),
        ("cwd", r"\\server\share\project"),
        ("cwd", "/tmp/repo/../../etc"),
        ("tool_input", {"command": "echo bearer sk-secretvalue1234567890"}),
        ("tool_input", {"command": "alice@example.com"}),
        ("tool_input", {"command": "A" * 80}),
        ("permission_mode", "alice"),
        ("model", "claude-secret-prose"),
    ],
)
def test_strict_sanitizer_rejects_unexpected_or_sensitive_data(
    field: str, value: object
) -> None:
    payload: dict[str, object] = {
        "session_id": "session",
        "transcript_path": "/tmp/transcript",
        "cwd": "/tmp/repo",
        "permission_mode": "manual",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "printf fixture-bash"},
        "tool_use_id": "tool",
    }
    payload[field] = value
    with pytest.raises(ValueError):
        sanitize_pretooluse(payload, fixture_root=Path("/tmp"))


def test_strict_sanitizer_accepts_the_exact_control_fixture(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    payload = {
        "session_id": "session",
        "transcript_path": str(tmp_path / "transcript"),
        "cwd": str(repository),
        "permission_mode": "manual",
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "printf fixture-bash"},
        "tool_use_id": "tool",
    }

    sanitized = sanitize_pretooluse(payload, fixture_root=tmp_path)

    assert sanitized["cwd"] == "<fixture-root>/repo"
    assert sanitized["tool_input"] == {"command": "printf fixture-bash"}


def test_strict_sanitizer_rejects_symlink_escape(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    repository.mkdir()
    outside = tmp_path.parent / "outside-secret"
    link = repository / "escape"
    link.symlink_to(outside)
    payload = {
        "session_id": "session",
        "transcript_path": str(tmp_path / "transcript"),
        "cwd": str(repository),
        "permission_mode": "manual",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": str(link)},
        "tool_use_id": "tool",
    }

    with pytest.raises(ValueError, match="outside the disposable fixture root"):
        sanitize_pretooluse(payload, fixture_root=tmp_path)


def test_claude_compatibility_document_is_honest_about_the_gate() -> None:
    compatibility = (ROOT / "docs" / "compatibility.md").read_text(encoding="utf-8")
    assert "2.1.219" in compatibility
    assert "minimum" in compatibility.lower()
    assert "unresolved" in compatibility.lower()
    assert "Gate 0" in compatibility


def test_capture_environment_drops_credentials_proxies_and_cloud_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "secret")
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", "secret")
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


def test_capture_has_no_permission_bypass_or_unsafe_fallback() -> None:
    source = (ROOT / "scripts" / "capture_claude_fixtures.py").read_text()

    assert "--dangerously-skip-permissions" not in source
    assert "no unsafe fallback exists" in source
    assert '"/usr/bin/sandbox-exec"' in source
    assert "_sandbox_deny_canary(temp)" in source
    assert "fixture harness rejected unexpected tool input" in source


def test_docker_capture_envelope_is_pinned_and_least_privilege(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    credentials = tmp_path / "credentials.json"
    credentials.write_text("{}")
    image = "example.invalid/claude@sha256:" + "a" * 64

    command = docker_capture_command(
        image=image,
        output=output,
        credentials=credentials,
        network="none",
        command=["claude", "--version"],
    )
    rendered = " ".join(command)

    for required in (
        "--user 10001:10001",
        "--read-only",
        "--network none",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--cpus 1",
        "--memory 1g",
        "--pids-limit 128",
        "/home/fixture:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "dst=/output",
        "dst=/home/fixture/.claude/.credentials.json,readonly",
    ):
        assert required in rendered
    assert command.count("--mount") == 2
    assert image in command


def test_docker_capture_rejects_mutable_image_or_implicit_network(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    output.mkdir()
    credentials = tmp_path / "credentials.json"
    credentials.write_text("{}")

    with pytest.raises(ValueError, match="pinned by digest"):
        docker_capture_command(
            image="node:22",
            output=output,
            credentials=credentials,
            network="none",
            command=[],
        )
    with pytest.raises(ValueError, match="explicitly"):
        docker_capture_command(
            image="node@sha256:" + "a" * 64,
            output=output,
            credentials=credentials,
            network="host",
            command=[],
        )


def test_cross_file_validator_rejects_scenario_tampering(tmp_path: Path) -> None:
    fixtures = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, fixtures)
    raw_path = fixtures / "legacy-scenarios" / "structured_deny.json"
    raw = _load_json(raw_path)
    raw["sentinelExistsAfter"] = False
    raw_path.write_text(json.dumps(raw), encoding="utf-8")

    errors = validate_evidence(fixtures)

    assert (
        "legacy capability result must be unknown: "
        "legacy-scenarios/structured_deny.json/sentinelExistsAfter"
        in errors
    )


def test_claude_gate0_requires_complete_trusted_evidence() -> None:
    capabilities = _load_json(FIXTURES / "expected-capabilities.json")
    evidence_errors = validate_evidence(FIXTURES)

    assert evidence_errors == [] and capabilities["gateComplete"] is True, (
        "trusted Claude Gate 0 evidence is missing; superseded observations "
        f"cannot satisfy the gate: {evidence_errors}"
    )
