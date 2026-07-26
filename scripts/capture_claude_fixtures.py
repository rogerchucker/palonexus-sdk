"""Capture sanitized Claude Code PreToolUse and blocking evidence.

This script intentionally uses a disposable HOME and repository. It requires an
authenticated Claude Code installation because the host must actually choose
and invoke its tools. Raw hook input is retained only in the temporary
directory; committed fixtures are sanitized before they leave that directory.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plugins" / "claude-code" / "tests" / "fixtures"
HOOKS_URL = "https://code.claude.com/docs/en/hooks.md"
CHANGELOG_URL = (
    "https://raw.githubusercontent.com/anthropics/claude-code/main/CHANGELOG.md"
)
APPROVAL_ID = "apr_fixture_01"
TOOL_FILES = {
    "Bash": "bash",
    "Read": "read",
    "Edit": "edit",
    "Write": "write",
    "WebFetch": "webfetch",
    "WebSearch": "websearch",
}
EXPECTED_TOOL_NAMES = {
    "bash": "Bash",
    "read": "Read",
    "edit": "Edit",
    "write": "Write",
    "webfetch": "WebFetch",
    "websearch": "WebSearch",
    "mcp": "mcp__fixture__ping",
}
RAW_TOP_LEVEL_FIELDS = {
    "cwd",
    "effort",
    "hook_event_name",
    "permission_mode",
    "session_id",
    "tool_input",
    "tool_name",
    "tool_use_id",
    "transcript_path",
}
TOOL_INPUT_FIELDS = {
    "Bash": {"command", "description"},
    "Read": {"file_path", "limit", "offset"},
    "Edit": {"file_path", "new_string", "old_string", "replace_all"},
    "Write": {"content", "file_path"},
    "WebFetch": {"url"},
    "WebSearch": {"query"},
    "mcp__fixture__ping": set(),
}
REQUIRED_FAMILIES = set(EXPECTED_TOOL_NAMES)
REQUIRED_SCENARIOS = {
    "structured_deny",
    "exit_2",
    "guard_failure",
    "approval_required",
    "stable_deny",
}
SENSITIVE = re.compile(
    r"(?i)(bearer\s+|api[_-]?key|access[_-]?token|secret|"
    r"sk-[a-z0-9_-]{12,}|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})"
)
WINDOWS_ABSOLUTE = re.compile(r"(?i)^[a-z]:[\\/]|^\\\\")
HIGH_ENTROPY = re.compile(r"(?<![a-zA-Z0-9])[A-Za-z0-9+/=_-]{64,}(?![a-zA-Z0-9])")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
SAFE_ENV_KEYS = {
    "HOME",
    "LANG",
    "LC_ALL",
    "PATH",
    "SHELL",
    "SSL_CERT_FILE",
    "TERM",
    "TMPDIR",
}


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: int = 240,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def _version(command: list[str], env: dict[str, str], *, timeout: int = 60) -> str:
    result = _run(command + ["--version"], cwd=ROOT, env=env, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    match = re.search(r"\d+\.\d+\.\d+", result.stdout)
    if match is None:
        raise RuntimeError(f"could not parse Claude version: {result.stdout!r}")
    return match.group()


def _download(url: str, *, env: dict[str, str], cwd: Path) -> bytes:
    result = subprocess.run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--user-agent",
            "palonexus-sdk-gate0/0.1",
            url,
        ],
        cwd=cwd,
        env=env,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace"))
    return result.stdout


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return f"sha256:{digest.hexdigest()}"


def _safe_environment(home: Path, temp: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if key in SAFE_ENV_KEYS and value
    }
    env.update(
        {
            "HOME": str(home),
            "LANG": env.get("LANG", "C.UTF-8"),
            "PATH": env.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin"),
            "SHELL": "/bin/sh",
            "TMPDIR": str(temp),
        }
    )
    forbidden = re.compile(
        r"(?i)(TOKEN|SECRET|PASSWORD|CREDENTIAL|API_KEY|PROXY|AWS|AZURE|GOOGLE|GCP)"
    )
    leaked = sorted(key for key in env if forbidden.search(key))
    if leaked:
        raise RuntimeError(f"unsafe environment keys survived scrubbing: {leaked}")
    return env


def _sandbox_profile(temp: Path, executables: list[Path]) -> tuple[Path, str]:
    if platform.system() != "Darwin" or shutil.which("sandbox-exec") is None:
        raise RuntimeError(
            "safe capture requires macOS sandbox-exec; no unsafe fallback exists"
        )
    quoted_temp = json.dumps(str(temp.resolve()))
    executable_rules = "\n".join(
        f"  (literal {json.dumps(str(path.resolve()))})" for path in executables
    )
    profile = temp / "capture.sb"
    profile.write_text(
        f"""\
(version 1)
(deny default)
(allow process*)
(allow network*)
(allow mach-lookup)
(allow ipc-posix*)
(allow sysctl-read)
(allow file-read-metadata)
(allow file-read*
  (subpath "/System")
  (subpath "/usr")
  (subpath "/bin")
  (subpath "/sbin")
  (subpath "/Library")
  (subpath "/usr/local")
  (subpath "/opt")
  (subpath "/private/etc")
  (subpath {quoted_temp})
{executable_rules})
(allow file-write* (subpath {quoted_temp}))
"""
    )
    return profile, _sha256_file(profile)


def _fixture_relative(value: str, fixture_root: Path) -> str:
    if WINDOWS_ABSOLUTE.search(value):
        raise ValueError("Windows or UNC absolute paths are forbidden")
    aliases = {str(fixture_root), str(fixture_root.resolve())}
    for alias in sorted(aliases, key=len, reverse=True):
        if value == alias:
            return "<fixture-root>"
        if value.startswith(alias + "/"):
            return "<fixture-root>/" + value[len(alias) + 1 :]
    raise ValueError("absolute path is outside the disposable fixture root")


def _safe_scalar(value: Any) -> Any:
    if isinstance(value, bool) or value is None:
        return value
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if not isinstance(value, str):
        raise ValueError(f"unsupported fixture scalar: {type(value).__name__}")
    if SENSITIVE.search(value) or HIGH_ENTROPY.search(value):
        raise ValueError("sensitive or high-entropy value rejected")
    if value.startswith(("/", "~")) or WINDOWS_ABSOLUTE.search(value):
        raise ValueError("unexpected absolute path")
    return value


def sanitize_pretooluse(
    payload: dict[str, Any], *, fixture_root: Path
) -> dict[str, Any]:
    """Validate a host payload and retain only the factual contract fields."""
    unexpected = set(payload) - RAW_TOP_LEVEL_FIELDS
    if unexpected:
        raise ValueError(f"unexpected PreToolUse fields: {sorted(unexpected)}")
    missing = {
        "cwd",
        "hook_event_name",
        "permission_mode",
        "tool_input",
        "tool_name",
    } - set(payload)
    if missing:
        raise ValueError(f"missing PreToolUse fields: {sorted(missing)}")
    if payload["hook_event_name"] != "PreToolUse":
        raise ValueError("not a PreToolUse payload")
    if payload["permission_mode"] not in {
        "acceptEdits",
        "auto",
        "bypassPermissions",
        "dontAsk",
        "manual",
        "plan",
    }:
        raise ValueError("unexpected permission mode")
    tool_name = payload["tool_name"]
    if tool_name not in TOOL_INPUT_FIELDS:
        raise ValueError(f"unsupported tool: {tool_name!r}")
    tool_input = payload["tool_input"]
    if not isinstance(tool_input, dict):
        raise ValueError("tool_input must be an object")
    unexpected_input = set(tool_input) - TOOL_INPUT_FIELDS[tool_name]
    if unexpected_input:
        raise ValueError(
            f"unexpected {tool_name} input fields: {sorted(unexpected_input)}"
        )

    clean_input: dict[str, Any] = {}
    for key, value in tool_input.items():
        if key == "description":
            continue
        if key == "file_path":
            if not isinstance(value, str):
                raise ValueError("file_path must be a string")
            clean_input[key] = _fixture_relative(value, fixture_root)
        elif key == "command":
            if not isinstance(value, str) or not re.fullmatch(
                r"(?:printf fixture-bash|touch sentinel-[a-z0-9_-]+)", value
            ):
                raise ValueError("Bash command is not an approved fixture command")
            clean_input[key] = value
        elif key == "url":
            if value != "https://example.com":
                raise ValueError("unexpected WebFetch URL")
            clean_input[key] = value
        elif key == "query":
            if value != "example domain":
                raise ValueError("unexpected WebSearch query")
            clean_input[key] = value
        elif key in {"content", "new_string", "old_string"}:
            if value not in {"fixture\n", "edited", "before"}:
                raise ValueError(f"unexpected fixture content in {key}")
            clean_input[key] = value
        else:
            clean_input[key] = _safe_scalar(value)

    result = {
        "cwd": _fixture_relative(str(payload["cwd"]), fixture_root),
        "hook_event_name": "PreToolUse",
        "permission_mode": _safe_scalar(payload["permission_mode"]),
        "session_id": "<session-id>",
        "tool_input": clean_input,
        "tool_name": tool_name,
        "tool_use_id": "<tool-use-id>",
        "transcript_path": "<transcript-path>",
    }
    serialized = json.dumps(result, sort_keys=True)
    if SENSITIVE.search(serialized) or HIGH_ENTROPY.search(serialized):
        raise ValueError("sanitized fixture still resembles sensitive data")
    return result


def _parse_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None


def _validate_sanitized_fixture(
    fixture: object, *, expected_tool: str
) -> list[str]:
    if not isinstance(fixture, dict):
        return ["fixture is not an object"]
    expected_fields = {
        "cwd",
        "hook_event_name",
        "permission_mode",
        "session_id",
        "tool_input",
        "tool_name",
        "tool_use_id",
        "transcript_path",
    }
    errors: list[str] = []
    if set(fixture) != expected_fields:
        errors.append("sanitized fixture fields are not exact")
    if fixture.get("tool_name") != expected_tool:
        errors.append("sanitized fixture tool does not match filename")
    if fixture.get("hook_event_name") != "PreToolUse":
        errors.append("sanitized fixture event is not PreToolUse")
    if fixture.get("session_id") != "<session-id>":
        errors.append("session ID is not redacted")
    if fixture.get("tool_use_id") != "<tool-use-id>":
        errors.append("tool-use ID is not redacted")
    if fixture.get("transcript_path") != "<transcript-path>":
        errors.append("transcript path is not redacted")
    cwd = fixture.get("cwd")
    if not isinstance(cwd, str) or not cwd.startswith("<fixture-root>/"):
        errors.append("cwd is not fixture-relative")
    tool_input = fixture.get("tool_input")
    if not isinstance(tool_input, dict):
        errors.append("sanitized tool input is not an object")
    elif set(tool_input) - (TOOL_INPUT_FIELDS[expected_tool] - {"description"}):
        errors.append("sanitized tool input has unexpected fields")
    serialized = json.dumps(fixture, sort_keys=True)
    forbidden_path = re.compile(
        r"(?i)(/Users/|/home/|(?:^|[\"\s])[a-z]:[\\/]|\\\\[^\\])"
    )
    if (
        SENSITIVE.search(serialized)
        or HIGH_ENTROPY.search(serialized)
        or forbidden_path.search(serialized)
    ):
        errors.append("sanitized fixture contains sensitive data or an absolute path")
    if any(
        marker in serialized.lower()
        for marker in ('"prompt', '"model', '"token', '"username')
    ):
        errors.append("sanitized fixture contains forbidden prose/identity fields")
    return errors


def validate_evidence(fixtures: Path) -> list[str]:
    """Cross-check committed Claude evidence instead of trusting status flags."""
    errors: list[str] = []
    try:
        host = json.loads((fixtures / "host-version.json").read_text())
        capabilities = json.loads(
            (fixtures / "expected-capabilities.json").read_text()
        )
        contract = json.loads((fixtures / "official-contract.json").read_text())
    except (OSError, json.JSONDecodeError) as exc:
        return [f"cannot load evidence: {exc}"]
    if not _parse_timestamp(host.get("capturedAt")):
        errors.append("invalid host capture timestamp")
    candidate = host.get("candidate", {})
    if not SHA256.fullmatch(str(candidate.get("sha256", ""))):
        errors.append("invalid candidate executable digest")
    if not candidate.get("os") or not candidate.get("arch"):
        errors.append("candidate platform identity is incomplete")
    if set(capabilities.get("toolFamilies", [])) != REQUIRED_FAMILIES:
        errors.append("claimed tool family set is not exact")
    for family, tool_name in EXPECTED_TOOL_NAMES.items():
        try:
            fixture = json.loads(
                (fixtures / "pretooluse" / f"{family}.json").read_text()
            )
        except (OSError, json.JSONDecodeError):
            errors.append(f"missing or invalid payload fixture: {family}")
            continue
        if fixture.get("tool_name") != tool_name:
            errors.append(f"filename/tool mismatch: {family}")
        errors.extend(
            f"{family}: {error}"
            for error in _validate_sanitized_fixture(
                fixture, expected_tool=tool_name
            )
        )
    scenarios = capabilities.get("scenarios", {})
    if set(scenarios) != REQUIRED_SCENARIOS:
        errors.append("blocking scenario set is not exact")
    for name in REQUIRED_SCENARIOS:
        summary = scenarios.get(name, {})
        raw_path = summary.get("rawEvidence")
        if raw_path != f"scenarios/{name}.json":
            errors.append(f"bad raw evidence path: {name}")
            continue
        try:
            raw = json.loads((fixtures / raw_path).read_text())
        except (OSError, json.JSONDecodeError):
            errors.append(f"missing raw evidence: {name}")
            continue
        for key in ("nonce", "attemptFingerprint", "hookInvocationCount"):
            if raw.get(key) != summary.get(key):
                errors.append(f"scenario summary/raw mismatch: {name}/{key}")
        if raw.get("hostVersion") != summary.get("hostVersion"):
            errors.append(f"scenario version mismatch: {name}")
        if raw.get("platform") != candidate.get("os"):
            errors.append(f"scenario platform mismatch: {name}")
        evidence_status = raw.get("evidenceStatus")
        if evidence_status == "trusted-sandboxed":
            if raw.get("hookInvocationCount") != 1:
                errors.append(f"scenario did not invoke exactly one hook: {name}")
            if not raw.get("hostRenderedEvidence"):
                errors.append(f"missing host-rendered evidence: {name}")
        elif evidence_status == "superseded-untrusted":
            if raw.get("claimExcluded") is not True:
                errors.append(f"untrusted scenario is not claim-excluded: {name}")
            if raw.get("hookInvocationCount") is not None:
                errors.append(f"untrusted hook count must remain unknown: {name}")
            if raw.get("hostRenderedEvidence") is not None:
                errors.append(
                    f"untrusted rendered evidence must remain unknown: {name}"
                )
            if not raw.get("limitation"):
                errors.append(f"untrusted scenario lacks limitation: {name}")
        else:
            errors.append(f"unknown evidence status: {name}")
        if not SHA256.fullmatch(str(raw.get("attemptFingerprint", ""))):
            errors.append(f"invalid attempt fingerprint: {name}")
        if raw.get("sentinelExistsAfter") is not False:
            errors.append(f"sentinel was not proven absent: {name}")
    for digest_key in ("sha256",):
        if not SHA256.fullmatch(str(contract.get(digest_key, ""))):
            errors.append(f"invalid official contract {digest_key}")
    if not _parse_timestamp(contract.get("retrievedAt")):
        errors.append("invalid contract retrieval timestamp")
    return errors


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def _runtime_files(temp: Path) -> tuple[Path, Path, Path]:
    hook = temp / "hook.py"
    fake_guard = temp / "fake_guard.py"
    mcp_server = temp / "mcp_server.py"
    hook.write_text(
        """\
import json
import hashlib
import os
import subprocess
import sys
from pathlib import Path

payload = json.load(sys.stdin)
root = Path(os.environ["PALONEXUS_FIXTURE_ROOT"]).resolve()
tool_name = payload.get("tool_name")
tool_input = payload.get("tool_input")
if not isinstance(tool_input, dict):
    print("fixture harness rejected non-object tool input", file=sys.stderr)
    raise SystemExit(2)
valid = True
if tool_name == "Bash":
    valid = set(tool_input) <= {"command", "description"}
    valid = valid and bool(__import__("re").fullmatch(
        r"(?:printf fixture-bash|touch sentinel-[a-z0-9_-]+)",
        tool_input.get("command", ""),
    ))
elif tool_name in {"Read", "Edit", "Write"}:
    allowed = {
        "Read": {"file_path", "limit", "offset"},
        "Edit": {"file_path", "old_string", "new_string", "replace_all"},
        "Write": {"file_path", "content"},
    }[tool_name]
    valid = set(tool_input) <= allowed
    try:
        path = Path(tool_input.get("file_path", "")).resolve()
        valid = valid and path.is_relative_to(root)
    except (OSError, TypeError):
        valid = False
    if tool_name == "Edit":
        valid = valid and tool_input.get("old_string") == "before"
        valid = valid and tool_input.get("new_string") == "edited"
    elif tool_name == "Write":
        valid = valid and tool_input.get("content") == "fixture\\n"
elif tool_name == "WebFetch":
    valid = valid and tool_input == {"url": "https://example.com"}
elif tool_name == "WebSearch":
    valid = valid and tool_input == {"query": "example domain"}
elif tool_name == "mcp__fixture__ping":
    valid = valid and tool_input == {}
else:
    valid = False
if not valid:
    print("fixture harness rejected unexpected tool input", file=sys.stderr)
    raise SystemExit(2)
capture = Path(os.environ["PALONEXUS_CAPTURE_DIR"])
capture.mkdir(parents=True, exist_ok=True)
name = payload.get("tool_name", "unknown").replace("/", "_")
(capture / f"{name}.json").write_text(json.dumps(payload))
mode = os.environ.get("PALONEXUS_HOOK_MODE", "noop")
nonce = os.environ.get("PALONEXUS_SCENARIO_NONCE")
scenario_log = os.environ.get("PALONEXUS_SCENARIO_LOG")
record = {
    "nonce": nonce,
    "hookMode": mode,
    "toolName": payload.get("tool_name"),
    "attemptFingerprint": "sha256:" + hashlib.sha256(
        json.dumps(
            {
                "tool_name": payload.get("tool_name"),
                "tool_input": payload.get("tool_input"),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest(),
    "hookExitCode": 0,
    "hookResult": "empty_json",
}
def persist():
    if scenario_log:
        with Path(scenario_log).open("a") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\\n")
if mode == "noop":
    persist()
    print("{}")
elif mode == "deny":
    record["hookResult"] = "structured_deny"
    persist()
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "fixture structured denial",
    }}))
elif mode == "exit2":
    record["hookExitCode"] = 2
    record["hookResult"] = "exit_2"
    persist()
    print("fixture exit-2 denial", file=sys.stderr)
    raise SystemExit(2)
elif mode == "guard_failure":
    guard = subprocess.run(
        [sys.executable, os.environ["PALONEXUS_FAKE_GUARD"], "--fail"],
        text=True, capture_output=True,
    )
    if guard.returncode == 0:
        raise SystemExit("fake guard unexpectedly succeeded")
    record["guardExitCode"] = guard.returncode
    record["hookResult"] = "guard_failure_deny"
    persist()
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "PaloNexus guard unavailable",
    }}))
elif mode == "approval":
    guard = subprocess.run(
        [sys.executable, os.environ["PALONEXUS_FAKE_GUARD"]],
        text=True, capture_output=True, check=True,
    )
    decision = json.loads(guard.stdout)
    reason = (
        "PaloNexus approval required: "
        + decision["approvalId"]
        + "; approve centrally, then retry"
    )
    record["guardExitCode"] = guard.returncode
    record["hookResult"] = "approval_required_deny"
    record["approvalId"] = decision["approvalId"]
    persist()
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": reason,
    }}))
else:
    raise SystemExit("unknown hook mode")
"""
    )
    fake_guard.write_text(
        'import json\nimport sys\n'
        'if "--fail" in sys.argv:\n'
        '    raise SystemExit(69)\n'
        'print(json.dumps({"outcome": "approval_required", '
        f'"approvalId": "{APPROVAL_ID}"}}))\n'
    )
    mcp_server.write_text(
        """\
import json
import sys

for line in sys.stdin:
    message = json.loads(line)
    method = message.get("method")
    if "id" not in message:
        continue
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fixture", "version": "1.0.0"},
        }
    elif method == "tools/list":
        result = {"tools": [{
            "name": "ping",
            "description": "Return a fixed fixture response.",
            "inputSchema": {"type": "object", "properties": {}},
        }]}
    elif method == "tools/call":
        result = {"content": [{"type": "text", "text": "fixture-pong"}]}
    else:
        result = {}
    print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}),
          flush=True)
"""
    )
    return hook, fake_guard, mcp_server


def _settings(hook: Path) -> dict[str, object]:
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": shutil.which("python3") or "python3",
                            "args": [str(hook)],
                        }
                    ],
                }
            ]
        }
    }


def _invoke(
    claude: list[str],
    prompt: str,
    *,
    repo: Path,
    settings: Path,
    env: dict[str, str],
    tools: str | None,
    sandbox_profile: Path,
    mcp_config: Path | None = None,
    allowed_tools: str | None = None,
    permission_mode: str = "manual",
) -> subprocess.CompletedProcess[str]:
    command = [
        shutil.which("sandbox-exec") or "sandbox-exec",
        "-f",
        str(sandbox_profile),
        *claude,
        "-p",
        prompt,
        "--settings",
        str(settings),
        "--setting-sources",
        "user",
        "--permission-mode",
        permission_mode,
        "--no-session-persistence",
        "--output-format",
        "json",
    ]
    if tools is not None:
        command += ["--tools", tools]
    if allowed_tools is not None:
        command += ["--allowedTools", allowed_tools]
    if mcp_config is not None:
        command += ["--mcp-config", str(mcp_config), "--strict-mcp-config"]
    return _run(command, cwd=repo, env=env)


def _require_success(result: subprocess.CompletedProcess[str], label: str) -> None:
    if result.returncode:
        raise RuntimeError(
            f"{label} failed ({result.returncode}): "
            f"{result.stderr[-1000:] or result.stdout[-1000:]}"
        )


def capture() -> None:
    installed = shutil.which("claude")
    if installed is None:
        raise RuntimeError("Claude Code is not installed")
    with tempfile.TemporaryDirectory(prefix="palonexus-claude-gate0-") as raw:
        temp = Path(raw)
        home = temp / "home"
        repo = temp / "repo"
        captures = temp / "captures"
        npm_cache = temp / "npm-cache"
        home.mkdir()
        repo.mkdir()
        base_env = _safe_environment(home, temp)
        candidate_path = Path(installed).resolve()
        candidate_version = _version([installed], base_env)
        tags_result = _run(
            ["npm", "view", "@anthropic-ai/claude-code", "dist-tags", "--json"],
            cwd=repo,
            env=base_env,
            timeout=60,
        )
        _require_success(tags_result, "npm Claude dist-tags lookup")
        stable_version = json.loads(tags_result.stdout)["stable"]
        commit_result = _run(
            ["git", "ls-remote", "https://github.com/anthropics/claude-code", "HEAD"],
            cwd=repo,
            env=base_env,
            timeout=60,
        )
        _require_success(commit_result, "Claude changelog commit lookup")
        changelog_commit = commit_result.stdout.split()[0]
        pinned_changelog_url = (
            "https://raw.githubusercontent.com/anthropics/claude-code/"
            f"{changelog_commit}/CHANGELOG.md"
        )
        hooks_doc = _download(HOOKS_URL, env=base_env, cwd=repo)
        changelog = _download(pinned_changelog_url, env=base_env, cwd=repo)
        retrieved_at = datetime.now(UTC).replace(microsecond=0).isoformat()
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
        stable_command = [
            "npx",
            "--cache",
            str(npm_cache),
            "-y",
            f"@anthropic-ai/claude-code@{stable_version}",
        ]
        if _version(stable_command, base_env, timeout=240) != stable_version:
            raise RuntimeError("npm stable Claude version did not match its dist-tag")
        (repo / "existing.txt").write_text("before\n")
        hook, fake_guard, mcp_server = _runtime_files(temp)
        sandbox_profile, sandbox_digest = _sandbox_profile(
            temp,
            [
                candidate_path,
                Path(shutil.which("python3") or "/usr/bin/python3"),
                Path(shutil.which("node") or "/usr/local/bin/node"),
                Path(shutil.which("npx") or "/usr/local/bin/npx"),
            ],
        )
        settings = temp / "settings.json"
        _write_json(settings, _settings(hook))
        empty_settings = temp / "empty-settings.json"
        _write_json(empty_settings, {})
        mcp_config = temp / "mcp.json"
        _write_json(
            mcp_config,
            {
                "mcpServers": {
                    "fixture": {
                        "command": shutil.which("python3") or "python3",
                        "args": [str(mcp_server)],
                    }
                }
            },
        )

        env = base_env.copy()
        env.update(
            {
                "HOME": str(home),
                "PALONEXUS_CAPTURE_DIR": str(captures),
                "PALONEXUS_FAKE_GUARD": str(fake_guard),
                "PALONEXUS_FIXTURE_ROOT": str(temp),
                "PALONEXUS_HOOK_MODE": "noop",
            }
        )
        local_result = _invoke(
            [installed],
            "Use each available tool exactly once: Bash `printf fixture-bash`; "
            "Read existing.txt; Edit existing.txt from `before` to `edited`; "
            "Write new.txt containing `fixture`. Do not retry.",
            repo=repo,
            settings=settings,
            env=env,
            tools="Bash,Read,Edit,Write",
            allowed_tools="Bash,Read,Edit,Write",
            sandbox_profile=sandbox_profile,
        )
        _require_success(local_result, "candidate local payload capture")
        web_result = _invoke(
            [installed],
            "Use WebFetch once for https://example.com and WebSearch once for "
            "`example domain`. Do not use local tools and do not retry.",
            repo=repo,
            settings=settings,
            env=env,
            tools="WebFetch,WebSearch",
            allowed_tools="WebFetch,WebSearch",
            sandbox_profile=sandbox_profile,
        )
        _require_success(web_result, "candidate network payload capture")
        mcp_result = _invoke(
            [installed],
            "Call the fixture MCP ping tool exactly once. Do not do anything else.",
            repo=repo,
            settings=settings,
            env=env,
            tools=None,
            mcp_config=mcp_config,
            allowed_tools="mcp__fixture__ping",
            sandbox_profile=sandbox_profile,
        )
        _require_success(mcp_result, "candidate MCP capture")

        raw_by_family: dict[str, dict[str, Any]] = {}
        for path in captures.glob("*.json"):
            payload = json.loads(path.read_text())
            tool_name = str(payload.get("tool_name", ""))
            if tool_name.startswith("mcp__"):
                raw_by_family["mcp"] = payload
            elif tool_name in TOOL_FILES:
                raw_by_family[TOOL_FILES[tool_name]] = payload
        missing = set(TOOL_FILES.values()) | {"mcp"}
        missing -= raw_by_family.keys()
        if missing:
            raise RuntimeError(
                f"host did not invoke required tool families: {sorted(missing)}; "
                f"MCP stdout={mcp_result.stdout[-2000:]!r}; "
                f"MCP stderr={mcp_result.stderr[-2000:]!r}; "
                f"captures={sorted(path.name for path in captures.glob('*.json'))}"
            )

        scenario_results: dict[str, dict[str, Any]] = {}
        expected_reasons = {
            "structured_deny": "fixture structured denial",
            "exit_2": "fixture exit-2 denial",
            "guard_failure": "PaloNexus guard unavailable",
            "approval_required": (
                f"PaloNexus approval required: {APPROVAL_ID}; "
                "approve centrally, then retry"
            ),
        }
        for name, mode in (
            ("structured_deny", "deny"),
            ("exit_2", "exit2"),
            ("guard_failure", "guard_failure"),
            ("approval_required", "approval"),
        ):
            nonce = secrets.token_hex(8)
            sentinel = repo / f"sentinel-{name}-{nonce}"
            scenario_log = temp / f"{name}.jsonl"
            env["PALONEXUS_HOOK_MODE"] = mode
            env["PALONEXUS_SCENARIO_NONCE"] = nonce
            env["PALONEXUS_SCENARIO_LOG"] = str(scenario_log)
            scenario = _invoke(
                [installed],
                f"Use Bash exactly once to run `touch {sentinel.name}`. "
                "Do not use another tool and do not retry.",
                repo=repo,
                settings=settings,
                env=env,
                tools="Bash",
                allowed_tools="Bash",
                sandbox_profile=sandbox_profile,
            )
            _require_success(scenario, name)
            rendered = expected_reasons[name]
            if rendered not in scenario.stdout + scenario.stderr:
                raise RuntimeError(f"{name}: host did not render hook evidence")
            mutated = sentinel.exists()
            if mutated:
                raise RuntimeError(f"{name}: denied sentinel mutated")
            records = [
                json.loads(line)
                for line in scenario_log.read_text().splitlines()
                if line
            ]
            if len(records) != 1:
                raise RuntimeError(
                    f"{name}: expected one hook invocation, got {len(records)}"
                )
            record = records[0]
            entry: dict[str, Any] = {
                "testedWithRealHost": True,
                "hostVersion": candidate_version,
                "hostProcessExitCode": scenario.returncode,
                "hostResult": "blocked",
                "sentinelMutated": False,
                "nonce": nonce,
                "attemptFingerprint": record["attemptFingerprint"],
                "hookInvocationCount": 1,
                "rawEvidence": f"scenarios/{name}.json",
            }
            if name == "guard_failure":
                entry["guardExitCode"] = record["guardExitCode"]
            if name == "approval_required":
                entry |= {
                    "guardResult": {
                        "outcome": "approval_required",
                        "approvalId": APPROVAL_ID,
                    },
                    "renderedReason": (
                        f"PaloNexus approval required: {APPROVAL_ID}; "
                        "approve centrally, then retry"
                    ),
                }
            scenario_results[name] = entry
            _write_json(
                FIXTURES / "scenarios" / f"{name}.json",
                {
                    **record,
                    "hookInvocationCount": 1,
                    "hostVersion": candidate_version,
                    "platform": platform.system(),
                    "arch": platform.machine(),
                    "hostProcessExitCode": scenario.returncode,
                    "hostRenderedEvidence": rendered,
                    "sentinelExistsAfter": False,
                    "sandboxProfileSha256": sandbox_digest,
                    "environmentPolicy": "strict-allowlist",
                    "evidenceStatus": "trusted-sandboxed",
                },
            )

        # Run the same blocking sentinel on npm's stable dist-tag. This is the
        # latest stable compatibility evidence, not minimum-version evidence.
        stable_nonce = secrets.token_hex(8)
        stable_sentinel = repo / f"sentinel-stable-deny-{stable_nonce}"
        stable_log = temp / "stable-deny.jsonl"
        env["PALONEXUS_HOOK_MODE"] = "deny"
        env["PALONEXUS_SCENARIO_NONCE"] = stable_nonce
        env["PALONEXUS_SCENARIO_LOG"] = str(stable_log)
        stable_result = _invoke(
            stable_command,
            f"Use Bash exactly once to run `touch {stable_sentinel.name}`. "
            "Do not use another tool and do not retry.",
            repo=repo,
            settings=settings,
            env=env,
            tools="Bash",
            allowed_tools="Bash",
            sandbox_profile=sandbox_profile,
        )
        _require_success(stable_result, "latest stable denial")
        if stable_sentinel.exists():
            raise RuntimeError("latest stable host executed a denied sentinel")
        if "fixture structured denial" not in (
            stable_result.stdout + stable_result.stderr
        ):
            raise RuntimeError("latest stable host did not render denial evidence")
        stable_records = [
            json.loads(line) for line in stable_log.read_text().splitlines() if line
        ]
        if len(stable_records) != 1:
            raise RuntimeError(
                "latest stable denial did not invoke exactly one hook"
            )
        stable_record = stable_records[0]
        scenario_results["stable_deny"] = {
            "testedWithRealHost": True,
            "hostVersion": stable_version,
            "hostProcessExitCode": stable_result.returncode,
            "hostResult": "blocked",
            "sentinelMutated": False,
            "nonce": stable_nonce,
            "attemptFingerprint": stable_record["attemptFingerprint"],
            "hookInvocationCount": 1,
            "rawEvidence": "scenarios/stable_deny.json",
        }
        _write_json(
            FIXTURES / "scenarios" / "stable_deny.json",
            {
                **stable_record,
                "hookInvocationCount": 1,
                "hostVersion": stable_version,
                "platform": platform.system(),
                "arch": platform.machine(),
                "hostProcessExitCode": stable_result.returncode,
                "hostRenderedEvidence": "fixture structured denial",
                "sentinelExistsAfter": False,
                "sandboxProfileSha256": sandbox_digest,
                "environmentPolicy": "strict-allowlist",
                "evidenceStatus": "trusted-sandboxed",
            },
        )

        def permission_probe(
            label: str,
            probe_settings: Path,
            *,
            allow: bool,
        ) -> dict[str, Any]:
            sentinel = repo / f"sentinel-{label}"
            env["PALONEXUS_HOOK_MODE"] = "noop"
            env.pop("PALONEXUS_SCENARIO_LOG", None)
            env.pop("PALONEXUS_SCENARIO_NONCE", None)
            result = _invoke(
                [installed],
                f"Use Bash exactly once to run `touch {sentinel.name}`. Do not retry.",
                repo=repo,
                settings=probe_settings,
                env=env,
                tools="Bash",
                allowed_tools="Bash" if allow else None,
                permission_mode="manual" if allow else "dontAsk",
                sandbox_profile=sandbox_profile,
            )
            _require_success(result, label)
            return {
                "hostVersion": candidate_version,
                "sentinelMutated": sentinel.exists(),
                "hostProcessExitCode": result.returncode,
            }

        native_allow_baseline = permission_probe(
            "native-allow-baseline", empty_settings, allow=True
        )
        native_allow_noop = permission_probe(
            "native-allow-noop", settings, allow=True
        )
        native_deny_baseline = permission_probe(
            "native-deny-baseline", empty_settings, allow=False
        )
        native_deny_noop = permission_probe(
            "native-deny-noop", settings, allow=False
        )
        native_preservation = {
            "nativeAllow": {
                "baseline": native_allow_baseline,
                "noopHook": native_allow_noop,
                "equivalent": (
                    native_allow_baseline["sentinelMutated"]
                    == native_allow_noop["sentinelMutated"]
                    is True
                ),
                "configuration": "explicit host allowedTools Bash; no bypass mode",
            },
            "nativeDeny": {
                "status": "tested",
                "baseline": native_deny_baseline,
                "noopHook": native_deny_noop,
                "equivalent": (
                    native_deny_baseline["sentinelMutated"]
                    == native_deny_noop["sentinelMutated"]
                    is False
                ),
                "configuration": "host dontAsk mode; no allowedTools; no bypass mode",
            },
        }

        payload_dir = FIXTURES / "pretooluse"
        for family, payload in raw_by_family.items():
            _write_json(
                payload_dir / f"{family}.json",
                sanitize_pretooluse(payload, fixture_root=temp),
            )

        host_evidence = {
            "host": "Claude Code",
            "candidate": {
                "version": candidate_version,
                "tested": True,
                "source": "locally installed executable",
                "origin": "Claude Code native installer executable",
                "sha256": _sha256_file(candidate_path),
                "os": platform.system(),
                "arch": platform.machine(),
            },
            "latestStable": {
                "version": stable_version,
                "tested": True,
                "source": "npm stable dist-tag at capture time",
                "package": "@anthropic-ai/claude-code",
            },
            "minimumSupported": {
                "version": None,
                "tested": False,
                "status": "unresolved",
                "reason": (
                    "Official docs do not state a minimum version and the "
                    "changelog does not identify one release containing every "
                    "required tool-family and blocking contract."
                ),
            },
            "gateComplete": False,
            "capturedAt": retrieved_at,
        }
        _write_json(FIXTURES / "host-version.json", host_evidence)
        _write_json(FIXTURES / "official-contract.json", {
            "url": HOOKS_URL,
            "retrievedAt": retrieved_at,
            "sha256": f"sha256:{hashlib.sha256(hooks_doc).hexdigest()}",
            "changelog": {
                "mutableUrl": CHANGELOG_URL,
                "immutableUrl": pinned_changelog_url,
                "commit": changelog_commit,
                "sha256": f"sha256:{hashlib.sha256(changelog).hexdigest()}",
            },
            "snapshotPolicy": (
                "Only factual URL, timestamp, commit, digest, and summarized "
                "semantics are retained; upstream prose is not republished."
            ),
            "reproduction": (
                "Fetch the mutable hooks URL and compare SHA-256; a mismatch "
                "records upstream drift and requires a new review rather than "
                "overwriting history."
            ),
            "documentedVersionEvidence": {
                "minimumVersion": None,
                "note": (
                    "No minimum Claude Code version is stated in the hooks "
                    "reference."
                ),
            },
            "blockingSemantics": {
                "structuredDeny": True,
                "exit2": True,
                "noopPreservesNativePermissions": True,
                "sourceSummary": (
                    "PreToolUse structured permissionDecision=deny prevents the "
                    "tool call; exit 2 blocks PreToolUse; an empty JSON object "
                    "contains no permission override."
                ),
            },
        })
        _write_json(FIXTURES / "expected-capabilities.json", {
            "host": "Claude Code",
            "toolFamilies": sorted(set(TOOL_FILES.values()) | {"mcp"}),
            "scenarios": scenario_results,
            "nativePermissionPreservation": native_preservation,
            "gateComplete": False,
        })
        evidence_errors = validate_evidence(FIXTURES)
        if evidence_errors:
            raise RuntimeError(
                "captured evidence failed validation: " + "; ".join(evidence_errors)
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.parse_args()
    capture()
    print(f"captured Claude Code Gate 0 evidence in {FIXTURES.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
