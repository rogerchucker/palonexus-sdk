"""Capture trusted Codex PreToolUse contract evidence in hardened containers.

The model-driven path has one security envelope: a pinned container image,
non-root UID, read-only root, dropped capabilities, no-new-privileges, bounded
resources, and a disposable workspace. The source workspace is never mounted.
Codex's nested sandbox is disabled because bubblewrap cannot create a nested
mount namespace under that envelope; the unchanged outer container is the
enforcement boundary. If that boundary fails, no unsafe fallback exists.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
import urllib.parse
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "plugins" / "codex" / "tests" / "fixtures"
HOOKS_URL = "https://developers.openai.com/codex/hooks.md"
HOOKS_PUBLIC_URL = "https://developers.openai.com/codex/hooks"
PLUGIN_URL = "https://developers.openai.com/plugins/build/plugins.md"
PLUGIN_PUBLIC_URL = "https://developers.openai.com/plugins/build/plugins"
BASE_IMAGE = (
    "docker.io/library/python@"
    "sha256:c18c7a910432dde3311fc54d02e5d5220f3ebe26fec43ff15745982863dd7b3b"
)
DOCKER = "/usr/local/bin/docker"
MINIMUM_VERSION = "0.124.0"
LATEST_VERSION = "0.145.0"
NEXT_CANDIDATE_VERSION = "0.125.0"
MINIMUM_TAG_COMMIT = "e9fb49366c93a1478ec71cc41ecee415a197d036"
LATEST_TAG_COMMIT = "25af12f7e61572b0bc18ddb1008be543b91519b0"
RELEASES = {
    "minimum": {
        "version": MINIMUM_VERSION,
        "tag": f"rust-v{MINIMUM_VERSION}",
        "tagCommit": MINIMUM_TAG_COMMIT,
        "publishedAt": "2026-04-23T18:29:40Z",
        "releaseUrl": (
            f"https://github.com/openai/codex/releases/tag/rust-v{MINIMUM_VERSION}"
        ),
        "archiveUrl": (
            "https://github.com/openai/codex/releases/download/"
            f"rust-v{MINIMUM_VERSION}/"
            "codex-aarch64-unknown-linux-musl.tar.gz"
        ),
        "archiveSha256": (
            "sha256:1301b1624c9ee89c41a501b77b95107a8dc3c8c285624d72edcda7921be6332e"
        ),
    },
    "latest": {
        "version": LATEST_VERSION,
        "tag": f"rust-v{LATEST_VERSION}",
        "tagCommit": LATEST_TAG_COMMIT,
        "publishedAt": "2026-07-21T18:21:04Z",
        "releaseUrl": (
            f"https://github.com/openai/codex/releases/tag/rust-v{LATEST_VERSION}"
        ),
        "archiveUrl": (
            "https://github.com/openai/codex/releases/download/"
            f"rust-v{LATEST_VERSION}/"
            "codex-aarch64-unknown-linux-musl.tar.gz"
        ),
        "archiveSha256": (
            "sha256:d384f90bc842450b42bd675feef06a12a46a3b1ca97efcb22566b270e4a11227"
        ),
    },
}
LATEST_SCHEMA_URL = (
    "https://raw.githubusercontent.com/openai/codex/"
    f"{LATEST_TAG_COMMIT}/"
    "codex-rs/hooks/schema/generated/pre-tool-use.command.input.schema.json"
)
REQUIRED_FAMILIES = {
    "bash": "Bash",
    "apply_patch": "apply_patch",
    "mcp": "mcp__palonexus_fixture__write_sentinel",
}
REQUIRED_SCENARIOS = (
    "structured_deny",
    "exit_2",
    "guard_failure",
    "approval_required",
)
RAW_TOP_LEVEL_FIELDS = {
    "agent_id",
    "agent_type",
    "cwd",
    "hook_event_name",
    "model",
    "permission_mode",
    "session_id",
    "tool_input",
    "tool_name",
    "tool_use_id",
    "transcript_path",
    "turn_id",
}
REQUIRED_TOP_LEVEL_FIELDS = {
    "cwd",
    "hook_event_name",
    "model",
    "permission_mode",
    "session_id",
    "tool_input",
    "tool_name",
    "tool_use_id",
    "transcript_path",
    "turn_id",
}
PERMISSION_MODES = {
    "default",
    "acceptEdits",
    "plan",
    "dontAsk",
    "bypassPermissions",
}
MODEL = re.compile(r"^gpt-[a-z0-9._+-]{1,60}$")
SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9._:-]{1,160}$")
WINDOWS_ABSOLUTE = re.compile(r"(?i)^[a-z]:[\\/]|^\\\\")
SENSITIVE = re.compile(
    r"(?i)(bearer\s+|api[_-]?key|access[_-]?token|secret|password|"
    r"sk-[a-z0-9_-]{12,}|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})"
)
HIGH_ENTROPY = re.compile(r"(?<![A-Za-z0-9])[A-Za-z0-9+/=_-]{64,}(?![A-Za-z0-9])")
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
APPROVAL_ID = "apr_gate0_codex_01"

HOOK_SCRIPT = r"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

RUN = json.loads(Path("/fixture/run.json").read_text(encoding="utf-8"))
raw = sys.stdin.read()
try:
    payload = json.loads(raw)
except json.JSONDecodeError as exc:
    print(f"fixture harness rejected malformed hook input: {exc}", file=sys.stderr)
    raise SystemExit(2)

expected = RUN["expectedInput"]
allowed_top_level = {
    "agent_id",
    "agent_type",
    "cwd",
    "hook_event_name",
    "model",
    "permission_mode",
    "session_id",
    "tool_input",
    "tool_name",
    "tool_use_id",
    "transcript_path",
    "turn_id",
}
required_top_level = {
    "cwd",
    "hook_event_name",
    "model",
    "permission_mode",
    "session_id",
    "tool_input",
    "tool_name",
    "tool_use_id",
    "transcript_path",
    "turn_id",
}
tool_input = payload.get("tool_input")
expected_input_fields = (
    {"nonce"}
    if RUN["toolName"] == "mcp__palonexus_fixture__write_sentinel"
    else {"command"}
)
serialized_input = json.dumps(tool_input, sort_keys=True)
safe_envelope = (
    isinstance(payload, dict)
    and not (set(payload) - allowed_top_level)
    and required_top_level <= set(payload)
    and payload.get("cwd") == "/work"
    and payload.get("hook_event_name") == "PreToolUse"
    and isinstance(payload.get("model"), str)
    and payload["model"].startswith("gpt-")
    and payload.get("tool_name") == RUN["toolName"]
    and isinstance(tool_input, dict)
    and set(tool_input) == expected_input_fields
    and len(serialized_input) <= 4096
    and not any(
        marker in serialized_input.lower()
        for marker in (
            "api_key",
            "bearer ",
            "password",
            "secret",
            "sk-",
            "token",
        )
    )
)
if not safe_envelope:
    print("fixture harness rejected unsafe structural envelope", file=sys.stderr)
    raise SystemExit(2)
with Path("/output/hook-quarantine.ndjson").open(
    "a", encoding="utf-8"
) as stream:
    stream.write(json.dumps(payload, sort_keys=True) + "\n")

canonical = json.dumps(
    tool_input, sort_keys=True, separators=(",", ":")
).encode()
fingerprint = "sha256:" + hashlib.sha256(canonical).hexdigest()
if (
    payload.get("hook_event_name") != "PreToolUse"
    or payload.get("tool_name") != RUN["toolName"]
    or payload.get("tool_input") != expected
    or fingerprint != RUN["inputFingerprint"]
):
    print("fixture harness rejected unexpected tool input", file=sys.stderr)
    raise SystemExit(2)

with Path("/output/hook.ndjson").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(payload, sort_keys=True) + "\n")

scenario = RUN["scenario"]
nonce = RUN["nonce"]
process_exit = 0
result = {
    "scenario": scenario,
    "nonce": nonce,
    "inputFingerprint": fingerprint,
}

if scenario == "noop":
    result["hookExitCode"] = 0
    result["rendered"] = {}
    print("{}")
elif scenario == "structured_deny":
    reason = f"PaloNexus fixture denial {nonce}"
    rendered = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }
    result["hookExitCode"] = 0
    result["rendered"] = rendered
    print(json.dumps(rendered, sort_keys=True))
elif scenario == "exit_2":
    reason = f"PaloNexus fixture exit-2 denial {nonce}"
    result["hookExitCode"] = 2
    result["rendered"] = {"stderr": reason}
    print(reason, file=sys.stderr)
    process_exit = 2
elif scenario in {"guard_failure", "approval_required"}:
    guard = subprocess.run(
        [
            "/usr/local/bin/python3",
            "/fixture/fake_guard.py",
            scenario,
            nonce,
        ],
        text=True,
        capture_output=True,
        check=False,
    )
    result["guardExitCode"] = guard.returncode
    if scenario == "guard_failure":
        reason = f"PaloNexus fixture guard failure blocked {nonce}"
        result["hookExitCode"] = 2
        result["rendered"] = {"stderr": reason}
        print(reason, file=sys.stderr)
        process_exit = 2
    else:
        if guard.returncode != 0:
            print("fixture guard approval response failed", file=sys.stderr)
            raise SystemExit(2)
        decision = json.loads(guard.stdout)
        if (
            decision != {
                "outcome": "approval_required",
                "approvalId": RUN["approvalId"],
            }
        ):
            print("fixture guard approval response drifted", file=sys.stderr)
            raise SystemExit(2)
        reason = (
            f"PaloNexus approval {decision['approvalId']} required for {nonce}; "
            "retry after approval"
        )
        rendered = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        }
        result["hookExitCode"] = 0
        result["rendered"] = rendered
        result["approvalId"] = decision["approvalId"]
        print(json.dumps(rendered, sort_keys=True))
else:
    print("fixture harness rejected unknown scenario", file=sys.stderr)
    raise SystemExit(2)

with Path("/output/hook-result.ndjson").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(result, sort_keys=True) + "\n")
raise SystemExit(process_exit)
"""

FAKE_GUARD_SCRIPT = r"""
from __future__ import annotations

import json
import sys

scenario, nonce = sys.argv[1:3]
if scenario == "guard_failure":
    print(f"controlled fake guard outage {nonce}", file=sys.stderr)
    raise SystemExit(69)
if scenario == "approval_required":
    print(
        json.dumps(
            {
                "outcome": "approval_required",
                "approvalId": "apr_gate0_codex_01",
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0)
raise SystemExit(64)
"""

MCP_SERVER_SCRIPT = r"""
from __future__ import annotations

import json
import sys
from pathlib import Path

RUN = json.loads(Path("/fixture/run.json").read_text(encoding="utf-8"))

def reply(message: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    request_id = request.get("id")
    if method == "initialize":
        reply(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "palonexus-gate0-fixture",
                        "version": "1.0.0",
                    },
                },
            }
        )
    elif method == "tools/list":
        reply(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {
                            "name": "write_sentinel",
                            "description": (
                                "Write the controlled Gate 0 sentinel. "
                                "Use only when explicitly requested."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {"nonce": {"type": "string"}},
                                "required": ["nonce"],
                            },
                        }
                    ]
                },
            }
        )
    elif method == "tools/call":
        params = request.get("params", {})
        arguments = params.get("arguments", {})
        if (
            params.get("name") != "write_sentinel"
            or arguments != {"nonce": RUN["nonce"]}
        ):
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "control input mismatch"},
                }
            )
            continue
        with Path("/output/tool-invocations").open("a", encoding="utf-8") as stream:
            stream.write(RUN["invocationBinding"] + "\n")
        Path(RUN["sentinelPath"]).write_text(RUN["nonce"] + "\n", encoding="utf-8")
        reply(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {"type": "text", "text": "controlled sentinel written"}
                    ],
                    "isError": False,
                },
            }
        )
    elif request_id is not None:
        reply(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }
        )
"""

CHECK_EFFECT_SCRIPT = r"""
from __future__ import annotations

import json
from pathlib import Path

run = json.loads(Path("/fixture/run.json").read_text(encoding="utf-8"))
sentinel = Path(run["sentinelPath"])
allowed = str(sentinel).startswith("/work/") or str(sentinel).startswith(
    "/etc/palonexus-gate0-"
)
if not allowed:
    raise SystemExit("unsafe sentinel path")
receipt_path = Path("/output/tool-invocations")
receipts = (
    receipt_path.read_text(encoding="utf-8").splitlines()
    if receipt_path.is_file()
    else []
)
if run["family"] == "apply_patch" and sentinel.exists():
    receipts = [run["invocationBinding"]]
Path("/output/effect-state.json").write_text(
    json.dumps(
        {
            "invocationBindingVerified": (
                bool(receipts)
                and all(value == run["invocationBinding"] for value in receipts)
            ),
            "toolInvocationCount": len(receipts),
            "sentinelExistsAfter": sentinel.exists(),
        },
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
"""

CONTAINER_ENTRYPOINT = r"""
mkdir -p "$CODEX_HOME"
cp /fixture-auth.json "$CODEX_HOME/auth.json"
chmod 600 "$CODEX_HOME/auth.json"
cp /fixture/config.toml "$CODEX_HOME/config.toml"
if [ -f /fixture/hooks.json ]; then
  cp /fixture/hooks.json "$CODEX_HOME/hooks.json"
fi
set +e
/usr/local/bin/codex --dangerously-bypass-hook-trust \
  --model gpt-5.6-sol --ask-for-approval never --sandbox danger-full-access exec \
  --json --ephemeral --skip-git-repo-check \
  --cd /work "$1"
codex_status=$?
set -e
/usr/local/bin/python3 /fixture/check_effect.py
exit "$codex_status"
"""
LEGACY_CONTAINER_ENTRYPOINT = CONTAINER_ENTRYPOINT.replace(
    "--dangerously-bypass-hook-trust ", ""
).replace("gpt-5.6-sol", "gpt-5.4")

RECEIPT_HOOK_RUNNER_SCRIPT = r"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

raw = sys.stdin.read()
try:
    payload = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit(2)
with Path("/output/hook-input-raw.ndjson").open("a", encoding="utf-8") as stream:
    stream.write(json.dumps(payload, sort_keys=True) + "\n")
result = subprocess.run(
    ["/usr/local/bin/python3", "/fixture/hook_impl.py"],
    input=raw,
    text=True,
    capture_output=True,
    check=False,
)
with Path("/output/hook-run-raw.ndjson").open("a", encoding="utf-8") as stream:
    stream.write(
        json.dumps(
            {
                "toolUseId": payload.get("tool_use_id"),
                "exitCode": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
            },
            sort_keys=True,
        )
        + "\n"
    )
sys.stdout.write(result.stdout)
sys.stderr.write(result.stderr)
raise SystemExit(result.returncode)
"""

RECEIPT_HOOK_IMPL_SCRIPT = r"""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

run = json.loads(Path("/fixture/run.json").read_text(encoding="utf-8"))
raw = sys.stdin.read()
try:
    payload = json.loads(raw)
except json.JSONDecodeError:
    raise SystemExit(2)
tool_input = payload.get("tool_input")
canonical = json.dumps(
    tool_input, sort_keys=True, separators=(",", ":")
).encode("utf-8")
fingerprint = "sha256:" + hashlib.sha256(canonical).hexdigest()
if (
    payload.get("hook_event_name") != "PreToolUse"
    or payload.get("tool_name") != run["toolName"]
    or tool_input != run["expectedInput"]
    or fingerprint != run["inputFingerprint"]
):
    print("fixture harness rejected unexpected tool input", file=sys.stderr)
    raise SystemExit(2)

scenario = run["scenario"]
nonce = run["nonce"]
if scenario in {"noop", "native_permission_noop"}:
    print("{}")
    raise SystemExit(0)
if scenario == "structured_deny":
    reason = f"PaloNexus fixture denial {nonce}"
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            },
            sort_keys=True,
        )
    )
    raise SystemExit(0)
if scenario == "exit_2":
    print(f"PaloNexus fixture exit-2 denial {nonce}", file=sys.stderr)
    raise SystemExit(2)
if scenario not in {"guard_failure", "approval_required"}:
    print("fixture harness rejected unknown scenario", file=sys.stderr)
    raise SystemExit(2)

guard = subprocess.run(
    ["/usr/local/bin/python3", "/fixture/fake_guard.py", scenario, nonce],
    text=True,
    capture_output=True,
    check=False,
)
with Path("/output/guard-raw.ndjson").open("a", encoding="utf-8") as stream:
    stream.write(
        json.dumps(
            {
                "toolUseId": payload.get("tool_use_id"),
                "scenario": scenario,
                "nonce": nonce,
                "exitCode": guard.returncode,
                "stdout": guard.stdout,
                "stderr": guard.stderr,
            },
            sort_keys=True,
        )
        + "\n"
    )
if scenario == "guard_failure":
    print(f"PaloNexus fixture guard failure blocked {nonce}", file=sys.stderr)
    raise SystemExit(2)
if guard.returncode != 0:
    print("fixture guard approval response failed", file=sys.stderr)
    raise SystemExit(2)
decision = json.loads(guard.stdout)
if decision != {
    "outcome": "approval_required",
    "approvalId": run["approvalId"],
}:
    print("fixture guard approval response drifted", file=sys.stderr)
    raise SystemExit(2)
reason = (
    f"PaloNexus approval {decision['approvalId']} required for {nonce}; "
    "retry after approval"
)
print(
    json.dumps(
        {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": reason,
            }
        },
        sort_keys=True,
    )
)
raise SystemExit(0)
"""

RECEIPT_MCP_SERVER_SCRIPT = r"""
from __future__ import annotations

import json
import sys
from pathlib import Path

run = json.loads(Path("/fixture/run.json").read_text(encoding="utf-8"))

def record(request: dict[str, object]) -> None:
    with Path("/output/mcp-raw.ndjson").open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(request, sort_keys=True) + "\n")

def reply(message: dict[str, object]) -> None:
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    request = json.loads(line)
    record(request)
    method = request.get("method")
    request_id = request.get("id")
    if method == "initialize":
        reply(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name": "palonexus-gate0-fixture",
                        "version": "1.0.0",
                    },
                },
            }
        )
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        reply(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "tools": [
                        {
                            "name": "write_sentinel",
                            "description": "Write the controlled Gate 0 sentinel.",
                            "inputSchema": {
                                "type": "object",
                                "additionalProperties": False,
                                "properties": {"nonce": {"type": "string"}},
                                "required": ["nonce"],
                            },
                        }
                    ]
                },
            }
        )
    elif method == "tools/call":
        params = request.get("params", {})
        arguments = params.get("arguments", {})
        if (
            params.get("name") != "write_sentinel"
            or arguments != {"nonce": run["nonce"]}
        ):
            reply(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32602, "message": "control input mismatch"},
                }
            )
            continue
        with Path("/output/tool-invocations").open("a", encoding="utf-8") as stream:
            stream.write(run["invocationBinding"] + "\n")
        Path(run["sentinelPath"]).write_text(
            run["nonce"] + "\n", encoding="utf-8"
        )
        reply(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "content": [
                        {"type": "text", "text": "controlled sentinel written"}
                    ],
                    "isError": False,
                },
            }
        )
    elif request_id is not None:
        reply(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }
        )
"""

RECEIPT_EFFECT_SCRIPT = r"""
from __future__ import annotations

import json
from pathlib import Path

run = json.loads(Path("/fixture/run.json").read_text(encoding="utf-8"))
sentinel = Path(run["sentinelPath"])
receipt_path = Path("/output/tool-invocations")
invocations = (
    receipt_path.read_text(encoding="utf-8").splitlines()
    if receipt_path.is_file()
    else []
)
content = sentinel.read_text(encoding="utf-8") if sentinel.is_file() else None
Path("/output/effect-raw.json").write_text(
    json.dumps(
        {
            "sentinelExistsAfter": sentinel.exists(),
            "sentinelContent": content,
            "toolInvocationReceipts": invocations,
        },
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
"""

RECEIPT_CONTAINER_ENTRYPOINT = r"""
mkdir -p "$CODEX_HOME"
cp /fixture-auth.json "$CODEX_HOME/auth.json"
chmod 600 "$CODEX_HOME/auth.json"
cp /fixture/config.toml "$CODEX_HOME/config.toml"
if [ -f /fixture/hooks.json ]; then
  cp /fixture/hooks.json "$CODEX_HOME/hooks.json"
fi
set +e
/usr/local/bin/codex $4 \
  --model "$3" --ask-for-approval "$2" --sandbox danger-full-access exec \
  --json --ephemeral --skip-git-repo-check \
  --cd /work "$1" > /output/codex-stdout-raw.jsonl \
  2> /output/codex-stderr-raw.log
codex_status=$?
set -e
/usr/local/bin/python3 /fixture/check_effect.py
printf '{"exitCode":%s}\n' "$codex_status" > /output/process-exit-raw.json
exit "$codex_status"
"""


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _identifier_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"invalid {field}")
    return _sha256_bytes(value.encode("utf-8"))


def _safe_host_text(value: Any, nonce: str) -> str:
    if not isinstance(value, str):
        raise ValueError("host event text must be a string")
    entropy_checked = re.sub(r"sha256:[0-9a-f]{64}", "<sha256>", value)
    if (
        len(value) > 8_000
        or SENSITIVE.search(value)
        or HIGH_ENTROPY.search(entropy_checked)
    ):
        raise ValueError("host event text is unsafe")
    if value and nonce not in value:
        raise ValueError("host event text is not nonce-bound")
    return value


def sanitize_codex_jsonl(
    raw_jsonl: str, request: dict[str, Any]
) -> list[dict[str, Any]]:
    """Allowlist Codex exec JSONL while retaining structural tool correlation."""
    nonce = request.get("nonce")
    family = request.get("family")
    tool_input = request.get("toolInput")
    if (
        not isinstance(nonce, str)
        or family not in REQUIRED_FAMILIES
        or not isinstance(tool_input, dict)
    ):
        raise ValueError("invalid request for JSONL sanitization")
    sanitized: list[dict[str, Any]] = []
    for ordinal, line in enumerate(raw_jsonl.splitlines(), 1):
        if not line:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Codex JSONL line {ordinal} is malformed") from exc
        if not isinstance(event, dict) or not isinstance(event.get("type"), str):
            raise ValueError(f"Codex JSONL line {ordinal} is not an event")
        event_type = event["type"]
        if event_type == "thread.started":
            if set(event) != {"type", "thread_id"}:
                raise ValueError("unexpected thread.started fields")
            sanitized.append(
                {
                    "type": event_type,
                    "thread_id": _identifier_digest(
                        event.get("thread_id"), "thread_id"
                    ),
                }
            )
            continue
        if event_type == "turn.started":
            if set(event) != {"type"}:
                raise ValueError("unexpected turn.started fields")
            sanitized.append({"type": event_type})
            continue
        if event_type == "turn.completed":
            usage = event.get("usage")
            if not isinstance(usage, dict) or not all(
                isinstance(value, int) and value >= 0 for value in usage.values()
            ):
                raise ValueError("invalid turn usage receipt")
            sanitized.append({"type": event_type, "usage": dict(usage)})
            continue
        if event_type in {"turn.failed", "error"}:
            error = event.get("error") if event_type == "turn.failed" else event
            message = error.get("message") if isinstance(error, dict) else None
            if not isinstance(message, str):
                raise ValueError("invalid Codex error event")
            sanitized.append(
                {
                    "type": event_type,
                    "messageFingerprint": _sha256_bytes(message.encode("utf-8")),
                    "containsNonce": nonce in message,
                }
            )
            continue
        if event_type not in {"item.started", "item.updated", "item.completed"}:
            raise ValueError(f"unsupported Codex JSONL event: {event_type}")
        item = event.get("item")
        if not isinstance(item, dict):
            raise ValueError("Codex item event has no item")
        item_type = item.get("type")
        item_id = _identifier_digest(item.get("id"), "item.id")
        if item_type in {"agent_message", "reasoning"}:
            text = item.get("text")
            if not isinstance(text, str):
                raise ValueError("Codex prose item has no text")
            sanitized.append(
                {
                    "type": event_type,
                    "item": {
                        "id": item_id,
                        "type": item_type,
                        "textFingerprint": _sha256_bytes(text.encode("utf-8")),
                        "containsNonce": nonce in text,
                    },
                }
            )
            continue
        if item_type == "command_execution":
            if family != "bash" or item.get("command") != tool_input.get("command"):
                raise ValueError("unexpected command execution event")
            aggregated_output = item.get("aggregated_output", "")
            if not isinstance(aggregated_output, str):
                raise ValueError("invalid command output")
            output_receipt: dict[str, Any]
            if not aggregated_output or nonce in aggregated_output:
                output_receipt = {
                    "aggregated_output": _safe_host_text(aggregated_output, nonce)
                }
            else:
                output_receipt = {
                    "aggregated_output": "",
                    "aggregatedOutputFingerprint": _sha256_bytes(
                        aggregated_output.encode("utf-8")
                    ),
                    "aggregatedOutputContainsNonce": False,
                }
            sanitized.append(
                {
                    "type": event_type,
                    "item": {
                        "id": item_id,
                        "type": item_type,
                        "command": item["command"],
                        **output_receipt,
                        "exit_code": item.get("exit_code"),
                        "status": item.get("status"),
                    },
                }
            )
            continue
        if item_type == "file_change":
            if family != "apply_patch":
                raise ValueError("unexpected file change event")
            changes = item.get("changes")
            if changes != [{"path": f"sentinel-{nonce}", "kind": "add"}]:
                raise ValueError("unexpected file change target")
            sanitized.append(
                {
                    "type": event_type,
                    "item": {
                        "id": item_id,
                        "type": item_type,
                        "changes": changes,
                        "status": item.get("status"),
                    },
                }
            )
            continue
        if item_type == "mcp_tool_call":
            if (
                family != "mcp"
                or item.get("server") != "palonexus_fixture"
                or item.get("tool") != "write_sentinel"
                or item.get("arguments") != tool_input
            ):
                raise ValueError("unexpected MCP tool event")
            error = item.get("error")
            sanitized_error = None
            if error is not None:
                if not isinstance(error, dict):
                    raise ValueError("invalid MCP error event")
                sanitized_error = {
                    "message": _safe_host_text(error.get("message"), nonce)
                }
            sanitized.append(
                {
                    "type": event_type,
                    "item": {
                        "id": item_id,
                        "type": item_type,
                        "server": item["server"],
                        "tool": item["tool"],
                        "arguments": item["arguments"],
                        "result": (
                            None if item.get("result") is None else {"observed": True}
                        ),
                        "error": sanitized_error,
                        "status": item.get("status"),
                    },
                }
            )
            continue
        if item_type == "error":
            message = item.get("message")
            if not isinstance(message, str):
                raise ValueError("invalid error item")
            sanitized.append(
                {
                    "type": event_type,
                    "item": {
                        "id": item_id,
                        "type": item_type,
                        "messageFingerprint": _sha256_bytes(message.encode("utf-8")),
                        "containsNonce": nonce in message,
                    },
                }
            )
            continue
        raise ValueError(f"unsupported Codex item type: {item_type}")
    return sanitized


def sanitize_hook_receipt(
    payload: dict[str, Any],
    *,
    expected_tool_name: str,
    expected_tool_input: dict[str, Any],
) -> dict[str, Any]:
    """Sanitize a raw hook payload while preserving pseudonymous IDs."""
    normalized = _normalize_raw_payload(payload)
    sanitized = sanitize_pretooluse(
        normalized,
        fixture_root=Path("/fixture"),
        expected_tool_name=expected_tool_name,
        expected_tool_input=expected_tool_input,
    )
    for field in ("session_id", "turn_id", "tool_use_id"):
        sanitized[field] = _identifier_digest(payload.get(field), field)
    for field in ("agent_id", "agent_type"):
        if field in payload:
            sanitized[field] = _identifier_digest(payload[field], field)
    return sanitized


def derive_cell_from_receipts(receipt_dir: Path) -> dict[str, Any]:
    """Derive one cell summary from its persisted capture receipts."""
    if not receipt_dir.is_dir():
        raise ValueError(f"receipt directory does not exist: {receipt_dir}")
    required = {
        "request.json",
        "process.json",
        "codex-events.ndjson",
        "hook-input.ndjson",
        "hook-run.ndjson",
        "guard.ndjson",
        "mcp.ndjson",
        "effect.json",
    }
    missing = sorted(name for name in required if not (receipt_dir / name).is_file())
    if missing:
        raise ValueError(f"receipt bundle is incomplete: {missing}")

    def load_json(name: str) -> dict[str, Any]:
        value = json.loads((receipt_dir / name).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"{name} must contain one JSON object")
        return value

    def load_ndjson(name: str) -> list[dict[str, Any]]:
        values: list[dict[str, Any]] = []
        for ordinal, line in enumerate(
            (receipt_dir / name).read_text(encoding="utf-8").splitlines(), 1
        ):
            if not line:
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{name}:{ordinal} must be a JSON object")
            values.append(value)
        return values

    request = load_json("request.json")
    process = load_json("process.json")
    events = load_ndjson("codex-events.ndjson")
    hook_inputs = load_ndjson("hook-input.ndjson")
    hook_runs = load_ndjson("hook-run.ndjson")
    guard_runs = load_ndjson("guard.ndjson")
    mcp_events = load_ndjson("mcp.ndjson")
    effect = load_json("effect.json")

    family = request.get("family")
    scenario = request.get("scenario")
    version = request.get("version")
    nonce = request.get("nonce")
    prompt = request.get("prompt")
    tool_name = request.get("toolName")
    tool_input = request.get("toolInput")
    invocation_binding = request.get("invocationBinding")
    if (
        request.get("schemaVersion") != 1
        or family not in REQUIRED_FAMILIES
        or not isinstance(version, str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", version)
        or not isinstance(scenario, str)
        or not isinstance(nonce, str)
        or not SAFE_IDENTIFIER.fullmatch(nonce)
        or not isinstance(prompt, str)
        or not isinstance(tool_input, dict)
        or tool_name != REQUIRED_FAMILIES[family]
        or not isinstance(invocation_binding, str)
        or not SHA256.fullmatch(invocation_binding)
    ):
        raise ValueError("invalid request receipt")
    _validate_tool_input_shape(tool_name, tool_input)
    _validate_safe_control_value(tool_input)
    expected_binding = canonical_sha256(
        {
            "family": family,
            "nonce": nonce,
            "scenario": scenario,
            "version": version,
        }
    )
    if invocation_binding != expected_binding:
        raise ValueError("invocation binding is not receipt-derived")
    expected_input = _expected_input(family, nonce, expected_binding)
    if tool_input != expected_input:
        raise ValueError("tool input is not derived from the invocation binding")
    expected_prompt = _prompt(
        family,
        expected_input,
        allow_mcp_discovery=request.get("allowMcpDiscovery") is True,
    )
    if prompt != expected_prompt:
        raise ValueError("request does not contain the deterministic prompt")
    if request.get("sentinelPath") != (
        f"<fixture-root>{_sentinel_path(family, nonce)}"
    ):
        raise ValueError("sentinel path is not nonce-bound")
    if process.get("prompt") != prompt:
        raise ValueError("process prompt is not bound to request receipt")
    if process.get("approvalPolicy") != request.get("approvalPolicy"):
        raise ValueError("process approval policy is not bound to request receipt")
    if process.get("sandbox") != "danger-full-access":
        raise ValueError("unexpected nested sandbox receipt")

    completed = [
        event
        for event in events
        if event.get("type") == "item.completed" and isinstance(event.get("item"), dict)
    ]
    if family == "bash":
        host_calls = [
            event
            for event in completed
            if event["item"].get("type") == "command_execution"
            and event["item"].get("command") == tool_input["command"]
        ]
    elif family == "apply_patch":
        expected_path = f"sentinel-{nonce}"
        host_calls = [
            event
            for event in completed
            if event["item"].get("type") == "file_change"
            and event["item"].get("changes") == [{"path": expected_path, "kind": "add"}]
        ]
    else:
        host_calls = [
            event
            for event in completed
            if event["item"].get("type") == "mcp_tool_call"
            and event["item"].get("server") == "palonexus_fixture"
            and event["item"].get("tool") == "write_sentinel"
            and event["item"].get("arguments") == tool_input
        ]
        listed = [event for event in mcp_events if event.get("method") == "tools/list"]
        calls = [
            event
            for event in mcp_events
            if event.get("method") == "tools/call"
            and event.get("tool") == "write_sentinel"
            and event.get("arguments") == tool_input
        ]
        if not listed:
            raise ValueError("MCP tools/list discovery receipt is missing")
        if scenario == "noop" and len(calls) != 1:
            raise ValueError("MCP exact dispatch receipt is missing")
        if scenario != "noop" and calls:
            raise ValueError("blocked MCP call reached the fixture server")
    if len(host_calls) != 1:
        raise ValueError("expected exactly one structurally matching host tool event")
    host_event = host_calls[0]
    host_item = host_event["item"]
    host_item_id = host_item.get("id")
    if not isinstance(host_item_id, str) or not SHA256.fullmatch(host_item_id):
        raise ValueError("host item id is not sanitized")

    started = [
        event
        for event in events
        if event.get("type") == "item.started"
        and isinstance(event.get("item"), dict)
        and event["item"].get("id") == host_item_id
    ]
    if family in {"bash", "mcp"} and len(started) != 1:
        raise ValueError("host start/completion correlation is incomplete")

    with_hook = request.get("withPreToolHook") is True
    if len(hook_inputs) != (1 if with_hook else 0):
        raise ValueError("hook input invocation count is not exact")
    if len(hook_runs) != (1 if with_hook else 0):
        raise ValueError("hook process invocation count is not exact")
    hook_payload: dict[str, Any] | None = None
    tool_use_id: str | None = None
    hook_exit_code: int | None = None
    guard_exit_code: int | None = None
    if with_hook:
        hook_payload = hook_inputs[0]
        if (
            hook_payload.get("hook_event_name") != "PreToolUse"
            or hook_payload.get("tool_name") != tool_name
            or hook_payload.get("tool_input") != tool_input
        ):
            raise ValueError("hook payload is not bound to the host tool input")
        tool_use_id = hook_payload.get("tool_use_id")
        if not isinstance(tool_use_id, str) or not SHA256.fullmatch(tool_use_id):
            raise ValueError("hook tool use id is not sanitized")
        if hook_runs[0].get("toolUseId") != tool_use_id:
            raise ValueError("hook tool use id does not match hook process receipt")
        hook_exit_code = hook_runs[0].get("exitCode")
        if not isinstance(hook_exit_code, int):
            raise ValueError("hook exit code is missing")

    blocked = scenario in REQUIRED_SCENARIOS or scenario in {
        "native_permission_baseline",
        "native_permission_noop",
    }
    status = host_item.get("status")
    host_text = ""
    if family == "bash":
        host_text = host_item.get("aggregated_output", "")
    elif family == "mcp":
        error = host_item.get("error")
        host_text = error.get("message", "") if isinstance(error, dict) else ""
    if blocked and status not in {"failed", "declined"}:
        raise ValueError("structural host denial event is missing")
    if not blocked and status != "completed":
        raise ValueError("structural host completion event is missing")

    expected_reason: str | None = None
    if scenario == "structured_deny":
        expected_reason = f"PaloNexus fixture denial {nonce}"
        expected_hook_exit = 0
    elif scenario == "exit_2":
        expected_reason = f"PaloNexus fixture exit-2 denial {nonce}"
        expected_hook_exit = 2
    elif scenario == "guard_failure":
        expected_reason = f"PaloNexus fixture guard failure blocked {nonce}"
        expected_hook_exit = 2
        if len(guard_runs) != 1:
            raise ValueError("guard failure receipt is missing")
        if guard_runs[0].get("toolUseId") != tool_use_id:
            raise ValueError("guard tool use id is not correlated")
        guard_exit_code = guard_runs[0].get("exitCode")
        if guard_exit_code != 69:
            raise ValueError("guard failure exit receipt is not 69")
    elif scenario == "approval_required":
        expected_reason = (
            f"PaloNexus approval {APPROVAL_ID} required for {nonce}; "
            "retry after approval"
        )
        expected_hook_exit = 0
        if len(guard_runs) != 1:
            raise ValueError("approval guard receipt is missing")
        if guard_runs[0].get("toolUseId") != tool_use_id:
            raise ValueError("guard tool use id is not correlated")
        guard_exit_code = guard_runs[0].get("exitCode")
        if guard_exit_code != 0:
            raise ValueError("approval guard exit receipt is not zero")
        guard_stdout = guard_runs[0].get("stdout")
        try:
            guard_decision = json.loads(guard_stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ValueError("approval guard output is not JSON") from exc
        if guard_decision != {
            "outcome": "approval_required",
            "approvalId": APPROVAL_ID,
        }:
            raise ValueError("approval guard decision drifted")
    elif scenario == "noop":
        expected_hook_exit = 0
    elif scenario.startswith("baseline_"):
        expected_hook_exit = None
    elif scenario in {"native_permission_baseline", "native_permission_noop"}:
        expected_hook_exit = 0 if with_hook else None
    else:
        raise ValueError(f"unsupported receipt scenario: {scenario}")

    if hook_exit_code != expected_hook_exit:
        raise ValueError("hook process exit does not match scenario")
    if expected_reason is not None:
        if expected_reason not in host_text and family != "apply_patch":
            raise ValueError("host denial event is not bound to hook reason")
        if hook_exit_code == 0:
            try:
                rendered = json.loads(hook_runs[0].get("stdout", ""))
            except json.JSONDecodeError as exc:
                raise ValueError("structured hook output is not JSON") from exc
            hook_reason = rendered.get("hookSpecificOutput", {}).get(
                "permissionDecisionReason"
            )
            if hook_reason != expected_reason:
                raise ValueError("host denial reason differs from hook output")
        elif expected_reason not in hook_runs[0].get("stderr", ""):
            raise ValueError("host denial reason differs from hook stderr")

    sentinel_exists = effect.get("sentinelExistsAfter")
    invocation_receipts = effect.get("toolInvocationReceipts")
    if not isinstance(sentinel_exists, bool) or not isinstance(
        invocation_receipts, list
    ):
        raise ValueError("effect receipt is incomplete")
    if any(value != invocation_binding for value in invocation_receipts):
        raise ValueError("tool execution receipt is not invocation-bound")
    if len(invocation_receipts) > 1:
        raise ValueError("tool executed more than once")
    if blocked and (sentinel_exists or invocation_receipts):
        raise ValueError("blocked tool produced an effect")
    if not blocked and (
        not sentinel_exists
        or (family in {"bash", "mcp"} and invocation_receipts != [invocation_binding])
    ):
        raise ValueError("allowed tool effect receipt is incomplete")

    result: dict[str, Any] = {
        "trusted": True,
        "receiptDerived": True,
        "version": version,
        "family": family,
        "scenario": scenario,
        "nonce": nonce,
        "promptFingerprint": _sha256_bytes(prompt.encode("utf-8")),
        "inputFingerprint": canonical_sha256(tool_input),
        "invocationBinding": invocation_binding,
        "hostItemId": host_item_id,
        "hostToolCallCount": 1,
        "hookInvocationCount": len(hook_inputs),
        "hookExitCode": hook_exit_code,
        "hostRenderedEvidence": {
            "eventType": host_event["type"],
            "itemId": host_item_id,
            "status": status,
            "text": expected_reason,
        },
        "sentinelExistsAfter": sentinel_exists,
        "toolExecuted": bool(invocation_receipts)
        or (family == "apply_patch" and sentinel_exists),
    }
    if tool_use_id is not None and hook_payload is not None:
        result["toolUseId"] = tool_use_id
        result["hookPayload"] = hook_payload
        result["hookPayloadFingerprint"] = canonical_sha256(hook_payload)
    if guard_exit_code is not None:
        result["guardExitCode"] = guard_exit_code
    if scenario == "approval_required":
        result["approvalId"] = APPROVAL_ID
    return result


def derive_host_from_receipts(receipt_dir: Path) -> dict[str, Any]:
    """Derive executable, package, MCP, and isolation facts from receipts."""
    required = {
        "npm-metadata.json",
        "npm-artifact.json",
        "release-metadata.json",
        "artifact.json",
        "version-process.json",
        "runtime-canary.json",
        "mcp-registration.json",
    }
    if not receipt_dir.is_dir() or any(
        not (receipt_dir / name).is_file() for name in required
    ):
        raise ValueError("host receipt bundle is incomplete")

    def load(name: str) -> dict[str, Any]:
        value = json.loads((receipt_dir / name).read_text(encoding="utf-8"))
        if not isinstance(value, dict):
            raise ValueError(f"{name} must contain a JSON object")
        return value

    npm = load("npm-metadata.json")
    npm_artifact = load("npm-artifact.json")
    release = load("release-metadata.json")
    artifact = load("artifact.json")
    version_process = load("version-process.json")
    runtime = load("runtime-canary.json")
    registration = load("mcp-registration.json")
    dist = npm.get("dist")
    if (
        npm.get("name") != "@openai/codex"
        or not isinstance(npm.get("version"), str)
        or not re.fullmatch(r"\d+\.\d+\.\d+", npm["version"])
        or not isinstance(dist, dict)
        or not isinstance(dist.get("tarball"), str)
        or not dist["tarball"].startswith("https://registry.npmjs.org/@openai/codex/-/")
        or not isinstance(dist.get("integrity"), str)
        or not re.fullmatch(r"sha512-[A-Za-z0-9+/=]+", dist["integrity"])
    ):
        raise ValueError("invalid official npm metadata receipt")
    if (
        npm_artifact.get("tarballUrl") != dist["tarball"]
        or npm_artifact.get("sha512") != dist["integrity"]
        or not isinstance(npm_artifact.get("size"), int)
        or npm_artifact["size"] <= 0
    ):
        raise ValueError("npm artifact integrity receipt mismatch")

    release_asset = release.get("asset")
    if (
        release.get("tagName") != f"rust-v{npm['version']}"
        or not isinstance(release.get("publishedAt"), str)
        or not isinstance(release_asset, dict)
        or release_asset.get("name") != "codex-aarch64-unknown-linux-musl.tar.gz"
        or not isinstance(release_asset.get("url"), str)
        or not release_asset["url"].startswith(
            "https://github.com/openai/codex/releases/download/"
        )
        or not isinstance(release_asset.get("digest"), str)
        or not SHA256.fullmatch(release_asset["digest"])
        or artifact.get("tarballUrl") != release_asset["url"]
        or artifact.get("sha256") != release_asset["digest"]
        or artifact.get("size") != release_asset.get("size")
        or not isinstance(artifact.get("executableSha256"), str)
        or not SHA256.fullmatch(artifact["executableSha256"])
    ):
        raise ValueError("release artifact integrity receipt mismatch")

    if version_process.get("exitCode") != 0:
        raise ValueError("Codex version process failed")
    stdout = version_process.get("stdout")
    if not isinstance(stdout, str):
        raise ValueError("Codex version stdout is missing")
    match = re.fullmatch(r"codex-cli (\d+\.\d+\.\d+)\n?", stdout)
    if match is None:
        raise ValueError("Codex version receipt is malformed")
    version = match.group(1)
    if npm["version"] != version:
        raise ValueError("Codex executable version differs from npm artifact")

    argv = runtime.get("dockerArgv")
    observations = runtime.get("observations")
    required_argv = {
        "--user": "10001:10001",
        "--network": "none",
        "--cap-drop": "ALL",
        "--security-opt": "no-new-privileges",
        "--cpus": "1",
        "--memory": "1g",
        "--pids-limit": "128",
    }
    required_mounts = {
        "type=bind,src=<host-temp>,dst=/usr/local/bin/codex,readonly",
        "type=bind,src=<host-temp>,dst=/fixture,readonly",
        "type=bind,src=<host-temp>,dst=/output",
        "type=bind,src=<host-temp>,dst=/work",
        "type=bind,src=<host-temp>,dst=/fixture-auth.json,readonly",
    }
    hardened = isinstance(argv, list) and "--read-only" in argv and BASE_IMAGE in argv
    if hardened:
        observed_mounts = {
            value
            for value in argv
            if isinstance(value, str) and value.startswith("type=bind,")
        }
        hardened = observed_mounts == required_mounts
    if hardened:
        for flag, expected in required_argv.items():
            indexes = [index for index, value in enumerate(argv) if value == flag]
            if (
                len(indexes) != 1
                or indexes[0] + 1 >= len(argv)
                or argv[indexes[0] + 1] != expected
            ):
                hardened = False
                break
    expected_observations = {
        "uid": 10001,
        "rootWriteDenied": True,
        "authWriteDenied": True,
        "sourceWorkspaceAbsent": True,
        "workWritable": True,
        "outputWritable": True,
    }
    if (
        not hardened
        or runtime.get("exitCode") != 0
        or observations != expected_observations
        or not isinstance(runtime.get("imageId"), str)
        or not SHA256.fullmatch(runtime["imageId"])
    ):
        raise ValueError("hardened Docker invocation receipt is invalid")

    registration_stdout = registration.get("stdout")
    if (
        registration.get("exitCode") != 0
        or not isinstance(registration_stdout, str)
        or not all(
            marker in registration_stdout
            for marker in (
                "palonexus_fixture",
                "/usr/local/bin/python3",
                "/fixture/mcp_server.py",
                "enabled",
            )
        )
    ):
        raise ValueError("MCP registration receipt is invalid")

    return {
        "trusted": True,
        "receiptDerived": True,
        "version": version,
        "npmVersion": npm["version"],
        "npmTarball": dist["tarball"],
        "npmIntegrity": dist["integrity"],
        "npmIntegrityVerified": True,
        "releaseArtifactSha256": artifact["sha256"],
        "releaseArtifactIntegrityVerified": True,
        "executableSha256": artifact["executableSha256"],
        "baseImage": BASE_IMAGE,
        "baseImageId": runtime["imageId"],
        "containerUser": "10001:10001",
        "readOnlyRoot": True,
        "capDrop": "ALL",
        "noNewPrivileges": True,
        "authMountReadOnly": True,
        "sourceWorkspaceMounted": False,
        "workspaceIsDisposable": True,
        "mcpRegistered": True,
    }


def _sha256_bytes(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


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


def _docker_environment() -> dict[str, str]:
    allowed = {"HOME", "LANG", "LC_ALL", "PATH", "TERM", "TMPDIR"}
    return {key: value for key, value in os.environ.items() if key in allowed}


def _validate_mount(path: Path, *, directory: bool) -> Path:
    resolved = path.resolve()
    if directory and not resolved.is_dir():
        raise ValueError(f"Docker directory mount does not exist: {path}")
    if not directory and not resolved.is_file():
        raise ValueError(f"Docker file mount does not exist: {path}")
    return resolved


def docker_capture_command(
    *,
    image: str,
    binary: Path,
    fixture_bundle: Path,
    output: Path,
    workspace: Path,
    auth: Path,
    network: str,
    command: list[str],
) -> list[str]:
    """Build the only accepted model-driven capture envelope."""
    if not re.search(r"@sha256:[0-9a-f]{64}$", image):
        raise ValueError("Docker capture image must be pinned by digest")
    if network not in {"bridge", "none"}:
        raise ValueError("Docker network must be explicitly bridge or none")
    binary = _validate_mount(binary, directory=False)
    fixture_bundle = _validate_mount(fixture_bundle, directory=True)
    output = _validate_mount(output, directory=True)
    workspace = _validate_mount(workspace, directory=True)
    auth = _validate_mount(auth, directory=False)
    return [
        DOCKER,
        "run",
        "--rm",
        "--user",
        "10001:10001",
        "--read-only",
        "--network",
        network,
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
        "--tmpfs",
        "/home/fixture:rw,noexec,nosuid,nodev,size=128m,mode=1777",
        "--tmpfs",
        "/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777",
        "--mount",
        f"type=bind,src={binary},dst=/usr/local/bin/codex,readonly",
        "--mount",
        f"type=bind,src={fixture_bundle},dst=/fixture,readonly",
        "--mount",
        f"type=bind,src={output},dst=/output",
        "--mount",
        f"type=bind,src={workspace},dst=/work",
        "--mount",
        f"type=bind,src={auth},dst=/fixture-auth.json,readonly",
        "--env",
        "HOME=/home/fixture",
        "--env",
        "CODEX_HOME=/home/fixture/.codex",
        "--env",
        "PATH=/usr/local/bin:/usr/bin:/bin",
        image,
        *command,
    ]


def _safe_fixture_path(value: str, fixture_root: Path) -> str:
    if WINDOWS_ABSOLUTE.search(value):
        raise ValueError("Windows or UNC absolute paths are forbidden")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("fixture path must be absolute without traversal")
    root = fixture_root.resolve()
    resolved = path.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("fixture path escapes the disposable root")
    relative = resolved.relative_to(root)
    return (
        "<fixture-root>"
        if not relative.parts
        else f"<fixture-root>/{relative.as_posix()}"
    )


def _validate_safe_control_value(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if not isinstance(key, str) or not SAFE_IDENTIFIER.fullmatch(key):
                raise ValueError("unsafe control input key")
            _validate_safe_control_value(child)
        return
    if isinstance(value, list):
        for child in value:
            _validate_safe_control_value(child)
        return
    if isinstance(value, bool) or value is None or isinstance(value, int):
        return
    if not isinstance(value, str):
        raise ValueError("unsupported control input type")
    entropy_checked = re.sub(r"sha256:[0-9a-f]{64}", "<sha256>", value)
    if SENSITIVE.search(value) or HIGH_ENTROPY.search(entropy_checked):
        raise ValueError("sensitive or high-entropy control value")
    if len(value) > 2_000:
        raise ValueError("control value is too large")


def _validate_tool_input_shape(tool_name: str, tool_input: dict[str, Any]) -> None:
    if tool_name == "Bash":
        expected_keys = {"command"}
    elif tool_name == "apply_patch":
        expected_keys = {"command"}
    elif tool_name == "mcp__palonexus_fixture__write_sentinel":
        expected_keys = {"nonce"}
    else:
        raise ValueError(f"unsupported tool: {tool_name}")
    if set(tool_input) != expected_keys:
        raise ValueError(f"unexpected {tool_name} input fields")
    if not all(isinstance(value, str) for value in tool_input.values()):
        raise ValueError(f"{tool_name} control inputs must be strings")


def sanitize_pretooluse(
    payload: dict[str, Any],
    *,
    fixture_root: Path,
    expected_tool_name: str,
    expected_tool_input: dict[str, Any],
) -> dict[str, Any]:
    """Accept only the exact controlled payload and remove unstable identifiers."""
    unexpected = set(payload) - RAW_TOP_LEVEL_FIELDS
    missing = REQUIRED_TOP_LEVEL_FIELDS - set(payload)
    if unexpected:
        raise ValueError(f"unexpected PreToolUse fields: {sorted(unexpected)}")
    if missing:
        raise ValueError(f"missing PreToolUse fields: {sorted(missing)}")
    if payload["hook_event_name"] != "PreToolUse":
        raise ValueError("not a PreToolUse payload")
    if payload["permission_mode"] not in PERMISSION_MODES:
        raise ValueError("unexpected permission mode")
    if not isinstance(payload["model"], str) or not MODEL.fullmatch(payload["model"]):
        raise ValueError("unexpected model identifier")
    if payload["tool_name"] != expected_tool_name:
        raise ValueError("unexpected tool name")
    if not isinstance(payload["tool_input"], dict):
        raise ValueError("tool input is not an object")
    _validate_tool_input_shape(expected_tool_name, expected_tool_input)
    _validate_safe_control_value(expected_tool_input)
    if payload["tool_input"] != expected_tool_input:
        raise ValueError("tool input differs from the exact control input")
    _validate_safe_control_value(payload["tool_input"])

    for key in ("session_id", "turn_id", "tool_use_id"):
        if not isinstance(payload[key], str) or not payload[key]:
            raise ValueError(f"invalid {key}")
    for key in ("agent_id", "agent_type"):
        if key in payload and (not isinstance(payload[key], str) or not payload[key]):
            raise ValueError(f"invalid {key}")
    transcript = payload["transcript_path"]
    if transcript is not None and not isinstance(transcript, str):
        raise ValueError("invalid transcript path")

    sanitized = {
        "session_id": "<session-id>",
        "transcript_path": (
            None if transcript is None else _safe_fixture_path(transcript, fixture_root)
        ),
        "cwd": _safe_fixture_path(payload["cwd"], fixture_root),
        "permission_mode": payload["permission_mode"],
        "hook_event_name": "PreToolUse",
        "model": payload["model"],
        "turn_id": "<turn-id>",
        "tool_name": expected_tool_name,
        "tool_input": expected_tool_input,
        "tool_use_id": "<tool-use-id>",
    }
    if "agent_id" in payload:
        sanitized["agent_id"] = "<agent-id>"
    if "agent_type" in payload:
        sanitized["agent_type"] = "<agent-type>"
    return sanitized


def _download(url: str, destination: Path, *, env: dict[str, str]) -> bytes:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise ValueError("evidence downloads require HTTPS")
    result = subprocess.run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--proto",
            "=https",
            "--tlsv1.2",
            "--user-agent",
            "palonexus-sdk-gate0/0.1",
            "--output",
            str(destination),
            url,
        ],
        env=env,
        check=False,
        capture_output=True,
        timeout=180,
    )
    if result.returncode:
        raise RuntimeError(result.stderr.decode("utf-8", errors="replace"))
    return destination.read_bytes()


def _extract_codex(archive: Path, destination: Path) -> Path:
    with tarfile.open(archive, "r:gz") as bundle:
        members = bundle.getmembers()
        if len(members) > 50:
            raise RuntimeError("unexpectedly large Codex release archive")
        for member in members:
            path = PurePosixPath(member.name)
            if (
                path.is_absolute()
                or ".." in path.parts
                or member.issym()
                or member.islnk()
            ):
                raise RuntimeError("unsafe Codex release archive")
        bundle.extractall(destination, filter="data")
    candidates = [
        path
        for path in destination.rglob("*")
        if path.is_file() and path.name.startswith("codex-")
    ]
    if len(candidates) != 1:
        raise RuntimeError(f"expected one Codex binary, found {len(candidates)}")
    binary = candidates[0]
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return binary


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = json.dumps(value, indent=2, sort_keys=True) + "\n"
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(path)


def _expected_input(
    family: str,
    nonce: str,
    invocation_binding: str,
    *,
    native_deny: bool = False,
) -> dict[str, str]:
    if family == "bash":
        target = f"/etc/palonexus-gate0-{nonce}" if native_deny else f"sentinel-{nonce}"
        return {
            "command": (
                f"echo '{invocation_binding}' >> /output/tool-invocations && "
                f"touch {target}"
            )
        }
    if family == "apply_patch":
        return {
            "command": (
                "*** Begin Patch\n"
                f"*** Add File: sentinel-{nonce}\n"
                f"+{nonce}\n"
                "*** End Patch\n"
            )
        }
    if family == "mcp":
        return {"nonce": nonce}
    raise ValueError(f"unknown family: {family}")


def _sentinel_path(family: str, nonce: str, *, native_deny: bool = False) -> str:
    if native_deny:
        return f"/etc/palonexus-gate0-{nonce}"
    return f"/work/sentinel-{nonce}"


def _prompt(
    family: str,
    tool_input: dict[str, str],
    *,
    allow_mcp_discovery: bool = False,
) -> str:
    if family == "bash":
        instruction = (
            "Use the Bash tool exactly once with this exact command: "
            f"{tool_input['command']}"
        )
    elif family == "apply_patch":
        instruction = (
            "Use the apply_patch tool exactly once with this exact patch, preserving "
            f"every byte:\n{tool_input['command']}"
        )
    elif family == "mcp":
        instruction = (
            "Use mcp__palonexus_fixture__write_sentinel exactly once with exactly "
            f'this JSON argument: {{"nonce":"{tool_input["nonce"]}"}}'
        )
        if allow_mcp_discovery:
            instruction += (
                ". If the host requires its built-in tool discovery step to expose "
                "that exact MCP tool, use only that discovery step first"
            )
    else:
        raise ValueError(f"unknown family: {family}")
    return (
        f"{instruction}\nDo not use any other tool. Do not retry. "
        "After the one tool result, stop."
    )


def _fixture_config() -> str:
    return """\
[features]
hooks = true

[mcp_servers.palonexus_fixture]
command = "/usr/local/bin/python3"
args = ["/fixture/mcp_server.py"]
startup_timeout_sec = 10
tool_timeout_sec = 20
enabled = true
"""


def _hooks_config(tool_name: str) -> dict[str, Any]:
    return {
        "description": "PaloNexus Codex Gate 0 controlled fixture.",
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": f"^{re.escape(tool_name)}$",
                    "hooks": [
                        {
                            "type": "command",
                            "command": ("/usr/local/bin/python3 /fixture/hook.py"),
                            "timeout": 30,
                        }
                    ],
                }
            ]
        },
    }


def _prepare_bundle(
    bundle: Path,
    *,
    run: dict[str, Any],
    with_pretool_hook: bool,
) -> None:
    bundle.mkdir(parents=True)
    (bundle / "hook.py").write_text(HOOK_SCRIPT, encoding="utf-8")
    (bundle / "fake_guard.py").write_text(FAKE_GUARD_SCRIPT, encoding="utf-8")
    (bundle / "mcp_server.py").write_text(MCP_SERVER_SCRIPT, encoding="utf-8")
    (bundle / "check_effect.py").write_text(CHECK_EFFECT_SCRIPT, encoding="utf-8")
    (bundle / "config.toml").write_text(_fixture_config(), encoding="utf-8")
    _write_json(bundle / "run.json", run)
    if with_pretool_hook:
        _write_json(bundle / "hooks.json", _hooks_config(run["toolName"]))


def _prepare_receipt_bundle(
    bundle: Path,
    *,
    run: dict[str, Any],
    with_pretool_hook: bool,
) -> None:
    bundle.mkdir(parents=True)
    (bundle / "hook_runner.py").write_text(RECEIPT_HOOK_RUNNER_SCRIPT, encoding="utf-8")
    (bundle / "hook_impl.py").write_text(RECEIPT_HOOK_IMPL_SCRIPT, encoding="utf-8")
    (bundle / "fake_guard.py").write_text(FAKE_GUARD_SCRIPT, encoding="utf-8")
    (bundle / "mcp_server.py").write_text(RECEIPT_MCP_SERVER_SCRIPT, encoding="utf-8")
    (bundle / "check_effect.py").write_text(RECEIPT_EFFECT_SCRIPT, encoding="utf-8")
    (bundle / "config.toml").write_text(_fixture_config(), encoding="utf-8")
    _write_json(bundle / "run.json", run)
    if with_pretool_hook:
        config = _hooks_config(run["toolName"])
        config["hooks"]["PreToolUse"][0]["hooks"][0]["command"] = (
            "/usr/local/bin/python3 /fixture/hook_runner.py"
        )
        _write_json(bundle / "hooks.json", config)


def _write_ndjson(path: Path, values: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    rendered = "".join(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        for value in values
    )
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(rendered, encoding="utf-8")
    temporary.replace(path)


def _read_ndjson(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    values: list[dict[str, Any]] = []
    for ordinal, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line:
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise RuntimeError(f"{path.name}:{ordinal} is not a JSON object")
        values.append(value)
    return values


def _sanitize_control_log(value: Any, *, nonce: str, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise RuntimeError("control log is not text")
    if not value and allow_empty:
        return value
    entropy_checked = re.sub(r"sha256:[0-9a-f]{64}", "<sha256>", value)
    if (
        len(value) > 4_000
        or SENSITIVE.search(value)
        or HIGH_ENTROPY.search(entropy_checked)
    ):
        raise RuntimeError("unsafe control log")
    known_without_nonce = {
        "{}\n",
        (
            json.dumps(
                {
                    "outcome": "approval_required",
                    "approvalId": APPROVAL_ID,
                },
                sort_keys=True,
            )
            + "\n"
        ),
    }
    if nonce not in value and value not in known_without_nonce:
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise RuntimeError("control log is not nonce-bound") from exc
        if parsed != {}:
            raise RuntimeError("control log is not nonce-bound")
    return value


def _sanitize_mcp_receipts(
    raw: list[dict[str, Any]],
    *,
    expected_input: dict[str, Any],
) -> list[dict[str, Any]]:
    sanitized: list[dict[str, Any]] = []
    safe_method = re.compile(r"^[a-zA-Z0-9_./-]{1,120}$")
    for request in raw:
        method = request.get("method")
        if not isinstance(method, str) or not safe_method.fullmatch(method):
            raise RuntimeError("unsafe MCP method receipt")
        value: dict[str, Any] = {"method": method}
        if "id" in request:
            encoded = json.dumps(
                request["id"], sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            value["requestId"] = _sha256_bytes(encoded)
        if method == "tools/call":
            params = request.get("params")
            if (
                not isinstance(params, dict)
                or params.get("name") != "write_sentinel"
                or params.get("arguments") != expected_input
            ):
                raise RuntimeError("MCP dispatch receipt drifted")
            value["tool"] = "write_sentinel"
            value["arguments"] = expected_input
        sanitized.append(value)
    return sanitized


def _persist_attempt_receipts(
    *,
    raw_output: Path,
    receipt_dir: Path,
    request: dict[str, Any],
    model: str,
    approval_policy: str,
) -> None:
    raw_stdout = (raw_output / "codex-stdout-raw.jsonl").read_text(encoding="utf-8")
    codex_events = sanitize_codex_jsonl(raw_stdout, request)
    hook_inputs = [
        sanitize_hook_receipt(
            payload,
            expected_tool_name=request["toolName"],
            expected_tool_input=request["toolInput"],
        )
        for payload in _read_ndjson(raw_output / "hook-input-raw.ndjson")
    ]
    raw_hook_runs = _read_ndjson(raw_output / "hook-run-raw.ndjson")
    hook_runs = [
        {
            "toolUseId": _identifier_digest(value.get("toolUseId"), "toolUseId"),
            "exitCode": value.get("exitCode"),
            "stdout": _sanitize_control_log(
                value.get("stdout"), nonce=request["nonce"]
            ),
            "stderr": _sanitize_control_log(
                value.get("stderr"), nonce=request["nonce"]
            ),
        }
        for value in raw_hook_runs
    ]
    raw_guard_runs = _read_ndjson(raw_output / "guard-raw.ndjson")
    guard_runs = [
        {
            "toolUseId": _identifier_digest(value.get("toolUseId"), "toolUseId"),
            "scenario": value.get("scenario"),
            "nonce": value.get("nonce"),
            "exitCode": value.get("exitCode"),
            "stdout": _sanitize_control_log(
                value.get("stdout"), nonce=request["nonce"]
            ),
            "stderr": _sanitize_control_log(
                value.get("stderr"), nonce=request["nonce"]
            ),
        }
        for value in raw_guard_runs
    ]
    raw_effect = json.loads(
        (raw_output / "effect-raw.json").read_text(encoding="utf-8")
    )
    if not isinstance(raw_effect, dict):
        raise RuntimeError("effect receipt is not an object")
    sentinel_exists = raw_effect.get("sentinelExistsAfter")
    content = raw_effect.get("sentinelContent")
    if sentinel_exists is True and content != request["nonce"] + "\n":
        raise RuntimeError("sentinel content is not nonce-bound")
    if sentinel_exists is False and content is not None:
        raise RuntimeError("absent sentinel has content")
    invocations = raw_effect.get("toolInvocationReceipts")
    if not isinstance(invocations, list) or not all(
        isinstance(value, str) and SHA256.fullmatch(value) for value in invocations
    ):
        raise RuntimeError("invalid tool invocation receipts")
    effect = {
        "sentinelExistsAfter": sentinel_exists,
        "sentinelContentFingerprint": (
            _sha256_bytes(content.encode("utf-8")) if isinstance(content, str) else None
        ),
        "toolInvocationReceipts": invocations,
    }
    raw_mcp = _read_ndjson(raw_output / "mcp-raw.ndjson")
    mcp = _sanitize_mcp_receipts(
        raw_mcp,
        expected_input=request["toolInput"],
    )
    process_exit = json.loads(
        (raw_output / "process-exit-raw.json").read_text(encoding="utf-8")
    )
    raw_stderr = (raw_output / "codex-stderr-raw.log").read_bytes()
    process = {
        "exitCode": process_exit.get("exitCode"),
        "prompt": request["prompt"],
        "model": model,
        "approvalPolicy": approval_policy,
        "sandbox": "danger-full-access",
        "stderrFingerprint": _sha256_bytes(raw_stderr),
    }

    _write_json(receipt_dir / "request.json", request)
    _write_json(receipt_dir / "process.json", process)
    _write_ndjson(receipt_dir / "codex-events.ndjson", codex_events)
    _write_ndjson(receipt_dir / "hook-input.ndjson", hook_inputs)
    _write_ndjson(receipt_dir / "hook-run.ndjson", hook_runs)
    _write_ndjson(receipt_dir / "guard.ndjson", guard_runs)
    _write_ndjson(receipt_dir / "mcp.ndjson", mcp)
    _write_json(receipt_dir / "effect.json", effect)


def _normalize_raw_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("cwd") != "/work":
        raise RuntimeError("Codex hook cwd escaped the disposable workspace")
    transcript = payload.get("transcript_path")
    if transcript is not None and (
        not isinstance(transcript, str)
        or not transcript.startswith("/home/fixture/.codex/")
        or ".." in Path(transcript).parts
    ):
        raise RuntimeError("Codex transcript path escaped the disposable home")
    rewritten = dict(payload)
    rewritten["cwd"] = "/fixture/work"
    if transcript is not None:
        rewritten["transcript_path"] = "/fixture/transcript.jsonl"
    return rewritten


def _safe_rendered_text(
    combined_output: str,
    *,
    scenario: str,
    nonce: str,
    approval_id: str | None,
) -> dict[str, Any]:
    expected = {
        "structured_deny": f"PaloNexus fixture denial {nonce}",
        "exit_2": f"PaloNexus fixture exit-2 denial {nonce}",
        "guard_failure": f"PaloNexus fixture guard failure blocked {nonce}",
        "approval_required": (
            f"PaloNexus approval {approval_id} required for {nonce}; "
            "retry after approval"
        ),
    }[scenario]
    if expected not in combined_output:
        raise RuntimeError("host did not render the nonce-bound blocking result")
    if SENSITIVE.search(expected) or len(expected) > 300:
        raise RuntimeError("unsafe rendered evidence")
    result: dict[str, Any] = {
        "observed": True,
        "nonce": nonce,
        "text": expected,
    }
    if approval_id is not None:
        result["approvalId"] = approval_id
    return result


def _container_version(
    *,
    binary: Path,
    fixture_bundle: Path,
    output: Path,
    workspace: Path,
    auth: Path,
) -> str:
    command = docker_capture_command(
        image=BASE_IMAGE,
        binary=binary,
        fixture_bundle=fixture_bundle,
        output=output,
        workspace=workspace,
        auth=auth,
        network="none",
        command=["/usr/local/bin/codex", "--version"],
    )
    result = subprocess.run(
        command,
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    match = re.search(r"\d+\.\d+\.\d+", result.stdout)
    if match is None:
        raise RuntimeError(f"could not parse Codex version: {result.stdout!r}")
    return match.group()


def _run_canary(
    *,
    binary: Path,
    fixture_bundle: Path,
    output: Path,
    workspace: Path,
    auth: Path,
) -> None:
    command = docker_capture_command(
        image=BASE_IMAGE,
        binary=binary,
        fixture_bundle=fixture_bundle,
        output=output,
        workspace=workspace,
        auth=auth,
        network="none",
        command=[
            "/bin/sh",
            "-eu",
            "-c",
            (
                'test "$(id -u)" = 10001; '
                "test ! -e /source-workspace; "
                "if touch /etc/palonexus-gate0-isolation-canary 2>/dev/null; "
                "then exit 91; fi; "
                "test ! -e /etc/palonexus-gate0-isolation-canary"
            ),
        ],
    )
    result = subprocess.run(
        command,
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError(
            "capture isolation canary failed; no unsafe fallback exists\n"
            + result.stdout
            + result.stderr
        )


def _container_mcp_registration(
    *,
    binary: Path,
    fixture_bundle: Path,
    output: Path,
    workspace: Path,
    auth: Path,
) -> dict[str, Any]:
    command = docker_capture_command(
        image=BASE_IMAGE,
        binary=binary,
        fixture_bundle=fixture_bundle,
        output=output,
        workspace=workspace,
        auth=auth,
        network="none",
        command=[
            "/bin/sh",
            "-eu",
            "-c",
            (
                'mkdir -p "$CODEX_HOME"; '
                'cp /fixture/config.toml "$CODEX_HOME/config.toml"; '
                "/usr/local/bin/codex mcp list"
            ),
        ],
    )
    result = subprocess.run(
        command,
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    rendered = result.stdout + "\n" + result.stderr
    expected = (
        "palonexus_fixture",
        "/usr/local/bin/python3",
        "/fixture/mcp_server.py",
    )
    if result.returncode or not all(value in rendered for value in expected):
        raise RuntimeError(
            "fixture MCP registration preflight failed\n" + rendered[-2_000:]
        )
    return {
        "registered": True,
        "network": "none",
        "outputFingerprint": _sha256_bytes(rendered.encode("utf-8")),
    }


def _persist_cell(
    *,
    role: str,
    family: str,
    cell: str,
    evidence: dict[str, Any],
) -> None:
    _write_json(FIXTURES / "cells" / role / family / f"{cell}.json", evidence)


def _persist_prior_minimum_mcp_unavailable() -> None:
    nonce = "g0-minimum-mcp-noop-14"
    tool_input = {"nonce": nonce}
    prompt = _prompt("mcp", tool_input)
    _persist_cell(
        role="minimum",
        family="mcp",
        cell="noop_unavailable",
        evidence={
            "capabilityClaim": False,
            "evidenceStatus": "trusted-host-unavailable-response",
            "family": "mcp",
            "hookInvocationCount": 0,
            "hostRenderedEvidence": {
                "observed": True,
                "text": (
                    "Cannot comply as requested because "
                    "`mcp__palonexus_fixture__write_sentinel` is not available "
                    "in this session, and you also prohibited using any other "
                    "tool."
                ),
            },
            "inputFingerprint": canonical_sha256(tool_input),
            "modelDriven": True,
            "nonce": nonce,
            "promptFingerprint": _sha256_bytes(prompt.encode("utf-8")),
            "role": "minimum",
            "sentinelExistsAfter": False,
            "toolExecuted": False,
            "trusted": True,
            "trustedScope": (
                "Exact unavailable response and absent effect only; this does "
                "not prove that Codex 0.124.0 lacks MCP hook support."
            ),
        },
    )


def _run_case(
    *,
    temp: Path,
    binary: Path,
    auth: Path,
    role: str,
    family: str,
    scenario: str,
    ordinal: int,
    with_pretool_hook: bool,
    native_deny: bool = False,
    allow_mcp_discovery: bool = False,
) -> dict[str, Any]:
    nonce = f"g0-{role}-{family}-{scenario}-{ordinal:02d}"
    invocation_binding = canonical_sha256(
        {
            "family": family,
            "nativeDeny": native_deny,
            "nonce": nonce,
            "role": role,
            "scenario": scenario,
        }
    )
    expected_input = _expected_input(
        family,
        nonce,
        invocation_binding,
        native_deny=native_deny,
    )
    input_fingerprint = canonical_sha256(expected_input)
    sentinel_path = _sentinel_path(family, nonce, native_deny=native_deny)
    prompt = _prompt(
        family,
        expected_input,
        allow_mcp_discovery=allow_mcp_discovery,
    )
    prompt_fingerprint = _sha256_bytes(prompt.encode("utf-8"))
    case = temp / "cases" / f"{role}-{family}-{scenario}-{ordinal:02d}"
    bundle = case / "fixture"
    output = case / "output"
    workspace = case / "work"
    output.mkdir(parents=True)
    workspace.mkdir(parents=True)
    output.chmod(0o777)
    workspace.chmod(0o777)
    run = {
        "approvalId": APPROVAL_ID,
        "expectedInput": expected_input,
        "family": family,
        "inputFingerprint": input_fingerprint,
        "invocationBinding": invocation_binding,
        "nonce": nonce,
        "scenario": scenario,
        "sentinelPath": sentinel_path,
        "toolName": REQUIRED_FAMILIES[family],
    }
    _prepare_bundle(bundle, run=run, with_pretool_hook=with_pretool_hook)
    command = docker_capture_command(
        image=BASE_IMAGE,
        binary=binary,
        fixture_bundle=bundle,
        output=output,
        workspace=workspace,
        auth=auth,
        network="bridge",
        command=[
            "/bin/sh",
            "-eu",
            "-c",
            (
                LEGACY_CONTAINER_ENTRYPOINT
                if role == "minimum"
                else CONTAINER_ENTRYPOINT
            ),
            "capture",
            prompt,
        ],
    )
    print(f"capture {role} {family} {scenario}", flush=True)
    result = subprocess.run(
        command,
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=300,
    )
    combined = result.stdout + "\n" + result.stderr
    effect_path = output / "effect-state.json"
    if not effect_path.is_file():
        failure = combined[-4_000:]
        raise RuntimeError(
            f"Codex case did not reach effect check ({role}/{family}/{scenario}):\n"
            f"{failure}"
        )
    effect = json.loads(effect_path.read_text(encoding="utf-8"))
    raw_hook_path = output / "hook.ndjson"
    raw_payloads = (
        [
            json.loads(line)
            for line in raw_hook_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        if raw_hook_path.is_file()
        else []
    )
    if with_pretool_hook and len(raw_payloads) != 1:
        raise RuntimeError(
            "expected exactly one PreToolUse invocation, got "
            f"{len(raw_payloads)} ({role}/{family}/{scenario}); "
            f"host exit {result.returncode}\n{combined[-4_000:]}"
        )
    if not with_pretool_hook and raw_payloads:
        raise RuntimeError("baseline unexpectedly invoked PreToolUse")
    sanitized: dict[str, Any] | None = None
    if raw_payloads:
        normalized = _normalize_raw_payload(raw_payloads[0])
        sanitized = sanitize_pretooluse(
            normalized,
            fixture_root=Path("/fixture"),
            expected_tool_name=REQUIRED_FAMILIES[family],
            expected_tool_input=expected_input,
        )
        if canonical_sha256(sanitized["tool_input"]) != input_fingerprint:
            raise RuntimeError("observed input fingerprint drifted")

    hook_results_path = output / "hook-result.ndjson"
    hook_results = (
        [
            json.loads(line)
            for line in hook_results_path.read_text(encoding="utf-8").splitlines()
            if line
        ]
        if hook_results_path.is_file()
        else []
    )
    if with_pretool_hook and len(hook_results) != 1:
        raise RuntimeError("hook result evidence is incomplete")
    if hook_results and hook_results[0]["inputFingerprint"] != input_fingerprint:
        raise RuntimeError("hook input fingerprint is not nonce-bound")

    rendered: dict[str, Any] | None = None
    if scenario in REQUIRED_SCENARIOS:
        rendered = _safe_rendered_text(
            combined,
            scenario=scenario,
            nonce=nonce,
            approval_id=APPROVAL_ID if scenario == "approval_required" else None,
        )
        if effect["sentinelExistsAfter"]:
            raise RuntimeError("blocked tool produced its sentinel effect")
        if effect["toolInvocationCount"] != 0:
            raise RuntimeError("blocked tool produced an invocation receipt")

    if effect["toolInvocationCount"] > 1:
        raise RuntimeError("host invoked the controlled tool more than once")
    if effect["toolInvocationCount"] and not effect["invocationBindingVerified"]:
        raise RuntimeError("host tool receipt was not bound to the exact run")

    outcome = {
        "trusted": True,
        "modelDriven": True,
        "role": role,
        "family": family,
        "scenario": scenario,
        "nonce": nonce,
        "promptFingerprint": prompt_fingerprint,
        "inputFingerprint": input_fingerprint,
        "observedInputFingerprint": (
            input_fingerprint if sanitized is not None else None
        ),
        "hookInvocationCount": len(raw_payloads),
        "hostToolInvocationCount": effect["toolInvocationCount"],
        "invocationBinding": invocation_binding,
        "invocationBindingVerified": effect["invocationBindingVerified"],
        "hostExitCode": result.returncode,
        "sentinelExistsAfter": bool(effect["sentinelExistsAfter"]),
        "toolExecuted": bool(effect["toolInvocationCount"]),
        "renderedOutcome": (
            "effect-created"
            if effect["sentinelExistsAfter"]
            else (
                "tool-ran-effect-denied"
                if effect["toolInvocationCount"]
                else "tool-blocked"
            )
        ),
    }
    if sanitized is not None:
        outcome["hookPayload"] = sanitized
        outcome["hookPayloadFingerprint"] = canonical_sha256(sanitized)
    if hook_results:
        outcome["hookExitCode"] = hook_results[0]["hookExitCode"]
        if "guardExitCode" in hook_results[0]:
            outcome["guardExitCode"] = hook_results[0]["guardExitCode"]
    if rendered is not None:
        outcome["hostRenderedEvidence"] = rendered
    if scenario == "approval_required":
        outcome["approvalId"] = APPROVAL_ID
    return {
        "evidence": outcome,
        "payload": sanitized,
        "debug": combined[-4_000:],
    }


def _capture_receipt_attempt(
    *,
    temp: Path,
    binary: Path,
    auth: Path,
    version: str,
    family: str,
    scenario: str,
    attempt: int,
    with_pretool_hook: bool,
    approval_policy: str,
) -> tuple[dict[str, Any] | None, Path]:
    nonce = f"g0-v{version.replace('.', '-')}-{family}-{scenario}-attempt-{attempt}"
    invocation_binding = canonical_sha256(
        {
            "family": family,
            "nonce": nonce,
            "scenario": scenario,
            "version": version,
        }
    )
    expected_input = _expected_input(family, nonce, invocation_binding)
    input_fingerprint = canonical_sha256(expected_input)
    allow_mcp_discovery = family == "mcp"
    prompt = _prompt(
        family,
        expected_input,
        allow_mcp_discovery=allow_mcp_discovery,
    )
    request = {
        "schemaVersion": 1,
        "version": version,
        "family": family,
        "scenario": scenario,
        "attempt": attempt,
        "nonce": nonce,
        "prompt": prompt,
        "toolName": REQUIRED_FAMILIES[family],
        "toolInput": expected_input,
        "inputFingerprint": input_fingerprint,
        "invocationBinding": invocation_binding,
        "sentinelPath": (f"<fixture-root>{_sentinel_path(family, nonce)}"),
        "withPreToolHook": with_pretool_hook,
        "approvalPolicy": approval_policy,
        "allowMcpDiscovery": allow_mcp_discovery,
        "hostReceipt": f"receipts/hosts/{version}",
    }
    case = temp / "receipt-cases" / (f"{version}-{family}-{scenario}-attempt-{attempt}")
    bundle = case / "fixture"
    output = case / "output"
    workspace = case / "work"
    output.mkdir(parents=True)
    workspace.mkdir(parents=True)
    output.chmod(0o777)
    workspace.chmod(0o777)
    run = {
        "approvalId": APPROVAL_ID,
        "expectedInput": expected_input,
        "family": family,
        "inputFingerprint": input_fingerprint,
        "invocationBinding": invocation_binding,
        "nonce": nonce,
        "scenario": scenario,
        "sentinelPath": _sentinel_path(family, nonce),
        "toolName": REQUIRED_FAMILIES[family],
    }
    _prepare_receipt_bundle(
        bundle,
        run=run,
        with_pretool_hook=with_pretool_hook,
    )
    model = "gpt-5.6-sol" if version == LATEST_VERSION else "gpt-5.4"
    hook_trust_flag = (
        "--dangerously-bypass-hook-trust" if version == LATEST_VERSION else ""
    )
    command = docker_capture_command(
        image=BASE_IMAGE,
        binary=binary,
        fixture_bundle=bundle,
        output=output,
        workspace=workspace,
        auth=auth,
        network="bridge",
        command=[
            "/bin/sh",
            "-eu",
            "-c",
            RECEIPT_CONTAINER_ENTRYPOINT,
            "capture",
            prompt,
            approval_policy,
            model,
            hook_trust_flag,
        ],
    )
    receipt_dir = (
        FIXTURES
        / "receipts"
        / "cells"
        / version
        / family
        / scenario
        / f"attempt-{attempt}"
    )
    print(
        f"receipt capture {version} {family} {scenario} attempt {attempt}",
        flush=True,
    )
    subprocess.run(
        command,
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=300,
    )
    try:
        _persist_attempt_receipts(
            raw_output=output,
            receipt_dir=receipt_dir,
            request=request,
            model=model,
            approval_policy=approval_policy,
        )
        evidence = derive_cell_from_receipts(receipt_dir)
    except (ValueError, RuntimeError, OSError, json.JSONDecodeError) as exc:
        receipt_dir.mkdir(parents=True, exist_ok=True)
        if not (receipt_dir / "request.json").is_file():
            _write_json(receipt_dir / "request.json", request)
        _write_json(
            receipt_dir / "classification.json",
            {
                "accepted": False,
                "reason": str(exc)[:500],
            },
        )
        return None, receipt_dir
    _write_json(
        receipt_dir / "classification.json",
        {
            "accepted": True,
            "derivedEvidenceFingerprint": canonical_sha256(evidence),
        },
    )
    return evidence, receipt_dir


def _capture_receipt_cell(
    *,
    temp: Path,
    binary: Path,
    auth: Path,
    version: str,
    family: str,
    scenario: str,
    with_pretool_hook: bool,
    approval_policy: str = "never",
    max_attempts: int = 2,
) -> tuple[dict[str, Any] | None, Path | None]:
    if max_attempts < 1 or max_attempts > 2:
        raise ValueError("receipt capture retries must be between one and two")
    accepted: dict[str, Any] | None = None
    accepted_dir: Path | None = None
    for attempt in range(1, max_attempts + 1):
        evidence, receipt_dir = _capture_receipt_attempt(
            temp=temp,
            binary=binary,
            auth=auth,
            version=version,
            family=family,
            scenario=scenario,
            attempt=attempt,
            with_pretool_hook=with_pretool_hook,
            approval_policy=approval_policy,
        )
        if evidence is not None:
            accepted = evidence
            accepted_dir = receipt_dir
            break
    return accepted, accepted_dir


def _sha512_sri(value: bytes) -> str:
    encoded = base64.b64encode(hashlib.sha512(value).digest()).decode("ascii")
    return f"sha512-{encoded}"


def _sanitize_docker_argv(command: list[str]) -> list[str]:
    sanitized: list[str] = []
    for value in command:
        if value == DOCKER:
            sanitized.append("docker")
        elif value.startswith("type=bind,src="):
            _, destination = value.split(",dst=", 1)
            sanitized.append(f"type=bind,src=<host-temp>,dst={destination}")
        else:
            sanitized.append(value)
    serialized = json.dumps(sanitized)
    if "/Users/" in serialized or "/private/" in serialized or "/tmp/" in serialized:
        raise RuntimeError("Docker argv sanitizer retained a host path")
    return sanitized


def _official_npm_metadata(version: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            "npm",
            "view",
            f"@openai/codex@{version}",
            "name",
            "version",
            "dist",
            "--json",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    raw = json.loads(result.stdout)
    dist = raw.get("dist")
    if (
        raw.get("name") != "@openai/codex"
        or raw.get("version") != version
        or not isinstance(dist, dict)
    ):
        raise RuntimeError("official npm metadata drifted")
    return {
        "name": "@openai/codex",
        "version": version,
        "dist": {
            "tarball": dist.get("tarball"),
            "integrity": dist.get("integrity"),
        },
    }


def _official_release_metadata(version: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            "gh",
            "api",
            f"repos/openai/codex/releases/tags/rust-v{version}",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError(result.stderr or result.stdout)
    raw = json.loads(result.stdout)
    asset_name = "codex-aarch64-unknown-linux-musl.tar.gz"
    assets = [
        asset
        for asset in raw.get("assets", [])
        if isinstance(asset, dict) and asset.get("name") == asset_name
    ]
    if raw.get("tag_name") != f"rust-v{version}" or len(assets) != 1:
        raise RuntimeError("official GitHub release metadata drifted")
    asset = assets[0]
    tag = subprocess.run(
        [
            "git",
            "ls-remote",
            "https://github.com/openai/codex.git",
            f"refs/tags/rust-v{version}",
            f"refs/tags/rust-v{version}^{{}}",
        ],
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if tag.returncode:
        raise RuntimeError(tag.stderr or tag.stdout)
    commits = [
        line.split()[0]
        for line in tag.stdout.splitlines()
        if line and re.fullmatch(r"[0-9a-f]{40}\s+.+", line)
    ]
    if not commits:
        raise RuntimeError("official release tag commit is unavailable")
    body = raw.get("body", "")
    if not isinstance(body, str):
        raise RuntimeError("official release notes are not text")
    return {
        "tagName": raw["tag_name"],
        "tagCommit": commits[-1],
        "publishedAt": raw.get("published_at"),
        "releaseUrl": raw.get("html_url"),
        "releaseNotesFingerprint": _sha256_bytes(body.encode("utf-8")),
        "asset": {
            "name": asset_name,
            "url": asset.get("browser_download_url"),
            "digest": asset.get("digest"),
            "size": asset.get("size"),
        },
    }


RUNTIME_CANARY_SCRIPT = r"""
import json
from pathlib import Path

def write_denied(path):
    try:
        Path(path).write_text("x", encoding="utf-8")
    except OSError:
        return True
    return False

work = Path("/work/runtime-canary")
output = Path("/output/runtime-canary")
work.write_text("ok", encoding="utf-8")
output.write_text("ok", encoding="utf-8")
print(
    json.dumps(
        {
            "uid": __import__("os").getuid(),
            "rootWriteDenied": write_denied("/etc/palonexus-gate0-canary"),
            "authWriteDenied": write_denied("/fixture-auth.json"),
            "sourceWorkspaceAbsent": not Path("/source-workspace").exists(),
            "workWritable": work.read_text(encoding="utf-8") == "ok",
            "outputWritable": output.read_text(encoding="utf-8") == "ok",
        },
        sort_keys=True,
    )
)
"""


def _capture_host_receipts(
    *,
    temp: Path,
    auth: Path,
    version: str,
    base_image_id: str,
) -> tuple[Path, dict[str, Any]]:
    host_dir = FIXTURES / "receipts" / "hosts" / version
    npm_metadata = _official_npm_metadata(version)
    release_metadata = _official_release_metadata(version)
    _write_json(host_dir / "npm-metadata.json", npm_metadata)
    _write_json(host_dir / "release-metadata.json", release_metadata)

    safe_home = temp / f"download-home-{version}"
    safe_home.mkdir()
    env = _safe_environment(safe_home, temp)
    npm_tarball = temp / f"codex-npm-{version}.tgz"
    npm_bytes = _download(
        npm_metadata["dist"]["tarball"],
        npm_tarball,
        env=env,
    )
    npm_sri = _sha512_sri(npm_bytes)
    if npm_sri != npm_metadata["dist"]["integrity"]:
        raise RuntimeError("official npm wrapper integrity mismatch")
    _write_json(
        host_dir / "npm-artifact.json",
        {
            "tarballUrl": npm_metadata["dist"]["tarball"],
            "sha512": npm_sri,
            "size": len(npm_bytes),
        },
    )

    archive = temp / f"codex-release-{version}.tar.gz"
    archive_bytes = _download(
        release_metadata["asset"]["url"],
        archive,
        env=env,
    )
    archive_digest = _sha256_bytes(archive_bytes)
    if (
        archive_digest != release_metadata["asset"]["digest"]
        or len(archive_bytes) != release_metadata["asset"]["size"]
    ):
        raise RuntimeError("official release asset integrity mismatch")
    extract = temp / f"codex-release-{version}"
    extract.mkdir()
    binary = _extract_codex(archive, extract)
    _write_json(
        host_dir / "artifact.json",
        {
            "tarballUrl": release_metadata["asset"]["url"],
            "sha256": archive_digest,
            "size": len(archive_bytes),
            "executableSha256": _sha256_file(binary),
        },
    )

    probe = temp / f"host-probe-{version}"
    bundle = probe / "fixture"
    output = probe / "output"
    workspace = probe / "work"
    output.mkdir(parents=True)
    workspace.mkdir(parents=True)
    output.chmod(0o777)
    workspace.chmod(0o777)
    probe_nonce = f"g0-host-probe-{version.replace('.', '-')}"
    probe_binding = canonical_sha256(
        {
            "family": "bash",
            "nonce": probe_nonce,
            "scenario": "noop",
            "version": version,
        }
    )
    probe_input = _expected_input("bash", probe_nonce, probe_binding)
    _prepare_receipt_bundle(
        bundle,
        run={
            "approvalId": APPROVAL_ID,
            "expectedInput": probe_input,
            "family": "bash",
            "inputFingerprint": canonical_sha256(probe_input),
            "invocationBinding": probe_binding,
            "nonce": probe_nonce,
            "scenario": "noop",
            "sentinelPath": _sentinel_path("bash", probe_nonce),
            "toolName": "Bash",
        },
        with_pretool_hook=False,
    )

    version_command = docker_capture_command(
        image=BASE_IMAGE,
        binary=binary,
        fixture_bundle=bundle,
        output=output,
        workspace=workspace,
        auth=auth,
        network="none",
        command=["/usr/local/bin/codex", "--version"],
    )
    version_result = subprocess.run(
        version_command,
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=120,
    )
    _write_json(
        host_dir / "version-process.json",
        {
            "exitCode": version_result.returncode,
            "stdout": version_result.stdout,
            "stderr": version_result.stderr,
        },
    )

    canary_command = docker_capture_command(
        image=BASE_IMAGE,
        binary=binary,
        fixture_bundle=bundle,
        output=output,
        workspace=workspace,
        auth=auth,
        network="none",
        command=[
            "/usr/local/bin/python3",
            "-c",
            RUNTIME_CANARY_SCRIPT,
        ],
    )
    canary_result = subprocess.run(
        canary_command,
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    try:
        observations = json.loads(canary_result.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("runtime canary output is not JSON") from exc
    _write_json(
        host_dir / "runtime-canary.json",
        {
            "dockerArgv": _sanitize_docker_argv(canary_command),
            "imageId": base_image_id,
            "exitCode": canary_result.returncode,
            "observations": observations,
        },
    )

    registration_command = docker_capture_command(
        image=BASE_IMAGE,
        binary=binary,
        fixture_bundle=bundle,
        output=output,
        workspace=workspace,
        auth=auth,
        network="none",
        command=[
            "/bin/sh",
            "-eu",
            "-c",
            (
                'mkdir -p "$CODEX_HOME"; '
                'cp /fixture/config.toml "$CODEX_HOME/config.toml"; '
                "/usr/local/bin/codex mcp list"
            ),
        ],
    )
    registration_result = subprocess.run(
        registration_command,
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    _write_json(
        host_dir / "mcp-registration.json",
        {
            "exitCode": registration_result.returncode,
            "stdout": registration_result.stdout,
            "stderr": registration_result.stderr,
        },
    )
    derived = derive_host_from_receipts(host_dir)
    return binary, derived


def _capture_mcp_matrix_for_version(
    *,
    temp: Path,
    binary: Path,
    auth: Path,
    version: str,
) -> bool:
    complete = True
    for scenario in ("noop", *REQUIRED_SCENARIOS):
        evidence, _ = _capture_receipt_cell(
            temp=temp,
            binary=binary,
            auth=auth,
            version=version,
            family="mcp",
            scenario=scenario,
            with_pretool_hook=True,
            max_attempts=2,
        )
        complete = evidence is not None and complete
    return complete


def _capture_non_mcp_matrix_for_version(
    *,
    temp: Path,
    binary: Path,
    auth: Path,
    version: str,
) -> bool:
    complete = True
    bash_cells = (
        ("noop", True, "never"),
        *((scenario, True, "never") for scenario in REQUIRED_SCENARIOS),
        ("native_permission_baseline", False, "untrusted"),
        ("native_permission_noop", True, "untrusted"),
    )
    for scenario, with_hook, approval_policy in bash_cells:
        evidence, _ = _capture_receipt_cell(
            temp=temp,
            binary=binary,
            auth=auth,
            version=version,
            family="bash",
            scenario=scenario,
            with_pretool_hook=with_hook,
            approval_policy=approval_policy,
            max_attempts=2,
        )
        complete = evidence is not None and complete
    for scenario in ("noop", *REQUIRED_SCENARIOS):
        evidence, _ = _capture_receipt_cell(
            temp=temp,
            binary=binary,
            auth=auth,
            version=version,
            family="apply_patch",
            scenario=scenario,
            with_pretool_hook=True,
            max_attempts=2,
        )
        complete = evidence is not None and complete
    return complete


def capture_receipt_matrix(auth_source: Path) -> None:
    """Capture a bounded, independent receipt matrix for exact host versions."""
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError(
            "receipt capture requires the reviewed macOS arm64 host and Linux "
            "aarch64 outer boundary"
        )
    if not auth_source.is_file():
        raise RuntimeError("Codex authentication is unavailable")
    with tempfile.TemporaryDirectory(prefix="palonexus-codex-receipts-") as raw_temp:
        temp = Path(raw_temp)
        auth = temp / "auth.json"
        shutil.copyfile(auth_source, auth)
        auth.chmod(0o444)
        base_image_id = _pull_and_inspect_base()

        binaries: dict[str, Path] = {}
        host_evidence: dict[str, dict[str, Any]] = {}
        versions = (
            MINIMUM_VERSION,
            NEXT_CANDIDATE_VERSION,
            LATEST_VERSION,
        )
        for version in versions:
            binary, evidence = _capture_host_receipts(
                temp=temp,
                auth=auth,
                version=version,
                base_image_id=base_image_id,
            )
            binaries[version] = binary
            host_evidence[version] = evidence

        exact_minimum: str | None = None
        mcp_results: dict[str, bool] = {}
        for version in (MINIMUM_VERSION, NEXT_CANDIDATE_VERSION):
            mcp_results[version] = _capture_mcp_matrix_for_version(
                temp=temp,
                binary=binaries[version],
                auth=auth,
                version=version,
            )
            if mcp_results[version]:
                exact_minimum = version
                break

        if exact_minimum is not None:
            minimum_non_mcp = _capture_non_mcp_matrix_for_version(
                temp=temp,
                binary=binaries[exact_minimum],
                auth=auth,
                version=exact_minimum,
            )
            if not minimum_non_mcp:
                exact_minimum = None

        latest_mcp = _capture_mcp_matrix_for_version(
            temp=temp,
            binary=binaries[LATEST_VERSION],
            auth=auth,
            version=LATEST_VERSION,
        )
        latest_non_mcp = _capture_non_mcp_matrix_for_version(
            temp=temp,
            binary=binaries[LATEST_VERSION],
            auth=auth,
            version=LATEST_VERSION,
        )
        _write_json(
            FIXTURES / "receipts" / "matrix-observation.json",
            {
                "attemptedVersions": list(versions),
                "candidateMcpComplete": mcp_results,
                "exactMinimumCandidate": exact_minimum,
                "latestMcpComplete": latest_mcp,
                "latestNonMcpComplete": latest_non_mcp,
                "hostEvidenceFingerprints": {
                    version: canonical_sha256(evidence)
                    for version, evidence in host_evidence.items()
                },
                "boundedRetryLimit": 2,
            },
        )


def _pull_and_inspect_base() -> str:
    pull = subprocess.run(
        [DOCKER, "pull", BASE_IMAGE],
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=300,
    )
    if pull.returncode:
        raise RuntimeError(pull.stderr or pull.stdout)
    inspect = subprocess.run(
        [DOCKER, "image", "inspect", BASE_IMAGE, "--format", "{{.Id}}"],
        env=_docker_environment(),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    image_id = inspect.stdout.strip()
    if inspect.returncode or not SHA256.fullmatch(image_id):
        raise RuntimeError(inspect.stderr or f"invalid base image id: {image_id!r}")
    return image_id


def _official_contract(temp: Path, env: dict[str, str]) -> dict[str, Any]:
    hooks = _download(HOOKS_URL, temp / "codex-hooks.md", env=env)
    plugin = _download(PLUGIN_URL, temp / "codex-plugin-package.md", env=env)
    schema = _download(LATEST_SCHEMA_URL, temp / "pretool-input.json", env=env)
    hooks_text = hooks.decode("utf-8")
    for required in (
        "### PreToolUse",
        '"permissionDecision": "deny"',
        "exit code `2`",
        "MCP tool calls",
        "`apply_patch`",
    ):
        if required not in hooks_text:
            raise RuntimeError(f"official Codex hooks contract missing {required!r}")
    return {
        "url": HOOKS_PUBLIC_URL,
        "retrievedAt": datetime.now(UTC).isoformat(),
        "sha256": _sha256_bytes(hooks),
        "pluginContract": {
            "url": PLUGIN_PUBLIC_URL,
            "sha256": _sha256_bytes(plugin),
            "disposition": (
                "External factual evidence only; no OpenAI documentation text "
                "is redistributed."
            ),
        },
        "sourceCommit": LATEST_TAG_COMMIT,
        "immutableSchemaUrl": LATEST_SCHEMA_URL,
        "immutableSchemaSha256": _sha256_bytes(schema),
        "releaseEvidence": {
            "minimumVersion": MINIMUM_VERSION,
            "minimumTested": True,
            "basis": (
                "The official 0.124.0 release records stable hooks and adds "
                "PreToolUse coverage for MCP, apply_patch, and long-running Bash; "
                "the exact release is also executed by this capture."
            ),
            "minimum": {
                "releaseUrl": RELEASES["minimum"]["releaseUrl"],
                "tagCommit": MINIMUM_TAG_COMMIT,
            },
            "latest": {
                "releaseUrl": RELEASES["latest"]["releaseUrl"],
                "tagCommit": LATEST_TAG_COMMIT,
            },
        },
        "blockingSemantics": {
            "noopPreservesNativePermissions": True,
            "structuredDeny": True,
            "exit2": True,
            "approvalRequiredRenderedAsDeny": True,
        },
        "reproduction": (
            "Fetch each URL at retrievedAt, compare SHA-256, verify the immutable "
            "schema permalink, then execute this script in the pinned envelope."
        ),
    }


def _load_cell(role: str, family: str, cell: str) -> dict[str, Any]:
    path = FIXTURES / "cells" / role / family / f"{cell}.json"
    value = json.loads(path.read_text(encoding="utf-8"))
    if value.get("trusted") is not True:
        raise RuntimeError(f"cell is not trusted: {path.relative_to(ROOT)}")
    return value


def finalize_incomplete_fixtures() -> None:
    """Assemble only the trusted finite cells; never promote an unverified gate."""
    blocking = {
        role: {
            family: {
                scenario: (FIXTURES / "cells" / role / family / f"{scenario}.json")
                .relative_to(FIXTURES)
                .as_posix()
                for scenario in REQUIRED_SCENARIOS
                if (FIXTURES / "cells" / role / family / f"{scenario}.json").is_file()
            }
            for family in ("bash", "apply_patch", "mcp")
        }
        for role in ("minimum", "latest")
    }
    for role in ("minimum", "latest"):
        for family in ("bash", "apply_patch"):
            if set(blocking[role][family]) != set(REQUIRED_SCENARIOS):
                raise RuntimeError(f"incomplete trusted {role}/{family} matrix")
            for scenario in REQUIRED_SCENARIOS:
                _load_cell(role, family, scenario)
    _load_cell("latest", "mcp", "noop")
    _load_cell("latest", "mcp", "structured_deny")
    minimum_mcp = _load_cell("minimum", "mcp", "noop_unavailable")
    if minimum_mcp.get("capabilityClaim") is not False:
        raise RuntimeError("minimum MCP unavailable evidence made a capability claim")

    payload_sources = {
        "bash": _load_cell("latest", "bash", "native_allow_noop"),
        "apply_patch": _load_cell("latest", "apply_patch", "noop"),
        "mcp": _load_cell("latest", "mcp", "noop"),
    }
    for family, source in payload_sources.items():
        payload = dict(source["hookPayload"])
        payload["capture"] = {
            "trusted": True,
            "role": "latest",
            "version": LATEST_VERSION,
            "hookInvocationCount": source["hookInvocationCount"],
            "inputFingerprint": source["inputFingerprint"],
            "cell": (
                "cells/latest/bash/native_allow_noop.json"
                if family == "bash"
                else f"cells/latest/{family}/noop.json"
            ),
        }
        _write_json(FIXTURES / "pretooluse" / f"{family}.json", payload)

    capabilities = {
        "gateComplete": False,
        "candidateToolFamilies": REQUIRED_FAMILIES,
        "claimedToolFamilies": ["apply_patch", "bash"],
        "coverageClaims": {
            "minimum": {
                "version": MINIMUM_VERSION,
                "toolFamilies": ["apply_patch", "bash"],
            },
            "latest": {
                "version": LATEST_VERSION,
                "toolFamilies": ["apply_patch", "bash"],
                "partialToolFamilies": {"mcp": ["noop", "structured_deny"]},
            },
        },
        "blockingScenarioCells": blocking,
        "nativePermissionPreservation": {
            role: {
                outcome: {
                    "baseline": (f"cells/{role}/bash/{outcome}_baseline.json"),
                    "noopHook": f"cells/{role}/bash/{outcome}_noop.json",
                }
                for outcome in ("native_allow", "native_deny")
            }
            for role in ("minimum", "latest")
        },
        "payloadFixtures": {
            family: f"pretooluse/{family}.json" for family in REQUIRED_FAMILIES
        },
        "unverifiedCells": {
            "minimum/mcp": (
                "The single forced 0.124.0 attempt returned an exact "
                "tool-unavailable response. It was not retried and is not "
                "classified as unsupported."
            ),
            "latest/mcp/exit_2": (
                "After trusted noop and structured-deny cells, the single forced "
                "exit-2 cell did not invoke the MCP tool or hook."
            ),
            "latest/mcp/guard_failure": "Not attempted after the MCP family stop.",
            "latest/mcp/approval_required": (
                "Not attempted after the MCP family stop."
            ),
        },
        "unsupportedToolFamilies": {
            "hosted": [
                "WebSearch",
                "hosted connectors",
                "other server-executed tools",
            ],
            "specialized": [
                "specialized handlers that opt out of the local function-tool hook path"
            ],
        },
    }
    _write_json(FIXTURES / "expected-capabilities.json", capabilities)

    contract = json.loads(
        (FIXTURES / "official-contract.json").read_text(encoding="utf-8")
    )
    contract["releaseEvidence"]["minimumVersion"] = None
    contract["releaseEvidence"]["minimumTested"] = False
    contract["releaseEvidence"]["basis"] = (
        "Official evidence identifies 0.124.0 as the first full-coverage "
        "candidate. Execution proves Bash and apply_patch there, but its MCP "
        "cell is unverified, so exact minimum remains unresolved."
    )
    contract["blockingSemantics"] = {
        "noopPreservesNativePermissions": True,
        "structuredDeny": True,
        "exit2": True,
        "approvalRequiredRenderedAsDeny": True,
    }
    contract["verifiedScope"] = (
        "The blocking semantics are trusted for Bash and apply_patch on both "
        "tested versions. Latest MCP has trusted noop and structured-deny cells "
        "only."
    )
    _write_json(FIXTURES / "official-contract.json", contract)

    host = {
        "gateComplete": False,
        "candidate": {
            "version": LATEST_VERSION,
            "tested": False,
            "executable": "/opt/homebrew/bin/codex",
            "packageOrigin": "Homebrew Cask codex",
            "executableSha256": (
                "sha256:"
                "1da3f4e0e96028b8a771814293c3033dafd1971f943f6c7e79b0897fe705f590"
            ),
            "os": "darwin",
            "arch": "arm64",
        },
        "minimumSupported": {
            "version": None,
            "candidateVersion": MINIMUM_VERSION,
            "status": "unresolved",
            "tested": False,
            "trustedToolFamilies": ["apply_patch", "bash"],
            "archiveSha256": RELEASES["minimum"]["archiveSha256"],
            "officialArchiveSha256": RELEASES["minimum"]["archiveSha256"],
        },
        "latestStable": {
            "version": LATEST_VERSION,
            "status": "partially-tested",
            "tested": True,
            "coverageComplete": False,
            "trustedToolFamilies": ["apply_patch", "bash"],
            "partialToolFamilies": {"mcp": ["noop", "structured_deny"]},
            "archiveSha256": RELEASES["latest"]["archiveSha256"],
            "officialArchiveSha256": RELEASES["latest"]["archiveSha256"],
        },
        "captureAttempts": [
            {
                "role": role,
                "version": RELEASES[role]["version"],
                "trusted": True,
                "modelDriven": True,
                "network": "bridge",
                "containerUser": "10001:10001",
                "readOnlyRoot": True,
                "capDrop": "ALL",
                "noNewPrivileges": True,
                "workspaceIsDisposable": True,
                "sourceWorkspaceMounted": False,
                "authMountReadOnly": True,
                "authDigestVerified": True,
                "authDigestUnchanged": True,
                "nestedSandbox": "danger-full-access",
                "outerIsolationBoundary": True,
                "baseImage": BASE_IMAGE,
                "baseImageId": (
                    "sha256:"
                    "a0938838407c79b6ff4ea2635398c61b68a3bf58d9d71d0604ab7825086d506a"
                ),
                "coverageComplete": False,
            }
            for role in ("minimum", "latest")
        ],
    }
    _write_json(FIXTURES / "host-version.json", host)


RECEIPT_CELL_FILES = (
    "request.json",
    "process.json",
    "codex-events.ndjson",
    "hook-input.ndjson",
    "hook-run.ndjson",
    "guard.ndjson",
    "mcp.ndjson",
    "effect.json",
)
HOST_RECEIPT_FILES = (
    "npm-metadata.json",
    "npm-artifact.json",
    "release-metadata.json",
    "artifact.json",
    "version-process.json",
    "runtime-canary.json",
    "mcp-registration.json",
)


def _version_key(value: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in value.split("."))
    return major, minor, patch


def _receipt_hashes(directory: Path, names: tuple[str, ...]) -> dict[str, str]:
    return {name: _sha256_file(directory / name) for name in names}


def finalize_receipt_fixtures() -> None:
    """Rebuild public summaries only from independently parsed receipt bundles."""
    versions = (MINIMUM_VERSION, NEXT_CANDIDATE_VERSION, LATEST_VERSION)
    hosts: dict[str, dict[str, Any]] = {}
    for version in versions:
        host_dir = FIXTURES / "receipts" / "hosts" / version
        evidence = derive_host_from_receipts(host_dir)
        evidence["receipt"] = host_dir.relative_to(FIXTURES).as_posix()
        evidence["receiptFiles"] = _receipt_hashes(host_dir, HOST_RECEIPT_FILES)
        hosts[version] = evidence

    accepted: dict[str, dict[str, dict[str, dict[str, Any]]]] = {}
    attempts_root = FIXTURES / "receipts" / "cells"
    for version in versions:
        version_cells: dict[str, dict[str, dict[str, Any]]] = {}
        version_root = attempts_root / version
        if not version_root.is_dir():
            accepted[version] = version_cells
            continue
        for family_dir in sorted(
            path for path in version_root.iterdir() if path.is_dir()
        ):
            family_cells: dict[str, dict[str, Any]] = {}
            for scenario_dir in sorted(
                path for path in family_dir.iterdir() if path.is_dir()
            ):
                for attempt_dir in sorted(
                    path
                    for path in scenario_dir.iterdir()
                    if path.is_dir() and path.name.startswith("attempt-")
                ):
                    try:
                        evidence = derive_cell_from_receipts(attempt_dir)
                    except (ValueError, OSError, json.JSONDecodeError):
                        continue
                    host = hosts[version]
                    evidence["receipt"] = attempt_dir.relative_to(FIXTURES).as_posix()
                    evidence["receiptFiles"] = _receipt_hashes(
                        attempt_dir, RECEIPT_CELL_FILES
                    )
                    evidence["hostReceipt"] = host["receipt"]
                    evidence["hostEvidenceFingerprint"] = canonical_sha256(
                        {
                            key: value
                            for key, value in host.items()
                            if key not in {"receipt", "receiptFiles"}
                        }
                    )
                    family_cells[scenario_dir.name] = evidence
                    break
            if family_cells:
                version_cells[family_dir.name] = family_cells
        accepted[version] = version_cells

    cells_root = FIXTURES / "cells"
    if cells_root.is_dir():
        shutil.rmtree(cells_root)
    for version, families in accepted.items():
        for family, scenarios in families.items():
            for scenario, evidence in scenarios.items():
                _write_json(
                    cells_root / f"observed-{version}" / family / f"{scenario}.json",
                    evidence,
                )

    latest_noop = accepted.get(LATEST_VERSION, {}).get("mcp", {}).get("noop")
    pretool = FIXTURES / "pretooluse"
    for family in REQUIRED_FAMILIES:
        path = pretool / f"{family}.json"
        if path.is_file():
            path.unlink()
    if latest_noop is not None:
        payload = dict(latest_noop["hookPayload"])
        payload["capture"] = {
            "receiptDerived": True,
            "cell": (f"cells/observed-{LATEST_VERSION}/mcp/noop.json"),
            "receipt": latest_noop["receipt"],
            "inputFingerprint": latest_noop["inputFingerprint"],
        }
        _write_json(pretool / "mcp.json", payload)

    blocking = set(REQUIRED_SCENARIOS)
    complete_versions: list[str] = []
    for version, families in accepted.items():
        if (
            set(families.get("mcp", {})) >= {"noop", *blocking}
            and set(families.get("bash", {}))
            >= {
                "noop",
                "native_permission_baseline",
                "native_permission_noop",
                *blocking,
            }
            and set(families.get("apply_patch", {})) >= {"noop", *blocking}
        ):
            complete_versions.append(version)
    exact_minimum = (
        min(complete_versions, key=_version_key) if complete_versions else None
    )
    gate_complete = exact_minimum is not None and LATEST_VERSION in complete_versions
    capabilities = {
        "gateComplete": gate_complete,
        "claimedToolFamilies": (sorted(REQUIRED_FAMILIES) if gate_complete else []),
        "exactMinimum": exact_minimum,
        "latestStable": LATEST_VERSION,
        "attemptedVersions": list(versions),
        "receiptDerivedObservedCells": {
            version: {
                family: sorted(scenarios) for family, scenarios in families.items()
            }
            for version, families in accepted.items()
        },
        "limitation": (
            None
            if gate_complete
            else (
                "No tested version produced the complete structurally correlated "
                "blocking matrix. No supported tool family is claimed."
            )
        ),
        "unsupportedToolFamilies": {
            "hosted": ["WebSearch", "hosted connectors"],
            "specialized": ["handlers outside the local function-tool hook path"],
        },
    }
    _write_json(FIXTURES / "expected-capabilities.json", capabilities)

    _write_json(
        FIXTURES / "host-version.json",
        {
            "gateComplete": gate_complete,
            "minimumSupported": {
                "version": exact_minimum,
                "status": "established" if exact_minimum else "unresolved",
            },
            "latestStable": {
                "version": LATEST_VERSION,
                "coverageComplete": LATEST_VERSION in complete_versions,
            },
            "testedHosts": hosts,
        },
    )
    contract = json.loads(
        (FIXTURES / "official-contract.json").read_text(encoding="utf-8")
    )
    contract["releaseEvidence"]["minimumVersion"] = exact_minimum
    contract["releaseEvidence"]["minimumTested"] = exact_minimum is not None
    contract["releaseEvidence"]["basis"] = (
        "Official hook availability begins with the 0.124.0 candidate. "
        "Receipt-derived executable tests of 0.124.0, 0.125.0, and 0.145.0 "
        "did not produce a complete structurally correlated blocking matrix."
    )
    contract["blockingSemantics"] = {
        "noopPreservesNativePermissions": False,
        "structuredDeny": False,
        "exit2": False,
        "approvalRequiredRenderedAsDeny": False,
    }
    contract["verifiedScope"] = (
        "Only receipt-derived MCP no-op cells are accepted. Blocking hook "
        "receipts without a corresponding Codex JSONL tool-denial item do not "
        "satisfy Gate 0."
    )
    _write_json(FIXTURES / "official-contract.json", contract)


def capture(
    auth_source: Path,
    *,
    probe_isolation_only: bool = False,
    resume_incomplete: bool = False,
    latest_mcp_only: bool = False,
) -> None:
    if platform.system() != "Darwin" or platform.machine() != "arm64":
        raise RuntimeError(
            "this recorded capture requires the reviewed macOS arm64 + Linux "
            "aarch64 container path; no unsafe fallback exists"
        )
    if not auth_source.is_file():
        raise RuntimeError(
            "Codex authentication is unavailable; trusted Gate 0 remains red"
        )
    with tempfile.TemporaryDirectory(prefix="palonexus-codex-gate0-") as raw_temp:
        temp = Path(raw_temp)
        safe_home = temp / "download-home"
        safe_home.mkdir()
        env = _safe_environment(safe_home, temp)
        base_image_id = _pull_and_inspect_base()
        contract = _official_contract(temp, env)

        auth = temp / "auth.json"
        shutil.copyfile(auth_source, auth)
        auth.chmod(0o444)
        auth_digest_before = _sha256_file(auth)

        local_executable = Path(shutil.which("codex") or "")
        local_version_result = subprocess.run(
            [str(local_executable), "--version"],
            text=True,
            capture_output=True,
            check=False,
            timeout=30,
        )
        if (
            not local_executable.is_file()
            or local_version_result.returncode
            or LATEST_VERSION not in local_version_result.stdout
        ):
            raise RuntimeError("installed Codex candidate is not exact 0.145.0")

        binaries: dict[str, Path] = {}
        binary_details: dict[str, dict[str, Any]] = {}
        for role, release in RELEASES.items():
            archive = temp / f"codex-{role}.tar.gz"
            archive_bytes = _download(release["archiveUrl"], archive, env=env)
            archive_hash = _sha256_bytes(archive_bytes)
            if archive_hash != release["archiveSha256"]:
                raise RuntimeError(f"{role} Codex release integrity mismatch")
            extract = temp / f"codex-{role}"
            extract.mkdir()
            binary = _extract_codex(archive, extract)
            binaries[role] = binary
            probe_bundle = temp / f"probe-{role}" / "fixture"
            probe_output = temp / f"probe-{role}" / "output"
            probe_work = temp / f"probe-{role}" / "work"
            probe_output.mkdir(parents=True)
            probe_work.mkdir(parents=True)
            probe_output.chmod(0o777)
            probe_work.chmod(0o777)
            _prepare_bundle(
                probe_bundle,
                run={
                    "approvalId": APPROVAL_ID,
                    "expectedInput": {"command": "printf probe"},
                    "family": "bash",
                    "inputFingerprint": canonical_sha256({"command": "printf probe"}),
                    "nonce": f"probe-{role}",
                    "scenario": "noop",
                    "sentinelPath": f"/work/sentinel-probe-{role}",
                    "toolName": "Bash",
                },
                with_pretool_hook=False,
            )
            observed_version = _container_version(
                binary=binary,
                fixture_bundle=probe_bundle,
                output=probe_output,
                workspace=probe_work,
                auth=auth,
            )
            if observed_version != release["version"]:
                raise RuntimeError(
                    f"{role} binary version mismatch: {observed_version}"
                )
            _run_canary(
                binary=binary,
                fixture_bundle=probe_bundle,
                output=probe_output,
                workspace=probe_work,
                auth=auth,
            )
            binary_details[role] = {
                "version": release["version"],
                "archiveUrl": release["archiveUrl"],
                "archiveSha256": archive_hash,
                "officialArchiveSha256": release["archiveSha256"],
                "executableSha256": _sha256_file(binary),
                "tagCommit": release["tagCommit"],
                "tested": True,
            }

        all_evidence: dict[str, Any] = {}
        payload_fixtures: dict[str, dict[str, Any]] = {}
        if resume_incomplete:
            _persist_prior_minimum_mcp_unavailable()
        ordinal = 0
        roles = ("latest",) if latest_mcp_only else ("minimum", "latest")
        for role in roles:
            role_families = (
                ("mcp",)
                if latest_mcp_only
                else (
                    ("bash", "apply_patch")
                    if resume_incomplete and role == "minimum"
                    else tuple(REQUIRED_FAMILIES)
                )
            )
            version_evidence: dict[str, Any] = {
                "trusted": True,
                "modelDriven": True,
                "isolated": True,
                "version": RELEASES[role]["version"],
                "toolFamilies": sorted(role_families),
                "blockingScenarios": {},
            }
            if resume_incomplete and role == "minimum":
                version_evidence["unverifiedToolFamilies"] = {
                    "mcp": (
                        "The single forced attempt reported that the fixture MCP "
                        "tool was unavailable; it was not retried."
                    )
                }
            preservation: dict[str, Any] = {}
            native_outcomes = (
                ()
                if latest_mcp_only
                else (
                    ("native_allow", False),
                    ("native_deny", True),
                )
            )
            for outcome, native_deny in native_outcomes:
                ordinal += 1
                baseline = _run_case(
                    temp=temp,
                    binary=binaries[role],
                    auth=auth,
                    role=role,
                    family="bash",
                    scenario=f"baseline_{outcome}",
                    ordinal=ordinal,
                    with_pretool_hook=False,
                    native_deny=native_deny,
                )
                if baseline["evidence"]["sentinelExistsAfter"] is native_deny:
                    raise RuntimeError(
                        f"native {outcome} baseline did not produce its expected "
                        f"effect state for {role}\n{baseline['debug']}"
                    )
                _persist_cell(
                    role=role,
                    family="bash",
                    cell=f"{outcome}_baseline",
                    evidence=baseline["evidence"],
                )
                if probe_isolation_only:
                    print(
                        "outer isolation canaries and one model-driven baseline passed",
                        flush=True,
                    )
                    return
                ordinal += 1
                noop = _run_case(
                    temp=temp,
                    binary=binaries[role],
                    auth=auth,
                    role=role,
                    family="bash",
                    scenario="noop",
                    ordinal=ordinal,
                    with_pretool_hook=True,
                    native_deny=native_deny,
                )
                _persist_cell(
                    role=role,
                    family="bash",
                    cell=f"{outcome}_noop",
                    evidence=noop["evidence"],
                )
                for key in (
                    "toolExecuted",
                    "sentinelExistsAfter",
                    "renderedOutcome",
                ):
                    if baseline["evidence"][key] != noop["evidence"][key]:
                        raise RuntimeError(
                            f"empty hook changed {outcome} behavior for {role}"
                        )
                preservation[outcome] = {
                    "trusted": True,
                    "baseline": baseline["evidence"],
                    "noopHook": noop["evidence"],
                }
                if outcome == "native_allow" and role == "latest":
                    assert noop["payload"] is not None
                    payload_fixtures["bash"] = noop["payload"]
            version_evidence["nativePermissionPreservation"] = preservation

            for family in role_families:
                family_scenarios: dict[str, Any] = {}
                if family != "bash":
                    if family == "mcp":
                        registration = _container_mcp_registration(
                            binary=binaries[role],
                            fixture_bundle=probe_bundle,
                            output=probe_output,
                            workspace=probe_work,
                            auth=auth,
                        )
                        version_evidence["mcpRegistrationPreflight"] = registration
                    ordinal += 1
                    noop_capture = _run_case(
                        temp=temp,
                        binary=binaries[role],
                        auth=auth,
                        role=role,
                        family=family,
                        scenario="noop",
                        ordinal=ordinal,
                        with_pretool_hook=True,
                        allow_mcp_discovery=(family == "mcp" and role == "latest"),
                    )
                    _persist_cell(
                        role=role,
                        family=family,
                        cell="noop",
                        evidence=noop_capture["evidence"],
                    )
                    if not noop_capture["evidence"]["sentinelExistsAfter"]:
                        raise RuntimeError(
                            f"no-op hook did not permit {family} on {role}"
                        )
                    if role == "latest":
                        assert noop_capture["payload"] is not None
                        payload_fixtures[family] = noop_capture["payload"]
                for scenario in REQUIRED_SCENARIOS:
                    ordinal += 1
                    case = _run_case(
                        temp=temp,
                        binary=binaries[role],
                        auth=auth,
                        role=role,
                        family=family,
                        scenario=scenario,
                        ordinal=ordinal,
                        with_pretool_hook=True,
                        allow_mcp_discovery=(family == "mcp" and role == "latest"),
                    )
                    family_scenarios[scenario] = case["evidence"]
                    _persist_cell(
                        role=role,
                        family=family,
                        cell=scenario,
                        evidence=case["evidence"],
                    )
                version_evidence["blockingScenarios"][family] = family_scenarios
            all_evidence[role] = version_evidence

        if latest_mcp_only:
            payload = payload_fixtures.get("mcp")
            if payload is None:
                raise RuntimeError("latest MCP payload was not captured")
            payload["capture"] = {
                "trusted": True,
                "role": "latest",
                "version": LATEST_VERSION,
                "hookInvocationCount": 1,
                "inputFingerprint": canonical_sha256(payload["tool_input"]),
            }
            _write_json(FIXTURES / "pretooluse" / "mcp.json", payload)
            print("latest MCP cells captured and persisted", flush=True)
            return

        if set(payload_fixtures) != set(REQUIRED_FAMILIES):
            raise RuntimeError("trusted payload fixture matrix is incomplete")
        for family, payload in payload_fixtures.items():
            payload["capture"] = {
                "trusted": True,
                "role": "latest",
                "version": LATEST_VERSION,
                "hookInvocationCount": 1,
                "inputFingerprint": canonical_sha256(payload["tool_input"]),
            }
            _write_json(FIXTURES / "pretooluse" / f"{family}.json", payload)
        for role, version_evidence in all_evidence.items():
            for family, scenarios in version_evidence["blockingScenarios"].items():
                for scenario, evidence in scenarios.items():
                    _write_json(
                        FIXTURES / "scenarios" / role / family / f"{scenario}.json",
                        evidence,
                    )

        auth_digest_after = _sha256_file(auth)
        if auth_digest_before != auth_digest_after:
            raise RuntimeError("read-only auth source changed during capture")

        gate_complete = not resume_incomplete
        capabilities = {
            "gateComplete": gate_complete,
            "claimedToolFamilies": (
                sorted(REQUIRED_FAMILIES) if gate_complete else ["apply_patch", "bash"]
            ),
            "unsupportedToolFamilies": {
                "hosted": [
                    "WebSearch",
                    "hosted connectors",
                    "other server-executed tools",
                ],
                "specialized": [
                    "specialized handlers that opt out of the local function-tool "
                    "hook path"
                ],
            },
            "testedVersions": all_evidence,
        }
        if not gate_complete:
            capabilities["unverifiedCells"] = {
                "minimum/mcp": (
                    "The one forced Codex 0.124.0 model attempt reported the "
                    "registered fixture MCP tool unavailable; no retry was made."
                )
            }
        _write_json(FIXTURES / "expected-capabilities.json", capabilities)
        if not gate_complete:
            contract["releaseEvidence"]["minimumVersion"] = None
            contract["releaseEvidence"]["minimumTested"] = False
            contract["releaseEvidence"]["basis"] = (
                "0.124.0 has trusted Bash and apply_patch evidence, but its one "
                "forced MCP attempt was unavailable. Exact minimum remains "
                "unresolved."
            )
            contract["blockingSemantics"]["approvalRequiredRenderedAsDeny"] = True
            contract["blockingSemantics"]["exit2"] = True
            contract["blockingSemantics"]["noopPreservesNativePermissions"] = True
            contract["blockingSemantics"]["structuredDeny"] = True
        _write_json(FIXTURES / "official-contract.json", contract)
        host = {
            "gateComplete": gate_complete,
            "candidate": {
                "version": LATEST_VERSION,
                "tested": True,
                "executable": "/usr/local/bin/codex",
                "packageOrigin": RELEASES["latest"]["archiveUrl"],
                "executableSha256": binary_details["latest"]["executableSha256"],
                "archiveSha256": binary_details["latest"]["archiveSha256"],
                "officialArchiveSha256": RELEASES["latest"]["archiveSha256"],
                "os": "linux",
                "arch": "aarch64",
            },
            "localInstalledCandidate": {
                "version": LATEST_VERSION,
                "executable": "/opt/homebrew/bin/codex",
                "executableSha256": _sha256_file(local_executable),
                "packageOrigin": "Homebrew Cask codex",
                "os": "darwin",
                "arch": "arm64",
            },
            "minimumSupported": {
                **binary_details["minimum"],
                "status": "established" if gate_complete else "unresolved",
                "version": MINIMUM_VERSION if gate_complete else None,
                "tested": gate_complete,
            },
            "latestStable": binary_details["latest"],
            "captureAttempts": [
                {
                    "role": role,
                    "version": RELEASES[role]["version"],
                    "trusted": True,
                    "modelDriven": True,
                    "network": "bridge",
                    "containerUser": "10001:10001",
                    "readOnlyRoot": True,
                    "capDrop": "ALL",
                    "noNewPrivileges": True,
                    "workspaceIsDisposable": True,
                    "sourceWorkspaceMounted": False,
                    "authMountReadOnly": True,
                    "authDigestVerified": True,
                    "authDigestUnchanged": True,
                    "baseImage": BASE_IMAGE,
                    "baseImageId": base_image_id,
                    "coverageComplete": (gate_complete or role == "latest"),
                }
                for role in ("minimum", "latest")
            ],
        }
        _write_json(FIXTURES / "host-version.json", host)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--auth",
        type=Path,
        default=Path.home() / ".codex" / "auth.json",
        help="Read-only source Codex authentication file; never persisted.",
    )
    parser.add_argument(
        "--latest-mcp-only",
        action="store_true",
        help=(
            "Run the corrected latest MCP discovery plus exact tool matrix only; "
            "persist its cells without retrying any other family."
        ),
    )
    parser.add_argument(
        "--resume-incomplete",
        action="store_true",
        help=(
            "Replay trusted minimum Bash/apply cells, preserve the prior minimum "
            "MCP-unavailable result without retry, then run the latest matrix."
        ),
    )
    parser.add_argument(
        "--probe-isolation-only",
        action="store_true",
        help="Run outer canaries and one minimum-host model-driven Bash baseline.",
    )
    parser.add_argument(
        "--finalize-incomplete",
        action="store_true",
        help="Assemble trusted persisted cells without making a complete-gate claim.",
    )
    parser.add_argument(
        "--capture-receipts",
        action="store_true",
        help=(
            "Capture the bounded receipt matrix for 0.124.0, the evidence-guided "
            "next candidate, and latest stable."
        ),
    )
    parser.add_argument(
        "--finalize-receipts",
        action="store_true",
        help="Rebuild all public summaries from persisted receipt bundles.",
    )
    args = parser.parse_args()
    if args.capture_receipts:
        capture_receipt_matrix(args.auth.expanduser().resolve())
        print("Codex receipt matrix captured; run receipt finalization next")
        return 0
    if args.finalize_receipts:
        finalize_receipt_fixtures()
        print("Receipt-derived Codex fixtures finalized")
        return 0
    if args.finalize_incomplete:
        finalize_incomplete_fixtures()
        print("trusted partial Codex fixtures finalized; Gate 0 remains incomplete")
        return 0
    capture(
        args.auth.expanduser().resolve(),
        probe_isolation_only=args.probe_isolation_only,
        resume_incomplete=args.resume_incomplete,
        latest_mcp_only=args.latest_mcp_only,
    )
    if args.probe_isolation_only:
        print("Codex Gate 0 isolation probe completed; fixture gate remains unchanged")
    else:
        print(f"Codex Gate 0 captured into {FIXTURES}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
