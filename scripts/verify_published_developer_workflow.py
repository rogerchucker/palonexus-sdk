#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
import json
import re
import subprocess
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit


class VerificationError(RuntimeError):
    """The published CLI did not produce the reviewed developer workflow."""


def run_checked(
    argv: list[str], cwd: Path | None = None
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        argv,
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        raise VerificationError(f"command failed: {argv[0]}")
    return result


def _object(raw: str, label: str) -> dict[str, Any]:
    def reject_duplicate(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise VerificationError(f"{label} contains duplicate fields")
            value[key] = item
        return value

    try:
        parsed = json.loads(raw, object_pairs_hook=reject_duplicate)
    except (json.JSONDecodeError, TypeError) as error:
        raise VerificationError(f"{label} is not strict JSON") from error
    if not isinstance(parsed, dict):
        raise VerificationError(f"{label} is not an object")
    return parsed


def verify_published_workflow(
    *, expected_version: str, expected_revision: str, pnxs: Path, workspace: Path
) -> None:
    if not expected_version or not re.fullmatch(
        r"[0-9A-Za-z][0-9A-Za-z.+!_-]*", expected_version
    ):
        raise VerificationError("expected version is invalid")
    if not re.fullmatch(r"[0-9a-f]{40}", expected_revision):
        raise VerificationError("expected revision is invalid")
    if workspace.exists():
        raise VerificationError("workspace must not already exist")
    workspace.mkdir(mode=0o700, parents=True)

    version = _object(
        run_checked([str(pnxs), "version", "--json"]).stdout, "version response"
    )
    if version != {
        "version": expected_version,
        "source_revision": expected_revision,
    }:
        raise VerificationError("installed release identity does not match publication")

    project = workspace / "release-risk-reviewer"
    run_checked(
        [
            str(pnxs),
            "agents",
            "init",
            str(project),
            "--name",
            "release-risk-reviewer",
            "--allow-file-credential-store",
        ]
    )
    pyproject = tomllib.loads((project / "pyproject.toml").read_text(encoding="utf-8"))
    if pyproject.get("project", {}).get("dependencies") != [
        f"palonexus=={expected_version}"
    ]:
        raise VerificationError("generated project does not pin the installed release")
    if pyproject.get("tool", {}).get("uv", {}).get("sources") is not None:
        raise VerificationError("generated project contains a local source override")
    if (project / ".pnxs").exists() or list(project.rglob("*.whl")):
        raise VerificationError("generated project contains a local SDK artifact")

    lock = tomllib.loads((project / "uv.lock").read_text(encoding="utf-8"))
    packages = [
        item
        for item in lock.get("package", [])
        if isinstance(item, dict) and item.get("name") == "palonexus"
    ]
    if len(packages) != 1 or packages[0].get("version") != expected_version:
        raise VerificationError("lock does not contain the exact published release")
    source = packages[0].get("source")
    registry = source.get("registry") if isinstance(source, dict) else None
    parsed = urlsplit(registry) if isinstance(registry, str) else None
    if (
        parsed is None
        or parsed.scheme != "https"
        or parsed.hostname not in {"pypi.org", "test.pypi.org"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise VerificationError(
            "lock does not resolve palonexus from the selected index"
        )

    run_checked(["uv", "sync", "--frozen"], cwd=project)
    run_checked(
        [
            "uv",
            "run",
            "--frozen",
            "python",
            "-c",
            "import palonexus; import agent",
        ],
        cwd=project,
    )
    run_checked(
        ["uv", "run", "--frozen", "python", "-m", "compileall", "-q", "agent.py"],
        cwd=project,
    )


def main() -> int:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("--pnxs", required=True, type=Path)
    parser.add_argument("--workspace", required=True, type=Path)
    args = parser.parse_args()
    try:
        verify_published_workflow(
            expected_version=args.expected_version,
            expected_revision=args.expected_revision,
            pnxs=args.pnxs,
            workspace=args.workspace,
        )
    except (OSError, VerificationError, tomllib.TOMLDecodeError) as error:
        print(f"FAIL: {error}")
        return 1
    print("PALONEXUS_PUBLISHED_DEVELOPER_WORKFLOW_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
