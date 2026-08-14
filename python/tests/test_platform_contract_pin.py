# SPDX-License-Identifier: MIT
"""Release contracts tying SDK artifacts to canonical platform schemas."""

from __future__ import annotations

import email
import json
import os
import re
import subprocess
import sys
import tomllib
import zipfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any, cast

import pytest
import yaml

ROOT = Path(__file__).parents[2]
PACKAGE = ROOT / "python"
PIN = ROOT / "contracts/platform-contract-sha.txt"
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
CONTRACT_VERIFIER = ROOT / "scripts/verify_platform_contracts.py"
BUILD_METADATA_PREFIX = "platform-contract-sha:"
SCHEMA_PATH = "contracts/developer/action.schema.json"


def _platform_sha() -> str:
    value = PIN.read_text(encoding="ascii")
    assert re.fullmatch(r"[0-9a-f]{40}\n", value)
    return value.rstrip("\n")


def _project() -> dict[str, Any]:
    document = tomllib.loads((PACKAGE / "pyproject.toml").read_text(encoding="utf-8"))
    return cast(dict[str, Any], document["project"])


def _workflow() -> dict[str, Any]:
    value = yaml.load(
        RELEASE_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader
    )
    assert isinstance(value, dict)
    return value


def _contract_fixture(
    tmp_path: Path,
    *,
    listed: list[str],
    sdk_files: Mapping[str, bytes],
    platform_files: Mapping[str, bytes],
) -> tuple[Path, Path]:
    sdk_root = tmp_path / "sdk"
    platform_root = tmp_path / "platform"
    (sdk_root / "python").mkdir(parents=True)
    platform_root.mkdir()
    rendered_paths = ", ".join(json.dumps(path) for path in listed)
    (sdk_root / "python/pyproject.toml").write_text(
        f"[tool.palonexus.platform-contract]\nschema-paths = [{rendered_paths}]\n",
        encoding="utf-8",
    )
    for root, files in ((sdk_root, sdk_files), (platform_root, platform_files)):
        for relative_path, content in files.items():
            path = root / relative_path
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    return sdk_root, platform_root


def _run_contract_verifier(
    sdk_root: Path, platform_root: Path
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            sys.executable,
            str(CONTRACT_VERIFIER),
            "--sdk-root",
            str(sdk_root),
            "--platform-root",
            str(platform_root),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_wheel_metadata_records_the_platform_contract_not_its_own_digest(
    tmp_path: Path,
) -> None:
    platform_sha = _platform_sha()
    result = subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(tmp_path), str(PACKAGE)],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    [wheel] = tmp_path.glob("palonexus-*.whl")
    with zipfile.ZipFile(wheel) as archive:
        [metadata_name] = [
            name for name in archive.namelist() if name.endswith(".dist-info/METADATA")
        ]
        metadata = email.message_from_bytes(archive.read(metadata_name))

    assert metadata["Keywords"] == f"{BUILD_METADATA_PREFIX}{platform_sha}"
    assert (
        "wheel-sha"
        not in (PACKAGE / "pyproject.toml").read_text(encoding="utf-8").lower()
    )


def test_release_verifies_reviewed_mirror_without_private_repo_credentials() -> None:
    platform_sha = _platform_sha()
    project = _project()
    workflow = _workflow()
    verify = workflow["jobs"]["verify"]
    steps = verify["steps"]
    assert isinstance(steps, list)

    resolve = next(step for step in steps if step.get("id") == "platform-contract")
    contract_tests = next(
        step for step in steps if step.get("name") == "Run SDK contract tests"
    )
    complete_suite = next(
        step
        for step in steps
        if step.get("name") == "Run the complete verification suite"
    )

    assert project["keywords"] == [f"{BUILD_METADATA_PREFIX}{platform_sha}"]
    assert "contracts/platform-contract-sha.txt" in resolve["run"]
    assert not any(
        step.get("with", {}).get("repository") == "rogerchucker/palonexus-platform"
        for step in steps
    )
    assert "uv run --frozen python -m pytest" in contract_tests["run"]
    assert complete_suite["run"] == "scripts/verify"
    assert (
        steps.index(resolve) < steps.index(contract_tests) < steps.index(complete_suite)
    )

    publish = workflow["jobs"]["publish"]
    assert publish["needs"] == ["verify"]
    publish_steps = publish["steps"]
    build = next(
        step
        for step in publish_steps
        if step.get("name") == "Build the wheel and sdist"
    )
    upload = next(
        step
        for step in publish_steps
        if step.get("name") == "Publish with Trusted Publishing"
    )
    assert build["run"] == "uv build --out-dir dist python"
    assert publish_steps.index(build) < publish_steps.index(upload)


def test_release_verifies_fresh_exact_install_after_publish() -> None:
    workflow = _workflow()
    publish = workflow["jobs"]["publish"]
    assert publish["outputs"] == {
        "version": "${{ steps.built-version.outputs.version }}"
    }
    resolve = next(
        step for step in publish["steps"] if step.get("id") == "built-version"
    )
    assert "version=$built" in resolve["run"]

    fresh = workflow["jobs"]["verify-published"]
    assert fresh["needs"] == ["publish"]
    assert fresh["env"]["EXPECTED_VERSION"] == "${{ needs.publish.outputs.version }}"
    assert fresh["env"]["EXPECTED_REVISION"] == "${{ github.sha }}"
    run = "\n".join(
        str(step.get("run", "")) for step in fresh["steps"] if "run" in step
    )
    for required in (
        "HOME=",
        "UV_TOOL_DIR=",
        "UV_TOOL_BIN_DIR=",
        "UV_CACHE_DIR=",
        "UV_NO_CONFIG=1",
        "/pypi/palonexus/${EXPECTED_VERSION}/json",
        "uv tool install",
        "--no-config",
        "--index-strategy first-index",
        "palonexus==${EXPECTED_VERSION}",
        "verify_published_developer_workflow.py",
    ):
        assert required in run
    assert "https://test.pypi.org/simple" in run
    assert "https://pypi.org/simple" in run


@pytest.mark.parametrize(
    ("listed", "sdk_files", "platform_files"),
    (
        ([], {}, {}),
        (
            [SCHEMA_PATH],
            {SCHEMA_PATH: b'{"title":"action"}\n'},
            {SCHEMA_PATH: b'{"title":"action"}\n'},
        ),
        (
            [
                "contracts/developer/action.schema.json",
                "contracts/developer/action/v1.schema.json",
            ],
            {
                "contracts/developer/action.schema.json": b"top-level\n",
                "contracts/developer/action/v1.schema.json": b"nested\n",
            },
            {
                "contracts/developer/action.schema.json": b"top-level\n",
                "contracts/developer/action/v1.schema.json": b"nested\n",
            },
        ),
    ),
    ids=("empty-contract", "exact-populated-contract", "mixed-depth-lexical-order"),
)
def test_platform_contract_verifier_accepts_exact_sets_and_bytes(
    tmp_path: Path,
    listed: list[str],
    sdk_files: Mapping[str, bytes],
    platform_files: Mapping[str, bytes],
) -> None:
    sdk_root, platform_root = _contract_fixture(
        tmp_path,
        listed=listed,
        sdk_files=sdk_files,
        platform_files=platform_files,
    )

    result = _run_contract_verifier(sdk_root, platform_root)

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("listed", "sdk_files", "platform_files", "message"),
    (
        (
            [],
            {},
            {SCHEMA_PATH: b"canonical\n"},
            "schema path sets differ",
        ),
        (
            [SCHEMA_PATH],
            {SCHEMA_PATH: b"mirror\n"},
            {},
            "schema path sets differ",
        ),
        (
            [SCHEMA_PATH],
            {SCHEMA_PATH: b"mirror\n"},
            {SCHEMA_PATH: b"canonical\n"},
            "schema bytes differ",
        ),
        (
            [SCHEMA_PATH, SCHEMA_PATH],
            {SCHEMA_PATH: b"same\n"},
            {SCHEMA_PATH: b"same\n"},
            "schema paths must be sorted and unique",
        ),
        (
            ["contracts/developer/../escape.schema.json"],
            {},
            {},
            "unsafe schema path",
        ),
    ),
    ids=(
        "canonical-only",
        "mirror-and-list-only",
        "byte-mismatch",
        "duplicate-list-entry",
        "unsafe-list-entry",
    ),
)
def test_platform_contract_verifier_fails_closed(
    tmp_path: Path,
    listed: list[str],
    sdk_files: Mapping[str, bytes],
    platform_files: Mapping[str, bytes],
    message: str,
) -> None:
    sdk_root, platform_root = _contract_fixture(
        tmp_path,
        listed=listed,
        sdk_files=sdk_files,
        platform_files=platform_files,
    )

    result = _run_contract_verifier(sdk_root, platform_root)

    assert result.returncode != 0
    assert message in result.stderr


@pytest.mark.parametrize("role", ("sdk", "platform"))
def test_platform_contract_verifier_rejects_nested_directory_symlink(
    tmp_path: Path, role: str
) -> None:
    sdk_root, platform_root = _contract_fixture(
        tmp_path, listed=[], sdk_files={}, platform_files={}
    )
    selected_root = sdk_root if role == "sdk" else platform_root
    schema_root = selected_root / "contracts/developer"
    schema_root.mkdir(parents=True)
    external = tmp_path / f"external-{role}"
    external.mkdir()
    (schema_root / "nested").symlink_to(external, target_is_directory=True)

    result = _run_contract_verifier(sdk_root, platform_root)

    assert result.returncode != 0
    assert "symlink" in result.stderr


@pytest.mark.parametrize("role", ("sdk", "platform"))
def test_platform_contract_verifier_rejects_ancestor_symlink(
    tmp_path: Path, role: str
) -> None:
    sdk_root, platform_root = _contract_fixture(
        tmp_path, listed=[], sdk_files={}, platform_files={}
    )
    selected_root = sdk_root if role == "sdk" else platform_root
    external = tmp_path / f"external-{role}"
    (external / "developer").mkdir(parents=True)
    (selected_root / "contracts").symlink_to(external, target_is_directory=True)

    result = _run_contract_verifier(sdk_root, platform_root)

    assert result.returncode != 0
    assert "symlink" in result.stderr


@pytest.mark.parametrize("role", ("sdk", "platform"))
def test_platform_contract_verifier_rejects_dangling_schema_root_symlink(
    tmp_path: Path, role: str
) -> None:
    sdk_root, platform_root = _contract_fixture(
        tmp_path, listed=[], sdk_files={}, platform_files={}
    )
    selected_root = sdk_root if role == "sdk" else platform_root
    contracts = selected_root / "contracts"
    contracts.mkdir()
    (contracts / "developer").symlink_to(tmp_path / f"missing-{role}")

    result = _run_contract_verifier(sdk_root, platform_root)

    assert result.returncode != 0
    assert "symlink" in result.stderr


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO creation is unavailable")
@pytest.mark.parametrize("role", ("sdk", "platform"))
def test_platform_contract_verifier_rejects_special_schema_entry(
    tmp_path: Path, role: str
) -> None:
    sdk_root, platform_root = _contract_fixture(
        tmp_path, listed=[], sdk_files={}, platform_files={}
    )
    selected_root = sdk_root if role == "sdk" else platform_root
    schema_root = selected_root / "contracts/developer"
    schema_root.mkdir(parents=True)
    os.mkfifo(schema_root / "special.schema.json")

    result = _run_contract_verifier(sdk_root, platform_root)

    assert result.returncode != 0
    assert "regular file" in result.stderr


def test_release_runs_the_sdk_contract_tests() -> None:
    verify = _workflow()["jobs"]["verify"]
    contract_tests = next(
        step for step in verify["steps"] if step.get("name") == "Run SDK contract tests"
    )

    assert "test_*contract*.py" in contract_tests["run"]
    assert "uv run --frozen python -m pytest" in contract_tests["run"]
