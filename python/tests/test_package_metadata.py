# SPDX-License-Identifier: MIT
"""Distribution metadata and artifact-boundary contracts."""

from __future__ import annotations

import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).parents[2]
PACKAGE = ROOT / "python"
PUBLIC_REPOSITORY = "https://github.com/rogerchucker/palonexus-sdk"


def _project() -> dict[str, Any]:
    document = tomllib.loads((PACKAGE / "pyproject.toml").read_text(encoding="utf-8"))
    return cast(dict[str, Any], document["project"])


def test_distribution_declares_mit_license_and_public_project_urls() -> None:
    project = _project()

    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert "License :: OSI Approved :: MIT License" in project["classifiers"]
    assert project["urls"] == {
        "Homepage": PUBLIC_REPOSITORY,
        "Repository": PUBLIC_REPOSITORY,
        "Documentation": f"{PUBLIC_REPOSITORY}#readme",
        "Issues": f"{PUBLIC_REPOSITORY}/issues",
        "Changelog": f"{PUBLIC_REPOSITORY}/blob/main/CHANGELOG.md",
    }


def test_distribution_declares_supported_framework_extras() -> None:
    extras = cast(dict[str, list[str]], _project()["optional-dependencies"])

    assert set(extras) == {"langchain", "langgraph", "deepagents"}
    assert any(item.startswith("langchain-core") for item in extras["langchain"])
    assert any(item.startswith("langgraph") for item in extras["langgraph"])
    assert any(item.startswith("deepagents") for item in extras["deepagents"])


def test_distribution_ships_pep561_marker() -> None:
    marker = PACKAGE / "src/palonexus/py.typed"

    assert marker.is_file()
    assert marker.read_text(encoding="utf-8") == "# SPDX-License-Identifier: MIT\n"


def test_artifacts_contain_only_the_python_distribution_boundary(
    tmp_path: Path,
) -> None:
    result = subprocess.run(
        [
            "uv",
            "build",
            "--package",
            "palonexus",
            "--out-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr

    [wheel] = tmp_path.glob("palonexus-*.whl")
    [sdist] = tmp_path.glob("palonexus-*.tar.gz")
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = archive.namelist()
    with tarfile.open(sdist, "r:gz") as archive:
        sdist_members = [member.name for member in archive.getmembers()]

    assert "palonexus/py.typed" in wheel_members
    assert all(name.startswith(("palonexus/", "palonexus-")) for name in wheel_members)
    forbidden_roots = (
        "guard/",
        "plugins/",
        "protocol/",
        "examples/",
        "foundation_tests/",
        "tests/",
    )
    assert not any(
        any(f"/{root}" in name for root in forbidden_roots) for name in sdist_members
    )


def test_clean_room_artifact_verifier_and_python_ci_are_present() -> None:
    verifier = ROOT / "scripts/verify_python_artifacts.py"
    workflow = ROOT / ".github/workflows/python.yml"

    assert verifier.is_file()
    assert workflow.is_file()
    workflow_text = workflow.read_text(encoding="utf-8")
    assert '"3.12"' in workflow_text
    assert '"3.13"' in workflow_text
    assert "verify_python_artifacts.py" in workflow_text
