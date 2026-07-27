# SPDX-License-Identifier: MIT
"""Distribution metadata and artifact-boundary contracts."""

from __future__ import annotations

import io
import shutil
import stat
import subprocess
import tarfile
import tomllib
import warnings
import zipfile
from pathlib import Path
from typing import Any, cast

import pytest
from packaging.version import Version

from scripts import verify_python_artifacts

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
    assert extras["langchain"] == [
        "langchain>=1,<2",
        "langchain-core>=1,<2",
        "langgraph>=1,<2",
    ]
    assert extras["langgraph"] == [
        "langchain-core>=1,<2",
        "langgraph>=1,<2",
        "langgraph-checkpoint-sqlite>=3,<4",
    ]
    assert extras["deepagents"] == [
        "deepagents>=0.3,<1",
        "langchain>=1,<2",
        "langchain-core>=1,<2",
        "langgraph>=1,<2",
    ]


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
    assert "--expected-version" in workflow_text


def test_gitless_source_tree_cannot_silently_build_version_zero(
    tmp_path: Path,
) -> None:
    copied_package = tmp_path / "python"
    shutil.copytree(PACKAGE, copied_package)
    result = subprocess.run(
        ["uv", "build", str(copied_package), "--out-dir", str(tmp_path / "dist")],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode != 0
    assert "0.0.0" not in "\n".join(path.name for path in (tmp_path / "dist").glob("*"))


@pytest.mark.parametrize("expected", ("0.0.0", "9.9.9"))
def test_verifier_rejects_fallback_or_mismatched_expected_version(
    expected: str,
) -> None:
    result = subprocess.run(
        [
            "uv",
            "run",
            "--frozen",
            "--no-sync",
            "python",
            "scripts/verify_python_artifacts.py",
            "--expected-version",
            expected,
        ],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )

    assert result.returncode != 0
    assert (
        "fallback version is forbidden" in result.stderr
        if expected == "0.0.0"
        else "version mismatch" in result.stderr
    )


def _zip_member(name: str, *, mode: int = stat.S_IFREG | 0o644) -> zipfile.ZipInfo:
    member = zipfile.ZipInfo(name)
    member.create_system = 3
    member.external_attr = mode << 16
    return member


@pytest.mark.parametrize(
    "members",
    (
        ("palonexus/value.py", "palonexus/./value.py"),
        ("palonexus/value.py", "palonexus/value.py"),
        ("palonexus\\value.py",),
        ("palonexus/../value.py",),
        ("C:/palonexus/value.py",),
        ("outside.py",),
    ),
)
def test_wheel_rejects_duplicate_and_non_posix_member_names(
    tmp_path: Path,
    members: tuple[str, ...],
) -> None:
    wheel = tmp_path / "malicious.whl"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(wheel, "w") as archive:
            archive.writestr(_zip_member("palonexus/py.typed"), b"")
            for name in members:
                archive.writestr(_zip_member(name), b"value")

    with pytest.raises(RuntimeError):
        verify_python_artifacts._verify_wheel(wheel)


@pytest.mark.parametrize("mode", (stat.S_IFLNK | 0o777, stat.S_IFIFO | 0o644))
def test_wheel_rejects_symlink_and_special_file_modes(
    tmp_path: Path,
    mode: int,
) -> None:
    wheel = tmp_path / "malicious.whl"
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(_zip_member("palonexus/py.typed"), b"")
        archive.writestr(_zip_member("palonexus/value", mode=mode), b"value")

    with pytest.raises(RuntimeError):
        verify_python_artifacts._verify_wheel(wheel)


@pytest.mark.parametrize(
    ("names", "special_type"),
    (
        (("root/src/palonexus/value.py", "root/src/palonexus/./value.py"), None),
        (("root/src/palonexus/value.py", "root/src/palonexus/value.py"), None),
        (("root/src/palonexus\\value.py",), None),
        (("root/src/palonexus/../../value.py",), None),
        (("C:/root/src/palonexus/value.py",), None),
        (("root/src/palonexus/value",), tarfile.FIFOTYPE),
    ),
)
def test_sdist_rejects_duplicate_non_posix_and_special_members(
    tmp_path: Path,
    names: tuple[str, ...],
    special_type: bytes | None,
) -> None:
    sdist = tmp_path / "malicious.tar.gz"
    with tarfile.open(sdist, "w:gz") as archive:
        marker = tarfile.TarInfo("root/src/palonexus/py.typed")
        marker.size = 0
        archive.addfile(marker, io.BytesIO())
        for name in names:
            member = tarfile.TarInfo(name)
            payload = b"value"
            if special_type is not None:
                member.type = special_type
                member.size = 0
                archive.addfile(member)
            else:
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))

    with pytest.raises(RuntimeError):
        verify_python_artifacts._verify_sdist(sdist)


@pytest.mark.parametrize("mismatch", ("metadata", "generated"))
def test_wheel_rejects_internal_version_mismatch(
    tmp_path: Path,
    mismatch: str,
) -> None:
    expected = Version("1.2.3")
    wheel = tmp_path / "palonexus-1.2.3-py3-none-any.whl"
    metadata_version = "9.9.9" if mismatch == "metadata" else str(expected)
    generated_version = "9.9.9" if mismatch == "generated" else str(expected)
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(_zip_member("palonexus/py.typed"), b"")
        archive.writestr(
            _zip_member("palonexus/_version.py"),
            f"__version__ = version = '{generated_version}'\n".encode(),
        )
        archive.writestr(
            _zip_member("palonexus-1.2.3.dist-info/METADATA"),
            (
                f"Metadata-Version: 2.4\nName: palonexus\nVersion: {metadata_version}\n"
            ).encode(),
        )

    with pytest.raises(RuntimeError, match="version mismatch"):
        verify_python_artifacts._verify_wheel(wheel, expected)


@pytest.mark.parametrize("mismatch", ("metadata", "generated"))
def test_sdist_rejects_internal_version_mismatch(
    tmp_path: Path,
    mismatch: str,
) -> None:
    expected = Version("1.2.3")
    sdist = tmp_path / "palonexus-1.2.3.tar.gz"
    metadata_version = "9.9.9" if mismatch == "metadata" else str(expected)
    generated_version = "9.9.9" if mismatch == "generated" else str(expected)
    payloads = {
        "palonexus-1.2.3/src/palonexus/py.typed": b"",
        "palonexus-1.2.3/src/palonexus/_version.py": (
            f"__version__ = version = '{generated_version}'\n".encode()
        ),
        "palonexus-1.2.3/PKG-INFO": (
            f"Metadata-Version: 2.4\nName: palonexus\nVersion: {metadata_version}\n"
        ).encode(),
    }
    with tarfile.open(sdist, "w:gz") as archive:
        for name, payload in payloads.items():
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))

    with pytest.raises(RuntimeError, match="version mismatch"):
        verify_python_artifacts._verify_sdist(sdist, expected)
