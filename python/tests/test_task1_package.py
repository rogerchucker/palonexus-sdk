# SPDX-License-Identifier: MIT
"""Task 1 package-boundary and license artifact tests."""

from __future__ import annotations

import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).parents[2]
PACKAGE = ROOT / "python"


def test_runtime_dependency_has_a_reviewed_compatible_range() -> None:
    project = tomllib.loads((PACKAGE / "pyproject.toml").read_text())["project"]

    assert project["dependencies"] == [
        "idna==3.18",
        "pydantic>=2.13.4,<3",
        "unicodedata2==15.1.0",
    ]


def test_package_license_is_the_canonical_repository_license() -> None:
    project = tomllib.loads((PACKAGE / "pyproject.toml").read_text())["project"]

    assert project["license"] == "MIT"
    assert project["license-files"] == ["LICENSE"]
    assert (PACKAGE / "LICENSE").read_bytes() == (ROOT / "LICENSE").read_bytes()


def test_wheel_and_sdist_contain_the_canonical_mit_license(
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
    )
    assert result.returncode == 0, result.stdout + result.stderr

    [wheel] = list(tmp_path.glob("palonexus-*.whl"))
    [sdist] = list(tmp_path.glob("palonexus-*.tar.gz"))
    canonical_license = (ROOT / "LICENSE").read_bytes()

    with zipfile.ZipFile(wheel) as archive:
        wheel_license_members = [
            name
            for name in archive.namelist()
            if name.endswith(".dist-info/licenses/LICENSE")
        ]
        assert len(wheel_license_members) == 1
        assert archive.read(wheel_license_members[0]) == canonical_license

    with tarfile.open(sdist, "r:gz") as archive:
        sdist_license_members = [
            member
            for member in archive.getmembers()
            if member.name.count("/") == 1 and member.name.endswith("/LICENSE")
        ]
        assert len(sdist_license_members) == 1
        stream = archive.extractfile(sdist_license_members[0])
        assert stream is not None
        assert stream.read() == canonical_license
