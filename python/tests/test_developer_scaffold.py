# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

import pytest
import yaml
from palonexus.developer.scaffold import ScaffoldError, initialize_plain_python


def test_scaffold_pins_installed_version_without_local_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    calls: list[tuple[list[str], Path]] = []

    def fake_run(argv: list[str], cwd: Path) -> None:
        calls.append((argv, cwd))
        (cwd / "uv.lock").write_text("version = 1\n", encoding="utf-8")

    monkeypatch.setattr("palonexus.developer.scaffold.run_checked", fake_run)
    initialize_plain_python(project, "release-risk-reviewer", "1.2.3")

    assert len(calls) == 1
    assert calls[0][0] == ["uv", "lock"]
    assert calls[0][1].parent == project.parent
    assert calls[0][1].name.startswith(".project.pnxs-")
    generated = sorted(
        path.relative_to(project).as_posix() for path in project.rglob("*")
    )
    assert generated == [
        "agent.py",
        "fixtures",
        "fixtures/release-change.json",
        "palonexus-agent.yaml",
        "pyproject.toml",
        "uv.lock",
    ]
    pyproject = (project / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dependencies = ["palonexus==1.2.3"]' in pyproject
    assert "[tool.uv.sources]" not in pyproject
    assert ".pnxs/vendor" not in pyproject
    assert str(Path(__file__).parents[2]) not in pyproject
    assert (
        "private"
        not in "\n".join(
            path.read_text(encoding="utf-8", errors="ignore")
            for path in project.rglob("*")
            if path.is_file() and path.suffix != ".whl"
        ).lower()
    )
    fixture = json.loads(
        (project / "fixtures/release-change.json").read_text(encoding="utf-8")
    )
    assert sorted(fixture) == ["change_id", "risk", "summary"]
    descriptor = yaml.safe_load((project / "palonexus-agent.yaml").read_text())
    assert descriptor["inputSchema"]["required"] == ["change_id", "risk", "summary"]
    assert descriptor["outputSchema"] == descriptor["actions"][0]["argumentSchema"]
    assert descriptor["actions"][0]["constraints"] == {"max_risk_score": 1}


def test_scaffold_rejects_bad_version_existing_content_and_invalid_name(
    tmp_path: Path,
) -> None:
    with pytest.raises(ScaffoldError, match="version"):
        initialize_plain_python(tmp_path / "bad", "agent", "not a version")
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "mine.txt").write_text("keep", encoding="utf-8")
    with pytest.raises(ScaffoldError, match="empty"):
        initialize_plain_python(occupied, "agent", "1.2.3")
    assert (occupied / "mine.txt").read_text(encoding="utf-8") == "keep"
    with pytest.raises(ScaffoldError, match="name"):
        initialize_plain_python(tmp_path / "bad-name", "../escape", "1.2.3")


def test_scaffold_lock_failure_leaves_existing_empty_target_and_no_staging(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()

    def fail_lock(argv: list[str], cwd: Path) -> None:
        (cwd / "partial.lock").write_text("partial", encoding="utf-8")
        raise ScaffoldError("uv could not create the project lock")

    monkeypatch.setattr("palonexus.developer.scaffold.run_checked", fail_lock)
    with pytest.raises(ScaffoldError, match="lock"):
        initialize_plain_python(project, "release-risk-reviewer", "1.2.3")

    assert project.is_dir()
    assert list(project.iterdir()) == []
    assert list(tmp_path.glob(".project.pnxs-*")) == []


def test_scaffold_initializes_the_existing_current_directory(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)

    def fake_run(argv: list[str], cwd: Path) -> None:
        assert argv == ["uv", "lock"]
        (cwd / "uv.lock").write_text("version = 1\n", encoding="utf-8")

    monkeypatch.setattr("palonexus.developer.scaffold.run_checked", fake_run)
    initialize_plain_python(Path("."), "release-risk-reviewer", "1.2.3")

    assert Path.cwd() == project
    assert (project / "pyproject.toml").is_file()
    assert (project / "uv.lock").is_file()
    assert list(tmp_path.glob(".project.pnxs-*")) == []


def test_wheel_from_sdist_ignores_ambient_unrelated_git_revision(
    tmp_path: Path,
) -> None:
    root = Path(__file__).parents[2]
    original_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    source_state = subprocess.run(
        ["git", "status", "--porcelain=v1"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    sdist_dir = tmp_path / "sdist"
    subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(sdist_dir), "python"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    [sdist] = sdist_dir.glob("palonexus-*.tar.gz")
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=unrelated, check=True)
    subprocess.run(
        ["git", "config", "user.email", "unrelated@example.invalid"],
        cwd=unrelated,
        check=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Unrelated"], cwd=unrelated, check=True
    )
    (unrelated / "unrelated.txt").write_text("unrelated", encoding="utf-8")
    subprocess.run(["git", "add", "unrelated.txt"], cwd=unrelated, check=True)
    subprocess.run(
        ["git", "commit", "-q", "-m", "unrelated"], cwd=unrelated, check=True
    )
    unrelated_revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=unrelated,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert unrelated_revision != original_revision

    with tarfile.open(sdist, "r:gz") as archive:
        archive.extractall(unrelated, filter="data")
    [extracted] = [path for path in unrelated.glob("palonexus-*") if path.is_dir()]
    marker = extracted / "src/palonexus/_sdist_provenance.py"
    assert "palonexus-sdk-sdist-v1" in marker.read_text(encoding="utf-8")
    wheel_dir = tmp_path / "wheel"
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheel_dir), str(extracted)],
        cwd=unrelated,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    [wheel] = wheel_dir.glob("palonexus-*.whl")
    with zipfile.ZipFile(wheel) as archive:
        embedded = archive.read("palonexus/_build.py").decode("utf-8")
    assert f'SOURCE_REVISION = "{original_revision}"' in embedded
    assert unrelated_revision not in embedded
    assert not (root / "python/src/palonexus/_build.py").exists()
    final_source_state = subprocess.run(
        ["git", "status", "--porcelain=v1"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    assert final_source_state == source_state


def test_live_checkout_ignores_stale_build_evidence(tmp_path: Path) -> None:
    root = Path(__file__).parents[2]
    checkout = tmp_path / "checkout"
    shutil.copytree(
        root / "python",
        checkout,
        ignore=shutil.ignore_patterns(
            "__pycache__", "_version.py", "_build.py", "_sdist_provenance.py"
        ),
    )
    subprocess.run(["git", "init", "-q"], cwd=checkout, check=True)
    subprocess.run(
        ["git", "config", "user.email", "source@example.invalid"],
        cwd=checkout,
        check=True,
    )
    subprocess.run(["git", "config", "user.name", "Source"], cwd=checkout, check=True)
    subprocess.run(["git", "add", "."], cwd=checkout, check=True)
    subprocess.run(["git", "commit", "-q", "-m", "source"], cwd=checkout, check=True)
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=checkout,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    stale_revision = "0" * 40
    (checkout / "src/palonexus/_build.py").write_text(
        "# generated by the PaloNexus build hook\n"
        f'SOURCE_REVISION = "{stale_revision}"\n',
        encoding="utf-8",
    )
    wheel_dir = tmp_path / "live-wheel"
    subprocess.run(
        ["uv", "build", "--wheel", "--out-dir", str(wheel_dir), str(checkout)],
        cwd=tmp_path,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    [wheel] = wheel_dir.glob("palonexus-*.whl")
    with zipfile.ZipFile(wheel) as archive:
        embedded = archive.read("palonexus/_build.py").decode("utf-8")
    assert f'SOURCE_REVISION = "{revision}"' in embedded
    assert stale_revision not in embedded


@pytest.mark.parametrize("tamper", ["malformed", "mismatch"])
def test_wheel_from_sdist_rejects_invalid_provenance_marker(
    tmp_path: Path, tamper: str
) -> None:
    root = Path(__file__).parents[2]
    sdist_dir = tmp_path / "sdist"
    subprocess.run(
        ["uv", "build", "--sdist", "--out-dir", str(sdist_dir), "python"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
        timeout=120,
    )
    [sdist] = sdist_dir.glob("palonexus-*.tar.gz")
    extracted_root = tmp_path / "extracted"
    extracted_root.mkdir()
    with tarfile.open(sdist, "r:gz") as archive:
        archive.extractall(extracted_root, filter="data")
    [extracted] = [path for path in extracted_root.iterdir() if path.is_dir()]
    marker = extracted / "src/palonexus/_sdist_provenance.py"
    marker.write_text(
        "malformed\n"
        if tamper == "malformed"
        else (
            "# generated by the PaloNexus build hook\n"
            'SDIST_MARKER = "palonexus-sdk-sdist-v1"\n'
            f'SOURCE_REVISION = "{"f" * 40}"\n'
        ),
        encoding="utf-8",
    )
    built = subprocess.run(
        [
            "uv",
            "build",
            "--wheel",
            "--out-dir",
            str(tmp_path / "wheel"),
            str(extracted),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert built.returncode != 0
    assert "packaged SDK source revision evidence is invalid" in built.stderr
