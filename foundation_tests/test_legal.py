from __future__ import annotations

import csv
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[1]
LEGAL = ROOT / "docs" / "legal"
SOURCE_COMMIT = "e5ebb21fc960f57a529f262c52c6d69c20fcf2f8"
PROVENANCE_COLUMNS = [
    "destination",
    "source_repository",
    "source_commit",
    "source_path",
    "owner",
    "contributors_reviewed",
    "migration_method",
    "result_license",
    "reviewer",
]
DEPENDENCY_HEADER = (
    "| Dependency | Version | License | Review status | Obligations "
    "| Notice | Source |\n"
    "| --- | --- | --- | --- | --- | --- | --- |\n"
)


def _legal_fixture(tmp_path: Path, *, pyproject: str = "") -> Path:
    script = ROOT / "scripts" / "verify_legal.py"
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / script.name).write_text(
        script.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs" / "legal").mkdir(parents=True)
    scaffold_rows = [
        "LICENSE",
        "docs/legal/PROVENANCE.csv",
        "docs/legal/THIRD_PARTY.md",
        "scripts/verify_legal.py",
    ]
    rows = [
        f"{path},rogerchucker/palonexus-sdk,WORKTREE,{path},"
        "PaloNexus,yes,new,MIT,reviewer"
        for path in scaffold_rows
    ]
    rows.append(
        "docs/legal/SOURCE_TREE.txt,rogerchucker/palonexus-sdk,GENERATED,"
        "scripts/verify_legal.py,PaloNexus,yes,generated,MIT,reviewer"
    )
    (tmp_path / "docs" / "legal" / "PROVENANCE.csv").write_text(
        ",".join(PROVENANCE_COLUMNS) + "\n" + "\n".join(rows) + "\n",
        encoding="utf-8",
    )
    (tmp_path / "docs" / "legal" / "SOURCE_TREE.txt").write_text(
        "format: eligible-migration-v1\n"
        "source_repository: rogerchucker/palonexus-platform\n"
        f"source_commit: {SOURCE_COMMIT}\n"
        "entries: 0\n"
        f"entries_sha256: {hashlib.sha256(b'').hexdigest()}\n\n"
        "source_path,blob_sha256\n",
        encoding="utf-8",
    )
    (tmp_path / "docs" / "legal" / "THIRD_PARTY.md").write_text(
        "<!-- dependency-inventory:start -->\n"
        + DEPENDENCY_HEADER
        + "<!-- dependency-inventory:end -->\n",
        encoding="utf-8",
    )
    (tmp_path / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    if pyproject:
        (tmp_path / "python").mkdir()
        (tmp_path / "python" / "pyproject.toml").write_text(pyproject, encoding="utf-8")
    return tmp_path


def _run_verifier(repository: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, "scripts/verify_legal.py"],
        cwd=repository,
        check=False,
        capture_output=True,
        text=True,
    )


def test_relicensing_record_identifies_the_authorized_extraction() -> None:
    record = (LEGAL / "RELICENSING.md").read_text(encoding="utf-8")

    for required_text in (
        "rogerchucker/palonexus-platform",
        SOURCE_COMMIT,
        "rogerchucker/palonexus-sdk",
        "MIT",
        "PaloNexus",
        "2026-07-26",
    ):
        assert required_text in record

    authorization = (LEGAL / "OWNER_AUTHORIZATION.md").read_text(encoding="utf-8")
    for required_text in (
        "Rajarshi Chakraborty",
        "rajarshic@gmail.com",
        "@rogerchucker",
        "2026-07-25",
        "2026-07-26",
        "MIT",
        "Signed-off-by",
    ):
        assert required_text in authorization
    assert "OWNER_AUTHORIZATION.md" in record


def test_source_tree_snapshot_is_bound_to_the_extraction_commit() -> None:
    snapshot = (LEGAL / "SOURCE_TREE.txt").read_text(encoding="utf-8")

    assert SOURCE_COMMIT in snapshot
    assert "sha256:" in snapshot
    assert "entries: 0" in snapshot
    assert "agentdid/" not in snapshot
    assert "control-plane/" not in snapshot


def test_verifier_rejects_unreferenced_migration_manifest_entry(
    tmp_path: Path,
) -> None:
    repository = _legal_fixture(tmp_path)
    entry = f"private/unrelated.py,{'a' * 64}\n"
    digest = hashlib.sha256(entry.encode()).hexdigest()
    (repository / "docs" / "legal" / "SOURCE_TREE.txt").write_text(
        "format: eligible-migration-v1\n"
        "source_repository: rogerchucker/palonexus-platform\n"
        f"source_commit: {SOURCE_COMMIT}\n"
        "entries: 1\n"
        f"entries_sha256: {digest}\n\n"
        "source_path,blob_sha256\n"
        f"{entry}",
        encoding="utf-8",
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "unreferenced eligible migration path: private/unrelated.py" in result.stdout


def test_provenance_inventory_has_the_normative_shape() -> None:
    with (LEGAL / "PROVENANCE.csv").open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        rows = list(reader)

    assert reader.fieldnames == PROVENANCE_COLUMNS
    assert rows, "the inventory must describe its own legal artifacts"
    assert {row["migration_method"] for row in rows} <= {
        "port",
        "rewrite",
        "new",
        "generated",
    }
    assert all(row["result_license"] == "MIT" for row in rows)


def test_repository_legal_verifier_passes() -> None:
    result = subprocess.run(
        [sys.executable, "scripts/verify_legal.py"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.parametrize(
    ("destination", "contents"),
    [
        ("python/src/palonexus/client.py", "VALUE = 1\n"),
        ("guard/internal/authz/client.go", "package authz\n"),
        ("plugins/codex/hooks/pretool.py", "def main():\n    return None\n"),
    ],
)
def test_verifier_requires_provenance_for_future_source_files(
    tmp_path: Path, destination: str, contents: str
) -> None:
    script = ROOT / "scripts" / "verify_legal.py"
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / script.name).write_text(
        script.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs" / "legal").mkdir(parents=True)
    (tmp_path / "docs" / "legal" / "PROVENANCE.csv").write_text(
        ",".join(PROVENANCE_COLUMNS) + "\n", encoding="utf-8"
    )
    (tmp_path / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    (tmp_path / "python").mkdir(exist_ok=True)
    (tmp_path / "python" / "pyproject.toml").write_text(
        '[project]\nname = "palonexus"\nlicense = "MIT"\n', encoding="utf-8"
    )
    source = tmp_path / destination
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(contents, encoding="utf-8")

    result = subprocess.run(
        [sys.executable, "scripts/verify_legal.py"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert f"missing provenance row: {destination}" in result.stdout


def test_third_party_policy_fails_closed_on_unreviewed_dependencies() -> None:
    policy = (LEGAL / "THIRD_PARTY.md").read_text(encoding="utf-8").lower()

    assert "unreviewed" in policy
    assert "forbidden" in policy
    assert "must not" in policy or "reject" in policy


def test_verifier_rejects_proprietary_plugin_package_metadata(
    tmp_path: Path,
) -> None:
    script = ROOT / "scripts" / "verify_legal.py"
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / script.name).write_text(
        script.read_text(encoding="utf-8"), encoding="utf-8"
    )
    (tmp_path / "docs" / "legal").mkdir(parents=True)
    (tmp_path / "docs" / "legal" / "PROVENANCE.csv").write_text(
        ",".join(PROVENANCE_COLUMNS) + "\n", encoding="utf-8"
    )
    (tmp_path / "docs" / "legal" / "THIRD_PARTY.md").write_text(
        "<!-- dependency-inventory:start -->\n"
        + DEPENDENCY_HEADER
        + "<!-- dependency-inventory:end -->\n",
        encoding="utf-8",
    )
    (tmp_path / "LICENSE").write_text("MIT License\n", encoding="utf-8")
    package = tmp_path / "plugins" / "codex" / "package.json"
    package.parent.mkdir(parents=True)
    package.write_text(
        json.dumps({"name": "palonexus-codex", "license": "UNLICENSED"}),
        encoding="utf-8",
    )

    result = subprocess.run(
        [sys.executable, "scripts/verify_legal.py"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 1
    assert "plugins/codex/package.json must declare MIT" in result.stdout


def test_verifier_rejects_proprietary_python_classifier(tmp_path: Path) -> None:
    repository = _legal_fixture(
        tmp_path,
        pyproject=(
            '[project]\nname = "palonexus"\nlicense = "MIT"\n'
            'classifiers = ["License :: Other/Proprietary License"]\n'
        ),
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "contradictory proprietary Python classifier" in result.stdout


def test_verifier_ignores_fixture_archives(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    fixture = repository / "plugins" / "codex" / "tests" / "fixtures" / "payload.zip"
    fixture.parent.mkdir(parents=True)
    with zipfile.ZipFile(fixture, "w") as archive:
        archive.writestr("payload.json", "{}")

    result = _run_verifier(repository)

    assert result.returncode == 0, result.stdout + result.stderr


def test_verifier_ignores_ndjson_fixture_receipts(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    fixture = (
        repository
        / "plugins"
        / "codex"
        / "tests"
        / "fixtures"
        / "receipts"
        / "events.ndjson"
    )
    fixture.parent.mkdir(parents=True)
    fixture.write_text('{"type":"event"}\n', encoding="utf-8")

    result = _run_verifier(repository)

    assert result.returncode == 0, result.stdout + result.stderr


def test_verifier_rejects_manifest_inventory_drift(tmp_path: Path) -> None:
    repository = _legal_fixture(
        tmp_path,
        pyproject=(
            '[project]\nname = "palonexus"\nlicense = "MIT"\n'
            'dependencies = ["httpx>=0.28"]\n'
        ),
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "dependency missing from inventory: httpx" in result.stdout


def test_verifier_requires_python_dependencies_in_lock(tmp_path: Path) -> None:
    repository = _legal_fixture(
        tmp_path,
        pyproject=(
            '[build-system]\nrequires = ["hatchling>=1.27"]\n'
            '[project]\nname = "palonexus"\nlicense = "MIT"\n'
        ),
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "dependency not resolved in uv.lock: hatchling" in result.stdout


@pytest.mark.parametrize(
    ("manifest", "contents", "message"),
    [
        (
            "python/pyproject.toml",
            '[project]\nname="palonexus"\nlicense="MIT"\n'
            'dependencies=["demo @ git+https://example.invalid/demo.git"]\n',
            "unsupported Python dependency source",
        ),
        (
            "plugins/demo/package.json",
            '{"name":"demo","license":"MIT","dependencies":{"left-pad":"1.0.0"}}',
            "unsupported dependency reconciliation: npm",
        ),
        (
            "guard/go.mod",
            "module example.com/guard\nrequire example.com/dependency v1.0.0\n",
            "unsupported dependency reconciliation: go",
        ),
        (
            "guard/Cargo.toml",
            '[package]\nname="guard"\nversion="1.0.0"\n[dependencies]\nserde="1"\n',
            "unsupported dependency reconciliation: cargo",
        ),
    ],
)
def test_verifier_fails_closed_on_unsupported_dependency_sources(
    tmp_path: Path, manifest: str, contents: str, message: str
) -> None:
    repository = _legal_fixture(tmp_path)
    target = repository / manifest
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(contents, encoding="utf-8")

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert message in result.stdout


@pytest.mark.parametrize(
    "destination",
    [
        "scripts/new_tool.py",
        "scripts/launcher.unknown",
        "examples/demo/run.sh",
        "examples/demo/template.j2",
        "plugins/codex/tests/fixtures/helper.py",
        "plugins/codex/testdata/runner.sh",
    ],
)
def test_verifier_requires_provenance_for_tooling_and_fixture_code(
    tmp_path: Path, destination: str
) -> None:
    repository = _legal_fixture(tmp_path)
    target = repository / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("# source\n", encoding="utf-8")

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert f"missing provenance row: {destination}" in result.stdout


def test_verifier_rejects_locked_version_drift(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    (repository / "uv.lock").write_text(
        'version = 1\n[[package]]\nname = "demo"\nversion = "1.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n',
        encoding="utf-8",
    )
    (repository / "docs" / "legal" / "THIRD_PARTY.md").write_text(
        "<!-- dependency-inventory:start -->\n"
        + DEPENDENCY_HEADER
        + "| demo | 2.0 | MIT | reviewed | retain notices | none | PyPI |\n"
        + "<!-- dependency-inventory:end -->\n",
        encoding="utf-8",
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert (
        "dependency version drift: demo (inventory 2.0, expected 1.0)" in result.stdout
    )


def test_verifier_rejects_lock_constraint_mismatch(tmp_path: Path) -> None:
    repository = _legal_fixture(
        tmp_path,
        pyproject=(
            '[project]\nname="palonexus"\nlicense="MIT"\ndependencies=["demo>=2.0"]\n'
        ),
    )
    (repository / "uv.lock").write_text(
        'version=1\n[[package]]\nname="demo"\nversion="1.0"\n'
        'source={registry="https://pypi.org/simple"}\n'
        'sdist={url="https://files.pythonhosted.org/demo.tar.gz",'
        'hash="sha256:abc",size=1}\n',
        encoding="utf-8",
    )
    (repository / "docs" / "legal" / "THIRD_PARTY.md").write_text(
        "<!-- dependency-inventory:start -->\n"
        + DEPENDENCY_HEADER
        + "| demo | 1.0 | MIT | reviewed | retain notices | none | PyPI |\n"
        + "<!-- dependency-inventory:end -->\n",
        encoding="utf-8",
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "locked version violates manifest constraint: demo" in result.stdout


def test_repository_pins_complete_isolated_build_closure() -> None:
    result = _run_verifier(ROOT)

    assert result.returncode == 0, result.stdout + result.stderr
    build_metadata = (ROOT / "python" / "pyproject.toml").read_text(encoding="utf-8")
    for dependency in (
        "packaging==26.2",
        "pathspec==1.1.1",
        "pluggy==1.6.0",
        "setuptools==83.0.0",
        "setuptools-scm==10.2.1",
        "trove-classifiers==2026.6.1.19",
        "vcs-versioning==2.2.2",
    ):
        assert dependency in build_metadata


@pytest.mark.parametrize(
    ("source", "distribution", "message"),
    [
        (
            'source={registry="https://packages.example.invalid/simple"}',
            'sdist={url="https://example.invalid/demo.tar.gz",'
            'hash="sha256:abc",size=1}',
            "unexpected registry for demo",
        ),
        (
            'source={registry="https://pypi.org/simple"}',
            'sdist={url="https://files.pythonhosted.org/demo.tar.gz",size=1}',
            "locked distribution missing SHA-256 hash: demo",
        ),
        (
            'source={registry="https://pypi.org/simple"}',
            'sdist={url="https://evil.example/demo.tar.gz",'
            'hash="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
            'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",size=1}',
            "unexpected locked artifact host for demo",
        ),
    ],
)
def test_verifier_rejects_bad_lock_integrity(
    tmp_path: Path, source: str, distribution: str, message: str
) -> None:
    repository = _legal_fixture(tmp_path)
    (repository / "uv.lock").write_text(
        f'version=1\n[[package]]\nname="demo"\nversion="1.0"\n'
        f"{source}\n{distribution}\n",
        encoding="utf-8",
    )
    (repository / "docs" / "legal" / "THIRD_PARTY.md").write_text(
        "<!-- dependency-inventory:start -->\n"
        + DEPENDENCY_HEADER
        + "| demo | 1.0 | MIT | reviewed | retain notices | none | PyPI |\n"
        + "<!-- dependency-inventory:end -->\n",
        encoding="utf-8",
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert message in result.stdout


def test_verifier_rejects_invalid_spdx_and_proprietary_conflict(
    tmp_path: Path,
) -> None:
    repository = _legal_fixture(tmp_path)
    third_party = repository / "docs" / "legal" / "THIRD_PARTY.md"
    third_party.write_text(
        "<!-- dependency-inventory:start -->\n"
        + DEPENDENCY_HEADER
        + "| demo | 1.0 | MIT OR Not-A-License | reviewed "
        + "| retain notices | none | pypi |\n"
        + "<!-- dependency-inventory:end -->\n",
        encoding="utf-8",
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "invalid SPDX expression for demo" in result.stdout


def test_verifier_rejects_bogus_migrated_provenance(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    source = repository / "python" / "src" / "client.py"
    source.parent.mkdir(parents=True)
    source.write_text("VALUE = 1\n", encoding="utf-8")
    provenance = repository / "docs" / "legal" / "PROVENANCE.csv"
    provenance.write_text(
        ",".join(PROVENANCE_COLUMNS)
        + "\n"
        + "python/src/client.py,wrong/repo,abc,../secret.py,"
        + "PaloNexus,yes,port,MIT,reviewer\n",
        encoding="utf-8",
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "invalid migrated source repository" in result.stdout
    assert "invalid migrated source commit" in result.stdout
    assert "unsafe migrated source path" in result.stdout


def test_verifier_rejects_malformed_csv_without_traceback(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    (repository / "docs" / "legal" / "PROVENANCE.csv").write_text(
        ",".join(PROVENANCE_COLUMNS) + "\nonly-one-field\n", encoding="utf-8"
    )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "malformed provenance row 2" in result.stdout
    assert "Traceback" not in result.stderr


def test_verifier_rejects_symlinked_source_escape(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    outside = tmp_path.parent / "outside.py"
    outside.write_text("VALUE = 1\n", encoding="utf-8")
    source = repository / "python" / "src" / "escape.py"
    source.parent.mkdir(parents=True)
    source.symlink_to(outside)

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "symlink is not allowed: python/src/escape.py" in result.stdout


def test_verifier_inspects_real_dist_artifacts(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    artifact = repository / "dist" / "palonexus-1.0.whl"
    artifact.parent.mkdir()
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "palonexus-1.0.dist-info/METADATA",
            "Name: palonexus\nLicense-Expression: Proprietary\n",
        )
        archive.writestr("LICENSE", "MIT License\n")

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "conflicting or proprietary archive metadata" in result.stdout


def test_wheel_requires_its_own_palonexus_metadata(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    artifact = repository / "dist" / "palonexus-1.0.whl"
    artifact.parent.mkdir()
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("vendor/LICENSE", "MIT License\n")
        archive.writestr("vendor.dist-info/METADATA", "Name: vendor\nLicense: MIT\n")

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "wheel lacks PaloNexus MIT metadata" in result.stdout


def test_wheel_rejects_non_mit_expression_with_mit_classifier(
    tmp_path: Path,
) -> None:
    repository = _legal_fixture(tmp_path)
    artifact = repository / "dist" / "palonexus-1.0.whl"
    artifact.parent.mkdir()
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr(
            "palonexus-1.0.dist-info/METADATA",
            "Name: palonexus\n"
            "License-Expression: BSD-3-Clause\n"
            "Classifier: License :: OSI Approved :: MIT License\n",
        )

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "conflicting or proprietary archive metadata" in result.stdout


def test_generic_bundle_requires_canonical_project_license(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    artifact = repository / "release" / "guard.zip"
    artifact.parent.mkdir()
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("LICENSE", "MIT License\nmodified text\n")

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "archive project LICENSE differs from repository LICENSE" in result.stdout


def test_generic_bundle_allows_lawful_third_party_notices(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    artifact = repository / "release" / "guard.zip"
    artifact.parent.mkdir()
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("LICENSE", "MIT License\n")
        archive.writestr(
            "THIRD_PARTY/vendor.LICENSE",
            "Copyright vendor. All rights reserved. BSD-3-Clause.\n",
        )

    result = _run_verifier(repository)

    assert result.returncode == 0, result.stdout + result.stderr


def test_generic_bundle_allows_large_guard_binary(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    artifact = repository / "release" / "guard.zip"
    artifact.parent.mkdir()
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("LICENSE", "MIT License\n")
        archive.writestr("palonexus-guard", b"\0" * (9 * 1024 * 1024))

    result = _run_verifier(repository)

    assert result.returncode == 0, result.stdout + result.stderr


def test_verifier_rejects_symlinked_release_artifact(tmp_path: Path) -> None:
    repository = _legal_fixture(tmp_path)
    outside = tmp_path.parent / "outside.zip"
    with zipfile.ZipFile(outside, "w") as archive:
        archive.writestr("LICENSE", "MIT License\n")
    artifact = repository / "dist" / "guard.zip"
    artifact.parent.mkdir()
    artifact.symlink_to(outside)

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "release artifact symlink is not allowed" in result.stdout


@pytest.mark.parametrize("limit_kind", ["entries", "bytes"])
def test_verifier_bounds_archive_inspection(tmp_path: Path, limit_kind: str) -> None:
    repository = _legal_fixture(tmp_path)
    artifact = repository / "dist" / "oversized.whl"
    artifact.parent.mkdir()
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_STORED) as archive:
        if limit_kind == "entries":
            for index in range(1_001):
                archive.writestr(f"data/{index}", "")
        else:
            archive.writestr("LICENSE", b"MIT License\n" + b" " * (8 * 1024 * 1024))

    result = _run_verifier(repository)

    assert result.returncode == 1
    expected = (
        "too many archive entries" if limit_kind == "entries" else "archive too large"
    )
    assert expected in result.stdout


def test_verifier_rejects_suspicious_archive_compression_ratio(
    tmp_path: Path,
) -> None:
    repository = _legal_fixture(tmp_path)
    artifact = repository / "dist" / "compressed.zip"
    artifact.parent.mkdir()
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("LICENSE", "MIT License\n")
        archive.writestr("payload", b"\0" * (10 * 1024 * 1024))

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "suspicious archive compression ratio" in result.stdout


def test_verifier_rejects_cumulative_archive_budget_before_reads(
    tmp_path: Path,
) -> None:
    repository = _legal_fixture(tmp_path)
    artifact = repository / "dist" / "cumulative.zip"
    artifact.parent.mkdir()
    block = b"x" * (8 * 1024 * 1024)
    with zipfile.ZipFile(artifact, "w", compression=zipfile.ZIP_STORED) as archive:
        for index in range(9):
            archive.writestr(f"payload/{index}", block)

    result = _run_verifier(repository)

    assert result.returncode == 1
    assert "cumulative archive size exceeds budget" in result.stdout
