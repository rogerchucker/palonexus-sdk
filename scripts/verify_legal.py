"""Verify PaloNexus SDK relicensing, provenance, dependencies, and artifacts."""

from __future__ import annotations

import csv
import hashlib
import json
import re
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from collections.abc import Iterator
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
PROVENANCE = ROOT / "docs" / "legal" / "PROVENANCE.csv"
THIRD_PARTY = ROOT / "docs" / "legal" / "THIRD_PARTY.md"
SOURCE_TREE = ROOT / "docs" / "legal" / "SOURCE_TREE.txt"
SOURCE_REPOSITORY = "rogerchucker/palonexus-platform"
SOURCE_COMMIT = "e5ebb21fc960f57a529f262c52c6d69c20fcf2f8"
DESTINATION_REPOSITORY = "rogerchucker/palonexus-sdk"
EXPECTED_COLUMNS = [
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
MIGRATION_METHODS = {"port", "rewrite", "new", "generated"}
SOURCE_DIRECTORIES = {
    "conformance",
    "examples",
    "guard",
    "packaging",
    "plugins",
    "protocol",
    "python",
    "scripts",
}
ROOT_INPUTS = {
    "LICENSE",
    "Makefile",
    "README.md",
    "go.mod",
    "go.sum",
    "Cargo.lock",
    "Cargo.toml",
    "package-lock.json",
    "package.json",
    "pnpm-lock.yaml",
    "pyproject.toml",
    "ruff.toml",
    "uv.lock",
    "yarn.lock",
}
IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "build",
    "dist",
    "node_modules",
}
ARCHIVE_SUFFIXES = (".tar.gz", ".tgz", ".whl", ".zip")
MAX_ARCHIVE_ENTRIES = 1_000
MAX_METADATA_BYTES = 1024 * 1024
MAX_ARCHIVE_ENTRY_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_DECLARED_BYTES = 64 * 1024 * 1024
MAX_COMPRESSION_RATIO = 200
ALLOWED_SPDX = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MIT",
    "MPL-2.0",
    "PSF-2.0",
    "Python-2.0",
    "Unicode-3.0",
}
ALLOWED_EXCEPTIONS = {"Classpath-exception-2.0", "LLVM-exception"}
FORBIDDEN_SPDX = {
    "AGPL-1.0-only",
    "AGPL-1.0-or-later",
    "AGPL-3.0-only",
    "AGPL-3.0-or-later",
    "BUSL-1.1",
    "GPL-2.0-only",
    "GPL-2.0-or-later",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "LicenseRef-Proprietary",
    "SSPL-1.0",
    "UNLICENSED",
}
SPDX_TOKEN = re.compile(r"\(|\)|AND|OR|WITH|[A-Za-z0-9][A-Za-z0-9.+-]*")
REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*")


def _safe_relative(value: str) -> PurePosixPath | None:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "." in path.parts:
        return None
    if path.as_posix() != value:
        return None
    return path


def _source_tree_paths(errors: list[str]) -> dict[str, str]:
    if not SOURCE_TREE.is_file():
        errors.append("missing source-tree manifest: docs/legal/SOURCE_TREE.txt")
        return {}
    try:
        header_text, inventory_text = SOURCE_TREE.read_text(encoding="utf-8").split(
            "\n\n", 1
        )
        header = dict(
            line.split(": ", 1) for line in header_text.splitlines() if ": " in line
        )
        lines = inventory_text.splitlines()
    except (OSError, ValueError) as exc:
        errors.append(f"invalid source-tree manifest: {exc}")
        return {}
    if header.get("format") != "eligible-migration-v1":
        errors.append("source-tree manifest format is unsupported")
    if header.get("source_commit") != SOURCE_COMMIT:
        errors.append("source-tree manifest commit does not match extraction commit")
    if not lines or lines[0] != "source_path,blob_sha256":
        errors.append("source-tree manifest columns are invalid")
        return {}
    entry_lines = lines[1:]
    digest_input = ("\n".join(entry_lines) + ("\n" if entry_lines else "")).encode()
    digest = hashlib.sha256(digest_input).hexdigest()
    if header.get("entries_sha256") != digest:
        errors.append("source-tree manifest digest mismatch")
    if header.get("entries") != str(len(entry_lines)):
        errors.append("source-tree manifest entry count mismatch")
    entries: dict[str, str] = {}
    for line in entry_lines:
        fields = line.split(",")
        if len(fields) != 2:
            errors.append("source-tree manifest row is malformed")
            continue
        path, blob_hash = fields
        if _safe_relative(path) is None:
            errors.append(f"unsafe source-tree path: {path}")
            continue
        if not re.fullmatch(r"[0-9a-f]{64}", blob_hash):
            errors.append(f"invalid source-tree content hash: {path}")
            continue
        if path in entries:
            errors.append(f"duplicate source-tree path: {path}")
        entries[path] = blob_hash
    if list(entries) != sorted(entries):
        errors.append("source-tree manifest paths are not unique and sorted")
    return entries


def _read_provenance(
    errors: list[str], source_tree: dict[str, str]
) -> dict[str, dict[str, str]]:
    if not PROVENANCE.is_file():
        errors.append("missing legal inventory: docs/legal/PROVENANCE.csv")
        return {}
    try:
        with PROVENANCE.open(newline="", encoding="utf-8") as stream:
            reader = csv.DictReader(stream, strict=True)
            if reader.fieldnames != EXPECTED_COLUMNS:
                errors.append(
                    "invalid provenance columns: expected " + ",".join(EXPECTED_COLUMNS)
                )
                return {}
            rows = list(reader)
    except (csv.Error, OSError) as exc:
        errors.append(f"malformed provenance CSV: {exc}")
        return {}

    inventory: dict[str, dict[str, str]] = {}
    referenced_source_paths: set[str] = set()
    for line_number, row in enumerate(rows, start=2):
        if None in row or any(value is None for value in row.values()):
            errors.append(f"malformed provenance row {line_number}")
            continue
        normalized = {key: value.strip() for key, value in row.items()}
        destination = normalized["destination"]
        missing = [key for key, value in normalized.items() if not value]
        if missing:
            errors.append(f"malformed provenance row {line_number}: empty {missing}")
            continue
        path = _safe_relative(destination)
        if path is None:
            errors.append(f"unsafe provenance destination: {destination}")
            continue
        if destination in inventory:
            errors.append(f"duplicate provenance destination: {destination}")
            continue
        method = normalized["migration_method"]
        if method not in MIGRATION_METHODS:
            errors.append(f"invalid migration method for {destination}: {method}")
        if normalized["result_license"] != "MIT":
            errors.append(f"non-MIT provenance result: {destination}")
        if normalized["contributors_reviewed"].lower() not in {"yes", "true"}:
            errors.append(f"contributors not reviewed: {destination}")
        if method in {"port", "rewrite"}:
            if normalized["source_repository"] != SOURCE_REPOSITORY:
                errors.append(f"invalid migrated source repository: {destination}")
            if normalized["source_commit"] != SOURCE_COMMIT:
                errors.append(f"invalid migrated source commit: {destination}")
            source_path = normalized["source_path"]
            if _safe_relative(source_path) is None:
                errors.append(f"unsafe migrated source path: {destination}")
            elif source_path not in source_tree:
                errors.append(f"migrated source path not in source tree: {destination}")
            else:
                referenced_source_paths.add(source_path)
        elif method == "new":
            if (
                normalized["source_repository"] != DESTINATION_REPOSITORY
                or normalized["source_commit"] != "WORKTREE"
                or normalized["source_path"] != destination
            ):
                errors.append(f"incoherent new-file provenance: {destination}")
        elif method == "generated":
            if (
                normalized["source_repository"] != DESTINATION_REPOSITORY
                or normalized["source_commit"] != "GENERATED"
                or _safe_relative(normalized["source_path"]) is None
            ):
                errors.append(f"incoherent generated-file provenance: {destination}")
        disk_path = ROOT / Path(*path.parts)
        try:
            if disk_path.is_symlink():
                errors.append(f"symlink is not allowed: {destination}")
            elif not disk_path.is_file():
                errors.append(f"provenance destination does not exist: {destination}")
            elif not disk_path.resolve().is_relative_to(ROOT.resolve()):
                errors.append(
                    f"provenance destination escapes repository: {destination}"
                )
        except OSError as exc:
            errors.append(f"cannot resolve provenance destination {destination}: {exc}")
        inventory[destination] = normalized
    for unreferenced in sorted(source_tree.keys() - referenced_source_paths):
        errors.append(f"unreferenced eligible migration path: {unreferenced}")
    return inventory


def _tracked_candidates() -> set[Path]:
    candidates: set[Path] = set()
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
        for raw in result.stdout.split(b"\0"):
            if raw:
                candidates.add(ROOT / raw.decode("utf-8", errors="strict"))
    except (FileNotFoundError, subprocess.CalledProcessError, UnicodeDecodeError):
        pass
    candidates.update(ROOT.rglob("*"))
    return candidates


def _is_inert_fixture(relative: Path) -> bool:
    fixture_parts = {"fixtures", "testdata"}
    if not fixture_parts.intersection(relative.parts):
        return False
    manifest_names = {
        "hooks.json",
        "manifest.json",
        "package.json",
        "plugin.json",
        "plugin.yaml",
        "plugin.yml",
    }
    inert_suffixes = {".golden", ".json", ".out", ".txt", ".xml", ".yaml", ".yml"}
    if relative.name == "payload.zip":
        return True
    return (
        relative.name not in manifest_names
        and relative.suffix.lower() in inert_suffixes
    )


def _is_provenance_input(relative: Path) -> bool:
    if not relative.parts or IGNORED_PARTS.intersection(relative.parts):
        return False
    if _is_inert_fixture(relative):
        return False
    if relative.parts[0] in SOURCE_DIRECTORIES:
        return True
    if relative.parts[0] == "foundation_tests":
        return relative.suffix.lower() in {".py", ".pyi"}
    if relative.parts[:2] == (".github", "workflows"):
        return relative.suffix.lower() in {".yaml", ".yml"}
    if relative.parts[:2] == ("docs", "legal"):
        return relative.name in {
            "OWNER_AUTHORIZATION.md",
            "PROVENANCE.csv",
            "RELICENSING.md",
            "SOURCE_TREE.txt",
            "THIRD_PARTY.md",
        }
    return len(relative.parts) == 1 and relative.name in ROOT_INPUTS


def _source_files(errors: list[str]) -> list[str]:
    source_files: list[str] = []
    for path in _tracked_candidates():
        try:
            relative = path.relative_to(ROOT)
        except ValueError:
            continue
        if path.is_symlink():
            if _is_provenance_input(relative):
                errors.append(f"symlink is not allowed: {relative.as_posix()}")
            continue
        if not path.is_file():
            continue
        if _is_provenance_input(relative):
            source_files.append(relative.as_posix())
    return sorted(set(source_files))


def _check_source_provenance(
    inventory: dict[str, dict[str, str]], errors: list[str]
) -> None:
    for source_file in _source_files(errors):
        if source_file not in inventory:
            errors.append(f"missing provenance row: {source_file}")


class _SpdxParser:
    def __init__(self, expression: str) -> None:
        self.tokens = SPDX_TOKEN.findall(expression)
        self.expression = expression
        self.position = 0

    def parse(self) -> bool:
        if "".join(self.tokens) != re.sub(r"\s+", "", self.expression):
            return False
        return self._or_expression() and self.position == len(self.tokens)

    def _or_expression(self) -> bool:
        if not self._and_expression():
            return False
        while self._take("OR"):
            if not self._and_expression():
                return False
        return True

    def _and_expression(self) -> bool:
        if not self._term():
            return False
        while self._take("AND"):
            if not self._term():
                return False
        return True

    def _term(self) -> bool:
        if self._take("("):
            if not self._or_expression() or not self._take(")"):
                return False
            return True
        if self.position >= len(self.tokens):
            return False
        identifier = self.tokens[self.position]
        if identifier in {"AND", "OR", "WITH", "(", ")"}:
            return False
        self.position += 1
        if identifier not in ALLOWED_SPDX or identifier in FORBIDDEN_SPDX:
            return False
        if self._take("WITH"):
            if self.position >= len(self.tokens):
                return False
            exception = self.tokens[self.position]
            self.position += 1
            return exception in ALLOWED_EXCEPTIONS
        return True

    def _take(self, value: str) -> bool:
        if self.position < len(self.tokens) and self.tokens[self.position] == value:
            self.position += 1
            return True
        return False


def _valid_spdx(expression: str) -> bool:
    return _SpdxParser(expression).parse()


def _project_license(project: dict[str, object]) -> str:
    value = project.get("license", "")
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        expression = value.get("text") or value.get("file")
        return expression if isinstance(expression, str) else ""
    return ""


def _check_package_metadata(errors: list[str]) -> None:
    license_file = ROOT / "LICENSE"
    if not license_file.is_file() or "MIT License" not in license_file.read_text(
        encoding="utf-8"
    ):
        errors.append("LICENSE must contain the MIT License")
    package_metadata = ROOT / "python" / "pyproject.toml"
    if package_metadata.is_file():
        try:
            project = tomllib.loads(package_metadata.read_text(encoding="utf-8")).get(
                "project", {}
            )
        except (OSError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"cannot read python/pyproject.toml: {exc}")
        else:
            if not isinstance(project, dict) or _project_license(project) != "MIT":
                errors.append('python/pyproject.toml must declare license = "MIT"')
            classifiers = (
                project.get("classifiers", []) if isinstance(project, dict) else []
            )
            license_classifiers = (
                [
                    classifier
                    for classifier in classifiers
                    if isinstance(classifier, str)
                    and classifier.startswith("License ::")
                ]
                if isinstance(classifiers, list)
                else []
            )
            if any(
                classifier != "License :: OSI Approved :: MIT License"
                for classifier in license_classifiers
            ):
                errors.append("contradictory proprietary Python classifier")
    for root_name in SOURCE_DIRECTORIES:
        root = ROOT / root_name
        if not root.is_dir():
            continue
        for package_json in root.rglob("package.json"):
            relative = package_json.relative_to(ROOT)
            if IGNORED_PARTS.intersection(relative.parts):
                continue
            try:
                metadata = json.loads(package_json.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError) as exc:
                errors.append(f"cannot read {relative}: {exc}")
                continue
            if not isinstance(metadata, dict) or metadata.get("license") != "MIT":
                errors.append(f"{relative} must declare MIT")


def _release_archives() -> Iterator[Path]:
    for path in ROOT.rglob("*"):
        if not path.is_file() or not path.name.endswith(ARCHIVE_SUFFIXES):
            continue
        relative = path.relative_to(ROOT)
        parts = relative.parts
        conventional = parts[0] in {"dist", "release", "releases", "artifacts"}
        build_release = len(parts) > 1 and parts[:2] in {
            ("build", "dist"),
            ("build", "release"),
            ("build", "releases"),
            ("build", "artifacts"),
        }
        if conventional or build_release:
            yield path


def _safe_archive_name(name: str) -> bool:
    candidate = PurePosixPath(name)
    return not candidate.is_absolute() and ".." not in candidate.parts


def _zip_evidence(path: Path, errors: list[str]) -> list[tuple[str, bytes]]:
    evidence: list[tuple[str, bytes]] = []
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ARCHIVE_ENTRIES:
            errors.append(f"too many archive entries: {path.relative_to(ROOT)}")
            return []
        declared_size = 0
        for info in infos:
            if not _safe_archive_name(info.filename):
                errors.append(f"escaped archive member: {path.relative_to(ROOT)}")
                return []
            if info.file_size > MAX_ARCHIVE_ENTRY_BYTES:
                errors.append(f"archive entry too large: {path.relative_to(ROOT)}")
                return []
            declared_size += info.file_size
            if declared_size > MAX_ARCHIVE_DECLARED_BYTES:
                errors.append(
                    f"cumulative archive size exceeds budget: {path.relative_to(ROOT)}"
                )
                return []
            if (
                info.compress_size
                and info.file_size / info.compress_size > MAX_COMPRESSION_RATIO
            ):
                errors.append(
                    f"suspicious archive compression ratio: {path.relative_to(ROOT)}"
                )
                return []
            is_evidence = Path(info.filename).name == "LICENSE" or (
                info.filename.endswith(".dist-info/METADATA")
            )
            if is_evidence:
                if info.file_size > MAX_METADATA_BYTES:
                    errors.append(f"archive too large: {path.relative_to(ROOT)}")
                    return []
                with archive.open(info) as stream:
                    contents = stream.read(MAX_METADATA_BYTES + 1)
                if len(contents) > MAX_METADATA_BYTES:
                    errors.append(f"archive too large: {path.relative_to(ROOT)}")
                    return []
                evidence.append((info.filename, contents))
    return evidence


def _tar_evidence(path: Path, errors: list[str]) -> list[tuple[str, bytes]]:
    evidence: list[tuple[str, bytes]] = []
    total_size = 0
    with tarfile.open(path, "r:*") as archive:
        entry_count = 0
        for member in archive:
            entry_count += 1
            if entry_count > MAX_ARCHIVE_ENTRIES:
                errors.append(f"too many archive entries: {path.relative_to(ROOT)}")
                return []
            if member.size > MAX_ARCHIVE_ENTRY_BYTES:
                errors.append(f"archive entry too large: {path.relative_to(ROOT)}")
                return []
            if member.isfile():
                total_size += member.size
            if total_size > MAX_ARCHIVE_DECLARED_BYTES:
                errors.append(
                    f"cumulative archive size exceeds budget: {path.relative_to(ROOT)}"
                )
                return []
            if not _safe_archive_name(member.name):
                errors.append(f"escaped archive member: {path.relative_to(ROOT)}")
                return []
            if member.isfile() and (
                Path(member.name).name == "LICENSE"
                or member.name.endswith(".dist-info/METADATA")
            ):
                if member.size > MAX_METADATA_BYTES:
                    errors.append(f"archive too large: {path.relative_to(ROOT)}")
                    return []
                stream = archive.extractfile(member)
                if stream is not None:
                    contents = stream.read(MAX_METADATA_BYTES + 1)
                    if len(contents) > MAX_METADATA_BYTES:
                        errors.append(f"archive too large: {path.relative_to(ROOT)}")
                        return []
                    evidence.append((member.name, contents))
    compressed_size = path.stat().st_size
    if compressed_size and total_size / compressed_size > MAX_COMPRESSION_RATIO:
        errors.append(f"suspicious archive compression ratio: {path.relative_to(ROOT)}")
        return []
    return evidence


def _metadata_is_palonexus_mit(contents: bytes) -> tuple[bool, bool]:
    metadata = BytesParser().parsebytes(contents)
    name = metadata.get("Name", "").lower().replace("-", "").replace("_", "")
    if name != "palonexus":
        return False, False
    fields = [
        value.strip()
        for header in ("License-Expression", "License")
        for value in metadata.get_all(header, [])
        if value.strip()
    ]
    license_classifiers = [
        classifier
        for classifier in metadata.get_all("Classifier", [])
        if classifier.startswith("License ::")
    ]
    has_mit = "MIT" in fields or (
        "License :: OSI Approved :: MIT License" in license_classifiers
    )
    conflict = any(value != "MIT" for value in fields) or any(
        classifier != "License :: OSI Approved :: MIT License"
        for classifier in license_classifiers
    )
    return has_mit and not conflict, conflict


def _root_license(name: str) -> bool:
    parts = PurePosixPath(name).parts
    if Path(name).name != "LICENSE" or len(parts) > 2:
        return False
    lowered = {part.lower() for part in parts}
    return not lowered.intersection({"third_party", "third-party", "vendor"})


def _check_archives(errors: list[str]) -> None:
    for path in _release_archives():
        relative = path.relative_to(ROOT)
        if path.is_symlink():
            errors.append(f"release artifact symlink is not allowed: {relative}")
            continue
        try:
            if not path.resolve().is_relative_to(ROOT.resolve()):
                errors.append(f"release artifact escapes repository: {relative}")
                continue
        except OSError as exc:
            errors.append(f"cannot resolve release artifact {relative}: {exc}")
            continue
        try:
            evidence = (
                _zip_evidence(path, errors)
                if path.name.endswith((".whl", ".zip"))
                else _tar_evidence(path, errors)
            )
        except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
            errors.append(f"cannot inspect archive {relative}: {exc}")
            continue
        if not evidence:
            if not any(str(relative) in error for error in errors):
                errors.append(
                    f"archive lacks authoritative license evidence: {relative}"
                )
            continue
        metadata_members = [
            (name, contents)
            for name, contents in evidence
            if name.endswith(".dist-info/METADATA")
        ]
        metadata_results = [
            _metadata_is_palonexus_mit(contents) for _, contents in metadata_members
        ]
        project_mit = any(mit for mit, _ in metadata_results)
        project_conflict = any(conflict for _, conflict in metadata_results)
        root_licenses = [contents for name, contents in evidence if _root_license(name)]
        canonical_license = (ROOT / "LICENSE").read_bytes().replace(b"\r\n", b"\n")
        root_license_matches = (
            len(root_licenses) == 1
            and root_licenses[0].replace(b"\r\n", b"\n") == canonical_license
        )
        if project_conflict:
            errors.append(f"conflicting or proprietary archive metadata: {relative}")
        elif path.name.endswith(".whl") and (
            len(metadata_members) != 1 or not project_mit
        ):
            errors.append(f"wheel lacks PaloNexus MIT metadata: {relative}")
        elif not path.name.endswith(".whl") and not root_license_matches:
            errors.append(
                f"archive project LICENSE differs from repository LICENSE: {relative}"
            )


def _dependency_rows(errors: list[str]) -> dict[str, list[str]]:
    if not THIRD_PARTY.is_file():
        errors.append("missing third-party policy: docs/legal/THIRD_PARTY.md")
        return {}
    text = THIRD_PARTY.read_text(encoding="utf-8")
    start = "<!-- dependency-inventory:start -->"
    end = "<!-- dependency-inventory:end -->"
    if start not in text or end not in text:
        errors.append("third-party dependency inventory markers are missing")
        return {}
    inventory = text.split(start, 1)[1].split(end, 1)[0]
    lines = [line for line in inventory.splitlines() if line.strip().startswith("|")]
    if len(lines) < 2:
        errors.append("third-party dependency inventory table is malformed")
        return {}
    header = [cell.strip() for cell in lines[0].strip().strip("|").split("|")]
    expected = [
        "Dependency",
        "Version",
        "License",
        "Review status",
        "Obligations",
        "Notice",
        "Source",
    ]
    if header != expected:
        errors.append("third-party dependency inventory columns are invalid")
        return {}
    rows: dict[str, list[str]] = {}
    for line_number, line in enumerate(lines[2:], start=1):
        row = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(row) != 7 or not all(row):
            errors.append(f"third-party dependency row {line_number} is incomplete")
            continue
        name = row[0].lower().replace("_", "-")
        if name in rows:
            errors.append(f"duplicate dependency inventory row: {name}")
        rows[name] = row
    return rows


def _requirement_name(requirement: str) -> str | None:
    match = REQUIREMENT_NAME.match(requirement.strip())
    return match.group(0).lower().replace("_", "-") if match else None


def _version_key(version: str) -> tuple[tuple[int, int | str], ...]:
    return tuple(
        (0, int(part)) if part.isdigit() else (1, part.lower())
        for part in re.findall(r"[A-Za-z]+|\d+", version)
    )


def _satisfies_constraint(version: str, constraint: str) -> bool:
    if not constraint or constraint == "*":
        return True
    version_key = _version_key(version)
    for clause in constraint.split(","):
        clause = clause.strip()
        match = re.fullmatch(r"(==|>=|<=|>|<|~=)\s*([A-Za-z0-9.+-]+)", clause)
        if match is None:
            return False
        operator, required = match.groups()
        required_key = _version_key(required)
        if operator == "==" and version != required:
            return False
        if operator == ">=" and version_key < required_key:
            return False
        if operator == "<=" and version_key > required_key:
            return False
        if operator == ">" and version_key <= required_key:
            return False
        if operator == "<" and version_key >= required_key:
            return False
        if operator == "~=":
            required_parts = required.split(".")
            prefix = required_parts[:-1] if len(required_parts) > 1 else required_parts
            matching_prefix = version.split(".")[: len(prefix)] == prefix
            if version_key < required_key or not matching_prefix:
                return False
    return True


def _locked_artifacts(package: dict[str, object]) -> list[dict[str, object]]:
    artifacts: list[dict[str, object]] = []
    sdist = package.get("sdist")
    if isinstance(sdist, dict):
        artifacts.append(sdist)
    wheels = package.get("wheels", [])
    if isinstance(wheels, list):
        artifacts.extend(item for item in wheels if isinstance(item, dict))
    return artifacts


def _manifest_dependencies(errors: list[str]) -> dict[str, str]:
    requirements_by_name: dict[str, str] = {}
    constraints_by_name: dict[str, list[str]] = {}
    build_requirements_by_name: dict[str, str] = {}
    manifests = [
        path
        for path in ROOT.rglob("pyproject.toml")
        if not IGNORED_PARTS.intersection(path.relative_to(ROOT).parts)
    ]
    for path in manifests:
        if path.is_symlink():
            errors.append(f"dependency manifest symlink is not allowed: {path}")
            continue
        try:
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            relative = path.relative_to(ROOT)
            errors.append(f"cannot read dependency manifest {relative}: {exc}")
            continue
        requirements: list[str] = []
        project = data.get("project", {})
        if isinstance(project, dict):
            project_dependencies = project.get("dependencies", [])
            if isinstance(project_dependencies, list):
                requirements.extend(project_dependencies)
            optional = project.get("optional-dependencies", {})
            if isinstance(optional, dict):
                for group in optional.values():
                    if isinstance(group, list):
                        requirements.extend(group)
        build = data.get("build-system", {})
        if isinstance(build, dict):
            build_requirements = build.get("requires", [])
            if isinstance(build_requirements, list):
                requirements.extend(build_requirements)
                for requirement in build_requirements:
                    if isinstance(requirement, str):
                        name = _requirement_name(requirement)
                        if name is not None:
                            match = REQUIREMENT_NAME.match(requirement.strip())
                            assert match is not None
                            constraint = (
                                requirement.strip()[match.end() :]
                                .split(";", 1)[0]
                                .strip()
                            )
                            build_requirements_by_name[name] = constraint or "*"
        groups = data.get("dependency-groups", {})
        if isinstance(groups, dict):
            for group in groups.values():
                if isinstance(group, list):
                    requirements.extend(item for item in group if isinstance(item, str))
        for requirement in requirements:
            if not isinstance(requirement, str):
                errors.append(f"invalid dependency requirement: {requirement!r}")
                continue
            name = _requirement_name(requirement)
            if name is None:
                errors.append(f"invalid dependency requirement: {requirement}")
            else:
                lowered = requirement.lower()
                if (
                    "@" in requirement
                    or "git+" in lowered
                    or "file:" in lowered
                    or "://" in requirement
                ):
                    errors.append(
                        f"unsupported Python dependency source: {requirement}"
                    )
                match = REQUIREMENT_NAME.match(requirement.strip())
                assert match is not None
                constraint = requirement.strip()[match.end() :].split(";", 1)[0].strip()
                requirements_by_name[name] = constraint or "*"
                constraints_by_name.setdefault(name, []).append(constraint or "*")

    for package_json in ROOT.rglob("package.json"):
        relative = package_json.relative_to(ROOT)
        if IGNORED_PARTS.intersection(relative.parts):
            continue
        try:
            data = json.loads(package_json.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        dependency_keys = (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        )
        if isinstance(data, dict) and any(data.get(key) for key in dependency_keys):
            errors.append(f"unsupported dependency reconciliation: npm ({relative})")
    for name in ("package-lock.json", "pnpm-lock.yaml", "yarn.lock"):
        for lock_path in ROOT.rglob(name):
            relative = lock_path.relative_to(ROOT)
            if not IGNORED_PARTS.intersection(relative.parts):
                errors.append(
                    f"unsupported dependency reconciliation: npm ({relative})"
                )
    for go_mod in ROOT.rglob("go.mod"):
        relative = go_mod.relative_to(ROOT)
        contents = go_mod.read_text(encoding="utf-8")
        if not IGNORED_PARTS.intersection(relative.parts) and re.search(
            r"(?m)^\s*require(?:\s|\()", contents
        ):
            errors.append(f"unsupported dependency reconciliation: go ({relative})")
    for go_sum in ROOT.rglob("go.sum"):
        relative = go_sum.relative_to(ROOT)
        if (
            not IGNORED_PARTS.intersection(relative.parts)
            and go_sum.read_text(encoding="utf-8").strip()
        ):
            errors.append(f"unsupported dependency reconciliation: go ({relative})")
    for cargo_toml in ROOT.rglob("Cargo.toml"):
        relative = cargo_toml.relative_to(ROOT)
        if IGNORED_PARTS.intersection(relative.parts):
            continue
        try:
            cargo = tomllib.loads(cargo_toml.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError):
            continue
        if any(
            key in cargo
            for key in ("dependencies", "dev-dependencies", "build-dependencies")
        ):
            errors.append(f"unsupported dependency reconciliation: cargo ({relative})")
    for cargo_lock in ROOT.rglob("Cargo.lock"):
        relative = cargo_lock.relative_to(ROOT)
        if not IGNORED_PARTS.intersection(relative.parts):
            errors.append(f"unsupported dependency reconciliation: cargo ({relative})")

    dependencies = dict(requirements_by_name)
    locked_names: set[str] = set()
    locked_graph: dict[str, set[str]] = {}
    lock = ROOT / "uv.lock"
    if lock.is_file():
        try:
            lock_data = tomllib.loads(lock.read_text(encoding="utf-8"))
        except (OSError, tomllib.TOMLDecodeError) as exc:
            errors.append(f"cannot read uv.lock: {exc}")
        else:
            for package in lock_data.get("package", []):
                if not isinstance(package, dict):
                    errors.append("malformed uv.lock package entry")
                    continue
                source = package.get("source", {})
                if not isinstance(source, dict):
                    errors.append("malformed uv.lock package source")
                    continue
                if "registry" in source:
                    name = package.get("name")
                    version = package.get("version")
                    if isinstance(name, str) and isinstance(version, str):
                        normalized_name = name.lower().replace("_", "-")
                        if source["registry"] != "https://pypi.org/simple":
                            errors.append(f"unexpected registry for {normalized_name}")
                        artifacts = _locked_artifacts(package)
                        if not artifacts:
                            errors.append(
                                f"locked distribution missing hashes: {normalized_name}"
                            )
                        for artifact in artifacts:
                            artifact_url = artifact.get("url")
                            parsed_url = (
                                urlparse(artifact_url)
                                if isinstance(artifact_url, str)
                                else None
                            )
                            if (
                                parsed_url is None
                                or parsed_url.scheme != "https"
                                or parsed_url.hostname != "files.pythonhosted.org"
                            ):
                                errors.append(
                                    "unexpected locked artifact host for "
                                    f"{normalized_name}"
                                )
                            artifact_hash = artifact.get("hash")
                            if not isinstance(artifact_hash, str) or not re.fullmatch(
                                r"sha256:[0-9a-f]{64}", artifact_hash
                            ):
                                errors.append(
                                    "locked distribution missing SHA-256 hash: "
                                    f"{normalized_name}"
                                )
                        dependencies[normalized_name] = version
                        locked_names.add(normalized_name)
                        locked_dependencies = package.get("dependencies", [])
                        locked_graph[normalized_name] = {
                            dependency["name"].lower().replace("_", "-")
                            for dependency in locked_dependencies
                            if isinstance(dependency, dict)
                            and isinstance(dependency.get("name"), str)
                        }
                elif "virtual" not in source:
                    errors.append(
                        f"unsupported locked dependency source: {package.get('name')}"
                    )
    if lock.is_file():
        for name in sorted(requirements_by_name.keys() - locked_names):
            errors.append(f"dependency not resolved in uv.lock: {name}")
    else:
        for name in sorted(requirements_by_name):
            errors.append(f"dependency not resolved in uv.lock: {name}")
    for name, constraints in constraints_by_name.items():
        version = dependencies.get(name)
        if version is not None and any(
            not _satisfies_constraint(version, constraint) for constraint in constraints
        ):
            errors.append(f"locked version violates manifest constraint: {name}")
    build_closure: set[str] = set()
    pending = list(build_requirements_by_name)
    while pending:
        name = pending.pop()
        if name in build_closure:
            continue
        build_closure.add(name)
        pending.extend(locked_graph.get(name, set()) - build_closure)
    for name in sorted(build_closure):
        version = dependencies.get(name)
        constraint = build_requirements_by_name.get(name)
        if version is None or constraint != f"=={version}":
            errors.append(f"build dependency closure is not exactly pinned: {name}")
    return dependencies


def _check_dependencies(errors: list[str]) -> None:
    rows = _dependency_rows(errors)
    expected = _manifest_dependencies(errors)
    for dependency in sorted(expected.keys() - rows.keys()):
        errors.append(f"dependency missing from inventory: {dependency}")
    for dependency in sorted(rows.keys() - expected.keys()):
        errors.append(f"stale dependency inventory row: {dependency}")
    for dependency, row in rows.items():
        _, version, expression, review_status, obligations, notice, source = row
        if dependency in expected and version != expected[dependency]:
            errors.append(
                f"dependency version drift: {dependency} "
                f"(inventory {version}, expected {expected[dependency]})"
            )
        if review_status.lower() != "reviewed":
            errors.append(f"dependency is unreviewed: {dependency}")
        if not _valid_spdx(expression):
            errors.append(f"invalid SPDX expression for {dependency}: {expression}")
        if any(identifier in expression for identifier in FORBIDDEN_SPDX):
            errors.append(f"dependency has forbidden license: {dependency}")
        if not obligations or not notice or not source:
            errors.append(f"dependency review is incomplete: {dependency}")


def _check_uv_lock(errors: list[str]) -> None:
    if not (ROOT / "pyproject.toml").is_file() or not (ROOT / "uv.lock").is_file():
        return
    try:
        result = subprocess.run(
            ["uv", "lock", "--check", "--offline"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        errors.append(f"cannot validate uv.lock offline: {exc}")
        return
    if result.returncode:
        detail = (result.stdout + result.stderr).strip()
        errors.append(f"uv.lock is stale or invalid: {detail}")


def verify() -> list[str]:
    errors: list[str] = []
    source_tree = _source_tree_paths(errors)
    inventory = _read_provenance(errors, source_tree)
    _check_source_provenance(inventory, errors)
    _check_package_metadata(errors)
    _check_archives(errors)
    _check_dependencies(errors)
    _check_uv_lock(errors)
    return errors


def main() -> int:
    errors = verify()
    if errors:
        for error in errors:
            print(error)
        return 1
    print("legal verification passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
