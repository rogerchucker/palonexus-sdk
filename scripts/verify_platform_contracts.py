# SPDX-License-Identifier: MIT
"""Verify mirrored developer schemas against an exact platform checkout."""

from __future__ import annotations

import argparse
import os
import stat
import sys
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA_DIRECTORY = PurePosixPath("contracts/developer")
SCHEMA_SUFFIX = ".schema.json"


class ContractVerificationError(RuntimeError):
    """A platform contract pin or mirror is incomplete or inconsistent."""


def _load_declared_paths(sdk_root: Path) -> tuple[str, ...]:
    pyproject = sdk_root / "python/pyproject.toml"
    try:
        document: dict[str, Any] = tomllib.loads(pyproject.read_text(encoding="utf-8"))
        raw_paths = document["tool"]["palonexus"]["platform-contract"]["schema-paths"]
    except (KeyError, OSError, tomllib.TOMLDecodeError) as error:
        raise ContractVerificationError(
            f"cannot load platform contract schema paths from {pyproject}: {error}"
        ) from error

    if not isinstance(raw_paths, list) or not all(
        isinstance(path, str) for path in raw_paths
    ):
        raise ContractVerificationError("schema paths must be a list of strings")
    if raw_paths != sorted(set(raw_paths)):
        raise ContractVerificationError("schema paths must be sorted and unique")

    for raw_path in raw_paths:
        path = PurePosixPath(raw_path)
        if (
            not raw_path
            or "\\" in raw_path
            or "\x00" in raw_path
            or path.is_absolute()
            or ".." in path.parts
            or path.as_posix() != raw_path
            or path.parts[:2] != SCHEMA_DIRECTORY.parts
            or len(path.parts) < 3
            or not path.name.endswith(SCHEMA_SUFFIX)
        ):
            raise ContractVerificationError(f"unsafe schema path: {raw_path!r}")
    return tuple(raw_paths)


def _directory_mode(path: Path, *, role: str) -> int | None:
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(mode):
        raise ContractVerificationError(f"{role} path component is a symlink: {path}")
    if not stat.S_ISDIR(mode):
        raise ContractVerificationError(
            f"{role} path component is not a directory: {path}"
        )
    return mode


def _schema_root(root: Path, *, role: str) -> Path | None:
    current = root
    if _directory_mode(current, role=role) is None:
        raise ContractVerificationError(f"{role} repository root is missing: {root}")
    for part in SCHEMA_DIRECTORY.parts:
        current /= part
        if _directory_mode(current, role=role) is None:
            return None
    return current


def _walk_schema_tree(
    directory: Path, root: Path, *, role: str, discovered: list[str]
) -> None:
    with os.scandir(directory) as entries:
        for entry in sorted(entries, key=lambda value: value.name):
            path = Path(entry.path)
            mode = entry.stat(follow_symlinks=False).st_mode
            if stat.S_ISLNK(mode):
                raise ContractVerificationError(
                    f"{role} schema entry is a symlink: {path}"
                )
            if stat.S_ISDIR(mode):
                _walk_schema_tree(path, root, role=role, discovered=discovered)
                continue
            if not stat.S_ISREG(mode):
                raise ContractVerificationError(
                    f"{role} schema entry is not a regular file: {path}"
                )
            if not entry.name.endswith(SCHEMA_SUFFIX):
                raise ContractVerificationError(
                    f"{role} schema tree contains an unexpected file: {path}"
                )
            discovered.append(path.relative_to(root).as_posix())


def _discover_schema_paths(root: Path, *, role: str) -> tuple[str, ...]:
    schema_root = _schema_root(root, role=role)
    if schema_root is None:
        return ()
    discovered: list[str] = []
    _walk_schema_tree(schema_root, root, role=role, discovered=discovered)
    return tuple(sorted(discovered))


def verify_platform_contracts(sdk_root: Path, platform_root: Path) -> int:
    """Require declared, mirrored, and canonical schema sets and bytes to agree."""

    declared = _load_declared_paths(sdk_root)
    mirrored = _discover_schema_paths(sdk_root, role="SDK mirror")
    canonical = _discover_schema_paths(platform_root, role="platform canonical")
    if not (declared == mirrored == canonical):
        raise ContractVerificationError(
            "schema path sets differ: "
            f"listed={list(declared)!r}, mirrored={list(mirrored)!r}, "
            f"canonical={list(canonical)!r}"
        )

    for relative_path in declared:
        mirrored_bytes = (sdk_root / relative_path).read_bytes()
        canonical_bytes = (platform_root / relative_path).read_bytes()
        if mirrored_bytes != canonical_bytes:
            raise ContractVerificationError(f"schema bytes differ: {relative_path}")
    return len(declared)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", type=Path, required=True)
    parser.add_argument("--platform-root", type=Path, required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        count = verify_platform_contracts(
            Path(os.path.abspath(args.sdk_root)),
            Path(os.path.abspath(args.platform_root)),
        )
    except (ContractVerificationError, OSError) as error:
        print(f"platform contract verification failed: {error}", file=sys.stderr)
        return 1
    print(f"verified {count} canonical developer schema(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
