# SPDX-License-Identifier: MIT
"""Build and verify the public Python distributions in clean environments."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
FORBIDDEN_PATH_PARTS = frozenset(
    {
        ".git",
        ".venv",
        "examples",
        "foundation_tests",
        "guard",
        "plugins",
        "protocol",
        "tests",
    }
)
FORBIDDEN_BYTE_MARKERS = (
    str(ROOT).encode(),
    b"/Users/",
    b"BEGIN OPENSSH PRIVATE KEY",
    b"BEGIN PRIVATE KEY",
    b"ghp_",
    b"github_pat_",
    b"sk-proj-",
)
SMOKE = """\
from importlib.metadata import metadata, version
from importlib.resources import files

import palonexus
from palonexus import ActionRequestBuilder, AuthorizationClient

distribution = metadata("palonexus")
assert distribution["License-Expression"] == "MIT"
assert version("palonexus")
assert files("palonexus").joinpath("py.typed").is_file()
assert ActionRequestBuilder is palonexus.ActionRequestBuilder
assert AuthorizationClient is palonexus.AuthorizationClient
print("ARTIFACT_IMPORT_OK")
"""


def _run(
    command: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
) -> None:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        text=True,
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"command failed ({result.returncode}): {' '.join(command)}\n"
            f"{result.stdout}{result.stderr}"
        )


def _safe_member(name: str, *, sdist: bool) -> bool:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts:
        return False
    relevant_parts = path.parts[1:] if sdist else path.parts
    return not FORBIDDEN_PATH_PARTS.intersection(relevant_parts)


def _verify_payload(name: str, payload: bytes) -> None:
    for marker in FORBIDDEN_BYTE_MARKERS:
        if marker in payload:
            raise RuntimeError(f"forbidden private marker in artifact member: {name}")


def _verify_wheel(path: Path) -> None:
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if "palonexus/py.typed" not in names:
            raise RuntimeError("wheel does not contain palonexus/py.typed")
        for name in names:
            if not _safe_member(name, sdist=False):
                raise RuntimeError(f"wheel crossed package boundary: {name}")
            if not name.endswith("/"):
                _verify_payload(name, archive.read(name))


def _verify_sdist(path: Path) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        roots = {PurePosixPath(member.name).parts[0] for member in members}
        if len(roots) != 1:
            raise RuntimeError("sdist must have exactly one top-level directory")
        marker_found = False
        for member in members:
            if not _safe_member(member.name, sdist=True):
                raise RuntimeError(f"sdist crossed package boundary: {member.name}")
            if member.issym() or member.islnk():
                raise RuntimeError(f"sdist contains a link: {member.name}")
            if not member.isfile():
                continue
            if member.name.endswith("/src/palonexus/py.typed"):
                marker_found = True
            stream = archive.extractfile(member)
            if stream is None:
                raise RuntimeError(f"cannot read sdist member: {member.name}")
            _verify_payload(member.name, stream.read())
        if not marker_found:
            raise RuntimeError("sdist does not contain src/palonexus/py.typed")


def _python_in(venv: Path) -> Path:
    return venv / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def _install_and_smoke(artifact: Path, clean_root: Path) -> None:
    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("VIRTUAL_ENV", None)
    venv = clean_root / f"venv-{artifact.name.replace('.', '-')}"
    _run(
        ["uv", "venv", "--python", os.environ.get("UV_PYTHON", "3.12"), str(venv)],
        cwd=clean_root,
    )
    python = _python_in(venv)
    _run(
        [
            "uv",
            "pip",
            "install",
            "--python",
            str(python),
            str(artifact),
        ],
        cwd=clean_root,
        env=environment,
    )
    smoke = clean_root / f"smoke-{artifact.name}.py"
    smoke.write_text(SMOKE, encoding="utf-8")
    _run([str(python), "-I", str(smoke)], cwd=clean_root, env=environment)
    for profile in ("python-basic", "python-async"):
        example = clean_root / f"{artifact.name}-{profile}.py"
        shutil.copy2(ROOT / "examples" / profile / "main.py", example)
        _run([str(python), "-I", str(example)], cwd=clean_root, env=environment)


def _exactly_one(paths: Iterable[Path], kind: str) -> Path:
    candidates = list(paths)
    if len(candidates) != 1:
        raise RuntimeError(f"expected one {kind}, found {len(candidates)}")
    return candidates[0]


def verify(*, keep_build: Path | None = None) -> None:
    with tempfile.TemporaryDirectory(prefix="palonexus-artifacts-") as directory:
        clean_root = Path(directory)
        dist = clean_root / "dist"
        dist.mkdir()
        _run(
            [
                "uv",
                "build",
                "--package",
                "palonexus",
                "--out-dir",
                str(dist),
            ],
            cwd=ROOT,
        )
        wheel = _exactly_one(dist.glob("palonexus-*.whl"), "wheel")
        sdist = _exactly_one(dist.glob("palonexus-*.tar.gz"), "sdist")
        _verify_wheel(wheel)
        _verify_sdist(sdist)
        _install_and_smoke(wheel, clean_root)
        _install_and_smoke(sdist, clean_root)
        if keep_build is not None:
            keep_build.mkdir(parents=True, exist_ok=True)
            shutil.copy2(wheel, keep_build / wheel.name)
            shutil.copy2(sdist, keep_build / sdist.name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--keep-build",
        type=Path,
        help="copy verified artifacts to this directory",
    )
    arguments = parser.parse_args()
    verify(keep_build=arguments.keep_build)
    print("Python wheel and sdist passed clean-room verification.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
