# SPDX-License-Identifier: MIT
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from importlib.resources import files
from pathlib import Path

from packaging.version import InvalidVersion, Version


class ScaffoldError(RuntimeError):
    """A scaffold input or local tool failed validation."""


def run_checked(argv: list[str], cwd: Path) -> None:
    try:
        subprocess.run(argv, cwd=cwd, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise ScaffoldError("uv could not create the project lock") from error


def preflight_plain_python(
    project: Path,
    name: str,
    sdk_version: str,
) -> str:
    if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name):
        raise ScaffoldError("agent name must be a lowercase DNS label")
    try:
        version = str(Version(sdk_version))
    except InvalidVersion as error:
        raise ScaffoldError("installed palonexus version is invalid") from error
    if project.is_symlink() or (project.exists() and not project.is_dir()):
        raise ScaffoldError("target path must be an empty directory")
    if project.exists() and any(project.iterdir()):
        raise ScaffoldError("target directory must be empty")
    return version


def initialize_plain_python(
    project: Path,
    name: str,
    sdk_version: str,
) -> None:
    project = project.absolute()
    version = preflight_plain_python(project, name, sdk_version)
    missing_parents: list[Path] = []
    cursor = project.parent
    while not cursor.exists():
        missing_parents.append(cursor)
        cursor = cursor.parent
    project.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{project.name}.pnxs-", dir=project.parent))

    try:
        template_root = files("palonexus.developer.templates.plain_python")
        for source_name, destination in (
            ("agent.py", stage / "agent.py"),
            ("palonexus-agent.yaml", stage / "palonexus-agent.yaml"),
            ("fixtures/release-change.json", stage / "fixtures/release-change.json"),
        ):
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(
                template_root.joinpath(source_name)
                .read_text(encoding="utf-8")
                .replace("release-risk-reviewer", name),
                encoding="utf-8",
            )
        pyproject = template_root.joinpath("pyproject.toml.tmpl").read_text(
            encoding="utf-8"
        )
        pyproject = pyproject.replace("@AGENT_NAME@", name).replace(
            "@SDK_VERSION@", version
        )
        (stage / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        run_checked(["uv", "lock"], stage)

        if project.exists():
            preflight_plain_python(project, name, version)
            moved: list[tuple[Path, Path]] = []
            try:
                for source in sorted(stage.iterdir(), key=lambda path: path.name):
                    destination = project / source.name
                    if destination.exists() or destination.is_symlink():
                        raise OSError("target directory changed")
                    os.rename(source, destination)
                    moved.append((source, destination))
            except OSError as error:
                for source, destination in reversed(moved):
                    try:
                        os.rename(destination, source)
                    except OSError:
                        pass
                raise ScaffoldError(
                    "target directory changed during initialization"
                ) from error
        else:
            try:
                os.replace(stage, project)
            except OSError as error:
                raise ScaffoldError(
                    "project scaffold could not be installed"
                ) from error
    finally:
        if stage.exists():
            shutil.rmtree(stage)
        for parent in missing_parents:
            try:
                parent.rmdir()
            except OSError:
                break
