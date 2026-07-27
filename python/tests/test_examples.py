# SPDX-License-Identifier: MIT
"""Executable contracts for the dependency-free core Python examples."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).parents[2]
EXAMPLES = (
    ROOT / "examples/python-basic/main.py",
    ROOT / "examples/python-async/main.py",
)
MARKERS = (
    "DENIED_EXECUTED_ZERO",
    "APPROVAL_REQUIRED_EXECUTED_ZERO",
    "APPROVAL_APPROVED",
    "RESUMED_ALLOW",
    "EXECUTED_ONCE",
    "AUDIT_CORRELATED",
)


@pytest.mark.parametrize("example", EXAMPLES, ids=("sync", "async"))
def test_core_example_runs_full_governed_lifecycle_offline(
    example: Path,
    tmp_path: Path,
) -> None:
    blocker = tmp_path / "sitecustomize.py"
    blocker.write_text(
        "import socket\n"
        "def blocked(*args, **kwargs):\n"
        "    raise AssertionError('network access is forbidden')\n"
        "socket.create_connection = blocked\n"
        "socket.socket.connect = blocked\n",
        encoding="utf-8",
    )
    environment = os.environ.copy()
    existing = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = (
        str(tmp_path) if not existing else os.pathsep.join((str(tmp_path), existing))
    )

    result = subprocess.run(
        [sys.executable, str(example)],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stderr == ""
    assert result.stdout.splitlines() == list(MARKERS)


@pytest.mark.parametrize("example", EXAMPLES, ids=("sync", "async"))
def test_core_example_uses_public_sdk_and_synthetic_inventory_only(
    example: Path,
) -> None:
    source = example.read_text(encoding="utf-8")

    assert "inventory" in source
    assert "palonexus._" not in source
    assert "python.tests" not in source
    assert "tests." not in source
    assert "http://" not in source
    assert "https://" not in source
    assert "socket" not in source
    assert "subprocess" not in source
