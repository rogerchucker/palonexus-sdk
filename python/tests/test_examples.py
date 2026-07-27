# SPDX-License-Identifier: MIT
"""Executable contracts for the dependency-free core Python examples."""

from __future__ import annotations

import ast
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
    "REPLAY_BLOCKED",
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
        "import sys\n"
        "def blocked(*args, **kwargs):\n"
        "    raise AssertionError('network access is forbidden')\n"
        "def audit(event, args):\n"
        "    if event in {'socket.connect', 'socket.getaddrinfo', 'socket.sendto'}:\n"
        "        blocked()\n"
        "sys.addaudithook(audit)\n"
        "socket.create_connection = blocked\n"
        "socket.getaddrinfo = blocked\n"
        "socket.gethostbyname = blocked\n"
        "socket.gethostbyname_ex = blocked\n"
        "socket.socket.connect = blocked\n"
        "socket.socket.connect_ex = blocked\n"
        "socket.socket.sendto = blocked\n",
        encoding="utf-8",
    )
    environment = {
        "HOME": str(tmp_path),
        "LANG": "C.UTF-8",
        "PATH": os.environ.get("PATH", ""),
        "PYTHONHASHSEED": "0",
        "PYTHONPATH": str(tmp_path),
    }

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
    tree = ast.parse(source, filename=str(example))
    imported_modules = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    } | {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }

    assert "inventory" in source
    assert imported_modules <= (
        sys.stdlib_module_names | {"__future__", "palonexus", "palonexus.testing"}
    )
    assert {
        module for module in imported_modules if module.startswith("palonexus")
    } <= {"palonexus", "palonexus.testing"}
    assert "http://" not in source
    assert "https://" not in source
