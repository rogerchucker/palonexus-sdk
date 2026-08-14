# SPDX-License-Identifier: MIT
from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from scripts import verify_published_developer_workflow as verifier


def test_fresh_install_verifier_checks_exact_pypi_scaffold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[tuple[list[str], Path | None]] = []
    pnxs = tmp_path / "bin" / "pnxs"
    workspace = tmp_path / "workspace"

    def fake_run(
        argv: list[str], cwd: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        calls.append((argv, cwd))
        if argv == [str(pnxs), "version", "--json"]:
            return subprocess.CompletedProcess(
                argv,
                0,
                json.dumps({"version": "1.2.3", "source_revision": "a" * 40}),
                "",
            )
        if argv[:3] == [str(pnxs), "agents", "init"]:
            project = Path(argv[3])
            project.mkdir(parents=True)
            (project / "agent.py").write_text("import palonexus\n", encoding="utf-8")
            (project / "pyproject.toml").write_text(
                '[project]\ndependencies=["palonexus==1.2.3"]\n', encoding="utf-8"
            )
            (project / "uv.lock").write_text(
                'version=1\n[[package]]\nname="palonexus"\nversion="1.2.3"\n'
                'source={registry="https://pypi.org/simple"}\n',
                encoding="utf-8",
            )
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(verifier, "run_checked", fake_run)
    verifier.verify_published_workflow(
        expected_version="1.2.3",
        expected_revision="a" * 40,
        pnxs=pnxs,
        workspace=workspace,
    )

    project = workspace / "release-risk-reviewer"
    assert calls == [
        ([str(pnxs), "version", "--json"], None),
        (
            [
                str(pnxs),
                "agents",
                "init",
                str(project),
                "--name",
                "release-risk-reviewer",
                "--allow-file-credential-store",
            ],
            None,
        ),
        (["uv", "sync", "--frozen"], project),
        (
            [
                "uv",
                "run",
                "--frozen",
                "python",
                "-c",
                "import palonexus; import agent",
            ],
            project,
        ),
        (
            ["uv", "run", "--frozen", "python", "-m", "compileall", "-q", "agent.py"],
            project,
        ),
    ]
    assert not (project / ".pnxs").exists()
