from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = ROOT / ".github" / "workflows"
REQUIRED_FILES = (
    WORKFLOWS / "ci.yml",
    WORKFLOWS / "codeql.yml",
    WORKFLOWS / "dependency-review.yml",
    ROOT / ".github" / "dependabot.yml",
    ROOT / ".gitleaks.toml",
    ROOT / "scripts" / "verify",
)
ACTION_PIN = re.compile(
    r"(?m)^\s*uses:\s*"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)?)"
    r"@(?P<sha>[0-9a-f]{40})\s+#\s+v[0-9][A-Za-z0-9.-]*\s*$"
)
APPROVED_ACTION_OWNERS = {"actions", "astral-sh", "github"}


def _yaml(path: Path) -> dict[str, Any]:
    value = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(value, dict), path
    return value


def _workflow_texts() -> dict[Path, str]:
    return {
        path: path.read_text(encoding="utf-8")
        for path in sorted(WORKFLOWS.glob("*.yml"))
    }


def _assert_pinned_actions(path: Path, text: str) -> None:
    uses_lines = [
        line.strip() for line in text.splitlines() if line.strip().startswith("uses:")
    ]
    matches = list(ACTION_PIN.finditer(text))
    assert uses_lines, f"{path} has no pinned action evidence"
    assert len(matches) == len(uses_lines), (
        f"{path} must pin every action to a full SHA and annotate its source version"
    )
    for match in matches:
        owner = match.group("action").split("/", 1)[0]
        assert owner in APPROVED_ACTION_OWNERS, (
            f"{path} uses unapproved action owner {owner}"
        )


def _steps_text(job: dict[str, Any]) -> str:
    steps = job.get("steps", [])
    assert isinstance(steps, list)
    return "\n".join(
        str(step.get("run", "")) for step in steps if isinstance(step, dict)
    )


def test_foundation_ci_files_exist() -> None:
    missing = [
        path.relative_to(ROOT).as_posix()
        for path in REQUIRED_FILES
        if not path.is_file()
    ]
    assert not missing, f"missing foundation CI files: {missing}"


def test_workflows_are_valid_yaml_with_least_privilege_and_immutable_actions() -> None:
    texts = _workflow_texts()
    assert set(texts) == {
        WORKFLOWS / "ci.yml",
        WORKFLOWS / "codeql.yml",
        WORKFLOWS / "dependency-review.yml",
        WORKFLOWS / "python.yml",
        WORKFLOWS / "release.yml",
    }
    for path, text in texts.items():
        workflow = _yaml(path)
        assert "pull_request_target" not in workflow.get("on", {})
        permissions = workflow.get("permissions")
        assert isinstance(permissions, dict)
        assert permissions.get("contents") == "read"
        assert "write-all" not in text
        assert "read-all" not in text
        assert "permissions: write" not in text
        assert "persist-credentials: true" not in text
        assert re.search(r"(?m)^\s*timeout-minutes:\s*[0-9]+\s*$", text)
        _assert_pinned_actions(path, text)


def test_ci_runs_complete_supported_foundation_matrix_without_unsafe_caches() -> None:
    path = WORKFLOWS / "ci.yml"
    workflow = _yaml(path)
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    assert {
        "python",
        "go",
        "secret-scan",
        "dco",
        "host-feasibility",
    } <= set(jobs)

    python = jobs["python"]
    strategy = python["strategy"]
    assert strategy["fail-fast"] == "false"
    assert strategy["matrix"]["python-version"] == ["3.12", "3.13"]
    python_commands = _steps_text(python)
    assert "uv sync --frozen" in python_commands
    assert "scripts/verify --python-only" in python_commands

    verify_text = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
    for command in (
        "uv lock --check --offline",
        "uv run --frozen --offline --no-sync ruff format --check",
        "uv run --frozen --offline --no-sync ruff check",
        # Pinned whole so the SDK suite cannot silently fall out of the single
        # verification entrypoint again. `python/tests` was covered only by the
        # separate Python SDK workflow, so a broken SDK suite looked green to
        # anyone running `scripts/verify` locally.
        "uv run --frozen --offline --no-sync pytest \\\n"
        "        foundation_tests protocol/tests python/tests -q",
        "uv run --frozen --offline --no-sync "
        "python scripts/generate_protocol.py --check",
        "uv run --frozen --offline --no-sync python scripts/verify_legal.py",
    ):
        assert command in verify_text
    uv_run_lines = [
        line.strip() for line in verify_text.splitlines() if "uv run " in line
    ]
    assert uv_run_lines
    assert all(
        line.startswith("uv run --frozen --offline --no-sync ") for line in uv_run_lines
    )

    go = jobs["go"]
    go_commands = _steps_text(go)
    assert go["name"] == "Go 1.25.12"
    assert "scripts/verify --go-only" in go_commands
    assert re.search(r'gofmt"?\s+-l\s+guard', verify_text)
    for command in ("go vet ./...", "go test ./..."):
        assert command in verify_text
    assert "GOTOOLCHAIN=go1.25.12+auto" in verify_text
    assert "go version go1.25.12 " in verify_text

    text = path.read_text(encoding="utf-8")
    assert "enable-cache: false" in text
    assert "cache: false" in text
    assert "actions/cache" not in text
    # Both suites sync: the Go suite differentially tests against the Python
    # reference canonicalizer, so it needs the same locked environment.
    assert text.count("uv sync --frozen") == 2
    assert "uv sync --frozen" in _steps_text(python)
    assert "uv sync --frozen" in go_commands
    assert "uv run " not in text
    setup_go_steps = [
        step
        for job in jobs.values()
        for step in job.get("steps", [])
        if isinstance(step, dict) and "actions/setup-go@" in step.get("uses", "")
    ]
    assert setup_go_steps
    assert all(step["with"]["go-version"] == "1.25.12" for step in setup_go_steps)
    assert all(step["with"]["cache"] == "false" for step in setup_go_steps)
    assert not re.search(r"(?i)(?:^|[^A-Za-z])pip(?:3)?(?:[^A-Za-z]|$)", text)
    assert "curl " not in text
    assert "wget " not in text
    assert text.count("go run github.com/zricethezav/gitleaks/v8@v8.30.1") == 1
    assert text.count("--config .gitleaks.toml") == 1
    assert re.search(r"gitleaks/v8@v8\.30\.1\s+git\b", text)


def test_ci_keeps_dco_provenance_and_unresolved_gate0_machine_enforced() -> None:
    workflow = _yaml(WORKFLOWS / "ci.yml")
    jobs = workflow["jobs"]

    dco = jobs["dco"]
    assert "if" not in dco
    dco_commands = _steps_text(dco)
    assert "scripts/verify --dco-range" in dco_commands
    assert "scripts/verify --dco-commit" in dco_commands

    host = jobs["host-feasibility"]
    assert "if" not in host
    assert "continue-on-error" not in host
    assert "scripts/verify --host-gate-only" in _steps_text(host)
    assert "not ready" in str(host.get("name", "")).lower()
    host_text = str(host)
    assert "uv sync" not in host_text
    assert "setup-uv" not in host_text

    assert "scripts/verify --python-only" in _steps_text(jobs["python"])


def test_codeql_covers_python_and_go_with_only_required_write_permission() -> None:
    workflow = _yaml(WORKFLOWS / "codeql.yml")
    assert workflow["permissions"] == {
        "contents": "read",
        "security-events": "write",
    }
    job = workflow["jobs"]["analyze"]
    matrix = job["strategy"]["matrix"]["include"]
    assert matrix == [
        {"language": "python", "build-mode": "none"},
        {"language": "go", "build-mode": "manual"},
    ]
    steps = job["steps"]
    setup_go = next(
        step for step in steps if "actions/setup-go@" in step.get("uses", "")
    )
    assert setup_go["if"] == "matrix.language == 'go'"
    assert setup_go["with"] == {"go-version": "1.25.12", "cache": "false"}
    manual_build = next(step for step in steps if step.get("name") == "Build Go")
    assert manual_build["if"] == "matrix.language == 'go'"
    # CodeQL needs the product code compiled under its tracer, not exercised. The
    # suite itself runs in Foundation CI, which owns the private temp root the
    # keystore and state store require.
    assert manual_build["run"] == "GOTOOLCHAIN=go1.25.12+auto go build ./..."
    init_index = next(
        index
        for index, step in enumerate(steps)
        if "github/codeql-action/init@" in step.get("uses", "")
    )
    build_index = steps.index(manual_build)
    analyze_index = next(
        index
        for index, step in enumerate(steps)
        if "github/codeql-action/analyze@" in step.get("uses", "")
    )
    assert init_index < build_index < analyze_index
    text = (WORKFLOWS / "codeql.yml").read_text(encoding="utf-8")
    assert "github/codeql-action/init@" in text
    assert "github/codeql-action/analyze@" in text
    assert "build-mode: ${{ matrix.build-mode }}" in text
    assert "language: go\n            build-mode: none" not in text


def test_dependency_review_is_pull_request_only_and_enforces_policy() -> None:
    workflow = _yaml(WORKFLOWS / "dependency-review.yml")
    assert set(workflow["on"]) == {"pull_request"}
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["dependency-review"]
    text = (WORKFLOWS / "dependency-review.yml").read_text(encoding="utf-8")
    assert "actions/dependency-review-action@" in text
    assert "fail-on-severity: moderate" in text
    assert "license-check: true" in text
    assert "vulnerability-check: true" in text
    assert "deny-licenses:" in text
    assert "continue-on-error" not in job


def test_dependabot_covers_every_foundation_package_ecosystem() -> None:
    config = _yaml(ROOT / ".github" / "dependabot.yml")
    assert config["version"] == "2"
    updates = config["updates"]
    assert isinstance(updates, list)
    assert {update["package-ecosystem"] for update in updates} == {
        "github-actions",
        "gomod",
        "pip",
    }
    for update in updates:
        assert update["directory"] == "/"
        assert update["schedule"]["interval"] == "weekly"
        assert update["open-pull-requests-limit"] == "5"


def test_gitleaks_extends_reviewed_defaults_without_broad_allowlist() -> None:
    text = (ROOT / ".gitleaks.toml").read_text(encoding="utf-8")
    assert "[extend]" in text
    assert "useDefault = true" in text
    assert "[allowlist]" not in text
    assert "paths" not in text
    assert "regexes" not in text


def test_gitleaks_false_positives_are_ignored_only_by_exact_fingerprint() -> None:
    ignore = ROOT / ".gitleaksignore"
    fingerprints = ignore.read_text(encoding="utf-8").splitlines()
    # Pinned so that adding an ignore entry requires reviewing this test.
    assert len(fingerprints) == 33
    assert len(set(fingerprints)) == len(fingerprints)
    assert all(
        re.fullmatch(
            r"[0-9a-f]{40}:[A-Za-z0-9_./-]+"
            r":(?:generic-api-key|curl-auth-header|jwt):[0-9]+",
            fingerprint,
        )
        for fingerprint in fingerprints
    )
    assert all("*" not in fingerprint for fingerprint in fingerprints)


def test_verification_entrypoint_is_cwd_independent_and_has_stable_modes(
    tmp_path: Path,
) -> None:
    verify = ROOT / "scripts" / "verify"
    help_result = subprocess.run(
        [str(verify), "--help"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert help_result.returncode == 0
    assert "--host-gate-only" in help_result.stdout
    assert "--dco-commit" in help_result.stdout
    assert "--dco-range" in help_result.stdout
    assert "uv sync --frozen" in help_result.stdout
    assert "offline" in help_result.stdout.lower()

    invalid = subprocess.run(
        [str(verify), "--unknown"],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert invalid.returncode == 64

    head = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    # `--dco-commit` always inspects the repository containing the script, so this
    # asserts cwd-independence rather than a property of HEAD itself. On a pull
    # request the checked-out HEAD is GitHub's synthetic merge commit, which carries
    # no sign-off, so requiring a 0 here would fail for reasons unrelated to cwd.
    # Real history is covered by the dedicated `dco` job, which runs `--dco-range`
    # over the actual commits with full depth.
    dco_from_tmp = subprocess.run(
        [str(verify), "--dco-commit", head],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    dco_from_root = subprocess.run(
        [str(verify), "--dco-commit", head],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert dco_from_tmp.returncode == dco_from_root.returncode
    assert dco_from_tmp.stdout == dco_from_root.stdout
    assert dco_from_tmp.stderr == dco_from_root.stderr
    assert dco_from_tmp.returncode in (0, 65)

    if not (ROOT / "scripts" / "verify_host_fixtures.py").is_file():
        host = subprocess.run(
            [str(verify), "--host-gate-only"],
            cwd=tmp_path,
            check=False,
            capture_output=True,
            text=True,
        )
        assert host.returncode == 78
        assert "not ready" in host.stderr.lower()


def test_host_gate_uses_system_python_without_syncing_project_dependencies() -> None:
    verify_text = (ROOT / "scripts" / "verify").read_text(encoding="utf-8")
    host_function = verify_text.split("run_host_gate() {", 1)[1].split("\n}", 1)[0]
    assert 'python3 "$verifier"' in host_function
    assert "uv " not in host_function
