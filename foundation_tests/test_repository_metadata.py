import tomllib
from pathlib import Path

ROOT = Path(__file__).parents[1]
GOVERNANCE_FILES = {
    "LICENSE",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "CODE_OF_CONDUCT.md",
    "SUPPORT.md",
    "GOVERNANCE.md",
    "CHANGELOG.md",
}


def test_repository_has_public_governance_and_uv_workspace() -> None:
    assert GOVERNANCE_FILES <= {path.name for path in ROOT.iterdir()}
    for name in GOVERNANCE_FILES:
        assert len((ROOT / name).read_text().strip()) >= 100, name

    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert data["tool"]["uv"]["workspace"]["members"] == ["python"]


def test_python_distribution_has_public_metadata() -> None:
    project = tomllib.loads((ROOT / "python" / "pyproject.toml").read_text())[
        "project"
    ]

    assert project["name"] == "palonexus"
    assert project["dynamic"] == ["version"]
    assert project["requires-python"] == ">=3.12"
    assert project["license"] == "MIT"
    assert project["description"].strip()
    assert all("Proprietary" not in classifier for classifier in project["classifiers"])
    assert {"Homepage", "Repository", "Issues", "Changelog"} <= project["urls"].keys()
    assert all(
        url.startswith("https://github.com/rogerchucker/palonexus-sdk")
        for url in project["urls"].values()
    )


def test_documented_clean_checkout_commands_have_declared_tools() -> None:
    root_metadata = tomllib.loads((ROOT / "pyproject.toml").read_text())
    development_dependencies = root_metadata["dependency-groups"]["dev"]

    assert {"pytest", "ruff"} <= {
        dependency.split(">=", maxsplit=1)[0] for dependency in development_dependencies
    }
    readme = (ROOT / "README.md").read_text()
    assert "uv sync" in readme
    assert "uv run pytest" in readme
    assert "uv run ruff check ." in readme


def test_security_and_conduct_policies_offer_private_reporting() -> None:
    security = (ROOT / "SECURITY.md").read_text()
    assert "all reports" in security.lower()
    assert "acknowledge" in security.lower()
    assert "triage" in security.lower()
    assert "before a report is investigated" not in security.lower()

    conduct = (ROOT / "CODE_OF_CONDUCT.md").read_text()
    assert "security/advisories/new" in conduct
    assert "support.github.com/contact" in conduct
    assert "repository owner" in conduct.lower()
