# Changelog

All notable user-visible changes will be recorded here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and intends to use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) after its first
release.

## [Unreleased]

### Added

- Initial public repository governance and Python workspace metadata.
- Tag-triggered PyPI release workflow using Trusted Publishing.

### Changed

- Agent registration now validates accountable ownership against the canonical
  workforce subject when a developer session also carries a distinct membership
  identifier.
- The `palonexus` distribution is now built and published from this repository
  rather than from `palonexus-platform`.
- `scripts/verify` now runs the Python SDK suite (`python/tests`) alongside the
  foundation and protocol suites, so one command covers every test in the
  repository. Set up the environment with `uv sync --frozen --all-extras`; the
  SDK integration tests import the optional extras.

### Removed

The first release from this repository is not a drop-in replacement for
`palonexus` 0.1.0, which was published from `palonexus-platform` on 2026-07-01.
Upgrading from 0.1.0 removes the following.

- The bundled `agentdid` and `idp_sdk` top-level packages. Both were shipped
  inside the 0.1.0 wheel and are absent here; `import agentdid` and
  `import idp_sdk` will fail after upgrading. This package now carries its own
  `palonexus.identity`, `palonexus.keystore`, and `palonexus.credentials`.
- The `palonexus.crypto`, `palonexus.idp`, `palonexus.reference`, and
  `palonexus.pytest_plugin` modules.
- The `all`, `otel`, `server`, and `test` extras. The remaining extras are
  `langchain`, `langgraph`, and `deepagents`.

Pin `palonexus==0.1.0` if you depend on any of the above.
