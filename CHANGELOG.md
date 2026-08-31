# Changelog

All notable user-visible changes will be recorded here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and intends to use
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) after its first
release.

## [Unreleased]

### Added

- Initial public repository governance and Python workspace metadata.
- Tag-triggered PyPI release workflow using Trusted Publishing.
- `pnxs agents add` creates a separate tenant-scoped registration workspace
  from an existing agent definition, confirms the owner and tenant before any
  server mutation, and preserves agent keys in credential custody.
- Agent registration retries can reconcile an exact owner-, key-, descriptor-,
  and authority-profile-bound server commit when the original response could
  not be accepted locally.
- Registration commands query the authenticated tenant's exact CLI
  compatibility contract before creating local or server state and send the
  accepted CLI contract and version with the registration request.
- Added standalone `pnxs` installation and upgrade instructions for `uv tool`.
- Governed MCP actions can now pause for human approval, detach, resume the
  same authority request, and return a verified target receipt.
- Agents can request a descriptor-bound subagent identity before spawn, resume
  the same request after a decision, and fail closed without creating a child
  identity when the request is denied.
- Added a runnable R3 agent walkthrough for the approved MCP, capability-denied,
  and denied-subagent scenarios, including Deep Agents adapter wiring.

### Changed

- `pnxs --version` and human-readable `pnxs version` now follow conventional
  CLI behavior, while `pnxs version --json` preserves the exact automation
  contract.
- Canceling device login with Ctrl-C now exits with status 130 and a concise
  message instead of exposing a Python traceback.
- Registration commands reject a `pnxs` executable shadowed by the active
  project virtual environment before making changes and point to a standalone
  executable when one is available.
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
