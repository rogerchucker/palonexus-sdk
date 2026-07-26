# PaloNexus SDK master implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this program task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build, verify, release, and publicly publish the MIT-licensed `palonexus-sdk` repository containing the shared protocol, Python SDK, guard companion, Claude Code plugin, Codex plugin, examples, and release evidence.

**Architecture:** Protocol schemas and golden vectors are frozen first. Python and Go implementations consume that contract; host plugins remain thin wrappers around the guard. Cross-adapter conformance and installed-artifact tests gate public prerelease publication.

**Tech Stack:** JSON Schema 2020-12, Python 3.12/3.13, Pydantic 2, httpx, pytest, Ruff, mypy, `uv`, Go 1.25+, Claude Code hooks, Codex hooks, GitHub Actions, GitHub CLI.

---

## Authoritative documents

- Design: `docs/superpowers/specs/2026-07-25-palonexus-sdk-design.md`
- Foundation and protocol: `docs/superpowers/plans/2026-07-26-palonexus-sdk-foundation-protocol.md`
- Python SDK: `docs/superpowers/plans/2026-07-26-palonexus-sdk-python.md`
- Guard companion: `docs/superpowers/plans/2026-07-26-palonexus-sdk-guard.md`
- Host plugins: `docs/superpowers/plans/2026-07-26-palonexus-sdk-plugins.md`
- Conformance and public release: `docs/superpowers/plans/2026-07-26-palonexus-sdk-release.md`

## Dependency graph

```text
Gate 0 host feasibility
        │
        ├── repository governance
        │
        └── protocol schemas + golden vectors
                    │
          ┌─────────┴─────────┐
          │                   │
      Python SDK          Go protocol/guard
          │                   │
          ├── frameworks      ├── Claude plugin
          │                   └── Codex plugin
          └─────────┬─────────┘
                    │
        cross-adapter conformance
                    │
       packaging + installed examples
                    │
       public GitHub repo + prerelease
```

## Branch and worktree policy

The repository starts with an integration branch named `feat/initial-sdk`.
Subagent tasks branch from the latest reviewed integration commit. A task owns
only the files named in its plan. Protocol schemas, workspace metadata,
top-level exports, and release workflows always have a single integration
owner.

Implementation tasks are not run concurrently when they modify:

- `protocol/schemas/`
- `protocol/test-vectors/`
- root `pyproject.toml` or `uv.lock`
- root `go.mod` or `go.sum`
- Python public exports
- shared Go protocol types
- GitHub release workflows

After the protocol freeze, these independent tracks may run in parallel:

- Python transport/client work
- Guard storage/session work
- Claude fixture normalizer
- Codex fixture normalizer
- Neutral examples and documentation

Each task follows:

1. Implementer writes and observes a failing test.
2. Implementer adds the minimum behavior.
3. Implementer runs scoped and affected suites.
4. Implementer commits and self-reviews.
5. Spec reviewer checks the exact task contract.
6. Code-quality reviewer checks maintainability and security.
7. Integration owner rebases or cherry-picks and runs the integration gate.

## Program phases

### Phase 0: Gate 0 and repository foundation

- [ ] Execute Foundation Tasks 1–4.
- [ ] Record current official Claude Code and Codex hook fixtures.
- [ ] Prove both hosts can block every claimed initial tool family.
- [ ] Commit the exact minimum/tested host matrix.
- [ ] Commit MIT relicensing and per-file provenance evidence.
- [ ] Establish formatting, linting, unit-test, secret, and license CI.

Exit evidence:

```bash
uv run pytest foundation_tests -q
uv run python scripts/verify_legal.py
uv run python scripts/verify_host_fixtures.py
```

### Phase 1: Protocol freeze

- [ ] Execute Foundation Tasks 5–10.
- [ ] Freeze action, decision, approval, error, and reconciliation schemas.
- [ ] Freeze canonicalization and scope-hash vectors.
- [ ] Freeze approval/resume and reconciliation state vectors.
- [ ] Tag the contract checkpoint `protocol-v1-freeze`.

Exit evidence:

```bash
uv run pytest protocol/tests -q
uv run python conformance/validate_vectors.py
git diff --exit-code
```

### Phase 2: Python SDK

- [ ] Execute every task in the Python plan.
- [ ] Prove sync/async parity.
- [ ] Prove fail-closed transport, redaction, retry, approval, and resume.
- [ ] Prove LangChain, LangGraph, and Deep Agents examples offline.
- [ ] Build and clean-install wheel and source distribution.

### Phase 3: Guard companion

- [ ] Execute every task in the guard plan.
- [ ] Prove socket, peer, credential, session, OIDC, routing, and redaction behavior.
- [ ] Prove no authorization allow cache is active.
- [ ] Prove reconciliation crash recovery and idempotent acknowledgement.
- [ ] Build macOS and Linux archives.

### Phase 4: Host plugins

- [ ] Execute every task in the plugin plan.
- [ ] Prove allow emits no host permission override.
- [ ] Prove deny and approval prevent execution.
- [ ] Prove malformed input and unavailable guard fail closed.
- [ ] Install/uninstall both plugins in disposable homes.

### Phase 5: Conformance and public release

- [ ] Execute every task in the release plan.
- [ ] Pass shared vectors against Python, guard, Claude, and Codex.
- [ ] Run all offline examples from built artifacts.
- [ ] Scan source history and archives for secrets and private fixtures.
- [ ] Create `rogerchucker/palonexus-sdk` as public.
- [ ] Push reviewed `main`.
- [ ] Configure GitHub security and branch rules.
- [ ] Publish signed prerelease assets.
- [ ] Download and verify released artifacts.

## Program-wide verification command

Create `scripts/verify` during the foundation phase. Its final implementation
must run:

```bash
uv lock --check
uv run ruff format --check python protocol conformance examples scripts
uv run ruff check python protocol conformance examples scripts
uv run mypy python/src
uv run pytest -q
go fmt ./...
go vet ./...
go test -race ./...
uv run python conformance/run_all.py
uv build --package palonexus
uv run python scripts/verify_python_artifacts.py
uv run python scripts/verify_plugin_bundles.py
uv run python scripts/verify_legal.py
uv run python scripts/verify_no_private_coupling.py
```

The script exits nonzero on a skipped required component.

## Definition of done

- [ ] Every explicit design success criterion has linked evidence.
- [ ] Every plan checkbox is complete.
- [ ] Independent final spec and code reviews have no open issue.
- [ ] Local and CI verification pass on the exact release commit.
- [ ] GitHub reports the repository as public with `main` default.
- [ ] Required branch/security settings are verified through API output.
- [ ] The public release contains checksums, SBOMs, signatures/attestations, and compatibility data.
- [ ] Clean machines install and run the public Python and plugin artifacts.
- [ ] README limitations match tested hook coverage.
- [ ] No control-plane implementation, private endpoint, partner fixture, token, or proprietary-only file is present.

