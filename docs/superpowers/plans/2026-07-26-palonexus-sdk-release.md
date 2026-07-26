# PaloNexus SDK conformance and public release implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove cross-adapter behavior, package and attest release artifacts, publish the repository publicly, and verify the released prerelease from clean environments.

**Architecture:** Conformance consumes committed vectors and built artifacts. Release jobs promote artifacts produced by the tested release commit. GitHub configuration and public downloads are verified through APIs and clean-install smoke tests.

**Tech Stack:** `uv`, pytest, Go, GitHub Actions/CLI, CodeQL, Syft/CycloneDX, Sigstore/cosign, GitHub attestations, PyPI Trusted Publishing.

---

## Mandatory red/green command matrix

| Task | Red command and expected result | Green command and expected result |
|---|---|---|
| 0 | `uv run pytest foundation_tests/test_rc_manifest.py -q` exits 1: no immutable RC artifacts | `uv run python packaging/build_release_candidate.py --output dist/release-candidate && uv run pytest foundation_tests/test_rc_manifest.py -q && uv run python scripts/verify_rc_manifest.py dist/release-candidate/manifest.json` exits 0 |
| 1 | `PALONEXUS_RELEASE_MANIFEST="$PWD/dist/release-candidate/manifest.json" uv run pytest conformance/tests/test_cross_adapter.py -q` exits 1: missing artifact adapters | `PALONEXUS_RELEASE_MANIFEST="$PWD/dist/release-candidate/manifest.json" uv run pytest conformance/tests/test_cross_adapter.py -q` exits 0 |
| 2 | `PALONEXUS_RELEASE_MANIFEST="$PWD/dist/release-candidate/manifest.json" uv run pytest conformance/tests/test_local_e2e.py -q` exits 1: missing mock flow | `PALONEXUS_RELEASE_MANIFEST="$PWD/dist/release-candidate/manifest.json" uv run pytest conformance/tests/test_local_e2e.py -q` exits 0 |
| 3 | `PALONEXUS_RELEASE_MANIFEST="$PWD/dist/release-candidate/manifest.json" uv run pytest conformance/tests/test_offline_examples.py -q` exits 1: missing installed examples | `PALONEXUS_RELEASE_MANIFEST="$PWD/dist/release-candidate/manifest.json" uv run pytest conformance/tests/test_offline_examples.py -q` exits 0 |
| 4 | `uv run pytest conformance/tests/test_public_hygiene.py -q` exits 1 on seeded forbidden fixture | `uv run pytest conformance/tests/test_public_hygiene.py -q && uv run python scripts/verify_no_private_coupling.py --archives dist/release-candidate` exits 0 |
| 5 | `uv run pytest foundation_tests/test_release_manifest.py -q` exits 1: missing SBOM/signature/provenance fields | `uv run pytest foundation_tests/test_release_manifest.py -q && uv run python scripts/verify_release_manifest.py dist/release-candidate/manifest.json` exits 0 |
| 6 | `uv run pytest foundation_tests/test_python_release_workflow.py -q` exits 1: missing workflow policy | `uv run pytest foundation_tests/test_python_release_workflow.py -q` exits 0 |
| 7 | `uv run pytest foundation_tests/test_asset_release_workflow.py -q` exits 1: missing asset workflow | `uv run pytest foundation_tests/test_asset_release_workflow.py -q` exits 0 |
| 8 | `uv run pytest foundation_tests/test_docs.py -q` exits 1: missing docs/snippets | `uv run pytest foundation_tests/test_docs.py -q` exits 0 |
| 9 | `scripts/verify` exits nonzero on the first incomplete required component | `PALONEXUS_RELEASE_MANIFEST="$PWD/dist/release-candidate/manifest.json" scripts/verify` exits 0 in a clean release worktree |
| 10 | `uv run pytest foundation_tests/test_github_settings_evidence.py -q` exits 1 before public settings evidence | `uv run pytest foundation_tests/test_github_settings_evidence.py -q` exits 0 after redacted API evidence |
| 11 | `uv run python scripts/verify_public_release.py v0.2.0a1` exits 1 before public artifacts | `uv run python scripts/verify_public_release.py v0.2.0a1` exits 0 after public download/runtime checks |
| 12 | `uv run pytest foundation_tests/test_completion_audit.py -q` exits 1 with unlinked criteria | `uv run pytest foundation_tests/test_completion_audit.py -q` exits 0 after the evidence map is complete |

### Task 0: Build the immutable release candidate

**Files:**
- Create: `packaging/build_release_candidate.py`
- Create: `scripts/verify_rc_manifest.py`
- Create: `foundation_tests/test_rc_manifest.py`
- Create output: `dist/release-candidate/manifest.json`

- [ ] Write the failing test requiring a wheel, sdist, guard archives, Claude
      bundle, Codex bundle, source commit, protocol version, and SHA-256 for
      every file. Reject editable/source paths.
- [ ] Run: `uv run pytest foundation_tests/test_rc_manifest.py -q`
      Expected: exit 1 because no release candidate exists.
- [ ] Implement the build orchestrator. It invokes the already-reviewed Python,
      guard, and plugin builders once, copies immutable outputs into
      `dist/release-candidate`, and writes their hashes/source commit.
- [ ] Run:

```bash
uv run python packaging/build_release_candidate.py --output dist/release-candidate
uv run pytest foundation_tests/test_rc_manifest.py -q
uv run python scripts/verify_rc_manifest.py dist/release-candidate/manifest.json
```

Expected: exit 0, clean source commit, and all artifact hashes verified.

- [ ] Commit scripts/tests, not generated `dist/`:

```bash
git add packaging/build_release_candidate.py scripts/verify_rc_manifest.py foundation_tests/test_rc_manifest.py
git commit -m "build: produce immutable sdk release candidate"
```

### Task 1: Cross-adapter conformance runner

**Files:**
- Create: `conformance/run_all.py`
- Create: `conformance/adapters/python_adapter.py`
- Create: `conformance/adapters/guard_adapter.py`
- Create: `conformance/adapters/claude_adapter.py`
- Create: `conformance/adapters/codex_adapter.py`
- Test: `conformance/tests/test_cross_adapter.py`

- [ ] Write failing tests that require every adapter to process all applicable
      action/decision/error/approval/reconciliation vectors.
- [ ] Build a release-candidate manifest first. Implement adapters that consume
      only:
      - a fresh `uv` environment containing the exact wheel path from the manifest,
      - the extracted guard binary archive from the manifest,
      - the extracted Claude plugin bundle from the manifest,
      - the extracted Codex plugin bundle from the manifest.
      Source commands, editable installs, checkout imports, and fallback to
      `go run` are errors.
- [ ] Compare canonical requests, outcomes, reason codes, IDs, and redaction.
- [ ] Record and assert each artifact SHA-256 and source commit. Fail on skipped
      adapters, hash mismatch, source-tree import, or missing promoted artifact.
- [ ] Commit.

### Task 2: Local end-to-end decision and approval flow

**Files:**
- Create: `conformance/mock_control_plane.py`
- Create: `conformance/tests/test_local_e2e.py`

- [ ] Write failing full-flow tests for allow, deny, approval creation, approve,
      fresh resume authorization, resource mutation, expiry, revocation,
      policy change, decision outage, reconciliation ack, and audit correlation.
- [ ] Implement only a protocol mock, not SDK-side policy.
- [ ] Run the same scenarios through Python and guard/plugin paths.
- [ ] Commit.

### Task 3: Offline example verification

**Files:**
- Create: `scripts/verify_examples.py`
- Test: `conformance/tests/test_offline_examples.py`
- Modify: `examples/*/README.md`

- [ ] Write failing subprocess tests for every required example with networking
      disabled or redirected to the local mock.
- [ ] Require deterministic output markers and no private credentials.
- [ ] Run examples from built wheel/binaries, not source imports.
- [ ] Commit.

### Task 4: Private-coupling and secret scan

**Files:**
- Create: `scripts/verify_no_private_coupling.py`
- Create: `conformance/tests/test_public_hygiene.py`
- Modify: `.gitleaks.toml`

- [ ] Write failing tests that detect platform module paths, private cluster
      suffixes, internal issue IDs, partner fixtures, proprietary classifiers,
      raw tokens, and missing provenance.
- [ ] Implement allowlisted legal source references only in provenance records.
- [ ] Scan generated archives in addition to source.
- [ ] Commit.

### Task 5: SBOM, checksums, signatures, and attestations

**Files:**
- Create: `packaging/release_manifest.py`
- Create: `scripts/verify_release_manifest.py`
- Create: `.github/workflows/release-build.yml`
- Test: `foundation_tests/test_release_manifest.py`

- [ ] Write failing tests requiring source commit, protocol version, artifact
      SHA-256, SPDX/CycloneDX SBOM, signature reference, provenance reference,
      toolchain versions, and compatibility matrix.
- [ ] Enrich the existing Task 0 manifest without rebuilding artifacts. Generate
      SBOMs, checksum manifest, signature references, and attestations over the
      exact verified hashes.
- [ ] Configure keyless signing/attestation with minimal workflow permissions.
- [ ] Commit.

### Task 6: Python prerelease workflow

**Files:**
- Create: `.github/workflows/release-python.yml`
- Create: `scripts/verify_pypi_release.py`
- Test: `foundation_tests/test_python_release_workflow.py`

- [ ] Write failing workflow-policy tests for tag trigger, trusted publishing,
      protected environment, artifact promotion, PEP 740 attestation, and
      post-publish clean install.
- [ ] Configure `0.2.0a1` only after checking the existing `0.1.0` package.
- [ ] Do not publish until the GitHub environment is configured.
- [ ] Commit.

### Task 7: Binary and plugin prerelease workflow

**Files:**
- Create: `.github/workflows/release-assets.yml`
- Create: `scripts/verify_github_release.py`
- Test: `foundation_tests/test_asset_release_workflow.py`

- [ ] Write failing tests for signed tag, exact tested archives, checksums,
      SBOMs, signatures, attestations, and downloaded verification.
- [ ] Configure GitHub release creation from promoted artifacts.
- [ ] Commit.

### Task 8: Final documentation and migration guide

**Files:**
- Modify: `README.md`
- Create: `docs/quickstart.md`
- Create: `docs/architecture.md`
- Create: `docs/threat-model.md`
- Create: `docs/protocol.md`
- Create: `docs/approvals.md`
- Create: `docs/plugins.md`
- Create: `docs/migration-0.1.md`
- Create: `docs/releasing.md`
- Create: `docs/evidence/0.2.0a1.md`
- Test: `foundation_tests/test_docs.py`

- [ ] Write failing snippet/link/command tests.
- [ ] Document public installs, real offline examples, host limitations,
      point-in-time plugin authorization, diagnostic adapter label, no offline
      allow cache, and exactly-once non-claim.
- [ ] Document migration from monorepo `palonexus==0.1.0`.
- [ ] Commit.

### Task 9: Full local release candidate audit

**Files:**
- Modify: `scripts/verify`
- Create: `docs/evidence/local-release-candidate.md`

- [ ] Run every master verification command on a clean integration worktree.
- [ ] Reuse Task 0's immutable release-candidate manifest; export
      `PALONEXUS_RELEASE_MANIFEST="$PWD/dist/release-candidate/manifest.json"`.
- [ ] Run independent spec-compliance and security/code-quality reviews.
- [ ] Record commands, versions, commit, counts, artifacts, and limitations.
- [ ] Fix all findings and rerun from the beginning.
- [ ] Commit the evidence record.

### Task 10: Create and configure the public GitHub repository

**External state:**
- Create: `https://github.com/rogerchucker/palonexus-sdk`
- Configure: repository features, security, ruleset, environments, topics
**Files:**
- Create: `scripts/capture_github_settings.py`
- Create: `foundation_tests/test_github_settings_evidence.py`
- Create: `docs/evidence/github-settings.json`

- [ ] Confirm `gh auth status` uses `rogerchucker` with repository scope.
- [ ] Reconfirm the repository name is not occupied.
- [ ] Create the repository public without auto-generated files:

```bash
gh repo create rogerchucker/palonexus-sdk \
  --public \
  --source . \
  --remote origin \
  --description "SDKs and coding-agent plugins for the PaloNexus agent control plane"
```

- [ ] Push reviewed `main`.
- [ ] Enable Issues, Discussions, dependency graph, Dependabot, secret scanning,
      push protection, private vulnerability reporting, and CodeQL.
- [ ] Create `main` and release-tag rules with required checks, no force/delete,
      up-to-date PRs, and conversation resolution.
- [ ] Configure `pypi` and `github-release` environments.
- [ ] Set default workflow permission read-only and allow only pinned actions.
- [ ] Verify all settings through `gh api`; save redacted evidence.
- [ ] Run: `uv run pytest foundation_tests/test_github_settings_evidence.py -q`
      Expected: PASS only when evidence proves public visibility, default branch,
      security features, rules, environments, and read-only workflow defaults.

### Task 11: Publish and verify prerelease

**External state:**
- Tag: `v0.2.0a1`
- GitHub prerelease
- PyPI prerelease `palonexus==0.2.0a1`
**Files:**
- Create: `scripts/verify_public_release.py`

- [ ] Sign and push the tag from the exact audited commit.
- [ ] Wait for release workflows and inspect every check.
- [ ] Download release artifacts and verify checksums, SBOMs, signatures, and attestations.
- [ ] Install `palonexus==0.2.0a1` from public PyPI in a clean `uv` environment.
- [ ] Install both plugin archives in disposable host homes and run allow/deny/approval/outage smoke tests.
- [ ] Run the public README quickstart without the source checkout.
- [ ] Record public URLs and evidence in `docs/evidence/0.2.0a1.md`.
- [ ] Commit any evidence update through the normal PR path.
- [ ] Run: `uv run python scripts/verify_public_release.py v0.2.0a1`
      Expected: PASS after downloading and exercising every public artifact.

### Task 12: Completion audit

**Files:**
- Create: `docs/evidence/completion-audit.md`
- Create: `foundation_tests/test_completion_audit.py`

- [ ] Enumerate every design success criterion and plan checkbox.
- [ ] Link each to authoritative source, test, CI run, GitHub setting, public
      artifact, or runtime output.
- [ ] Treat missing or indirect evidence as incomplete.
- [ ] Confirm no required work remains before marking the goal complete.
