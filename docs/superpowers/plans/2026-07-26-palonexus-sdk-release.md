# PaloNexus SDK conformance and public release implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prove cross-adapter behavior, package and attest release artifacts, publish the repository publicly, and verify the released prerelease from clean environments.

**Architecture:** Conformance consumes committed vectors and built artifacts. Release jobs promote artifacts produced by the tested release commit. GitHub configuration and public downloads are verified through APIs and clean-install smoke tests.

**Tech Stack:** `uv`, pytest, Go, GitHub Actions/CLI, CodeQL, Syft/CycloneDX, Sigstore/cosign, GitHub attestations, PyPI Trusted Publishing.

---

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
- [ ] Implement subprocess adapters over built or source commands.
- [ ] Compare canonical requests, outcomes, reason codes, IDs, and redaction.
- [ ] Fail on skipped required adapters.
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
- [ ] Build artifacts once and generate the manifest.
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
- [ ] Run independent spec-compliance and security/code-quality reviews.
- [ ] Record commands, versions, commit, counts, artifacts, and limitations.
- [ ] Fix all findings and rerun from the beginning.
- [ ] Commit the evidence record.

### Task 10: Create and configure the public GitHub repository

**External state:**
- Create: `https://github.com/rogerchucker/palonexus-sdk`
- Configure: repository features, security, ruleset, environments, topics

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

### Task 11: Publish and verify prerelease

**External state:**
- Tag: `v0.2.0a1`
- GitHub prerelease
- PyPI prerelease `palonexus==0.2.0a1`

- [ ] Sign and push the tag from the exact audited commit.
- [ ] Wait for release workflows and inspect every check.
- [ ] Download release artifacts and verify checksums, SBOMs, signatures, and attestations.
- [ ] Install `palonexus==0.2.0a1` from public PyPI in a clean `uv` environment.
- [ ] Install both plugin archives in disposable host homes and run allow/deny/approval/outage smoke tests.
- [ ] Run the public README quickstart without the source checkout.
- [ ] Record public URLs and evidence in `docs/evidence/0.2.0a1.md`.
- [ ] Commit any evidence update through the normal PR path.

### Task 12: Completion audit

**Files:**
- Create: `docs/evidence/completion-audit.md`

- [ ] Enumerate every design success criterion and plan checkbox.
- [ ] Link each to authoritative source, test, CI run, GitHub setting, public
      artifact, or runtime output.
- [ ] Treat missing or indirect evidence as incomplete.
- [ ] Confirm no required work remains before marking the goal complete.

