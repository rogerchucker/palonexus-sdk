# PaloNexus coding-agent plugins implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement installable Claude Code and Codex plugins that govern supported tool calls through the local guard without storing credentials, policy, or cache.

**Architecture:** Each host package contains a manifest, blocking `PreToolUse` configuration, a small Go hook normalizer/renderer, fixtures, and a skill. Both wrappers import shared protocol/client code and pass the same conformance vectors.

**Tech Stack:** Go 1.25+, Claude Code plugin/hooks, Codex plugin/hooks, JSON fixtures, subprocess tests.

---

### Task 1: Shared hook client and renderer contract

**Files:**
- Create: `guard/pkg/hookclient/client.go`
- Create: `guard/pkg/hookclient/result.go`
- Test: `guard/pkg/hookclient/client_test.go`

- [ ] Write failing tests for guard invocation, timeout, malformed result,
      allow/no-override, deny, approval-as-deny, safe reason, and exit `2`.
- [ ] Implement one shared client with injectable command/socket transport.
- [ ] Prove credentials and policy identifiers are absent from the package.
- [ ] Commit.

### Task 2: Claude Code normalizer

**Files:**
- Create: `plugins/claude-code/cmd/palonexus-claude-hook/main.go`
- Create: `plugins/claude-code/internal/normalize/normalize.go`
- Test: `plugins/claude-code/internal/normalize/normalize_test.go`

- [ ] Write failing table tests against Gate 0 fixtures for Bash, Read, Edit,
      Write, WebFetch, WebSearch, MCP, and unknown tool.
- [ ] Implement native payload → shared action mapping.
- [ ] Match canonical resource vectors and redact inputs.
- [ ] Commit.

### Task 3: Claude Code renderer

**Files:**
- Create: `plugins/claude-code/internal/render/render.go`
- Test: `plugins/claude-code/internal/render/render_test.go`

- [ ] Write failing tests: allow produces `{}`, deny produces native deny,
      approval produces deny with approval ID/retry text, guard failure blocks,
      and no local `ask` or interactive `defer` is emitted.
- [ ] Implement renderer.
- [ ] Commit.

### Task 4: Claude Code manifest and skill

**Files:**
- Create: `plugins/claude-code/.claude-plugin/plugin.json`
- Create: `plugins/claude-code/hooks/hooks.json`
- Create: `plugins/claude-code/skills/palonexus-governed-actions/SKILL.md`
- Create: `plugins/claude-code/README.md`
- Test: `plugins/claude-code/tests/test_manifest.py`

- [ ] Write failing manifest/hook tests for MIT metadata, plugin-relative paths,
      blocking matchers, command hook, timeout, and supported host version.
- [ ] Implement manifest and hook configuration.
- [ ] Keep SessionStart diagnostic-only.
- [ ] Commit.

### Task 5: Claude Code disposable-host integration

**Files:**
- Create: `plugins/claude-code/tests/test_host_integration.py`
- Create: `plugins/claude-code/tests/fake_guard.py`

- [ ] Write subprocess tests using a disposable home for install, allow/native
      permission preservation, deny sentinel, approval sentinel, timeout,
      malformed input, outage, upgrade, and uninstall.
- [ ] Run only when compatible Claude CLI is present; scheduled CI treats
      absence separately, but release CI requires the exact tested host.
- [ ] Commit fixtures and tests.

### Task 6: Codex normalizer

**Files:**
- Create: `plugins/codex/cmd/palonexus-codex-hook/main.go`
- Create: `plugins/codex/internal/normalize/normalize.go`
- Test: `plugins/codex/internal/normalize/normalize_test.go`

- [ ] Write failing table tests against Gate 0 shell, unified exec,
      apply-patch/file change, MCP, local-function, and unknown fixtures.
- [ ] Implement native payload → shared action mapping.
- [ ] Mark hosted/unexposed tools unsupported in compatibility data.
- [ ] Commit.

### Task 7: Codex renderer

**Files:**
- Create: `plugins/codex/internal/render/render.go`
- Test: `plugins/codex/internal/render/render_test.go`

- [ ] Write failing tests: allow produces `{}`, deny blocks, approval blocks with
      approval ID/retry text, failure exits `2`, and `"ask"` is never emitted.
- [ ] Implement renderer and commit.

### Task 8: Codex manifest and skill

**Files:**
- Create: `plugins/codex/.codex-plugin/plugin.json`
- Create: `plugins/codex/hooks/hooks.json`
- Create: `plugins/codex/skills/palonexus-governed-actions/SKILL.md`
- Create: `plugins/codex/README.md`
- Test: `plugins/codex/tests/test_manifest.py`

- [ ] Write failing tests for Codex manifest schema, hooks, paths, legal URLs,
      minimum version, and claimed matcher coverage.
- [ ] Implement manifest/hook/skill.
- [ ] Commit.

### Task 9: Codex disposable-host integration

**Files:**
- Create: `plugins/codex/tests/test_host_integration.py`
- Create: `plugins/codex/tests/fake_guard.py`

- [ ] Write subprocess tests for install, allow/native permission preservation,
      deny sentinel, approval sentinel, timeout, malformed input, unavailable
      guard, upgrade, and uninstall.
- [ ] Prove no `permissionDecision: "ask"` path can continue execution.
- [ ] Commit.

### Task 10: Shared plugin conformance

**Files:**
- Create: `conformance/plugin_vectors.py`
- Create: `conformance/tests/test_plugin_parity.py`

- [ ] Write failing parity tests that send equivalent action vectors through
      both host normalizers and compare canonical action fields and verdicts.
- [ ] Include duplicate IDs, redaction, unknown tool, malformed input, and
      authorization outage.
- [ ] Fix adapters, never vectors, when behavior diverges from the frozen protocol.
- [ ] Commit.

### Task 11: Plugin archives and bundle verification

**Files:**
- Create: `packaging/build_plugins.py`
- Create: `scripts/verify_plugin_bundles.py`
- Create: `.github/workflows/plugins.yml`
- Test: `foundation_tests/test_plugin_bundles.py`

- [ ] Write failing tests for manifest, hook executable, skill, README, LICENSE,
      version, checksum, no secrets, and clean install from archive.
- [ ] Build separate Claude and Codex bundles from the same source commit.
- [ ] Verify each bundle in disposable host configuration.
- [ ] Commit.

