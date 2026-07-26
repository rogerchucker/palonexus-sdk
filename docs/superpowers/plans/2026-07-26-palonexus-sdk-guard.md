# PaloNexus guard companion implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement the hardened local guard CLI and daemon that authenticates the user, owns credentials, normalizes/redacts actions, calls the decision service, and reconciles safe evidence.

**Architecture:** One Go module exposes generated protocol types, a strict NDJSON Unix-socket service, and the `palonexus` CLI. Host wrappers carry no credentials or policy. Authorization caching is disabled in version 1.

**Tech Stack:** Go 1.25+, Unix domain sockets, OAuth 2/OIDC PKCE, OS keyring, HTTPS, NDJSON, Go tests/race/fuzz.

---

## Mandatory red/green command matrix

Each red command must fail for the named missing behavior before implementation.
Each green command must pass along with the affected package tests.

| Task | Red command and expected result | Green command and expected result |
|---|---|---|
| 1 | `go test ./guard/internal/cli -run Test -count=1` → FAIL missing CLI | same → PASS |
| 2 | `go test ./guard/internal/config ./guard/internal/routing -count=1` → FAIL missing config/routing | same → PASS |
| 3 | `go test ./guard/internal/normalize ./guard/internal/redact -count=1` → FAIL missing normalization | same plus `uv run pytest protocol/tests/test_canonicalization.py -q` → PASS |
| 4 | `go test ./guard/internal/keystore ./guard/internal/state -count=1` → FAIL missing secure stores | same → PASS |
| 5 | `go test ./guard/internal/auth -count=1` → FAIL missing verified OIDC | same → PASS |
| 6 | `go test ./guard/internal/decision -count=1` → FAIL missing decision client | same plus protocol decision tests → PASS |
| 7 | `go test ./guard/internal/socket -count=1` → FAIL missing socket hardening | `go test -race ./guard/internal/socket -count=1` → PASS |
| 8 | `go test ./guard/internal/guard -count=1` → FAIL missing pipeline | same plus decision/normalize tests → PASS |
| 9 | `go test ./guard/internal/daemon -count=1` → FAIL missing lifecycle | same plus socket tests → PASS |
| 10 | `go test ./guard/internal/reconcile -count=1` → FAIL missing queue | same plus protocol reconciliation tests → PASS |
| 11 | `go test ./guard/internal/plugin -count=1` → FAIL missing installer | same plus CLI tests → PASS |
| 12 | `go test ./guard/tests -run TestLocalDemo -count=1` → FAIL missing demo | same → PASS |
| 13 | `uv run pytest foundation_tests/test_guard_release_matrix.py -q` → FAIL missing matrix/workflow | same then build and artifact verifier → PASS |

### Task 1: CLI skeleton and version

**Files:**
- Create: `guard/cmd/palonexus/main.go`
- Create: `guard/internal/cli/cli.go`
- Test: `guard/internal/cli/cli_test.go`

- [ ] Write failing tests for help, version, unknown command, safe output, and
      exit codes.
- [ ] Implement command dispatch for login/logout/status/guard/plugin stubs.
- [ ] Run `go test ./guard/internal/cli` and commit.

### Task 2: Strict configuration and routing

**Files:**
- Create: `guard/internal/config/config.go`
- Create: `guard/internal/routing/routing.go`
- Test: `guard/internal/config/config_test.go`
- Test: `guard/internal/routing/routing_test.go`

- [ ] Write failing tests for HTTPS-only endpoints, explicit local test mode,
      trusted CA, route precedence, unknown target denial, permissions, and
      symlink-safe config reads.
- [ ] Implement immutable loaded config and deterministic routing.
- [ ] Commit.

### Task 3: Redaction and canonical normalization

**Files:**
- Create: `guard/internal/normalize/normalize.go`
- Create: `guard/internal/redact/redact.go`
- Test: `guard/internal/normalize/normalize_test.go`
- Fuzz: `guard/internal/normalize/fuzz_test.go`

- [ ] Write/fuzz failing vector tests for shell, paths, URLs, MCP JSON, Unicode,
      tokens, credentials, and malformed values.
- [ ] Implement parity with protocol canonicalization vectors.
- [ ] Prove raw values do not enter logs or errors.
- [ ] Commit.

### Task 4: Keyring abstraction and secure state

**Files:**
- Create: `guard/internal/keystore/keystore.go`
- Create: `guard/internal/keystore/keyring.go`
- Create: `guard/internal/state/store.go`
- Test: `guard/internal/keystore/keystore_test.go`
- Test: `guard/internal/state/store_test.go`

- [ ] Write failing tests for macOS Keychain/Secret Service adapter contracts,
      unavailable backend, atomic writes, 0700 directory, 0600 files, symlinks,
      locking, logout deletion, and no plaintext token fallback.
- [ ] Implement interfaces and fake backend; wire supported OS keyring library.
- [ ] Keep encrypted file fallback test-only and disabled by default.
- [ ] Commit.

### Task 5: OIDC discovery and PKCE session

**Files:**
- Create: `guard/internal/auth/oidc.go`
- Create: `guard/internal/auth/session.go`
- Test: `guard/internal/auth/oidc_test.go`

- [ ] Write failing mock-provider tests for PKCE, state, nonce, issuer, audience,
      signature, algorithm, expiry, rotation, refresh, logout, and outages.
- [ ] Implement verified authorization-code flow.
- [ ] Never parse an ID-token payload without signature verification.
- [ ] Commit.

### Task 6: Decision endpoint client

**Files:**
- Create: `guard/internal/decision/client.go`
- Create: `guard/internal/decision/errors.go`
- Test: `guard/internal/decision/client_test.go`

- [ ] Write failing tests for TLS, auth, both scope hashes, server time, timeout,
      malformed response, policy denial, approval, redaction, and outage.
- [ ] Implement fail-closed HTTPS client.
- [ ] Assert no fallback allow and no offline allow cache.
- [ ] Commit.

### Task 7: Unix socket server and peer checks

**Files:**
- Create: `guard/internal/socket/server.go`
- Create: `guard/internal/socket/peer_unix.go`
- Create: `guard/internal/socket/peer_test.go`
- Test: `guard/internal/socket/server_test.go`
- Fuzz: `guard/internal/socket/fuzz_test.go`

- [ ] Write failing tests for user-only runtime directory/socket, peer UID,
      framing, size limit, unknown major, malformed JSON, concurrent clients,
      shutdown, crash cleanup, a symlink at the socket path, a symlinked runtime
      directory, a pre-existing regular/FIFO/device inode, attacker replacement
      between validation and bind, and runtime-directory swap during cleanup.
- [ ] Implement one-request/one-response NDJSON framing. Open/validate the
      runtime directory through a directory file descriptor, reject symlinks
      and non-directory ownership/mode mismatches, use no-follow semantics where
      supported, bind only after exclusive path validation, verify the bound
      inode before serving/removal, and never unlink a replacement inode during
      cleanup.
- [ ] Ensure error paths return deny-compatible structured results.
- [ ] Commit.

### Task 8: Guard check pipeline

**Files:**
- Create: `guard/internal/guard/check.go`
- Test: `guard/internal/guard/check_test.go`

- [ ] Write failing tests for normalize → authenticated client ID → route →
      decide → render, all outcomes, missing login, unknown route, and
      authoritative adapter-label exclusion.
- [ ] Implement pipeline with injected interfaces.
- [ ] Verify one decision call for one uncached action.
- [ ] Commit.

### Task 9: Daemon lifecycle and CLI fallback

**Files:**
- Create: `guard/internal/daemon/daemon.go`
- Create: `guard/internal/daemon/autostart.go`
- Modify: `guard/internal/cli/cli.go`
- Test: `guard/internal/daemon/daemon_test.go`

- [ ] Write failing tests for start/status/stop, concurrent auto-start,
      unavailable daemon, stale socket, one-shot CLI, and fail-closed start
      failure.
- [ ] Implement lifecycle without shell-injection-prone command strings.
- [ ] Commit.

### Task 10: Reconciliation queue

**Files:**
- Create: `guard/internal/reconcile/queue.go`
- Create: `guard/internal/reconcile/uploader.go`
- Test: `guard/internal/reconcile/reconcile_test.go`

- [ ] Write failing tests from reconciliation vectors: crash during sending,
      retry wait, restart recovery, ack loss, dedupe, conflict, discard policy,
      and no raw resource values.
- [ ] Implement durable safe queue with atomic transitions.
- [ ] Commit.

### Task 11: Plugin installation commands

**Files:**
- Create: `guard/internal/plugin/install.go`
- Modify: `guard/internal/cli/cli.go`
- Test: `guard/internal/plugin/install_test.go`

- [ ] Write failing disposable-home tests for install, existing configuration,
      upgrade, uninstall, idempotency, rollback, and unrelated-setting
      preservation.
- [ ] Prefer native plugin mechanisms; do not rewrite broad user settings.
- [ ] Commit.

### Task 12: Guard examples and local mock service

**Files:**
- Create: `examples/local-demo/server.py`
- Create: `examples/local-demo/run.sh`
- Create: `examples/local-demo/README.md`
- Test: `guard/tests/local_demo_test.go`

- [ ] Write failing subprocess tests for login fixture, allow, deny, approval,
      malformed input, outage, redaction, and reconciliation.
- [ ] Implement one-command no-private-service demo.
- [ ] Commit.

### Task 13: Cross-platform builds and archives

**Files:**
- Create: `packaging/build_guard.py`
- Create: `scripts/verify_guard_artifacts.py`
- Create: `.github/workflows/guard.yml`
- Test: `foundation_tests/test_guard_release_matrix.py`

- [ ] Write failing tests for declared Go 1.25 toolchain, required runtime
      platforms, archive names, MIT license, version output, and checksums.
- [ ] Run format, vet, staticcheck, race, and fuzz smoke.
- [ ] Add non-skippable runtime workflow jobs:
      `ubuntu-24.04` amd64 and both supported macOS 14/15 arm64 runner images.
      Each job runs `go test -race ./guard/...` and launches the built binary.
- [ ] Build Linux/macOS amd64/arm64. Only Linux arm64 and macOS amd64 may be
      labeled cross-built-only unless native runners are added; the required
      Ubuntu amd64 and macOS arm64 runtime cells may not be skipped.
- [ ] Verify archives in clean temporary directories.
- [ ] Commit.
