# PaloNexus Python SDK implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement a typed, fail-closed synchronous and asynchronous Python SDK with approval/resume, identity helpers, framework adapters, and working offline examples.

**Architecture:** Generated protocol types are wrapped by stable public models. Sync and async clients share transport-neutral behavior and parity tests. Framework integrations depend on the public authorization protocol, never private client internals.

**Tech Stack:** Python 3.12/3.13, Pydantic 2, httpx, cryptography, PyJWT, pytest, Ruff, mypy, `uv`.

---

## Mandatory red/green command matrix

Every task runs its red command before implementation and records the named
missing-module or missing-behavior failure. After implementation it runs the
green command plus the affected shared suite. A passing red command is invalid.

| Task | Red command and expected result | Green command and expected result |
|---|---|---|
| 1 | `uv run pytest python/tests/test_models_errors.py -q` → FAIL missing public models | same command plus `uv run mypy python/src` → PASS |
| 2 | `uv run pytest python/tests/test_context_protocol.py -q` → FAIL missing context/builder | same plus `uv run pytest protocol/tests -q` → PASS |
| 3 | `uv run pytest python/tests/test_credentials_redaction_retry.py -q` → FAIL missing policies | same plus `uv run pytest python/tests/test_context_protocol.py -q` → PASS |
| 3B | `uv run pytest python/tests/test_keystore.py -q` → FAIL missing `KeyStore` | same plus credentials tests → PASS |
| 4 | `uv run pytest python/tests/test_http_transport.py -q` → FAIL missing transport | same plus protocol tests → PASS |
| 5 | `uv run pytest python/tests/test_client_parity.py -q` → FAIL missing clients | same plus model/transport tests → PASS |
| 6 | `uv run pytest python/tests/test_approval_resume.py -q` → FAIL missing approval/resume | same plus client parity/protocol approval tests → PASS |
| 7 | `uv run pytest python/tests/identity/test_did_vc.py python/tests/identity/test_delegation.py -q` → FAIL missing identity modules | same commands → PASS |
| 8 | `uv run pytest python/tests/identity/test_oidc.py -q` → FAIL missing OIDC verifier | same plus keystore tests → PASS |
| 9 | `uv run pytest python/tests/test_testing_tools.py -q` → FAIL missing testing package | same plus client parity → PASS |
| 10 | `uv run pytest python/tests/integrations/test_langchain.py -q` → FAIL missing adapter | same plus client parity → PASS |
| 11 | `uv run pytest python/tests/integrations/test_langgraph.py -q` → FAIL missing adapter | same plus approval/resume → PASS |
| 12 | `uv run pytest python/tests/integrations/test_deepagents.py -q` → FAIL missing adapter | same plus context tests → PASS |
| 13 | `uv run pytest python/tests/test_examples.py -q` → FAIL missing examples | same plus all integration tests → PASS |
| 14 | `uv run pytest python/tests/test_package_metadata.py -q` → FAIL missing artifact policy | same then `uv build --package palonexus` and artifact verifier → PASS |

### Task 1: Public models, outcomes, and errors

**Files:**
- Create: `python/src/palonexus/__init__.py`
- Create: `python/src/palonexus/models.py`
- Create: `python/src/palonexus/errors.py`
- Create: `python/src/palonexus/py.typed`
- Test: `python/tests/test_models_errors.py`

- [ ] Write failing tests for strict action/target/task models, outcome enum,
      safe typed exceptions, ID propagation, unknown fields, and secret-free
      exception strings.
- [ ] Run: `uv run pytest python/tests/test_models_errors.py -q` and observe failure.
- [ ] Implement immutable Pydantic wrappers around generated types.
- [ ] Export only the approved public API from `__init__.py`.
- [ ] Run pytest, Ruff, and mypy.
- [ ] Commit: `feat(python): add public authorization models`.

Required exception shape:

```python
class PaloNexusError(Exception):
    code: str
    request_id: str | None
    decision_id: str | None
    correlation_id: str | None
    retryable: bool
```

### Task 2: Task context and canonical request builder

**Files:**
- Create: `python/src/palonexus/context.py`
- Create: `python/src/palonexus/protocol.py`
- Test: `python/tests/test_context_protocol.py`

- [ ] Write failing tests for nested sync/async context isolation, no
      process-global mutation, ID generation, canonical hash parity, and fresh
      resume request IDs.
- [ ] Observe failures.
- [ ] Implement `TaskContext`, `task()`, `atask()`, and `ActionRequestBuilder`.
- [ ] Validate output against committed protocol vectors.
- [ ] Run affected tests and commit.

### Task 3: Credential, redaction, and retry policies

**Files:**
- Create: `python/src/palonexus/credentials.py`
- Create: `python/src/palonexus/redaction.py`
- Create: `python/src/palonexus/retry.py`
- Test: `python/tests/test_credentials_redaction_retry.py`

- [ ] Write failing tests for credential-provider protocol, token/header/query
      redaction, shell/URL redaction, bounded jitter, side-effect retry safety,
      cancellation, and ambiguous completion.
- [ ] Observe failures.
- [ ] Implement `CredentialProvider`, `Redactor`, and `RetryPolicy`.
- [ ] Ensure write/destructive/external retries require authorization idempotency.
- [ ] Run tests and commit.

### Task 3B: Production key-store contract

**Files:**
- Create: `python/src/palonexus/keystore.py`
- Test: `python/tests/test_keystore.py`

- [ ] Write failing tests for a `KeyStore` protocol with load/store/delete,
      unavailable-backend failure, no plaintext default, and an
      `EphemeralKeyStore` constructor that requires explicit
      `testing_only=True`.
- [ ] Run: `uv run pytest python/tests/test_keystore.py -q`  
      Expected: FAIL because `palonexus.keystore` does not exist.
- [ ] Implement the protocol and test-only in-memory backend. Production SDK
      construction without an injected supported store fails closed rather
      than generating or writing a key.
- [ ] Run: `uv run pytest python/tests/test_keystore.py python/tests/test_credentials_redaction_retry.py -q`  
      Expected: PASS.
- [ ] Commit: `feat(python): define secure key store boundary`.

### Task 4: HTTP sync and async transports

**Files:**
- Create: `python/src/palonexus/transports/base.py`
- Create: `python/src/palonexus/transports/http.py`
- Create: `python/src/palonexus/transports/__init__.py`
- Test: `python/tests/test_http_transport.py`

- [ ] Write failing mock-server tests for HTTPS enforcement, auth headers,
      timeouts, malformed JSON, hash mismatch, server-time validation, retry,
      cancellation, and redacted errors.
- [ ] Observe failures.
- [ ] Implement sync and async transport methods over shared request/response
      parsing.
- [ ] Prove no fallback identity after credential failure.
- [ ] Run transport tests and commit.

### Task 5: Sync and async clients with parity

**Files:**
- Create: `python/src/palonexus/client.py`
- Create: `python/src/palonexus/async_client.py`
- Test: `python/tests/test_client_parity.py`

- [ ] Write one parameterized behavior suite that drives both clients through
      allow, deny, approval, malformed response, outage, retry, close, and
      cancellation.
- [ ] Observe failure.
- [ ] Implement `AuthorizationClient` and `AsyncAuthorizationClient`.
- [ ] Implement `decide`, `authorize`, context management, and close behavior.
- [ ] Assert byte-equivalent requests and equivalent exceptions.
- [ ] Run parity suite and commit.

### Task 6: Approval and resume

**Files:**
- Create: `python/src/palonexus/approvals.py`
- Modify: `python/src/palonexus/client.py`
- Modify: `python/src/palonexus/async_client.py`
- Test: `python/tests/test_approval_resume.py`

- [ ] Write failing tests for idempotent approval creation, wait deadline,
      approved/denied/expired/cancelled, immutable action ID, new resume request
      identity, fresh resource hashing, scope mismatch, policy/revocation change,
      and no wrapped action before allow.
- [ ] Observe failure.
- [ ] Implement sync/async approval operations and `resume`.
- [ ] Prove authorization retries do not invoke application work.
- [ ] Run tests and commit.

### Task 7: Generic DID and verifiable credential helpers

**Files:**
- Create: `python/src/palonexus/identity/did.py`
- Create: `python/src/palonexus/identity/vc.py`
- Create: `python/src/palonexus/identity/__init__.py`
- Test: `python/tests/identity/test_did_vc.py`
- Test: `python/tests/identity/test_delegation.py`

- [ ] Write failing Ed25519/did:key, VC, VP, delegation narrowing, expiry,
      challenge, audience, tamper, and replay tests.
- [ ] Observe failures.
- [ ] Port or rewrite only provenance-approved generic logic.
- [ ] Make revocation lookup failure fail closed.
- [ ] Run identity tests and commit.

### Task 8: Explicit OIDC verification

**Files:**
- Create: `python/src/palonexus/identity/oidc.py`
- Test: `python/tests/identity/test_oidc.py`

- [ ] Write failing tests for discovery, issuer, audience, algorithm, signature,
      key rotation, nonce, expiry, unavailable JWKS, and hard-coded issuer
      absence.
- [ ] Observe failures.
- [ ] Implement explicit `OIDCVerifierConfig` and verifier.
- [ ] Run tests and commit.

### Task 9: Testing utilities and mock decision server

**Files:**
- Create: `python/src/palonexus/testing/__init__.py`
- Create: `python/src/palonexus/testing/fake_transport.py`
- Create: `python/src/palonexus/testing/mock_server.py`
- Test: `python/tests/test_testing_tools.py`

- [ ] Write failing tests for programmable outcomes, deterministic clock/IDs,
      approval transitions, idempotency conflicts, recorded calls, and absence
      of embedded platform policy.
- [ ] Implement the minimum fake transport and local server.
- [ ] Run tests and commit.

### Task 10: LangChain integration

**Files:**
- Create: `python/src/palonexus/integrations/langchain.py`
- Test: `python/tests/integrations/test_langchain.py`
- Create: `examples/langchain/main.py`

- [ ] Write failing sync/async tool and model middleware tests for allow, deny,
      approval, nested task context, timeout, and no execution before allow.
- [ ] Implement against the public client protocol.
- [ ] Run example with fake transport.
- [ ] Commit.

### Task 11: LangGraph integration

**Files:**
- Create: `python/src/palonexus/integrations/langgraph.py`
- Test: `python/tests/integrations/test_langgraph.py`
- Create: `examples/langgraph/main.py`

- [ ] Write failing tests for interrupt, checkpointed immutable scope, approval,
      fresh resume, scope mutation denial, expiry/revocation denial, and one
      wrapped invocation for one allowed graph event.
- [ ] Implement governed node wrappers.
- [ ] Run offline example and commit.

### Task 12: Deep Agents integration

**Files:**
- Create: `python/src/palonexus/integrations/deepagents.py`
- Test: `python/tests/integrations/test_deepagents.py`
- Create: `examples/deepagents/main.py`

- [ ] Write failing tests for parent/child task correlation, accountable actor,
      nested tool denial, approval propagation, and unsupported hook behavior.
- [ ] Implement the adapter without private APIs.
- [ ] Run offline example and commit.

### Task 13: Core sync and async examples

**Files:**
- Create: `examples/python-basic/main.py`
- Create: `examples/python-async/main.py`
- Create: `examples/python-basic/README.md`
- Create: `examples/python-async/README.md`
- Test: `python/tests/test_examples.py`

- [ ] Write failing subprocess tests for deny → approval → approve → resume →
      allow → execute once → audit correlation.
- [ ] Implement neutral inventory examples with synthetic IDs.
- [ ] Prove no network and no private fixtures.
- [ ] Commit.

### Task 14: Python package and artifact verification

**Files:**
- Modify: `python/pyproject.toml`
- Create: `scripts/verify_python_artifacts.py`
- Test: `python/tests/test_package_metadata.py`
- Create: `.github/workflows/python.yml`

- [ ] Write failing tests for MIT metadata, `py.typed`, extras, public URLs,
      wheel/sdist contents, and no sibling-path vendoring.
- [ ] Configure Hatchling or uv-supported build backend with normal package
      contents.
- [ ] Build wheel and sdist with `uv build --package palonexus`.
- [ ] Install each artifact in a fresh `uv venv` outside the checkout and run
      imports/examples.
- [ ] Commit.
