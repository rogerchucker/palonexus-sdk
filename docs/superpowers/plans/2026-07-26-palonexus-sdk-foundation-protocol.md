# PaloNexus SDK foundation and protocol implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Establish the public repository, prove host-hook feasibility, record legal provenance, and freeze protocol version 1 through schemas and golden vectors.

**Architecture:** JSON Schema 2020-12 is normative. Python validation utilities and generated Python/Go types are reproducible derivatives. Gate 0 records real host payloads before plugin architecture or coverage is frozen.

**Tech Stack:** `uv`, Python 3.12+, JSON Schema 2020-12, Pydantic 2, pytest, Ruff, mypy, Go 1.25+, GitHub Actions.

---

### Task 1: Repository governance and workspace

**Files:**
- Modify: `README.md`
- Create: `pyproject.toml`
- Create: `python/pyproject.toml`
- Create: `ruff.toml`
- Create: `SECURITY.md`
- Create: `CONTRIBUTING.md`
- Create: `CODE_OF_CONDUCT.md`
- Create: `SUPPORT.md`
- Create: `GOVERNANCE.md`
- Create: `CHANGELOG.md`
- Create: `.github/CODEOWNERS`
- Create: `.github/PULL_REQUEST_TEMPLATE.md`
- Create: `.github/ISSUE_TEMPLATE/bug.yml`
- Create: `.github/ISSUE_TEMPLATE/feature.yml`
- Create: `.github/ISSUE_TEMPLATE/config.yml`
- Test: `foundation_tests/test_repository_metadata.py`

- [ ] **Step 1: Write the failing repository metadata test**

```python
from pathlib import Path
import tomllib

ROOT = Path(__file__).parents[1]

def test_repository_has_public_governance_and_uv_workspace() -> None:
    required = {
        "LICENSE", "SECURITY.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md",
        "SUPPORT.md", "GOVERNANCE.md", "CHANGELOG.md",
    }
    assert required <= {p.name for p in ROOT.iterdir()}
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert data["tool"]["uv"]["workspace"]["members"] == ["python"]
```

- [ ] **Step 2: Run the test and observe missing-file failure**

Run: `uv run --with pytest pytest foundation_tests/test_repository_metadata.py -q`  
Expected: FAIL because governance/workspace files do not exist.

- [ ] **Step 3: Add governance files and the `uv` workspace**

The Python package metadata uses:

```toml
[project]
name = "palonexus"
dynamic = ["version"]
requires-python = ">=3.12"
license = "MIT"

[tool.uv.workspace]
members = ["python"]
```

Document DCO sign-off, `uv`-only Python commands, protocol ownership, security
reporting, supported release policy, and the trademark boundary.

- [ ] **Step 4: Run metadata and Markdown checks**

Run: `uv run --with pytest pytest foundation_tests/test_repository_metadata.py -q`  
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md pyproject.toml python/pyproject.toml ruff.toml SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md SUPPORT.md GOVERNANCE.md CHANGELOG.md .github foundation_tests
git commit -m "chore: establish public sdk repository governance"
```

### Task 2: Durable MIT relicensing and provenance

**Files:**
- Create: `docs/legal/RELICENSING.md`
- Create: `docs/legal/PROVENANCE.csv`
- Create: `docs/legal/THIRD_PARTY.md`
- Create: `scripts/verify_legal.py`
- Test: `foundation_tests/test_legal.py`

- [ ] **Step 1: Write failing legal-evidence tests**

Test that:

- `RELICENSING.md` names `rogerchucker/palonexus-platform`, its extraction commit,
  `rogerchucker/palonexus-sdk`, MIT, PaloNexus, and the authorization date.
- Every migrated file later added to `python/`, `guard/`, or `plugins/` has a row
  in `PROVENANCE.csv`.
- Package metadata and archives contain MIT.
- No dependency row has an unreviewed or forbidden license.

- [ ] **Step 2: Run and observe failure**

Run: `uv run --with pytest pytest foundation_tests/test_legal.py -q`  
Expected: FAIL because legal evidence is absent.

- [ ] **Step 3: Add the owner authorization record and inventory format**

`PROVENANCE.csv` columns:

```text
destination,source_repository,source_commit,source_path,owner,contributors_reviewed,migration_method,result_license,reviewer
```

Use `port`, `rewrite`, `new`, or `generated` for `migration_method`.

- [ ] **Step 4: Implement `scripts/verify_legal.py`**

The verifier enumerates source files, validates provenance rows, checks SPDX
metadata, rejects proprietary classifiers, and reports missing review.

- [ ] **Step 5: Run tests and commit**

```bash
uv run --with pytest pytest foundation_tests/test_legal.py -q
uv run python scripts/verify_legal.py
git add docs/legal scripts/verify_legal.py foundation_tests/test_legal.py
git commit -m "docs: record sdk relicensing and provenance policy"
```

### Task 3: Gate 0 Claude Code host fixture

**Files:**
- Create: `plugins/claude-code/tests/fixtures/host-version.json`
- Create: `plugins/claude-code/tests/fixtures/pretooluse/`
- Create: `plugins/claude-code/tests/fixtures/expected-capabilities.json`
- Create: `plugins/claude-code/tests/fixtures/official-contract.json`
- Create: `scripts/capture_claude_fixtures.py`
- Test: `foundation_tests/test_claude_gate0.py`
- Create: `docs/compatibility.md`

- [ ] **Step 1: Write a failing fixture completeness test**

The test requires versioned payloads for Bash, Read, Edit, Write, WebFetch,
WebSearch, and MCP plus evidence that denial, guard failure, and a real
`approval_required` guard result rendered as denial prevent a sentinel command
or file mutation.

- [ ] **Step 2: Run against an empty fixture directory**

Run: `uv run --with pytest pytest foundation_tests/test_claude_gate0.py -q`  
Expected: FAIL listing missing tool families.

- [ ] **Step 3: Capture real fixtures from installed Claude Code**

Use a disposable home and repository. Record installed version `2.1.219` as the
first tested candidate without claiming it is the eventual minimum. Never record
tokens, prompts, user paths, or repository secrets.

Fetch the current official hooks/plugin contract, store its URL, retrieval
timestamp, content digest, documented minimum when present, and relevant
blocking semantics in `official-contract.json`. Determine the minimum supported
version through release/changelog evidence plus executable fixture tests; do
not infer it from the installed candidate alone. Test both that minimum and the
latest available stable host before Gate 0 completes.

- [ ] **Step 4: Prove no-op allow and blocking denial**

The fixture harness must distinguish:

- Hook emits `{}`: host continues native permission behavior.
- Hook emits deny: sentinel does not execute.
- Hook exits `2`: sentinel does not execute.
- Fake guard returns `approval_required`: hook renders denial containing the
  approval ID, and the sentinel does not execute.

- [ ] **Step 5: Update compatibility evidence and commit**

```bash
uv run pytest foundation_tests/test_claude_gate0.py -q
git add plugins/claude-code/tests/fixtures scripts/capture_claude_fixtures.py docs/compatibility.md foundation_tests/test_claude_gate0.py
git commit -m "test: record Claude Code blocking hook contract"
```

### Task 4: Gate 0 Codex host fixture

**Files:**
- Create: `plugins/codex/tests/fixtures/host-version.json`
- Create: `plugins/codex/tests/fixtures/pretooluse/`
- Create: `plugins/codex/tests/fixtures/expected-capabilities.json`
- Create: `plugins/codex/tests/fixtures/official-contract.json`
- Create: `scripts/capture_codex_fixtures.py`
- Test: `foundation_tests/test_codex_gate0.py`
- Modify: `docs/compatibility.md`

- [ ] **Step 1: Write a failing fixture completeness test**

Require recorded payloads for shell/unified execution, apply-patch/file change,
MCP, and every additional local function tool claimed by the plugin. Require a
real `approval_required` fake-guard result to render as host denial and prevent
the sentinel effect.

- [ ] **Step 2: Run against missing fixtures**

Run: `uv run --with pytest pytest foundation_tests/test_codex_gate0.py -q`  
Expected: FAIL.

- [ ] **Step 3: Capture from installed Codex**

Use a disposable home with `codex-cli 0.145.0`. Record hosted or specialized
tools absent from `PreToolUse` as unsupported rather than fabricating fixtures.

Fetch and digest the current official Codex hooks/plugin contract. Establish
the exact minimum through official version evidence and executable tests, then
test both minimum and latest stable Codex. Record unsupported hook families.

- [ ] **Step 4: Prove denial and failure block**

Run sentinel shell and file-change cases. Capture hook response and verify the
sentinel effect does not occur for deny, exit `2`, or an
`approval_required` result rendered as denial.

- [ ] **Step 5: Commit**

```bash
uv run pytest foundation_tests/test_codex_gate0.py -q
git add plugins/codex/tests/fixtures scripts/capture_codex_fixtures.py docs/compatibility.md foundation_tests/test_codex_gate0.py
git commit -m "test: record Codex blocking hook contract"
```

### Task 4B: Machine-enforced Gate 0 completion

**Files:**
- Create: `scripts/verify_host_fixtures.py`
- Test: `foundation_tests/test_gate0_complete.py`
- Modify: `docs/compatibility.md`

- [ ] **Step 1: Write the failing completion gate**

Require nonempty exact minimum and latest-tested versions for both hosts,
official-contract URL/digest/timestamp, every claimed payload fixture, no-op
allow evidence, deny evidence, exit-2 evidence, and approval-as-deny sentinel
evidence.

- [ ] **Step 2: Run and observe incomplete-matrix failure**

Run: `uv run pytest foundation_tests/test_gate0_complete.py -q`  
Expected: FAIL until both host matrices and sentinel evidence are complete.

- [ ] **Step 3: Implement the verifier**

`scripts/verify_host_fixtures.py` validates fixture digests, version ordering,
required scenarios, and compatibility cells. It exits nonzero if either host
minimum/latest job was skipped or unsupported.

- [ ] **Step 4: Run the non-skippable gate before Task 5**

```bash
uv run pytest foundation_tests/test_claude_gate0.py foundation_tests/test_codex_gate0.py foundation_tests/test_gate0_complete.py -q
uv run python scripts/verify_host_fixtures.py
```

Expected: all tests PASS and both exact compatibility rows print.

- [ ] **Step 5: Commit**

```bash
git add scripts/verify_host_fixtures.py foundation_tests/test_gate0_complete.py docs/compatibility.md plugins/*/tests/fixtures
git commit -m "test: enforce complete coding-host feasibility gate"
```

### Task 5: Action and decision schemas

**Files:**
- Create: `protocol/schemas/common-v1.schema.json`
- Create: `protocol/schemas/action-v1.schema.json`
- Create: `protocol/schemas/decision-v1.schema.json`
- Create: `protocol/tests/test_action_decision_schema.py`
- Create: `protocol/test-vectors/action/`
- Create: `protocol/test-vectors/decision/`

- [ ] **Step 1: Write failing schema tests from the approved design**

Tests cover required IDs, adapter diagnostic fields, task, action taxonomy,
side-effect enum, canonical resource hash, both scope hashes, server time,
expiry, outcome enum, and malformed/unknown-major rejection.

- [ ] **Step 2: Run and observe schema-not-found failures**

Run: `uv run --with pytest --with jsonschema pytest protocol/tests/test_action_decision_schema.py -q`

- [ ] **Step 3: Implement JSON Schema 2020-12 documents**

Set:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "additionalProperties": false
}
```

Permit additive compatibility only through explicitly versioned extension maps;
do not silently accept unknown top-level security fields.

- [ ] **Step 4: Add valid and invalid golden vectors**

Include allow, deny, approval-required, missing identity context, malformed
hashes, invalid time order, unknown outcome, and unknown major.

- [ ] **Step 5: Run and commit**

```bash
uv run pytest protocol/tests/test_action_decision_schema.py -q
git add protocol
git commit -m "feat(protocol): define action and decision version 1"
```

### Task 6: Canonicalization and scope hash vectors

**Files:**
- Create: `protocol/canonicalization.md`
- Create: `protocol/test-vectors/canonicalization/`
- Create: `protocol/reference/canonicalize.py`
- Test: `protocol/tests/test_canonicalization.py`

- [ ] **Step 1: Write failing table-driven canonicalization tests**

Cover Unicode NFC, sorted keys, omitted absent values, paths, URLs, shell
redaction, MCP canonical JSON, diagnostic adapter in client hash, and trusted
client ID only in authoritative hash.

- [ ] **Step 2: Observe failure**

Run: `uv run pytest protocol/tests/test_canonicalization.py -q`

- [ ] **Step 3: Implement the small reference canonicalizer**

The reference implementation exists to generate/verify vectors, not as an SDK
transport. It uses deterministic JSON separators and SHA-256.

- [ ] **Step 4: Generate committed vectors and rerun**

Run:

```bash
uv run python protocol/reference/canonicalize.py --write-vectors
uv run pytest protocol/tests/test_canonicalization.py -q
```

- [ ] **Step 5: Commit**

```bash
git add protocol
git commit -m "feat(protocol): freeze canonical scope hashing"
```

### Task 7: Approval and error schemas

**Files:**
- Create: `protocol/schemas/approval-v1.schema.json`
- Create: `protocol/schemas/error-v1.schema.json`
- Create: `protocol/test-vectors/approval/`
- Create: `protocol/test-vectors/error/`
- Test: `protocol/tests/test_approval_error_schema.py`

- [ ] **Step 1: Write failing state and identifier tests**

Test `approvalId` consistency, pending terminal transitions, new authorization
request/idempotency IDs on resume, stable action/correlation IDs, mutation
failure, expiry, duplicate terminal decision, and stable error codes.

- [ ] **Step 2: Run and observe failure**

Run: `uv run pytest protocol/tests/test_approval_error_schema.py -q`

- [ ] **Step 3: Implement schemas and vectors**

Never use authorization `requestId` as the approval identifier. Safe reviewer
references cannot contain email or token values in public fixtures.

- [ ] **Step 4: Run and commit**

```bash
uv run pytest protocol/tests/test_approval_error_schema.py -q
git add protocol
git commit -m "feat(protocol): define approval and error contracts"
```

### Task 8: Reconciliation schema and state machine

**Files:**
- Create: `protocol/schemas/reconciliation-v1.schema.json`
- Create: `protocol/test-vectors/reconciliation/`
- Create: `protocol/reference/reconciliation.py`
- Test: `protocol/tests/test_reconciliation.py`

- [ ] **Step 1: Write failing transition tests**

Cover pending, sending, retry wait, restart recovery, acknowledged, discarded,
duplicate upload, acknowledgement loss, conflict, and ordered batch resume.

- [ ] **Step 2: Observe failure**

Run: `uv run pytest protocol/tests/test_reconciliation.py -q`

- [ ] **Step 3: Implement the reference state machine and schema**

Make acknowledged/discarded terminal. Only authenticated user or organization
retention policy may discard. Persist `nextAttemptAt` for retry wait.

- [ ] **Step 4: Run and commit**

```bash
uv run pytest protocol/tests/test_reconciliation.py -q
git add protocol
git commit -m "feat(protocol): define reconciliation version 1"
```

### Task 9: Reproducible Python and Go protocol generation

**Files:**
- Create: `scripts/generate_protocol.py`
- Create: `python/src/palonexus/_generated/protocol.py`
- Create: `guard/pkg/protocol/generated.go`
- Create: `protocol/tests/test_generated_clean.py`
- Modify: `pyproject.toml`
- Create: `go.mod`

- [ ] **Step 1: Write a failing generated-clean test**

Copy generated outputs, invoke the generator, and assert byte equality.

- [ ] **Step 2: Run and observe missing generator failure**

Run: `uv run pytest protocol/tests/test_generated_clean.py -q`

- [ ] **Step 3: Implement deterministic generation**

Pin the generation dependencies in `uv.lock` and Go tool metadata. Generated
files include a header naming source schemas and the generator version.

- [ ] **Step 4: Generate, format, and test**

```bash
uv run python scripts/generate_protocol.py
uv run pytest protocol/tests/test_generated_clean.py -q
gofmt -w guard/pkg/protocol/generated.go
```

- [ ] **Step 5: Commit**

```bash
git add scripts python/src/palonexus/_generated guard/pkg/protocol go.mod go.sum pyproject.toml uv.lock protocol/tests
git commit -m "build: generate protocol types reproducibly"
```

### Task 10: Foundation CI and verification entrypoint

**Files:**
- Create: `.github/workflows/ci.yml`
- Create: `.github/workflows/codeql.yml`
- Create: `.github/workflows/dependency-review.yml`
- Create: `.github/dependabot.yml`
- Create: `.gitleaks.toml`
- Create: `scripts/verify`
- Test: `foundation_tests/test_workflows.py`

- [ ] **Step 1: Write failing workflow-policy tests**

Require read-only default permissions, pinned action SHAs, Python 3.12/3.13,
Go 1.25, protocol vectors, secret scanning, and no `pip` command.

- [ ] **Step 2: Run and observe failure**

Run: `uv run pytest foundation_tests/test_workflows.py -q`

- [ ] **Step 3: Add workflows and verification script**

Use `uv sync --frozen`; never install Python dependencies with `pip`.

- [ ] **Step 4: Run local foundation gate**

```bash
uv lock --check
uv run pytest foundation_tests protocol/tests -q
uv run python scripts/verify_legal.py
uv run python scripts/verify_host_fixtures.py
```

- [ ] **Step 5: Commit and tag checkpoint**

```bash
git add .github .gitleaks.toml scripts foundation_tests
git commit -m "ci: gate protocol and repository foundation"
git tag protocol-v1-freeze
```
