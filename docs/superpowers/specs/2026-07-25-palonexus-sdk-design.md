# PaloNexus SDK repository design

**Status:** Proposed for implementation  
**Repository:** `github.com/rogerchucker/palonexus-sdk`  
**License:** MIT  
**Package:** `palonexus`  
**Initial protocol version:** `1`

## Purpose

`palonexus-sdk` is the public integration boundary for the PaloNexus agent
control plane. It contains the language SDK, local enforcement companion,
Claude Code plugin, Codex plugin, shared protocol schemas, conformance tests,
and examples needed to govern an action before it executes.

The repository does not implement authorization policy. Each integration sends
the same normalized action to a PaloNexus decision service and receives one of
three outcomes:

- `allow`
- `deny`
- `approval_required`

The control plane remains the authority for identity, registry resolution,
policy, approval state, revocation, and audit.

## Success criteria

The first public release is complete when:

1. A Python application can authorize actions through equivalent synchronous
   and asynchronous clients.
2. LangChain, LangGraph, and Deep Agents examples enforce the same contract.
3. Claude Code and Codex block governed tool calls before execution.
4. The Python SDK and both coding-agent plugins pass the same protocol vectors.
5. Approval does not become a local bypass: execution requires a fresh decision
   over the original scope after approval.
6. Missing identity, malformed responses, and authorization outages fail closed.
7. Offline examples run without a PaloNexus Cloud account or private service.
8. Built wheels, source distributions, guard binaries, and plugin bundles are
   installable from clean environments.
9. CI tests the supported Python, Go, operating-system, and host-plugin matrix.
10. `github.com/rogerchucker/palonexus-sdk` is public and its default branch,
    security settings, documentation, and release evidence are verified.

Authorization retries do not execute application work. The repository proves
idempotent authorization processing and that framework/plugin adapters do not
execute a blocked proposal before approval. It does not claim exactly-once
delivery for arbitrary application side effects; applications remain
responsible for their own transactional or idempotent execution boundary.

## Scope

### Included

- Versioned action, decision, approval, error, and reconciliation schemas.
- A Python package with sync and async authorization clients.
- Framework adapters for LangChain, LangGraph, and Deep Agents.
- Generic DID, verifiable-credential, and OIDC verification helpers required by
  public clients.
- A local `palonexus` guard command and background companion.
- Claude Code and Codex plugins using blocking pre-tool hooks.
- Shared fixtures, mock decision server, golden vectors, and conformance runner.
- Neutral examples and a one-command local demonstration.
- GitHub Actions for CI, security scanning, packaging, and signed releases.
- Migration documentation for users of `palonexus==0.1.0`.

### Deferred from the first release

- CrewAI, AutoGen, and OpenAI Agents SDK adapters. The repository layout and
  adapter protocol must allow these to be added without changing core types.
- Windows companion enforcement. Windows build portability is tested where
  practical, but the initial supported daemon transport is a Unix domain socket
  on macOS and Linux.
- A governed offline allow cache. The initial public release defaults to no
  cached authorization. A later version may accept server-issued cache
  directives after the cache scope and reconciliation protocol are proven.
- Native marketplace publication when a host requires a separate review.
  Signed GitHub release bundles remain required.
- The control-plane decision endpoint and Kubernetes deployment. These remain
  in the platform repository.

### Not included

- Rego modules or an SDK-side policy evaluator.
- A second identity provider, tenant registry, approval database, or audit log.
- Host-local approval that overrides a PaloNexus decision.
- Interception of activity that a host does not expose through a blocking hook.
- Claims that child-process effects or direct user shell activity are governed
  by a coding-agent plugin.

## Design principles

### One protocol, several adapters

Python, Claude Code, and Codex use different host APIs but must serialize the
same action scope and interpret the same decision outcome. Golden protocol
vectors are normative across implementations.

### Thin host plugins

A host plugin:

1. Reads the host hook payload.
2. Converts it to a normalized action.
3. Calls the local guard.
4. Converts the guard decision into the host response.

It does not store a token, derive identity, evaluate policy, or cache a decision.

### Identity is not caller-selected

Host payloads may contribute non-authoritative context such as working
directory, repository, session ID, and tool name. They cannot provide the
effective tenant, subject, agent identity, delegation, or approval authority.
The guard obtains those values from its authenticated session.

### Approval is not allow

`approval_required` prevents execution. An approved request is not replayed as
an allow. The caller retries or resumes the original action, and the control
plane evaluates current identity, registry, policy, revocation, approval
expiry, and exact scope before returning `allow`.

### Preserve native permissions

An SDK or plugin may narrow execution but must not widen the application's or
host's own permissions. A plugin emits no explicit allow override when the
PaloNexus outcome is `allow`; the host continues through its normal permission
flow.

### Fail closed

The following conditions produce a typed denial or enforcement failure:

- Missing authenticated identity.
- Missing tenant or task binding when required.
- Unsupported protocol major version.
- Invalid or malformed decision data.
- Authorization timeout or network failure.
- Failed credential or revocation verification.
- An approval whose scope differs from the retried action.

## System architecture

```text
Python agent ───────────────┐
                           │ normalized ActionRequest
Claude Code hook ──┐       │
                   ├─ guard├──────── decision endpoint ───── control plane
Codex hook ────────┘       │                                  │
                           │ Decision                         │
Python framework adapter ──┘                                  │
                                                              └─ audit
```

Python can call the public decision endpoint directly through its transport.
Laptop plugins call the local guard, which owns device authentication,
short-lived credentials, routing, redaction, and host-independent error
handling.

## Repository structure

```text
palonexus-sdk/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   ├── workflows/
│   ├── CODEOWNERS
│   └── PULL_REQUEST_TEMPLATE.md
├── protocol/
│   ├── schemas/
│   │   ├── action-v1.schema.json
│   │   ├── decision-v1.schema.json
│   │   ├── approval-v1.schema.json
│   │   ├── error-v1.schema.json
│   │   └── reconciliation-v1.schema.json
│   ├── test-vectors/
│   ├── compatibility.md
│   └── taxonomy.md
├── python/
│   ├── pyproject.toml
│   ├── src/palonexus/
│   └── tests/
├── guard/
│   ├── cmd/palonexus/
│   ├── internal/
│   ├── pkg/protocol/
│   └── tests/
├── plugins/
│   ├── claude-code/
│   └── codex/
├── conformance/
├── examples/
│   ├── python-basic/
│   ├── python-async/
│   ├── langchain/
│   ├── langgraph/
│   ├── deepagents/
│   ├── claude-code/
│   ├── codex/
│   └── local-demo/
├── packaging/
├── docs/
├── pyproject.toml
├── uv.lock
├── go.mod
├── LICENSE
├── SECURITY.md
└── README.md
```

The root Python project is a `uv` workspace. The public Python distribution is
`palonexus`; supporting crypto and identity code lives inside that distribution
under explicit modules rather than being copied into a wheel from sibling
directories.

The guard and hook wrappers use one Go module. Shared Go protocol types are
imported rather than copied between binaries.

## Protocol

### Compatibility

- `schemaVersion` is a string containing the major protocol version.
- Implementations must reject an unknown major version.
- Additive optional fields are permitted within a major version.
- Required fields cannot be removed or reinterpreted within a major version.
- Canonical serialization rules define scope hashing and golden-vector output.
- JSON Schema files and golden vectors are committed source artifacts.
- Generated language types must not be edited directly.

Before protocol schemas are frozen, a host-contract feasibility gate records
real hook payloads and responses from the minimum candidate Claude Code and
Codex versions. The gate must prove that each supported host:

- Invokes a blocking pre-tool hook for every claimed tool family.
- Can block execution on a denial or hook failure.
- Allows the plugin to return no permission override on PaloNexus `allow`.
- Does not execute after the plugin renders `approval_required` as a denial.

If a host cannot satisfy these conditions, that tool family is excluded from
the supported coverage matrix. The plugin architecture is not frozen around an
unverified host assumption.

### Action request

An action request identifies an immutable proposed effect. It carries no bearer
credential in its serializable public model.

```json
{
  "schemaVersion": "1",
  "actionId": "act_01J...",
  "requestId": "req_01J...",
  "correlationId": "corr_01J...",
  "causationId": "cause_01J...",
  "idempotencyKey": "authz_01J...",
  "adapter": {
    "id": "codex",
    "version": "0.1.0",
    "hostVersion": "1.2.3"
  },
  "task": {
    "taskId": "task_01J...",
    "sessionId": "session_01J..."
  },
  "action": "file:write",
  "target": {
    "kind": "local-action",
    "service": "workspace",
    "resource": "workspace:/deploy/production.yaml",
    "resourceHash": "sha256:..."
  },
  "sideEffect": "write",
  "occurredAt": "2026-07-25T20:00:00Z",
  "context": {
    "cwd": "/workspace",
    "repository": "example/service"
  }
}
```

Normative fields:

| Field | Requirement |
|---|---|
| `actionId` | Unique proposed execution. Reused only when resuming that action. |
| `requestId` | Unique authorization attempt. Stable across transport retries of that attempt. |
| `correlationId` | Links the task, decisions, approvals, and audit evidence. |
| `causationId` | Optional predecessor action or event. |
| `idempotencyKey` | Stable across transport retries of one authorization attempt; changes for a fresh post-approval attempt. |
| `adapter` | Diagnostic host/package label supplied by the caller; never grants privilege. |
| `task` | Identifies the agent task and host session. |
| `action` | Namespaced verb such as `file:write`. |
| `target` | Typed service and canonical resource scope. |
| `sideEffect` | `read_only`, `write`, `destructive`, or `external`. |
| `context` | Allowlisted, non-authoritative diagnostic fields. |

Raw commands, URLs, prompts, file contents, tokens, and secrets are not included
by default. A local normalizer derives a safe display value and canonical hash.

### Canonicalization

Canonicalization is versioned with the protocol and performed before sending a
request:

- Strings are UTF-8 and normalized to Unicode NFC.
- Object keys are sorted lexicographically.
- Absent optional values are omitted; they are not serialized as `null`.
- Paths are made absolute against the captured working directory, cleaned
  lexically, and never resolved through a symlink merely to calculate scope.
- URLs lower-case the scheme and host, remove a default port, discard
  credentials and fragments, sort query keys, and redact configured sensitive
  values before hashing.
- Shell commands use a redacted token representation and a hash of the
  unredacted bytes calculated locally. Unredacted bytes are not sent as
  diagnostic context.
- MCP targets use the server-qualified tool name plus canonical JSON tool input.

`resourceHash` is the hash of the canonical resource representation. The
client can verify that its action fields match the response `clientScopeHash`.
The server separately returns `authoritativeScopeHash`, which additionally
binds trusted tenant, subject, agent, delegation, and registered client data.
Clients cannot recompute the authoritative hash and must not use it to select
identity.

### Action taxonomy

The initial taxonomy includes:

| Host operation | Action | Target kind |
|---|---|---|
| Shell or subprocess | `shell:exec` | `local-action` |
| Read a file | `file:read` | `local-action` |
| Create or modify a file | `file:write` | `local-action` |
| Delete a file | `file:delete` | `local-action` |
| Local outbound fetch | `web:fetch` | `local-action` |
| Invoke an MCP tool | `mcp:call` | `mcp-tool` |
| Unclassified named tool | `tool:invoke` | `tool` |

New actions are data. Adding an action does not add a policy branch to the SDK
or guard.

### Decision

```json
{
  "schemaVersion": "1",
  "requestId": "req_01J...",
  "decisionId": "dec_01J...",
  "correlationId": "corr_01J...",
  "outcome": "approval_required",
  "reasonCode": "delegation_required",
  "displayReason": "Approval is required for this action.",
  "clientScopeHash": "sha256:...",
  "authoritativeScopeHash": "sha256:...",
  "policyRevision": "policy_42",
  "serverTime": "2026-07-25T20:00:01Z",
  "expiresAt": "2026-07-25T20:05:00Z",
  "approval": {
    "approvalId": "apr_01J...",
    "status": "pending",
    "expiresAt": "2026-07-25T20:15:00Z"
  },
  "auditRef": "audit_01J...",
  "cache": {
    "cacheable": false
  }
}
```

The `outcome` enum is exactly:

- `allow`
- `deny`
- `approval_required`

Every decision contains:

- `clientScopeHash`, which must equal the client's canonical action scope.
- `authoritativeScopeHash`, which additionally binds the server-derived tenant,
  actor, agent, delegation, and registered guard client.
- `serverTime`, an RFC 3339 timestamp used to calculate bounded clock offset.
- `expiresAt`, an RFC 3339 timestamp later than `serverTime`.

The client rejects a decision whose `clientScopeHash` does not match its
request, whose authoritative hash is missing, whose time fields are invalid, or
whose expiry is not later than server time. Approval and reconciliation records
use the same authoritative hash returned by the decision.

An allow is usable only before `expiresAt` and only for the exact request scope.
The SDK does not execute an action; it returns or enforces the decision.

`expiresAt` bounds reuse of the decision and any delay controlled by an SDK
adapter. Implementations use the server time returned with the decision and a
configured maximum clock-skew allowance. An SDK adapter checks validity
immediately before calling application work and reauthorizes when the deadline
has passed or falls inside the skew window.

Coding-host plugins do not reuse an allow: each host `PreToolUse` event performs
one guard check. A later native permission prompt is outside the plugin's
control, so the compatibility documentation must disclose that a host may begin
execution after the point-in-time authorization decision. High-assurance
deployments must combine the plugin with host-managed permissions and
OS/network enforcement. The plugin must not claim continuous authorization
between the hook and an arbitrarily delayed host execution.

### Approval

The approval protocol has a separate `approval-v1` schema. An approval record
contains:

- `approvalId`
- `actionId`
- `correlationId`
- `authoritativeScopeHash`
- `status`
- `requestedAt`
- `expiresAt`
- safe requester and reviewer references
- decision and audit references

The status transitions are:

```text
pending → approved
pending → denied
pending → expired
pending → cancelled
```

Terminal states do not transition. Duplicate creation using the original
authorization request returns the same approval ID. A duplicate decision by a
reviewer returns the existing terminal result; conflicting terminal input is a
conflict.

Approval does not mutate the original authorization result. Resume creates a
new authorization attempt:

- `actionId` and `correlationId` remain unchanged.
- The canonical action, target, side effect, and task remain unchanged.
- `requestId` and authorization `idempotencyKey` are new.
- `causationId` references the prior decision.
- `resumeFromApprovalId` identifies the approval.
- The client re-normalizes the current target and recalculates
  `resourceHash` and `clientScopeHash`.

If the recalculated scope differs, resume fails with
`approval_scope_mismatch` and does not request an allow. If it matches, the
server re-evaluates current identity, registry, policy, delegation, revocation,
approval expiry, and authoritative scope.

Transport retries of this resumed authorization attempt reuse its new
`requestId` and idempotency key. This prevents duplicate billable authorization
processing without replaying the pre-approval `approval_required` result.

### Error

Protocol errors contain a stable code, safe message, identifiers available at
the point of failure, and a retry classification. They do not expose raw
credentials, prompts, commands, or server responses.

Initial categories:

- `invalid_request`
- `missing_identity`
- `unsupported_protocol`
- `authentication_failed`
- `authorization_unavailable`
- `invalid_decision`
- `idempotency_conflict`
- `approval_expired`
- `approval_scope_mismatch`
- `credential_revoked`
- `policy_denied`

### Scope hash and authorization idempotency

The scope hash covers canonical values for:

- Tenant and authenticated actor supplied by the trusted transport layer.
- Agent and task identifiers.
- Action and side-effect class.
- Target kind, service, and canonical resource hash.
- Adapter identity.

The serialized host request does not choose tenant or actor, but the server
includes them when computing its authoritative scope hash.

The same authorization idempotency key with the same canonical authorization
attempt returns the same semantic processing result. The same key with
different canonical content is an `idempotency_conflict`. A fresh
post-approval attempt uses a new key as defined above.

Authorization does not execute the proposed action. Therefore retrying
`decide`, `authorize`, approval reads, or resume authorization cannot by itself
duplicate the application side effect. A framework adapter proves that it does
not call the wrapped tool before an allow and calls it once for one successful
host/framework event. It cannot promise distributed exactly-once effects after
the application begins executing. An ambiguous application result is surfaced
to the application and is never automatically replayed by the SDK.

### Reconciliation

The `reconciliation-v1` schema describes durable delivery of safe local guard
evidence. Each item contains:

- `reconciliationId`
- `actionId`
- `requestId`
- `decisionId`, when a decision was received
- `correlationId`
- registered client ID
- action and target kind
- client and authoritative scope hashes, when available
- outcome and stable reason code
- observed and acknowledged timestamps

Local item states are:

```text
pending → sending → acknowledged
                  ↘ retry_wait
retry_wait → sending
   sending → pending
pending → discarded
```

Only server acknowledgement moves an item to `acknowledged`. A retry reuses the
reconciliation ID. Same ID and same body is idempotent; same ID and different
body is a conflict. `discarded` requires an explicit local retention decision
by the authenticated user or organization retention policy, records a safe
reason, and is terminal. On process restart, an unacknowledged `sending` item
returns to `pending`; retryable delivery failure records `retry_wait` and a
bounded `nextAttemptAt`, after which it returns to `sending`. Vectors cover
duplicate upload, crash before
acknowledgement, acknowledgement loss, conflicting content, and ordered batch
resume.

## Python SDK

### Public modules

```text
palonexus/
├── __init__.py
├── approvals.py
├── client.py
├── async_client.py
├── context.py
├── credentials.py
├── errors.py
├── models.py
├── protocol.py
├── redaction.py
├── retry.py
├── transports/
│   ├── base.py
│   └── http.py
├── identity/
│   ├── did.py
│   ├── oidc.py
│   └── vc.py
├── integrations/
│   ├── langchain.py
│   ├── langgraph.py
│   └── deepagents.py
└── testing/
    ├── fake_transport.py
    └── mock_server.py
```

### Public API

```python
from palonexus import (
    ActionRequest,
    ActionTarget,
    AsyncAuthorizationClient,
    AuthorizationClient,
    DecisionOutcome,
    TaskContext,
)

request = ActionRequest(
    action="inventory:read",
    target=ActionTarget(
        kind="tool",
        service="inventory-api",
        resource="inventory-api:/items/42",
    ),
    task=TaskContext(
        task_id="task_123",
        session_id="session_123",
    ),
    side_effect="read_only",
    correlation_id="corr_123",
    idempotency_key="idem_123",
)

decision = client.decide(request)
if decision.outcome is DecisionOutcome.ALLOW:
    result = inventory.read("42")
```

The equivalent async operation is:

```python
decision = await client.decide(request)
```

Required client operations:

- `decide` returns the typed decision without executing work.
- `authorize` returns an allow or raises a typed outcome exception.
- `request_approval` creates or returns the matching approval request.
- `get_approval` reads approval state.
- `wait_for_approval` waits within a caller-supplied deadline.
- `resume` obtains a new authorization request for the original action and
  preserves its action ID and immutable scope while creating a new request ID
  and authorization idempotency key.
- `task` and `atask` bind task context without process-global mutation.
- `close` and `aclose` release transport resources.

### Transport

`AuthorizationTransport` is the stable adapter boundary. It accepts typed
protocol data and returns typed protocol data. The default HTTP transport:

- Requires an HTTPS endpoint unless explicitly configured for local testing.
- Obtains credentials through `CredentialProvider`.
- Uses separate connect, read, write, and pool timeouts.
- Retries only according to an explicit `RetryPolicy`.
- Redacts errors before exposing them to the application.
- Never falls back to a caller-selected identity after an identity lookup fails.

Sync and async clients share contract tests and must produce equivalent
decisions and exceptions.

### Retry behavior

- Validation, authentication, denial, and idempotency conflicts are not retried.
- A read-only request may retry a retryable connection failure within its
  configured budget.
- Write, destructive, external, and billable requests require an idempotency key
  before retry.
- Ambiguous transport completion reuses the same key and request identity.
- Backoff is bounded and includes jitter.
- Cancellation ends retries and approval polling promptly.
- Authorization retries never invoke application work.
- Ambiguous application execution is never automatically retried.

### Framework adapters

Framework adapters build `ActionRequest` values and depend only on the public
client protocol.

- LangChain gates model and tool execution in sync and async middleware.
- LangGraph interrupts on `approval_required`, persists the immutable action
  scope, and calls `resume` before executing after approval.
- Deep Agents propagates parent task and accountable actor information to
  nested agents and tools.

Unsupported interception points are identified in the compatibility matrix.

### Identity helpers

The public package contains generic:

- Ed25519 key generation and verification.
- `did:key` resolution.
- JWT VC/VP construction and verification.
- Delegation-chain narrowing and expiry verification.
- OIDC discovery and JWT verification with explicit issuer, audience,
  algorithms, and JWKS configuration.

Production key storage is abstracted through `CredentialProvider` and
`KeyStore`. Test-only ephemeral issuance is explicit and cannot become a silent
production default.

## Local guard companion

### Responsibilities

The `palonexus` executable provides:

```text
palonexus login
palonexus logout
palonexus status
palonexus guard run
palonexus guard check
palonexus plugin install claude-code
palonexus plugin install codex
palonexus plugin uninstall <host>
```

The companion owns:

- OIDC authorization code flow with PKCE and nonce verification.
- Verified issuer, audience, signature, and key rotation.
- Device/session state and short-lived authorization credentials.
- Secure credential storage.
- Target routing and client registration.
- Local input normalization and redaction helpers.
- Guard socket lifecycle.
- Fail-closed decision calls.
- Action and reconciliation identifiers.

### Local IPC

- macOS and Linux use NDJSON over a Unix domain socket.
- The runtime directory and socket are user-only.
- The daemon verifies the connecting peer UID where the operating system
  supports it.
- Writes use symlink-safe, atomic file replacement and process locking.
- The CLI can start the daemon when absent, but a failed start returns a denial.
- An unsupported or malformed request receives a structured fail-closed result.

### Client identity

The serialized `adapter.id` is diagnostic and non-authoritative. The initial
release does not claim that a same-user process can cryptographically prove it
is Claude Code or Codex. Peer UID protects the per-user socket from other OS
users but not from another process owned by the same user.

The guard assigns a locally registered `clientId` from the socket/CLI entrypoint
and sends it through authenticated guard credentials. The control plane may use
that registered client identity for audit and compatibility reporting, but
authorization policy must not grant privilege solely from the caller-provided
adapter label. Caller-supplied `adapter.id` is excluded from privilege-bearing
scope inputs. The authenticated, guard-assigned `clientId` is the registered
client value included in the authoritative scope. Strong application identity
requires an organization-managed installation or future platform attestation
mechanism.

### Credential storage

- macOS uses Keychain.
- Linux uses Secret Service when available.
- A file fallback is disabled by default and, if explicitly enabled for test
  environments, encrypts state with a user-supplied key.
- Logout revokes or removes stored session material and deletes local
  reconciliation state according to the documented retention policy.
- Tokens and private keys never appear in command output or debug logs.

### Cache

The first public release does not serve authorization allows from an offline
cache. Internal types reserve server-issued cache directives, but the guard
treats them as non-cacheable until a later protocol version enables a tested
scope and reconciliation contract.

### Reconciliation

Every check has an action ID, request ID, decision ID when available, client,
scope hash, outcome, and timestamp. Local records contain safe metadata rather
than raw tool inputs. Upload is idempotent and removes or marks an item
acknowledged only after server confirmation.

## Claude Code plugin

The plugin includes:

```text
plugins/claude-code/
├── .claude-plugin/plugin.json
├── hooks/hooks.json
├── skills/palonexus-governed-actions/SKILL.md
├── cmd/palonexus-claude-hook/
└── tests/fixtures/
```

`PreToolUse` matches:

- `Bash`
- `Read`
- `Edit`
- `Write`
- `WebFetch`
- `WebSearch`
- MCP tools

Mapping remains honest about the fields supplied by each host tool. Unknown
tools use `tool:invoke`.

Outcome rendering:

| PaloNexus outcome | Claude response |
|---|---|
| `allow` | No permission decision; native permissions continue. |
| `deny` | `permissionDecision: "deny"` with a safe reason. |
| `approval_required` | Deny with request ID and retry instructions. |
| Guard error | Deny or command exit `2`. |

The interactive plugin does not map server approval to Claude's local `ask`.
That would permit a local confirmation to bypass server reauthorization.
Claude's deferred noninteractive behavior may be supported later through a
coordinator that proves resume and reauthorization.

## Codex plugin

The plugin includes:

```text
plugins/codex/
├── .codex-plugin/plugin.json
├── hooks/hooks.json
├── skills/palonexus-governed-actions/SKILL.md
├── cmd/palonexus-codex-hook/
└── tests/fixtures/
```

`PreToolUse` covers the tool families exposed by the supported Codex versions,
including shell/unified execution, file changes, and MCP tools. The
compatibility document lists hosted and specialized tools that are not exposed
to hooks.

Outcome rendering:

| PaloNexus outcome | Codex response |
|---|---|
| `allow` | No permission decision; native permissions continue. |
| `deny` | Hook-specific deny with a safe reason. |
| `approval_required` | Deny with request ID and retry instructions. |
| Guard error | Deny or command exit `2`. |

Codex does not receive `permissionDecision: "ask"` because that response is not
a supported approval mechanism. Approval always requires a later fresh tool
attempt.

## Plugin installation and trust

- Plugin bundles are host-native and versioned separately from the protocol.
- A plugin declares its minimum and tested host versions.
- Installation verifies the guard binary is present and reports login state.
- Session-start diagnostics never authorize a tool.
- Uninstall removes the host registration without silently deleting unrelated
  user settings.
- Organization-managed installation is required for enforcement that users
  cannot disable.
- The documentation states that hook enforcement does not govern direct shell
  activity, unexposed hosted tools, or child-process sub-effects.

## Examples

All examples use synthetic identities, reserved domains, deterministic fixtures,
and neutral resources.

Required CI-run examples:

1. Python sync: deny, request approval, approve in a fake service, resume,
   obtain allow, execute once, and correlate audit evidence.
2. Python async parity.
3. LangChain guarded tool call.
4. LangGraph approval interrupt and durable resume.
5. Deep Agents nested attribution.
6. Claude Code allow, deny, approval, malformed input, and guard outage fixtures.
7. Codex allow, deny, approval, malformed input, and guard outage fixtures.
8. Guard CLI against a local mock decision server.
9. Redaction proving tokens and secret-looking arguments are absent from output.
10. Idempotency proving authorization retries do not duplicate decision
    processing, and each allowed framework/host event invokes its wrapped action
    once.
11. A local demonstration runnable with one documented command.

Offline examples do not call private cluster addresses or require credentials.

## Testing

### Test-driven implementation

New behavior starts with a failing test. Protocol tests are written before
language implementations. Each supported action family has allow, deny,
approval, invalid-input, and unavailable-authority cases.

### Protocol conformance

One vector set validates:

- Canonical serialization.
- Scope hashing inputs.
- Unknown-major rejection.
- Additive-field compatibility.
- Stable outcome and error mapping.
- Duplicate, orphaned, and conflicting identifiers.
- Equivalent Python, guard, Claude, and Codex results.
- Approval creation, terminal decisions, expiry, resume, mutation, and conflict.
- Reconciliation retry, acknowledgement loss, deduplication, and conflict.

### Security

Required tests cover:

- Missing tenant, identity, task, and credential.
- Wrong JWT issuer, audience, algorithm, key, signature, and nonce.
- Credential rotation and revocation.
- Secret redaction from exceptions, logs, audit fixtures, and hook output.
- Socket ownership, peer checks, permissions, symlinks, and concurrent writes.
- Approval expiry, revocation, policy change, and resource mutation before retry.
- Idempotency conflicts and ambiguous network completion.
- Authorization retry without application execution.
- One wrapped invocation for one allowed framework or host event.
- Unknown host tool and malformed hook payload.
- Guard crash, timeout, and unavailable decision service.
- Host allow behavior that does not override native permissions.

### Packaging

Python:

- Python 3.12 and 3.13.
- Locked and lowest-supported dependencies.
- Ruff, strict mypy, and pytest.
- Wheel and source distribution builds.
- Clean installation of each artifact without workspace paths.
- Import, typing marker, extras, and example smoke tests.

Go:

- Go 1.25 is the initial build toolchain.
- Format, vet, staticcheck, unit, race, and fuzz tests.
- Required runtime tests: Ubuntu 24.04 amd64 and macOS 14/15 arm64.
- Required cross-builds: Linux amd64/arm64 and macOS amd64/arm64.
- Cross-built but untested combinations are labeled experimental, not
  supported.
- Reproducible release builds where toolchains permit.

Plugins:

- Manifest validation.
- Recorded native hook fixtures.
- Disposable-host installation.
- Install, upgrade, and uninstall behavior.
- Scheduled compatibility smoke tests isolated from required pull-request CI.
- Before any prerelease, `docs/compatibility.md` records the exact minimum and
  tested Claude Code and Codex versions established by the host feasibility
  gate. Publication fails if either value is absent.

## Public repository governance

Required files:

- `LICENSE`
- `README.md`
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CODE_OF_CONDUCT.md`
- `SUPPORT.md`
- `GOVERNANCE.md`
- `CHANGELOG.md`
- `CODEOWNERS`
- Issue forms and pull-request template
- Dependabot configuration

Contributions use Developer Certificate of Origin sign-off. PaloNexus names and
logos remain trademarks even though the code is MIT-licensed.

Relicensing evidence is committed under `docs/legal/`:

- `RELICENSING.md` records the copyright owner's authorization, date, source
  repository, destination repository, and MIT terms.
- `PROVENANCE.csv` lists every migrated or rewritten source file, original
  path/commit, copyright owner, contributor review, migration method, and
  resulting license.
- `THIRD_PARTY.md` records dependencies, generated code, licenses, and required
  notices.

CI rejects imports or links to proprietary platform-internal packages, scans
fixtures and artifacts for private identifiers, validates package license
metadata, and runs a dependency-license policy. A maintainer reviews files with
non-PaloNexus contributors before migration rather than assuming the repository
owner controls every contribution.

GitHub configuration:

- Public visibility and `main` as default.
- Issues, Discussions, dependency graph, Dependabot, private vulnerability
  reporting, secret scanning, push protection, and CodeQL enabled.
- A `main` ruleset requiring pull requests, current required checks,
  conversation resolution, no force push, and no deletion.
- Read-only workflow tokens by default.
- Third-party actions pinned to immutable commits.
- Protected release environments and release tags.

## Releases

Release artifacts:

- `palonexus` wheel and source distribution.
- macOS and Linux guard archives.
- Claude Code plugin archive.
- Codex plugin archive.
- SHA-256 checksum manifest.
- SPDX or CycloneDX SBOMs.
- Sigstore signatures where supported.
- GitHub artifact attestations and provenance.

Python publishing uses PyPI Trusted Publishing. GitHub releases are built once
from a signed tag, and publishing jobs promote the tested artifacts rather than
rebuilding them.

Release verification downloads public artifacts into clean environments and
runs the documented quickstarts. Release notes record protocol version, source
commit, toolchain versions, supported host versions, known interception gaps,
and migration information.

The repository initially publishes a prerelease such as `0.2.0a1`. A stable
release follows only after live control-plane conformance and host compatibility
evidence are complete.

## Migration from the platform repository

The extraction preserves useful behavior but does not copy the existing layout
unchanged.

### Port with attribution

- Typed domain models and error concepts.
- Task context behavior.
- Generic DID, VC, VP, delegation, and OIDC verification.
- LangChain, LangGraph, and Deep Agents enforcement semantics.
- Guard taxonomy, socket/CLI structure, host normalization concepts, and
  negative protocol tests.
- Offline example behavior after replacing product-specific fixtures.

### Reimplement

- The large synchronous facade as focused sync and async clients.
- Cross-directory wheel bundling as a normal standalone package.
- Local issuer storage behind credential and keystore interfaces.
- Platform-policy fakes as a programmable transport and mock server.
- OIDC and STS handling with full verification.
- Cache and reconciliation behavior.
- Host approval rendering.
- Authenticated guard client registration while keeping caller adapter labels
  diagnostic and non-authoritative.

### Exclude

- Private cluster endpoints and internal ports as defaults.
- Northstar, Meridian, Incy, Logto, runbooks, and partner fixtures.
- Internal issue identifiers and private file references.
- Control-plane or Kubernetes implementation.
- Unencrypted local private keys or tokens.
- Any code not owned by PaloNexus or not compatible with MIT.

The extraction commit records that PaloNexus authorized relicensing its owned
SDK and plugin source under MIT on 2026-07-25.

## Delivery sequence

1. Run Gate 0 against current official Claude Code and Codex host contracts,
   record fixtures, and establish the exact blocking coverage and minimum
   versions. Failure to verify either required plugin's claimed blocking path
   blocks publication; it cannot be hidden by silently shrinking the success
   criteria.
2. Establish governance, CI skeleton, and protocol schemas.
3. Implement golden vectors and language-neutral conformance.
4. Implement Python models, transports, sync client, and async client.
5. Implement approval/resume, identity helpers, redaction, and retry behavior.
6. Implement framework adapters and neutral examples.
7. Implement the hardened guard companion.
8. Implement Claude Code and Codex plugins against the guard contract.
9. Run cross-adapter, packaging, security, and install tests.
10. Publish the public GitHub repository and prerelease artifacts.
11. Run live control-plane and host compatibility evidence before stable release.

Protocol schemas and vectors are frozen before parallel adapter implementation.
One integration owner controls schema changes, shared exports, release metadata,
and final merges.

The initial release matrix is:

| Component | Required tested targets |
|---|---|
| Python | CPython 3.12 and 3.13 on Ubuntu; clean install smoke on macOS |
| Guard | Go 1.25; Ubuntu 24.04 amd64; macOS 14/15 arm64 |
| Archives | Linux amd64/arm64; macOS amd64/arm64 |
| Claude plugin | Exact minimum and latest tested versions recorded by Gate 0 |
| Codex plugin | Exact minimum and latest tested versions recorded by Gate 0 |

Gate 0 host versions are deliberately obtained from live official host
contracts because they change independently of this repository. The repository
cannot publish a prerelease while those exact version cells are unset.

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| SDK behavior drifts from the control plane | Shared live conformance and versioned schemas. |
| Local approval bypasses policy | Approval blocks; retry performs fresh authorization. |
| Plugin allow widens host permissions | Emit no allow override. |
| Raw tool arguments leak secrets | Local redaction and canonical hashes by default. |
| Cached decision authorizes a wider scope | No public v1 allow cache. |
| Host lacks a blocking hook | Mark the tool unsupported; do not claim coverage. |
| Plugin is disabled or bypassed | Document the boundary; use managed installation and OS controls for stronger assurance. |
| Extracted source carries proprietary coupling | Provenance review, neutral fixtures, MIT metadata, and reverse-import CI. |
| Public artifacts differ from tested builds | Build once, attest, promote, and verify downloaded artifacts. |
| Same-user process impersonates a plugin | Treat adapter as diagnostic; do not authorize from the label. |
| Native permission prompt outlives decision | Treat hook decision as point-in-time and document host limitation. |
| Authorization success is confused with exactly-once execution | SDK never retries application work and makes no distributed exactly-once claim. |

## Design decisions

1. The repository and extracted PaloNexus-owned source use the MIT license.
2. The public protocol is the source of truth; no client evaluates policy.
3. Python ships as one normal standalone distribution without cross-directory
   vendoring.
4. Plugins call one hardened local guard and contain no credentials or cache.
5. `approval_required` blocks in both coding-agent hosts.
6. Plugin allow emits no native permission override.
7. The initial public release has no offline allow cache.
8. The decision endpoint stays in the platform repository.
9. GitHub release bundles are the initial plugin distribution channel.
10. A prerelease precedes the stable public release.
11. Adapter labels are diagnostic in v1 and cannot independently grant privilege.
12. Authorization idempotency is per attempt; resume creates a new attempt for
    the same immutable action.

## Open implementation details

The implementation plan must resolve these details without changing the design:

- Exact JSON Schema draft and code-generation tool.
- Concrete Go keyring library and Linux Secret Service fallback.
- Exact minimum Claude Code and Codex versions established by Gate 0 before
  prerelease publication.
- Public decision endpoint path and authentication configuration names.
- Whether the local demo uses a Go mock server or a Python mock server.
- Release version chosen after inspecting the existing PyPI `0.1.0` artifact.
