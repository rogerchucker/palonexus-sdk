# Draft protocol version 1 approval and error safety

Status: draft pending the non-skippable host feasibility gate. This document
does not freeze protocol version 1.

## Approval state and time

Approval storage applies a pending-to-terminal transition with an atomic
compare-and-swap. The caller supplies the revision it observed, and the store
compares that revision with the current record in the same transaction that
writes the terminal record. A second writer reads the terminal record and can
only receive the same semantic result idempotently or an
`idempotency_conflict`; it cannot apply another terminal result.

An identical terminal retry is recognized after structural, creation-identity,
and compare-and-swap precondition checks but before current-time expiry checks.
It returns the existing result even after expiry. A different outcome,
reviewer, decision, reason, or idempotency identity remains a conflict.
For that no-op replay, a regenerated `decidedAt` may itself be after expiry;
the existing stored terminal record remains authoritative and is not mutated.

Duplicate pending creation is anchored by the originating authorization
decision and the immutable creation identity. A retry that generated a
different `approvalId` receives the existing pending record and its
`approvalId`; the authorization `requestId` is never reused as an approval
identifier. Regenerated server metadata (`requestedAt`, `expiresAt`, and
`creationAuditRef`) is not part of duplicate identity and never replaces the
metadata already stored on the existing record.

Resume expiry is evaluated against trusted server time. `occurredAt` is audit
metadata and cannot extend an approval. RFC 3339 fractional seconds have
arbitrary precision. Go implementations must compare the exact fractional
digits after timezone normalization and must not truncate the comparison
through `time.Time`, nanoseconds, floating point, or another fixed-width
timestamp representation.

## Safe errors

Protocol v1 uses a canonical safe message registry. A sender cannot choose
`safeMessage`; its value must exactly match the template registered for
`code`. This construction prevents a raw command, password, bearer value, API
key, credential URL, prompt, or upstream response from entering the public
message field.

| Code | Canonical `safeMessage` |
| --- | --- |
| `invalid_request` | `The request is invalid.` |
| `missing_identity` | `Identity is required.` |
| `unsupported_protocol` | `The protocol version is unsupported.` |
| `authentication_failed` | `Authentication failed.` |
| `authorization_unavailable` | `Authorization is temporarily unavailable.` |
| `invalid_decision` | `The authorization decision is invalid.` |
| `idempotency_conflict` | `The idempotency key conflicts with an earlier request.` |
| `approval_expired` | `The approval has expired.` |
| `approval_scope_mismatch` | `The action no longer matches the approved scope.` |
| `credential_revoked` | `The credential has been revoked.` |
| `policy_denied` | `Current policy denies this action.` |

There are no registered error extension keys in protocol v1, so the error
extension object, when present, must be empty. Adding a future key requires
schema and version review; an implementation cannot accept a namespaced
free-form value ahead of that review.

Renderers treat even validated error text as untrusted. An HTML renderer must
HTML escape text and insert it through a text API. A terminal renderer must not
emit control sequences and should preserve the host's normal quoting boundary.
Every renderer must never evaluate, execute, interpolate, or parse
`safeMessage` or extension text as code, markup, a command, a URL to fetch, or
host configuration.
