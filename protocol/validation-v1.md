# Draft protocol version 1 validation boundary

Status: draft pending the non-skippable host feasibility gate. This document
does not freeze protocol version 1.

Task 5 defines structural action and decision documents. JSON Schema 2020-12
enforces required fields, enums, closed object shapes, identifier and hash
syntax, diagnostic string safety, and explicitly versioned extension maps.

The sole cross-field semantic in Task 5 is:

```text
expiresAt > serverTime
```

The reference validator strictly parses every timestamp in an action or
decision, including `occurredAt` and an embedded approval's `expiresAt`, and
enforces the decision ordering. RFC 3339 timestamps permit any nonempty number
of fractional-second digits. The validator compares them exactly after
normalizing the integral second to UTC; it does not truncate through floating
point or fixed microsecond precision. JSON Schema `format` is not relied on
because format assertion is optional and JSON Schema cannot compare two
fields. The validator does not apply a lifetime ceiling, wall-clock freshness
check, clock policy,
authorization policy, action classification policy, or reason-code registry.

Task 6 owns canonicalization, client and authoritative scope-hash calculation,
and cross-document action-to-decision binding. Task 7 owns approvals, resume,
errors, and their state transitions. Task 5 does not define those semantics.

## Portable structural constraints

Schema regular expressions use syntax shared by ECMAScript and Go RE2: simple
anchors, groups, alternation, repetition, and character classes. They do not
use lookahead, lookbehind, or noncapturing groups. Fixed-width identifiers and
hashes combine exact length limits with allowed character classes so a trailing
line feed cannot be accepted by end-anchor behavior.

Diagnostic fields allow intended Unicode but reject C0 and C1 controls, DEL,
ANSI escape, Unicode line and paragraph separators, and bidirectional control
characters. DNS service names cannot contain slashes or traversal components.
Canonical resource strings reject backslashes, controls, and `.` or `..` path
segments.

## Extensions and redaction

Extension namespaces are explicitly versioned. Schemas bound names at every
object depth, object and array counts, and individual string sizes where those
limits are directly expressible. Extension numbers must be finite and in the
inclusive portable range `[-1e308, 1e308]`. Recursive depth and aggregate wire
size belong at the transport/client boundary rather than this Task 5 schema.

Redaction and secret exclusion are a consumer obligation. Callers must not put
tokens, passwords, credentials, prompts, commands, or file contents in
extensions, and consumers must never log raw extension values. Arbitrary
secret detection is not reliable and is not presented as a protocol guarantee.

The CLI emits stable validation codes without echoing protocol contents.
