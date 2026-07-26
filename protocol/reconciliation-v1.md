# Reconciliation version 1 safety boundary

Status: draft pending the non-skippable host feasibility gate. The JSON Schema
is the wire and persisted-record contract; the Python module is an executable
reference state machine.

Reconciliation provides durable at-least-once delivery of safe guard evidence.
A stable `reconciliationId` and evidence hash make duplicate uploads
idempotent. This mechanism does not provide distributed exactly-once execution
for application effects.

## External authoritative partition

Tenant and actor identity are not caller-controlled evidence fields. The store
keeps each record in an external authoritative partition containing the record
tenant and owner subject. Every transition receives a trusted context built
from that partition plus the authenticated tenant and subject. The state
machine rejects a missing record binding, a tenant mismatch, or an owner
subject mismatch. Tenant and subject values are not copied into the public
record, receipt, vector, exception, or log.

An organization retention service may replace the owner-subject match only for
an explicit manual retry or discard, and only when the trusted context carries
verified organization retention authority for the same tenant partition.

An acknowledged transition additionally requires an authenticated server
receipt. Trusted receipt metadata binds the `reconciliationId`, evidence hash,
registered `clientId`, and tenant partition. Only the receipt identifier,
reconciliation identifier, evidence hash, and acknowledgement timestamp are
persisted in public evidence.

## Delivery and crash semantics

The automatic state graph remains:

```text
pending → sending → acknowledged
                  ↘ retry_wait
retry_wait → sending
sending → pending
pending → discarded
```

Every transition uses an atomic compare-and-swap digest. Attempt count and last
attempt time are immutable except when a send transition increments and stamps
them. Restart recovery preserves that history.

`deliveryPolicy.maxAttempts` bounds every record whose disposition is
`automatic`, including `sending`, `retry_wait`, and `acknowledged` records.
Only authenticated manual-intervention transitions may exceed that bound, and
`deliveryPolicy.maxTotalAttempts` bounds those explicit manual attempts. An
acknowledgement preserves the attempt count, disposition, and manual reason
provenance of the sending record. A
retryable failure or restart at the automatic limit returns the record to
`pending` with `deliveryDisposition` set to `manual_intervention`, the safe
reason `attempt_limit_reached`, and no `nextAttemptAt`. The automatic scheduler
does not select it. An authenticated owner or verified organization retention
authority may explicitly retry it or discard it; exhaustion never causes
automatic discard.

Ordered batch selection requires a trusted store checkpoint containing the
batch identifier, authoritative `expectedNextSequence`, and bindings for any
retained acknowledged prefix. A pruned tail is valid only when its first
remaining sequence equals that checkpoint; the function never infers a
completed prefix from the tail. It rejects omitted unresolved records, gaps,
duplicates, input reordering, mismatched retained acknowledgements, and a
terminal item after unresolved work. The input record count cannot exceed the
declared limit and is checked before record parsing. A manual or not-yet-due
head blocks later items.

## Bounds and extensions

Timestamps retain exact RFC 3339 fractional precision, have a 128-character
wire bound, and use stable errors for invalid offsets or date-range overflow.
A canonical record is limited to 64 KiB before persistence or digest
calculation.

There are no registered reconciliation extension keys in version 1. If the
optional `extensions` object is present, it must be empty. Raw prompts,
commands, resource values, credentials, bearer values, and arbitrary strings
do not belong in reconciliation evidence.
