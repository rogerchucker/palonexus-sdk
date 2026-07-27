# Protocol version 1 canonicalization and scope hashing

Status: draft pending the non-skippable host feasibility gate. The rules and
vectors in this document define the Task 6 contract content, but they do not
freeze or release protocol version 1. The `protocol-v1-freeze` tag is created
only after Gate 0 and the remaining protocol tasks pass.

Canonicalization turns equivalent client-visible action data into the same
UTF-8 byte sequence before hashing. It also separates data supplied by a host
adapter from identity supplied by an authenticated guard or transport. This
page defines the byte-level rules, resource normalizers, and the two scope-hash
inputs. It does not define an SDK transport, make an authorization decision, or
resolve a filesystem object.

All Unicode behavior uses Unicode 15.1.0. The Python reference pins
`unicodedata2==15.1.0`; it does not inherit normalization tables from the
running Python version or host locale. Other implementations MUST use Unicode
15.1.0 and sort normalized keys by Unicode scalar value, not UTF-16 code unit,
UTF-8 byte, collation, or locale order.

Every canonicalized string MUST reject a code point whose general category is
`Cn` (unassigned) in the pinned Unicode 15.1.0 tables. This prevents a later
runtime from silently assigning new normalization or identifier behavior to a
previously unknown scalar value.

## Hash representation

Every hash in this contract is:

```text
sha256:<64 lowercase hexadecimal characters>
```

The hexadecimal value is SHA-256 over the canonical UTF-8 bytes. There is no
implicit salt, prefix, newline, or trailing NUL. A scope input includes
`scopeType` and `scopeVersion` fields for domain separation.

`resourceHash` is SHA-256 over the typed canonical preimage defined under
[Resource preimage](#resource-preimage). `clientScopeHash` and
`authoritativeScopeHash` are SHA-256 over the explicit JSON objects defined under
[Scope-hash inputs](#scope-hash-inputs).

## Canonical JSON

Implementations MUST apply these rules in order:

1. Decode input JSON as UTF-8. Invalid UTF-8 and invalid JSON fail closed.
2. Preserve numbers as exact decimal values while parsing. A parser MUST NOT
   round through an IEEE 754 binary floating-point value.
3. Normalize every string and object key to Unicode NFC.
4. Reject an object containing duplicate keys after NFC normalization. For
   example, `e\u0301` and `\u00e9` are duplicate keys.
5. Omit an absent object member. Serialize an explicitly present null value as
   `null`. An absent array position is invalid because removing it would change
   the positions of later values.
6. Sort object keys in ascending Unicode scalar-value order after NFC
   normalization. Preserve array order.
7. Serialize without insignificant whitespace. The separators are `,` and `:`.
   Emit Unicode directly as UTF-8; apply normal JSON escaping to quotes,
   backslashes, and control characters.
8. Serialize booleans as `true` or `false`, and null as `null`.
9. Serialize an exact decimal without an exponent or insignificant leading or
   trailing zeroes. Negative zero becomes `0`. A nonzero magnitude MUST be in
   the inclusive range `1e-308` through `1e308`.

Programmatic binary floating-point inputs are invalid. A native implementation
can accept an integer or an exact decimal type. A host implementation reading
JSON can retain the source number lexeme and convert it to the normalized
decimal form. NaN and infinities are not JSON and fail closed.

These numeric rules deliberately choose a portable subset instead of relying
on the runtime-specific formatting of `float`, JavaScript `Number`, or Go
`float64`. They apply to nested MCP input as well as other canonical JSON.

### Portable input limits

Implementations MUST enforce these limits before recursive canonicalization:

| Limit | Protocol version 1 value |
|---|---:|
| Encoded JSON input and canonical output | 65,536 UTF-8 bytes |
| Object or array nesting | 32 containers |
| Keys in one object | 256 |
| Items in one array | 1,024 |
| One input or normalized string | 8,192 UTF-8 bytes |
| Significant digits after removing trailing zeroes | 128 |
| Normalized decimal exponent | `-435` through `308` |
| Nonzero adjusted decimal exponent | `-308` through `308` |

The input-size limit is checked before JSON parsing. Native values receive the
same structural and output-size checks. Cycles fail with `cyclic_value`. Other
limit codes are `input_too_large`, `nesting_too_deep`,
`too_many_object_keys`, `too_many_array_items`, `string_too_large`,
`number_too_precise`, and `number_out_of_range`. Invalid input does not surface
a runtime recursion, memory, or decimal-formatting exception as a protocol
result.

## Resource normalizers

Resource normalizers produce a stable value to hash. They do not authorize the
resource and do not execute the proposed action.

Each normalizer returns a prepared canonical `resource` string and the exact
normalized `execution` value the adapter passes to its host. The adapter MUST
execute that prepared value. If the host API can execute only the canonically
distinct raw input, the adapter MUST fail closed. Normalizing one value for
authorization and executing another is outside this contract.

### POSIX paths

Protocol version 1 supports POSIX path syntax on the supported macOS and Linux
hosts:

- Normalize the captured path and working directory to Unicode NFC.
- Require the captured working directory to be absolute.
- Join a relative path to that captured working directory.
- Remove empty and `.` segments. Apply `..` lexically without traversing above
  `/`.
- Emit one leading slash and no trailing slash except for `/`.
- Reject NUL, backslash syntax, and a relative working directory.
- Do not call `stat`, inspect a symlink, resolve an inode, or access the
  filesystem.

The result is a lexical authorization name. It does not claim that two names
refer to the same inode or that one name will continue to refer to the same
object. In particular, `/workspace/link/../secret` canonicalizes to
`/workspace/secret` even when `link` might be a symlink. An enforcement layer
that cannot guarantee execution against the canonical path MUST deny the
operation or add OS-level path enforcement; it must not treat the hash as proof
of a physical target.

The prepared resource is `path:<canonical-absolute-path>`. The prepared
execution value is the canonical path without `path:`. An adapter passes that
execution value to the file operation.

Windows companion enforcement is outside the initial release. A Windows path
MUST NOT be silently interpreted using POSIX rules.

### HTTP and HTTPS URLs

URL normalization applies this policy:

- Accept only `http` and `https`.
- Reject backslashes, raw or decoded controls, user information, an empty host,
  authority percent encoding, and IPv6. Discard the fragment.
- Lowercase the scheme and host. A DNS host must already be ASCII A-label form,
  contain no empty or underscore label, have labels of 1–63 characters, have a
  total length of at most 253 characters, and have no trailing dot. Protocol
  version 1 does not perform runtime-dependent Unicode IDNA conversion.
- Validate each `xn--` label as IDNA2008 with STD3 rules, strict processing,
  and no UTS 46 or transitional mapping, then require an exact decode/re-encode
  round trip. The Python reference pins `idna==3.18`. Other implementations
  MUST produce the same accepted, canonical, and rejected results recorded in
  `idna2008-a-label.json`; malformed, disallowed, contextual-rule-invalid, and
  bidi-invalid A-labels fail with `invalid_url_host`.
- IDNA category, combining-class, normalization, and bidi lookups MUST use the
  pinned Unicode 15.1.0 tables, never the host runtime tables. The Python
  reference clones the required pure-Python `idna.core` functions into private
  function globals bound to `unicodedata2==15.1.0`; it never mutates
  `idna.core.unicodedata` or another process-global dependency. It asserts both
  dependency versions before exposing an operation. In particular,
  `xn--8g0n.example` is accepted identically on Python 3.12 and Python 3.13.
- Accept IPv4 only as canonical dotted decimal. Reject shortened,
  single-number, octal-looking, hexadecimal-looking, zero-padded, and other
  ambiguous numeric forms.
- Remove port 80 from HTTP and port 443 from HTTPS. Preserve another valid
  port. Port syntax is unpadded unsigned decimal in the range 1–65535.
- Use `/` for an empty path. Normalize percent escapes to uppercase, decode
  percent-encoded unreserved characters, encode Unicode as UTF-8 percent
  escapes, and remove dot segments by RFC 3986 section 5.2.4. Preserve empty
  path segments, so `/a//b` and `/a/b` remain distinct. A percent-encoded
  reserved character remains encoded, so `a%2Fb` and `a/b` remain distinct.
- Decode query keys and values as UTF-8, normalize them to NFC, then sort by
  key. Repeated values for the same key preserve their original relative order.
- Interpret `+` as a query-space encoding, then emit that space as `%20`.
- Replace the value of a configured sensitive query key with `[REDACTED]`.
  Sensitive names contain ASCII letters, digits, hyphens, or underscores only.
  Comparison uses ASCII lowercase and treats `_` and `-` as the same separator;
  it never uses runtime Unicode case folding. Encode the resulting query with
  `%20` for a space.
- Reject malformed percent escapes, invalid UTF-8, noncanonical authority
  syntax, invalid ports, and unsupported schemes.

Query-key sorting is part of the authorization contract even though some
applications assign meaning to query order. Reordering values attached to the
same repeated key therefore remains significant. Integrations for an endpoint
where key order itself is significant need a different typed resource
normalizer; they must not reuse this URL contract.

Fragments do not contribute to URL authorization scope. Configured secret query
values contribute only through the protected execution hash below. URL user
information is rejected. The authenticated transport supplies identity
separately.

The protocol defaults are `access_key`, `access_token`, `api_key`, `apikey`,
`authorization`, `code`, `credential`, `password`, `secret`, `signature`, and
`token`. A deployment can add sensitive keys but cannot remove these defaults.

The prepared execution URL applies the same authority, Unicode, path, and query
ordering rules but retains sensitive query values needed by the request. The
prepared resource is canonical JSON:

```json
{
  "executionHash": "sha256:<hash of the typed full execution URL preimage>",
  "url": "https://example.com/run?token=%5BREDACTED%5D"
}
```

`executionHash` hashes canonical JSON containing
`preimageType: "palonexus.url-execution"`, `preimageVersion: "1"`, and the full
normalized unredacted URL. Consequently, two credential values have distinct
resources and scope hashes while the diagnostic URL exposes neither value. The
adapter receives the normalized full URL only through the non-logged prepared
execution object; it never executes the raw URL or redacted diagnostic URL.

### Shell commands

A shell resource is the following canonical JSON object:

```json
{
  "commandHash": "sha256:<hash of normalized unredacted UTF-8 command bytes>",
  "tokens": ["<redacted diagnostic tokens>"]
}
```

The normalizer applies NFC to the captured command, calculates `commandHash`
before redaction, and applies POSIX quote, escape, and whitespace tokenization
with shell comments disabled. It does not expand variables, glob paths, parse
subshells, or execute the command. Operators separated by whitespace are
tokens; punctuation attached to a word remains part of that word.

The normalizer redacts all values passed through `-H`, `-Hvalue`, `--header`,
or `--header=value`; configured sensitive assignments and option values; known
authorization and cookie header tokens; and sensitive query values in
case-insensitive HTTP(S) URL tokens. The initial sensitive names are
`access-key`, `access_key`, `api-key`, `api_key`, `authorization`, `cookie`,
`password`, `secret`, and `token`. Matching ignores case and leading hyphens
and treats `_` and `-` as the same separator.

`additional_sensitive_names` extends that mandatory set. Each name is
NFC-normalized and must contain 1–64 ASCII letters, digits, hyphens, or
underscores after normalization. The union redacts `--name value`,
`--name=value`, `NAME=value`, and matching query parameter names inside
HTTP(S) URL tokens. Comparison uses ASCII lowercase and treats `_` and `-` as
the same separator. A deployment can add names but cannot remove defaults. If
tokenization fails, `tokens` is exactly `["[UNPARSEABLE]"]`; the unredacted hash
still binds the scope.

Different commands that reduce to the same redacted token list retain distinct
`commandHash` values. This avoids widening authorization when only a redacted
secret differs. Raw command bytes are never included in the canonical object
or diagnostic context.

Name-based redaction cannot detect every secret. A host normalizer MUST extend
the configured sensitive names for its inputs and MUST NOT log raw input or
pre-redaction tokens. Command hashes can permit guessing of low-entropy input
and must be handled as security metadata, not as public diagnostics.

The command hash binds the proposed top-level shell string. It does not govern
child-process effects or prove distributed exactly-once execution.

The prepared execution value is the NFC-normalized unredacted command. The
prepared resource is canonical JSON containing only `commandHash` and redacted
`tokens`. The adapter executes the prepared command, never canonically distinct
raw bytes.

### MCP tools

An MCP resource has this form:

```text
mcp:<server>/<tool>#sha256:<canonical-tool-input-hash>
```

`server` and `tool` are separate NFC-normalized name segments. Each segment
starts with an ASCII letter or digit and then contains only ASCII letters,
digits, `.`, `_`, or `-`; each is at most 128 characters. Slash, `#`, traversal
segments, and an empty name are invalid.

The suffix is SHA-256 over the complete nested MCP tool input using the
canonical JSON rules. Object-key order and canonically equivalent Unicode do
not change the resource. Array order, a missing field versus null, repeated
array values, and a different exact number do change it. Raw tool input is not
part of the resource string or default diagnostic context.

The prepared MCP execution value contains the NFC-normalized server, tool, and
complete canonicalized tool input. The adapter invokes exactly those values.

## Resource preimage

The client derives `resourceHash`; it does not trust a supplied digest. The
preimage is exactly:

```json
{
  "preimageType": "palonexus.resource",
  "preimageVersion": "1",
  "kind": "local-action",
  "service": "workspace",
  "resource": "path:/workspace/deploy/production.yaml"
}
```

The fields come from the prepared target. `resourceHash` is SHA-256 over the
canonical JSON bytes of this object. Before either scope hash is calculated,
the implementation MUST recompute this digest and compare it with
`target.resourceHash`. A missing or unequal value fails with
`resource_hash_mismatch`. The validated target retains the canonical
`resource`, pairing authorization with the prepared execution value.

## Scope-hash inputs

The two hashes have different producers and different verification purposes.
They MUST NOT be calculated from the whole action document.

### Client scope

The client constructs exactly this object from allowlisted action fields:

```json
{
  "scopeType": "client",
  "scopeVersion": "1",
  "adapter": {
    "id": "codex",
    "version": "0.2.0-alpha.1"
  },
  "task": {
    "taskId": "task_01J5ABCDEFGHJKMNPQRSTVWXY0",
    "sessionId": "session_01J5ABCDEFGHJKMNPQRSTVWXY0"
  },
  "action": "file:write",
  "target": {
    "kind": "local-action",
    "service": "workspace",
    "resourceHash": "sha256:7fcdf880e7ace656f9936da7c355726f97ca513c61896ad04d20aa87f1322b81"
  },
  "sideEffect": "write"
}
```

`clientScopeHash` is SHA-256 over the canonical JSON bytes of that object. The
client first verifies the typed digest against `target.resource`; the digest is
not accepted as an opaque caller assertion.
`adapter.id` and `adapter.version` are included so a client can detect a
decision replayed for a different diagnostic adapter contract. They remain
caller-supplied diagnostics and MUST NOT grant privilege.

The client input excludes:

- `actionId`, `requestId`, `correlationId`, and authorization
  `idempotencyKey`;
- `occurredAt`, diagnostic `context`, and extensions;
- `adapter.hostVersion`;
- the display form of `target.resource`; and
- tenant, actor, agent, delegation, and registered client identity.

Changing an excluded request-attempt field does not change the scope. Changing
the task, action, side-effect class, target kind, target service,
`resourceHash`, adapter ID, or adapter version does.

### Authoritative scope

The authenticated guard or server constructs exactly this outer object:

```json
{
  "scopeType": "authoritative",
  "scopeVersion": "1",
  "clientScope": {
    "...": "the complete client scope object above"
  },
  "trusted": {
    "tenantId": "tenant_example",
    "actorId": "subject_example",
    "agentId": "agent_example",
    "delegationId": "delegation_example",
    "clientId": "registered-codex"
  }
}
```

`tenantId`, `actorId`, and authenticated guard-assigned `clientId` are required
nonempty strings. `agentId` and `delegationId` are optional authenticated
values; when absent, they are omitted rather than serialized as null. Unknown
trusted fields and null identity values fail closed.

`authoritativeScopeHash` is SHA-256 over the canonical JSON bytes of this
object. It covers the complete client scope plus identity obtained from the
trusted transport. A client cannot recompute this hash and must not use it to
choose identity.

Caller-provided `clientId`, tenant, actor, agent, or delegation values outside
this server-owned `trusted` object have no effect. In particular:

- changing `adapter.id` changes both hashes because it changes request
  integrity;
- changing authenticated `clientId` changes only the authoritative hash; and
- claiming a privileged adapter name never becomes a privileged registered
  client identity.

## Reference and vectors

[`reference/canonicalize.py`](reference/canonicalize.py) is an executable
reference for vector generation and independent recomputation from committed
raw inputs. It has no SDK transport surface.

Regenerate the committed vectors:

```bash
uv run python protocol/reference/canonicalize.py --write-vectors
```

Reject vector drift:

```bash
uv run python protocol/reference/canonicalize.py --check-vectors
```

The files under
[`test-vectors/canonicalization/`](test-vectors/canonicalization/) cover Unicode
equivalence, duplicate keys, numeric portability, traversal and symlink
ambiguity, URL ordering, shell redaction and collision resistance, nested MCP
JSON, missing versus null, resource-preimage mutation, and the adapter/client
trust boundary. Raw JSON order and Unicode forms, full adapter and trusted
client-ID mutations, concrete rejected numbers, and path/URL collision pairs
remain in vector inputs. Each vector is marked `draft-pending-gate-0`.

The structural action and decision boundary is defined in
[`validation-v1.md`](validation-v1.md). Approval, resume, error, and
reconciliation semantics remain owned by later protocol tasks.
