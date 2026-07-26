# Host compatibility

Codex Gate 0 is incomplete. No Codex tool family is claimed as supported and
the exact minimum remains unresolved.

## Receipt-derived observations

| Executable | Official package and release integrity | Accepted cells | Gate |
| --- | --- | --- | --- |
| `0.124.0` | verified | MCP no-op only | incomplete |
| `0.125.0` | verified | MCP no-op only | incomplete |
| `0.145.0` | verified | MCP no-op only | incomplete |

`0.124.0` is the first official availability candidate. `0.125.0` was selected
as the bounded next candidate because its official release notes specifically
record MCP tool-discovery stabilization. The latest stable executable was also
tested. Every MCP blocking cell ran independently with at most two attempts.

The MCP no-op cells contain correlated Codex JSONL start/completion events,
sanitized hook payload and runner receipts, exact MCP discovery and dispatch
receipts, invocation binding, and sentinel effect. Blocking attempts often
invoked the hook and produced the expected hook or guard result, but Codex
`exec --json` did not emit a corresponding tool-denial item. They therefore
cannot satisfy the required host-event plus tool-call correlation and are not
promoted. Bash, `apply_patch`, and native-permission attempts also did not
produce complete parser-accepted receipt bundles. Searching output text or
inferring execution from an effect is explicitly insufficient.

All host probes ran inside the same hardened outer container: non-root UID,
read-only root, dropped capabilities, no-new-privileges, resource limits,
read-only authentication mount, no source workspace mount, and disposable
work/output mounts. Codex's nested sandbox was disabled only inside that outer
boundary. The persisted runtime canaries and Docker invocation receipts are
validated together with official npm integrity, GitHub release-asset digest,
executable digest, version output, and MCP registration.

The hosted tools such as WebSearch and specialized handlers outside the local
function-tool hook path remain unsupported. Hooks are a useful guardrail and
not a complete enforcement boundary.
