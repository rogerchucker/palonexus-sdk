# Compatibility

This document records executable host-contract evidence. It is not a promise
about untested versions.

## Gate 0 status

Claude Code Gate 0 is **incomplete** because an exact minimum supported version
is unresolved. Anthropic's current hooks reference documents the required
blocking behavior, but does not state the first release that provides the whole
contract. The changelog does not establish one release that can honestly stand
in for executable testing across all seven required tool families.

Protocol schemas must not be frozen until the machine-enforced combined Gate 0
for Claude Code and Codex passes.

## Claude Code evidence

| Role | Version | Executed | Interpretation |
| --- | --- | --- | --- |
| First observed candidate | 2.1.219 | Superseded | Legacy run lacked enforced isolation and complete raw evidence |
| npm `stable` at capture time | 2.1.212 | Superseded | Legacy denial observation is claim-excluded |
| Exact minimum supported | Unresolved | No | No minimum claim is made |

The legacy candidate emitted `PreToolUse` payloads for Bash, Read, Edit, Write,
WebFetch, WebSearch, and a disposable MCP tool. Those sanitized payload shapes
remain useful interoperability observations, but they are not release
compatibility evidence. The legacy sentinel observations are also retained only
as superseded, claim-excluded records because they lack exact invocation logs,
native-permission baselines, and enforced capture isolation.

A hardened replacement harness now:

- refuses to run model-driven captures without an enforced macOS sandbox;
- passes a strict environment allowlist with credential, token, proxy, and
  cloud variables removed;
- separates local shell/file tools from network web tools;
- rejects every tool input outside the fixture command, path, URL, query, and
  content allowlists before the host can execute it;
- uses strict per-tool payload schemas and fails on unexpected or sensitive
  values;
- records per-scenario nonce, input fingerprint, invocation count, hook/guard
  result, rendered evidence, and sentinel state; and
- compares no-hook and `{}` behavior under explicit native allow and native
  deny configurations without bypass mode.

On this machine the enforced sandbox terminated Claude Code with signal 6
before the first tool invocation. No weaker retry was made. Therefore the
native allow/deny comparisons, blocking scenarios, stable-host scenario, and
minimum version remain unresolved, and Gate 0 remains incomplete.

## Sources and reproduction

The official contract is Anthropic's [hooks reference](https://code.claude.com/docs/en/hooks.md).
Its retrieval timestamp and SHA-256 digest, plus the official changelog digest,
are recorded in
`plugins/claude-code/tests/fixtures/official-contract.json`.

Reproduce the candidate and stable-host experiments with:

```bash
uv run python scripts/capture_claude_fixtures.py
uv run pytest foundation_tests/test_claude_gate0.py -q
```

The capture requires authenticated Claude Code access, network access to the
official documentation and npm registry, and a compatible enforced sandbox. It
uses a disposable home, repository, hook, MCP server, and sentinel files. The
script has no unsafe fallback.
