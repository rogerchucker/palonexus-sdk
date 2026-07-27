# Contributing

Contributions are welcome through GitHub issues and pull requests. Discuss
large features or protocol changes in an issue before implementation.

## Developer Certificate of Origin

Every commit must certify the [Developer Certificate of Origin 1.1](https://developercertificate.org/)
with a `Signed-off-by` trailer:

```console
git commit --signoff
```

The sign-off confirms that you have the right to submit the contribution under
this repository's license. It is not a cryptographic signature.

## Development

Use `uv` for all Python environment, dependency, test, build, and publishing
commands. Do not use `pip`, checked-in virtual environments, or ad hoc
requirements files.

```console
uv sync --frozen
scripts/verify
```

The explicit sync is the only verification phase allowed to fetch locked
artifacts. `scripts/verify` then runs frozen, offline, and without syncing. It
also selects the security-patched Go 1.25.12 toolchain declared in `go.mod`;
the module language baseline remains Go 1.25.0.

Keep changes focused, add tests before implementation, update documentation,
and record user-visible changes in `CHANGELOG.md`. Pull requests must explain
their purpose, verification, compatibility impact, and security impact.

## Protocol changes

Files under `protocol/schemas/` and `protocol/test-vectors/` are the
cross-language source of truth. Protocol changes require an issue, compatibility
analysis, updated schemas and golden vectors, and approval from the protocol
code owner. Generated code must be regenerated, not edited by hand. Breaking
changes require a new protocol major version; existing versioned schemas remain
immutable after release except for clarifying non-behavioral corrections.

Report vulnerabilities privately as described in `SECURITY.md`.
