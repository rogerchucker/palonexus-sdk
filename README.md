# PaloNexus SDK

PaloNexus SDK is the planned public integration boundary for the PaloNexus
agent control plane. This repository will contain the Python SDK, local guard,
shared protocol, and thin coding-agent plugins.

Implementation is underway. The repository does not yet publish installable
packages, binaries, or plugins. Until the first release, the committed design
and implementation plans under `docs/superpowers/` describe the intended
interfaces.

## Development

Python development uses [uv](https://docs.astral.sh/uv/) exclusively:

```console
uv sync
uv run pytest
uv run ruff check .
```

See [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a change. Security
reports follow the private process in [SECURITY.md](SECURITY.md).

### Local guard credential storage

The local guard supports macOS and Linux. It stores credentials in the macOS
Keychain through Security.framework or in an unlocked Linux Secret Service
collection. The Secret Service exchange uses the specification's
DH/AES-CBC session to obscure credential bytes on D-Bus; that exchange is not
authenticated transport and does not replace the operating system keyring's
user isolation. A missing or locked native store fails closed; the guard does
not prompt, shell out with secrets, or fall back to plaintext storage. Other
operating systems are currently unsupported.

An AES-GCM file backend exists only for isolated tests. It is disabled unless
the caller uses the explicit testing-only constructor flag and is never
selected by native backend discovery.

Pre-release credential code used ambiguous `tenant:account` keys. Every lookup, write, and explicit delete
attempts removal of the exact service-scoped legacy credential and never reads
it. A cleanup failure fails closed: lookups return no current credential,
writes do not begin, and later operations retry cleanup. Delete attempts both
the current and legacy entries and reports any partial cleanup failure. Users
with only a legacy credential must authenticate again. Local state only owns
canonical current-format filenames: version 0 typed metadata is upgraded in
place to version 1, while unknown versions and arbitrary payloads fail closed.

## License

Source code is licensed under the MIT License. PaloNexus names and logos are
trademarks and are not licensed by the MIT License.
