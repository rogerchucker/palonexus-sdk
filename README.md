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

## License

Source code is licensed under the MIT License. PaloNexus names and logos are
trademarks and are not licensed by the MIT License.
