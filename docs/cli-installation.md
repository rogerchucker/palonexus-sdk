# Install the standalone `pnxs` CLI

Use a standalone `pnxs` executable for agent registration. Keep it separate
from the virtual environment that contains an agent's runtime dependencies.

## Install

Install the released tool with `uv`:

```console
uv tool install palonexus
```

Confirm which executable and version your shell will use:

```console
command -v pnxs
pnxs version
```

The executable must not be inside the agent project's `.venv` directory.

For local pre-release testing from an SDK checkout, install that checkout into
the isolated tool environment:

```console
uv tool install --reinstall ./python
```

## Upgrade

Upgrade the standalone tool before registration when the tenant reports an
incompatible version:

```console
uv tool upgrade palonexus
pnxs version
```

Registration commands query the authenticated tenant before they create a
workspace, credential, or server registration. A compatible command prints the
resolved executable, installed version, and tenant-supported range. An
incompatible command stops with `No changes were made` and gives the upgrade
command.

## Register an agent

Sign in, then register from the existing agent definition:

```console
pnxs login --tenant TENANT
pnxs agents add --from PATH --name AGENT_NAME --tenant TENANT
```

`pnxs agents register` remains available for an initialized project. Both
registration commands use the same compatibility check and exact recovery
rules.
