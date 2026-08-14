# SPDX-License-Identifier: MIT
from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import commands


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pnxs", allow_abbrev=False)
    subcommands = parser.add_subparsers(dest="command", required=True)

    login = subcommands.add_parser("login", allow_abbrev=False)
    login.add_argument("--tenant")
    login.add_argument("--auth-url")
    login.add_argument("--allow-file-credential-store", action="store_true")
    login.set_defaults(handler=commands.login)

    agents = subcommands.add_parser("agents", allow_abbrev=False)
    agent_commands = agents.add_subparsers(dest="agent_command", required=True)
    init = agent_commands.add_parser("init", allow_abbrev=False)
    init.add_argument("path")
    init.add_argument("--name", required=True)
    init.add_argument("--allow-file-credential-store", action="store_true")
    init.set_defaults(handler=commands.agents_init)
    for name, handler in (
        ("register", commands.agents_register),
        ("request-authority", commands.agents_request_authority),
        ("status", commands.agents_status),
        ("revoke", commands.agents_revoke),
    ):
        command = agent_commands.add_parser(name, allow_abbrev=False)
        command.add_argument("--allow-file-credential-store", action="store_true")
        command.set_defaults(handler=handler)

    run = subcommands.add_parser("run", allow_abbrev=False)
    run.add_argument("agent_file")
    run.add_argument("--input", required=True)
    run.add_argument("--detach", action="store_true")
    run.add_argument("--json", action="store_true")
    run.add_argument("--allow-file-credential-store", action="store_true")
    run.set_defaults(handler=commands.run_agent)

    actions = subcommands.add_parser("actions", allow_abbrev=False)
    action_commands = actions.add_subparsers(dest="action_command", required=True)
    wait = action_commands.add_parser("wait", allow_abbrev=False)
    wait.add_argument("action_id")
    wait.add_argument("--json", action="store_true")
    wait.add_argument("--allow-file-credential-store", action="store_true")
    wait.set_defaults(handler=commands.actions_wait)

    logout = subcommands.add_parser("logout", allow_abbrev=False)
    logout.add_argument("--auth-url")
    logout.add_argument("--allow-file-credential-store", action="store_true")
    logout.set_defaults(handler=commands.logout)

    version = subcommands.add_parser("version", allow_abbrev=False)
    version.add_argument("--json", action="store_true", required=True)
    version.set_defaults(handler=commands.version)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.handler(args))
    except commands.CommandError as error:
        print(str(error), file=sys.stderr)
        return error.exit_code


def entrypoint() -> None:
    raise SystemExit(main())
