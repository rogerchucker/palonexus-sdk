// SPDX-License-Identifier: MIT

// Package cli implements the palonexus command-line entry point.
package cli

import (
	"fmt"
	"io"
)

// Version is the build version reported by --version. Release builds may set it
// with -ldflags "-X github.com/rogerchucker/palonexus-sdk/guard/internal/cli.Version=<version>".
var Version = "dev"

const rootHelp = `Usage: palonexus <command> [options]

Commands:
  login    Authenticate this user
  logout   Remove this user's session
  status   Show local guard status
  guard    Authorize an action
  plugin   Manage host plugins

Options:
  -h, --help     Show help
  --version      Show version
`

var commands = map[string]struct{}{
	"login":  {},
	"logout": {},
	"status": {},
	"guard":  {},
	"plugin": {},
}

// Run executes the CLI and returns a process exit code. It does not close or
// otherwise retain stdout or stderr.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = io.WriteString(stdout, rootHelp)
		return 0
	}

	if args[0] == "-h" || args[0] == "--help" {
		if len(args) != 1 {
			return invalidArguments(stderr, "")
		}
		_, _ = io.WriteString(stdout, rootHelp)
		return 0
	}
	if args[0] == "--version" {
		if len(args) == 2 && args[1] == "--json" {
			_, _ = fmt.Fprintf(stdout,
				"{\"name\":\"palonexus\",\"version\":%q,\"protocolVersion\":\"1.0\"}\n", Version)
			return 0
		}
		if len(args) != 1 {
			return invalidArguments(stderr, "")
		}
		_, _ = fmt.Fprintf(stdout, "palonexus %s\n", Version)
		return 0
	}

	command := args[0]
	if _, ok := commands[command]; !ok {
		_, _ = io.WriteString(stderr, "palonexus: unknown command\n")
		return 2
	}
	if command == "plugin" && len(args) > 1 {
		return runPluginCommand(args[1:], stdout, stderr)
	}
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help") {
		_, _ = fmt.Fprintf(stdout, "Usage: palonexus %s\n", command)
		return 0
	}
	if command == "status" && len(args) > 1 {
		return runStatusCommand(args[1:], stdout, stderr)
	}
	if len(args) != 1 {
		return invalidArguments(stderr, command)
	}

	_, _ = fmt.Fprintf(stderr, "palonexus: %s: not implemented\n", command)
	return 1
}

func invalidArguments(stderr io.Writer, command string) int {
	if command == "" {
		_, _ = io.WriteString(stderr, "palonexus: invalid arguments\n")
	} else {
		_, _ = fmt.Fprintf(stderr, "palonexus: %s: invalid arguments\n", command)
	}
	return 2
}
