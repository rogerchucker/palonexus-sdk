// SPDX-License-Identifier: MIT

// Package cli implements the palonexus command-line entry point.
package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

// Version is the build version reported by --version. Release builds may set it
// with -ldflags "-X github.com/rogerchucker/palonexus-sdk/guard/internal/cli.Version=<version>".
var Version = "dev"

const MaxCLIRequestBytes = 1 << 20

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

type DaemonLifecycle interface {
	Start(context.Context) error
	Running(context.Context) (bool, error)
	Stop(context.Context) error
	Check(context.Context, []byte, bool) ([]byte, error)
}

// Run executes the CLI and returns a process exit code. It does not close or
// otherwise retain stdout or stderr.
func Run(args []string, stdout, stderr io.Writer) int {
	return RunWithDaemonIO(context.Background(), args, bytes.NewReader(nil), stdout, stderr, nil)
}

// RunWithDaemon wires only daemon lifecycle commands. Authentication, checks,
// and plugin management remain independently injected by their owning tasks.
func RunWithDaemon(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	daemon DaemonLifecycle,
) int {
	return RunWithDaemonIO(ctx, args, bytes.NewReader(nil), stdout, stderr, daemon)
}

func RunWithDaemonIO(
	ctx context.Context,
	args []string,
	stdin io.Reader,
	stdout, stderr io.Writer,
	daemon DaemonLifecycle,
) int {
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
	if command == "status" && len(args) == 1 && daemon != nil {
		return daemonStatus(ctx, stdout, stderr, daemon)
	}
	if command == "guard" && len(args) == 2 && daemon != nil {
		switch args[1] {
		case "start":
			if daemon.Start(ctx) != nil {
				return daemonUnavailable(stderr)
			}
			_, _ = io.WriteString(stdout, "guard started\n")
			return 0
		case "status":
			return daemonStatus(ctx, stdout, stderr, daemon)
		case "stop":
			if daemon.Stop(ctx) != nil {
				return daemonUnavailable(stderr)
			}
			_, _ = io.WriteString(stdout, "guard stopped\n")
			return 0
		case "check":
			return daemonCheck(ctx, stdin, stdout, stderr, daemon, false)
		default:
			return invalidArguments(stderr, command)
		}
	}
	if command == "guard" && len(args) == 3 && daemon != nil &&
		args[1] == "check" && args[2] == "--one-shot" {
		return daemonCheck(ctx, stdin, stdout, stderr, daemon, true)
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

func daemonCheck(
	ctx context.Context,
	stdin io.Reader,
	stdout, stderr io.Writer,
	daemon DaemonLifecycle,
	oneShot bool,
) int {
	if stdin == nil {
		return invalidArguments(stderr, "guard")
	}
	document, err := io.ReadAll(io.LimitReader(stdin, MaxCLIRequestBytes+2))
	if err != nil || len(document) == 0 || len(document) > MaxCLIRequestBytes+1 {
		return invalidArguments(stderr, "guard")
	}
	document = bytes.TrimSuffix(document, []byte{'\n'})
	if len(document) == 0 || len(document) > MaxCLIRequestBytes ||
		bytes.ContainsAny(document, "\r\n") {
		return invalidArguments(stderr, "guard")
	}
	response, err := daemon.Check(ctx, document, oneShot)
	if err != nil || len(response) == 0 || len(response) > MaxCLIRequestBytes ||
		bytes.ContainsAny(response, "\r\n") {
		return daemonUnavailable(stderr)
	}
	_, _ = stdout.Write(response)
	_, _ = io.WriteString(stdout, "\n")
	return 0
}

func daemonStatus(
	ctx context.Context,
	stdout, stderr io.Writer,
	daemon DaemonLifecycle,
) int {
	running, err := daemon.Running(ctx)
	if err != nil {
		return daemonUnavailable(stderr)
	}
	if running {
		_, _ = io.WriteString(stdout, "guard running\n")
	} else {
		_, _ = io.WriteString(stdout, "guard stopped\n")
	}
	return 0
}

func daemonUnavailable(stderr io.Writer) int {
	_, _ = io.WriteString(stderr, "palonexus: guard: unavailable\n")
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
