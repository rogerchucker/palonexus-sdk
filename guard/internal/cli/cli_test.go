// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"strings"
	"testing"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestRootHelpIsDeterministic(t *testing.T) {
	code, stdout, stderr := runCLI(t, "--help")
	if code != 0 {
		t.Fatalf("exit code = %d, want 0", code)
	}
	const want = `Usage: palonexus <command> [options]

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
	if stdout != want {
		t.Fatalf("stdout:\n%q\nwant:\n%q", stdout, want)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q, want empty", stderr)
	}
}

func TestNoArgumentsShowsHelp(t *testing.T) {
	code, stdout, stderr := runCLI(t)
	if code != 0 || !strings.HasPrefix(stdout, "Usage: palonexus ") || stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestVersionUsesInjectablePublicValue(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })
	Version = "1.2.3-test"

	code, stdout, stderr := runCLI(t, "--version")
	if code != 0 || stdout != "palonexus 1.2.3-test\n" || stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestKnownCommandsDispatchToFailClosedStubs(t *testing.T) {
	for _, command := range []string{"login", "logout", "status", "guard", "plugin"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, command)
			if code != 1 {
				t.Fatalf("exit code = %d, want 1", code)
			}
			if stdout != "" {
				t.Fatalf("stdout = %q, want empty", stdout)
			}
			want := "palonexus: " + command + ": not implemented\n"
			if stderr != want {
				t.Fatalf("stderr = %q, want %q", stderr, want)
			}
		})
	}
}

func TestSubcommandHelpIsAvailableWithoutRunningStub(t *testing.T) {
	for _, command := range []string{"login", "logout", "status", "guard", "plugin"} {
		t.Run(command, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, command, "--help")
			if code != 0 {
				t.Fatalf("exit code = %d, want 0", code)
			}
			want := "Usage: palonexus " + command + "\n"
			if stdout != want || stderr != "" {
				t.Fatalf("stdout=%q stderr=%q", stdout, stderr)
			}
		})
	}
}

func TestUnknownCommandFailsClosed(t *testing.T) {
	secret := "Bearer_super-secret-command"
	code, stdout, stderr := runCLI(t, secret)
	if code != 2 || stdout != "" {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	if stderr != "palonexus: unknown command\n" {
		t.Fatalf("stderr = %q", stderr)
	}
	if strings.Contains(stdout+stderr, secret) {
		t.Fatal("output exposed the unknown command value")
	}
}

func TestInvalidArgumentsFailClosedWithoutEchoingValues(t *testing.T) {
	secret := "super-secret-token"
	code, stdout, stderr := runCLI(t, "guard", "--token", secret)
	if code != 2 || stdout != "" {
		t.Fatalf("code=%d stdout=%q", code, stdout)
	}
	if stderr != "palonexus: guard: invalid arguments\n" {
		t.Fatalf("stderr = %q", stderr)
	}
	if strings.Contains(stdout+stderr, secret) {
		t.Fatal("output exposed an argument value")
	}
}

func TestGlobalFlagsRejectExtraArguments(t *testing.T) {
	for _, flag := range []string{"--help", "-h", "--version"} {
		t.Run(flag, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, flag, "extra")
			if code != 2 || stdout != "" || stderr != "palonexus: invalid arguments\n" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}
