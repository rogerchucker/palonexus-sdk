// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"errors"
	"strconv"
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

type fakeDaemonLifecycle struct {
	started  int
	stopped  int
	running  bool
	checked  int
	oneShot  bool
	request  []byte
	response []byte
	err      error
}

func (f *fakeDaemonLifecycle) Start(context.Context) error {
	f.started++
	return f.err
}

func (f *fakeDaemonLifecycle) Stop(context.Context) error {
	f.stopped++
	return f.err
}

func (f *fakeDaemonLifecycle) Running(context.Context) (bool, error) {
	return f.running, f.err
}

func (f *fakeDaemonLifecycle) Check(_ context.Context, request []byte, oneShot bool) ([]byte, error) {
	f.checked++
	f.oneShot = oneShot
	f.request = append([]byte(nil), request...)
	return append([]byte(nil), f.response...), f.err
}

func runCLIWithDaemon(t *testing.T, daemon DaemonLifecycle, args ...string) (int, string, string) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := RunWithDaemon(context.Background(), args, &stdout, &stderr, daemon)
	return code, stdout.String(), stderr.String()
}

func TestDaemonLifecycleCLIWiring(t *testing.T) {
	for _, command := range []string{"start", "status", "stop"} {
		t.Run(command, func(t *testing.T) {
			fake := &fakeDaemonLifecycle{running: true}
			code, stdout, stderr := runCLIWithDaemon(t, fake, "guard", command)
			if code != 0 || stderr != "" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
			switch command {
			case "start":
				if fake.started != 1 || stdout != "guard started\n" {
					t.Fatalf("start calls=%d stdout=%q", fake.started, stdout)
				}
			case "stop":
				if fake.stopped != 1 || stdout != "guard stopped\n" {
					t.Fatalf("stop calls=%d stdout=%q", fake.stopped, stdout)
				}
			case "status":
				if stdout != "guard running\n" || strings.Contains(stdout, "123") {
					t.Fatalf("unsafe/nondeterministic status output %q", stdout)
				}
			}
		})
	}
}

func TestRootStatusUsesDaemonLifecycle(t *testing.T) {
	fake := &fakeDaemonLifecycle{running: false}
	code, stdout, stderr := runCLIWithDaemon(t, fake, "status")
	if code != 0 || stdout != "guard stopped\n" || stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestDaemonLifecycleFailureIsFailClosedAndDoesNotLeak(t *testing.T) {
	fake := &fakeDaemonLifecycle{err: errors.New("Bearer top-secret")}
	code, stdout, stderr := runCLIWithDaemon(t, fake, "guard", "start")
	if code != 1 || stdout != "" || stderr != "palonexus: guard: unavailable\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestGuardCheckAndExplicitOneShotUseInjectedPipeline(t *testing.T) {
	for _, oneShot := range []bool{false, true} {
		t.Run(strconv.FormatBool(oneShot), func(t *testing.T) {
			fake := &fakeDaemonLifecycle{response: []byte(`{"safe":"decision"}`)}
			args := []string{"guard", "check"}
			if oneShot {
				args = append(args, "--one-shot")
			}
			var stdout, stderr bytes.Buffer
			code := RunWithDaemonIO(
				context.Background(), args,
				strings.NewReader("{\"schemaVersion\":\"1\"}\n"),
				&stdout, &stderr, fake,
			)
			if code != 0 || stderr.String() != "" ||
				stdout.String() != "{\"safe\":\"decision\"}\n" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if fake.checked != 1 || fake.oneShot != oneShot ||
				string(fake.request) != `{"schemaVersion":"1"}` {
				t.Fatalf("check calls=%d oneShot=%v request=%q", fake.checked, fake.oneShot, fake.request)
			}
		})
	}
}

func TestGuardCheckRejectsOversizedOrMultipleFramesWithoutCallingPipeline(t *testing.T) {
	for _, input := range []string{
		"{\"schemaVersion\":\"1\"}\n{}\n",
		strings.Repeat("x", MaxCLIRequestBytes+1),
	} {
		fake := &fakeDaemonLifecycle{}
		var stdout, stderr bytes.Buffer
		code := RunWithDaemonIO(
			context.Background(), []string{"guard", "check"},
			strings.NewReader(input), &stdout, &stderr, fake,
		)
		if code != 2 || fake.checked != 0 || stdout.Len() != 0 ||
			stderr.String() != "palonexus: guard: invalid arguments\n" {
			t.Fatalf("code=%d calls=%d stdout=%q stderr=%q",
				code, fake.checked, stdout.String(), stderr.String())
		}
	}
}
