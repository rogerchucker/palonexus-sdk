// SPDX-License-Identifier: MIT

package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/plugin"
)

type cliNativeRunner struct {
	marketplace string
	installed   bool
	home        string
}

func (f *cliNativeRunner) Run(_ context.Context, command plugin.NativeCommand) ([]byte, error) {
	for _, variable := range command.Env {
		if strings.HasPrefix(variable, "HOME=") {
			f.home = strings.TrimPrefix(variable, "HOME=")
		}
	}
	args := strings.Join(command.Args, " ")
	switch {
	case args == "--version --json":
		return []byte(`{"name":"palonexus","version":"dev","protocolVersion":"1.0"}`), nil
	case args == "status --json":
		return []byte(`{"name":"palonexus","version":"dev","protocolVersion":"1.0","authenticated":false,"ready":true,"loginRequired":true}`), nil
	case args == "--version":
		return []byte("2.1.219 (Claude Code)\n"), nil
	case strings.HasPrefix(args, "plugin validate --strict "):
		return []byte("valid\n"), nil
	case strings.Contains(args, "marketplace add"):
		f.marketplace = command.Args[len(command.Args)-1]
		return []byte(`{}`), nil
	case strings.Contains(args, "plugin install"):
		f.installed = true
		return []byte(`{}`), nil
	case strings.Contains(args, "plugin uninstall"):
		f.installed = false
		return []byte(`{}`), nil
	case strings.Contains(args, "marketplace remove"):
		f.marketplace = ""
		return []byte(`{}`), nil
	case args == "plugin list --json":
		if !f.installed {
			return []byte(`[]`), nil
		}
		return []byte(fmt.Sprintf(
			`[{"id":"palonexus@palonexus-sdk","version":"dev","scope":"user","enabled":true,"errors":[],"installPath":%q}]`,
			filepath.Join(f.home, ".claude", "plugins", "cache", "palonexus-sdk", "palonexus", "dev"),
		)), nil
	case args == "plugin marketplace list --json":
		if f.marketplace == "" {
			return []byte(`[]`), nil
		}
		return []byte(fmt.Sprintf(
			`[{"name":"palonexus-sdk","source":"directory","path":%q,"installLocation":%q}]`,
			f.marketplace, f.marketplace,
		)), nil
	default:
		return []byte(`{}`), nil
	}
}

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

func TestVersionJSONReportsGuardIdentityAndProtocol(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })
	Version = "1.2.3-test"
	code, stdout, stderr := runCLI(t, "--version", "--json")
	if code != 0 ||
		stdout != "{\"name\":\"palonexus\",\"version\":\"1.2.3-test\",\"protocolVersion\":\"1.0\"}\n" ||
		stderr != "" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}

func TestStatusJSONReportsReadinessWithoutIdentity(t *testing.T) {
	original := statusRuntime
	t.Cleanup(func() { statusRuntime = original })
	statusRuntime = func(context.Context) runtimeStatus {
		return runtimeStatus{Authenticated: true, Ready: false}
	}
	code, stdout, stderr := runCLI(t, "status", "--json")
	if code != 0 || stderr != "" {
		t.Fatalf("status code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	const want = `{"name":"palonexus","version":"dev","protocolVersion":"1.0","authenticated":true,"ready":false,"loginRequired":false}` + "\n"
	if stdout != want {
		t.Fatalf("status = %q, want %q", stdout, want)
	}
	if strings.Contains(stdout, "subject") || strings.Contains(stdout, "account") ||
		strings.Contains(stdout, "tenant") || strings.Contains(stdout, "token") {
		t.Fatal("status leaked identity or credentials")
	}
}

func TestStatusRecognizesLiveSessionEnvelope(t *testing.T) {
	root := t.TempDir()
	document := fmt.Sprintf(
		`{"version":1,"tenant":"hidden","account":"hidden","metadata":{"kind":"session","sessionId":"session_01J5ABCDEFGHJKMNPQRSTVWXYZ","expiresAt":%q}}`,
		time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
	)
	if err := os.WriteFile(filepath.Join(root, "state-"+strings.Repeat("a", 64)+".json"),
		[]byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	if !hasLiveSession(root) {
		t.Fatal("live persisted session was reported logged out")
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
	for _, command := range []string{"login", "logout", "status", "guard"} {
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
	code, stdout, stderr := runCLI(t, "plugin", "--help")
	if code != 0 || stdout != pluginHelp || stderr != "" {
		t.Fatalf("plugin help code=%d stdout=%q stderr=%q", code, stdout, stderr)
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
	for _, flag := range []string{"--help", "-h"} {
		t.Run(flag, func(t *testing.T) {
			code, stdout, stderr := runCLI(t, flag, "extra")
			if code != 2 || stdout != "" || stderr != "palonexus: invalid arguments\n" {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout, stderr)
			}
		})
	}
}

func TestPluginCommandDispatchesWithoutEchoingPaths(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(home, "source")
	pluginRoot := filepath.Join(source, "plugins", "palonexus")
	if err := os.MkdirAll(filepath.Join(pluginRoot, ".claude-plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, ".claude-plugin", "plugin.json"), []byte(`{"name":"palonexus","version":"dev","description":"PaloNexus governed actions","license":"MIT","author":{"name":"PaloNexus"},"skills":"./skills/"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pluginRoot, "hooks"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, "hooks", "hooks.json"), []byte(`{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[{"type":"command","command":"__PALONEXUS_GUARD__","args":["guard","check"],"timeout":30}]}]}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pluginRoot, "skills"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, "palonexus.json"), []byte(`{"protocolVersion":"1.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(source, ".claude-plugin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, ".claude-plugin", "marketplace.json"), []byte(`{"name":"palonexus-sdk","description":"PaloNexus governed actions","owner":{"name":"PaloNexus"},"plugins":[{"name":"palonexus","source":"./plugins/palonexus"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(home, "palonexus")
	if err := os.WriteFile(guard, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(home, "claude")
	if err := os.WriteFile(host, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	restoreHome, restoreExecutable, restoreLookPath, restoreRunner := pluginUserHome, pluginExecutable, pluginLookPath, pluginRunner
	t.Cleanup(func() {
		pluginUserHome, pluginExecutable, pluginLookPath, pluginRunner =
			restoreHome, restoreExecutable, restoreLookPath, restoreRunner
	})
	pluginUserHome = func() (string, error) { return home, nil }
	pluginExecutable = func() (string, error) { return guard, nil }
	pluginLookPath = func(string) (string, error) { return host, nil }
	pluginRunner = &cliNativeRunner{}

	code, stdout, stderr := runCLI(t, "plugin", "install", "claude-code", "--source", source)
	if code != 0 || stdout != "palonexus: plugin claude-code installed; login required; run `palonexus login`\n" || stderr != "" {
		t.Fatalf("install code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	code, stdout, stderr = runCLI(t, "plugin", "uninstall", "claude-code")
	if code != 0 || stdout != "palonexus: plugin claude-code uninstalled\n" || stderr != "" {
		t.Fatalf("uninstall code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
	packaged := filepath.Join(filepath.Dir(guard), "plugins", "claude-code")
	if err := os.MkdirAll(filepath.Dir(packaged), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(source, packaged); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = runCLI(t, "plugin", "install", "claude-code")
	if code != 0 || !strings.Contains(stdout, "plugin claude-code installed") || stderr != "" {
		t.Fatalf("packaged install code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}

	secret := filepath.Join(home, "secret-token")
	code, stdout, stderr = runCLI(t, "plugin", "install", "invalid", "--source", secret)
	if code != 2 || stdout != "" || stderr != "palonexus: plugin: invalid arguments\n" ||
		strings.Contains(stdout+stderr, secret) {
		t.Fatalf("invalid code=%d stdout=%q stderr=%q", code, stdout, stderr)
	}
}
