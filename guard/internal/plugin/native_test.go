// SPDX-License-Identifier: MIT

//go:build darwin || linux

package plugin

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type diagnosticRunner struct{ t *testing.T }

func (r diagnosticRunner) Run(ctx context.Context, invocation NativeCommand) ([]byte, error) {
	command := exec.CommandContext(ctx, invocation.Path, invocation.Args...)
	command.Env = invocation.Env
	output, err := command.CombinedOutput()
	r.t.Logf("%s %q => %v\n%s", invocation.Path, invocation.Args, err, output)
	if err != nil {
		return output, errors.New("native command failed")
	}
	return output, nil
}

func TestNativeVersionCapabilityBoundaries(t *testing.T) {
	for _, test := range []struct {
		target Target
		value  string
		valid  bool
	}{
		{ClaudeCode, "2.1.219 (Claude Code)", true},
		{ClaudeCode, "2.1.218 (Claude Code)", true},
		{ClaudeCode, "2.1.219", false},
		{Codex, "codex-cli 0.145.0", true},
		{Codex, "codex-cli 0.144.9", true},
		{Codex, "0.145.0", false},
	} {
		version, err := parseHostVersion(test.target, test.value)
		if test.valid != (err == nil) {
			t.Fatalf("%s parse(%q) = %#v, %v", test.target, test.value, version, err)
		}
	}
	for _, test := range []struct {
		target  Target
		version string
	}{
		{ClaudeCode, "2.1.218 (Claude Code)"},
		{Codex, "codex-cli 0.144.9"},
	} {
		options := fixture(t, test.target, "1.0.0")
		options.Runner.(*fakeNative).hostVersion = test.version
		if err := probeNative(context.Background(), test.target, options); err == nil {
			t.Fatalf("unsupported %s version %q accepted", test.target, test.version)
		}
	}
}

func TestNativeCommandsUseExactArgvAndSanitizedEnvironment(t *testing.T) {
	options := fixture(t, ClaudeCode, "1.0.0")
	if _, err := Install(context.Background(), ClaudeCode, options); err != nil {
		t.Fatal(err)
	}
	runner := options.Runner.(*fakeNative)
	if len(runner.commands) < 7 {
		t.Fatalf("too few native commands: %#v", runner.commands)
	}
	for _, command := range runner.commands {
		if (command.Path != options.HostPath && command.Path != options.GuardPath) || len(command.Args) == 0 {
			t.Fatalf("unsafe command: %#v", command)
		}
		joined := strings.Join(command.Args, " ")
		if strings.ContainsAny(joined, ";&|`$") {
			t.Fatalf("shell metacharacter reached argv: %q", joined)
		}
		for _, variable := range command.Env {
			if strings.HasPrefix(variable, "TOKEN=") || strings.HasPrefix(variable, "AWS_") ||
				strings.HasPrefix(variable, "SSH_") {
				t.Fatalf("ambient credential inherited: %q", variable)
			}
		}
	}
}

func TestInstalledGuardConfigurationUsesExactValidatedPath(t *testing.T) {
	for _, target := range []Target{ClaudeCode, Codex} {
		options := fixture(t, target, "1.0.0")
		result, err := Install(context.Background(), target, options)
		if err != nil {
			t.Fatal(err)
		}
		data, err := os.ReadFile(filepath.Join(result.Path, "plugins", installName, "hooks", "hooks.json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte(options.GuardPath)) ||
			bytes.Contains(data, []byte("__PALONEXUS_GUARD__")) {
			t.Fatalf("%s hook does not use exact guard path: %s", target, data)
		}
	}
}

func TestNativeVerificationRejectsDisabledOrErroredPlugin(t *testing.T) {
	for _, mutate := range []func(*fakeNative){
		func(r *fakeNative) { r.enabled = false },
		func(r *fakeNative) { r.nativeErrors = []string{"hook failed validation"} },
	} {
		options := fixture(t, ClaudeCode, "1.0.0")
		runner := options.Runner.(*fakeNative)
		runner.installed = true
		runner.marketplace = marketplaceInstallPath(options.Home, ClaudeCode)
		mutate(runner)
		if err := verifyNativeInstalled(context.Background(), ClaudeCode, options,
			runner.marketplace, "1.0.0", true); err == nil {
			t.Fatal("invalid native plugin was reported installed")
		}
	}
}

func TestNativeFailureRollsBackRegistrationAndMarketplaceExactly(t *testing.T) {
	options := fixture(t, Codex, "1.0.0")
	result, err := Install(context.Background(), Codex, options)
	if err != nil {
		t.Fatal(err)
	}
	before, err := snapshotTree(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(options.SourceDir, "upgrade"), []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	setFixtureVersion(t, Codex, &options, "2.0.0")
	runner := options.Runner.(*fakeNative)
	runner.failContains = "plugin add"
	if _, err := Install(context.Background(), Codex, options); err == nil {
		t.Fatal("native failure did not fail installation")
	}
	after, err := snapshotTree(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("local marketplace rollback mismatch\nbefore=%s\nafter=%s", before, after)
	}
	if !runner.installed || runner.version != "1.0.0" ||
		!sameCanonicalPath(runner.marketplace, result.Path) {
		t.Fatalf("native registration not restored: %#v", runner)
	}
}

func TestUninstallNativePartialFailureRestoresRegistration(t *testing.T) {
	options := fixture(t, ClaudeCode, "1.0.0")
	result, err := Install(context.Background(), ClaudeCode, options)
	if err != nil {
		t.Fatal(err)
	}
	before, err := snapshotTree(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	runner := options.Runner.(*fakeNative)
	runner.failContains = "marketplace remove"
	if _, err := Uninstall(context.Background(), ClaudeCode, uninstallOptions(options)); err == nil {
		t.Fatal("partial native uninstall unexpectedly succeeded")
	}
	after, err := snapshotTree(result.Path)
	if err != nil {
		t.Fatal(err)
	}
	if before != after || !runner.installed || !runner.enabled ||
		runner.version != "1.0.0" || !sameCanonicalPath(runner.marketplace, result.Path) {
		t.Fatalf("partial native uninstall was not rolled back: %#v", runner)
	}
}

func TestInstalledHostCLIsValidateDisposableMarketplace(t *testing.T) {
	for _, target := range []Target{ClaudeCode, Codex} {
		t.Run(string(target), func(t *testing.T) {
			binary := "claude"
			if target == Codex {
				binary = "codex"
			}
			path, err := exec.LookPath(binary)
			if err != nil {
				t.Skipf("%s is not installed", binary)
			}
			path, err = filepath.EvalSymlinks(path)
			if err != nil {
				t.Fatal(err)
			}
			options := fixture(t, target, "1.0.0")
			options.HostPath = path
			options.Runner = diagnosticRunner{t}
			if err := ensureNativeHome(options.Home, target); err != nil {
				t.Fatal(err)
			}
			if err := probeNative(context.Background(), target, options); err != nil {
				t.Fatal(err)
			}
			if err := nativeValidate(context.Background(), target, options, options.SourceDir); err != nil {
				if target == ClaudeCode {
					command := exec.Command(path, "plugin", "validate", "--strict", options.SourceDir)
					command.Env, _ = nativeEnvironment(options.Home, options.HostPath, target)
					output, _ := command.CombinedOutput()
					t.Logf("Claude validation output: %s", output)
				}
				t.Fatal(err)
			}
		})
	}
}

func TestInstalledHostCLIsRoundTripDisposableHome(t *testing.T) {
	for _, target := range []Target{ClaudeCode, Codex} {
		t.Run(string(target), func(t *testing.T) {
			binary := "claude"
			if target == Codex {
				binary = "codex"
			}
			path, err := exec.LookPath(binary)
			if err != nil {
				t.Skipf("%s is not installed", binary)
			}
			path, err = filepath.EvalSymlinks(path)
			if err != nil {
				t.Fatal(err)
			}
			options := fixture(t, target, "1.0.0")
			options.HostPath = path
			options.Runner = diagnosticRunner{t}
			result, err := Install(context.Background(), target, options)
			if err != nil {
				t.Fatal(err)
			}
			if !result.Changed {
				t.Fatal("native install did not report a change")
			}
			owned, err := nativeMarketplaceOwned(context.Background(), target, options, result.Path)
			if err != nil || !owned {
				t.Fatalf("native marketplace ownership not discoverable: %v", err)
			}
			removed, err := Uninstall(context.Background(), target, uninstallOptions(options))
			if err != nil {
				t.Fatal(err)
			}
			if !removed.Changed {
				t.Fatal("native uninstall did not report a change")
			}
		})
	}
}
