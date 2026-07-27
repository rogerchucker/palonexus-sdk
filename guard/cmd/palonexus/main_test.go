// SPDX-License-Identifier: MIT
//go:build darwin || linux

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

func TestBuiltBinaryDaemonLifecycleAndOneShot(t *testing.T) {
	binary := buildBinary(t)
	root, err := os.MkdirTemp("", "pn-main-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, _ = filepath.EvalSymlinks(root)
	configPath := filepath.Join(root, "config.json")
	config := `{
	  "decision_endpoint":"http://127.0.0.1:65534",
	  "oidc_issuer":"http://127.0.0.1:65533",
	  "local_test_mode":true,
	  "routes":[{"target":"api.example.com","decision_endpoint":"http://127.0.0.1:65534"}]
	}`
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "run")
	environment := append(os.Environ(),
		"PALONEXUS_CONFIG="+configPath,
		"PALONEXUS_RUNTIME_DIR="+runtimeDir,
		"PALONEXUS_ALLOW_LOCAL_TEST_MODE=1",
	)
	t.Setenv("PALONEXUS_CONFIG", configPath)
	t.Setenv("PALONEXUS_RUNTIME_DIR", runtimeDir)
	t.Setenv("PALONEXUS_ALLOW_LOCAL_TEST_MODE", "1")
	if _, err := productionManager(); err != nil {
		t.Fatalf("production manager: %v", err)
	}
	run := func(input string, arguments ...string) (int, string, string) {
		command := exec.Command(binary, arguments...)
		command.Env = environment
		command.Stdin = strings.NewReader(input)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		if err == nil {
			return 0, stdout.String(), stderr.String()
		}
		var exit *exec.ExitError
		if !strings.Contains(err.Error(), "exit status") || !errorAs(err, &exit) {
			t.Fatalf("%v", err)
		}
		return exit.ExitCode(), stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("", "guard", "start"); code != 0 ||
		stdout != "guard started\n" || stderr != "" {
		log, logErr := os.ReadFile(filepath.Join(runtimeDir, "daemon.log"))
		entries, _ := os.ReadDir(runtimeDir)
		t.Fatalf("start: %d %q %q log=%q logErr=%v entries=%v",
			code, stdout, stderr, log, logErr, entries)
	}
	t.Cleanup(func() { _, _, _ = run("", "guard", "stop") })
	if code, stdout, stderr := run("", "status"); code != 0 ||
		stdout != "guard running\n" || stderr != "" {
		t.Fatalf("status: %d %q %q", code, stdout, stderr)
	}
	action, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "protocol", "test-vectors", "action", "valid", "file-write.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, action); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(compact.String()+"\n", "guard", "check", "--one-shot")
	if code != 0 || stderr != "" {
		t.Fatalf("one-shot: %d %q %q", code, stdout, stderr)
	}
	failure, err := protocol.ParseProtocolError([]byte(stdout))
	if err != nil || failure.Code != protocol.ProtocolErrorCodeAuthenticationFailed {
		t.Fatalf("one-shot response: %s, %v", stdout, err)
	}
	code, stdout, stderr = run(compact.String()+"\n", "guard", "check")
	if code != 0 || stderr != "" {
		t.Fatalf("daemon check: %d %q %q", code, stdout, stderr)
	}
	daemonFailure, err := protocol.ParseProtocolError([]byte(stdout))
	if err != nil || daemonFailure.Code != failure.Code {
		t.Fatalf("daemon/one-shot mismatch: %s vs %s, %v", stdout, failure.Code, err)
	}
	if code, stdout, stderr := run("", "guard", "stop"); code != 0 ||
		stdout != "guard stopped\n" || stderr != "" {
		t.Fatalf("stop: %d %q %q", code, stdout, stderr)
	}
}

func TestBuiltBinaryInvalidConfigurationFailsClosed(t *testing.T) {
	binary := buildBinary(t)
	command := exec.Command(binary, "guard", "start")
	command.Env = append(os.Environ(),
		"PALONEXUS_CONFIG="+filepath.Join(t.TempDir(), "missing.json"),
		"PALONEXUS_RUNTIME_DIR="+filepath.Join(t.TempDir(), "run"),
	)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	var exit *exec.ExitError
	if !errorAs(err, &exit) || exit.ExitCode() != 1 || stdout.Len() != 0 ||
		stderr.String() != "palonexus: guard: unavailable\n" {
		t.Fatalf("invalid config: %v %q %q", err, stdout.String(), stderr.String())
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "palonexus")
	command := exec.Command("go", "build", "-o", path, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}
	return path
}

func errorAs(err error, target any) bool {
	return err != nil && errors.As(err, target)
}
