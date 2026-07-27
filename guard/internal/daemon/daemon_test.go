// SPDX-License-Identifier: MIT
//go:build darwin || linux

package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	guardsocket "github.com/rogerchucker/palonexus-sdk/guard/internal/socket"
	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
	"golang.org/x/sys/unix"
)

func safeHandler(_ context.Context, request []byte) ([]byte, error) {
	var envelope struct {
		RequestID string `json:"requestId"`
	}
	_ = json.Unmarshal(request, &envelope)
	value := protocol.ProtocolError{
		SchemaVersion: "1",
		Code:          protocol.ProtocolErrorCodeInvalidRequest,
		SafeMessage:   "The request is invalid.",
		Retryable:     false,
	}
	return json.Marshal(value)
}

func validActionDocument(t *testing.T) []byte {
	t.Helper()
	document, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "protocol", "test-vectors", "action", "valid", "file-write.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	document = bytes.TrimSpace(document)
	if _, err := protocol.ParseActionRequest(document); err != nil {
		t.Fatalf("valid action fixture: %v", err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, document); err != nil {
		t.Fatal(err)
	}
	return compact.Bytes()
}

func testConfig(t *testing.T) Config {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp("", "pnd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	base, err = filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(base, "run")
	return Config{
		RuntimeDir:     runtimeDir,
		Handler:        safeHandler,
		Executable:     executable,
		Arguments:      []string{"-test.run=TestDaemonProcessHelper", "--"},
		StartupTimeout: 4 * time.Second,
		StopTimeout:    2 * time.Second,
		KillTimeout:    time.Second,
		ChildEnv: []string{
			"PALONEXUS_DAEMON_HELPER=1",
			"PALONEXUS_RUNTIME_DIR=" + runtimeDir,
		},
	}
}

func requireAutoStart(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "darwin" && !darwinDescriptorExecutionSupported() {
		t.Skip("Darwin has no exact-descriptor executable launch primitive; fail-closed is required")
	}
}

func testConfigForRuntime(t *testing.T, runtimeDir string) Config {
	t.Helper()
	cfg := testConfig(t)
	// testConfig allocates another disposable root; retain its executable and
	// launch contract but target the crash fixture's existing runtime.
	cfg.RuntimeDir = runtimeDir
	for index, value := range cfg.ChildEnv {
		if strings.HasPrefix(value, "PALONEXUS_RUNTIME_DIR=") {
			cfg.ChildEnv[index] = "PALONEXUS_RUNTIME_DIR=" + runtimeDir
		}
	}
	return cfg
}

func TestDaemonProcessHelper(t *testing.T) {
	if os.Getenv("PALONEXUS_DAEMON_HELPER") != "1" {
		return
	}
	cfg := Config{
		RuntimeDir: os.Getenv("PALONEXUS_RUNTIME_DIR"),
		Handler:    safeHandler,
		Arguments:  os.Args[1:],
		ChildEnv: []string{
			"PALONEXUS_DAEMON_HELPER=" + os.Getenv("PALONEXUS_DAEMON_HELPER"),
			"PALONEXUS_RUNTIME_DIR=" + os.Getenv("PALONEXUS_RUNTIME_DIR"),
		},
	}
	if value := os.Getenv("PALONEXUS_DAEMON_HELPER_MODE"); value != "" {
		cfg.ChildEnv = append(cfg.ChildEnv, "PALONEXUS_DAEMON_HELPER_MODE="+value)
	}
	mode := os.Getenv("PALONEXUS_DAEMON_HELPER_MODE")
	if mode == "hang" {
		select {}
	}
	if mode == "crash-after-socket" {
		cfg.afterSocketPublished = func() { os.Exit(88) }
	}
	if mode == "caller" {
		executable, _ := os.Executable()
		cfg.Executable = executable
		cfg.Arguments = []string{"-test.run=TestDaemonProcessHelper", "--"}
		cfg.ChildEnv = []string{
			"PALONEXUS_DAEMON_HELPER=1",
			"PALONEXUS_DAEMON_HELPER_MODE=server",
			"PALONEXUS_RUNTIME_DIR=" + cfg.RuntimeDir,
		}
		cfg.StartupTimeout = 4 * time.Second
	}
	manager, err := New(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(91)
	}
	if mode == "caller" {
		err = manager.Start(context.Background())
	} else {
		err = manager.Run(context.Background())
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, guardsocket.ErrRecoveryAmbiguous) {
			os.Exit(93)
		}
		os.Exit(92)
	}
	os.Exit(0)
}

func TestStartStatusStopAndDoubleStop(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		log, _ := os.ReadFile(filepath.Join(cfg.RuntimeDir, logName))
		t.Fatalf("Start: %v log=%q", err, log)
	}
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })
	status, err := manager.Status(context.Background())
	if err != nil || !status.Running || status.PID <= 0 {
		t.Fatalf("Status = %#v, %v", status, err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	status, err = manager.Status(context.Background())
	if err != nil || status.Running {
		t.Fatalf("Status after stop = %#v, %v", status, err)
	}
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestConcurrentAutoStartAcrossProcessesStartsOneDaemon(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	const callers = 8
	commands := make([]*exec.Cmd, 0, callers)
	outputs := make([]*bytes.Buffer, 0, callers)
	for range callers {
		command := exec.Command(cfg.Executable, "-test.run=TestDaemonProcessHelper", "--")
		command.Env = append(os.Environ(),
			"PALONEXUS_DAEMON_HELPER=1",
			"PALONEXUS_DAEMON_HELPER_MODE=caller",
			"PALONEXUS_RUNTIME_DIR="+cfg.RuntimeDir,
		)
		output := new(bytes.Buffer)
		command.Stdout = output
		command.Stderr = output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, command)
		outputs = append(outputs, output)
	}
	for index, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("concurrent Start: %v: %s", err, outputs[index].Bytes())
		}
	}
	observerConfig := cfg
	observerConfig.ChildEnv = []string{
		"PALONEXUS_DAEMON_HELPER=1",
		"PALONEXUS_DAEMON_HELPER_MODE=server",
		"PALONEXUS_RUNTIME_DIR=" + cfg.RuntimeDir,
	}
	manager, _ := New(observerConfig)
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })
	first, err := manager.Status(context.Background())
	if err != nil || !first.Running {
		t.Fatalf("Status = %#v, %v", first, err)
	}
	time.Sleep(50 * time.Millisecond)
	second, err := manager.Status(context.Background())
	if err != nil || second.PID != first.PID {
		t.Fatalf("daemon changed: %#v -> %#v, %v", first, second, err)
	}
}

func TestUnavailableDaemonFailsClosedAndExplicitOneShotUsesSameHandler(t *testing.T) {
	cfg := testConfig(t)
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	manager.cfg.Executable = filepath.Join(t.TempDir(), "missing")
	request := validActionDocument(t)
	if _, err := manager.Check(context.Background(), request, false); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Check with failed start = %v, want ErrUnavailable", err)
	}
	response, err := manager.Check(context.Background(), request, true)
	if err != nil {
		t.Fatalf("one-shot Check: %v", err)
	}
	failure, err := protocol.ParseProtocolError(response)
	if err != nil || failure.Code != protocol.ProtocolErrorCodeInvalidRequest {
		t.Fatalf("one-shot response = %s, %v", response, err)
	}
}

func TestOneShotNeverConvertsPipelineFailureToAllow(t *testing.T) {
	cfg := testConfig(t)
	cfg.Handler = func(context.Context, []byte) ([]byte, error) {
		return nil, errors.New("decision service unavailable with Bearer-secret")
	}
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	response, err := manager.Check(context.Background(), validActionDocument(t), true)
	if err != nil {
		t.Fatalf("one-shot failure = %q, %v", response, err)
	}
	failure, parseErr := protocol.ParseProtocolError(response)
	if parseErr != nil || failure.Code != protocol.ProtocolErrorCodeAuthorizationUnavailable {
		t.Fatalf("one-shot failure = %q, %v", response, parseErr)
	}
	if bytes.Contains(response, []byte("Bearer-secret")) {
		t.Fatal("handler error leaked")
	}
}

func TestOneShotPanicFailsClosed(t *testing.T) {
	cfg := testConfig(t)
	cfg.Handler = func(context.Context, []byte) ([]byte, error) {
		panic("Bearer panic-secret")
	}
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	response, err := manager.Check(context.Background(), validActionDocument(t), true)
	if err != nil {
		t.Fatalf("panic response = %q, %v", response, err)
	}
	failure, parseErr := protocol.ParseProtocolError(response)
	if parseErr != nil || failure.Code != protocol.ProtocolErrorCodeAuthorizationUnavailable {
		t.Fatalf("panic response = %q, %v", response, parseErr)
	}
	if bytes.Contains(response, []byte("panic-secret")) {
		t.Fatal("panic value leaked")
	}
}

func TestDaemonAndOneShotRejectMalformedActionBeforePipeline(t *testing.T) {
	invalid := [][]byte{
		[]byte(`{}`),
		[]byte(`{"schemaVersion":"2"}`),
		[]byte(`{"schemaVersion":"1","schemaVersion":"1"}`),
		[]byte(`{"schemaVersion":"1"}`),
	}
	for _, oneShot := range []bool{true, false} {
		t.Run(strconv.FormatBool(oneShot), func(t *testing.T) {
			if !oneShot {
				requireAutoStart(t)
			}
			var calls atomic.Int32
			cfg := testConfig(t)
			cfg.Handler = func(context.Context, []byte) ([]byte, error) {
				calls.Add(1)
				return marshalFailure(), nil
			}
			manager, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if !oneShot {
				t.Cleanup(func() { _ = manager.Stop(context.Background()) })
			}
			for _, document := range invalid {
				response, err := manager.Check(context.Background(), document, oneShot)
				if err != nil {
					t.Fatalf("Check(%s): %v", document, err)
				}
				failure, parseErr := protocol.ParseProtocolError(response)
				wantCode := protocol.ProtocolErrorCodeInvalidRequest
				if bytes.Contains(document, []byte(`"schemaVersion":"2"`)) {
					wantCode = protocol.ProtocolErrorCodeUnsupportedProtocol
				}
				if parseErr != nil || failure.Code != wantCode {
					t.Fatalf("response = %s, %v", response, parseErr)
				}
			}
			if calls.Load() != 0 {
				t.Fatalf("pipeline called %d times", calls.Load())
			}
		})
	}
}

func TestDaemonAndOneShotShareFiveSecondRequestBudget(t *testing.T) {
	cfg := testConfig(t)
	var delay atomic.Int64
	delay.Store(int64(1500 * time.Millisecond))
	cfg.Handler = func(ctx context.Context, request []byte) ([]byte, error) {
		select {
		case <-time.After(time.Duration(delay.Load())):
			return safeHandler(ctx, request)
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	document := validActionDocument(t)
	check := func(oneShot bool) {
		t.Helper()
		started := time.Now()
		response, checkErr := manager.Check(context.Background(), document, oneShot)
		if checkErr != nil {
			t.Fatalf("oneShot=%t: %v", oneShot, checkErr)
		}
		if elapsed := time.Since(started); elapsed < 1400*time.Millisecond ||
			elapsed > 3*time.Second {
			t.Fatalf("oneShot=%t elapsed %s", oneShot, elapsed)
		}
		if _, parseErr := protocol.ParseProtocolError(response); parseErr != nil {
			t.Fatalf("oneShot=%t response: %s: %v", oneShot, response, parseErr)
		}
	}
	check(true)

	runContext, cancelRun := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() { runDone <- manager.Run(runContext) }()
	t.Cleanup(func() {
		cancelRun()
		<-runDone
	})
	deadline := time.Now().Add(3 * time.Second)
	for {
		status, statusErr := manager.Status(context.Background())
		if statusErr == nil && status.Running {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("daemon readiness: %#v, %v", status, statusErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
	check(false)

	delay.Store(int64(6 * time.Second))
	for _, oneShot := range []bool{true, false} {
		started := time.Now()
		response, checkErr := manager.Check(context.Background(), document, oneShot)
		elapsed := time.Since(started)
		if elapsed < 4500*time.Millisecond || elapsed > 6*time.Second {
			t.Fatalf("oneShot=%t timeout elapsed %s", oneShot, elapsed)
		}
		if checkErr == nil {
			failure, parseErr := protocol.ParseProtocolError(response)
			if parseErr != nil ||
				failure.Code != protocol.ProtocolErrorCodeAuthorizationUnavailable {
				t.Fatalf("oneShot=%t timeout response %s, %v", oneShot, response, parseErr)
			}
		}
	}
}

func TestCancelledUncooperativeOneShotIsBounded(t *testing.T) {
	cfg := testConfig(t)
	block := make(chan struct{})
	cfg.Handler = func(context.Context, []byte) ([]byte, error) {
		<-block
		return marshalFailure(), nil
	}
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	if _, err := manager.Check(ctx, validActionDocument(t), true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("uncooperative one-shot = %v", err)
	}
	close(block)
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("uncooperative cancellation took %v", elapsed)
	}
}

func TestStaleAndAmbiguousSocketArtifactsFailClosed(t *testing.T) {
	for _, kind := range []string{"regular", "fifo", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			cfg := testConfig(t)
			if err := os.Mkdir(cfg.RuntimeDir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(cfg.RuntimeDir, "guard.sock")
			switch kind {
			case "regular":
				if err := os.WriteFile(path, []byte("attacker"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(t.TempDir(), "target"), path); err != nil {
					t.Fatal(err)
				}
			}
			manager, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if err := manager.Start(context.Background()); !errors.Is(err, ErrUnsafeRuntime) {
				t.Fatalf("Start over %s = %v, want ErrUnsafeRuntime", kind, err)
			}
			info, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "regular" && info.Mode().IsRegular() {
				document, _ := os.ReadFile(path)
				if string(document) != "attacker" {
					t.Fatal("attacker file was overwritten")
				}
			}
		})
	}
}

func TestRejectsUnsafeRuntimeAncestorsAndLifecycleArtifacts(t *testing.T) {
	cfg := testConfig(t)
	real := filepath.Join(t.TempDir(), "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeDir = filepath.Join(link, "run")
	if _, err := New(cfg); !errors.Is(err, ErrUnsafeRuntime) {
		t.Fatalf("New with symlink ancestor = %v", err)
	}

	for _, kind := range []string{"symlink", "hardlink", "fifo"} {
		t.Run(kind, func(t *testing.T) {
			cfg := testConfig(t)
			if err := os.Mkdir(cfg.RuntimeDir, 0o700); err != nil {
				t.Fatal(err)
			}
			state := filepath.Join(cfg.RuntimeDir, stateName)
			switch kind {
			case "symlink":
				if err := os.Symlink(filepath.Join(t.TempDir(), "target"), state); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				source := filepath.Join(cfg.RuntimeDir, "source")
				if err := os.WriteFile(source, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Link(source, state); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(state, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			manager, err := New(cfg)
			if err == nil {
				_, err = manager.Status(context.Background())
			}
			if !errors.Is(err, ErrUnsafeRuntime) {
				t.Fatalf("%s lifecycle artifact = %v", kind, err)
			}
		})
	}
}

func TestStartRejectsUnsafeLockAndLogArtifactsWithoutBlocking(t *testing.T) {
	for _, name := range []string{startLockName, logName} {
		for _, kind := range []string{"symlink", "hardlink", "fifo"} {
			t.Run(name+"/"+kind, func(t *testing.T) {
				cfg := testConfig(t)
				manager, err := New(cfg)
				if err != nil {
					t.Fatal(err)
				}
				path := filepath.Join(cfg.RuntimeDir, name)
				switch kind {
				case "symlink":
					if err := os.Symlink(filepath.Join(t.TempDir(), "target"), path); err != nil {
						t.Fatal(err)
					}
				case "hardlink":
					source := filepath.Join(cfg.RuntimeDir, "source")
					if err := os.WriteFile(source, []byte("attacker"), 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Link(source, path); err != nil {
						t.Fatal(err)
					}
				case "fifo":
					if err := unix.Mkfifo(path, 0o600); err != nil {
						t.Fatal(err)
					}
				}
				done := make(chan error, 1)
				go func() { done <- manager.Start(context.Background()) }()
				select {
				case err := <-done:
					if !errors.Is(err, ErrUnsafeRuntime) {
						t.Fatalf("Start with %s %s = %v", kind, name, err)
					}
				case <-time.After(time.Second):
					t.Fatalf("Start blocked on %s %s", kind, name)
				}
			})
		}
	}
}

func TestExecutableAndArgumentsAreValidatedWithoutShell(t *testing.T) {
	cfg := testConfig(t)
	relative := cfg
	relative.Executable = "palonexus"
	if _, err := New(relative); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("relative executable = %v", err)
	}
	for _, args := range [][]string{{""}, {"ok\x00bad"}, {strings.Repeat("a", 4097)}} {
		bad := cfg
		bad.Arguments = args
		if _, err := New(bad); !errors.Is(err, ErrUnsafeExecutable) {
			t.Fatalf("arguments %#v = %v", args, err)
		}
	}
	for _, environment := range [][]string{
		{"LD_PRELOAD=/tmp/attacker.so"},
		{"PATH=/tmp/attacker"},
		{"PALONEXUS_RUNTIME_DIR=/one", "PALONEXUS_RUNTIME_DIR=/two"},
		{"PALONEXUS-BAD=value"},
		{"PALONEXUS_EMPTY="},
	} {
		bad := cfg
		bad.ChildEnv = environment
		if _, err := New(bad); !errors.Is(err, ErrUnsafeExecutable) {
			t.Fatalf("environment %#v = %v", environment, err)
		}
	}
	script := filepath.Join(t.TempDir(), "palonexus;touch PWNED")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	bad := cfg
	bad.Executable = script
	if _, err := New(bad); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("script executable = %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(script), "PWNED")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("executable name was interpreted by a shell")
	}
}

func TestExecutableReplacementAfterValidationIsRejected(t *testing.T) {
	cfg := testConfig(t)
	copyPath := filepath.Join(t.TempDir(), "palonexus-copy")
	copyExecutable(t, cfg.Executable, copyPath)
	cfg.Executable = copyPath
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(t.TempDir(), "replacement")
	copyExecutable(t, os.Args[0], replacement)
	if err := os.Rename(replacement, copyPath); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("Start after executable replacement = %v", err)
	}
}

func TestExecutableContentMutationAfterValidationIsRejected(t *testing.T) {
	cfg := testConfig(t)
	copyPath := filepath.Join(t.TempDir(), "palonexus-copy")
	copyExecutable(t, cfg.Executable, copyPath)
	cfg.Executable = copyPath
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(copyPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt([]byte{0}, 16); err != nil {
		t.Fatal(err)
	}
	_ = file.Close()
	if err := manager.Start(context.Background()); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("Start after executable content mutation = %v", err)
	}
}

func TestArgumentMetacharactersArePassedLiterally(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	marker := filepath.Join(t.TempDir(), "PWNED")
	cfg.Arguments = append(cfg.Arguments, ";touch", marker)
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("argument metacharacters were interpreted by a shell")
	}
}

func TestContextCancellationBoundsStartupAndOneShot(t *testing.T) {
	cfg := testConfig(t)
	cfg.Handler = func(ctx context.Context, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	if _, err := manager.Check(ctx, validActionDocument(t), true); !errors.Is(err, context.Canceled) {
		t.Fatalf("one-shot cancellation = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("cancellation took %v", elapsed)
	}
}

func TestBoundedStartupFailureTerminatesSpawnedChild(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	cfg.StartupTimeout = 50 * time.Millisecond
	cfg.KillTimeout = 50 * time.Millisecond
	for index, value := range cfg.ChildEnv {
		if strings.HasPrefix(value, "PALONEXUS_DAEMON_HELPER=") {
			cfg.ChildEnv[index] = "PALONEXUS_DAEMON_HELPER=1"
		}
	}
	cfg.ChildEnv = append(cfg.ChildEnv, "PALONEXUS_DAEMON_HELPER_MODE=hang")
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := manager.Start(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Start hanging child = %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("bounded startup took %v", elapsed)
	}
	status, err := manager.Status(context.Background())
	if err != nil || status.Running {
		t.Fatalf("hanging child survived: %#v, %v", status, err)
	}
}

func TestCrashCleanupAndRestart(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	manager, _ := New(cfg)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, _ := manager.Status(context.Background())
	process, _ := os.FindProcess(status.PID)
	if err := process.Kill(); err != nil {
		t.Fatal(err)
	}
	_, _ = process.Wait()
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("restart after crash: %v", err)
	}
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })
	restarted, err := manager.Status(context.Background())
	if err != nil || !restarted.Running || restarted.PID == status.PID {
		t.Fatalf("restarted status = %#v, %v (old PID %d)", restarted, err, status.PID)
	}
}

func TestSIGKILLAfterSocketPublicationBeforeStateRecovers(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	cfg.ChildEnv = append(cfg.ChildEnv, "PALONEXUS_DAEMON_HELPER_MODE=crash-after-socket")
	crashing, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := crashing.Start(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("crashing Start = %v", err)
	}
	if _, err := os.Lstat(filepath.Join(cfg.RuntimeDir, socketName)); err != nil {
		t.Fatalf("crash did not leave published socket: %v", err)
	}
	recoveryConfig := testConfigForRuntime(t, cfg.RuntimeDir)
	restarted, err := New(recoveryConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Start(context.Background()); err != nil {
		t.Fatalf("restart after publication crash: %v", err)
	}
	t.Cleanup(func() { _ = restarted.Stop(context.Background()) })
}

func TestAmbiguousSocketRecoveryErrorIsPreserved(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	if _, err := New(cfg); err != nil {
		t.Fatal(err)
	}
	stageName := ".sambiguous"
	stagePath := filepath.Join(cfg.RuntimeDir, stageName)
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: stagePath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	if err := os.Chmod(stagePath, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	record := fmt.Sprintf(
		`{"version":1,"phase":"preparing","generation":"%s","stageName":"%s","finalName":"%s"}`,
		strings.Repeat("a", 32), stageName, socketName,
	)
	if err := os.WriteFile(
		filepath.Join(cfg.RuntimeDir, "."+socketName+".lifecycle"),
		[]byte(record), 0o600,
	); err != nil {
		t.Fatal(err)
	}
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); !errors.Is(err, guardsocket.ErrRecoveryAmbiguous) {
		t.Fatalf("Start ambiguous socket = %v", err)
	}
}

func TestTerminationSignalCleansUpAndAllowsRestart(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	manager, _ := New(cfg)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, _ := manager.Status(context.Background())
	process, _ := os.FindProcess(status.PID)
	if err := process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		current, err := manager.Status(context.Background())
		if err == nil && !current.Running {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatalf("restart after SIGTERM: %v", err)
	}
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })
}

func TestStatusDoesNotReportStoppedWhenMatchingProcessIsUnresponsive(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	manager, _ := New(cfg)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := manager.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(status.PID, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(status.PID, syscall.SIGCONT)
		_ = manager.Stop(context.Background())
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	got, err := manager.Status(ctx)
	if err == nil || got.Running {
		t.Fatalf("Status of live unresponsive daemon = %#v, %v", got, err)
	}
	if !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrUnprovenProcess) {
		t.Fatalf("wrong unresponsive status error: %v", err)
	}
	if err := syscall.Kill(status.PID, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
}

func TestStopDoesNotKillUnrelatedOrReusedPID(t *testing.T) {
	cfg := testConfig(t)
	manager, _ := New(cfg)
	sleeper := exec.Command("sleep", "30")
	if err := sleeper.Start(); err != nil {
		t.Skipf("sleep unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = sleeper.Process.Kill()
		_, _ = sleeper.Process.Wait()
	})
	fake := lifecycleState{
		Version:    lifecycleVersion,
		PID:        sleeper.Process.Pid,
		Token:      strings.Repeat("a", 64),
		Executable: manager.cfg.Executable,
		Device:     manager.launch.Device,
		Inode:      manager.launch.Inode,
		Mode:       manager.launch.Mode,
		UID:        manager.launch.UID,
		BinaryHash: manager.launch.Digest,
		LaunchHash: manager.launchHash,
	}
	fake.StartToken, _ = processStartToken(sleeper.Process.Pid)
	if err := writeTestState(cfg.RuntimeDir, fake); err != nil {
		t.Fatal(err)
	}
	if err := manager.Stop(context.Background()); !errors.Is(err, ErrUnprovenProcess) {
		t.Fatalf("Stop fake PID = %v", err)
	}
	if err := sleeper.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was killed: %v", err)
	}
}

func TestStopRequiresCompleteProcessIdentityInLifecycleState(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	manager, _ := New(cfg)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })
	dir, err := openRuntime(cfg.RuntimeDir, false)
	if err != nil {
		t.Fatal(err)
	}
	original, err := readState(dir)
	if err != nil {
		t.Fatal(err)
	}
	originalDocument, _ := json.Marshal(original)
	for name, mutate := range map[string]func(*lifecycleState){
		"executable identity": func(state *lifecycleState) { state.Inode++ },
		"process start token": func(state *lifecycleState) { state.StartToken += "-reused" },
	} {
		t.Run(name, func(t *testing.T) {
			tampered := original
			mutate(&tampered)
			document, _ := json.Marshal(tampered)
			if err := os.WriteFile(filepath.Join(cfg.RuntimeDir, stateName), document, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := manager.Stop(context.Background()); !errors.Is(err, ErrUnprovenProcess) {
				t.Fatalf("Stop with tampered %s = %v", name, err)
			}
			if err := syscall.Kill(original.PID, 0); err != nil {
				t.Fatalf("daemon was killed from tampered %s: %v", name, err)
			}
			if err := os.WriteFile(filepath.Join(cfg.RuntimeDir, stateName), originalDocument, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
	_ = dir.Close()
}

func TestStatusBindsCanonicalArgumentsAndEnvironment(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	manager, _ := New(cfg)
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })
	for _, mutate := range []func(*Config){
		func(value *Config) { value.Arguments = append(value.Arguments, "--changed") },
		func(value *Config) {
			value.ChildEnv = append(value.ChildEnv, "PALONEXUS_CHANGED=1")
		},
		func(value *Config) { value.ConfigurationDigest = strings.Repeat("b", 64) },
	} {
		changed := cfg
		mutate(&changed)
		other, err := New(changed)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := other.Status(context.Background()); !errors.Is(err, ErrUnprovenProcess) {
			t.Fatalf("Status with changed launch identity = %v", err)
		}
	}
	t.Setenv("HOME", filepath.Join(t.TempDir(), "changed-home"))
	changedEnvironment, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := changedEnvironment.Status(context.Background()); !errors.Is(err, ErrUnprovenProcess) {
		t.Fatalf("Status with changed sanitized environment = %v", err)
	}
}

func TestStatusRejectsCorruptOversizedAndTrailingState(t *testing.T) {
	for _, document := range [][]byte{
		[]byte(`{}`),
		[]byte(`{"version":1}{"version":1}`),
		bytes.Repeat([]byte("x"), maxStateBytes+1),
	} {
		t.Run(strconv.Itoa(len(document)), func(t *testing.T) {
			cfg := testConfig(t)
			if err := os.Mkdir(cfg.RuntimeDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(cfg.RuntimeDir, stateName), document, 0o600); err != nil {
				t.Fatal(err)
			}
			manager, _ := New(cfg)
			if _, err := manager.Status(context.Background()); !errors.Is(err, ErrUnsafeRuntime) {
				t.Fatalf("Status corrupt state = %v", err)
			}
		})
	}
}

func TestCheckUsesDaemonTransportAfterAutoStart(t *testing.T) {
	requireAutoStart(t)
	cfg := testConfig(t)
	manager, _ := New(cfg)
	t.Cleanup(func() { _ = manager.Stop(context.Background()) })
	response, err := manager.Check(context.Background(), validActionDocument(t), false)
	if err != nil {
		t.Fatal(err)
	}
	failure, err := protocol.ParseProtocolError(response)
	if err != nil || failure.Code != protocol.ProtocolErrorCodeInvalidRequest {
		t.Fatalf("response = %s, %v", response, err)
	}
}

func TestClientRejectsUnterminatedAndOversizedDaemonResponse(t *testing.T) {
	for _, response := range [][]byte{
		[]byte(`{"schemaVersion":"1"}`),
		append(bytes.Repeat([]byte("x"), maxFrameBytes+1), '\n'),
	} {
		t.Run(strconv.Itoa(len(response)), func(t *testing.T) {
			cfg := testConfig(t)
			manager, _ := New(cfg)
			socketPath := filepath.Join(cfg.RuntimeDir, "guard.sock")
			listener, err := net.Listen("unix", socketPath)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			_ = os.Chmod(socketPath, 0o600)
			go func() {
				conn, acceptErr := listener.Accept()
				if acceptErr == nil {
					defer conn.Close()
					_, _ = bufio.NewReader(conn).ReadBytes('\n')
					_, _ = conn.Write(response)
				}
			}()
			// This is deliberately not a PaloNexus readiness peer, so the
			// manager must fail before trusting its response.
			if _, err := manager.Check(context.Background(), validActionDocument(t), false); err == nil {
				t.Fatal("untrusted daemon response was accepted")
			}
		})
	}
}

func TestRepeatedStatusAndOneShotChecksDoNotLeakDescriptors(t *testing.T) {
	cfg := testConfig(t)
	manager, _ := New(cfg)
	before := descriptorCount(t)
	for range 100 {
		if _, err := manager.Status(context.Background()); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.Check(
			context.Background(), validActionDocument(t), true,
		); err != nil {
			t.Fatal(err)
		}
	}
	after := descriptorCount(t)
	if after > before+3 {
		t.Fatalf("descriptor count grew from %d to %d", before, after)
	}
}

func descriptorCount(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/dev/fd")
	if err != nil {
		t.Skipf("descriptor directory unavailable: %v", err)
	}
	return len(entries)
}

func copyExecutable(t *testing.T, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(output, input); err != nil {
		_ = output.Close()
		t.Fatal(err)
	}
	if err := output.Close(); err != nil {
		t.Fatal(err)
	}
}

func writeTestState(root string, value lifecycleState) error {
	document, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, stateName), document, 0o600)
}
