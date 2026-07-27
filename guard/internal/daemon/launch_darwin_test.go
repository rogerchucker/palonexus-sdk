// SPDX-License-Identifier: MIT
//go:build darwin

package daemon

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinEscalationNeverSignalsNumericPID(t *testing.T) {
	sleeper := exec.Command("sleep", "30")
	if err := sleeper.Start(); err != nil {
		t.Skipf("sleep unavailable: %v", err)
	}
	t.Cleanup(func() {
		_ = sleeper.Process.Kill()
		_, _ = sleeper.Process.Wait()
	})
	if err := signalStableProcess(lifecycleState{
		PID: sleeper.Process.Pid, StartToken: "forced-reuse-token",
	}, syscall.SIGKILL); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Darwin numeric escalation = %v", err)
	}
	guard := &startedProcessGuard{
		pid: sleeper.Process.Pid, startToken: "forced-reuse-token",
	}
	if err := guard.signal(syscall.SIGKILL); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Darwin startup escalation = %v", err)
	}
	if err := sleeper.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("unrelated process was signaled: %v", err)
	}
}

func TestDarwinLaunchRejectsPreexistingStageSymlinkWithoutFollowingIt(t *testing.T) {
	cfg := testConfig(t)
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(cfg.Executable)
	if err != nil {
		t.Fatal(err)
	}
	copyPath := filepath.Join(filepath.Dir(cfg.RuntimeDir), "executable-copy")
	copyFile, err := os.OpenFile(copyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o500)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(copyFile, source); err != nil {
		t.Fatal(err)
	}
	_ = source.Close()
	if err := copyFile.Close(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(copyPath, unix.UF_IMMUTABLE); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Chflags(copyPath, 0) })
	stagePath := filepath.Join(cfg.RuntimeDir, ".palonexus-exec-"+manager.launch.Digest)
	if err := os.Symlink(copyPath, stagePath); err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); !errors.Is(err, ErrUnsafeExecutable) {
		if err == nil {
			_ = manager.Stop(context.Background())
		}
		t.Fatalf("Start through preexisting stage symlink = %v", err)
	}
	info, err := os.Lstat(stagePath)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("stage symlink was followed or removed: %#v, %v", info, err)
	}
}

func TestDarwinLaunchSnapshotIsImmutableUntilDaemonExit(t *testing.T) {
	cfg := testConfig(t)
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(cfg.Executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	stagePath := filepath.Join(cfg.RuntimeDir, ".palonexus-exec-"+manager.launch.Digest)
	stage, err := openOrCreateDarwinStage(stagePath, source, manager.launch.Digest)
	if err != nil {
		t.Fatal(err)
	}
	defer stage.Close()
	matches, err := filepath.Glob(filepath.Join(cfg.RuntimeDir, ".palonexus-exec-*"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("staged launch = %v, %v", matches, err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(matches[0], &stat); err != nil ||
		stat.Flags&unix.UF_IMMUTABLE == 0 || stat.Mode&0o777 != 0o500 {
		t.Fatalf("staged launch is not immutable: %#v, %v", stat, err)
	}
	if file, err := os.OpenFile(matches[0], os.O_WRONLY, 0); err == nil {
		_ = file.Close()
		t.Fatal("immutable staged launch opened for writing")
	}
	removeExactDarwinStage(stage, matches[0])
	if _, err := os.Lstat(matches[0]); !os.IsNotExist(err) {
		t.Fatalf("exact staged launch cleanup failed: %v", err)
	}
}

func TestDarwinLaunchExecutesVerifiedDescriptorAcrossPathSwap(t *testing.T) {
	cfg := testConfig(t)
	var originalPath string
	cfg.afterLaunchVerified = func(stagePath string) {
		if err := unix.Chflags(stagePath, 0); err != nil {
			t.Fatal(err)
		}
		originalPath = stagePath + ".original"
		if err := os.Rename(stagePath, originalPath); err != nil {
			t.Fatal(err)
		}
		replacement, err := os.ReadFile("/usr/bin/false")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(stagePath, replacement, 0o500); err != nil {
			t.Fatal(err)
		}
	}
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); !errors.Is(err, ErrUnsafeExecutable) {
		t.Fatalf("unsupported exact-descriptor launch did not fail closed: %v", err)
	}
	if originalPath == "" {
		t.Fatal("swap hook did not run")
	}
	if _, err := os.Lstat(originalPath); err != nil {
		t.Fatalf("verified inode was removed through its replacement path: %v", err)
	}
	stagePath := strings.TrimSuffix(originalPath, ".original")
	if _, err := os.Lstat(stagePath); err != nil {
		t.Fatalf("replacement path was removed during exact-inode cleanup: %v", err)
	}
}
