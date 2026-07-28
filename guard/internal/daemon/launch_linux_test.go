// SPDX-License-Identifier: MIT
//go:build linux

package daemon

import (
	"context"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLinuxLaunchSnapshotIsSealedMemfd(t *testing.T) {
	cfg := testConfig(t)
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	logFile, err := os.CreateTemp(t.TempDir(), "daemon-log-")
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	command, closeSnapshot, err := manager.launchCommand(context.Background(), logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer closeSnapshot()
	if command.Path != "/proc/self/fd/3" || len(command.ExtraFiles) != 1 {
		t.Fatalf("launch command does not execute the snapshot: %#v", command)
	}
	seals, err := unix.FcntlInt(command.ExtraFiles[0].Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := unix.F_SEAL_WRITE | unix.F_SEAL_GROW | unix.F_SEAL_SHRINK | unix.F_SEAL_SEAL
	if seals&want != want {
		t.Fatalf("memfd seals = %#x, want %#x", seals, want)
	}
}
