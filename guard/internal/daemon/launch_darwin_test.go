// SPDX-License-Identifier: MIT
//go:build darwin

package daemon

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDarwinLaunchSnapshotIsImmutableUntilDaemonExit(t *testing.T) {
	cfg := testConfig(t)
	manager, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
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
	if err := manager.Stop(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(matches[0]); !os.IsNotExist(err) {
		t.Fatalf("staged launch survived daemon exit: %v", err)
	}
}
