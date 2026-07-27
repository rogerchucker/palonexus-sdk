// SPDX-License-Identifier: MIT

//go:build darwin || linux

package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func fixture(t *testing.T, target Target, version string) Options {
	t.Helper()
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(home, "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	manifestDir, manifest := ".claude-plugin", "plugin.json"
	if target == Codex {
		manifestDir = ".codex-plugin"
	}
	if err := os.Mkdir(filepath.Join(source, manifestDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, manifestDir, manifest), []byte(`{"name":"palonexus"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "hook"), []byte("#!/bin/sh\nexit 2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(home, "palonexus")
	if err := os.WriteFile(guard, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	return Options{Home: home, SourceDir: source, GuardPath: guard, Version: version}
}

func TestInstallAndIdempotentUpgradePreserveUnrelatedSettings(t *testing.T) {
	for _, target := range []Target{ClaudeCode, Codex} {
		t.Run(string(target), func(t *testing.T) {
			options := fixture(t, target, "1.0.0")
			settings := filepath.Join(options.Home, hostDirectory(target), "settings.json")
			if err := os.MkdirAll(filepath.Dir(settings), 0o700); err != nil {
				t.Fatal(err)
			}
			const unrelated = "{\n  \"unknown\": true\n}\n"
			if err := os.WriteFile(settings, []byte(unrelated), 0o600); err != nil {
				t.Fatal(err)
			}
			first, err := Install(context.Background(), target, options)
			if err != nil || !first.Changed {
				t.Fatalf("first install = %#v, %v", first, err)
			}
			second, err := Install(context.Background(), target, options)
			if err != nil || second.Changed {
				t.Fatalf("idempotent install = %#v, %v", second, err)
			}
			if got, _ := os.ReadFile(settings); string(got) != unrelated {
				t.Fatalf("unrelated settings changed: %q", got)
			}
			if err := os.WriteFile(filepath.Join(options.SourceDir, "new"), []byte("v2"), 0o600); err != nil {
				t.Fatal(err)
			}
			options.Version = "2.0.0"
			upgraded, err := Install(context.Background(), target, options)
			if err != nil || !upgraded.Changed {
				t.Fatalf("upgrade = %#v, %v", upgraded, err)
			}
			if _, err := os.Stat(filepath.Join(upgraded.Path, "new")); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUninstallOnlyRemovesOwnedPlugin(t *testing.T) {
	options := fixture(t, ClaudeCode, "1.0.0")
	result, err := Install(context.Background(), ClaudeCode, options)
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(options.Home, ".claude", "plugins", "other")
	if err := os.MkdirAll(other, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(other, "keep"), []byte("yes"), 0o600); err != nil {
		t.Fatal(err)
	}
	removed, err := Uninstall(context.Background(), ClaudeCode, Options{Home: options.Home})
	if err != nil || !removed.Changed {
		t.Fatalf("uninstall = %#v, %v", removed, err)
	}
	if _, err := os.Stat(result.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned plugin remains: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(other, "keep")); err != nil || string(got) != "yes" {
		t.Fatalf("unrelated plugin changed: %q, %v", got, err)
	}
	second, err := Uninstall(context.Background(), ClaudeCode, Options{Home: options.Home})
	if err != nil || second.Changed {
		t.Fatalf("idempotent uninstall = %#v, %v", second, err)
	}
}

func TestUninstallRefusesUnknownFilesInsideOwnedDirectory(t *testing.T) {
	options := fixture(t, Codex, "1.0.0")
	result, err := Install(context.Background(), Codex, options)
	if err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(result.Path, "user-file")
	if err := os.WriteFile(foreign, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(context.Background(), Codex, Options{Home: options.Home}); err == nil {
		t.Fatal("uninstall removed a directory containing unknown files")
	}
	if got, err := os.ReadFile(foreign); err != nil || string(got) != "preserve" {
		t.Fatalf("unknown file changed: %q, %v", got, err)
	}
}

func TestRejectsUnsafeTargetsAndArtifacts(t *testing.T) {
	options := fixture(t, Codex, "1.0.0")
	for _, name := range []string{"relative-home", "relative-source", "relative-guard", "unknown-target"} {
		t.Run(name, func(t *testing.T) {
			copy := options
			switch name {
			case "relative-home":
				copy.Home = "relative"
			case "relative-source":
				copy.SourceDir = "relative"
			case "relative-guard":
				copy.GuardPath = "relative"
			case "unknown-target":
			}
			target := Codex
			if name == "unknown-target" {
				target = Target("other")
			}
			if _, err := Install(context.Background(), target, copy); err == nil {
				t.Fatal("unsafe input accepted")
			}
		})
	}
	link := filepath.Join(options.Home, "guard-link")
	if err := os.Symlink(options.GuardPath, link); err != nil {
		t.Fatal(err)
	}
	options.GuardPath = link
	if _, err := Install(context.Background(), Codex, options); err == nil {
		t.Fatal("symlink guard accepted")
	}
}

func snapshotTree(root string) (string, error) {
	var rows []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		row := relative + ":" + info.Mode().String()
		if info.Mode().IsRegular() {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			digest := sha256.Sum256(data)
			row += ":" + hex.EncodeToString(digest[:])
		}
		rows = append(rows, row)
		return nil
	})
	sort.Strings(rows)
	return strings.Join(rows, "\n"), err
}

func TestMalformedOrUnownedExistingPluginFailsClosed(t *testing.T) {
	options := fixture(t, ClaudeCode, "1.0.0")
	path := filepath.Join(options.Home, ".claude", "plugins", installName)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "foreign"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), ClaudeCode, options); err == nil {
		t.Fatal("foreign destination overwritten")
	}
	if _, err := Uninstall(context.Background(), ClaudeCode, Options{Home: options.Home}); err == nil {
		t.Fatal("foreign destination removed")
	}
	if got, _ := os.ReadFile(filepath.Join(path, "foreign")); string(got) != "keep" {
		t.Fatal("foreign destination changed")
	}
}

func TestRollbackRestoresExactPreviousPlugin(t *testing.T) {
	for _, boundary := range []string{"journal", "backup", "publish", "delete"} {
		t.Run(boundary, func(t *testing.T) {
			options := fixture(t, Codex, "1.0.0")
			result, err := Install(context.Background(), Codex, options)
			if err != nil {
				t.Fatal(err)
			}
			before, err := snapshotTree(result.Path)
			if err != nil {
				t.Fatal(err)
			}
			options.Version = "2.0.0"
			if err := os.WriteFile(filepath.Join(options.SourceDir, "new"), []byte("new"), 0o600); err != nil {
				t.Fatal(err)
			}
			restore := installFaults
			t.Cleanup(func() { installFaults = restore })
			injected := func() error { return errors.New("injected") }
			switch boundary {
			case "journal":
				installFaults.afterJournal = injected
			case "backup":
				installFaults.afterBackup = injected
			case "publish":
				installFaults.afterPublish = injected
			case "delete":
				installFaults.beforeDelete = injected
			}
			if _, err := Install(context.Background(), Codex, options); err == nil {
				t.Fatal("faulted install succeeded")
			}
			installFaults = restore
			after, err := snapshotTree(result.Path)
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatalf("rollback mismatch\nbefore=%s\nafter=%s", before, after)
			}
		})
	}
}

func TestUninstallRollbackRestoresExactPlugin(t *testing.T) {
	for _, boundary := range []string{"journal", "backup", "delete"} {
		t.Run(boundary, func(t *testing.T) {
			options := fixture(t, ClaudeCode, "1.0.0")
			result, err := Install(context.Background(), ClaudeCode, options)
			if err != nil {
				t.Fatal(err)
			}
			before, err := snapshotTree(result.Path)
			if err != nil {
				t.Fatal(err)
			}
			restore := installFaults
			t.Cleanup(func() { installFaults = restore })
			injected := func() error { return errors.New("injected") }
			switch boundary {
			case "journal":
				installFaults.afterJournal = injected
			case "backup":
				installFaults.afterBackup = injected
			case "delete":
				installFaults.beforeDelete = injected
			}
			if _, err := Uninstall(context.Background(), ClaudeCode, Options{Home: options.Home}); err == nil {
				t.Fatal("faulted uninstall succeeded")
			}
			installFaults = restore
			after, err := snapshotTree(result.Path)
			if err != nil {
				t.Fatal(err)
			}
			if before != after {
				t.Fatalf("rollback mismatch\nbefore=%s\nafter=%s", before, after)
			}
		})
	}
}

func TestConcurrentInstallersSerialize(t *testing.T) {
	options := fixture(t, ClaudeCode, "1.0.0")
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Install(context.Background(), ClaudeCode, options)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := readOwnedMarker(filepath.Join(options.Home, ".claude", "plugins", installName), ClaudeCode); err != nil {
		t.Fatal(err)
	}
}

func TestCrashRecoveryRestoresInstallAndCompletesUninstall(t *testing.T) {
	t.Run("install", func(t *testing.T) {
		options := fixture(t, Codex, "1.0.0")
		result, err := Install(context.Background(), Codex, options)
		if err != nil {
			t.Fatal(err)
		}
		parent := filepath.Dir(result.Path)
		if err := os.Rename(result.Path, filepath.Join(parent, backupName)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(parent, journalName),
			mustJSON(transactionJournal{Schema: 1, Operation: "install"}), 0o600); err != nil {
			t.Fatal(err)
		}
		recovered, err := Install(context.Background(), Codex, options)
		if err != nil || recovered.Changed {
			t.Fatalf("recovery = %#v, %v", recovered, err)
		}
		if _, err := os.Stat(result.Path); err != nil {
			t.Fatal(err)
		}
		if _, err := os.Stat(filepath.Join(parent, backupName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("backup survived recovery: %v", err)
		}
	})

	t.Run("uninstall", func(t *testing.T) {
		options := fixture(t, ClaudeCode, "1.0.0")
		result, err := Install(context.Background(), ClaudeCode, options)
		if err != nil {
			t.Fatal(err)
		}
		parent := filepath.Dir(result.Path)
		if err := os.Rename(result.Path, filepath.Join(parent, backupName)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(parent, journalName),
			mustJSON(transactionJournal{Schema: 1, Operation: "uninstall"}), 0o600); err != nil {
			t.Fatal(err)
		}
		recovered, err := Uninstall(context.Background(), ClaudeCode, Options{Home: options.Home})
		if err != nil || recovered.Changed {
			t.Fatalf("recovery = %#v, %v", recovered, err)
		}
		if _, err := os.Stat(filepath.Join(parent, backupName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("backup survived recovery: %v", err)
		}
	})
}

func TestArtifactSpecialFilesAndHardlinksAreRejected(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			options := fixture(t, ClaudeCode, "1.0.0")
			switch kind {
			case "symlink":
				if err := os.Symlink("hook", filepath.Join(options.SourceDir, "unsafe")); err != nil {
					t.Fatal(err)
				}
			case "fifo":
				if err := unix.Mkfifo(filepath.Join(options.SourceDir, "unsafe"), 0o600); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(filepath.Join(options.SourceDir, "hook"), filepath.Join(options.SourceDir, "unsafe")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := Install(context.Background(), ClaudeCode, options); err == nil {
				t.Fatalf("%s artifact accepted", kind)
			}
		})
	}
}

func TestArtifactBoundsAndPermissionsAreEnforced(t *testing.T) {
	t.Run("oversized", func(t *testing.T) {
		options := fixture(t, Codex, "1.0.0")
		file, err := os.OpenFile(filepath.Join(options.SourceDir, "large"), os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := file.Truncate(maxIndividualFile + 1); err != nil {
			file.Close()
			t.Fatal(err)
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(context.Background(), Codex, options); err == nil {
			t.Fatal("oversized artifact accepted")
		}
	})

	t.Run("writable-source", func(t *testing.T) {
		options := fixture(t, ClaudeCode, "1.0.0")
		if err := os.Chmod(options.SourceDir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(context.Background(), ClaudeCode, options); err == nil {
			t.Fatal("writable artifact directory accepted")
		}
	})

	t.Run("non-private-home", func(t *testing.T) {
		options := fixture(t, Codex, "1.0.0")
		if err := os.Chmod(options.Home, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(context.Background(), Codex, options); err == nil {
			t.Fatal("non-private home accepted")
		}
	})
}

func TestAmbiguousMarkerAndUnjournaledRecoveryArtifactsFailClosed(t *testing.T) {
	options := fixture(t, Codex, "1.0.0")
	result, err := Install(context.Background(), Codex, options)
	if err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(result.Path, markerName)
	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := strings.Replace(string(data), `"owner":`, `"owner":"attacker","owner":`, 1)
	if err := os.WriteFile(markerPath, []byte(ambiguous), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), Codex, options); err == nil {
		t.Fatal("duplicate marker field accepted")
	}

	options = fixture(t, ClaudeCode, "1.0.0")
	parent := filepath.Join(options.Home, ".claude", "plugins")
	if err := os.MkdirAll(filepath.Join(parent, stageName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), ClaudeCode, options); err == nil {
		t.Fatal("unjournaled staging artifact silently removed")
	}
}
