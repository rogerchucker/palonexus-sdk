// SPDX-License-Identifier: MIT

//go:build darwin || linux

package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

type fakeNative struct {
	mu           sync.Mutex
	target       Target
	version      string
	hostVersion  string
	marketplace  string
	home         string
	installed    bool
	commands     []NativeCommand
	failAt       int
	failContains string
}

func (f *fakeNative) Run(_ context.Context, command NativeCommand) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.commands = append(f.commands, command)
	for _, variable := range command.Env {
		if strings.HasPrefix(variable, "HOME=") {
			f.home = strings.TrimPrefix(variable, "HOME=")
		}
	}
	if f.failAt > 0 && len(f.commands) == f.failAt {
		return nil, errors.New("native failure")
	}
	args := strings.Join(command.Args, " ")
	if f.failContains != "" && strings.Contains(args, f.failContains) {
		f.failContains = ""
		return nil, errors.New("native failure")
	}
	if args == "--version --json" {
		return []byte(fmt.Sprintf(
			`{"name":"palonexus","version":%q,"protocolVersion":"1.0"}`, f.version,
		)), nil
	}
	if args == "status --json" {
		return []byte(`{"authenticated":false,"ready":true}`), nil
	}
	if args == "--version" {
		if f.target == ClaudeCode {
			if f.hostVersion != "" {
				return []byte(f.hostVersion), nil
			}
			return []byte("2.1.219 (Claude Code)\n"), nil
		}
		if f.hostVersion != "" {
			return []byte(f.hostVersion), nil
		}
		return []byte("codex-cli 0.145.0\n"), nil
	}
	if strings.Contains(args, "marketplace add") {
		f.marketplace = command.Args[len(command.Args)-1]
		if data, err := os.ReadFile(filepath.Join(f.marketplace, markerName)); err == nil {
			var marker ownershipMarker
			if json.Unmarshal(data, &marker) == nil {
				f.version = marker.Version
			}
		}
		return []byte(`{}`), nil
	}
	if strings.Contains(args, "marketplace remove") {
		f.marketplace = ""
		return []byte(`{}`), nil
	}
	if strings.Contains(args, " plugin install ") || strings.HasPrefix(args, "plugin install ") ||
		strings.Contains(args, "plugin add") {
		f.installed = true
		return []byte(`{}`), nil
	}
	if strings.Contains(args, "plugin uninstall") || strings.Contains(args, "plugin remove") {
		f.installed = false
		return []byte(`{}`), nil
	}
	if args == "plugin validate --strict "+f.marketplace || strings.HasPrefix(args, "plugin validate --strict ") {
		return []byte("valid\n"), nil
	}
	if args == "plugin list --json" {
		if !f.installed {
			if f.target == ClaudeCode {
				return []byte(`[]`), nil
			}
			return []byte(`{"installed":[],"available":[]}`), nil
		}
		pluginPath := filepath.Join(f.marketplace, "plugins", "palonexus")
		if f.target == ClaudeCode {
			pluginPath = filepath.Join(f.home, ".claude", "plugins", "cache", "palonexus-sdk", "palonexus", f.version)
			return []byte(fmt.Sprintf(
				`[{"id":"palonexus@palonexus-sdk","version":%q,"scope":"user","installPath":%q}]`,
				f.version, pluginPath,
			)), nil
		}
		return []byte(fmt.Sprintf(
			`{"installed":[{"pluginId":"palonexus@palonexus-sdk","version":%q,"installed":true,"marketplaceName":"palonexus-sdk","source":{"source":"local","path":%q},"marketplaceSource":{"sourceType":"local","source":%q}}],"available":[]}`,
			f.version, pluginPath, f.marketplace,
		)), nil
	}
	return []byte(`{}`), nil
}

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
	manifestDir := ".claude-plugin"
	marketplaceDir := ".claude-plugin"
	if target == Codex {
		manifestDir = ".codex-plugin"
		marketplaceDir = filepath.Join(".agents", "plugins")
	}
	pluginRoot := filepath.Join(source, "plugins", installName)
	if err := os.MkdirAll(filepath.Join(pluginRoot, manifestDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(source, marketplaceDir), 0o755); err != nil {
		t.Fatal(err)
	}
	pluginManifest := fmt.Sprintf(
		`{"name":"palonexus","version":%q,"description":"PaloNexus governed actions","license":"MIT","author":{"name":"PaloNexus"},"hooks":"./hooks/hooks.json","skills":"./skills/"}`,
		version,
	)
	if err := os.WriteFile(filepath.Join(pluginRoot, manifestDir, "plugin.json"), []byte(pluginManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	marketplaceManifest := `{"name":"palonexus-sdk","plugins":[{"name":"palonexus","source":{"source":"local","path":"./plugins/palonexus"}}]}`
	if target == ClaudeCode {
		marketplaceManifest = `{"name":"palonexus-sdk","description":"PaloNexus governed actions","owner":{"name":"PaloNexus"},"plugins":[{"name":"palonexus","source":"./plugins/palonexus"}]}`
	}
	if err := os.WriteFile(filepath.Join(source, marketplaceDir, "marketplace.json"), []byte(marketplaceManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pluginRoot, "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, "hooks", "hooks.json"), []byte(`{"version":1,"guardConfig":"./guard.json"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, "hooks", "guard.json"), []byte(`{"guardPath":"__PALONEXUS_GUARD__","argv":["guard","check"]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(pluginRoot, "skills"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, "skills", "SKILL.md"), []byte("---\nname: palonexus\n---\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pluginRoot, "palonexus.json"), []byte(`{"protocolVersion":"1.0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "hook"), []byte("#!/bin/sh\nexit 2\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	guard := filepath.Join(home, "palonexus")
	guardScript := fmt.Sprintf(
		"#!/bin/sh\nprintf '%%s\\n' '{\"name\":\"palonexus\",\"version\":\"%s\",\"protocolVersion\":\"1.0\"}'\n",
		version,
	)
	if err := os.WriteFile(guard, []byte(guardScript), 0o700); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(home, string(target))
	if err := os.WriteFile(host, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	runner := &fakeNative{target: target, version: version}
	return Options{
		Home: home, SourceDir: source, GuardPath: guard, HostPath: host,
		Version: version, Runner: runner,
	}
}

func uninstallOptions(options Options) Options {
	return Options{Home: options.Home, HostPath: options.HostPath, Runner: options.Runner}
}

func setFixtureVersion(t *testing.T, target Target, options *Options, version string) {
	t.Helper()
	options.Version = version
	options.Runner.(*fakeNative).version = version
	manifestDirectory := ".claude-plugin"
	if target == Codex {
		manifestDirectory = ".codex-plugin"
	}
	manifestPath := filepath.Join(options.SourceDir, "plugins", installName, manifestDirectory, "plugin.json")
	manifest := fmt.Sprintf(
		`{"name":"palonexus","version":%q,"description":"PaloNexus governed actions","license":"MIT","author":{"name":"PaloNexus"},"hooks":"./hooks/hooks.json","skills":"./skills/"}`,
		version,
	)
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
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
			setFixtureVersion(t, target, &options, "2.0.0")
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
	removed, err := Uninstall(context.Background(), ClaudeCode, uninstallOptions(options))
	if err != nil || !removed.Changed {
		t.Fatalf("uninstall = %#v, %v", removed, err)
	}
	if _, err := os.Stat(result.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned plugin remains: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(other, "keep")); err != nil || string(got) != "yes" {
		t.Fatalf("unrelated plugin changed: %q, %v", got, err)
	}
	second, err := Uninstall(context.Background(), ClaudeCode, uninstallOptions(options))
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
	if _, err := Uninstall(context.Background(), Codex, uninstallOptions(options)); err == nil {
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
	path := marketplaceInstallPath(options.Home, ClaudeCode)
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "foreign"), []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), ClaudeCode, options); err == nil {
		t.Fatal("foreign destination overwritten")
	}
	if _, err := Uninstall(context.Background(), ClaudeCode, uninstallOptions(options)); err == nil {
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
			setFixtureVersion(t, Codex, &options, "2.0.0")
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
			if _, err := Uninstall(context.Background(), ClaudeCode, uninstallOptions(options)); err == nil {
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
	if _, err := readOwnedMarker(marketplaceInstallPath(options.Home, ClaudeCode), ClaudeCode); err != nil {
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
		recovered, err := Uninstall(context.Background(), ClaudeCode, uninstallOptions(options))
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

	t.Run("writable-home", func(t *testing.T) {
		options := fixture(t, Codex, "1.0.0")
		if err := os.Chmod(options.Home, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(context.Background(), Codex, options); err == nil {
			t.Fatal("group/world-writable home accepted")
		}
	})

	t.Run("owner-controlled-readable-home", func(t *testing.T) {
		options := fixture(t, Codex, "1.0.0")
		if err := os.Chmod(options.Home, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(context.Background(), Codex, options); err != nil {
			t.Fatalf("safe 0755 home rejected: %v", err)
		}
	})
}

func TestStrictPluginAndMarketplaceManifestsFailClosed(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(t *testing.T, options Options)
	}{
		{"unknown-plugin-key", func(t *testing.T, options Options) {
			path := filepath.Join(options.SourceDir, "plugins", installName, ".claude-plugin", "plugin.json")
			data, _ := os.ReadFile(path)
			data = bytes.Replace(data, []byte(`"name":`), []byte(`"token":"secret","name":`), 1)
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicate-marketplace-key", func(t *testing.T, options Options) {
			path := filepath.Join(options.SourceDir, ".claude-plugin", "marketplace.json")
			data, _ := os.ReadFile(path)
			data = bytes.Replace(data, []byte(`"name":`), []byte(`"name":"other","name":`), 1)
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"traversal-hook", func(t *testing.T, options Options) {
			path := filepath.Join(options.SourceDir, "plugins", installName, ".claude-plugin", "plugin.json")
			data, _ := os.ReadFile(path)
			data = bytes.Replace(data, []byte(`./hooks/hooks.json`), []byte(`../hooks.json`), 1)
			if err := os.WriteFile(path, data, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong-protocol", func(t *testing.T, options Options) {
			path := filepath.Join(options.SourceDir, "plugins", installName, "palonexus.json")
			if err := os.WriteFile(path, []byte(`{"protocolVersion":"2.0"}`), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := fixture(t, ClaudeCode, "1.0.0")
			test.mutate(t, options)
			if _, err := Install(context.Background(), ClaudeCode, options); err == nil {
				t.Fatal("unsafe manifest accepted")
			}
		})
	}
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
	parent := filepath.Dir(marketplaceInstallPath(options.Home, ClaudeCode))
	if err := os.MkdirAll(filepath.Join(parent, stageName), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(context.Background(), ClaudeCode, options); err == nil {
		t.Fatal("unjournaled staging artifact silently removed")
	}
}

func TestDuplicateOrTrailingTransactionJournalFailsClosed(t *testing.T) {
	for _, document := range []string{
		`{"schema":1,"schema":1,"operation":"install"}`,
		"{\"schema\":1,\"operation\":\"install\"}\n{}",
	} {
		options := fixture(t, Codex, "1.0.0")
		result, err := Install(context.Background(), Codex, options)
		if err != nil {
			t.Fatal(err)
		}
		parent := filepath.Dir(result.Path)
		if err := os.Rename(result.Path, filepath.Join(parent, backupName)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(parent, journalName), []byte(document), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Install(context.Background(), Codex, options); err == nil {
			t.Fatalf("ambiguous journal accepted: %s", document)
		}
		if _, err := os.Stat(filepath.Join(parent, backupName)); err != nil {
			t.Fatalf("recovery artifact changed: %v", err)
		}
	}
}
