// SPDX-License-Identifier: MIT

//go:build darwin || linux

// Package plugin installs PaloNexus host-plugin artifacts without modifying
// broad host settings.
package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	installName       = "palonexus"
	marketplaceName   = "palonexus-sdk"
	markerName        = ".palonexus-install.json"
	lockName          = ".palonexus-install.lock"
	journalName       = ".palonexus-install.journal"
	journalTempName   = ".palonexus-install.journal.tmp"
	stageName         = ".palonexus-install.stage"
	backupName        = ".palonexus-install.backup"
	maxArtifactFiles  = 4096
	maxArtifactBytes  = 64 << 20
	maxIndividualFile = 16 << 20
)

var versionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}$`)

// Target is an explicitly supported plugin host.
type Target string

const (
	ClaudeCode Target = "claude-code"
	Codex      Target = "codex"
)

// Options describes an installation. Every path must be absolute.
type Options struct {
	Home      string
	SourceDir string
	GuardPath string
	HostPath  string
	Version   string
	Runner    NativeRunner
}

// Result reports whether the requested operation changed the installation.
type Result struct {
	Changed              bool
	Path                 string
	Version              string
	AuthenticationStatus string
}

type ownershipMarker struct {
	Schema       int    `json:"schema"`
	Owner        string `json:"owner"`
	Target       Target `json:"target"`
	Version      string `json:"version"`
	GuardPath    string `json:"guardPath"`
	SourceDigest string `json:"sourceDigest"`
	Digest       string `json:"digest"`
}

type transactionJournal struct {
	Schema          int    `json:"schema"`
	Operation       string `json:"operation"`
	Phase           string `json:"phase"`
	PreviousVersion string `json:"previousVersion,omitempty"`
	NextVersion     string `json:"nextVersion,omitempty"`
}

type faultHooks struct {
	afterJournal func() error
	afterBackup  func() error
	afterPublish func() error
	beforeDelete func() error
}

var installFaults faultHooks
var processInstallGate = func() chan struct{} {
	gate := make(chan struct{}, 1)
	gate <- struct{}{}
	return gate
}()

// Install copies one repository plugin artifact into the host's native
// per-user plugin directory. It never edits host settings.
func Install(ctx context.Context, target Target, options Options) (Result, error) {
	if err := validateOptions(target, options, true); err != nil {
		return Result{}, err
	}
	if err := ensureNativeHome(options.Home, target); err != nil {
		return Result{}, err
	}
	sourceFD, err := openAbsoluteSourceDirectory(options.SourceDir)
	if err != nil {
		return Result{}, fmt.Errorf("validate plugin artifact: %w", err)
	}
	defer unix.Close(sourceFD)
	if err := requireManifest(sourceFD, target, options.Version); err != nil {
		return Result{}, err
	}
	if err := validateGuard(options.GuardPath); err != nil {
		return Result{}, err
	}
	if err := probeGuard(ctx, target, options); err != nil {
		return Result{}, err
	}
	authenticationStatus := guardAuthenticationStatus(ctx, target, options)
	if err := probeNative(ctx, target, options); err != nil {
		return Result{}, err
	}
	sourceDigest, err := digestTree(sourceFD)
	if err != nil {
		return Result{}, fmt.Errorf("validate plugin artifact: %w", err)
	}
	marker := ownershipMarker{
		Schema: 1, Owner: "github.com/rogerchucker/palonexus-sdk",
		Target: target, Version: options.Version, GuardPath: options.GuardPath,
		SourceDigest: sourceDigest,
	}
	parentFD, destination, err := openPluginParent(options.Home, target)
	if err != nil {
		return Result{}, err
	}
	defer unix.Close(parentFD)
	path := marketplaceInstallPath(options.Home, target)
	changed, err := withTransactionLock(ctx, parentFD, func() (bool, error) {
		if err := recoverTransaction(parentFD, target); err != nil {
			return false, err
		}
		existing, markerErr := readOwnedMarkerAt(parentFD, destination, target)
		switch {
		case markerErr == nil:
			if err := verifyNativeInstalled(ctx, target, options, path, existing.Version, true); err != nil {
				return false, errors.New("owned local install does not match native registration")
			}
			if sameInstallIntent(existing, marker) {
				return false, nil
			}
		case errors.Is(markerErr, os.ErrNotExist):
			if err := verifyNativeInstalled(ctx, target, options, "", "", false); err != nil {
				return false, errors.New("foreign native plugin registration")
			}
			absent, absentErr := nativeMarketplaceAbsent(ctx, target, options)
			if absentErr != nil || !absent {
				return false, errors.New("foreign native marketplace registration")
			}
		default:
			return false, markerErr
		}
		if err := nativeValidate(ctx, target, options, options.SourceDir); err != nil {
			return false, err
		}
		if err := removeIfOwnedStale(parentFD, stageName, target); err != nil {
			return false, err
		}
		if err := unix.Mkdirat(parentFD, stageName, 0o700); err != nil {
			return false, errors.New("create staging directory")
		}
		stageFD, err := openDirectoryAt(parentFD, stageName)
		if err != nil {
			return false, rollbackStage(parentFD, err)
		}
		copyErr := copyTree(sourceFD, stageFD)
		if copyErr == nil {
			copyErr = writeGuardConfigAt(stageFD, target, options.GuardPath)
		}
		if copyErr == nil {
			var stagedDigest string
			stagedDigest, copyErr = digestTreeContent(stageFD, true)
			if copyErr == nil {
				marker.Digest = stagedDigest
				copyErr = writeFileAt(stageFD, markerName, mustJSON(marker), 0o600)
			}
		}
		if syncErr := unix.Fsync(stageFD); copyErr == nil {
			copyErr = syncErr
		}
		unix.Close(stageFD)
		if copyErr != nil {
			return false, rollbackStage(parentFD, copyErr)
		}
		previousVersion := ""
		if markerErr == nil {
			previousVersion = existing.Version
		}
		journal := transactionJournal{
			Schema: 1, Operation: "install", Phase: "local-prepared",
			PreviousVersion: previousVersion, NextVersion: options.Version,
		}
		if err := writeJournal(parentFD, journal); err != nil {
			return false, rollbackStage(parentFD, err)
		}
		if installFaults.afterJournal != nil {
			if err := installFaults.afterJournal(); err != nil {
				return false, rollbackBeforeBackup(parentFD, err)
			}
		}
		hadExisting := markerErr == nil
		if hadExisting {
			if err := unix.Renameat(parentFD, destination, parentFD, backupName); err != nil {
				return false, rollbackInstall(parentFD, false, err)
			}
			if err := unix.Fsync(parentFD); err != nil {
				return false, rollbackInstall(parentFD, true, err)
			}
		}
		if installFaults.afterBackup != nil {
			if err := installFaults.afterBackup(); err != nil {
				return false, rollbackInstall(parentFD, hadExisting, err)
			}
		}
		if err := unix.Renameat(parentFD, stageName, parentFD, destination); err != nil {
			return false, rollbackInstall(parentFD, hadExisting, err)
		}
		if err := unix.Fsync(parentFD); err != nil {
			return false, rollbackInstall(parentFD, hadExisting, err)
		}
		if installFaults.afterPublish != nil {
			if err := installFaults.afterPublish(); err != nil {
				return false, rollbackInstall(parentFD, hadExisting, err)
			}
		}
		journal.Phase = "native-pending"
		if err := writeJournal(parentFD, journal); err != nil {
			return false, rollbackInstall(parentFD, hadExisting, err)
		}
		if err := nativeReplace(ctx, target, options, path, options.Version, previousVersion); err != nil {
			rollbackErr := rollbackInstall(parentFD, hadExisting, err)
			if hadExisting {
				_ = nativeRemoveOwned(ctx, target, options, path, options.Version)
				if restoreErr := nativeReplace(ctx, target, options, path, existing.Version, ""); restoreErr != nil {
					return false, errors.Join(rollbackErr, errors.New("native plugin rollback failed"))
				}
			}
			return false, rollbackErr
		}
		journal.Phase = "native-complete"
		if err := writeJournal(parentFD, journal); err != nil {
			rollbackErr := rollbackInstall(parentFD, hadExisting, err)
			_ = nativeRemoveOwned(ctx, target, options, path, options.Version)
			if hadExisting {
				_ = nativeRestore(ctx, target, options, path, existing.Version)
			}
			return false, rollbackErr
		}
		if hadExisting {
			if installFaults.beforeDelete != nil {
				if err := installFaults.beforeDelete(); err != nil {
					rollbackErr := rollbackInstall(parentFD, true, err)
					_ = nativeRemoveOwned(ctx, target, options, path, options.Version)
					if restoreErr := nativeReplace(ctx, target, options, path, existing.Version, ""); restoreErr != nil {
						return false, errors.Join(rollbackErr, errors.New("native plugin rollback failed"))
					}
					return false, rollbackErr
				}
			}
			if err := removeTreeAt(parentFD, backupName); err != nil {
				return false, errors.New("commit plugin upgrade")
			}
		}
		if err := removeJournal(parentFD); err != nil {
			return false, err
		}
		return true, nil
	})
	return Result{
		Changed: changed, Path: path, Version: options.Version,
		AuthenticationStatus: authenticationStatus,
	}, err
}

func sameInstallIntent(existing, wanted ownershipMarker) bool {
	return existing.Schema == wanted.Schema && existing.Owner == wanted.Owner &&
		existing.Target == wanted.Target && existing.Version == wanted.Version &&
		existing.GuardPath == wanted.GuardPath && existing.SourceDigest == wanted.SourceDigest
}

// Uninstall removes only an installation carrying this project's exact
// ownership marker.
func Uninstall(ctx context.Context, target Target, options Options) (Result, error) {
	if err := validateOptions(target, options, false); err != nil {
		return Result{}, err
	}
	if err := ensureNativeHome(options.Home, target); err != nil {
		return Result{}, err
	}
	parentFD, destination, err := openPluginParent(options.Home, target)
	if err != nil {
		return Result{}, err
	}
	defer unix.Close(parentFD)
	path := marketplaceInstallPath(options.Home, target)
	if err := probeNative(ctx, target, options); err != nil {
		return Result{}, err
	}
	changed, err := withTransactionLock(ctx, parentFD, func() (bool, error) {
		if err := recoverTransaction(parentFD, target); err != nil {
			return false, err
		}
		existing, err := readOwnedMarkerAt(parentFD, destination, target)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return false, nil
			}
			return false, err
		}
		journal := transactionJournal{
			Schema: 1, Operation: "uninstall", Phase: "native-pending",
			PreviousVersion: existing.Version,
		}
		if err := writeJournal(parentFD, journal); err != nil {
			return false, err
		}
		if installFaults.afterJournal != nil {
			if err := installFaults.afterJournal(); err != nil {
				if cleanupErr := removeJournal(parentFD); cleanupErr != nil {
					return false, errors.Join(err, cleanupErr)
				}
				return false, err
			}
		}
		if err := nativeRemoveOwned(ctx, target, options, path, existing.Version); err != nil {
			if restoreErr := nativeRestore(ctx, target, options, path, existing.Version); restoreErr != nil {
				return false, errors.Join(err, errors.New("native plugin rollback failed"))
			}
			_ = removeJournal(parentFD)
			return false, err
		}
		journal.Phase = "native-complete"
		if err := writeJournal(parentFD, journal); err != nil {
			if restoreErr := nativeRestore(ctx, target, options, path, existing.Version); restoreErr != nil {
				return false, errors.Join(err, errors.New("native plugin rollback failed"))
			}
			return false, err
		}
		if err := unix.Renameat(parentFD, destination, parentFD, backupName); err != nil {
			_ = removeJournal(parentFD)
			if restoreErr := nativeRestore(ctx, target, options, path, existing.Version); restoreErr != nil {
				return false, errors.Join(errors.New("stage plugin uninstall"),
					errors.New("native plugin rollback failed"))
			}
			return false, errors.New("stage plugin uninstall")
		}
		if err := unix.Fsync(parentFD); err != nil {
			rollbackErr := rollbackUninstall(parentFD, err)
			if restoreErr := nativeRestore(ctx, target, options, path, existing.Version); restoreErr != nil {
				return false, errors.Join(rollbackErr, errors.New("native plugin rollback failed"))
			}
			return false, rollbackErr
		}
		if installFaults.afterBackup != nil {
			if err := installFaults.afterBackup(); err != nil {
				rollbackErr := rollbackUninstall(parentFD, err)
				if restoreErr := nativeRestore(ctx, target, options, path, existing.Version); restoreErr != nil {
					return false, errors.Join(rollbackErr, errors.New("native plugin rollback failed"))
				}
				return false, rollbackErr
			}
		}
		if installFaults.beforeDelete != nil {
			if err := installFaults.beforeDelete(); err != nil {
				rollbackErr := rollbackUninstall(parentFD, err)
				if restoreErr := nativeRestore(ctx, target, options, path, existing.Version); restoreErr != nil {
					return false, errors.Join(rollbackErr, errors.New("native plugin rollback failed"))
				}
				return false, rollbackErr
			}
		}
		if err := removeTreeAt(parentFD, backupName); err != nil {
			return false, rollbackUninstall(parentFD, err)
		}
		if err := removeJournal(parentFD); err != nil {
			return false, err
		}
		return true, nil
	})
	return Result{Changed: changed, Path: path}, err
}

func validateOptions(target Target, options Options, installing bool) error {
	if target != ClaudeCode && target != Codex {
		return errors.New("unsupported plugin target")
	}
	if !safeAbsolute(options.Home) {
		return errors.New("invalid home path")
	}
	if !safeAbsolute(options.HostPath) {
		return errors.New("native host path must be absolute")
	}
	if installing {
		if !safeAbsolute(options.SourceDir) || !safeAbsolute(options.GuardPath) {
			return errors.New("plugin and guard paths must be absolute")
		}
		if !versionPattern.MatchString(options.Version) {
			return errors.New("invalid plugin version")
		}
	}
	if err := validateGuard(options.HostPath); err != nil {
		return errors.New("invalid native host binary")
	}
	return nil
}

func safeAbsolute(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path && path != string(filepath.Separator)
}

func hostDirectory(target Target) string {
	if target == ClaudeCode {
		return ".claude"
	}
	return ".codex"
}

func marketplaceInstallPath(home string, target Target) string {
	return filepath.Join(home, ".palonexus", "marketplaces", string(target), "palonexus-sdk")
}

func openPluginParent(home string, target Target) (int, string, error) {
	homeFD, err := openAbsoluteDirectory(home)
	if err != nil {
		return -1, "", errors.New("unsafe home directory")
	}
	defer unix.Close(homeFD)
	appFD, err := ensurePrivateDirectoryAt(homeFD, ".palonexus")
	if err != nil {
		return -1, "", err
	}
	defer unix.Close(appFD)
	marketplacesFD, err := ensurePrivateDirectoryAt(appFD, "marketplaces")
	if err != nil {
		return -1, "", err
	}
	defer unix.Close(marketplacesFD)
	parentFD, err := ensurePrivateDirectoryAt(marketplacesFD, string(target))
	if err != nil {
		return -1, "", err
	}
	return parentFD, marketplaceName, nil
}

func ensureNativeHome(home string, target Target) error {
	homeFD, err := openAbsoluteDirectory(home)
	if err != nil {
		return errors.New("unsafe home directory")
	}
	defer unix.Close(homeFD)
	hostFD, err := ensureDirectoryAt(homeFD, hostDirectory(target))
	if err != nil {
		return err
	}
	return unix.Close(hostFD)
}

func openAbsoluteDirectory(path string) (int, error) {
	if !safeAbsolute(path) {
		return -1, errors.New("unsafe path")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, errors.New("open directory")
	}
	if err := validateDirectoryFD(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openAbsoluteSourceDirectory(path string) (int, error) {
	if !safeAbsolute(path) {
		return -1, errors.New("unsafe path")
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, errors.New("open directory")
	}
	if err := validateSourceDirectoryFD(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func ensureDirectoryAt(parentFD int, name string) (int, error) {
	fd, err := openDirectoryAt(parentFD, name)
	if errors.Is(err, unix.ENOENT) {
		if err := unix.Mkdirat(parentFD, name, 0o700); err != nil && !errors.Is(err, unix.EEXIST) {
			return -1, errors.New("create plugin directory")
		}
		if err := unix.Fsync(parentFD); err != nil {
			return -1, errors.New("sync plugin directory")
		}
		fd, err = openDirectoryAt(parentFD, name)
	}
	if err != nil {
		return -1, errors.New("open plugin directory")
	}
	return fd, nil
}

func ensurePrivateDirectoryAt(parentFD int, name string) (int, error) {
	fd, err := ensureDirectoryAt(parentFD, name)
	if err != nil {
		return -1, err
	}
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&0o077 != 0 {
		unix.Close(fd)
		return -1, errors.New("installer-owned directory is not private")
	}
	return fd, nil
}

func openDirectoryAt(parentFD int, name string) (int, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if err := validateDirectoryFD(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func openSourceDirectoryAt(parentFD int, name string) (int, error) {
	fd, err := unix.Openat(parentFD, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if err := validateSourceDirectoryFD(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func validateDirectoryFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		int(stat.Uid) != os.Geteuid() || stat.Mode&0o022 != 0 || stat.Nlink < 1 {
		return errors.New("unsafe directory")
	}
	return nil
}

func validateSourceDirectoryFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		(int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid()) || stat.Mode&0o022 != 0 || stat.Nlink < 1 {
		return errors.New("unsafe directory")
	}
	return nil
}

func validateRegularFD(fd int, executable bool) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		int(stat.Uid) != os.Geteuid() || stat.Mode&0o022 != 0 || stat.Nlink != 1 {
		return stat, errors.New("unsafe file")
	}
	if executable && stat.Mode&0o100 == 0 {
		return stat, errors.New("guard is not executable")
	}
	if stat.Size < 0 || stat.Size > maxIndividualFile {
		return stat, errors.New("file is too large")
	}
	return stat, nil
}

func validateSourceRegularFD(fd int, executable bool) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		(int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid()) || stat.Mode&0o022 != 0 || stat.Nlink != 1 {
		return stat, errors.New("unsafe file")
	}
	if executable && stat.Mode&0o111 == 0 {
		return stat, errors.New("file is not executable")
	}
	if stat.Size < 0 || stat.Size > maxIndividualFile {
		return stat, errors.New("file is too large")
	}
	return stat, nil
}

func validateGuard(path string) error {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("invalid guard binary")
	}
	defer unix.Close(fd)
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		(int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid()) || stat.Mode&0o022 != 0 ||
		stat.Nlink != 1 || stat.Mode&0o111 == 0 || stat.Size <= 0 || stat.Size > 512<<20 {
		return errors.New("invalid guard binary")
	}
	return nil
}

func requireManifest(sourceFD int, target Target, version string) error {
	pluginRoot, err := openSourceDirectoryAt(sourceFD, "plugins")
	if err != nil {
		return errors.New("plugin directory missing")
	}
	defer unix.Close(pluginRoot)
	palonexusRoot, err := openSourceDirectoryAt(pluginRoot, installName)
	if err != nil {
		return errors.New("PaloNexus plugin missing")
	}
	defer unix.Close(palonexusRoot)
	directory := ".claude-plugin"
	if target == Codex {
		directory = ".codex-plugin"
	}
	fd, err := openSourceDirectoryAt(palonexusRoot, directory)
	if err != nil {
		return errors.New("plugin manifest directory missing")
	}
	defer unix.Close(fd)
	fileFD, err := unix.Openat(fd, "plugin.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return errors.New("plugin manifest missing")
	}
	defer unix.Close(fileFD)
	if _, err := validateSourceRegularFD(fileFD, false); err != nil {
		return errors.New("plugin manifest unsafe")
	}
	pluginData, err := readBoundedFD(fileFD, 64*1024)
	if err != nil {
		return errors.New("plugin manifest unreadable")
	}
	var pluginManifest struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		Description string `json:"description"`
		License     string `json:"license"`
		Hooks       string `json:"hooks"`
		Skills      string `json:"skills"`
		Author      struct {
			Name string `json:"name"`
		} `json:"author"`
	}
	if decodeStrictDocument(pluginData, &pluginManifest) != nil ||
		pluginManifest.Name != installName || pluginManifest.Version != version ||
		pluginManifest.Description == "" || len(pluginManifest.Description) > 512 ||
		pluginManifest.License != "MIT" ||
		pluginManifest.Author.Name != "PaloNexus" || pluginManifest.Skills != "./skills/" ||
		(target == ClaudeCode && pluginManifest.Hooks != "") ||
		(target == Codex && pluginManifest.Hooks != "./hooks/hooks.json") {
		return errors.New("invalid plugin manifest")
	}
	if pluginManifest.Hooks != "" {
		if err := requireRelativeFile(palonexusRoot, pluginManifest.Hooks); err != nil {
			return errors.New("invalid plugin hook path")
		}
	}
	if err := requireRelativeDirectory(palonexusRoot, pluginManifest.Skills); err != nil {
		return errors.New("invalid plugin skill path")
	}
	hooksFD, err := openSourceDirectoryAt(palonexusRoot, "hooks")
	if err != nil {
		return errors.New("plugin hooks directory missing")
	}
	defer unix.Close(hooksFD)
	hooksManifestFD, err := unix.Openat(
		hooksFD, "hooks.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return errors.New("plugin hooks manifest missing")
	}
	hooksData, hooksErr := readBoundedFD(hooksManifestFD, 64*1024)
	unix.Close(hooksManifestFD)
	if hooksErr != nil || validateHookManifest(hooksData, target, "__PALONEXUS_GUARD__") != nil {
		return errors.New("invalid plugin hooks manifest")
	}
	protocolFD, err := unix.Openat(
		palonexusRoot, "palonexus.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return errors.New("plugin protocol manifest missing")
	}
	protocolData, protocolErr := readBoundedFD(protocolFD, 4096)
	unix.Close(protocolFD)
	var protocolManifest struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	if protocolErr != nil || decodeStrictDocument(protocolData, &protocolManifest) != nil ||
		protocolManifest.ProtocolVersion != "1.0" {
		return errors.New("invalid plugin protocol manifest")
	}
	marketplaceRoot := sourceFD
	var closeMarketplace func()
	if target == Codex {
		agents, err := openSourceDirectoryAt(sourceFD, ".agents")
		if err != nil {
			return errors.New("Codex marketplace missing")
		}
		plugins, err := openSourceDirectoryAt(agents, "plugins")
		unix.Close(agents)
		if err != nil {
			return errors.New("Codex marketplace missing")
		}
		marketplaceRoot = plugins
		closeMarketplace = func() { unix.Close(plugins) }
	} else {
		claude, err := openSourceDirectoryAt(sourceFD, ".claude-plugin")
		if err != nil {
			return errors.New("Claude marketplace missing")
		}
		marketplaceRoot = claude
		closeMarketplace = func() { unix.Close(claude) }
	}
	defer closeMarketplace()
	marketplaceFD, err := unix.Openat(
		marketplaceRoot, "marketplace.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return errors.New("marketplace manifest missing")
	}
	defer unix.Close(marketplaceFD)
	if _, err := validateSourceRegularFD(marketplaceFD, false); err != nil {
		return errors.New("marketplace manifest unsafe")
	}
	marketplaceData, err := readBoundedFD(marketplaceFD, 64*1024)
	if err != nil {
		return errors.New("marketplace manifest unreadable")
	}
	if err := validateMarketplaceManifest(target, marketplaceData); err != nil {
		return err
	}
	return nil
}

func readBoundedFD(fd int, limit int64) ([]byte, error) {
	duplicate, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "bounded-plugin-file")
	defer file.Close()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("file exceeds limit")
	}
	return data, nil
}

func decodeStrictDocument(data []byte, destination any) error {
	if len(data) == 0 || rejectDuplicateJSONKeys(data) != nil {
		return errors.New("invalid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func validateMarketplaceManifest(target Target, data []byte) error {
	if target == ClaudeCode {
		var document struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			Owner       struct {
				Name string `json:"name"`
			} `json:"owner"`
			Plugins []struct {
				Name   string `json:"name"`
				Source string `json:"source"`
			} `json:"plugins"`
		}
		if decodeStrictDocument(data, &document) != nil || document.Name != "palonexus-sdk" ||
			document.Description != "PaloNexus governed actions" ||
			document.Owner.Name != "PaloNexus" || len(document.Plugins) != 1 ||
			document.Plugins[0].Name != installName ||
			document.Plugins[0].Source != "./plugins/palonexus" {
			return errors.New("invalid Claude marketplace manifest")
		}
		return nil
	}
	var document struct {
		Name    string `json:"name"`
		Plugins []struct {
			Name   string `json:"name"`
			Source struct {
				Source string `json:"source"`
				Path   string `json:"path"`
			} `json:"source"`
		} `json:"plugins"`
	}
	if decodeStrictDocument(data, &document) != nil || document.Name != "palonexus-sdk" ||
		len(document.Plugins) != 1 || document.Plugins[0].Name != installName ||
		document.Plugins[0].Source.Source != "local" ||
		document.Plugins[0].Source.Path != "./plugins/palonexus" {
		return errors.New("invalid Codex marketplace manifest")
	}
	return nil
}

func requireRelativeFile(rootFD int, path string) error {
	parts, err := safeRelativeParts(path)
	if err != nil || len(parts) == 0 {
		return errors.New("unsafe relative path")
	}
	parent := rootFD
	opened := make([]int, 0, len(parts))
	defer func() {
		for _, fd := range opened {
			unix.Close(fd)
		}
	}()
	for _, part := range parts[:len(parts)-1] {
		fd, err := openSourceDirectoryAt(parent, part)
		if err != nil {
			return err
		}
		opened = append(opened, fd)
		parent = fd
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = validateSourceRegularFD(fd, false)
	return err
}

func requireRelativeDirectory(rootFD int, path string) error {
	parts, err := safeRelativeParts(path)
	if err != nil || len(parts) == 0 {
		return errors.New("unsafe relative path")
	}
	parent := rootFD
	opened := make([]int, 0, len(parts))
	defer func() {
		for _, fd := range opened {
			unix.Close(fd)
		}
	}()
	for _, part := range parts {
		fd, err := openSourceDirectoryAt(parent, part)
		if err != nil {
			return err
		}
		opened = append(opened, fd)
		parent = fd
	}
	return nil
}

func safeRelativeParts(path string) ([]string, error) {
	if path == "" || filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return nil, errors.New("unsafe relative path")
	}
	clean := filepath.Clean(strings.TrimPrefix(path, "./"))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return nil, errors.New("unsafe relative path")
	}
	parts := strings.Split(strings.TrimSuffix(clean, string(filepath.Separator)), string(filepath.Separator))
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("unsafe relative path")
		}
	}
	return parts, nil
}

func withTransactionLock(ctx context.Context, parentFD int, operation func() (bool, error)) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-processInstallGate:
	}
	defer func() { processInstallGate <- struct{}{} }()
	var parentStat unix.Stat_t
	if err := unix.Fstat(parentFD, &parentStat); err != nil {
		return false, fmt.Errorf("plugin parent descriptor: %w", err)
	}
	fd, err := unix.Openat(parentFD, lockName, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return false, errors.New("open plugin lock")
	}
	defer unix.Close(fd)
	if _, err := validateRegularFD(fd, false); err != nil {
		return false, errors.New("unsafe plugin lock")
	}
	for {
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			break
		} else if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return false, errors.New("lock plugin installation")
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		default:
			if _, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 10); err != nil && !errors.Is(err, unix.EINTR) {
				return false, errors.New("wait for plugin lock")
			}
		}
	}
	defer unix.Flock(fd, unix.LOCK_UN) //nolint:errcheck
	return operation()
}

func digestTree(rootFD int) (string, error) {
	return digestTreeContent(rootFD, false)
}

func digestTreeContent(rootFD int, installed bool) (string, error) {
	hash := sha256.New()
	count, total := 0, int64(0)
	var walk func(int, string) error
	walk = func(fd int, prefix string) error {
		names, err := directoryNames(fd)
		if err != nil {
			return err
		}
		for _, name := range names {
			if name == markerName {
				if installed {
					continue
				}
				return errors.New("artifact contains reserved marker")
			}
			var stat unix.Stat_t
			if err := unix.Fstatat(fd, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return err
			}
			relative := strings.TrimPrefix(prefix+"/"+name, "/")
			hash.Write([]byte(relative))
			hash.Write([]byte{0})
			if stat.Mode&0o100 != 0 {
				hash.Write([]byte{1})
			} else {
				hash.Write([]byte{0})
			}
			switch stat.Mode & unix.S_IFMT {
			case unix.S_IFDIR:
				var child int
				var err error
				if installed {
					child, err = openDirectoryAt(fd, name)
				} else {
					child, err = openSourceDirectoryAt(fd, name)
				}
				if err != nil {
					return err
				}
				var openedDirectory unix.Stat_t
				if err := unix.Fstat(child, &openedDirectory); err != nil ||
					openedDirectory.Dev != stat.Dev || openedDirectory.Ino != stat.Ino {
					unix.Close(child)
					return errors.New("artifact directory changed during validation")
				}
				err = walk(child, relative)
				unix.Close(child)
				if err != nil {
					return err
				}
			case unix.S_IFREG:
				fileFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
				if err != nil {
					return err
				}
				var opened unix.Stat_t
				if installed {
					opened, err = validateRegularFD(fileFD, false)
				} else {
					opened, err = validateSourceRegularFD(fileFD, false)
				}
				if err == nil && (opened.Dev != stat.Dev || opened.Ino != stat.Ino) {
					err = errors.New("artifact changed during validation")
				}
				if err == nil {
					count++
					total += opened.Size
					if count > maxArtifactFiles || total > maxArtifactBytes {
						err = errors.New("artifact bounds exceeded")
					}
				}
				if err == nil {
					file := os.NewFile(uintptr(fileFD), name)
					var copied int64
					copied, err = io.Copy(hash, io.LimitReader(file, maxIndividualFile+1))
					if err == nil && copied != opened.Size {
						err = errors.New("artifact changed during validation")
					}
					closeErr := file.Close()
					fileFD = -1
					if err == nil {
						err = closeErr
					}
				}
				if fileFD >= 0 {
					unix.Close(fileFD)
				}
				if err != nil {
					return err
				}
			default:
				return errors.New("unsupported artifact entry")
			}
		}
		return nil
	}
	if err := walk(rootFD, ""); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func copyTree(sourceFD, destinationFD int) error {
	names, err := directoryNames(sourceFD)
	if err != nil {
		return err
	}
	for _, name := range names {
		var stat unix.Stat_t
		if err := unix.Fstatat(sourceFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			return err
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if err := unix.Mkdirat(destinationFD, name, 0o700); err != nil {
				return err
			}
			sourceChild, err := openSourceDirectoryAt(sourceFD, name)
			if err != nil {
				return err
			}
			var openedDirectory unix.Stat_t
			if err := unix.Fstat(sourceChild, &openedDirectory); err != nil ||
				openedDirectory.Dev != stat.Dev || openedDirectory.Ino != stat.Ino {
				unix.Close(sourceChild)
				return errors.New("artifact directory changed during copy")
			}
			destinationChild, err := openDirectoryAt(destinationFD, name)
			if err == nil {
				err = copyTree(sourceChild, destinationChild)
			}
			unix.Close(sourceChild)
			if destinationChild >= 0 {
				if syncErr := unix.Fsync(destinationChild); err == nil {
					err = syncErr
				}
				unix.Close(destinationChild)
			}
			if err != nil {
				return err
			}
		case unix.S_IFREG:
			sourceFile, err := unix.Openat(sourceFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				return err
			}
			opened, err := validateSourceRegularFD(sourceFile, false)
			if err == nil && (opened.Dev != stat.Dev || opened.Ino != stat.Ino) {
				err = errors.New("artifact changed during copy")
			}
			mode := uint32(0o600)
			if stat.Mode&0o100 != 0 {
				mode = 0o700
			}
			destinationFile := -1
			if err == nil {
				destinationFile, err = unix.Openat(destinationFD, name,
					unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
			}
			if err == nil {
				destinationHandle := os.NewFile(uintptr(destinationFile), name)
				sourceHandle := os.NewFile(uintptr(sourceFile), name)
				var copied int64
				copied, err = io.Copy(destinationHandle, io.LimitReader(sourceHandle, maxIndividualFile+1))
				if err == nil && copied != opened.Size {
					err = errors.New("artifact changed during copy")
				}
				if closeErr := sourceHandle.Close(); err == nil {
					err = closeErr
				}
				sourceFile = -1
				if err == nil {
					err = destinationHandle.Sync()
				}
				if closeErr := destinationHandle.Close(); err == nil {
					err = closeErr
				}
				destinationFile = -1
			}
			if destinationFile >= 0 {
				unix.Close(destinationFile)
			}
			unix.Close(sourceFile)
			if err != nil {
				return err
			}
		default:
			return errors.New("unsupported artifact entry")
		}
	}
	return nil
}

func directoryNames(fd int) ([]string, error) {
	duplicate, err := unix.Openat(fd, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "plugin-directory")
	defer file.Close()
	entries, err := file.ReadDir(maxArtifactFiles + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	if len(entries) > maxArtifactFiles {
		return nil, errors.New("too many artifact entries")
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if name == "" || name == "." || name == ".." || strings.ContainsRune(name, filepath.Separator) {
			return nil, errors.New("unsafe artifact name")
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names, nil
}

func writeFileAt(parentFD int, name string, data []byte, mode uint32) error {
	fd, err := unix.Openat(parentFD, name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, mode)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

type hookDocument struct {
	Hooks map[string][]hookMatcher `json:"hooks"`
}

type hookMatcher struct {
	Matcher string        `json:"matcher"`
	Hooks   []hookCommand `json:"hooks"`
}

type hookCommand struct {
	Type    string   `json:"type"`
	Command string   `json:"command"`
	Args    []string `json:"args,omitempty"`
	Timeout int      `json:"timeout"`
}

func validateHookManifest(data []byte, target Target, guardPath string) error {
	var document hookDocument
	if decodeStrictDocument(data, &document) != nil || len(document.Hooks) != 1 {
		return errors.New("invalid hook document")
	}
	matchers, ok := document.Hooks["PreToolUse"]
	if !ok || len(matchers) != 1 || len(matchers[0].Hooks) != 1 {
		return errors.New("invalid hook event")
	}
	matcher, command := matchers[0], matchers[0].Hooks[0]
	if command.Type != "command" || command.Timeout != 30 {
		return errors.New("invalid hook command")
	}
	if target == ClaudeCode {
		if matcher.Matcher != "*" || command.Command != guardPath ||
			len(command.Args) != 2 || command.Args[0] != "guard" || command.Args[1] != "check" {
			return errors.New("invalid Claude hook")
		}
		return nil
	}
	if matcher.Matcher != ".*" || len(command.Args) != 0 ||
		command.Command != shellCommand(guardPath) {
		return errors.New("invalid Codex hook")
	}
	return nil
}

func shellCommand(guardPath string) string {
	return "'" + strings.ReplaceAll(guardPath, "'", "'\\''") + "' guard check"
}

func writeGuardConfigAt(marketplaceFD int, target Target, guardPath string) error {
	pluginsFD, err := openDirectoryAt(marketplaceFD, "plugins")
	if err != nil {
		return errors.New("open installed plugin directory")
	}
	defer unix.Close(pluginsFD)
	pluginFD, err := openDirectoryAt(pluginsFD, installName)
	if err != nil {
		return errors.New("open installed plugin")
	}
	defer unix.Close(pluginFD)
	hooksFD, err := openDirectoryAt(pluginFD, "hooks")
	if err != nil {
		return errors.New("open installed hooks")
	}
	defer unix.Close(hooksFD)
	existingFD, err := unix.Openat(
		hooksFD, "hooks.json", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
	)
	if err != nil {
		return errors.New("hook configuration placeholder missing")
	}
	if _, err := validateRegularFD(existingFD, false); err != nil {
		unix.Close(existingFD)
		return errors.New("unsafe hook configuration placeholder")
	}
	unix.Close(existingFD)
	if err := unix.Unlinkat(hooksFD, "hooks.json", 0); err != nil {
		return errors.New("replace hook configuration")
	}
	command := hookCommand{Type: "command", Command: guardPath, Args: []string{"guard", "check"}, Timeout: 30}
	matcher := "*"
	if target == Codex {
		command.Command = shellCommand(guardPath)
		command.Args = nil
		matcher = ".*"
	}
	document := hookDocument{Hooks: map[string][]hookMatcher{
		"PreToolUse": {{Matcher: matcher, Hooks: []hookCommand{command}}},
	}}
	if err := writeFileAt(hooksFD, "hooks.json", mustJSON(document), 0o600); err != nil {
		return errors.New("write hook configuration")
	}
	return unix.Fsync(hooksFD)
}

func readOwnedMarker(path string, target Target) (ownershipMarker, error) {
	parent, name := filepath.Split(filepath.Clean(path))
	fd, err := openAbsoluteDirectory(strings.TrimSuffix(parent, string(filepath.Separator)))
	if err != nil {
		return ownershipMarker{}, err
	}
	defer unix.Close(fd)
	return readOwnedMarkerAt(fd, name, target)
}

func readOwnedMarkerAt(parentFD int, directory string, target Target) (ownershipMarker, error) {
	fd, err := openDirectoryAt(parentFD, directory)
	if errors.Is(err, unix.ENOENT) {
		return ownershipMarker{}, os.ErrNotExist
	}
	if err != nil {
		return ownershipMarker{}, errors.New("unsafe existing plugin")
	}
	defer unix.Close(fd)
	markerFD, err := unix.Openat(fd, markerName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return ownershipMarker{}, errors.New("existing plugin is not owned by PaloNexus")
	}
	if err != nil {
		return ownershipMarker{}, errors.New("unsafe ownership marker")
	}
	stat, err := validateRegularFD(markerFD, false)
	if err != nil || stat.Size > 4096 {
		unix.Close(markerFD)
		return ownershipMarker{}, errors.New("unsafe ownership marker")
	}
	markerFile := os.NewFile(uintptr(markerFD), markerName)
	data, err := io.ReadAll(io.LimitReader(markerFile, 4097))
	closeErr := markerFile.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil || len(data) > 4096 || bytes.Contains(data, []byte(`"owner"`+`:`+`"`+`github.com/rogerchucker/palonexus-sdk`+`"`)) == false {
		return ownershipMarker{}, errors.New("invalid ownership marker")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return ownershipMarker{}, errors.New("invalid ownership marker")
	}
	var marker ownershipMarker
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil || marker.Schema != 1 ||
		marker.Owner != "github.com/rogerchucker/palonexus-sdk" || marker.Target != target ||
		!versionPattern.MatchString(marker.Version) || !safeAbsolute(marker.GuardPath) ||
		len(marker.SourceDigest) != sha256.Size*2 || len(marker.Digest) != sha256.Size*2 {
		return ownershipMarker{}, errors.New("invalid ownership marker")
	}
	if _, err := hex.DecodeString(marker.SourceDigest); err != nil {
		return ownershipMarker{}, errors.New("invalid ownership marker")
	}
	if _, err := hex.DecodeString(marker.Digest); err != nil {
		return ownershipMarker{}, errors.New("invalid ownership marker")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ownershipMarker{}, errors.New("invalid ownership marker")
	}
	actualDigest, err := digestTreeContent(fd, true)
	if err != nil || actualDigest != marker.Digest {
		return ownershipMarker{}, errors.New("installed plugin differs from owned artifact")
	}
	return marker, nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid object key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate object key")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	return walk()
}

func writeJournal(parentFD int, journal transactionJournal) error {
	_ = unix.Unlinkat(parentFD, journalTempName, 0)
	if err := writeFileAt(parentFD, journalTempName,
		mustJSON(journal), 0o600); err != nil {
		return errors.New("write plugin journal")
	}
	if err := unix.Renameat(parentFD, journalTempName, parentFD, journalName); err != nil {
		return errors.New("publish plugin journal")
	}
	if err := unix.Fsync(parentFD); err != nil {
		return errors.New("sync plugin journal")
	}
	return nil
}

func recoverTransaction(parentFD int, target Target) error {
	journalFD, err := unix.Openat(parentFD, journalName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return rejectUnjournaledArtifacts(parentFD)
	}
	if err != nil {
		return errors.New("unsafe plugin transaction journal")
	}
	stat, validationErr := validateRegularFD(journalFD, false)
	journalFile := os.NewFile(uintptr(journalFD), journalName)
	data, readErr := io.ReadAll(io.LimitReader(journalFile, 1025))
	closeErr := journalFile.Close()
	if readErr == nil {
		readErr = closeErr
	}
	if validationErr != nil || readErr != nil || stat.Size > 1024 {
		return errors.New("invalid plugin transaction journal")
	}
	var journal transactionJournal
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if rejectDuplicateJSONKeys(data) != nil || decoder.Decode(&journal) != nil || journal.Schema != 1 ||
		(journal.Operation != "install" && journal.Operation != "uninstall") ||
		(journal.Phase != "local-prepared" && journal.Phase != "native-pending" &&
			journal.Phase != "native-complete") {
		return errors.New("invalid plugin transaction journal")
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("invalid plugin transaction journal")
	}
	_, destinationErr := readOwnedMarkerAt(parentFD, marketplaceName, target)
	_, backupErr := readOwnedMarkerAt(parentFD, backupName, target)
	if destinationErr != nil && !errors.Is(destinationErr, os.ErrNotExist) {
		return destinationErr
	}
	if backupErr != nil && !errors.Is(backupErr, os.ErrNotExist) {
		return backupErr
	}
	if journal.Operation == "install" {
		if errors.Is(destinationErr, os.ErrNotExist) && backupErr == nil {
			if err := unix.Renameat(parentFD, backupName, parentFD, marketplaceName); err != nil {
				return errors.New("recover plugin upgrade")
			}
		} else if destinationErr == nil && backupErr == nil {
			if err := removeTreeAt(parentFD, backupName); err != nil {
				return errors.New("complete plugin upgrade recovery")
			}
		}
		if err := removeIfOwnedStale(parentFD, stageName, target); err != nil {
			return err
		}
	} else {
		if destinationErr == nil && errors.Is(backupErr, os.ErrNotExist) {
			// The journal was durable but the first rename was not: roll back
			// the transaction by retaining the verified owned destination.
		} else if errors.Is(destinationErr, os.ErrNotExist) && backupErr == nil {
			if err := removeTreeAt(parentFD, backupName); err != nil {
				return errors.New("complete plugin uninstall recovery")
			}
		} else if destinationErr == nil && backupErr == nil {
			return errors.New("ambiguous uninstall transaction")
		}
	}
	return removeJournal(parentFD)
}

func rejectUnjournaledArtifacts(parentFD int) error {
	for _, name := range []string{stageName, backupName, journalTempName} {
		var stat unix.Stat_t
		err := unix.Fstatat(parentFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
		if err == nil {
			return errors.New("unproven plugin transaction artifact")
		}
		if !errors.Is(err, unix.ENOENT) {
			return errors.New("inspect plugin transaction artifacts")
		}
	}
	return nil
}

func removeIfOwnedStale(parentFD int, name string, target Target) error {
	if _, err := readOwnedMarkerAt(parentFD, name, target); err == nil {
		return removeTreeAt(parentFD, name)
	} else if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return errors.New("unproven plugin transaction artifact")
}

func rollbackStage(parentFD int, cause error) error {
	if err := removeTreeAt(parentFD, stageName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, errors.New("plugin rollback failed"))
	}
	return cause
}

func rollbackBeforeBackup(parentFD int, cause error) error {
	if err := removeTreeAt(parentFD, stageName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, errors.New("plugin rollback failed"))
	}
	if err := removeJournal(parentFD); err != nil {
		return errors.Join(cause, errors.New("plugin rollback failed"))
	}
	return cause
}

func rollbackInstall(parentFD int, hadBackup bool, cause error) error {
	if err := removeTreeAt(parentFD, marketplaceName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, errors.New("plugin rollback failed"))
	}
	if hadBackup {
		if err := unix.Renameat(parentFD, backupName, parentFD, marketplaceName); err != nil {
			return errors.Join(cause, errors.New("plugin rollback failed"))
		}
	}
	if err := removeTreeAt(parentFD, stageName); err != nil && !errors.Is(err, os.ErrNotExist) {
		return errors.Join(cause, errors.New("plugin rollback failed"))
	}
	if err := removeJournal(parentFD); err != nil {
		return errors.Join(cause, errors.New("plugin rollback failed"))
	}
	return cause
}

func rollbackUninstall(parentFD int, cause error) error {
	if err := unix.Renameat(parentFD, backupName, parentFD, marketplaceName); err != nil {
		return errors.Join(cause, errors.New("plugin rollback failed"))
	}
	if err := removeJournal(parentFD); err != nil {
		return errors.Join(cause, errors.New("plugin rollback failed"))
	}
	return cause
}

func removeJournal(parentFD int) error {
	if err := unix.Unlinkat(parentFD, journalName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return errors.New("remove plugin journal")
	}
	if err := unix.Fsync(parentFD); err != nil {
		return errors.New("sync plugin directory")
	}
	return nil
}

func removeTreeAt(parentFD int, name string) error {
	fd, err := openDirectoryAt(parentFD, name)
	if errors.Is(err, unix.ENOENT) {
		return os.ErrNotExist
	}
	if err != nil {
		return errors.New("unsafe plugin tree")
	}
	names, err := directoryNames(fd)
	if err != nil {
		unix.Close(fd)
		return err
	}
	for _, child := range names {
		var stat unix.Stat_t
		if err := unix.Fstatat(fd, child, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			unix.Close(fd)
			return err
		}
		switch stat.Mode & unix.S_IFMT {
		case unix.S_IFDIR:
			if err := removeTreeAt(fd, child); err != nil {
				unix.Close(fd)
				return err
			}
		case unix.S_IFREG:
			childFD, err := unix.Openat(fd, child, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			if err != nil {
				unix.Close(fd)
				return err
			}
			_, validationErr := validateRegularFD(childFD, false)
			unix.Close(childFD)
			if validationErr != nil {
				unix.Close(fd)
				return validationErr
			}
			if err := unix.Unlinkat(fd, child, 0); err != nil {
				unix.Close(fd)
				return err
			}
		default:
			unix.Close(fd)
			return errors.New("unsafe plugin tree entry")
		}
	}
	if err := unix.Fsync(fd); err != nil {
		unix.Close(fd)
		return err
	}
	unix.Close(fd)
	if err := unix.Unlinkat(parentFD, name, unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return unix.Fsync(parentFD)
}

func mustJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return append(data, '\n')
}
