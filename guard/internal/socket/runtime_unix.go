// SPDX-License-Identifier: MIT
//go:build unix

package socket

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func prepareRuntimeDir(path string) (*os.File, os.FileInfo, error) {
	created := false
	if err := os.Mkdir(path, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return nil, nil, fmt.Errorf("socket: create runtime directory: %w", err)
	}
	// An extreme caller umask may create the directory without owner search
	// permission. Restrict the directory before opening it; the subsequent
	// O_NOFOLLOW open and inode checks detect pathname replacement.
	if created {
		if err := os.Chmod(path, 0o700); err != nil {
			return nil, nil, fmt.Errorf("socket: initialize runtime permissions: %w", err)
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socket: securely open runtime directory: %w", err)
	}
	dir := os.NewFile(uintptr(fd), path)
	info, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return nil, nil, fmt.Errorf("socket: inspect runtime directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		_ = dir.Close()
		return nil, nil, errors.New("socket: runtime directory must be user-only")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != currentUID() {
		_ = dir.Close()
		return nil, nil, errors.New("socket: runtime directory has wrong owner")
	}
	// Make creation-mode independent of the caller's umask.
	if err := dir.Chmod(0o700); err != nil {
		_ = dir.Close()
		return nil, nil, fmt.Errorf("socket: restrict runtime directory: %w", err)
	}
	info, err = dir.Stat()
	return dir, info, err
}

func verifyRuntimeDir(dir *os.File, path string, expected os.FileInfo) error {
	anchored, err := dir.Stat()
	if err != nil {
		return fmt.Errorf("socket: runtime directory descriptor: %w", err)
	}
	named, err := os.Lstat(path)
	if err != nil || named.Mode()&os.ModeSymlink != 0 || !named.IsDir() ||
		!os.SameFile(anchored, expected) || !os.SameFile(named, expected) {
		return errors.New("socket: runtime directory was replaced")
	}
	anchoredStat, anchoredOK := anchored.Sys().(*syscall.Stat_t)
	namedStat, namedOK := named.Sys().(*syscall.Stat_t)
	if !anchoredOK || !namedOK || anchoredStat.Uid != currentUID() ||
		namedStat.Uid != currentUID() || anchored.Mode().Perm() != 0o700 ||
		named.Mode().Perm() != 0o700 {
		return errors.New("socket: runtime directory security changed")
	}
	return nil
}

func currentUID() uint32 { return uint32(os.Getuid()) }

type fileIdentity struct {
	device uint64
	inode  uint64
}

func identityFromInfo(info os.FileInfo) (fileIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, errors.New("socket: unavailable inode identity")
	}
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func removeOwnedAt(dir *os.File, name string, expected fileIdentity) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("socket: cleanup nonce: %w", err)
	}
	quarantine := "." + name + ".cleanup-" + hex.EncodeToString(nonce[:])
	dirfd := int(dir.Fd())
	if err := renameNoReplace(dirfd, name, quarantine); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("socket: quarantine cleanup target: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(dirfd, quarantine, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = renameNoReplace(dirfd, quarantine, name)
		return fmt.Errorf("socket: inspect quarantined target: %w", err)
	}
	if uint64(stat.Dev) != expected.device || uint64(stat.Ino) != expected.inode ||
		stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		restoreErr := renameNoReplace(dirfd, quarantine, name)
		if restoreErr != nil {
			return fmt.Errorf("socket: path replaced; replacement preserved as %s", quarantine)
		}
		return errors.New("socket: path replaced; refusing cleanup")
	}
	if err := unix.Unlinkat(dirfd, quarantine, 0); err != nil {
		return fmt.Errorf("socket: cleanup: %w", err)
	}
	return nil
}
