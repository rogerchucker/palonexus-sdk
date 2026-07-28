// SPDX-License-Identifier: MIT
//go:build linux

package daemon

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"syscall"
)

func runningExecutablePath() (string, error) {
	return os.Executable()
}

func inspectRunningExecutable(_ string) (executableIdentity, error) {
	file, err := os.Open("/proc/self/exe")
	if err != nil {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&0o022 != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 ||
		(int(stat.Uid) != os.Geteuid() && stat.Uid != 0) ||
		(stat.Nlink != 0 && stat.Nlink != 1) {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	return executableIdentity{
		Device: uint64(stat.Dev), Inode: uint64(stat.Ino),
		Mode: uint32(stat.Mode), UID: stat.Uid,
		Digest: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}
