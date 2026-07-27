// SPDX-License-Identifier: MIT
//go:build linux

package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"

	"golang.org/x/sys/unix"
)

func (m *Manager) launchCommand(
	ctx context.Context,
	logFile *os.File,
) (*exec.Cmd, func(), error) {
	executable, err := os.Open(m.cfg.Executable)
	if err != nil {
		return nil, nil, ErrUnsafeExecutable
	}
	identity, err := inspectExecutableFile(executable)
	if err != nil || identity != m.launch {
		_ = executable.Close()
		return nil, nil, ErrUnsafeExecutable
	}
	fd, err := unix.MemfdCreate("palonexus-guard", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if err != nil {
		_ = executable.Close()
		return nil, nil, ErrUnsafeExecutable
	}
	snapshot := os.NewFile(uintptr(fd), "sealed-palonexus-guard")
	closeAll := func() {
		_ = snapshot.Close()
		_ = executable.Close()
	}
	if _, err := executable.Seek(0, io.SeekStart); err != nil {
		closeAll()
		return nil, nil, ErrUnsafeExecutable
	}
	if _, err := io.Copy(snapshot, executable); err != nil ||
		unix.Fchmod(fd, 0o500) != nil {
		closeAll()
		return nil, nil, ErrUnsafeExecutable
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_ADD_SEALS,
		unix.F_SEAL_WRITE|unix.F_SEAL_GROW|unix.F_SEAL_SHRINK|unix.F_SEAL_SEAL); err != nil {
		closeAll()
		return nil, nil, ErrUnsafeExecutable
	}
	if _, err := snapshot.Seek(0, io.SeekStart); err != nil {
		closeAll()
		return nil, nil, ErrUnsafeExecutable
	}
	sealed, err := inspectSealedExecutable(snapshot)
	if err != nil || sealed.Digest != m.launch.Digest {
		closeAll()
		return nil, nil, ErrUnsafeExecutable
	}
	command := exec.CommandContext(context.WithoutCancel(ctx), "/proc/self/fd/3")
	command.Args = append([]string{m.cfg.Executable}, m.cfg.Arguments...)
	command.Stdin = nil
	command.Stdout = logFile
	command.Stderr = logFile
	command.Env = append([]string(nil), m.environment...)
	command.ExtraFiles = []*os.File{snapshot}
	command.SysProcAttr = &unix.SysProcAttr{Setsid: true}
	return command, closeAll, nil
}

func inspectSealedExecutable(file *os.File) (executableIdentity, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o500 {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	return executableIdentity{Digest: hex.EncodeToString(hasher.Sum(nil))}, nil
}
