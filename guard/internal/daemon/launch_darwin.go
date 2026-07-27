// SPDX-License-Identifier: MIT
//go:build darwin

package daemon

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func (m *Manager) launchCommand(
	ctx context.Context,
	logFile *os.File,
) (*exec.Cmd, func(), error) {
	source, err := os.Open(m.cfg.Executable)
	if err != nil {
		return nil, nil, ErrUnsafeExecutable
	}
	opened, err := inspectExecutableFile(source)
	if err != nil || opened != m.launch {
		_ = source.Close()
		return nil, nil, ErrUnsafeExecutable
	}
	stagePath := filepath.Join(
		m.cfg.RuntimeDir, ".palonexus-exec-"+m.launch.Digest,
	)
	stage, err := openOrCreateDarwinStage(stagePath, source, m.launch.Digest)
	if err != nil {
		_ = source.Close()
		return nil, nil, err
	}
	// Reverify the exact staged descriptor immediately before posix_spawn.
	staged, err := inspectExecutableFile(stage)
	if err != nil || staged.Digest != m.launch.Digest ||
		staged.Mode&0o777 != 0o500 {
		_ = stage.Close()
		_ = source.Close()
		return nil, nil, ErrUnsafeExecutable
	}
	if m.cfg.afterLaunchVerified != nil {
		m.cfg.afterLaunchVerified(stagePath)
	}
	if _, err := unix.FcntlInt(stage.Fd(), unix.F_SETFD, 0); err != nil {
		_ = stage.Close()
		_ = source.Close()
		return nil, nil, ErrUnsafeExecutable
	}
	if !darwinDescriptorExecutionSupported() {
		removeExactDarwinStage(stage, stagePath)
		_ = stage.Close()
		_ = source.Close()
		return nil, nil, ErrUnsafeExecutable
	}
	command := exec.CommandContext(
		context.WithoutCancel(ctx), fmt.Sprintf("/dev/fd/%d", stage.Fd()), m.cfg.Arguments...,
	)
	command.Args[0] = m.cfg.Executable
	command.Stdin = nil
	command.Stdout = logFile
	command.Stderr = logFile
	command.Env = append([]string(nil), m.environment...)
	command.ExtraFiles = []*os.File{stage}
	command.SysProcAttr = &unix.SysProcAttr{Setsid: true}
	return command, func() {
		_ = stage.Close()
		_ = source.Close()
	}, nil
}

func darwinDescriptorExecutionSupported() bool {
	// Darwin's posix_spawn resolves the executable before applying inherited
	// descriptor file actions, and the system fdesc mount rejects execve of
	// /dev/fd entries. There is no fexecve-equivalent in the supported Go API.
	return false
}

func openOrCreateDarwinStage(
	path string,
	source *os.File,
	digest string,
) (*os.File, error) {
	directory, err := openRuntime(filepath.Dir(path), false)
	if err != nil {
		return nil, ErrUnsafeExecutable
	}
	defer directory.Close()
	name := filepath.Base(path)
	fd, err := unix.Openat(
		int(directory.Fd()), name,
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o700,
	)
	var stage *os.File
	if err == nil {
		stage = os.NewFile(uintptr(fd), filepath.Base(path))
		if _, err = source.Seek(0, io.SeekStart); err == nil {
			_, err = io.Copy(stage, source)
		}
		if err == nil {
			err = stage.Sync()
		}
		if err == nil {
			err = stage.Chmod(0o500)
		}
		if err == nil {
			err = stage.Sync()
		}
		if err == nil {
			err = unix.Fchflags(int(stage.Fd()), unix.UF_IMMUTABLE)
		}
		if err == nil {
			err = directory.Sync()
		}
		if err != nil {
			_ = stage.Close()
			return nil, ErrUnsafeExecutable
		}
		_ = stage.Close()
		fd, err = unix.Openat(
			int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
		)
		if err == nil {
			stage = os.NewFile(uintptr(fd), filepath.Base(path))
		}
	} else if err == unix.EEXIST {
		fd, err = unix.Openat(
			int(directory.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
		)
		if err == nil {
			stage = os.NewFile(uintptr(fd), filepath.Base(path))
		}
	}
	if err != nil {
		return nil, ErrUnsafeExecutable
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		_ = stage.Close()
		return nil, ErrUnsafeExecutable
	}
	identity, err := inspectExecutableFile(stage)
	var stat unix.Stat_t
	if err != nil || identity.Digest != digest || identity.Mode&0o777 != 0o500 ||
		unix.Fstat(int(stage.Fd()), &stat) != nil ||
		stat.Flags&unix.UF_IMMUTABLE == 0 {
		_ = stage.Close()
		return nil, ErrUnsafeExecutable
	}
	if _, err := stage.Seek(0, io.SeekStart); err != nil {
		_ = stage.Close()
		return nil, ErrUnsafeExecutable
	}
	return stage, nil
}

func cleanupRunningExecutable(runtimeDir string) {
	path, err := os.Executable()
	if err != nil || filepath.Dir(path) != runtimeDir ||
		!strings.HasPrefix(filepath.Base(path), ".palonexus-exec-") {
		return
	}
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()
	removeExactDarwinStage(file, path)
}

func removeExactDarwinStage(file *os.File, path string) {
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o500 {
		return
	}
	opened, ok := info.Sys().(*syscall.Stat_t)
	if !ok || unix.Fchflags(int(file.Fd()), 0) != nil {
		return
	}
	directory, err := openRuntime(filepath.Dir(path), false)
	if err != nil {
		return
	}
	defer directory.Close()
	var current unix.Stat_t
	if unix.Fstatat(
		int(directory.Fd()), filepath.Base(path), &current, unix.AT_SYMLINK_NOFOLLOW,
	) == nil && current.Dev == int32(opened.Dev) && current.Ino == opened.Ino {
		_ = unix.Unlinkat(int(directory.Fd()), filepath.Base(path), 0)
		_ = directory.Sync()
	}
}
