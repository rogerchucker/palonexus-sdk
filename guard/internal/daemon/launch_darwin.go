// SPDX-License-Identifier: MIT
//go:build darwin

package daemon

import (
	"context"
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
	command := exec.CommandContext(
		context.WithoutCancel(ctx), stagePath, m.cfg.Arguments...,
	)
	command.Args[0] = m.cfg.Executable
	command.Stdin = nil
	command.Stdout = logFile
	command.Stderr = logFile
	command.Env = append([]string(nil), m.environment...)
	command.SysProcAttr = &unix.SysProcAttr{Setsid: true}
	return command, func() {
		_ = stage.Close()
		_ = source.Close()
	}, nil
}

func openOrCreateDarwinStage(
	path string,
	source *os.File,
	digest string,
) (*os.File, error) {
	stage, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o700)
	if err == nil {
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
			err = unix.Chflags(path, unix.UF_IMMUTABLE)
		}
		if err == nil {
			if directory, openErr := os.Open(filepath.Dir(path)); openErr == nil {
				err = directory.Sync()
				_ = directory.Close()
			} else {
				err = openErr
			}
		}
		if err != nil {
			_ = stage.Close()
			_ = os.Remove(path)
			return nil, ErrUnsafeExecutable
		}
	} else if os.IsExist(err) {
		stage, err = os.Open(path)
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
	info, statErr := file.Stat()
	if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o500 {
		return
	}
	opened, ok := info.Sys().(*syscall.Stat_t)
	if !ok || unix.Fchflags(int(file.Fd()), 0) != nil {
		return
	}
	current, err := os.Lstat(path)
	currentStat, currentOK := current.Sys().(*syscall.Stat_t)
	if err == nil && currentOK &&
		currentStat.Dev == opened.Dev && currentStat.Ino == opened.Ino {
		_ = os.Remove(path)
		if directory, openErr := os.Open(runtimeDir); openErr == nil {
			_ = directory.Sync()
			_ = directory.Close()
		}
	}
}
