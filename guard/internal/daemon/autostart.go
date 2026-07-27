// SPDX-License-Identifier: MIT
//go:build darwin || linux

package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"time"

	"golang.org/x/sys/unix"
)

func (m *Manager) Start(ctx context.Context) error {
	if m == nil || ctx == nil || m.cfg.Executable == "" {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	dir, err := openRuntime(m.cfg.RuntimeDir, false)
	if err != nil {
		return fmt.Errorf("daemon: open runtime: %w", err)
	}
	defer dir.Close()
	lock, err := acquireStartLock(ctx, dir)
	if err != nil {
		return fmt.Errorf("daemon: acquire start lock: %w", err)
	}
	defer releaseStartLock(lock)
	status, statusErr := m.Status(ctx)
	if statusErr == nil && status.Running {
		return nil
	}
	if statusErr != nil && !errors.Is(statusErr, ErrUnprovenProcess) {
		return fmt.Errorf("daemon: inspect status: %w", statusErr)
	}
	if existsAt(dir, socketName) && statusErr != nil {
		return ErrUnsafeRuntime
	}
	if current, readErr := readState(dir); readErr == nil {
		if !m.stateMatchesLaunch(current) {
			return ErrUnprovenProcess
		}
		if processExists(current.PID) {
			if !waitProcessExit(ctx, current.PID, min(m.cfg.StartupTimeout, 2*time.Second)) {
				return ErrUnprovenProcess
			}
		}
		if removeErr := removeStateIfOwned(dir, current); removeErr != nil {
			return removeErr
		}
	} else if !errors.Is(readErr, os.ErrNotExist) {
		return readErr
	}
	device, inode, err := validateLaunch(
		m.cfg.Executable, m.cfg.Arguments, m.cfg.ChildEnv,
	)
	if err != nil || device != m.launchDevice || inode != m.launchInode {
		return ErrUnsafeExecutable
	}
	logFile, err := openLog(dir)
	if err != nil {
		return err
	}
	command := exec.CommandContext(context.WithoutCancel(ctx), m.cfg.Executable, m.cfg.Arguments...)
	command.Stdin = nil
	command.Stdout = logFile
	command.Stderr = logFile
	command.Env = append(safeBaseEnvironment(), m.cfg.ChildEnv...)
	command.SysProcAttr = &unix.SysProcAttr{Setsid: true}
	if err := command.Start(); err != nil {
		_ = logFile.Close()
		return ErrUnavailable
	}
	_ = logFile.Close()
	waitDone := make(chan error, 1)
	go func() { waitDone <- command.Wait() }()
	deadline := time.NewTimer(m.cfg.StartupTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := m.Status(ctx)
		if err == nil && status.Running {
			return nil
		}
		select {
		case <-waitDone:
			return ErrUnavailable
		default:
		}
		select {
		case <-ctx.Done():
			stopStartedProcess(command.Process, waitDone, m.cfg.KillTimeout)
			return ctx.Err()
		case <-deadline.C:
			stopStartedProcess(command.Process, waitDone, m.cfg.KillTimeout)
			return ErrUnavailable
		case <-ticker.C:
		}
	}
}

func stopStartedProcess(process *os.Process, waitDone <-chan error, maximum time.Duration) {
	select {
	case <-waitDone:
		return
	default:
	}
	_ = process.Signal(os.Interrupt)
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	select {
	case <-waitDone:
		return
	case <-timer.C:
		_ = process.Kill()
	}
	select {
	case <-waitDone:
	case <-time.After(maximum):
	}
}

func waitProcessExit(ctx context.Context, pid int, maximum time.Duration) bool {
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for processExists(pid) {
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		case <-ticker.C:
		}
	}
	return true
}

func acquireStartLock(ctx context.Context, dir *os.File) (*os.File, error) {
	fd, err := openOrCreateRegularAt(dir, startLockName, unix.O_RDWR)
	if err != nil {
		return nil, fmt.Errorf("open lock (%v): %w", err, ErrUnsafeRuntime)
	}
	lock := os.NewFile(uintptr(fd), startLockName)
	if _, err := inspectRegularAt(dir, startLockName); err != nil {
		_ = lock.Close()
		return nil, fmt.Errorf("inspect lock: %w", err)
	}
	for {
		if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err == nil {
			return lock, nil
		} else if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			_ = lock.Close()
			return nil, fmt.Errorf("flock: %w", ErrUnsafeRuntime)
		}
		select {
		case <-ctx.Done():
			_ = lock.Close()
			return nil, ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func releaseStartLock(lock *os.File) {
	if lock == nil {
		return
	}
	_ = unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	_ = lock.Close()
}

func openLog(dir *os.File) (*os.File, error) {
	fd, err := openOrCreateRegularAt(dir, logName, unix.O_WRONLY|unix.O_APPEND)
	if err != nil {
		return nil, ErrUnsafeRuntime
	}
	file := os.NewFile(uintptr(fd), logName)
	if _, err := inspectRegularAt(dir, logName); err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}

func openOrCreateRegularAt(dir *os.File, name string, flags int) (int, error) {
	for range 4 {
		expected, inspectErr := inspectRegularAt(dir, name)
		if inspectErr == nil {
			fd, err := unix.Openat(
				int(dir.Fd()), name, flags|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0,
			)
			if err != nil {
				if errors.Is(err, unix.ENOENT) {
					continue
				}
				return -1, err
			}
			if !openedRegularMatches(fd, expected) {
				_ = unix.Close(fd)
				return -1, ErrUnsafeRuntime
			}
			return fd, nil
		}
		if !errors.Is(inspectErr, os.ErrNotExist) {
			return -1, inspectErr
		}
		fd, err := unix.Openat(
			int(dir.Fd()), name,
			flags|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			0o600,
		)
		if err == nil {
			created, inspectErr := inspectRegularAt(dir, name)
			if inspectErr != nil || !openedRegularMatches(fd, created) {
				_ = unix.Close(fd)
				return -1, ErrUnsafeRuntime
			}
			return fd, nil
		}
		if !errors.Is(err, unix.EEXIST) && !errors.Is(err, unix.ENOENT) {
			return -1, err
		}
	}
	return -1, unix.ENOENT
}

func openedRegularMatches(fd int, expected fileID) bool {
	var stat unix.Stat_t
	return unix.Fstat(fd, &stat) == nil &&
		stat.Mode&unix.S_IFMT == unix.S_IFREG &&
		stat.Mode&0o077 == 0 &&
		int(stat.Uid) == os.Geteuid() &&
		stat.Nlink == 1 &&
		uint64(stat.Dev) == expected.device &&
		uint64(stat.Ino) == expected.inode
}

func safeBaseEnvironment() []string {
	result := []string{}
	for _, name := range []string{"HOME", "TMPDIR", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS"} {
		if value, ok := os.LookupEnv(name); ok && value != "" {
			result = append(result, name+"="+value)
		}
	}
	return result
}
