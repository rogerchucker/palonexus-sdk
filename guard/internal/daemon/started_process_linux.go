// SPDX-License-Identifier: MIT
//go:build linux

package daemon

import (
	"errors"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type startedProcessGuard struct{ pidfd int }

func pinStartedProcess(process *os.Process) (*startedProcessGuard, error) {
	fd, err := unix.PidfdOpen(process.Pid, 0)
	if err != nil {
		return nil, ErrUnprovenProcess
	}
	return &startedProcessGuard{pidfd: fd}, nil
}

func (g *startedProcessGuard) signal(signal syscall.Signal) error {
	if g == nil || g.pidfd < 0 {
		return ErrUnprovenProcess
	}
	if err := unix.PidfdSendSignal(g.pidfd, unix.Signal(signal), nil, 0); err != nil &&
		!errors.Is(err, unix.ESRCH) {
		return ErrUnavailable
	}
	return nil
}

func (g *startedProcessGuard) close() {
	if g != nil && g.pidfd >= 0 {
		_ = unix.Close(g.pidfd)
		g.pidfd = -1
	}
}
