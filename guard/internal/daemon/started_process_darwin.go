// SPDX-License-Identifier: MIT
//go:build darwin

package daemon

import (
	"os"
	"syscall"
)

type startedProcessGuard struct {
	pid        int
	startToken string
}

func pinStartedProcess(process *os.Process) (*startedProcessGuard, error) {
	token, err := processStartToken(process.Pid)
	if err != nil {
		return nil, ErrUnprovenProcess
	}
	return &startedProcessGuard{pid: process.Pid, startToken: token}, nil
}

func (g *startedProcessGuard) signal(signal syscall.Signal) error {
	// A launch-time PID plus start token is still not a stable signaling
	// handle. Wait may prove exit, but an unresponsive live child is never
	// signaled numerically on Darwin.
	return ErrUnavailable
}

func (*startedProcessGuard) close() {}
