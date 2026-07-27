// SPDX-License-Identifier: MIT
//go:build darwin

package daemon

import (
	"errors"
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
	if g == nil {
		return ErrUnprovenProcess
	}
	token, err := processStartToken(g.pid)
	if err != nil || token != g.startToken {
		return ErrUnprovenProcess
	}
	if err := syscall.Kill(g.pid, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
		return ErrUnavailable
	}
	return nil
}

func (*startedProcessGuard) close() {}
