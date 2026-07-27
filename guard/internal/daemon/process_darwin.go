// SPDX-License-Identifier: MIT
//go:build darwin

package daemon

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"
)

func processIdentity(pid int) (uint64, uint64, error) {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil || len(raw) < 6 {
		return 0, 0, ErrUnprovenProcess
	}
	argc := int(int32(binary.NativeEndian.Uint32(raw[:4])))
	if argc < 1 {
		return 0, 0, ErrUnprovenProcess
	}
	terminator := bytes.IndexByte(raw[4:], 0)
	if terminator < 1 {
		return 0, 0, ErrUnprovenProcess
	}
	path := string(raw[4 : 4+terminator])
	info, err := os.Stat(path)
	if err != nil {
		return 0, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, errors.New("daemon: unsupported process identity")
	}
	return uint64(stat.Dev), uint64(stat.Ino), nil
}

func processStartToken(pid int) (string, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || info == nil || info.Proc.P_pid != int32(pid) {
		return "", ErrUnprovenProcess
	}
	start := info.Proc.P_starttime
	if start.Sec <= 0 {
		return "", ErrUnprovenProcess
	}
	return strconv.FormatInt(start.Sec, 10) + ":" + strconv.FormatInt(int64(start.Usec), 10), nil
}

func processExists(pid int) bool {
	_, err := processStartToken(pid)
	return err == nil
}

func signalStableProcess(state lifecycleState, signal syscall.Signal) error {
	// Darwin exposes no stable process handle equivalent to Linux pidfd.
	// Numeric signaling can target a reused PID after any validation, so
	// escalation is deliberately unavailable.
	return ErrUnavailable
}
