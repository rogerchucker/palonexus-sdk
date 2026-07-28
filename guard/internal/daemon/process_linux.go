// SPDX-License-Identifier: MIT
//go:build linux

package daemon

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func processIdentity(pid int) (uint64, uint64, error) {
	info, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
	if err != nil {
		return 0, 0, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, ErrUnprovenProcess
	}
	return uint64(stat.Dev), uint64(stat.Ino), nil
}

func processExists(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

func signalStableProcess(state lifecycleState, signal syscall.Signal) error {
	pidfd, err := unix.PidfdOpen(state.PID, 0)
	if err != nil {
		return ErrUnprovenProcess
	}
	defer unix.Close(pidfd)
	if !stateMatchesProcess(state) {
		return ErrUnprovenProcess
	}
	if err := unix.PidfdSendSignal(pidfd, unix.Signal(signal), nil, 0); err != nil &&
		!errors.Is(err, unix.ESRCH) {
		return ErrUnavailable
	}
	return nil
}

func processStartToken(pid int) (string, error) {
	document, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return "", err
	}
	closeParen := bytes.LastIndexByte(document, ')')
	if closeParen < 0 || closeParen+2 >= len(document) {
		return "", ErrUnprovenProcess
	}
	fields := strings.Fields(string(document[closeParen+2:]))
	// Fields after comm begin with field 3 (state); starttime is field 22.
	if len(fields) < 20 || fields[19] == "" {
		return "", ErrUnprovenProcess
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", ErrUnprovenProcess
	}
	return fields[19], nil
}
