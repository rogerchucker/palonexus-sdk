// SPDX-License-Identifier: MIT
//go:build linux

package daemon

import (
	"os"
	"strconv"
	"syscall"
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
