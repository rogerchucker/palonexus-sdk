// SPDX-License-Identifier: MIT
//go:build unix

package socket

import "golang.org/x/sys/unix"

func makeFIFO(path string) error { return unix.Mkfifo(path, 0o600) }
