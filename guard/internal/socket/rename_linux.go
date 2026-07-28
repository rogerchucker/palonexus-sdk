// SPDX-License-Identifier: MIT
//go:build linux

package socket

import "golang.org/x/sys/unix"

func renameNoReplace(dirfd int, from, to string) error {
	return unix.Renameat2(dirfd, from, dirfd, to, unix.RENAME_NOREPLACE)
}
