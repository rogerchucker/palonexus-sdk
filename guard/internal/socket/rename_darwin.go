// SPDX-License-Identifier: MIT
//go:build darwin

package socket

import "golang.org/x/sys/unix"

func renameNoReplace(dirfd int, from, to string) error {
	return unix.RenameatxNp(dirfd, from, dirfd, to, unix.RENAME_EXCL)
}
