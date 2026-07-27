//go:build linux

package reconcile

import (
	"errors"

	"golang.org/x/sys/unix"
)

func publishAtomic(dirFD int, temporary, target string, expected *diskEnvelope) error {
	if expected == nil {
		if err := unix.Renameat2(dirFD, temporary, dirFD, target, unix.RENAME_NOREPLACE); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return ErrConflict
			}
			return ErrUnsafePath
		}
		return nil
	}
	if err := unix.Renameat2(dirFD, temporary, dirFD, target, unix.RENAME_EXCHANGE); err != nil {
		return ErrUnsafePath
	}
	if !matchExpectedAt(dirFD, temporary, expected) {
		_ = unix.Renameat2(dirFD, temporary, dirFD, target, unix.RENAME_EXCHANGE)
		return ErrConflict
	}
	if unix.Unlinkat(dirFD, temporary, 0) != nil {
		return ErrUnsafePath
	}
	return nil
}
