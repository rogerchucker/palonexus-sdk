//go:build darwin

package reconcile

import (
	"errors"

	"golang.org/x/sys/unix"
)

func publishAtomic(dirFD int, temporary, target string, expected *diskEnvelope) error {
	if expected == nil {
		if err := unix.RenameatxNp(dirFD, temporary, dirFD, target, unix.RENAME_EXCL); err != nil {
			if errors.Is(err, unix.EEXIST) {
				return ErrConflict
			}
			return ErrUnsafePath
		}
		return nil
	}
	if err := unix.RenameatxNp(dirFD, temporary, dirFD, target, unix.RENAME_SWAP); err != nil {
		return ErrUnsafePath
	}
	if !matchExpectedAt(dirFD, temporary, expected) {
		_ = unix.RenameatxNp(dirFD, temporary, dirFD, target, unix.RENAME_SWAP)
		return ErrConflict
	}
	if unix.Unlinkat(dirFD, temporary, 0) != nil {
		return ErrUnsafePath
	}
	return nil
}

func quarantineAtomicNoReplace(dirFD int, source, target string) error {
	if err := unix.RenameatxNp(dirFD, source, dirFD, target, unix.RENAME_EXCL); err != nil {
		if errors.Is(err, unix.EEXIST) {
			return ErrConflict
		}
		return ErrUnsafePath
	}
	return nil
}
