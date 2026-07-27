//go:build !darwin && !linux

package state

import "errors"

// ErrUnsupported documents that secure local state is currently implemented
// only for macOS and Linux.
var ErrUnsupported = errors.New("secure state store unsupported on this operating system")
