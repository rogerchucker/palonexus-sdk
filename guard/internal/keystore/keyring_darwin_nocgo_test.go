//go:build darwin && !cgo

package keystore

import (
	"errors"
	"testing"
)

func TestDarwinWithoutCGOFailsClosed(t *testing.T) {
	t.Parallel()
	backend, err := NativeBackend()
	if backend != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("NativeBackend = %#v, %v", backend, err)
	}
}
