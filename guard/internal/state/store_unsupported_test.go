//go:build !darwin && !linux

package state

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatformAPIIsStableAndFailsClosed(t *testing.T) {
	t.Parallel()
	store, err := New("ignored")
	if store != nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New = %#v, %v", store, err)
	}
	var typed *Store
	if err := typed.PutMetadata(nil, Binding{}, Metadata{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("nil Store PutMetadata = %v", err)
	}
}
