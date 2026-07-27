//go:build darwin || linux

package keystore

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedFileFallbackCancellationWhileWaitingForLock(t *testing.T) {
	t.Parallel()
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewEncryptedFileBackend(EncryptedFileOptions{
		Root:             filepath.Join(base, "credentials"),
		Key:              bytes.Repeat([]byte{4}, 32),
		EnableForTesting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	files := backend.(*encryptedFileBackend).files.(*unixEncryptedFiles)
	<-files.gate
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := backend.Get(ctx, "service", "account"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get waiting for lock = %v", err)
	}
	files.gate <- struct{}{}
}
