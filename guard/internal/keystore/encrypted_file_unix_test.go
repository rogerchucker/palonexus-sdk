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

func TestEncryptedFileFallbackMaximumSecretAndMalformedDocuments(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewEncryptedFileBackend(EncryptedFileOptions{
		Root: filepath.Join(base, "credentials"), Key: bytes.Repeat([]byte{7}, 32), EnableForTesting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := New("guard.test", backend)
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Tenant: "tenant", Account: "account"}
	secret := bytes.Repeat([]byte{9}, MaxSecretBytes)
	if err := store.Put(context.Background(), key, secret); err != nil {
		t.Fatalf("maximum Put: %v", err)
	}
	got, err := store.Get(context.Background(), key)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("maximum round trip: len=%d err=%v", len(got), err)
	}
	Zero(got)
	if err := store.Put(context.Background(), key, append(secret, 1)); !errors.Is(err, ErrInvalidSecret) {
		t.Fatalf("oversized Put = %v", err)
	}
	encrypted := backend.(*encryptedFileBackend)
	name := encryptedName("guard.test", accountName(key))
	for _, document := range [][]byte{bytes.Repeat([]byte{1}, maxEncryptedDocumentBytes+1), {1, 2, 3}} {
		if err := encrypted.files.Put(context.Background(), name, document); err != nil {
			t.Fatal(err)
		}
		if value, err := store.Get(context.Background(), key); !errors.Is(err, ErrUnavailable) || value != nil {
			t.Fatalf("malformed Get = %x, %v", value, err)
		}
	}
}
