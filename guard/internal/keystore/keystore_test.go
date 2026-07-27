package keystore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStoreBindsSecretsToTenantAndAccountAndCopiesMemory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	backend := NewMemoryBackendForTesting()
	store, err := New("dev.palonexus.guard", backend)
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("token-alpha")
	if err := store.Put(ctx, Key{Tenant: "tenant-a", Account: "user-a"}, secret); err != nil {
		t.Fatal(err)
	}
	secret[0] = 'X'

	got, err := store.Get(ctx, Key{Tenant: "tenant-a", Account: "user-a"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "token-alpha" {
		t.Fatalf("stored secret aliased caller memory")
	}
	got[0] = 'X'
	again, err := store.Get(ctx, Key{Tenant: "tenant-a", Account: "user-a"})
	if err != nil || string(again) != "token-alpha" {
		t.Fatalf("returned secret aliased backend memory: %q, %v", again, err)
	}
	if _, err := store.Get(ctx, Key{Tenant: "tenant-b", Account: "user-a"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant lookup = %v, want ErrNotFound", err)
	}
}

func TestStoreValidatesBindingsWithoutReflectingSensitiveInput(t *testing.T) {
	t.Parallel()
	const sensitive = "tenant/raw-secret"
	store, err := New("dev.palonexus.guard", NewMemoryBackendForTesting())
	if err != nil {
		t.Fatal(err)
	}
	err = store.Put(context.Background(), Key{Tenant: sensitive, Account: "user"}, []byte("token"))
	if !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("Put error = %v, want ErrInvalidKey", err)
	}
	if strings.Contains(err.Error(), sensitive) || strings.Contains(err.Error(), "token") {
		t.Fatalf("error reflected sensitive input: %v", err)
	}
}

func TestStoreZeroesBackendReadBufferAfterCopy(t *testing.T) {
	t.Parallel()
	raw := []byte("temporary-secret")
	backend := &observingBackend{getResult: raw}
	store, err := New("dev.palonexus.guard", backend)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), Key{Tenant: "tenant", Account: "account"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "temporary-secret" {
		t.Fatalf("Get = %q", got)
	}
	if !bytes.Equal(raw, make([]byte, len(raw))) {
		t.Fatal("backend-owned temporary buffer was not zeroed")
	}
}

func TestDeleteIsIdempotentAndRemovesOnlyBoundAccount(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store, err := New("dev.palonexus.guard", NewMemoryBackendForTesting())
	if err != nil {
		t.Fatal(err)
	}
	left := Key{Tenant: "tenant-a", Account: "user"}
	right := Key{Tenant: "tenant-b", Account: "user"}
	for _, key := range []Key{left, right} {
		if err := store.Put(ctx, key, []byte("secret")); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Delete(ctx, left); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, left); err != nil {
		t.Fatalf("second Delete = %v", err)
	}
	if _, err := store.Get(ctx, left); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted Get = %v", err)
	}
	if _, err := store.Get(ctx, right); err != nil {
		t.Fatalf("other tenant removed: %v", err)
	}
}

func TestUnavailableBackendFailsClosedWithoutFallback(t *testing.T) {
	t.Parallel()
	backendErr := errors.New("desktop secret service unavailable: raw-secret")
	store, err := New("dev.palonexus.guard", UnavailableBackend(backendErr))
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Tenant: "tenant", Account: "account"}
	if err := store.Put(context.Background(), key, []byte("raw-secret")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Put error = %v, want ErrUnavailable", err)
	} else if strings.Contains(err.Error(), "raw-secret") {
		t.Fatalf("backend detail leaked: %v", err)
	}
	if _, err := store.Get(context.Background(), key); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Get error = %v, want ErrUnavailable", err)
	}
}

func TestMemoryBackendSupportsConcurrentAccess(t *testing.T) {
	t.Parallel()
	store, err := New("dev.palonexus.guard", NewMemoryBackendForTesting())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			key := Key{Tenant: "tenant", Account: "account"}
			if err := store.Put(ctx, key, []byte("secret")); err != nil {
				t.Errorf("Put: %v", err)
				return
			}
			value, err := store.Get(ctx, key)
			if err != nil {
				t.Errorf("Get: %v", err)
			}
			Zero(value)
		}()
	}
	wg.Wait()
}

func TestCommittedMutationDoesNotReportLateCancellation(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	backend := &cancelAfterMutationBackend{cancel: cancel}
	store, err := New("dev.palonexus.guard", backend)
	if err != nil {
		t.Fatal(err)
	}
	key := Key{Tenant: "tenant", Account: "account"}
	if err := store.Put(ctx, key, []byte("secret")); err != nil {
		t.Fatalf("committed Put reported failure: %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	backend.cancel = cancel
	if err := store.Delete(ctx, key); err != nil {
		t.Fatalf("committed Delete reported failure: %v", err)
	}
}

func TestNativeBackendContractReportsSupportedPlatform(t *testing.T) {
	backend, err := NativeBackend()
	if err != nil {
		if !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrUnsupported) {
			t.Fatalf("NativeBackend error = %v", err)
		}
		return
	}
	if backend == nil {
		t.Fatal("NativeBackend returned nil without error")
	}
}

func TestEncryptedFileFallbackIsDisabledByDefault(t *testing.T) {
	t.Parallel()
	_, err := NewEncryptedFileBackend(EncryptedFileOptions{
		Root: t.TempDir(),
		Key:  bytes.Repeat([]byte{1}, 32),
	})
	if !errors.Is(err, ErrTestingOnly) {
		t.Fatalf("NewEncryptedFileBackend error = %v, want ErrTestingOnly", err)
	}
}

func TestEncryptedFileFallbackRequiresExplicitTestingFlagAndEncrypts(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "credentials")
	backend, err := NewEncryptedFileBackend(EncryptedFileOptions{
		Root:             root,
		Key:              bytes.Repeat([]byte{7}, 32),
		EnableForTesting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	store, err := New("dev.palonexus.guard", backend)
	if err != nil {
		t.Fatal(err)
	}
	const secret = "raw-file-fallback-secret"
	key := Key{Tenant: "tenant", Account: "account"}
	if err := store.Put(context.Background(), key, []byte(secret)); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("fallback did not persist an encrypted record")
	}
	for _, entry := range entries {
		data, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(secret)) {
			t.Fatal("fallback persisted plaintext secret")
		}
	}
	got, err := store.Get(context.Background(), key)
	if err != nil || string(got) != secret {
		t.Fatalf("Get = %q, %v", got, err)
	}
	Zero(got)
	if err := store.Delete(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get after Delete = %v", err)
	}
}

type observingBackend struct {
	getResult []byte
}

func (b *observingBackend) Put(context.Context, string, string, []byte) error { return nil }
func (b *observingBackend) Get(context.Context, string, string) ([]byte, error) {
	return b.getResult, nil
}
func (b *observingBackend) Delete(context.Context, string, string) error { return nil }

type cancelAfterMutationBackend struct {
	cancel context.CancelFunc
}

func (b *cancelAfterMutationBackend) Put(context.Context, string, string, []byte) error {
	b.cancel()
	return nil
}
func (b *cancelAfterMutationBackend) Get(context.Context, string, string) ([]byte, error) {
	return nil, ErrNotFound
}
func (b *cancelAfterMutationBackend) Delete(context.Context, string, string) error {
	b.cancel()
	return nil
}
