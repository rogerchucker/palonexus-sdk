package keystore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestLinuxBackendRefusesLockedAndPromptRequiredStores(t *testing.T) {
	t.Parallel()
	for _, facade := range []*fakeLinuxFacade{
		{locked: true},
		{putPrompt: true},
		{items: []linuxItem{"item"}, deletePrompt: true},
	} {
		backend := newLinuxBackend(facade)
		var err error
		if facade.deletePrompt {
			err = backend.Delete(context.Background(), "service", "account")
		} else {
			err = backend.Put(context.Background(), "service", "account", []byte("secret"))
		}
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("operation error = %v, want ErrUnavailable", err)
		}
	}
}

func TestLinuxBackendMapsMissingDuplicateAndOutage(t *testing.T) {
	t.Parallel()
	backend := newLinuxBackend(&fakeLinuxFacade{})
	if _, err := backend.Get(context.Background(), "service", "account"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing Get = %v", err)
	}
	backend = newLinuxBackend(&fakeLinuxFacade{putError: errors.New("duplicate raw-secret")})
	if err := backend.Put(context.Background(), "service", "account", []byte("secret")); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("duplicate Put = %v", err)
	}
	backend = newLinuxBackend(&fakeLinuxFacade{lockedError: errors.New("outage raw-secret")})
	if err := backend.Delete(context.Background(), "service", "account"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("outage Delete = %v", err)
	} else if strings.Contains(err.Error(), "raw-secret") {
		t.Fatalf("native detail leaked: %v", err)
	}
}

func TestLinuxBackendRejectsNilEmptyAndMalformedDecryptionResults(t *testing.T) {
	t.Parallel()
	for _, facade := range []*fakeLinuxFacade{
		{items: []linuxItem{"item"}, getValue: nil},
		{items: []linuxItem{"item"}, getValue: []byte{}},
		{items: []linuxItem{"item"}, getError: errLinuxMalformedSecret},
	} {
		backend := newLinuxBackend(facade)
		if _, err := backend.Get(context.Background(), "service", "account"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Get = %v, want ErrUnavailable", err)
		}
	}
}

func TestLinuxBackendPreservesCancellationAndDeadlineAfterLock(t *testing.T) {
	t.Parallel()
	for _, timeout := range []time.Duration{0, time.Millisecond} {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		facade := &fakeLinuxFacade{blockAfterLock: true}
		backend := newLinuxBackend(facade)
		_, err := backend.Get(ctx, "service", "account")
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Get = %v, want deadline", err)
		}
	}
}

func TestLinuxBackendCancellationWhileWaitingForOperationLock(t *testing.T) {
	t.Parallel()
	backend := newLinuxBackend(&fakeLinuxFacade{})
	<-backend.gate
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := backend.Get(ctx, "service", "account"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get waiting for lock = %v", err)
	}
	backend.gate <- struct{}{}
}

func TestLinuxDeleteMissingIsIdempotentAndMultipleMatchesFailClosed(t *testing.T) {
	t.Parallel()
	if err := newLinuxBackend(&fakeLinuxFacade{}).Delete(
		context.Background(), "service", "account",
	); err != nil {
		t.Fatalf("Delete missing = %v", err)
	}
	facade := &fakeLinuxFacade{items: []linuxItem{"one", "two"}}
	if err := newLinuxBackend(facade).Delete(
		context.Background(), "service", "account",
	); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Delete duplicate matches = %v", err)
	}
}

func TestLinuxFacadeReceivesInjectiveEncodedBindings(t *testing.T) {
	t.Parallel()
	facade := &fakeLinuxFacade{}
	store, err := New("dev.palonexus.guard", newLinuxBackend(facade))
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []Key{
		{Tenant: "a:b", Account: "c"},
		{Tenant: "a", Account: "b:c"},
		{Tenant: "租户", Account: strings.Repeat("a", MaxBindingBytes)},
	} {
		if err := store.Put(context.Background(), key, []byte("secret")); err != nil {
			t.Fatal(err)
		}
	}
	if len(facade.putAccounts) != 3 ||
		facade.putAccounts[0] == facade.putAccounts[1] ||
		facade.putAccounts[1] == facade.putAccounts[2] {
		t.Fatalf("Linux binding encoding = %#v", facade.putAccounts)
	}
}

type fakeLinuxFacade struct {
	locked         bool
	lockedError    error
	putPrompt      bool
	putError       error
	items          []linuxItem
	findError      error
	getValue       []byte
	getError       error
	deletePrompt   bool
	deleteError    error
	blockAfterLock bool
	putAccounts    []string
}

func (f *fakeLinuxFacade) Locked(context.Context) (bool, error) {
	return f.locked, f.lockedError
}
func (f *fakeLinuxFacade) Put(_ context.Context, _, account string, _ []byte) (bool, error) {
	f.putAccounts = append(f.putAccounts, account)
	return f.putPrompt, f.putError
}
func (f *fakeLinuxFacade) Find(ctx context.Context, _, _ string) ([]linuxItem, error) {
	if f.blockAfterLock {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return append([]linuxItem(nil), f.items...), f.findError
}
func (f *fakeLinuxFacade) Get(context.Context, linuxItem) ([]byte, error) {
	return append([]byte(nil), f.getValue...), f.getError
}
func (f *fakeLinuxFacade) Delete(context.Context, linuxItem) (bool, error) {
	return f.deletePrompt, f.deleteError
}
