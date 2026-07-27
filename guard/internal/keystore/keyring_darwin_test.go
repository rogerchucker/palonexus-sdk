//go:build darwin && cgo

package keystore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDarwinPutBuildsDeviceOnlyUnlockedItemAndHandlesMissing(t *testing.T) {
	t.Parallel()
	facade := &fakeDarwinFacade{updateErrors: []error{errNativeNotFound}}
	backend := newDarwinBackend(facade)
	if err := backend.Put(context.Background(), "service", "account", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if facade.added.Accessibility != darwinAccessibleWhenUnlockedThisDeviceOnly {
		t.Fatalf("accessibility = %v", facade.added.Accessibility)
	}
	if facade.added.Service != "service" || facade.added.Account != "account" {
		t.Fatalf("binding = %#v", facade.added)
	}
}

func TestDarwinPutRetriesUpdateAfterDuplicateAddRace(t *testing.T) {
	t.Parallel()
	facade := &fakeDarwinFacade{
		updateErrors: []error{errNativeNotFound, nil},
		addError:     errNativeDuplicate,
	}
	backend := newDarwinBackend(facade)
	if err := backend.Put(context.Background(), "service", "account", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if facade.updateCalls != 2 {
		t.Fatalf("Update calls = %d, want 2", facade.updateCalls)
	}
}

func TestDarwinUpdateCarriesDeviceOnlyAccessibility(t *testing.T) {
	t.Parallel()
	facade := &fakeDarwinFacade{}
	backend := newDarwinBackend(facade)
	if err := backend.Put(context.Background(), "service", "account", []byte("secret")); err != nil {
		t.Fatal(err)
	}
	if len(facade.updated) != 1 ||
		facade.updated[0].Accessibility != darwinAccessibleWhenUnlockedThisDeviceOnly {
		t.Fatalf("updated item = %#v", facade.updated)
	}
}

func TestDarwinNativeFailuresAreClosedAndNotReflected(t *testing.T) {
	t.Parallel()
	for _, nativeErr := range []error{
		errors.New("locked raw-secret"),
		errors.New("outage raw-secret"),
		errors.New("malformed raw-secret"),
	} {
		facade := &fakeDarwinFacade{getError: nativeErr}
		backend := newDarwinBackend(facade)
		if _, err := backend.Get(context.Background(), "service", "account"); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("Get error = %v", err)
		} else if contains(err.Error(), "raw-secret") {
			t.Fatalf("error reflected native detail: %v", err)
		}
	}
}

func TestDarwinFacadeHonorsCancellationAndDeadline(t *testing.T) {
	t.Parallel()
	for _, makeContext := range []func() (context.Context, context.CancelFunc){
		func() (context.Context, context.CancelFunc) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			return ctx, func() {}
		},
		func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), time.Nanosecond)
		},
	} {
		ctx, cancel := makeContext()
		defer cancel()
		backend := newDarwinBackend(&fakeDarwinFacade{})
		if _, err := backend.Get(ctx, "service", "account"); err == nil {
			t.Fatal("canceled native Get succeeded")
		}
	}
}

func TestDarwinBackendCancellationWhileWaitingForOperationLock(t *testing.T) {
	t.Parallel()
	backend := newDarwinBackend(&fakeDarwinFacade{})
	<-backend.gate
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := backend.Get(ctx, "service", "account"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Get waiting for lock = %v", err)
	}
	backend.gate <- struct{}{}
}

func TestDarwinInteractionCancellationWhileWaiting(t *testing.T) {
	<-darwinInteractionGate
	defer func() { darwinInteractionGate <- struct{}{} }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	called := false
	err := withInteractionDisabled(ctx, func() error {
		called = true
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("interaction wait = %v, called=%v", err, called)
	}
}

func TestDarwinGetZerosValueOnLateCancellation(t *testing.T) {
	value := []byte("secret")
	ctx, cancel := context.WithCancel(context.Background())
	backend := newDarwinBackend(lateCancelDarwinFacade{value: value, cancel: cancel})
	got, err := backend.Get(ctx, "service", "account")
	if !errors.Is(err, context.Canceled) || got != nil {
		t.Fatalf("late-canceled Get = %x, %v", got, err)
	}
	if !allZero(value) {
		t.Fatalf("late-canceled value not zeroed: %x", value)
	}
}

func TestDarwinSuccessfulMutationsWinOverLateCancellation(t *testing.T) {
	for _, operation := range []string{"put", "delete"} {
		ctx, cancel := context.WithCancel(context.Background())
		backend := newDarwinBackend(lateCancelDarwinFacade{cancel: cancel, cancelOperation: operation})
		var err error
		if operation == "put" {
			err = backend.Put(ctx, "service", "account", []byte("secret"))
		} else {
			err = backend.Delete(ctx, "service", "account")
		}
		if err != nil {
			t.Fatalf("%s reported failure after successful mutation: %v", operation, err)
		}
	}
}

func TestDarwinFacadeReceivesInjectiveEncodedBindings(t *testing.T) {
	t.Parallel()
	facade := &fakeDarwinFacade{}
	store, err := New("dev.palonexus.guard", newDarwinBackend(facade))
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
	if len(facade.updated) != 3 ||
		facade.updated[0].Account == facade.updated[1].Account ||
		facade.updated[1].Account == facade.updated[2].Account {
		t.Fatalf("Darwin binding encoding = %#v", facade.updated)
	}
}

type fakeDarwinFacade struct {
	updateErrors []error
	updateCalls  int
	addError     error
	getValue     []byte
	getError     error
	deleteError  error
	added        darwinItem
	updated      []darwinItem
}

type lateCancelDarwinFacade struct {
	value           []byte
	cancel          context.CancelFunc
	cancelOperation string
}

func (f lateCancelDarwinFacade) Update(context.Context, darwinItem) error {
	if f.cancelOperation == "put" {
		f.cancel()
	}
	return nil
}
func (f lateCancelDarwinFacade) Add(context.Context, darwinItem) error { return nil }
func (f lateCancelDarwinFacade) Get(context.Context, darwinItem) ([]byte, error) {
	f.cancel()
	return f.value, nil
}
func (f lateCancelDarwinFacade) Delete(context.Context, darwinItem) error {
	if f.cancelOperation == "delete" {
		f.cancel()
	}
	return nil
}

func allZero(value []byte) bool {
	for _, element := range value {
		if element != 0 {
			return false
		}
	}
	return true
}

func (f *fakeDarwinFacade) Update(_ context.Context, item darwinItem) error {
	f.updated = append(f.updated, item)
	index := f.updateCalls
	f.updateCalls++
	if index < len(f.updateErrors) {
		return f.updateErrors[index]
	}
	return nil
}
func (f *fakeDarwinFacade) Add(_ context.Context, item darwinItem) error {
	f.added = item
	return f.addError
}
func (f *fakeDarwinFacade) Get(context.Context, darwinItem) ([]byte, error) {
	return append([]byte(nil), f.getValue...), f.getError
}
func (f *fakeDarwinFacade) Delete(context.Context, darwinItem) error { return f.deleteError }

func contains(value, substring string) bool {
	for index := 0; index+len(substring) <= len(value); index++ {
		if value[index:index+len(substring)] == substring {
			return true
		}
	}
	return false
}
