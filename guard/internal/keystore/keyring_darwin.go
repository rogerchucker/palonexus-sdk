//go:build darwin && cgo

package keystore

/*
#cgo CFLAGS: -Wno-deprecated-declarations
#cgo LDFLAGS: -framework Security
#include <Security/SecKeychain.h>
*/
import "C"

import (
	"context"
	"errors"
	"sync"

	keychain "github.com/keybase/go-keychain"
)

var (
	errNativeNotFound  = errors.New("native keychain item not found")
	errNativeDuplicate = errors.New("native keychain item already exists")
)

type darwinAccessibility uint8

const darwinAccessibleWhenUnlockedThisDeviceOnly darwinAccessibility = 1

type darwinItem struct {
	Service       string
	Account       string
	Label         string
	Data          []byte
	Accessibility darwinAccessibility
}

type darwinFacade interface {
	Update(context.Context, darwinItem) error
	Add(context.Context, darwinItem) error
	Get(context.Context, darwinItem) ([]byte, error)
	Delete(context.Context, darwinItem) error
}

type darwinBackend struct {
	facade darwinFacade
	gate   chan struct{}
}

func newNativeBackend() (Backend, error) {
	return newDarwinBackend(nativeDarwinFacade{}), nil
}

func newDarwinBackend(facade darwinFacade) *darwinBackend {
	backend := &darwinBackend{facade: facade, gate: make(chan struct{}, 1)}
	backend.gate <- struct{}{}
	return backend
}

func (b *darwinBackend) Put(ctx context.Context, service, account string, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.lock(ctx); err != nil {
		return err
	}
	defer b.unlock()
	item := darwinItem{
		Service:       service,
		Account:       account,
		Label:         "PaloNexus Guard credential",
		Data:          secret,
		Accessibility: darwinAccessibleWhenUnlockedThisDeviceOnly,
	}
	err := b.facade.Update(ctx, item)
	if errors.Is(err, errNativeNotFound) {
		err = b.facade.Add(ctx, item)
		if errors.Is(err, errNativeDuplicate) {
			err = b.facade.Update(ctx, item)
		}
	}
	return mapDarwinError(err)
}

func (b *darwinBackend) Get(ctx context.Context, service, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := b.lock(ctx); err != nil {
		return nil, err
	}
	defer b.unlock()
	value, err := b.facade.Get(ctx, darwinItem{Service: service, Account: account})
	if err != nil {
		return nil, mapDarwinError(err)
	}
	if value == nil {
		return nil, ErrUnavailable
	}
	return value, nil
}

func (b *darwinBackend) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.lock(ctx); err != nil {
		return err
	}
	defer b.unlock()
	err := b.facade.Delete(ctx, darwinItem{Service: service, Account: account})
	if errors.Is(err, errNativeNotFound) {
		return nil
	}
	return mapDarwinError(err)
}

func (b *darwinBackend) lock(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.gate:
	}
	if err := ctx.Err(); err != nil {
		b.gate <- struct{}{}
		return err
	}
	return nil
}

func (b *darwinBackend) unlock() { b.gate <- struct{}{} }

func mapDarwinError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	case errors.Is(err, errNativeNotFound):
		return ErrNotFound
	default:
		return ErrUnavailable
	}
}

type nativeDarwinFacade struct{}

func (nativeDarwinFacade) Update(ctx context.Context, item darwinItem) error {
	return withInteractionDisabled(ctx, func() error {
		query := keychain.NewItem()
		query.SetSecClass(keychain.SecClassGenericPassword)
		query.SetService(item.Service)
		query.SetAccount(item.Account)
		update := keychain.NewItem()
		update.SetData(item.Data)
		update.SetSynchronizable(keychain.SynchronizableNo)
		update.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
		return nativeDarwinError(keychain.UpdateItem(query, update))
	})
}

func (nativeDarwinFacade) Add(ctx context.Context, item darwinItem) error {
	return withInteractionDisabled(ctx, func() error {
		native := keychain.NewGenericPassword(item.Service, item.Account, item.Label, item.Data, "")
		native.SetSynchronizable(keychain.SynchronizableNo)
		native.SetAccessible(keychain.AccessibleWhenUnlockedThisDeviceOnly)
		return nativeDarwinError(keychain.AddItem(native))
	})
}

func (nativeDarwinFacade) Get(ctx context.Context, item darwinItem) ([]byte, error) {
	var result []byte
	err := withInteractionDisabled(ctx, func() error {
		var err error
		result, err = keychain.GetGenericPassword(item.Service, item.Account, "", "")
		if err == nil && result == nil {
			return errNativeNotFound
		}
		return nativeDarwinError(err)
	})
	return result, err
}

func (nativeDarwinFacade) Delete(ctx context.Context, item darwinItem) error {
	return withInteractionDisabled(ctx, func() error {
		return nativeDarwinError(keychain.DeleteGenericPasswordItem(item.Service, item.Account))
	})
}

func nativeDarwinError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, keychain.ErrorItemNotFound):
		return errNativeNotFound
	case errors.Is(err, keychain.ErrorDuplicateItem):
		return errNativeDuplicate
	default:
		return ErrUnavailable
	}
}

var darwinInteractionMu sync.Mutex

func withInteractionDisabled(ctx context.Context, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	darwinInteractionMu.Lock()
	defer darwinInteractionMu.Unlock()
	var previous C.Boolean
	if status := C.SecKeychainGetUserInteractionAllowed(&previous); status != 0 {
		return ErrUnavailable
	}
	if status := C.SecKeychainSetUserInteractionAllowed(C.Boolean(0)); status != 0 {
		return ErrUnavailable
	}
	defer C.SecKeychainSetUserInteractionAllowed(previous)
	if err := ctx.Err(); err != nil {
		return err
	}
	err := operation()
	if err != nil {
		return err
	}
	return ctx.Err()
}
