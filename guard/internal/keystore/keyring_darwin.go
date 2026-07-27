//go:build darwin

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

// darwinBackend uses Security.framework through go-keychain. No subprocess is
// created and credential bytes are never placed in argv or the environment.
type darwinBackend struct {
	mu sync.Mutex
}

var darwinInteractionMu sync.Mutex

func newNativeBackend() (Backend, error) {
	return &darwinBackend{}, nil
}

func (b *darwinBackend) Put(ctx context.Context, service, account string, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	restore, err := disableKeychainInteraction()
	if err != nil {
		return err
	}
	defer restore()

	query := keychain.NewItem()
	query.SetSecClass(keychain.SecClassGenericPassword)
	query.SetService(service)
	query.SetAccount(account)
	update := keychain.NewItem()
	update.SetData(secret)
	err = keychain.UpdateItem(query, update)
	if errors.Is(err, keychain.ErrorItemNotFound) {
		item := keychain.NewGenericPassword(service, account, "PaloNexus Guard credential", secret, "")
		item.SetSynchronizable(keychain.SynchronizableNo)
		item.SetAccessible(keychain.AccessibleAfterFirstUnlock)
		err = keychain.AddItem(item)
	}
	if err != nil {
		return mapDarwinError(err)
	}
	return nil
}

func (b *darwinBackend) Get(ctx context.Context, service, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	restore, err := disableKeychainInteraction()
	if err != nil {
		return nil, err
	}
	defer restore()
	value, err := keychain.GetGenericPassword(service, account, "", "")
	if err != nil {
		return nil, mapDarwinError(err)
	}
	if value == nil {
		return nil, ErrNotFound
	}
	if err := ctx.Err(); err != nil {
		Zero(value)
		return nil, err
	}
	return value, nil
}

func (b *darwinBackend) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	restore, err := disableKeychainInteraction()
	if err != nil {
		return err
	}
	defer restore()
	err = keychain.DeleteGenericPasswordItem(service, account)
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return nil
	}
	if err != nil {
		return mapDarwinError(err)
	}
	return nil
}

func disableKeychainInteraction() (func(), error) {
	darwinInteractionMu.Lock()
	var previous C.Boolean
	if status := C.SecKeychainGetUserInteractionAllowed(&previous); status != 0 {
		darwinInteractionMu.Unlock()
		return nil, ErrUnavailable
	}
	if status := C.SecKeychainSetUserInteractionAllowed(C.Boolean(0)); status != 0 {
		darwinInteractionMu.Unlock()
		return nil, ErrUnavailable
	}
	return func() {
		C.SecKeychainSetUserInteractionAllowed(previous)
		darwinInteractionMu.Unlock()
	}, nil
}

func mapDarwinError(err error) error {
	if errors.Is(err, keychain.ErrorItemNotFound) {
		return ErrNotFound
	}
	return ErrUnavailable
}
