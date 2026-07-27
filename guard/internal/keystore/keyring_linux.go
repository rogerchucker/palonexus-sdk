//go:build linux

package keystore

import (
	"context"
	"sync"

	dbus "github.com/keybase/dbus"
	"github.com/keybase/go-keychain/secretservice"
)

const (
	collectionCreateItem = "org.freedesktop.Secret.Collection.CreateItem"
	itemDelete           = "org.freedesktop.Secret.Item.Delete"
	lockedProperty       = "org.freedesktop.Secret.Collection.Locked"
)

// linuxBackend uses the session D-Bus Secret Service. It deliberately never
// invokes Prompt or Unlock: a locked collection fails closed for headless use.
type linuxBackend struct {
	service *secretservice.SecretService
	mu      sync.Mutex
}

func newNativeBackend() (Backend, error) {
	service, err := secretservice.NewService()
	if err != nil {
		return nil, ErrUnavailable
	}
	return &linuxBackend{service: service}, nil
}

func (b *linuxBackend) Put(ctx context.Context, service, account string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.requireUnlocked(); err != nil {
		return err
	}
	session, err := b.service.OpenSession(secretservice.AuthenticationDHAES)
	if err != nil {
		return ErrUnavailable
	}
	defer b.service.CloseSession(session)
	secret, err := session.NewSecret(value)
	if err != nil {
		return ErrUnavailable
	}
	defer Zero(secret.Value)
	properties := secretservice.NewSecretProperties(
		"PaloNexus Guard credential",
		map[string]string{"service": service, "account": account},
	)
	var item, prompt dbus.ObjectPath
	err = b.service.Obj(secretservice.DefaultCollection).
		Call(collectionCreateItem, secretservice.NilFlags, properties, secret, true).
		Store(&item, &prompt)
	if err != nil {
		return ErrUnavailable
	}
	if prompt != secretservice.NullPrompt {
		return ErrUnavailable
	}
	return nil
}

func (b *linuxBackend) Get(ctx context.Context, service, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.requireUnlocked(); err != nil {
		return nil, err
	}
	items, err := b.service.SearchCollection(
		secretservice.DefaultCollection,
		secretservice.Attributes{"service": service, "account": account},
	)
	if err != nil {
		return nil, ErrUnavailable
	}
	if len(items) == 0 {
		return nil, ErrNotFound
	}
	if len(items) != 1 {
		return nil, ErrUnavailable
	}
	session, err := b.service.OpenSession(secretservice.AuthenticationDHAES)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer b.service.CloseSession(session)
	value, err := b.service.GetSecret(items[0], *session)
	if err != nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		Zero(value)
		return nil, err
	}
	return value, nil
}

func (b *linuxBackend) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.requireUnlocked(); err != nil {
		return err
	}
	items, err := b.service.SearchCollection(
		secretservice.DefaultCollection,
		secretservice.Attributes{"service": service, "account": account},
	)
	if err != nil {
		return ErrUnavailable
	}
	for _, item := range items {
		var prompt dbus.ObjectPath
		if err := b.service.Obj(item).Call(itemDelete, secretservice.NilFlags).Store(&prompt); err != nil {
			return ErrUnavailable
		}
		if prompt != secretservice.NullPrompt {
			return ErrUnavailable
		}
	}
	return nil
}

func (b *linuxBackend) requireUnlocked() error {
	value, err := b.service.Obj(secretservice.DefaultCollection).GetProperty(lockedProperty)
	if err != nil {
		return ErrUnavailable
	}
	locked, ok := value.Value().(bool)
	if !ok || locked {
		return ErrUnavailable
	}
	return nil
}
