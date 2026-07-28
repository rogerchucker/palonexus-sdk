package keystore

import (
	"context"
	"errors"
)

var errLinuxMalformedSecret = errors.New("malformed Secret Service response")

type linuxItem string

type linuxFacade interface {
	Locked(context.Context) (bool, error)
	Put(context.Context, string, string, []byte) (promptRequired bool, err error)
	Find(context.Context, string, string) ([]linuxItem, error)
	Get(context.Context, linuxItem) ([]byte, error)
	Delete(context.Context, linuxItem) (promptRequired bool, err error)
}

type linuxBackend struct {
	facade linuxFacade
	gate   chan struct{}
}

func newLinuxBackend(facade linuxFacade) *linuxBackend {
	backend := &linuxBackend{facade: facade, gate: make(chan struct{}, 1)}
	backend.gate <- struct{}{}
	return backend
}

func (b *linuxBackend) Put(ctx context.Context, service, account string, value []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.lock(ctx); err != nil {
		return err
	}
	defer b.unlock()
	locked, err := b.facade.Locked(ctx)
	if err != nil || locked {
		return mapLinuxError(err)
	}
	prompt, err := b.facade.Put(ctx, service, account, value)
	if err != nil || prompt {
		return mapLinuxError(err)
	}
	return nil
}

func (b *linuxBackend) Get(ctx context.Context, service, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := b.lock(ctx); err != nil {
		return nil, err
	}
	defer b.unlock()
	locked, err := b.facade.Locked(ctx)
	if err != nil || locked {
		return nil, mapLinuxError(err)
	}
	items, err := b.facade.Find(ctx, service, account)
	if err != nil {
		return nil, mapLinuxError(err)
	}
	switch len(items) {
	case 0:
		return nil, ErrNotFound
	case 1:
	default:
		return nil, ErrUnavailable
	}
	value, err := b.facade.Get(ctx, items[0])
	if err != nil {
		return nil, mapLinuxError(err)
	}
	if len(value) == 0 {
		return nil, ErrUnavailable
	}
	return value, nil
}

func (b *linuxBackend) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := b.lock(ctx); err != nil {
		return err
	}
	defer b.unlock()
	locked, err := b.facade.Locked(ctx)
	if err != nil || locked {
		return mapLinuxError(err)
	}
	items, err := b.facade.Find(ctx, service, account)
	if err != nil {
		return mapLinuxError(err)
	}
	if len(items) > 1 {
		return ErrUnavailable
	}
	if len(items) == 0 {
		return nil
	}
	prompt, err := b.facade.Delete(ctx, items[0])
	if err != nil || prompt {
		return mapLinuxError(err)
	}
	return nil
}

func (b *linuxBackend) lock(ctx context.Context) error {
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

func (b *linuxBackend) unlock() { b.gate <- struct{}{} }

func mapLinuxError(err error) error {
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrUnavailable
	}
}
