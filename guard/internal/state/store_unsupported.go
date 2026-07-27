//go:build !darwin && !linux

package state

func newStore(string) (storeImpl, error) { return nil, ErrUnsupported }
