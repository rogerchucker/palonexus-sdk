//go:build !darwin && !linux

package reconcile

func openQueue(Config) (queueImpl, error) { return nil, ErrUnsafePath }
