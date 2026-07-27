//go:build !darwin && !linux

package keystore

func newNativeBackend() (Backend, error) {
	return nil, ErrUnsupported
}
