//go:build darwin && !cgo

package keystore

func newNativeBackend() (Backend, error) {
	return nil, ErrUnsupported
}
