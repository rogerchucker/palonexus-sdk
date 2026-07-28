//go:build linux

package keystore

func newNativeBackend() (Backend, error) {
	facade, err := newNativeLinuxFacade()
	if err != nil {
		return nil, ErrUnavailable
	}
	return newLinuxBackend(facade), nil
}
