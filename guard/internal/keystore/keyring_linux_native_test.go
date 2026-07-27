//go:build linux

package keystore

import (
	"errors"
	"testing"

	dbus "github.com/keybase/dbus"
)

type lifecycleLinuxConnection struct{ closes int }

func (*lifecycleLinuxConnection) Object(string, dbus.ObjectPath) dbus.BusObject { return nil }
func (c *lifecycleLinuxConnection) Close() error {
	c.closes++
	return nil
}

func TestLinuxWithConnectionUsesAndClosesOnePrivateConnection(t *testing.T) {
	for _, operationErr := range []error{nil, errors.New("operation")} {
		connection := &lifecycleLinuxConnection{}
		connects := 0
		facade := &nativeLinuxFacade{connect: func() (linuxConnection, error) {
			connects++
			return connection, nil
		}}
		err := facade.withConnection(func(operation *nativeLinuxFacade) error {
			if operation.conn != connection {
				t.Fatal("operation received wrong connection")
			}
			return operationErr
		})
		if !errors.Is(err, operationErr) || connects != 1 || connection.closes != 1 {
			t.Fatalf("lifecycle err=%v connects=%d closes=%d", err, connects, connection.closes)
		}
	}
}
