// SPDX-License-Identifier: MIT
//go:build unix && !darwin && !linux

package socket

import (
	"errors"
	"net"
)

func peerUID(net.Conn) (uint32, error) {
	return 0, errors.New("socket: Unix peer credentials are unsupported on this platform")
}

func peerPID(net.Conn) (int, error) {
	return 0, errors.New("socket: Unix peer process identity is unsupported on this platform")
}
