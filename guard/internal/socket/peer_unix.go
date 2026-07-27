// SPDX-License-Identifier: MIT
//go:build unix

package socket

import (
	"errors"
	"net"
	"syscall"
)

func rawPeerConn(conn net.Conn) (syscall.RawConn, error) {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("socket: peer is not a Unix connection")
	}
	return unixConn.SyscallConn()
}
