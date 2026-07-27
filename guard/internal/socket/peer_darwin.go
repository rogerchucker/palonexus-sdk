// SPDX-License-Identifier: MIT
//go:build darwin

package socket

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

func peerUID(conn net.Conn) (uint32, error) {
	raw, err := rawPeerConn(conn)
	if err != nil {
		return 0, err
	}
	var credential *unix.Xucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptXucred(
			int(fd), unix.SOL_LOCAL, unix.LOCAL_PEERCRED,
		)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	if credential == nil {
		return 0, errors.New("socket: peer credential is unavailable")
	}
	return credential.Uid, nil
}
