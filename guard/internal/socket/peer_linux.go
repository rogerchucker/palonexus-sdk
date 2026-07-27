// SPDX-License-Identifier: MIT
//go:build linux

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
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(
			int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED,
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

func peerPID(conn net.Conn) (int, error) {
	raw, err := rawPeerConn(conn)
	if err != nil {
		return 0, err
	}
	var credential *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credential, socketErr = unix.GetsockoptUcred(
			int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED,
		)
	}); err != nil {
		return 0, err
	}
	if socketErr != nil {
		return 0, socketErr
	}
	if credential == nil || credential.Pid <= 0 {
		return 0, errors.New("socket: peer process ID is unavailable")
	}
	return int(credential.Pid), nil
}
