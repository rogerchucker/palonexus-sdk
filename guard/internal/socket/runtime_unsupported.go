// SPDX-License-Identifier: MIT
//go:build !unix

package socket

import (
	"errors"
	"net"
	"os"
)

func prepareRuntimeDir(string) (*os.File, os.FileInfo, error) {
	return nil, nil, errors.New("socket: Unix sockets are unsupported on this platform")
}

func verifyRuntimeDir(*os.File, string, os.FileInfo) error {
	return errors.New("socket: Unix sockets are unsupported on this platform")
}

func currentUID() uint32 { return 0 }

func peerUID(net.Conn) (uint32, error) {
	return 0, errors.New("socket: Unix peer credentials are unsupported on this platform")
}

type fileIdentity struct{}

func identityFromInfo(os.FileInfo) (fileIdentity, error) {
	return fileIdentity{}, errors.New("socket: Unix inode identity is unsupported on this platform")
}

func removeOwnedAt(*os.File, string, fileIdentity) error {
	return errors.New("socket: Unix safe cleanup is unsupported on this platform")
}
