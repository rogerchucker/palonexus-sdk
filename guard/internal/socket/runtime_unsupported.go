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

func peerPID(net.Conn) (int, error) {
	return 0, errors.New("socket: Unix peer process identity is unsupported on this platform")
}

type fileIdentity struct {
	device uint64
	inode  uint64
}
type nodeInfo struct {
	identity fileIdentity
	mode     uint32
	uid      uint32
	nlink    uint64
}

func removeOwnedAt(*os.File, string, fileIdentity) error {
	return errors.New("socket: Unix safe cleanup is unsupported on this platform")
}

func inspectAt(*os.File, string) (nodeInfo, error) {
	return nodeInfo{}, errors.New("socket: Unix inode inspection is unsupported on this platform")
}

func verifyListenerFD(*net.UnixListener, string) error {
	return errors.New("socket: Unix listener inspection is unsupported on this platform")
}

func chmodAt(*os.File, string, uint32) error {
	return errors.New("socket: Unix chmod is unsupported on this platform")
}

func acquireServerLock(*os.File, string) (*os.File, fileIdentity, error) {
	return nil, fileIdentity{}, errors.New("socket: Unix locking is unsupported on this platform")
}

func verifyLockPath(*os.File, string, fileIdentity) error {
	return errors.New("socket: Unix locking is unsupported on this platform")
}

func releaseServerLock(*os.File) error {
	return errors.New("socket: Unix locking is unsupported on this platform")
}

func renameNoReplace(int, string, string) error {
	return errors.New("socket: Unix rename is unsupported on this platform")
}

func readLifecycleRecord(*os.File, string) (*lifecycleRecord, error) {
	return nil, errors.New("socket: Unix lifecycle journal is unsupported on this platform")
}

func writeLifecycleRecord(*os.File, string, lifecycleRecord, func(string)) error {
	return errors.New("socket: Unix lifecycle journal is unsupported on this platform")
}

func cleanupLifecycleTemps(*os.File, string, string) error {
	return errors.New("socket: Unix lifecycle journal is unsupported on this platform")
}
