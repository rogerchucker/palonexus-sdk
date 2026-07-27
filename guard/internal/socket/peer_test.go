// SPDX-License-Identifier: MIT
//go:build unix

package socket

import (
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestPeerUIDMatchesCurrentUser(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peer.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	done := make(chan error, 1)
	go func() {
		conn, err := net.Dial("unix", path)
		if err == nil {
			_ = conn.Close()
		}
		done <- err
	}()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil {
		t.Fatal(err)
	}
	if uid != uint32(os.Getuid()) {
		t.Fatalf("peer uid %d, want %d", uid, os.Getuid())
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
