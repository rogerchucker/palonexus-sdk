// SPDX-License-Identifier: MIT
//go:build darwin || linux

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/keystore"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/state"
)

func TestSessionReaderReturnsTrustedIdentityAndFreshTokenCopy(t *testing.T) {
	metadata, err := state.New(sessionReaderStateRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	credentials, err := keystore.New("palonexus-test", keystore.NewMemoryBackendForTesting())
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.Close()

	sessionID := "session_01J5ABCDEFGHJKMNPQRSTVWXY0"
	expires := time.Now().Add(time.Hour).UTC()
	if err := metadata.PutMetadata(
		context.Background(),
		state.Binding{Tenant: "tenant-a", Account: "account-a"},
		state.Metadata{
			Kind: state.KindSession, SessionID: sessionID, ExpiresAt: expires, Generation: 1,
		},
	); err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(credential{
		SessionID: sessionID, Subject: "subject-a", Nonce: "nonce",
		AccessToken: "access-token", RefreshToken: "refresh-token", ExpiresAt: expires,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := credentials.Put(
		context.Background(), credentialKey("tenant-a", "account-a", sessionID), document,
	); err != nil {
		t.Fatal(err)
	}

	reader, err := NewSessionReader(SessionReaderOptions{
		Tenant: "tenant-a", Account: "account-a", ClientID: "codex",
		Metadata: metadata, Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	current, err := reader.Current(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if current.TenantID != "tenant-a" || current.AccountID != "account-a" ||
		current.ClientID != "codex" || current.SessionID != sessionID ||
		current.Subject != "subject-a" {
		t.Fatalf("current = %#v", current)
	}
	first, err := reader.AccessToken(context.Background(), sessionID)
	if err != nil || string(first) != "access-token" {
		t.Fatalf("first token = %q, %v", first, err)
	}
	first[0] = 'X'
	second, err := reader.AccessToken(context.Background(), sessionID)
	if err != nil || string(second) != "access-token" {
		t.Fatalf("second token aliases first: %q, %v", second, err)
	}
	keystore.Zero(first)
	keystore.Zero(second)
}

func TestSessionReaderFailsClosedWithoutActiveLogin(t *testing.T) {
	metadata, err := state.New(sessionReaderStateRoot(t))
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	credentials, err := keystore.New("palonexus-test", keystore.NewMemoryBackendForTesting())
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.Close()
	reader, err := NewSessionReader(SessionReaderOptions{
		Tenant: "tenant-a", Account: "account-a", ClientID: "codex",
		Metadata: metadata, Credentials: credentials,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Current(context.Background()); !errors.Is(err, ErrNoSession) {
		t.Fatalf("Current = %v", err)
	}
}

func sessionReaderStateRoot(t *testing.T) string {
	t.Helper()
	root, err := os.MkdirTemp("", "psr-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "state")
}
