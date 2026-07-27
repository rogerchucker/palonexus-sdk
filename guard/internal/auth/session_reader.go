// SPDX-License-Identifier: MIT

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/keystore"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/state"
)

// SessionReaderOptions binds runtime session lookup to one configured account.
type SessionReaderOptions struct {
	Tenant, Account, ClientID string
	Credentials               credentialStore
	Metadata                  metadataStore
	Now                       func() time.Time
}

// RuntimeSession contains trusted non-secret identity metadata.
type RuntimeSession struct {
	TenantID, AccountID, ClientID string
	SessionID, Subject            string
}

// SessionReader retrieves the active session metadata and its separately
// protected credential. It never retains or exposes refresh tokens.
type SessionReader struct{ options SessionReaderOptions }

func NewSessionReader(options SessionReaderOptions) (*SessionReader, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Tenant == "" || options.Account == "" || options.ClientID == "" ||
		options.Credentials == nil || options.Metadata == nil {
		return nil, ErrInvalidConfig
	}
	return &SessionReader{options: options}, nil
}

func (r *SessionReader) active(ctx context.Context) (state.Metadata, credential, error) {
	if r == nil || ctx == nil {
		return state.Metadata{}, credential{}, ErrNoSession
	}
	metadata, err := r.options.Metadata.GetMetadata(
		ctx, state.Binding{Tenant: r.options.Tenant, Account: r.options.Account}, state.KindSession,
	)
	if err != nil {
		if errors.Is(err, state.ErrNotFound) {
			return state.Metadata{}, credential{}, ErrNoSession
		}
		return state.Metadata{}, credential{}, ErrStorage
	}
	if metadata.Tombstoned || metadata.SessionID == "" ||
		!metadata.ExpiresAt.After(r.options.Now()) {
		return state.Metadata{}, credential{}, ErrNoSession
	}
	raw, err := r.options.Credentials.Get(
		ctx, credentialKey(r.options.Tenant, r.options.Account, metadata.SessionID),
	)
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return state.Metadata{}, credential{}, ErrNoSession
		}
		return state.Metadata{}, credential{}, ErrStorage
	}
	defer keystore.Zero(raw)
	value, err := decodeCredential(raw, metadata.SessionID)
	if err != nil || !value.ExpiresAt.After(r.options.Now()) {
		return state.Metadata{}, credential{}, ErrStorage
	}
	return metadata, value, nil
}

func decodeCredential(raw []byte, sessionID string) (credential, error) {
	var value credential
	if len(raw) > maxCredentialBytes || json.Unmarshal(raw, &value) != nil ||
		value.SessionID != sessionID || !validTokenField(value.RefreshToken) ||
		!validTokenField(value.AccessToken) || value.Subject == "" ||
		len(value.Subject) > 1024 || len(value.Nonce) > 1024 {
		return credential{}, ErrStorage
	}
	return value, nil
}

func (r *SessionReader) Current(ctx context.Context) (RuntimeSession, error) {
	metadata, value, err := r.active(ctx)
	if err != nil {
		return RuntimeSession{}, err
	}
	return RuntimeSession{
		TenantID: r.options.Tenant, AccountID: r.options.Account,
		ClientID: r.options.ClientID, SessionID: metadata.SessionID, Subject: value.Subject,
	}, nil
}

// AccessToken returns a fresh caller-owned token only when sessionID is still
// the active configured session.
func (r *SessionReader) AccessToken(ctx context.Context, sessionID string) ([]byte, error) {
	metadata, value, err := r.active(ctx)
	if err != nil || metadata.SessionID != sessionID {
		return nil, ErrNoSession
	}
	return append([]byte(nil), value.AccessToken...), nil
}
