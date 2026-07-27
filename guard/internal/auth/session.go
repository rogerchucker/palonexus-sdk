package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/keystore"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/state"
	"golang.org/x/oauth2"
)

type Session struct {
	ID, Subject string
	ExpiresAt   time.Time
	// AccessToken is retained for backward-safe struct compatibility but is
	// deliberately always empty. Credentials never cross the manager boundary.
	AccessToken string `json:"-"`
}

type credential struct {
	SessionID, Subject, Nonce, AccessToken, RefreshToken string
	ExpiresAt, RefreshedAt                               time.Time
}

const (
	maxTokenBytes      = 16 << 10
	maxCredentialBytes = 64 << 10
)

type PartialError struct {
	RevocationFailed   bool
	LocalCleanupFailed bool
	CommitUncertain    bool
}

func (e *PartialError) Error() string { return ErrPartial.Error() }
func (e *PartialError) Is(target error) bool {
	return target == ErrPartial ||
		(target == ErrRevocation && e.RevocationFailed) ||
		(target == ErrCommitIndeterminate && e.CommitUncertain)
}

type verifiedClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	AZP       string   `json:"azp"`
	Nonce     string   `json:"nonce"`
	IssuedAt  int64    `json:"iat"`
	NotBefore int64    `json:"nbf"`
	Expiry    int64    `json:"exp"`
	AuthTime  int64    `json:"auth_time"`
}

func (c *verifiedClaims) UnmarshalJSON(data []byte) error {
	type alias verifiedClaims
	var raw struct {
		alias
		Audience json.RawMessage `json:"aud"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*c = verifiedClaims(raw.alias)
	var single string
	if err := json.Unmarshal(raw.Audience, &single); err == nil {
		c.Audience = []string{single}
		return nil
	}
	return json.Unmarshal(raw.Audience, &c.Audience)
}

func (m *Manager) Complete(ctx context.Context, callback Callback) (Session, error) {
	if err := ctx.Err(); err != nil {
		return Session{}, err
	}
	if callback.State == "" || len(callback.State) > 256 || len(callback.Code) > 4096 || len(callback.Error) > 256 {
		return Session{}, ErrInvalidCallback
	}
	m.mu.Lock()
	selected, ok := m.attempts[callback.State]
	delete(m.attempts, callback.State)
	m.mu.Unlock()
	if !ok || !selected.expires.After(m.options.Now()) || callback.Error != "" || callback.Code == "" {
		return Session{}, ErrInvalidCallback
	}
	token, err := m.config.Exchange(oidcClientContext(ctx, m.client), callback.Code,
		oauth2.SetAuthURLParam("code_verifier", selected.verifier))
	if err != nil {
		return Session{}, sanitizeError(err)
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" || len(rawIDToken) > 64<<10 {
		return Session{}, ErrInvalidToken
	}
	idToken, err := m.verifier.Verify(oidcClientContext(ctx, m.client), rawIDToken)
	if err != nil {
		return Session{}, wrapInvalidToken(err)
	}
	var claims verifiedClaims
	if err := idToken.Claims(&claims); err != nil || !m.validateClaims(claims, selected.nonce) {
		return Session{}, ErrInvalidToken
	}
	refresh, _ := token.Extra("refresh_token").(string)
	if refresh == "" {
		refresh = token.RefreshToken
	}
	if !validTokenField(token.AccessToken) || !validTokenField(refresh) || !strings.EqualFold(token.TokenType, "Bearer") {
		return Session{}, ErrInvalidToken
	}
	sessionID, err := newSessionID()
	if err != nil {
		return Session{}, ErrStorage
	}
	expires := token.Expiry
	if expires.IsZero() || !expires.After(m.options.Now().Add(-m.options.ClockSkew)) ||
		expires.After(m.options.Now().Add(m.options.MaxTokenLifetime+m.options.ClockSkew)) {
		return Session{}, ErrInvalidToken
	}
	stored := credential{SessionID: sessionID, Subject: claims.Subject, Nonce: selected.nonce, AccessToken: token.AccessToken, RefreshToken: refresh, ExpiresAt: expires}
	result := Session{ID: sessionID, Subject: claims.Subject, ExpiresAt: expires}
	var previous state.Metadata
	var hadPrevious bool
	binding := state.Binding{Tenant: m.options.Tenant, Account: m.options.Account}
	err = m.options.Metadata.WithSessionTransaction(ctx, binding, func(current state.Metadata, found bool) (*state.Metadata, error) {
		previous, hadPrevious = current, found && !current.Tombstoned
		generation := uint64(1)
		if found {
			generation = current.Generation + 1
		}
		if err := m.putCredential(ctx, stored); err != nil {
			return nil, err
		}
		next := state.Metadata{Kind: state.KindSession, SessionID: sessionID, Generation: generation, ExpiresAt: expires}
		return &next, nil
	})
	if err != nil {
		if errors.Is(err, state.ErrDurabilityIndeterminate) {
			return result, ErrCommitIndeterminate
		}
		cleanupErr := m.options.Credentials.Delete(context.WithoutCancel(ctx), credentialKey(m.options.Tenant, m.options.Account, sessionID))
		if cleanupErr != nil {
			return Session{}, ErrCommitIndeterminate
		}
		return Session{}, ErrStorage
	}
	if hadPrevious && previous.SessionID != sessionID {
		if err := m.options.Credentials.Delete(context.WithoutCancel(ctx),
			credentialKey(m.options.Tenant, m.options.Account, previous.SessionID)); err != nil {
			return result, &PartialError{LocalCleanupFailed: true}
		}
	}
	return result, nil
}

func oidcClientContext(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func (m *Manager) validateClaims(claims verifiedClaims, expectedNonce string) bool {
	now := m.options.Now()
	issued := time.Unix(claims.IssuedAt, 0)
	notBefore := time.Unix(claims.NotBefore, 0)
	expires := time.Unix(claims.Expiry, 0)
	authTime := time.Unix(claims.AuthTime, 0)
	if claims.Issuer != m.options.Issuer || claims.Subject == "" || !constantEqual(claims.Nonce, expectedNonce) ||
		claims.IssuedAt == 0 || claims.Expiry == 0 ||
		issued.After(now.Add(m.options.ClockSkew)) || (claims.NotBefore != 0 && notBefore.After(now.Add(m.options.ClockSkew))) ||
		!expires.After(now.Add(-m.options.ClockSkew)) || !expires.After(issued) ||
		expires.Sub(issued) > m.options.MaxTokenLifetime+m.options.ClockSkew ||
		now.Sub(issued) > m.options.MaxTokenLifetime+m.options.ClockSkew {
		return false
	}
	if claims.AuthTime != 0 && (authTime.After(now.Add(m.options.ClockSkew)) ||
		now.Sub(authTime) > m.options.MaxTokenLifetime+m.options.ClockSkew) {
		return false
	}
	found := false
	for _, audience := range claims.Audience {
		found = found || audience == m.options.ClientID
	}
	if !found || (len(claims.Audience) > 1 && claims.AZP != m.options.ClientID) ||
		(claims.AZP != "" && claims.AZP != m.options.ClientID) {
		return false
	}
	return true
}

func newSessionID() (string, error) {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	random, err := randomURL(32)
	if err != nil {
		return "", err
	}
	var builder strings.Builder
	builder.WriteString("session_")
	builder.WriteByte(alphabet[0])
	for i := 0; i < 25; i++ {
		builder.WriteByte(alphabet[int(random[i])%len(alphabet)])
	}
	return builder.String(), nil
}

func validTokenField(value string) bool {
	return value != "" && len(value) <= maxTokenBytes && !strings.ContainsAny(value, "\r\n\x00")
}

func (m *Manager) putCredential(ctx context.Context, value credential) error {
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > maxCredentialBytes {
		return ErrStorage
	}
	defer keystore.Zero(raw)
	key := credentialKey(m.options.Tenant, m.options.Account, value.SessionID)
	if err := m.options.Credentials.Put(ctx, key, raw); err != nil {
		return ErrStorage
	}
	return nil
}

func (m *Manager) Refresh(ctx context.Context, sessionID string) (Session, error) {
	binding := state.Binding{Tenant: m.options.Tenant, Account: m.options.Account}
	var result Session
	var oldID, newID string
	exchanged := false
	err := m.options.Metadata.WithSessionTransaction(ctx, binding, func(current state.Metadata, found bool) (*state.Metadata, error) {
		if !found || current.Tombstoned {
			return nil, ErrNoSession
		}
		if current.SessionID != sessionID {
			value, loadErr := m.loadCredential(ctx, current.SessionID)
			if loadErr != nil {
				return nil, loadErr
			}
			result = Session{ID: value.SessionID, Subject: value.Subject, ExpiresAt: value.ExpiresAt}
			return &current, nil
		}
		value, loadErr := m.loadCredential(ctx, current.SessionID)
		if loadErr != nil {
			return nil, loadErr
		}
		token, refreshErr := m.exchangeRefresh(ctx, value)
		if refreshErr != nil {
			return nil, refreshErr
		}
		exchanged = true
		newID, refreshErr = newSessionID()
		if refreshErr != nil {
			return nil, ErrCommitIndeterminate
		}
		nextCredential := credential{SessionID: newID, Subject: value.Subject, Nonce: value.Nonce, AccessToken: token.AccessToken,
			RefreshToken: token.RefreshToken, ExpiresAt: token.Expiry, RefreshedAt: m.options.Now()}
		if putErr := m.putCredential(ctx, nextCredential); putErr != nil {
			return nil, ErrCommitIndeterminate
		}
		oldID = current.SessionID
		next := state.Metadata{Kind: state.KindSession, SessionID: newID, Generation: current.Generation + 1, ExpiresAt: token.Expiry}
		result = Session{ID: newID, Subject: value.Subject, ExpiresAt: token.Expiry}
		return &next, nil
	})
	if err != nil {
		if exchanged {
			m.tombstoneAfterFailedRefresh(binding, oldID, newID)
			return Session{}, ErrCommitIndeterminate
		}
		return Session{}, err
	}
	if oldID != "" {
		if deleteErr := m.options.Credentials.Delete(context.WithoutCancel(ctx),
			credentialKey(m.options.Tenant, m.options.Account, oldID)); deleteErr != nil {
			return result, &PartialError{LocalCleanupFailed: true}
		}
	}
	return result, nil
}

func (m *Manager) loadCredential(ctx context.Context, sessionID string) (credential, error) {
	raw, err := m.options.Credentials.Get(ctx, credentialKey(m.options.Tenant, m.options.Account, sessionID))
	if err != nil {
		if errors.Is(err, keystore.ErrNotFound) {
			return credential{}, ErrNoSession
		}
		return credential{}, ErrStorage
	}
	defer keystore.Zero(raw)
	var value credential
	if len(raw) > maxCredentialBytes || json.Unmarshal(raw, &value) != nil || value.SessionID != sessionID ||
		!validTokenField(value.RefreshToken) || !validTokenField(value.AccessToken) || value.Subject == "" ||
		len(value.Subject) > 1024 || len(value.Nonce) > 1024 {
		return credential{}, ErrStorage
	}
	return value, nil
}

func (m *Manager) exchangeRefresh(ctx context.Context, value credential) (*oauth2.Token, error) {
	config := *m.config
	config.RedirectURL = ""
	token, err := config.TokenSource(oidcClientContext(ctx, m.client), &oauth2.Token{
		RefreshToken: value.RefreshToken, Expiry: time.Unix(0, 0),
	}).Token()
	if err != nil {
		return nil, ErrProvider
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || !validTokenField(rawID) {
		return nil, ErrInvalidToken
	}
	verified, err := m.verifier.Verify(oidcClientContext(ctx, m.client), rawID)
	if err != nil {
		return nil, ErrInvalidToken
	}
	var claims verifiedClaims
	if verified.Claims(&claims) != nil || claims.Subject != value.Subject || !m.validateClaims(claims, value.Nonce) {
		return nil, ErrInvalidToken
	}
	if !validTokenField(token.RefreshToken) || !validTokenField(token.AccessToken) ||
		!strings.EqualFold(token.TokenType, "Bearer") || token.Expiry.IsZero() ||
		!token.Expiry.After(m.options.Now().Add(-m.options.ClockSkew)) ||
		token.Expiry.After(m.options.Now().Add(m.options.MaxTokenLifetime+m.options.ClockSkew)) {
		return nil, ErrInvalidToken
	}
	return token, nil
}

func (m *Manager) tombstoneAfterFailedRefresh(binding state.Binding, oldID, newID string) {
	cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = m.options.Metadata.WithSessionTransaction(cleanup, binding, func(current state.Metadata, found bool) (*state.Metadata, error) {
		generation := uint64(1)
		selected := oldID
		if found {
			generation = current.Generation + 1
			selected = current.SessionID
		}
		if selected == "" {
			selected = newID
		}
		tombstone := state.Metadata{Kind: state.KindSession, SessionID: selected, Generation: generation, Tombstoned: true}
		return &tombstone, nil
	})
	for _, id := range []string{oldID, newID} {
		if id != "" {
			_ = m.options.Credentials.Delete(cleanup, credentialKey(m.options.Tenant, m.options.Account, id))
		}
	}
}

func (m *Manager) Logout(ctx context.Context, sessionID string) error {
	binding := state.Binding{Tenant: m.options.Tenant, Account: m.options.Account}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	partial := &PartialError{}
	transactionErr := m.options.Metadata.WithSessionTransaction(cleanup, binding, func(current state.Metadata, found bool) (*state.Metadata, error) {
		if !found || current.Tombstoned {
			return nil, ErrNoSession
		}
		value, loadErr := m.loadCredential(cleanup, current.SessionID)
		if loadErr != nil {
			partial.LocalCleanupFailed = true
		} else if revokeErr := m.revoke(ctx, value); revokeErr != nil {
			partial.RevocationFailed = true
		}
		if deleteErr := m.options.Credentials.Delete(cleanup,
			credentialKey(m.options.Tenant, m.options.Account, current.SessionID)); deleteErr != nil {
			partial.LocalCleanupFailed = true
		}
		return nil, nil
	})
	if errors.Is(transactionErr, state.ErrCorrupt) {
		partial.LocalCleanupFailed = true
		_ = m.options.Credentials.Delete(cleanup, credentialKey(m.options.Tenant, m.options.Account, sessionID))
		if err := m.options.Metadata.DeleteMetadata(cleanup, binding, state.KindSession); err != nil {
			partial.LocalCleanupFailed = true
		}
		transactionErr = nil
	}
	if transactionErr != nil {
		return transactionErr
	}
	if partial.LocalCleanupFailed || partial.RevocationFailed {
		return partial
	}
	return nil
}

func (m *Manager) revoke(ctx context.Context, value credential) error {
	if m.discovery.RevocationEndpoint == "" {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return ErrRevocation
	}
	for _, item := range []struct{ token, hint string }{
		{value.RefreshToken, "refresh_token"}, {value.AccessToken, "access_token"},
	} {
		form := url.Values{"token": {item.token}, "token_type_hint": {item.hint}}
		if m.options.RevocationAuthMethod == "client_secret_post" {
			form.Set("client_id", m.options.ClientID)
			form.Set("client_secret", m.options.ClientSecret)
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.discovery.RevocationEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			return ErrRevocation
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if m.options.RevocationAuthMethod == "client_secret_basic" {
			req.SetBasicAuth(m.options.ClientID, m.options.ClientSecret)
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return ErrRevocation
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4097))
		closeErr := resp.Body.Close()
		if readErr != nil || closeErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return ErrRevocation
		}
	}
	return nil
}
