package auth

import (
	"context"
	"encoding/json"
	"errors"
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
	SessionID, Subject, AccessToken, RefreshToken string
	ExpiresAt, RefreshedAt                        time.Time
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
	if callback.Error != "" || callback.Code == "" || callback.State == "" || len(callback.Code) > 4096 {
		return Session{}, ErrInvalidCallback
	}
	m.mu.Lock()
	selected, ok := m.attempts[callback.State]
	delete(m.attempts, callback.State)
	m.mu.Unlock()
	if !ok || !selected.expires.After(m.options.Now()) || !constantEqual(callback.State, callback.State) {
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
	if token.AccessToken == "" || refresh == "" || !strings.EqualFold(token.TokenType, "Bearer") {
		return Session{}, ErrInvalidToken
	}
	sessionID, err := newSessionID()
	if err != nil {
		return Session{}, ErrStorage
	}
	expires := token.Expiry
	if expires.IsZero() || expires.After(m.options.Now().Add(m.options.MaxTokenLifetime+m.options.ClockSkew)) {
		return Session{}, ErrInvalidToken
	}
	stored := credential{SessionID: sessionID, Subject: claims.Subject, AccessToken: token.AccessToken, RefreshToken: refresh, ExpiresAt: expires}
	if err := m.commitCredential(ctx, stored); err != nil {
		return Session{}, err
	}
	return Session{ID: sessionID, Subject: claims.Subject, ExpiresAt: expires}, nil
}

func oidcClientContext(ctx context.Context, client *http.Client) context.Context {
	return context.WithValue(ctx, oauth2.HTTPClient, client)
}

func (m *Manager) validateClaims(claims verifiedClaims, expectedNonce string) bool {
	now := m.options.Now()
	issued := time.Unix(claims.IssuedAt, 0)
	notBefore := time.Unix(claims.NotBefore, 0)
	expires := time.Unix(claims.Expiry, 0)
	if claims.Issuer != m.options.Issuer || claims.Subject == "" || !constantEqual(claims.Nonce, expectedNonce) ||
		claims.IssuedAt == 0 || claims.Expiry == 0 ||
		issued.After(now.Add(m.options.ClockSkew)) || (claims.NotBefore != 0 && notBefore.After(now.Add(m.options.ClockSkew))) ||
		expires.Before(now.Add(-m.options.ClockSkew)) || expires.Sub(issued) > m.options.MaxTokenLifetime+m.options.ClockSkew {
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

func (m *Manager) commitCredential(ctx context.Context, value credential) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return ErrStorage
	}
	defer keystore.Zero(raw)
	key := credentialKey(m.options.Tenant, m.options.Account, value.SessionID)
	if err := m.options.Credentials.Put(ctx, key, raw); err != nil {
		return ErrStorage
	}
	metadata := state.Metadata{Kind: state.KindSession, SessionID: value.SessionID, ExpiresAt: value.ExpiresAt}
	if err := m.options.Metadata.PutMetadata(ctx, state.Binding{Tenant: m.options.Tenant, Account: m.options.Account}, metadata); err != nil {
		_ = m.options.Credentials.Delete(context.WithoutCancel(ctx), key)
		return ErrStorage
	}
	return nil
}

func (m *Manager) Refresh(ctx context.Context, sessionID string) (Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if last := m.lastRefresh[sessionID]; !last.IsZero() && m.options.Now().Sub(last) < time.Second {
		value, err := m.loadCredential(ctx, sessionID)
		if err != nil {
			return Session{}, err
		}
		return Session{ID: value.SessionID, Subject: value.Subject, ExpiresAt: value.ExpiresAt}, nil
	}
	value, err := m.loadCredential(ctx, sessionID)
	if err != nil {
		return Session{}, err
	}
	config := *m.config
	config.RedirectURL = ""
	source := config.TokenSource(oidcClientContext(ctx, m.client), &oauth2.Token{
		RefreshToken: value.RefreshToken, Expiry: time.Unix(0, 0),
	})
	token, err := source.Token()
	if err != nil {
		return Session{}, ErrProvider
	}
	rawID, ok := token.Extra("id_token").(string)
	if !ok || rawID == "" {
		return Session{}, ErrInvalidToken
	}
	verified, err := m.verifier.Verify(oidcClientContext(ctx, m.client), rawID)
	if err != nil {
		return Session{}, ErrInvalidToken
	}
	var claims verifiedClaims
	if verified.Claims(&claims) != nil || claims.Subject != value.Subject || !m.validateClaims(claims, "") {
		return Session{}, ErrInvalidToken
	}
	refresh := token.RefreshToken
	if refresh == "" {
		return Session{}, ErrInvalidToken
	}
	if token.AccessToken == "" || !strings.EqualFold(token.TokenType, "Bearer") || token.Expiry.IsZero() ||
		token.Expiry.After(m.options.Now().Add(m.options.MaxTokenLifetime+m.options.ClockSkew)) {
		return Session{}, ErrInvalidToken
	}
	next := credential{SessionID: sessionID, Subject: value.Subject, AccessToken: token.AccessToken,
		RefreshToken: refresh, ExpiresAt: token.Expiry, RefreshedAt: m.options.Now()}
	if err := m.commitCredential(ctx, next); err != nil {
		previous, marshalErr := json.Marshal(value)
		if marshalErr == nil {
			_ = m.options.Credentials.Put(context.WithoutCancel(ctx),
				credentialKey(m.options.Tenant, m.options.Account, sessionID), previous)
			keystore.Zero(previous)
		}
		return Session{}, err
	}
	m.lastRefresh[sessionID] = m.options.Now()
	return Session{ID: sessionID, Subject: value.Subject, ExpiresAt: token.Expiry}, nil
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
	if json.Unmarshal(raw, &value) != nil || value.SessionID != sessionID || value.RefreshToken == "" {
		return credential{}, ErrStorage
	}
	return value, nil
}

func (m *Manager) Logout(ctx context.Context, sessionID string) error {
	value, err := m.loadCredential(ctx, sessionID)
	if err != nil && !errors.Is(err, ErrNoSession) {
		return err
	}
	if err == nil && m.discovery.RevocationEndpoint != "" {
		for _, token := range []string{value.RefreshToken, value.AccessToken} {
			if token == "" {
				continue
			}
			form := url.Values{"token": {token}}
			req, requestErr := http.NewRequestWithContext(ctx, http.MethodPost, m.discovery.RevocationEndpoint, strings.NewReader(form.Encode()))
			if requestErr == nil {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				resp, revokeErr := m.client.Do(req)
				if revokeErr == nil {
					resp.Body.Close()
				}
			}
		}
	}
	deleteErr := m.options.Credentials.Delete(context.WithoutCancel(ctx), credentialKey(m.options.Tenant, m.options.Account, sessionID))
	stateErr := m.options.Metadata.DeleteAccount(context.WithoutCancel(ctx), state.Binding{Tenant: m.options.Tenant, Account: m.options.Account})
	if deleteErr != nil || stateErr != nil {
		return ErrStorage
	}
	m.mu.Lock()
	delete(m.lastRefresh, sessionID)
	m.mu.Unlock()
	return nil
}
