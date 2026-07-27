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
	Cause              error
}

func (e *PartialError) Error() string { return ErrPartial.Error() }
func (e *PartialError) Is(target error) bool {
	return target == ErrPartial ||
		(target == ErrRevocation && e.RevocationFailed) ||
		(target == ErrCommitIndeterminate && e.CommitUncertain) ||
		(e.Cause != nil && errors.Is(e.Cause, target))
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
	binding := state.Binding{Tenant: m.options.Tenant, Account: m.options.Account}
	err = m.options.Metadata.WithSessionLifecycle(ctx, binding, func() error {
		if err := m.recoverSessionJournal(ctx, binding); err != nil {
			return err
		}
		journal, err := m.beginSessionJournal(ctx, binding, "login", sessionID)
		if err != nil {
			return err
		}
		if err := m.putCredential(ctx, stored); err != nil {
			return m.abortSessionJournal(ctx, binding, journal, ErrStorage)
		}
		if err := m.deleteJournalPredecessors(ctx, journal); err != nil {
			return err
		}
		active := state.Metadata{
			Kind: state.KindSession, SessionID: sessionID, Generation: journal.Generation,
			ExpiresAt: expires,
		}
		if err := m.activateSessionJournal(ctx, binding, journal, active); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return Session{}, err
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
	err := m.options.Metadata.WithSessionLifecycle(ctx, binding, func() error {
		if err := m.recoverSessionJournal(ctx, binding); err != nil {
			return err
		}
		current, err := m.options.Metadata.GetMetadata(ctx, binding, state.KindSession)
		if err != nil || current.Tombstoned || current.SessionID != sessionID {
			return ErrNoSession
		}
		value, err := m.loadCredential(ctx, sessionID)
		if err != nil {
			return err
		}
		newID, err := newSessionID()
		if err != nil {
			return ErrStorage
		}
		reservation, err := m.beginSessionJournal(ctx, binding, "refresh", newID)
		if err != nil {
			return err
		}
		token, err := m.exchangeRefresh(ctx, value)
		if err != nil {
			return m.abortSessionJournal(context.WithoutCancel(ctx), binding, reservation, err)
		}
		nextCredential := credential{
			SessionID: newID, Subject: value.Subject, Nonce: value.Nonce, AccessToken: token.AccessToken,
			RefreshToken: token.RefreshToken, ExpiresAt: token.Expiry, RefreshedAt: m.options.Now(),
		}
		if err := m.putCredential(ctx, nextCredential); err != nil {
			return m.abortSessionJournal(ctx, binding, reservation, ErrCommitIndeterminate)
		}
		if err := m.deleteJournalPredecessors(ctx, reservation); err != nil {
			return err
		}
		active := state.Metadata{
			Kind: state.KindSession, SessionID: newID, Generation: reservation.Generation,
			ExpiresAt: token.Expiry,
		}
		if err := m.activateSessionJournal(ctx, binding, reservation, active); err != nil {
			return err
		}
		result = Session{ID: newID, Subject: value.Subject, ExpiresAt: token.Expiry}
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	return result, nil
}

func newOperationID() (string, error) {
	id, err := newSessionID()
	if err != nil {
		return "", err
	}
	return "operation_" + strings.TrimPrefix(id, "session_"), nil
}

func (m *Manager) beginSessionJournal(
	ctx context.Context,
	binding state.Binding,
	operation string,
	pendingID string,
) (state.Metadata, error) {
	current, getErr := m.options.Metadata.GetMetadata(ctx, binding, state.KindSession)
	found := getErr == nil
	if getErr != nil && !errors.Is(getErr, state.ErrNotFound) {
		return state.Metadata{}, ErrCommitIndeterminate
	}
	if found && current.Tombstoned {
		return state.Metadata{}, ErrCommitIndeterminate
	}
	operationID, err := newOperationID()
	if err != nil {
		return state.Metadata{}, ErrStorage
	}
	sessionID := pendingID
	previousID := ""
	generation := uint64(1)
	if found {
		sessionID = current.SessionID
		previousID = current.SessionID
		generation = current.Generation + 1
	}
	journal := state.Metadata{
		Kind: state.KindSession, SessionID: sessionID, PendingSessionID: pendingID,
		PreviousSessionID: previousID, SessionOperation: operation,
		Generation: generation, Tombstoned: true, OperationID: operationID,
	}
	err = m.options.Metadata.WithSessionTransaction(ctx, binding, func(actual state.Metadata, actualFound bool) (*state.Metadata, error) {
		if actualFound != found {
			return nil, ErrCommitIndeterminate
		}
		if found && (!sameActiveSession(actual, current) || actual.ExpiresAt != current.ExpiresAt) {
			return nil, ErrCommitIndeterminate
		}
		return &journal, nil
	})
	if errors.Is(err, state.ErrDurabilityIndeterminate) {
		actual, readErr := m.options.Metadata.GetMetadata(context.WithoutCancel(ctx), binding, state.KindSession)
		if readErr == nil && sameReservation(actual, journal) {
			err = nil
		}
	}
	if err != nil {
		return state.Metadata{}, ErrCommitIndeterminate
	}
	return journal, nil
}

func (m *Manager) deleteJournalPredecessors(ctx context.Context, journal state.Metadata) error {
	seen := make(map[string]struct{}, 2)
	for _, id := range []string{journal.PreviousSessionID} {
		if id == "" || id == journal.PendingSessionID {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if err := m.options.Credentials.Delete(ctx,
			credentialKey(m.options.Tenant, m.options.Account, id)); err != nil {
			return &PartialError{LocalCleanupFailed: true, CommitUncertain: true}
		}
	}
	return nil
}

func (m *Manager) activateSessionJournal(
	ctx context.Context,
	binding state.Binding,
	journal state.Metadata,
	active state.Metadata,
) error {
	err := m.options.Metadata.WithSessionTransaction(ctx, binding, func(current state.Metadata, found bool) (*state.Metadata, error) {
		if !found || !sameReservation(current, journal) {
			return nil, ErrCommitIndeterminate
		}
		return &active, nil
	})
	if errors.Is(err, state.ErrDurabilityIndeterminate) {
		current, getErr := m.options.Metadata.GetMetadata(context.WithoutCancel(ctx), binding, state.KindSession)
		if getErr == nil && sameActiveSession(current, active) && current.ExpiresAt == active.ExpiresAt {
			return nil
		}
	}
	if err != nil {
		return &PartialError{CommitUncertain: true, Cause: ErrCommitIndeterminate}
	}
	return nil
}

func (m *Manager) abortSessionJournal(
	ctx context.Context,
	binding state.Binding,
	journal state.Metadata,
	cause error,
) error {
	current, err := m.options.Metadata.GetMetadata(ctx, binding, state.KindSession)
	if err != nil || !sameReservation(current, journal) {
		return cause
	}
	if err := m.recoverSessionJournal(ctx, binding); err != nil {
		var partial *PartialError
		if errors.As(err, &partial) {
			partial.Cause = cause
			return partial
		}
		return &PartialError{CommitUncertain: true, Cause: cause}
	}
	return cause
}

func (m *Manager) recoverSessionJournal(ctx context.Context, binding state.Binding) error {
	current, err := m.options.Metadata.GetMetadata(ctx, binding, state.KindSession)
	if errors.Is(err, state.ErrNotFound) {
		return nil
	}
	if err != nil {
		return ErrCommitIndeterminate
	}
	if !current.Tombstoned {
		return nil
	}
	ids := []string{current.PendingSessionID, current.PreviousSessionID}
	if current.PendingSessionID == "" {
		ids = append(ids, current.SessionID)
	}
	seen := make(map[string]struct{}, len(ids))
	partial := &PartialError{}
	for _, id := range ids {
		if id == "" {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		if err := m.options.Credentials.Delete(ctx,
			credentialKey(m.options.Tenant, m.options.Account, id)); err != nil {
			partial.LocalCleanupFailed = true
		}
	}
	if partial.LocalCleanupFailed {
		partial.CommitUncertain = true
		return partial
	}
	if err := m.options.Metadata.DeleteMetadata(ctx, binding, state.KindSession); err != nil {
		return &PartialError{CommitUncertain: true}
	}
	return nil
}

func sameReservation(actual, expected state.Metadata) bool {
	return actual.Kind == state.KindSession && actual.Tombstoned &&
		actual.SessionID == expected.SessionID && actual.Generation == expected.Generation &&
		actual.OperationID == expected.OperationID &&
		actual.PendingSessionID == expected.PendingSessionID &&
		actual.PreviousSessionID == expected.PreviousSessionID &&
		actual.SessionOperation == expected.SessionOperation
}

func sameActiveSession(actual, expected state.Metadata) bool {
	return actual.Kind == state.KindSession && !actual.Tombstoned &&
		actual.SessionID == expected.SessionID && actual.Generation == expected.Generation
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

func (m *Manager) Logout(ctx context.Context, sessionID string) error {
	binding := state.Binding{Tenant: m.options.Tenant, Account: m.options.Account}
	partial := &PartialError{}
	localContext, cancelLocal := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancelLocal()
	var value credential
	loadErr := ErrNoSession
	lifecycleErr := m.options.Metadata.WithSessionLifecycle(localContext, binding, func() error {
		current, metadataErr := m.options.Metadata.GetMetadata(localContext, binding, state.KindSession)
		found := metadataErr == nil
		corrupt := metadataErr != nil && !errors.Is(metadataErr, state.ErrNotFound)
		matching := found && (current.SessionID == sessionID ||
			current.PendingSessionID == sessionID || current.PreviousSessionID == sessionID)
		value, loadErr = m.loadCredential(localContext, sessionID)
		if loadErr != nil && ((!errors.Is(loadErr, ErrNoSession) || matching) &&
			m.discovery.RevocationEndpoint != "") {
			partial.RevocationFailed = true
		}
		if matching && current.Tombstoned {
			if err := m.recoverSessionJournal(localContext, binding); err != nil {
				var cleanup *PartialError
				if errors.As(err, &cleanup) {
					partial.LocalCleanupFailed = partial.LocalCleanupFailed || cleanup.LocalCleanupFailed
					partial.CommitUncertain = partial.CommitUncertain || cleanup.CommitUncertain
				} else {
					partial.CommitUncertain = true
				}
			}
		} else if matching || corrupt {
			if err := m.options.Metadata.DeleteMetadata(localContext, binding, state.KindSession); err != nil {
				partial.CommitUncertain = true
			}
		}
		if deleteErr := m.options.Credentials.Delete(localContext,
			credentialKey(m.options.Tenant, m.options.Account, sessionID)); deleteErr != nil {
			partial.LocalCleanupFailed = true
		}
		return nil
	})
	if lifecycleErr != nil {
		partial.CommitUncertain = true
	}
	if loadErr == nil {
		if revokeErr := m.revoke(context.WithoutCancel(ctx), value); revokeErr != nil {
			partial.RevocationFailed = true
		}
	}
	if partial.LocalCleanupFailed || partial.RevocationFailed || partial.CommitUncertain {
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
	failed := false
	for _, item := range []struct{ token, hint string }{
		{value.RefreshToken, "refresh_token"}, {value.AccessToken, "access_token"},
	} {
		itemContext, cancelItem := context.WithTimeout(context.WithoutCancel(ctx), 500*time.Millisecond)
		form := url.Values{"token": {item.token}, "token_type_hint": {item.hint}}
		if m.options.RevocationAuthMethod == "client_secret_post" {
			form.Set("client_id", m.options.ClientID)
			form.Set("client_secret", m.options.ClientSecret)
		}
		req, err := http.NewRequestWithContext(itemContext, http.MethodPost, m.discovery.RevocationEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			cancelItem()
			failed = true
			continue
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if m.options.RevocationAuthMethod == "client_secret_basic" {
			req.SetBasicAuth(url.QueryEscape(m.options.ClientID), url.QueryEscape(m.options.ClientSecret))
		}
		resp, err := m.client.Do(req)
		if err != nil {
			cancelItem()
			failed = true
			continue
		}
		_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 4097))
		closeErr := resp.Body.Close()
		cancelItem()
		if readErr != nil || closeErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 {
			failed = true
		}
	}
	if failed {
		return ErrRevocation
	}
	return nil
}
