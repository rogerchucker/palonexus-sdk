package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/keystore"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/state"
)

type providerFixture struct {
	server       *httptest.Server
	key          *rsa.PrivateKey
	signingKey   *rsa.PrivateKey
	kid          string
	clientID     string
	nonce        atomic.Value
	refreshCount atomic.Int32
	mu           sync.Mutex
	revoked      []string
}

func newProvider(t *testing.T) *providerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &providerFixture{key: key, signingKey: key, kid: "key-1", clientID: "client"}
	mux := http.NewServeMux()
	p.server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize",
			"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks",
			"revocation_endpoint":                   p.server.URL + "/revoke",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": p.kid, "use": "sig", "alg": "RS256", "n": n, "e": e,
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		refreshing := r.Form.Get("grant_type") == "refresh_token"
		if refreshing {
			p.refreshCount.Add(1)
		} else {
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "valid-code" ||
				base64.RawURLEncoding.EncodeToString(sum[:]) != r.Header.Get("X-Test-Challenge") {
				http.Error(w, "invalid grant", 400)
				return
			}
		}
		nonce, _ := p.nonce.Load().(string)
		if refreshing {
			nonce = ""
		}
		now := time.Now()
		claims := map[string]any{
			"iss": p.server.URL, "aud": p.clientID, "sub": "subject",
			"nonce": nonce, "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(),
			"exp": now.Add(5 * time.Minute).Unix(),
		}
		raw, err := signRS256(p.signingKey, p.kid, claims)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-secret", "refresh_token": fmt.Sprintf("refresh-%d", p.refreshCount.Load()+1),
			"token_type": "Bearer", "expires_in": 300, "id_token": raw,
		})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		p.mu.Lock()
		p.revoked = append(p.revoked, r.Form.Get("token"))
		p.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	})
	return p
}

func signRS256(key *rsa.PrivateKey, kid string, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": kid, "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sum := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func (p *providerFixture) Close() { p.server.Close() }

func testManager(t *testing.T, p *providerFixture) *Manager {
	t.Helper()
	secrets, err := keystore.New("palonexus-test", keystore.NewMemoryBackendForTesting())
	if err != nil {
		t.Fatal(err)
	}
	manager, err := New(Options{
		Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "account",
		RedirectURI: "http://127.0.0.1:49152/callback", AllowInsecureLoopback: true,
		HTTPClient: p.server.Client(), Credentials: secrets, Metadata: newMemoryMetadata(),
		Algorithms: []string{"RS256"}, ClockSkew: time.Minute, MaxTokenLifetime: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestAuthorizationCodePKCEAndVerifiedClaims(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	request, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.nonce.Store(request.nonce)
	u, _ := url.Parse(request.URL)
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("state") == "" ||
		u.Query().Get("nonce") == "" || strings.Contains(request.URL, request.verifier) {
		t.Fatal("authorization URL did not bind PKCE, state, and nonce safely")
	}
	m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
	session, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"})
	if err != nil {
		t.Fatal(err)
	}
	if session.Subject != "subject" || session.AccessToken != "" {
		t.Fatalf("unexpected public session: %#v", session)
	}
	if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("state replay was accepted: %v", err)
	}
}

func TestRejectsCallbackAndTokenConfusion(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	if _, err := m.Complete(context.Background(), Callback{State: "unknown", Code: "code"}); !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("unknown state accepted: %v", err)
	}
	request, _ := m.Begin(context.Background())
	p.nonce.Store("wrong")
	u, _ := url.Parse(request.URL)
	m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
	if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("wrong nonce accepted: %v", err)
	}
}

func TestRefreshIsSingleFlightAndLogoutRevokesAndDeletes(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	request, _ := m.Begin(context.Background())
	p.nonce.Store(request.nonce)
	u, _ := url.Parse(request.URL)
	m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
	session, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := m.Refresh(context.Background(), session.ID); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if got := p.refreshCount.Load(); got != 1 {
		t.Fatalf("refresh count=%d, want 1", got)
	}
	if err := m.Logout(context.Background(), session.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Refresh(context.Background(), session.ID); !errors.Is(err, ErrNoSession) {
		t.Fatalf("credential survived logout: %v", err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.revoked) == 0 || p.revoked[0] == "" {
		t.Fatal("logout did not revoke a credential")
	}
}

func TestClaimValidationRejectsAudienceAZPAndTimeViolations(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	now := time.Now()
	valid := verifiedClaims{
		Issuer: p.server.URL, Subject: "subject", Audience: []string{"client"},
		Nonce: "nonce", IssuedAt: now.Unix(), NotBefore: now.Add(-time.Second).Unix(),
		Expiry: now.Add(5 * time.Minute).Unix(),
	}
	if !m.validateClaims(valid, "nonce") {
		t.Fatal("valid claims rejected")
	}
	cases := []verifiedClaims{valid, valid, valid, valid, valid}
	cases[0].Audience = []string{"other"}
	cases[1].Audience = []string{"client", "other"}
	cases[1].AZP = "other"
	cases[2].IssuedAt = now.Add(2 * time.Minute).Unix()
	cases[3].NotBefore = now.Add(2 * time.Minute).Unix()
	cases[4].Expiry = now.Add(2 * time.Hour).Unix()
	for index, claims := range cases {
		if m.validateClaims(claims, "nonce") {
			t.Fatalf("invalid claim case %d accepted", index)
		}
	}
}

func TestConfigurationRejectsNoneAndNonLoopbackHTTP(t *testing.T) {
	base := Options{
		Issuer: "http://192.168.1.2", ClientID: "client", Tenant: "tenant", Account: "account",
		RedirectURI: "http://127.0.0.1:1234/callback", AllowInsecureLoopback: true,
		Algorithms: []string{"RS256"}, HTTPClient: &http.Client{},
		Credentials: mustStore(t), Metadata: newMemoryMetadata(),
	}
	if _, err := New(base); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("private HTTP issuer accepted: %v", err)
	}
	base.Issuer = "https://issuer.example"
	base.Algorithms = []string{"none"}
	if _, err := New(base); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("none algorithm accepted: %v", err)
	}
}

func TestCanceledOperationsFailWithoutNetworkOrState(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.Begin(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("begin ignored cancellation: %v", err)
	}
	if _, err := m.Complete(ctx, Callback{State: "state", Code: "code"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("complete ignored cancellation: %v", err)
	}
}

func TestRejectsInvalidSignatureAndUnsupportedProviderAlgorithm(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	attacker, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p.signingKey = attacker
	request, _ := m.Begin(context.Background())
	p.nonce.Store(request.nonce)
	u, _ := url.Parse(request.URL)
	m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
	if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("invalid signature accepted: %v", err)
	}
	options := m.options
	options.Algorithms = []string{"RS512"}
	if _, err := New(options); !errors.Is(err, ErrProvider) {
		t.Fatalf("unsupported provider algorithm accepted: %v", err)
	}
}

func TestJWKSUnknownKidTriggersBoundedRotationFetch(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	first, _ := m.Begin(context.Background())
	p.nonce.Store(first.nonce)
	u, _ := url.Parse(first.URL)
	m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
	if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p.key, p.signingKey, p.kid = key, key, "key-2"
	second, _ := m.Begin(context.Background())
	p.nonce.Store(second.nonce)
	u, _ = url.Parse(second.URL)
	m.client.Transport = challengeTransport{base: p.server.Client().Transport, challenge: u.Query().Get("code_challenge")}
	if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); err != nil {
		t.Fatalf("rotated signing key rejected: %v", err)
	}
}

func mustStore(t *testing.T) *keystore.Store {
	t.Helper()
	store, err := keystore.New("palonexus-test", keystore.NewMemoryBackendForTesting())
	if err != nil {
		t.Fatal(err)
	}
	return store
}

type challengeTransport struct {
	base      http.RoundTripper
	challenge string
}

type memoryMetadata struct {
	mu    sync.Mutex
	value state.Metadata
	ok    bool
}

func newMemoryMetadata() *memoryMetadata { return &memoryMetadata{} }
func (m *memoryMetadata) PutMetadata(_ context.Context, _ state.Binding, value state.Metadata) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.value, m.ok = value, true
	return nil
}
func (m *memoryMetadata) GetMetadata(_ context.Context, _ state.Binding, _ state.Kind) (state.Metadata, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.ok {
		return state.Metadata{}, state.ErrNotFound
	}
	return m.value, nil
}
func (m *memoryMetadata) DeleteAccount(_ context.Context, _ state.Binding) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ok = false
	return nil
}

func (t challengeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("X-Test-Challenge", t.challenge)
	return t.base.RoundTrip(clone)
}
