package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/keystore"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/state"
)

type providerFixture struct {
	server          *httptest.Server
	key             *rsa.PrivateKey
	signingKey      *rsa.PrivateKey
	kid             string
	clientID        string
	nonce           atomic.Value
	refreshCount    atomic.Int32
	mu              sync.Mutex
	revoked         []string
	revokeAuth      []string
	revokeForms     []url.Values
	revokeStatus    atomic.Int32
	discoveryStatus atomic.Int32
	tokenStatus     atomic.Int32
	jwksStatus      atomic.Int32
	mutateClaims    func(map[string]any)
	signingAlg      string
	revokeBlock     func(int)
	revokeCalls     atomic.Int32
	refreshBlock    func()
}

func newProvider(t *testing.T) *providerFixture {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p := &providerFixture{key: key, signingKey: key, kid: "key-1", clientID: "client", signingAlg: "RS256"}
	mux := http.NewServeMux()
	p.server = httptest.NewServer(mux)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		if status := p.discoveryStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.server.URL, "authorization_endpoint": p.server.URL + "/authorize",
			"token_endpoint": p.server.URL + "/token", "jwks_uri": p.server.URL + "/jwks",
			"revocation_endpoint":                   p.server.URL + "/revoke",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		if status := p.jwksStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		n := base64.RawURLEncoding.EncodeToString(p.key.PublicKey.N.Bytes())
		e := base64.RawURLEncoding.EncodeToString([]byte{1, 0, 1})
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]any{
			"kty": "RSA", "kid": p.kid, "use": "sig", "alg": "RS256", "n": n, "e": e,
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if status := p.tokenStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad request", 400)
			return
		}
		refreshing := r.Form.Get("grant_type") == "refresh_token"
		nonce, _ := p.nonce.Load().(string)
		if refreshing {
			p.refreshCount.Add(1)
			if p.refreshBlock != nil {
				p.refreshBlock()
			}
		} else {
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if r.Form.Get("code") != "valid-code" ||
				base64.RawURLEncoding.EncodeToString(sum[:]) != r.Header.Get("X-Test-Challenge") {
				http.Error(w, "invalid grant", 400)
				return
			}
		}
		now := time.Now()
		claims := map[string]any{
			"iss": p.server.URL, "aud": p.clientID, "sub": "subject",
			"nonce": nonce, "iat": now.Unix(), "nbf": now.Add(-time.Second).Unix(),
			"exp": now.Add(5 * time.Minute).Unix(),
		}
		if p.mutateClaims != nil {
			p.mutateClaims(claims)
		}
		raw, err := signRSA(p.signingKey, p.kid, p.signingAlg, claims)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "access-secret", "refresh_token": fmt.Sprintf("refresh-%d", p.refreshCount.Load()+1),
			"token_type": "Bearer", "expires_in": 300, "id_token": raw,
		})
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		call := int(p.revokeCalls.Add(1))
		if p.revokeBlock != nil {
			p.revokeBlock(call)
		}
		_ = r.ParseForm()
		p.mu.Lock()
		p.revoked = append(p.revoked, r.Form.Get("token"))
		p.revokeAuth = append(p.revokeAuth, r.Header.Get("Authorization"))
		p.revokeForms = append(p.revokeForms, r.Form)
		p.mu.Unlock()
		if status := p.revokeStatus.Load(); status != 0 {
			w.WriteHeader(int(status))
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	return p
}

func signRSA(key *rsa.PrivateKey, kid, algorithm string, claims map[string]any) (string, error) {
	header, _ := json.Marshal(map[string]string{"alg": algorithm, "kid": kid, "typ": "JWT"})
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
	manager, err := newForTesting(Options{
		Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "account",
		RedirectURI: "http://127.0.0.1:49152/callback",
		HTTPClient:  p.server.Client(), Credentials: secrets, Metadata: newMemoryMetadata(),
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
	failed, _ := m.Begin(context.Background())
	failedURL, _ := url.Parse(failed.URL)
	if _, err := m.Complete(context.Background(), Callback{State: failedURL.Query().Get("state"), Error: "access_denied"}); !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("provider callback error accepted: %v", err)
	}
	if _, err := m.Complete(context.Background(), Callback{State: failedURL.Query().Get("state"), Code: "valid-code"}); !errors.Is(err, ErrInvalidCallback) {
		t.Fatalf("state survived provider callback error: %v", err)
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
	results := make(chan Session, 12)
	errs := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			refreshed, refreshErr := m.Refresh(context.Background(), session.ID)
			results <- refreshed
			errs <- refreshErr
		}()
	}
	wg.Wait()
	close(results)
	close(errs)
	if got := p.refreshCount.Load(); got != 1 {
		t.Fatalf("refresh count=%d, want 1", got)
	}
	var current Session
	successes, stale := 0, 0
	for result := range results {
		if result.ID != "" {
			current = result
			successes++
		}
	}
	for refreshErr := range errs {
		switch {
		case refreshErr == nil:
		case errors.Is(refreshErr, ErrNoSession):
			stale++
		default:
			t.Fatalf("unexpected refresh result: %v", refreshErr)
		}
	}
	if successes != 1 || stale != 11 {
		t.Fatalf("refresh ownership results: successes=%d stale=%d", successes, stale)
	}
	if err := m.Logout(context.Background(), current.ID); err != nil {
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
		RedirectURI: "http://127.0.0.1:1234/callback",
		Algorithms:  []string{"RS256"}, HTTPClient: &http.Client{},
		Credentials: mustStore(t), Metadata: newMemoryMetadata(),
	}
	if _, err := newForTesting(base); !errors.Is(err, ErrInvalidConfig) {
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

func TestProviderOutageMatrixFailsClosed(t *testing.T) {
	t.Run("discovery", func(t *testing.T) {
		p := newProvider(t)
		defer p.Close()
		p.discoveryStatus.Store(http.StatusServiceUnavailable)
		if _, err := newForTesting(Options{
			Issuer: p.server.URL, ClientID: "client", Tenant: "tenant", Account: "account",
			RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
			Credentials: mustStore(t), Metadata: newMemoryMetadata(), Algorithms: []string{"RS256"},
		}); !errors.Is(err, ErrProvider) {
			t.Fatalf("discovery outage did not fail closed: %v", err)
		}
	})
	t.Run("token", func(t *testing.T) {
		p := newProvider(t)
		defer p.Close()
		m := testManager(t, p)
		request, _ := m.Begin(context.Background())
		p.tokenStatus.Store(http.StatusServiceUnavailable)
		u, _ := url.Parse(request.URL)
		if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); !errors.Is(err, ErrProvider) {
			t.Fatalf("token outage did not fail closed: %v", err)
		}
	})
	t.Run("jwks", func(t *testing.T) {
		p := newProvider(t)
		defer p.Close()
		m := testManager(t, p)
		request, _ := m.Begin(context.Background())
		p.nonce.Store(request.nonce)
		p.jwksStatus.Store(http.StatusServiceUnavailable)
		u, _ := url.Parse(request.URL)
		m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
		if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("JWKS outage did not fail closed: %v", err)
		}
	})
}

func TestAuthorizationAttemptCapacityAndExpiryCleanup(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	now := time.Now()
	m.options.Now = func() time.Time { return now }
	for range maxAttempts {
		if _, err := m.Begin(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Begin(context.Background()); !errors.Is(err, ErrProvider) {
		t.Fatalf("attempt capacity not enforced: %v", err)
	}
	now = now.Add(6 * time.Minute)
	if _, err := m.Begin(context.Background()); err != nil {
		t.Fatalf("expired attempts were not reclaimed: %v", err)
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

func TestSignedIDTokenAdversarialClaimMatrix(t *testing.T) {
	now := time.Now()
	cases := map[string]func(map[string]any){
		"issuer":   func(c map[string]any) { c["iss"] = "https://attacker.example" },
		"audience": func(c map[string]any) { c["aud"] = "other" },
		"azp":      func(c map[string]any) { c["aud"] = []string{"client", "other"}; c["azp"] = "other" },
		"expired":  func(c map[string]any) { c["exp"] = now.Add(-10 * time.Minute).Unix() },
		"expiry before issued": func(c map[string]any) {
			c["iat"] = now.Add(30 * time.Second).Unix()
			c["exp"] = now.Add(10 * time.Second).Unix()
		},
		"stale issued": func(c map[string]any) {
			c["iat"] = now.Add(-2 * time.Hour).Unix()
			c["exp"] = now.Add(5 * time.Minute).Unix()
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := newProvider(t)
			defer p.Close()
			p.mutateClaims = mutate
			m := testManager(t, p)
			request, _ := m.Begin(context.Background())
			p.nonce.Store(request.nonce)
			u, _ := url.Parse(request.URL)
			m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
			if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("invalid signed claims accepted: %v", err)
			}
		})
	}
	t.Run("disallowed token algorithm", func(t *testing.T) {
		p := newProvider(t)
		defer p.Close()
		p.signingAlg = "HS256"
		m := testManager(t, p)
		request, _ := m.Begin(context.Background())
		p.nonce.Store(request.nonce)
		u, _ := url.Parse(request.URL)
		m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
		if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("disallowed signed algorithm accepted: %v", err)
		}
	})
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

func TestMultipleLoginReplacesCredentialWithoutOrphan(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	login := func() Session {
		t.Helper()
		request, err := m.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		p.nonce.Store(request.nonce)
		u, _ := url.Parse(request.URL)
		base := m.client.Transport
		if previous, ok := base.(challengeTransport); ok {
			base = previous.base
		}
		m.client.Transport = challengeTransport{base: base, challenge: u.Query().Get("code_challenge")}
		session, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"})
		if err != nil {
			t.Fatal(err)
		}
		return session
	}
	first := login()
	second := login()
	if first.ID == second.ID {
		t.Fatal("login did not rotate session identifier")
	}
	if _, err := m.options.Credentials.Get(context.Background(),
		credentialKey(m.options.Tenant, m.options.Account, first.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("old credential survived replacement: %v", err)
	}
	metadata, err := m.options.Metadata.GetMetadata(context.Background(),
		state.Binding{Tenant: "tenant", Account: "account"}, state.KindSession)
	if err != nil || metadata.SessionID != second.ID || metadata.Generation != 2 {
		t.Fatalf("current session metadata mismatch: %#v, %v", metadata, err)
	}
}

func TestRefreshRejectsStaleAndGuessedSessionHandles(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	firstRequest, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.nonce.Store(firstRequest.nonce)
	firstURL, _ := url.Parse(firstRequest.URL)
	m.client.Transport = challengeTransport{base: m.client.Transport, challenge: firstURL.Query().Get("code_challenge")}
	first, err := m.Complete(context.Background(), Callback{
		State: firstURL.Query().Get("state"), Code: "valid-code",
	})
	if err != nil {
		t.Fatal(err)
	}
	second := loginForTest(t, m, p)
	for _, id := range []string{first.ID, "session_00000000000000000000000000"} {
		if _, err := m.Refresh(context.Background(), id); !errors.Is(err, ErrNoSession) {
			t.Fatalf("refresh accepted non-current handle %q: %v", id, err)
		}
	}
	current, err := m.options.Metadata.GetMetadata(context.Background(),
		state.Binding{Tenant: "tenant", Account: "account"}, state.KindSession)
	if err != nil || current.SessionID != second.ID || current.Tombstoned {
		t.Fatalf("non-current refresh changed current session: %#v, %v", current, err)
	}
}

func TestLogoutStaleHandlePreservesCurrentSessionAndOrphanLogoutIsIdempotent(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	first := loginForTest(t, m, p)
	second := loginForTest(t, m, p)
	if err := m.Logout(context.Background(), first.ID); err != nil {
		t.Fatalf("stale logout was not idempotent: %v", err)
	}
	current, err := m.options.Metadata.GetMetadata(context.Background(),
		state.Binding{Tenant: "tenant", Account: "account"}, state.KindSession)
	if err != nil || current.SessionID != second.ID {
		t.Fatalf("stale logout removed current session: %#v, %v", current, err)
	}
	if err := m.options.Metadata.DeleteMetadata(context.Background(),
		state.Binding{Tenant: "tenant", Account: "account"}, state.KindSession); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		err := m.Logout(context.Background(), first.ID)
		if err != nil && !errors.Is(err, ErrNoSession) && !errors.Is(err, ErrRevocation) {
			t.Fatalf("orphan cleanup was not idempotent: %v", err)
		}
	}
}

func TestProductionTransportRejectsTLSVerificationBypasses(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	base := p.server.Client().Transport.(*http.Transport).Clone()
	cases := map[string]func(*http.Transport){
		"insecure skip verify": func(tr *http.Transport) { tr.TLSClientConfig.InsecureSkipVerify = true },
		"verify peer hook": func(tr *http.Transport) {
			tr.TLSClientConfig.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		},
		"verify connection hook": func(tr *http.Transport) {
			tr.TLSClientConfig.VerifyConnection = func(tls.ConnectionState) error { return nil }
		},
		"dial TLS": func(tr *http.Transport) {
			tr.DialTLS = func(string, string) (net.Conn, error) { return nil, errors.New("unused") }
		},
		"dial TLS context": func(tr *http.Transport) {
			tr.DialTLSContext = func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("unused") }
		},
		"server name override": func(tr *http.Transport) { tr.TLSClientConfig.ServerName = "other.example" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			tr := base.Clone()
			if tr.TLSClientConfig == nil {
				tr.TLSClientConfig = &tls.Config{}
			}
			mutate(tr)
			_, err := New(Options{
				Issuer: "https://issuer.example", ClientID: "client", Tenant: "tenant", Account: "account",
				RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: &http.Client{Transport: tr},
				Credentials: mustStore(t), Metadata: newMemoryMetadata(), Algorithms: []string{"RS256"},
			})
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("unsafe transport accepted: %v", err)
			}
		})
	}
}

func TestSecureTransportPreservesTrustMaterialAndReplacesNetworkHooks(t *testing.T) {
	roots := x509.NewCertPool()
	certificates := []tls.Certificate{{Certificate: [][]byte{{1, 2, 3}}}}
	base := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unsafe custom dial")
		},
		TLSClientConfig: &tls.Config{RootCAs: roots, Certificates: certificates, MinVersion: tls.VersionTLS12},
	}
	secured, err := secureTransport(base)
	if err != nil {
		t.Fatal(err)
	}
	if secured.Proxy != nil || secured.TLSClientConfig.RootCAs != roots ||
		len(secured.TLSClientConfig.Certificates) != 1 ||
		secured.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatal("safe TLS trust material was not preserved")
	}
	if _, err := secured.DialContext(context.Background(), "tcp", "127.0.0.1:443"); !errors.Is(err, ErrProvider) {
		t.Fatalf("custom dial hook survived transport hardening: %v", err)
	}
}

func TestSecureTransportEnforcesTLS12FloorAndPreservesTLS13(t *testing.T) {
	for _, minimum := range []uint16{0, tls.VersionTLS10, tls.VersionTLS11} {
		secured, err := secureTransport(&http.Transport{
			TLSClientConfig: &tls.Config{MinVersion: minimum},
		})
		if err != nil {
			t.Fatalf("safe transport minimum %x was not hardened: %v", minimum, err)
		}
		if secured.TLSClientConfig.MinVersion != tls.VersionTLS12 {
			t.Fatalf("TLS minimum %x remained below TLS 1.2: %x", minimum, secured.TLSClientConfig.MinVersion)
		}
	}
	if _, err := secureTransport(&http.Transport{
		TLSClientConfig: &tls.Config{MaxVersion: tls.VersionTLS11},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("TLS maximum below 1.2 was accepted: %v", err)
	}
	secured, err := secureTransport(&http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13},
	})
	if err != nil || secured.TLSClientConfig.MinVersion != tls.VersionTLS13 ||
		secured.TLSClientConfig.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("strict TLS 1.3 configuration was not preserved: %#v, %v", secured, err)
	}
}

func TestDefaultHardenedTransportHasExplicitTLSAndHeaderBounds(t *testing.T) {
	transport := hardenedTransport()
	if transport.TLSClientConfig == nil ||
		transport.TLSClientConfig.MinVersion != tls.VersionTLS12 {
		t.Fatalf("default transport has no explicit TLS 1.2 floor: %#v", transport.TLSClientConfig)
	}
	if transport.MaxResponseHeaderBytes <= 0 || transport.MaxResponseHeaderBytes > 64<<10 {
		t.Fatalf("default response headers are not tightly bounded: %d", transport.MaxResponseHeaderBytes)
	}
}

func TestDiscoveryURLForRootAndPathIssuers(t *testing.T) {
	cases := map[string]string{
		"https://issuer.example":         "https://issuer.example/.well-known/openid-configuration",
		"https://issuer.example/tenant":  "https://issuer.example/tenant/.well-known/openid-configuration",
		"https://issuer.example/tenant/": "https://issuer.example/tenant/.well-known/openid-configuration",
	}
	for issuer, expected := range cases {
		actual, err := discoveryURL(issuer)
		if err != nil || actual != expected {
			t.Fatalf("discoveryURL(%q)=%q,%v want %q", issuer, actual, err, expected)
		}
	}
	for _, issuer := range []string{"https://issuer.example/a%2Fb", "https://issuer.example/a%5Cb"} {
		if _, err := discoveryURL(issuer); err == nil {
			t.Fatalf("ambiguous escaped issuer accepted: %s", issuer)
		}
	}
}

func TestForbiddenDestinationRejectsReservedAndDocumentationNetworks(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.1", "10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1",
		"192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1",
		"::1", "fc00::1", "fe80::1", "2001:db8::1", "ff02::1",
	} {
		if !forbiddenDestination(net.ParseIP(raw)) {
			t.Fatalf("reserved destination accepted: %s", raw)
		}
	}
	if forbiddenDestination(net.ParseIP("8.8.8.8")) {
		t.Fatal("public unicast destination rejected")
	}
	for _, raw := range []string{
		"https://100.64.0.1/oidc", "https://192.0.2.1/oidc",
		"https://198.51.100.1/oidc", "https://203.0.113.1/oidc",
	} {
		if validateRemoteURL(raw, false) == nil {
			t.Fatalf("literal forbidden endpoint accepted: %s", raw)
		}
	}
}

func TestResponseLimiterRejectsOversizedTokenAndExcessiveJWKSKeys(t *testing.T) {
	base := roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body := strings.Repeat("x", maxTokenBodyBytes+1)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})
	limiter := &responseLimiter{base: base, endpoints: map[string]responseKind{"https://issuer/token": responseToken}}
	request, _ := http.NewRequest(http.MethodPost, "https://issuer/token", nil)
	if _, err := limiter.RoundTrip(request); !errors.Is(err, ErrProvider) {
		t.Fatalf("oversized token response accepted: %v", err)
	}
	keys := make([]map[string]string, maxJWKSKeys+1)
	for index := range keys {
		keys[index] = map[string]string{"kty": "RSA"}
	}
	document, _ := json.Marshal(map[string]any{"keys": keys})
	if validJWKSShape(document) {
		t.Fatal("excessive JWKS key set accepted")
	}
}

func TestRefreshAndLogoutAcrossManagersCannotResurrectSession(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := state.New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	metadataSecond, err := state.New(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer metadataSecond.Close()
	credentials := mustStore(t)
	makeManager := func(store *state.Store) *Manager {
		manager, err := newForTesting(Options{
			Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "account",
			RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
			Credentials: credentials, Metadata: store, Algorithms: []string{"RS256"},
			ClockSkew: time.Minute, MaxTokenLifetime: time.Hour,
		})
		if err != nil {
			t.Fatal(err)
		}
		return manager
	}
	first, second := makeManager(metadata), makeManager(metadataSecond)
	request, _ := first.Begin(context.Background())
	p.nonce.Store(request.nonce)
	u, _ := url.Parse(request.URL)
	first.client.Transport = challengeTransport{base: first.client.Transport, challenge: u.Query().Get("code_challenge")}
	session, err := first.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"})
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var refreshErr, logoutErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		<-start
		_, refreshErr = first.Refresh(context.Background(), session.ID)
	}()
	go func() {
		defer wg.Done()
		<-start
		logoutErr = second.Logout(context.Background(), session.ID)
	}()
	close(start)
	wg.Wait()
	if refreshErr != nil && !errors.Is(refreshErr, ErrNoSession) &&
		!errors.Is(refreshErr, ErrCommitIndeterminate) {
		t.Fatalf("unexpected refresh result: %v", refreshErr)
	}
	if logoutErr != nil {
		t.Fatalf("logout failed: %v", logoutErr)
	}
	if _, err := first.Refresh(context.Background(), session.ID); !errors.Is(err, ErrNoSession) {
		t.Fatalf("session resurrected after logout: %v", err)
	}
}

func TestRevocationAuthenticatesAndSurfacesFailureAfterLocalCleanup(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	m.options.ClientSecret = "client-secret"
	m.options.RevocationAuthMethod = "client_secret_basic"
	if err := m.revoke(context.Background(), credential{RefreshToken: "refresh", AccessToken: "access"}); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	if len(p.revokeAuth) != 2 || !strings.HasPrefix(p.revokeAuth[0], "Basic ") ||
		p.revokeForms[0].Get("client_secret") != "" {
		t.Fatal("basic revocation authentication was not applied safely")
	}
	p.mu.Unlock()
	m.options.RevocationAuthMethod = "client_secret_post"
	if err := m.revoke(context.Background(), credential{RefreshToken: "refresh", AccessToken: "access"}); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	last := p.revokeForms[len(p.revokeForms)-1]
	if last.Get("client_id") != "client" || last.Get("client_secret") != "client-secret" {
		t.Fatal("post revocation authentication missing")
	}
	p.mu.Unlock()

	m.options.ClientID = "client id:with/slash"
	m.options.ClientSecret = "secret value+percent%"
	m.options.RevocationAuthMethod = "client_secret_basic"
	if err := m.revoke(context.Background(), credential{RefreshToken: "refresh", AccessToken: "access"}); err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	encoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimPrefix(
		p.revokeAuth[len(p.revokeAuth)-1], "Basic "))
	if decodeErr != nil || string(encoded) != url.QueryEscape(m.options.ClientID)+":"+url.QueryEscape(m.options.ClientSecret) {
		t.Fatalf("basic credentials were not RFC 6749 form-encoded: %q, %v", encoded, decodeErr)
	}
	p.mu.Unlock()
	m.options.ClientID = p.clientID
	m.options.ClientSecret = "client-secret"

	session := loginForTest(t, m, p)
	p.revokeStatus.Store(http.StatusServiceUnavailable)
	p.mu.Lock()
	beforeRevoke := len(p.revoked)
	p.mu.Unlock()
	if err := m.Logout(context.Background(), session.ID); !errors.Is(err, ErrPartial) || !errors.Is(err, ErrRevocation) {
		t.Fatalf("revocation failure not surfaced as partial: %v", err)
	}
	p.mu.Lock()
	if got := len(p.revoked) - beforeRevoke; got != 2 {
		p.mu.Unlock()
		t.Fatalf("revocation failure stopped before independently attempting both tokens: %d", got)
	}
	p.mu.Unlock()
	if _, err := m.options.Credentials.Get(context.Background(),
		credentialKey(m.options.Tenant, m.options.Account, session.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("local credential survived revocation outage: %v", err)
	}
}

func TestHangingRevocationCannotKeepLocalSessionLive(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	p.revokeBlock = func(_ int) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
	}
	m := testManager(t, p)
	session := loginForTest(t, m, p)
	done := make(chan error, 1)
	go func() { done <- m.Logout(context.Background(), session.ID) }()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("revocation request did not start")
	}
	metadataResult := make(chan error, 1)
	go func() {
		_, err := m.options.Metadata.GetMetadata(context.Background(),
			state.Binding{Tenant: "tenant", Account: "account"}, state.KindSession)
		metadataResult <- err
	}()
	select {
	case err := <-metadataResult:
		if !errors.Is(err, state.ErrNotFound) {
			close(release)
			<-done
			t.Fatalf("session metadata remained live during hanging revocation: %v", err)
		}
	case <-time.After(100 * time.Millisecond):
		close(release)
		<-done
		t.Fatal("hanging revocation retained the global state lock")
	}
	if _, err := m.options.Credentials.Get(context.Background(),
		credentialKey("tenant", "account", session.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("credential remained live during hanging revocation: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHangingFirstRevocationDoesNotPreventSecondAttempt(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	firstEntered, secondEntered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	p.revokeBlock = func(call int) {
		switch call {
		case 1:
			close(firstEntered)
			<-release
		case 2:
			close(secondEntered)
		}
	}
	m := testManager(t, p)
	done := make(chan error, 1)
	go func() {
		done <- m.revoke(context.Background(), credential{RefreshToken: "refresh", AccessToken: "access"})
	}()
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first revocation did not start")
	}
	select {
	case <-secondEntered:
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("hanging first revocation prevented independent second attempt")
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrRevocation) {
		t.Fatalf("timed-out first revocation was not aggregated: %v", err)
	}
}

func TestLogoutStateLockFailureStillDeletesCredentialAndReportsUncertainInvalidation(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	metadata := &faultMetadata{memoryMetadata: newMemoryMetadata()}
	credentials := mustStore(t)
	m, err := newForTesting(Options{
		Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "account",
		RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
		Credentials: credentials, Metadata: metadata, Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	session := loginForTest(t, m, p)
	metadata.failDeleteMetadata.Store(true)
	err = m.Logout(context.Background(), session.ID)
	if !errors.Is(err, ErrPartial) || !errors.Is(err, ErrCommitIndeterminate) {
		t.Fatalf("lock failure did not report uncertain invalidation: %v", err)
	}
	if _, err := credentials.Get(context.Background(),
		credentialKey("tenant", "account", session.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("credential survived state lock failure: %v", err)
	}
}

func TestLogoutCorruptCredentialFailsRevocationButStillRemovesLocalSession(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	session := loginForTest(t, m, p)
	if err := m.options.Credentials.Put(context.Background(),
		credentialKey("tenant", "account", session.ID), []byte("{corrupt")); err != nil {
		t.Fatal(err)
	}
	err := m.Logout(context.Background(), session.ID)
	if !errors.Is(err, ErrPartial) || !errors.Is(err, ErrRevocation) {
		t.Fatalf("corrupt credential did not surface revocation uncertainty: %v", err)
	}
	if _, err := m.options.Metadata.GetMetadata(context.Background(),
		state.Binding{Tenant: "tenant", Account: "account"}, state.KindSession); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("corrupt credential prevented metadata cleanup: %v", err)
	}
	if _, err := m.options.Credentials.Get(context.Background(),
		credentialKey("tenant", "account", session.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("corrupt credential survived logout: %v", err)
	}
}

func TestLogoutMatchingSessionWithMissingCredentialReportsRevocationUncertainty(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	session := loginForTest(t, m, p)
	if err := m.options.Credentials.Delete(context.Background(),
		credentialKey("tenant", "account", session.ID)); err != nil {
		t.Fatal(err)
	}
	err := m.Logout(context.Background(), session.ID)
	if !errors.Is(err, ErrPartial) || !errors.Is(err, ErrRevocation) {
		t.Fatalf("matching session with missing credential was reported as stale: %v", err)
	}
	if _, err := m.options.Metadata.GetMetadata(context.Background(),
		state.Binding{Tenant: "tenant", Account: "account"}, state.KindSession); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("matching missing credential prevented local invalidation: %v", err)
	}
}

func loginForTest(t *testing.T, m *Manager, p *providerFixture) Session {
	t.Helper()
	request, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.nonce.Store(request.nonce)
	u, _ := url.Parse(request.URL)
	base := m.client.Transport
	if previous, ok := base.(challengeTransport); ok {
		base = previous.base
	}
	m.client.Transport = challengeTransport{base: base, challenge: u.Query().Get("code_challenge")}
	session, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"})
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestRefreshCommitFailureTombstonesWithoutRestoringConsumedToken(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	baseMetadata := newMemoryMetadata()
	metadata := &faultMetadata{memoryMetadata: baseMetadata}
	credentials := mustStore(t)
	m, err := newForTesting(Options{
		Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "account",
		RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
		Credentials: credentials, Metadata: metadata, Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	session := loginForTest(t, m, p)
	metadata.failBeforeCall.Store(metadata.calls.Load() + 2)
	if _, err := m.Refresh(context.Background(), session.ID); !errors.Is(err, ErrCommitIndeterminate) {
		t.Fatalf("refresh commit failure was not indeterminate: %v", err)
	}
	current, err := metadata.GetMetadata(context.Background(), state.Binding{}, state.KindSession)
	if err != nil || !current.Tombstoned || current.PendingSessionID == "" ||
		current.PreviousSessionID != session.ID {
		t.Fatalf("failed refresh was not tombstoned: %#v, %v", current, err)
	}
	if _, err := credentials.Get(context.Background(),
		credentialKey("tenant", "account", session.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("consumed refresh token was restored: %v", err)
	}
	if _, err := credentials.Get(context.Background(),
		credentialKey("tenant", "account", current.PendingSessionID)); err != nil {
		t.Fatalf("pending credential was not journaled across activation crash boundary: %v", err)
	}
	if err := metadata.WithSessionLifecycle(context.Background(),
		state.Binding{Tenant: "tenant", Account: "account"}, func() error {
			return m.recoverSessionJournal(context.Background(),
				state.Binding{Tenant: "tenant", Account: "account"})
		}); err != nil {
		t.Fatal(err)
	}
	if _, err := credentials.Get(context.Background(),
		credentialKey("tenant", "account", current.PendingSessionID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("recovery retained pending credential after activation crash: %v", err)
	}
}

func TestRefreshCleanupFailuresAreTypedAndReservationRemainsFailClosed(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	metadata := &faultMetadata{memoryMetadata: newMemoryMetadata()}
	credentials := &faultCredentials{Store: mustStore(t)}
	m, err := newForTesting(Options{
		Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "account",
		RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
		Credentials: credentials, Metadata: metadata, Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	session := loginForTest(t, m, p)
	metadata.failBeforeFrom.Store(metadata.calls.Load() + 2)
	credentials.failDelete = true
	_, err = m.Refresh(context.Background(), session.ID)
	if !errors.Is(err, ErrPartial) || !errors.Is(err, ErrCommitIndeterminate) {
		t.Fatalf("cleanup uncertainty was not typed: %v", err)
	}
	partial := &PartialError{}
	if !errors.As(err, &partial) || !partial.LocalCleanupFailed || !partial.CommitUncertain {
		t.Fatalf("cleanup dimensions were not retained: %#v", err)
	}
	if _, retryErr := m.Refresh(context.Background(), session.ID); retryErr == nil {
		t.Fatalf("uncertain refresh reservation became usable: %v", retryErr)
	}
}

func TestSessionJournalRecoveryAfterCrashReopen(t *testing.T) {
	if os.Getenv("PALONEXUS_CRASH_RECOVERY_HELPER") == "1" {
		base := os.Getenv("PALONEXUS_CRASH_RECOVERY_ROOT")
		metadata, err := state.New(filepath.Join(base, "state"))
		if err != nil {
			t.Fatal(err)
		}
		defer metadata.Close()
		backend, err := keystore.NewEncryptedFileBackend(keystore.EncryptedFileOptions{
			Root: filepath.Join(base, "credentials"), Key: bytes.Repeat([]byte{9}, 32), EnableForTesting: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		credentials, err := keystore.New("palonexus-test", backend)
		if err != nil {
			t.Fatal(err)
		}
		defer credentials.Close()
		binding := state.Binding{Tenant: "tenant", Account: "account"}
		manager := &Manager{options: Options{
			Tenant: "tenant", Account: "account", Metadata: metadata, Credentials: credentials,
		}}
		if err := metadata.WithSessionLifecycle(context.Background(), binding, func() error {
			return manager.recoverSessionJournal(context.Background(), binding)
		}); err != nil {
			t.Fatal(err)
		}
		return
	}
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := filepath.Join(base, "state")
	credentialRoot := filepath.Join(base, "credentials")
	keyMaterial := bytes.Repeat([]byte{9}, 32)
	binding := state.Binding{Tenant: "tenant", Account: "account"}
	oldID := "session_00000000000000000000000000"
	pendingID := "session_00000000000000000000000001"

	metadata, err := state.New(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	backend, err := keystore.NewEncryptedFileBackend(keystore.EncryptedFileOptions{
		Root: credentialRoot, Key: keyMaterial, EnableForTesting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := keystore.New("palonexus-test", backend)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{oldID, pendingID} {
		if err := credentials.Put(context.Background(), credentialKey("tenant", "account", id), []byte("crash-secret")); err != nil {
			t.Fatal(err)
		}
	}
	journal := state.Metadata{
		Kind: state.KindSession, SessionID: oldID, PendingSessionID: pendingID,
		PreviousSessionID: oldID, SessionOperation: "refresh", Generation: 2,
		Tombstoned: true, OperationID: "operation_00000000000000000000000000",
	}
	if err := metadata.PutMetadata(context.Background(), binding, journal); err != nil {
		t.Fatal(err)
	}
	if err := metadata.Close(); err != nil {
		t.Fatal(err)
	}
	if err := credentials.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestSessionJournalRecoveryAfterCrashReopen$")
	command.Env = append(os.Environ(),
		"PALONEXUS_CRASH_RECOVERY_HELPER=1",
		"PALONEXUS_CRASH_RECOVERY_ROOT="+base,
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("recovery subprocess failed: %v\n%s", err, output)
	}

	reopenedMetadata, err := state.New(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedMetadata.Close()
	reopenedBackend, err := keystore.NewEncryptedFileBackend(keystore.EncryptedFileOptions{
		Root: credentialRoot, Key: keyMaterial, EnableForTesting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	reopenedCredentials, err := keystore.New("palonexus-test", reopenedBackend)
	if err != nil {
		t.Fatal(err)
	}
	defer reopenedCredentials.Close()
	if _, err := reopenedMetadata.GetMetadata(context.Background(), binding, state.KindSession); !errors.Is(err, state.ErrNotFound) {
		t.Fatalf("crash journal survived reopen recovery: %v", err)
	}
	for _, id := range []string{oldID, pendingID} {
		if _, err := reopenedCredentials.Get(context.Background(),
			credentialKey("tenant", "account", id)); !errors.Is(err, keystore.ErrNotFound) {
			t.Fatalf("journal-owned credential %s survived crash recovery: %v", id, err)
		}
	}
}

func TestStaleJournalAbortNeverDeletesSupersedingSession(t *testing.T) {
	metadata := newMemoryMetadata()
	credentials := mustStore(t)
	manager := &Manager{options: Options{
		Tenant: "tenant", Account: "account", Metadata: metadata, Credentials: credentials,
	}}
	binding := state.Binding{Tenant: "tenant", Account: "account"}
	stale := state.Metadata{
		Kind: state.KindSession, SessionID: "session_00000000000000000000000000",
		PendingSessionID:  "session_00000000000000000000000001",
		PreviousSessionID: "session_00000000000000000000000000",
		SessionOperation:  "refresh", Generation: 2, Tombstoned: true,
		OperationID: "operation_00000000000000000000000000",
	}
	superseding := state.Metadata{
		Kind: state.KindSession, SessionID: "session_00000000000000000000000002",
		Generation: 3, ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := metadata.PutMetadata(context.Background(), binding, superseding); err != nil {
		t.Fatal(err)
	}
	if err := credentials.Put(context.Background(),
		credentialKey("tenant", "account", superseding.SessionID), []byte("current-secret")); err != nil {
		t.Fatal(err)
	}
	if err := manager.abortSessionJournal(context.Background(), binding, stale, ErrCommitIndeterminate); !errors.Is(err, ErrCommitIndeterminate) {
		t.Fatalf("stale abort returned unexpected error: %v", err)
	}
	current, err := metadata.GetMetadata(context.Background(), binding, state.KindSession)
	if err != nil || current.SessionID != superseding.SessionID {
		t.Fatalf("stale abort changed superseding metadata: %#v, %v", current, err)
	}
	if _, err := credentials.Get(context.Background(),
		credentialKey("tenant", "account", superseding.SessionID)); err != nil {
		t.Fatalf("stale abort deleted superseding credential: %v", err)
	}
}

func TestRefreshPersistsReservationBeforeNetworkAndDoesNotHoldStateLock(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	tempRoot, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(tempRoot, "state")
	metadata, err := state.New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	other, err := state.New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	m, err := newForTesting(Options{
		Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "account",
		RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
		Credentials: mustStore(t), Metadata: metadata, Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	session := loginForTest(t, m, p)
	entered, release := make(chan struct{}), make(chan struct{})
	base := m.client.Transport
	m.client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.URL.Path == "/token" {
			record, getErr := other.GetMetadata(context.Background(),
				state.Binding{Tenant: "tenant", Account: "account"}, state.KindSession)
			if getErr != nil || !record.Tombstoned || record.SessionID != session.ID || record.OperationID == "" {
				t.Errorf("refresh reached provider without durable reservation: %#v, %v", record, getErr)
			}
			close(entered)
			<-release
		}
		return base.RoundTrip(request)
	})
	done := make(chan error, 1)
	go func() {
		_, refreshErr := m.Refresh(context.Background(), session.ID)
		done <- refreshErr
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not reach provider")
	}
	if err := other.PutMetadata(context.Background(),
		state.Binding{Tenant: "tenant", Account: "other"}, state.Metadata{Kind: state.KindRouting, RouteID: "route-default"}); err != nil {
		t.Fatalf("slow IdP call held root state lock: %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestSupersedingLoginSurvivesInFlightRefreshCleanup(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	m := testManager(t, p)
	firstRequest, err := m.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	p.nonce.Store(firstRequest.nonce)
	firstURL, _ := url.Parse(firstRequest.URL)
	m.client.Transport = challengeTransport{base: m.client.Transport, challenge: firstURL.Query().Get("code_challenge")}
	first, err := m.Complete(context.Background(), Callback{
		State: firstURL.Query().Get("state"), Code: "valid-code",
	})
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	p.refreshBlock = func() {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
	}
	done := make(chan error, 1)
	go func() {
		_, err := m.Refresh(context.Background(), first.ID)
		done <- err
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("refresh did not reach provider")
	}
	type loginResult struct {
		session Session
		err     error
	}
	loginDone := make(chan loginResult, 1)
	go func() {
		request, beginErr := m.Begin(context.Background())
		if beginErr != nil {
			loginDone <- loginResult{err: beginErr}
			return
		}
		p.nonce.Store(request.nonce)
		callbackURL, _ := url.Parse(request.URL)
		base := m.client.Transport
		if previous, ok := base.(challengeTransport); ok {
			base = previous.base
		}
		m.client.Transport = challengeTransport{base: base, challenge: callbackURL.Query().Get("code_challenge")}
		session, completeErr := m.Complete(context.Background(), Callback{
			State: callbackURL.Query().Get("state"), Code: "valid-code",
		})
		loginDone <- loginResult{session: session, err: completeErr}
	}()
	select {
	case result := <-loginDone:
		t.Fatalf("same-account login bypassed the in-flight lifecycle: %#v (%v)", result, result.err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("serialized refresh failed: %v", err)
	}
	second := <-loginDone
	if second.err != nil {
		t.Fatalf("queued replacement login failed: %v", second.err)
	}
	current, err := m.options.Metadata.GetMetadata(context.Background(),
		state.Binding{Tenant: "tenant", Account: "account"}, state.KindSession)
	if err != nil || current.SessionID != second.session.ID || current.Tombstoned {
		t.Fatalf("refresh cleanup removed superseding login: %#v, %v", current, err)
	}
	if _, err := m.options.Credentials.Get(context.Background(),
		credentialKey("tenant", "account", first.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("replacement left original credential: %v", err)
	}
	if _, err := m.options.Credentials.Get(context.Background(),
		credentialKey("tenant", "account", second.session.ID)); err != nil {
		t.Fatalf("replacement credential was not committed: %v", err)
	}
}

func TestInitialCredentialWriteAndCleanupFailureIsIndeterminate(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	base := mustStore(t)
	credentials := &faultCredentials{Store: base, failPutAfter: true, failDelete: true}
	m, err := newForTesting(Options{
		Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "account",
		RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
		Credentials: credentials, Metadata: newMemoryMetadata(), Algorithms: []string{"RS256"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request, _ := m.Begin(context.Background())
	p.nonce.Store(request.nonce)
	u, _ := url.Parse(request.URL)
	m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
	if _, err := m.Complete(context.Background(), Callback{State: u.Query().Get("state"), Code: "valid-code"}); !errors.Is(err, ErrCommitIndeterminate) {
		t.Fatalf("uncertain keyring write/cleanup not indeterminate: %v", err)
	}
}

func TestInitialMetadataCommitReconcilesPostWriteAndCleansPreWrite(t *testing.T) {
	p := newProvider(t)
	defer p.Close()
	t.Run("post-write is committed success", func(t *testing.T) {
		metadata := &faultMetadata{memoryMetadata: newMemoryMetadata()}
		metadata.failAfterCall.Store(1)
		m, err := newForTesting(Options{
			Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "post",
			RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
			Credentials: mustStore(t), Metadata: metadata, Algorithms: []string{"RS256"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if session := loginForTest(t, m, p); session.ID == "" {
			t.Fatal("reconciled committed login returned no session")
		}
	})
	t.Run("post-write replacement deletes predecessor", func(t *testing.T) {
		metadata := &faultMetadata{memoryMetadata: newMemoryMetadata()}
		credentials := mustStore(t)
		m, err := newForTesting(Options{
			Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "replace",
			RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
			Credentials: credentials, Metadata: metadata, Algorithms: []string{"RS256"},
		})
		if err != nil {
			t.Fatal(err)
		}
		first := loginForTest(t, m, p)
		metadata.failAfterCall.Store(metadata.calls.Load() + 2)
		second := loginForTest(t, m, p)
		if _, err := credentials.Get(context.Background(),
			credentialKey("tenant", "replace", first.ID)); !errors.Is(err, keystore.ErrNotFound) {
			t.Fatalf("reconciled replacement retained predecessor: %v", err)
		}
		if _, err := credentials.Get(context.Background(),
			credentialKey("tenant", "replace", second.ID)); err != nil {
			t.Fatalf("reconciled replacement lost current credential: %v", err)
		}
	})
	t.Run("pre-write leaves no credential", func(t *testing.T) {
		metadata := &faultMetadata{memoryMetadata: newMemoryMetadata()}
		metadata.failBeforeCall.Store(1)
		credentials := &faultCredentials{Store: mustStore(t)}
		m, err := newForTesting(Options{
			Issuer: p.server.URL, ClientID: p.clientID, Tenant: "tenant", Account: "pre",
			RedirectURI: "http://127.0.0.1:49152/callback", HTTPClient: p.server.Client(),
			Credentials: credentials, Metadata: metadata, Algorithms: []string{"RS256"},
		})
		if err != nil {
			t.Fatal(err)
		}
		request, err := m.Begin(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		p.nonce.Store(request.nonce)
		u, _ := url.Parse(request.URL)
		m.client.Transport = challengeTransport{base: m.client.Transport, challenge: u.Query().Get("code_challenge")}
		if _, err := m.Complete(context.Background(), Callback{
			State: u.Query().Get("state"), Code: "valid-code",
		}); !errors.Is(err, ErrCommitIndeterminate) {
			t.Fatalf("pre-write failure was not indeterminate: %v", err)
		}
		if metadata.memoryMetadata.ok {
			t.Fatal("pre-write failure unexpectedly installed session metadata")
		}
		if credentials.lastPut.Tenant != "" {
			if _, getErr := credentials.Get(context.Background(), credentials.lastPut); !errors.Is(getErr, keystore.ErrNotFound) {
				t.Fatalf("pre-write failure orphaned credential: %v", getErr)
			}
		}
	})
}

type faultMetadata struct {
	*memoryMetadata
	failAfter          atomic.Bool
	failBefore         atomic.Bool
	calls              atomic.Int32
	failAfterCall      atomic.Int32
	failBeforeCall     atomic.Int32
	failBeforeFrom     atomic.Int32
	failDeleteMetadata atomic.Bool
}

type faultCredentials struct {
	*keystore.Store
	failPutAfter bool
	failDelete   bool
	lastPut      keystore.Key
}

func (f *faultCredentials) Put(ctx context.Context, key keystore.Key, value []byte) error {
	f.lastPut = key
	err := f.Store.Put(ctx, key, value)
	if err == nil && f.failPutAfter {
		f.failPutAfter = false
		return keystore.ErrUnavailable
	}
	return err
}

func (f *faultCredentials) Delete(ctx context.Context, key keystore.Key) error {
	if f.failDelete {
		return keystore.ErrUnavailable
	}
	return f.Store.Delete(ctx, key)
}

func (m *faultMetadata) WithSessionTransaction(ctx context.Context, binding state.Binding, transaction state.SessionTransaction) error {
	call := m.calls.Add(1)
	if m.failBefore.CompareAndSwap(true, false) ||
		(m.failBeforeCall.Load() != 0 && m.failBeforeCall.Load() == call) ||
		(m.failBeforeFrom.Load() != 0 && call >= m.failBeforeFrom.Load()) {
		return state.ErrUnsafePath
	}
	err := m.memoryMetadata.WithSessionTransaction(ctx, binding, transaction)
	if err == nil && (m.failAfter.CompareAndSwap(true, false) ||
		(m.failAfterCall.Load() != 0 && m.failAfterCall.Load() == call)) {
		return state.ErrDurabilityIndeterminate
	}
	return err
}

func (m *faultMetadata) DeleteMetadata(ctx context.Context, binding state.Binding, kind state.Kind) error {
	if m.failDeleteMetadata.CompareAndSwap(true, false) {
		return state.ErrUnsafePath
	}
	return m.memoryMetadata.DeleteMetadata(ctx, binding, kind)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

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
	mu          sync.Mutex
	lifecycleMu sync.Mutex
	value       state.Metadata
	ok          bool
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
func (m *memoryMetadata) DeleteMetadata(_ context.Context, _ state.Binding, _ state.Kind) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ok = false
	return nil
}
func (m *memoryMetadata) WithSessionTransaction(_ context.Context, _ state.Binding, transaction state.SessionTransaction) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	next, err := transaction(m.value, m.ok)
	if err != nil {
		return err
	}
	if next == nil {
		m.ok = false
		return nil
	}
	m.value, m.ok = *next, true
	return nil
}
func (m *memoryMetadata) WithSessionLifecycle(ctx context.Context, _ state.Binding, lifecycle state.SessionLifecycle) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	return lifecycle()
}

func (t challengeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("X-Test-Challenge", t.challenge)
	return t.base.RoundTrip(clone)
}
