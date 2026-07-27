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
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	if refreshErr != nil && !errors.Is(refreshErr, ErrNoSession) {
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

	session := loginForTest(t, m, p)
	p.revokeStatus.Store(http.StatusServiceUnavailable)
	if err := m.Logout(context.Background(), session.ID); !errors.Is(err, ErrPartial) || !errors.Is(err, ErrRevocation) {
		t.Fatalf("revocation failure not surfaced as partial: %v", err)
	}
	if _, err := m.options.Credentials.Get(context.Background(),
		credentialKey(m.options.Tenant, m.options.Account, session.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("local credential survived revocation outage: %v", err)
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
	metadata.failAfter.Store(true)
	if _, err := m.Refresh(context.Background(), session.ID); !errors.Is(err, ErrCommitIndeterminate) {
		t.Fatalf("refresh commit failure was not indeterminate: %v", err)
	}
	current, err := metadata.GetMetadata(context.Background(), state.Binding{}, state.KindSession)
	if err != nil || !current.Tombstoned {
		t.Fatalf("failed refresh was not tombstoned: %#v, %v", current, err)
	}
	if _, err := credentials.Get(context.Background(),
		credentialKey("tenant", "account", session.ID)); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("consumed refresh token was restored: %v", err)
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

type faultMetadata struct {
	*memoryMetadata
	failAfter atomic.Bool
}

type faultCredentials struct {
	*keystore.Store
	failPutAfter bool
	failDelete   bool
}

func (f *faultCredentials) Put(ctx context.Context, key keystore.Key, value []byte) error {
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
	err := m.memoryMetadata.WithSessionTransaction(ctx, binding, transaction)
	if err == nil && m.failAfter.CompareAndSwap(true, false) {
		return state.ErrDurabilityIndeterminate
	}
	return err
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

func (t challengeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	clone := r.Clone(r.Context())
	clone.Header.Set("X-Test-Challenge", t.challenge)
	return t.base.RoundTrip(clone)
}
