// Package auth implements the guard's verified OpenID Connect login session.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/keystore"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/state"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidConfig       = errors.New("invalid OIDC configuration")
	ErrProvider            = errors.New("OIDC provider unavailable")
	ErrInvalidCallback     = errors.New("invalid OIDC callback")
	ErrInvalidToken        = errors.New("invalid OIDC token")
	ErrNoSession           = errors.New("OIDC session not found")
	ErrStorage             = errors.New("OIDC session storage failed")
	ErrCommitIndeterminate = errors.New("OIDC session commit indeterminate; reauthentication required")
	ErrPartial             = errors.New("OIDC session operation partially completed")
	ErrRevocation          = errors.New("OIDC credential revocation failed")
)

const (
	maxDiscoveryBytes = 64 << 10
	maxJWKSBytes      = 256 << 10
	maxTokenBodyBytes = 64 << 10
	maxRevokeBytes    = 4 << 10
	maxJWKSKeys       = 32
	maxAttempts       = 32
)

type credentialStore interface {
	Put(context.Context, keystore.Key, []byte) error
	Get(context.Context, keystore.Key) ([]byte, error)
	Delete(context.Context, keystore.Key) error
}

type metadataStore interface {
	PutMetadata(context.Context, state.Binding, state.Metadata) error
	GetMetadata(context.Context, state.Binding, state.Kind) (state.Metadata, error)
	DeleteAccount(context.Context, state.Binding) error
	DeleteMetadata(context.Context, state.Binding, state.Kind) error
	WithSessionTransaction(context.Context, state.Binding, state.SessionTransaction) error
}

type Options struct {
	Issuer, ClientID, ClientSecret string
	RevocationAuthMethod           string
	Tenant, Account                string
	RedirectURI                    string
	Algorithms                     []string
	ClockSkew, MaxTokenLifetime    time.Duration
	HTTPClient                     *http.Client
	Credentials                    credentialStore
	Metadata                       metadataStore
	Now                            func() time.Time
	testing                        *testingOptions
}

type testingOptions struct{}

func newForTesting(options Options) (*Manager, error) {
	options.testing = &testingOptions{}
	return New(options)
}

type discovery struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	RevocationEndpoint    string   `json:"revocation_endpoint"`
	Algorithms            []string `json:"id_token_signing_alg_values_supported"`
}

type Manager struct {
	options   Options
	client    *http.Client
	mu        sync.Mutex
	config    *oauth2.Config
	verifier  *oidc.IDTokenVerifier
	discovery discovery
	attempts  map[string]attempt
	limits    *responseLimiter
}

type attempt struct {
	verifier, nonce, redirectURI string
	expires                      time.Time
}

type Authorization struct {
	URL      string
	state    string
	nonce    string
	verifier string
}

type Callback struct{ State, Code, Error string }

func New(options Options) (*Manager, error) {
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.ClockSkew <= 0 {
		options.ClockSkew = time.Minute
	}
	if options.MaxTokenLifetime <= 0 {
		options.MaxTokenLifetime = time.Hour
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: 10 * time.Second, Transport: hardenedTransport()}
	} else if options.testing == nil {
		base, ok := options.HTTPClient.Transport.(*http.Transport)
		if options.HTTPClient.Transport == nil {
			base = http.DefaultTransport.(*http.Transport)
			ok = true
		}
		if !ok {
			return nil, ErrInvalidConfig
		}
		secured := base.Clone()
		secured.Proxy = nil
		secured.DialContext = safeDial
		options.HTTPClient = &http.Client{Timeout: options.HTTPClient.Timeout, Transport: secured}
	}
	if options.Credentials == nil || options.Metadata == nil || options.ClientID == "" ||
		options.Tenant == "" || options.Account == "" || len(options.Algorithms) == 0 {
		return nil, ErrInvalidConfig
	}
	if options.RevocationAuthMethod == "" {
		if options.ClientSecret != "" {
			options.RevocationAuthMethod = "client_secret_basic"
		} else {
			options.RevocationAuthMethod = "none"
		}
	}
	if options.RevocationAuthMethod != "none" && options.RevocationAuthMethod != "client_secret_basic" &&
		options.RevocationAuthMethod != "client_secret_post" {
		return nil, ErrInvalidConfig
	}
	if options.RevocationAuthMethod != "none" && options.ClientSecret == "" {
		return nil, ErrInvalidConfig
	}
	for _, alg := range options.Algorithms {
		if alg != "RS256" && alg != "RS384" && alg != "RS512" &&
			alg != "ES256" && alg != "ES384" && alg != "ES512" && alg != "PS256" && alg != "PS384" && alg != "PS512" {
			return nil, ErrInvalidConfig
		}
	}
	if err := validateRemoteURL(options.Issuer, options.testing != nil); err != nil {
		return nil, ErrInvalidConfig
	}
	redirect, err := url.Parse(options.RedirectURI)
	if err != nil || redirect.Scheme != "http" || redirect.User != nil || redirect.RawQuery != "" ||
		redirect.Fragment != "" || net.ParseIP(redirect.Hostname()) == nil || !net.ParseIP(redirect.Hostname()).IsLoopback() ||
		redirect.Port() == "" {
		return nil, ErrInvalidConfig
	}
	client := *options.HTTPClient
	client.Timeout = boundedTimeout(client.Timeout)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	limiter := &responseLimiter{base: client.Transport, endpoints: make(map[string]responseKind)}
	client.Transport = limiter
	m := &Manager{options: options, client: &client, attempts: make(map[string]attempt), limits: limiter}
	if err := m.discover(context.Background()); err != nil {
		return nil, err
	}
	return m, nil
}

func boundedTimeout(value time.Duration) time.Duration {
	if value <= 0 || value > 15*time.Second {
		return 15 * time.Second
	}
	return value
}

func (m *Manager) discover(ctx context.Context) error {
	wellKnown, err := discoveryURL(m.options.Issuer)
	if err != nil {
		return ErrProvider
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, wellKnown, nil)
	if err != nil {
		return ErrProvider
	}
	resp, err := m.client.Do(req)
	if err != nil {
		return ErrProvider
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ContentLength > maxDiscoveryBytes {
		return ErrProvider
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDiscoveryBytes+1))
	if err != nil || len(body) > maxDiscoveryBytes {
		return ErrProvider
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	var document discovery
	if err := decoder.Decode(&document); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		document.Issuer != m.options.Issuer {
		return ErrProvider
	}
	for _, endpoint := range []string{document.AuthorizationEndpoint, document.TokenEndpoint, document.JWKSURI} {
		if validateRemoteURL(endpoint, m.options.testing != nil) != nil {
			return ErrProvider
		}
	}
	if document.RevocationEndpoint != "" && validateRemoteURL(document.RevocationEndpoint, m.options.testing != nil) != nil {
		return ErrProvider
	}
	if !containsAny(document.Algorithms, m.options.Algorithms) {
		return ErrProvider
	}
	ctx = oidc.ClientContext(ctx, m.client)
	if m.options.testing != nil {
		ctx = oidc.InsecureIssuerURLContext(ctx, m.options.Issuer)
	}
	keySet := oidc.NewRemoteKeySet(ctx, document.JWKSURI)
	m.verifier = oidc.NewVerifier(document.Issuer, keySet, &oidc.Config{
		ClientID: m.options.ClientID, SupportedSigningAlgs: append([]string(nil), m.options.Algorithms...),
		Now: m.options.Now,
	})
	m.discovery = document
	m.limits.configure(document)
	m.config = &oauth2.Config{
		ClientID: m.options.ClientID, ClientSecret: m.options.ClientSecret,
		Endpoint:    oauth2.Endpoint{AuthURL: document.AuthorizationEndpoint, TokenURL: document.TokenEndpoint},
		RedirectURL: m.options.RedirectURI, Scopes: []string{oidc.ScopeOpenID, "profile", "offline_access"},
	}
	return nil
}

type responseKind uint8

const (
	responseJWKS responseKind = iota + 1
	responseToken
	responseRevoke
)

type responseLimiter struct {
	base      http.RoundTripper
	mu        sync.RWMutex
	endpoints map[string]responseKind
}

func (l *responseLimiter) configure(document discovery) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.endpoints[document.JWKSURI] = responseJWKS
	l.endpoints[document.TokenEndpoint] = responseToken
	if document.RevocationEndpoint != "" {
		l.endpoints[document.RevocationEndpoint] = responseRevoke
	}
}

func (l *responseLimiter) RoundTrip(request *http.Request) (*http.Response, error) {
	base := l.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	limit := int64(maxDiscoveryBytes)
	l.mu.RLock()
	kind := l.endpoints[request.URL.String()]
	l.mu.RUnlock()
	switch kind {
	case responseJWKS:
		limit = maxJWKSBytes
	case responseToken:
		limit = maxTokenBodyBytes
	case responseRevoke:
		limit = maxRevokeBytes
	}
	if response.ContentLength > limit {
		response.Body.Close()
		return nil, ErrProvider
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit+1))
	response.Body.Close()
	if readErr != nil || int64(len(body)) > limit {
		return nil, ErrProvider
	}
	if (kind == responseJWKS || kind == responseToken || kind == 0) && !boundedJSONDepth(body, 16) {
		return nil, ErrProvider
	}
	if kind == responseJWKS && !validJWKSShape(body) {
		return nil, ErrProvider
	}
	response.Body = io.NopCloser(strings.NewReader(string(body)))
	response.ContentLength = int64(len(body))
	return response, nil
}

func boundedJSONDepth(document []byte, maximum int) bool {
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	depth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return depth == 0
		}
		if err != nil {
			return false
		}
		delimiter, ok := token.(json.Delim)
		if !ok {
			continue
		}
		switch delimiter {
		case '{', '[':
			depth++
			if depth > maximum {
				return false
			}
		case '}', ']':
			depth--
			if depth < 0 {
				return false
			}
		}
	}
}

func validJWKSShape(document []byte) bool {
	var value struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if !boundedJSONDepth(document, 16) || json.Unmarshal(document, &value) != nil ||
		len(value.Keys) == 0 || len(value.Keys) > maxJWKSKeys {
		return false
	}
	for _, key := range value.Keys {
		if len(key) > 16<<10 {
			return false
		}
	}
	return true
}

func discoveryURL(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.RawPath != "" || strings.Contains(strings.ToLower(u.EscapedPath()), "%2f") ||
		strings.Contains(strings.ToLower(u.EscapedPath()), "%5c") {
		return "", ErrInvalidConfig
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + "/.well-known/openid-configuration"
	return u.String(), nil
}

func validateRemoteURL(raw string, allowLocal bool) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Opaque != "" || u.User != nil || u.Hostname() == "" ||
		u.RawQuery != "" || u.Fragment != "" {
		return ErrInvalidConfig
	}
	ip := net.ParseIP(u.Hostname())
	if u.Scheme == "http" && allowLocal && ip != nil && ip.IsLoopback() {
		return nil
	}
	if u.Scheme != "https" {
		return ErrInvalidConfig
	}
	if ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()) {
		return ErrInvalidConfig
	}
	return nil
}

func hardenedTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = safeDial
	transport.MaxIdleConns = 16
	transport.MaxIdleConnsPerHost = 4
	transport.MaxConnsPerHost = 8
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.TLSHandshakeTimeout = 10 * time.Second
	return transport
}

func safeDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrProvider
	}
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addresses) == 0 {
		return nil, ErrProvider
	}
	for _, candidate := range addresses {
		if forbiddenDestination(net.IP(candidate.AsSlice())) {
			return nil, ErrProvider
		}
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	for _, candidate := range addresses {
		connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
		if dialErr == nil {
			return connection, nil
		}
	}
	return nil, ErrProvider
}

var forbiddenNetworks = func() []*net.IPNet {
	values := []string{
		"0.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
		"::/128", "::1/128", "fc00::/7", "fe80::/10", "2001:db8::/32", "ff00::/8",
	}
	result := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, _ := net.ParseCIDR(value)
		result = append(result, network)
	}
	return result
}()

func forbiddenDestination(ip net.IP) bool {
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	for _, network := range forbiddenNetworks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func containsAny(provider, allowed []string) bool {
	for _, p := range provider {
		for _, a := range allowed {
			if p == a {
				return true
			}
		}
	}
	return false
}

func (m *Manager) Begin(ctx context.Context) (Authorization, error) {
	if err := ctx.Err(); err != nil {
		return Authorization{}, err
	}
	stateValue, err := randomURL(32)
	if err != nil {
		return Authorization{}, ErrProvider
	}
	nonce, err := randomURL(32)
	if err != nil {
		return Authorization{}, ErrProvider
	}
	verifier, err := randomURL(48)
	if err != nil {
		return Authorization{}, ErrProvider
	}
	challenge := sha256.Sum256([]byte(verifier))
	m.mu.Lock()
	now := m.options.Now()
	for key, value := range m.attempts {
		if !value.expires.After(now) {
			delete(m.attempts, key)
		}
	}
	if len(m.attempts) >= maxAttempts {
		m.mu.Unlock()
		return Authorization{}, ErrProvider
	}
	m.attempts[stateValue] = attempt{verifier: verifier, nonce: nonce, redirectURI: m.options.RedirectURI, expires: now.Add(5 * time.Minute)}
	m.mu.Unlock()
	authURL := m.config.AuthCodeURL(stateValue, oauth2.AccessTypeOffline,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:])),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"))
	return Authorization{URL: authURL, state: stateValue, nonce: nonce, verifier: verifier}, nil
}

func randomURL(bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func constantEqual(left, right string) bool {
	return len(left) == len(right) && subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}

func sanitizeError(error) error { return ErrProvider }

func wrapInvalidToken(error) error { return ErrInvalidToken }

func credentialKey(tenant, account, sessionID string) keystore.Key {
	sum := sha256.Sum256([]byte(account))
	return keystore.Key{
		Tenant:  tenant,
		Account: "oidc-session-" + base64.RawURLEncoding.EncodeToString(sum[:]) + "-" + sessionID,
	}
}
