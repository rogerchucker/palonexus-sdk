// SPDX-License-Identifier: MIT
// Package decision implements the guard's fail-closed authorization transport.
package decision

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/config"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/normalize"
	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

const MaxResponseBytes = 256 << 10

// TokenSource transfers ownership of a fresh bearer-token buffer to the
// client. Decide overwrites the complete buffer before it returns. A source
// must return a distinct buffer for every concurrent call and honor ctx.
type TokenSource func(context.Context) ([]byte, error)

// TLSOptions is the complete caller-configurable TLS surface. It deliberately
// exposes no dial, verification, proxy, redirect, or RoundTripper hooks.
type TLSOptions struct {
	RootCAs            *x509.CertPool
	ClientCertificates []tls.Certificate
	MinVersion         uint16
	MaxVersion         uint16
}

type Options struct {
	Endpoint     string
	TLS          TLSOptions
	AccessToken  TokenSource
	Timeout      time.Duration
	MaxClockSkew time.Duration
	Now          func() time.Time
}

type Client struct {
	endpoint string
	http     *http.Client
	token    TokenSource
	now      func() time.Time
	skew     time.Duration
	timeout  time.Duration
}

func (*Client) String() string     { return "decision.Client{configuration:[REDACTED]}" }
func (c *Client) GoString() string { return c.String() }

type transportControls struct {
	resolver ipResolver
	dial     contextDialer
}

// New constructs the production HTTPS-only client.
func New(options Options) (*Client, error) {
	return newClient(options, false, transportControls{})
}

// NewFromConfig constructs a client from a configuration that has already
// enforced the file-plus-runtime local-test opt-in. Callers cannot enable
// plaintext transport through Options.
func NewFromConfig(configuration *config.Config, options Options) (*Client, error) {
	if configuration == nil || options.Endpoint != "" {
		return nil, ErrInvalidConfig
	}
	options.Endpoint = configuration.DecisionEndpoint()
	pem := configuration.TrustedCAPEM()
	parsedEndpoint, parseErr := url.Parse(options.Endpoint)
	if parseErr != nil {
		return nil, ErrInvalidConfig
	}
	if len(pem) != 0 && parsedEndpoint.Scheme != "https" {
		return nil, ErrInvalidConfig
	}
	if len(pem) != 0 && parsedEndpoint.Scheme == "https" {
		if options.TLS.RootCAs != nil {
			return nil, ErrInvalidConfig
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, ErrInvalidConfig
		}
		options.TLS.RootCAs = pool
	}
	return newClient(options, configuration.LocalTestMode(), transportControls{})
}

func newWithNetworkForTesting(options Options, controls transportControls) (*Client, error) {
	if controls.resolver == nil || controls.dial == nil {
		return nil, ErrInvalidConfig
	}
	return newClient(options, false, controls)
}

func newClient(options Options, allowLocalHTTP bool, controls transportControls) (*Client, error) {
	endpoint, scheme, localHTTP, err := validateEndpoint(options.Endpoint, allowLocalHTTP)
	if err != nil || options.AccessToken == nil {
		return nil, ErrInvalidConfig
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.MaxClockSkew < 0 {
		return nil, ErrInvalidConfig
	}
	if options.MaxClockSkew == 0 {
		options.MaxClockSkew = time.Minute
	}
	if options.MaxClockSkew > 5*time.Minute {
		return nil, ErrInvalidConfig
	}
	if options.Timeout < 0 {
		return nil, ErrInvalidConfig
	}
	if options.Timeout == 0 {
		options.Timeout = 10 * time.Second
	}
	if options.Timeout > 15*time.Second {
		return nil, ErrInvalidConfig
	}
	tlsConfig, err := buildTLSConfig(options.TLS, localHTTP)
	if err != nil {
		return nil, err
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	// Protocol v1 authorization is deliberately HTTP/1.1-only. Go's bundled
	// HTTP/2 transport may replay a stream refused before its body is consumed,
	// which conflicts with this client's strict zero-network-retry policy.
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	resolver := controls.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := controls.dial
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	if localHTTP {
		host := mustEndpointHost(endpoint)
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialLoopback(ctx, network, address, host, dial)
		}
	} else {
		transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			return dialResolved(ctx, network, address, resolver, dial)
		}
	}
	if scheme == "https" {
		transport.TLSClientConfig = tlsConfig
	} else {
		transport.TLSClientConfig = nil
	}
	return &Client{
		endpoint: endpoint,
		http:     &http.Client{Transport: transport, Timeout: options.Timeout, CheckRedirect: rejectRedirect},
		token:    options.AccessToken, now: options.Now, skew: options.MaxClockSkew,
		timeout: options.Timeout,
	}, nil
}

func buildTLSConfig(options TLSOptions, plaintext bool) (*tls.Config, error) {
	if plaintext {
		if options.RootCAs != nil || len(options.ClientCertificates) != 0 ||
			options.MinVersion != 0 || options.MaxVersion != 0 {
			return nil, ErrInvalidConfig
		}
		return nil, nil
	}
	minimum := options.MinVersion
	if minimum == 0 {
		minimum = tls.VersionTLS12
	}
	if minimum != tls.VersionTLS12 && minimum != tls.VersionTLS13 {
		return nil, ErrInvalidConfig
	}
	if options.MaxVersion != 0 &&
		(options.MaxVersion != tls.VersionTLS12 && options.MaxVersion != tls.VersionTLS13 ||
			options.MaxVersion < minimum) {
		return nil, ErrInvalidConfig
	}
	if len(options.ClientCertificates) > 8 {
		return nil, ErrInvalidConfig
	}
	certificates := make([]tls.Certificate, len(options.ClientCertificates))
	for index := range options.ClientCertificates {
		certificate, err := cloneCertificate(options.ClientCertificates[index])
		if err != nil {
			return nil, ErrInvalidConfig
		}
		certificates[index] = certificate
	}
	result := &tls.Config{
		MinVersion:   minimum,
		MaxVersion:   options.MaxVersion,
		Certificates: certificates,
	}
	if options.RootCAs != nil {
		result.RootCAs = options.RootCAs.Clone()
	}
	return result, nil
}

const (
	maxCertificateChain    = 8
	maxCertificateDERBytes = 1 << 20
)

func cloneCertificate(source tls.Certificate) (tls.Certificate, error) {
	if len(source.Certificate) == 0 || len(source.Certificate) > maxCertificateChain ||
		source.PrivateKey == nil {
		return tls.Certificate{}, ErrInvalidConfig
	}
	result := source
	result.Certificate = make([][]byte, len(source.Certificate))
	total := 0
	for index := range source.Certificate {
		if len(source.Certificate[index]) == 0 ||
			total > maxCertificateDERBytes-len(source.Certificate[index]) {
			return tls.Certificate{}, ErrInvalidConfig
		}
		total += len(source.Certificate[index])
		result.Certificate[index] = append([]byte(nil), source.Certificate[index]...)
	}
	result.SupportedSignatureAlgorithms =
		append([]tls.SignatureScheme(nil), source.SupportedSignatureAlgorithms...)
	result.OCSPStaple = append([]byte(nil), source.OCSPStaple...)
	result.SignedCertificateTimestamps = make([][]byte, len(source.SignedCertificateTimestamps))
	for index := range source.SignedCertificateTimestamps {
		result.SignedCertificateTimestamps[index] =
			append([]byte(nil), source.SignedCertificateTimestamps[index]...)
	}
	leaf, err := x509.ParseCertificate(result.Certificate[0])
	if err != nil {
		return tls.Certificate{}, ErrInvalidConfig
	}
	result.Leaf = leaf

	// Snapshot standard TLS private keys rather than retaining caller-owned
	// mutable pointers. Custom signer implementations are intentionally
	// rejected because their concurrency and mutation semantics are unknown.
	keyDER, err := x509.MarshalPKCS8PrivateKey(source.PrivateKey)
	if err != nil {
		return tls.Certificate{}, ErrInvalidConfig
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(keyDER)
	wipe(keyDER)
	if err != nil {
		return tls.Certificate{}, ErrInvalidConfig
	}
	signer, ok := privateKey.(crypto.Signer)
	if !ok {
		return tls.Certificate{}, ErrInvalidConfig
	}
	leafPublic, err1 := x509.MarshalPKIXPublicKey(leaf.PublicKey)
	keyPublic, err2 := x509.MarshalPKIXPublicKey(signer.Public())
	if err1 != nil || err2 != nil || !bytes.Equal(leafPublic, keyPublic) {
		return tls.Certificate{}, ErrInvalidConfig
	}
	result.PrivateKey = privateKey
	return result, nil
}

func rejectRedirect(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

func validateEndpoint(raw string, allowLocalHTTP bool) (string, string, bool, error) {
	for _, r := range raw {
		if r <= 0x1f || r == 0x7f {
			return "", "", false, ErrInvalidConfig
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" ||
		parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" ||
		parsed.ForceQuery || parsed.Fragment != "" || parsed.Opaque != "" ||
		strings.HasSuffix(parsed.Host, ":") || !validEndpointHost(parsed.Hostname()) ||
		!validEndpointPath(parsed) {
		return "", "", false, ErrInvalidConfig
	}
	if port := parsed.Port(); port != "" {
		number, portErr := strconv.Atoi(port)
		if portErr != nil || number < 1 || number > 65535 {
			return "", "", false, ErrInvalidConfig
		}
	}
	if parsed.Scheme == "https" {
		return parsed.String(), parsed.Scheme, false, nil
	}
	ip := net.ParseIP(parsed.Hostname())
	if parsed.Scheme != "http" || !allowLocalHTTP || ip == nil || !ip.IsLoopback() {
		return "", "", false, ErrInvalidConfig
	}
	return parsed.String(), parsed.Scheme, true, nil
}

func mustEndpointHost(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		panic("validated endpoint became invalid")
	}
	return parsed.Hostname()
}

var endpointDNSLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
var ambiguousNumericHost = regexp.MustCompile(`^(?:[0-9.]+|0[xX][0-9A-Fa-f]+)$`)

func validEndpointHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) > 253 || strings.HasSuffix(host, ".") || ambiguousNumericHost.MatchString(host) {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !endpointDNSLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func validEndpointPath(endpoint *url.URL) bool {
	if endpoint.RawPath != "" || strings.ContainsAny(endpoint.Path, "\\\r\n") ||
		strings.Contains(endpoint.Path, "//") {
		return false
	}
	if endpoint.Path == "" {
		return true
	}
	if !strings.HasPrefix(endpoint.Path, "/") {
		return false
	}
	for _, segment := range strings.Split(endpoint.Path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

func dialLoopback(
	ctx context.Context,
	network string,
	address string,
	expectedHost string,
	dial contextDialer,
) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("unsafe decision destination")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil || host != expectedHost {
		return nil, errors.New("unsafe decision destination")
	}
	ip := net.ParseIP(host)
	portNumber, portErr := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || portErr != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("unsafe decision destination")
	}
	return dial(ctx, network, net.JoinHostPort(ip.String(), port))
}

type contextDialer func(context.Context, string, string) (net.Conn, error)

func dialResolved(
	ctx context.Context,
	network string,
	address string,
	resolver ipResolver,
	dial contextDialer,
) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("unsafe decision destination")
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("unsafe decision destination")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, errors.New("unsafe decision destination")
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return nil, errors.New("decision destination unavailable")
	}
	for _, candidate := range ips {
		if candidate.Zone != "" || unsafeIP(candidate.IP) {
			return nil, errors.New("unsafe decision destination")
		}
	}
	// Pin the connection to one address from the validated answer, preventing a
	// second resolver lookup from changing the destination.
	return dial(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func unsafeIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return true
	}
	address = address.Unmap()
	if !address.IsGlobalUnicast() {
		return true
	}
	for _, prefix := range unsafeDestinationPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

var unsafeDestinationPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// ClientScopeHash computes the protocol-v1 client-visible scope binding.
func ClientScopeHash(request protocol.ActionRequest) (protocol.SHA256Digest, error) {
	if err := request.ValidateStructural(); err != nil {
		return "", ErrInvalidRequest
	}
	resourcePreimage := map[string]any{
		"preimageType": "palonexus.resource", "preimageVersion": "1",
		"kind": request.Target.Kind, "service": request.Target.Service,
		"resource": request.Target.Resource,
	}
	resourceJSON, err := canonicalJSON(resourcePreimage)
	if err != nil {
		return "", ErrInvalidRequest
	}
	resourceSum := sha256.Sum256(resourceJSON)
	expectedResourceHash := "sha256:" + hex.EncodeToString(resourceSum[:])
	if subtle.ConstantTimeCompare([]byte(expectedResourceHash), []byte(request.Target.ResourceHash)) != 1 {
		return "", ErrInvalidRequest
	}
	scope := map[string]any{
		"scopeType": "client", "scopeVersion": "1",
		"adapter":    map[string]any{"id": request.Adapter.ID, "version": request.Adapter.Version},
		"task":       map[string]any{"taskId": request.Task.TaskID, "sessionId": request.Task.SessionID},
		"action":     request.Action,
		"target":     map[string]any{"kind": request.Target.Kind, "service": request.Target.Service, "resourceHash": request.Target.ResourceHash},
		"sideEffect": request.SideEffect,
	}
	encoded, err := canonicalJSON(scope)
	if err != nil {
		return "", ErrInvalidRequest
	}
	sum := sha256.Sum256(encoded)
	return protocol.SHA256Digest("sha256:" + hex.EncodeToString(sum[:])), nil
}

func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return normalize.CanonicalJSON(raw)
}

func (c *Client) Decide(ctx context.Context, request protocol.ActionRequest) (protocol.AuthorizationDecision, error) {
	if ctx == nil {
		return protocol.AuthorizationDecision{}, unavailable()
	}
	if err := ctx.Err(); err != nil {
		return protocol.AuthorizationDecision{}, unavailable()
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	scope, err := ClientScopeHash(request)
	if err != nil {
		return protocol.AuthorizationDecision{}, err
	}
	body, err := json.Marshal(request)
	if err != nil {
		return protocol.AuthorizationDecision{}, ErrInvalidRequest
	}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, nil)
	if err != nil {
		return protocol.AuthorizationDecision{}, unavailable()
	}
	httpRequest.Body = io.NopCloser(bytes.NewReader(body))
	httpRequest.ContentLength = int64(len(body))
	// GetBody intentionally stays nil. net/http treats Idempotency-Key plus a
	// rewindable body as permission to replay a request on a failed reused
	// connection. Authorization attempts have explicit idempotency semantics,
	// but this client has a strict zero-retry policy.
	httpRequest.GetBody = nil
	token, err := c.token(ctx)
	if err != nil || !validBearerToken(token) {
		wipe(token)
		return protocol.AuthorizationDecision{}, unavailable()
	}
	httpRequest.Header.Set("Authorization", "Bearer "+string(token))
	httpRequest.Header.Set("Content-Type", "application/json")
	httpRequest.Header.Set("Accept", "application/json")
	httpRequest.Header.Set("Accept-Encoding", "identity")
	httpRequest.Header.Set("Idempotency-Key", string(request.IdempotencyKey))
	httpRequest.Header.Set("X-Palonexus-Protocol-Version", "1")
	response, err := func() (*http.Response, error) {
		// The standard library and TLS stack necessarily make transient string
		// and record copies. Remove our retained header immediately after Do
		// and overwrite the owned source buffer even if a test transport panics;
		// neither is kept in Client state or returned errors.
		defer func() {
			httpRequest.Header.Del("Authorization")
			wipe(token)
		}()
		return c.http.Do(httpRequest)
	}()
	if err != nil {
		return protocol.AuthorizationDecision{}, unavailable()
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return protocol.AuthorizationDecision{}, unavailable()
	}
	if !validResponseHeaders(response) {
		return protocol.AuthorizationDecision{}, ErrInvalidDecision
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil || len(document) > MaxResponseBytes {
		return protocol.AuthorizationDecision{}, ErrInvalidDecision
	}
	decision, err := protocol.ParseAuthorizationDecision(document)
	if err != nil || decision.RequestID != request.RequestID ||
		decision.CorrelationID != request.CorrelationID ||
		decision.ClientScopeHash != scope || decision.AuthoritativeScopeHash == "" {
		return protocol.AuthorizationDecision{}, ErrInvalidDecision
	}
	serverTime, err1 := parseTimestamp(string(decision.ServerTime))
	expiresAt, err2 := parseTimestamp(string(decision.ExpiresAt))
	now := c.now()
	if err1 != nil || err2 != nil || compareTimestamp(expiresAt, serverTime) <= 0 ||
		compareTimestamp(serverTime, timestampFromTime(now.Add(-c.skew))) < 0 ||
		compareTimestamp(serverTime, timestampFromTime(now.Add(c.skew))) > 0 ||
		compareTimestamp(expiresAt, timestampFromTime(now.Add(c.skew))) <= 0 {
		return protocol.AuthorizationDecision{}, ErrInvalidDecision
	}
	switch decision.Outcome {
	case protocol.DecisionOutcomeAllow:
		return decision, nil
	case protocol.DecisionOutcomeDeny, protocol.DecisionOutcomeApprovalRequired:
		return decision, &OutcomeError{Decision: decision}
	default:
		return protocol.AuthorizationDecision{}, ErrInvalidDecision
	}
}

var bearerToken = regexp.MustCompile(`^[A-Za-z0-9\-._~+/]+=*$`)

func validBearerToken(token []byte) bool {
	return len(token) != 0 && len(token) <= 16<<10 && bearerToken.Match(token)
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}

func validResponseHeaders(response *http.Response) bool {
	contentTypes := response.Header.Values("Content-Type")
	if len(contentTypes) != 1 {
		return false
	}
	mediaType, parameters, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || strings.ToLower(mediaType) != "application/json" {
		return false
	}
	if len(parameters) > 1 {
		return false
	}
	if charset, ok := parameters["charset"]; ok && !strings.EqualFold(charset, "utf-8") {
		return false
	}
	encodings := response.Header.Values("Content-Encoding")
	if len(encodings) > 1 ||
		len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return false
	}
	return response.ContentLength >= -1 && response.ContentLength <= MaxResponseBytes
}

var strictTimestamp = regexp.MustCompile(
	`^([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]+))?(Z|[+-][0-9]{2}:[0-9]{2})$`,
)

type exactTimestamp struct {
	seconds  int64
	fraction string
}

func parseTimestamp(value string) (exactTimestamp, error) {
	match := strictTimestamp.FindStringSubmatch(value)
	if match == nil {
		return exactTimestamp{}, errors.New("invalid timestamp")
	}
	base, err := time.Parse("2006-01-02T15:04:05Z07:00", match[1]+match[3])
	if err != nil {
		return exactTimestamp{}, errors.New("invalid timestamp")
	}
	return exactTimestamp{seconds: base.Unix(), fraction: strings.TrimRight(match[2], "0")}, nil
}

func timestampFromTime(value time.Time) exactTimestamp {
	return exactTimestamp{
		seconds:  value.Unix(),
		fraction: strings.TrimRight(fmt.Sprintf("%09d", value.Nanosecond()), "0"),
	}
}

func compareTimestamp(left, right exactTimestamp) int {
	if left.seconds < right.seconds {
		return -1
	}
	if left.seconds > right.seconds {
		return 1
	}
	width := len(left.fraction)
	if len(right.fraction) > width {
		width = len(right.fraction)
	}
	leftFraction := left.fraction + strings.Repeat("0", width-len(left.fraction))
	rightFraction := right.fraction + strings.Repeat("0", width-len(right.fraction))
	return strings.Compare(leftFraction, rightFraction)
}
