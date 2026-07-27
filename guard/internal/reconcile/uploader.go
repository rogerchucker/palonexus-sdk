package reconcile

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	p "github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

type HTTPConfig struct {
	Endpoint     string
	TrustedCAPEM []byte
	Token        func(context.Context) ([]byte, error)
	Binding      Binding
	ClientID     string
	Clock        func() time.Time
	Timeout      time.Duration
}

type HTTPTransport struct {
	endpoint string
	client   *http.Client
	token    func(context.Context) ([]byte, error)
	binding  Binding
	clientID string
	clock    func() time.Time
}

type ipResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}
type contextDialer func(context.Context, string, string) (net.Conn, error)
type networkControls struct {
	resolver ipResolver
	dial     contextDialer
}

var endpointDNSLabel = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func NewHTTPTransport(config HTTPConfig) (*HTTPTransport, error) {
	return newHTTPTransport(config, networkControls{})
}

func newHTTPTransportWithNetwork(config HTTPConfig, controls networkControls) (*HTTPTransport, error) {
	if controls.resolver == nil || controls.dial == nil {
		return nil, ErrUnsafeRecord
	}
	return newHTTPTransport(config, controls)
}

func newHTTPTransport(config HTTPConfig, controls networkControls) (*HTTPTransport, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Fragment != "" || endpoint.RawQuery != "" || endpoint.Opaque != "" || endpoint.RawPath != "" ||
		!validEndpointPath(endpoint.Path) || !validEndpointHost(endpoint) ||
		!validBinding(config.Binding) || config.ClientID == "" || config.Token == nil {
		return nil, ErrUnsafeRecord
	}
	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}
	if config.Timeout < time.Millisecond || config.Timeout > 15*time.Second {
		return nil, ErrUnsafeRecord
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableCompression = true
	transport.DisableKeepAlives = true
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if len(config.TrustedCAPEM) > 0 {
		if len(config.TrustedCAPEM) > 1<<20 {
			return nil, ErrUnsafeRecord
		}
		pool := x509.NewCertPool()
		rest := config.TrustedCAPEM
		count := 0
		for len(rest) > 0 {
			block, next := pem.Decode(rest)
			if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(block.Bytes) == 0 || len(block.Bytes) > 1<<20 {
				return nil, ErrUnsafeRecord
			}
			certificate, parseErr := x509.ParseCertificate(block.Bytes)
			if parseErr != nil {
				return nil, ErrUnsafeRecord
			}
			pool.AddCert(certificate)
			count++
			if count > 128 {
				return nil, ErrUnsafeRecord
			}
			rest = next
		}
		tlsConfig.RootCAs = pool
	}
	transport.TLSClientConfig = tlsConfig
	resolver := controls.resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dial := controls.dial
	if dial == nil {
		dialer := &net.Dialer{}
		dial = dialer.DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialResolved(ctx, network, address, resolver, dial)
	}
	client := &http.Client{Transport: transport, Timeout: config.Timeout}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	clock := config.Clock
	if clock == nil {
		clock = time.Now
	}
	return &HTTPTransport{endpoint: endpoint.String(), client: client, token: config.Token,
		binding: config.Binding, clientID: config.ClientID, clock: clock}, nil
}

func (t *HTTPTransport) Send(ctx context.Context, record p.ReconciliationRecord) (VerifiedReceipt, error) {
	if t == nil || record.ClientID != t.clientID {
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
	}
	body, err := validateRecord(record, maxRecordBytesDefault)
	if err != nil {
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
	}
	token, err := t.token(ctx)
	if err != nil {
		wipe(token)
		if ctxErr := ctx.Err(); ctxErr != nil {
			return VerifiedReceipt{}, ctxErr
		}
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryTransient}
	}
	if len(token) == 0 || bytes.ContainsAny(token, "\r\n") || len(token) > 8192 {
		wipe(token)
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryAuthentication}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
	}
	request.GetBody = nil
	request.Header.Set("Authorization", "Bearer "+string(token))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := func() (*http.Response, error) {
		defer func() { request.Header.Del("Authorization"); wipe(token) }()
		return t.client.Do(request)
	}()
	if err != nil {
		return VerifiedReceipt{}, &DeliveryError{Class: classifyNetworkError(err)}
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		switch response.StatusCode {
		case http.StatusUnauthorized, http.StatusForbidden:
			return VerifiedReceipt{}, &DeliveryError{Class: DeliveryAuthentication}
		case http.StatusConflict:
			return VerifiedReceipt{}, &DeliveryError{Class: DeliveryConflict}
		case http.StatusTooManyRequests:
			return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRateLimit, RetryAfter: parseRetryAfter(response.Header.Get("Retry-After"))}
		default:
			if response.StatusCode >= 500 {
				return VerifiedReceipt{}, &DeliveryError{Class: DeliveryTransient}
			}
			return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
		}
	}
	if !strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		// A 2xx response whose body could not be read completely may have
		// contained the acknowledgement. Treat it as ambiguous acknowledgement
		// loss so the identical reconciliation/evidence is retried.
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryTransient}
	}
	if len(document) > maxResponseBytes {
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
	}
	var public p.ReconciliationAcknowledgement
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&public) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
	}
	hash, err := evidenceHash(record)
	if err != nil || public.ReconciliationID != record.ReconciliationID || public.EvidenceHash != hash {
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryConflict}
	}
	at, err := parseTime(public.AcknowledgedAt)
	if err != nil {
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
	}
	return mintVerifiedReceipt(record, public.ReceiptID, at, t.clock().UTC(), t.binding, t.clientID)
}

func classifyNetworkError(err error) DeliveryErrorClass {
	var unknown x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	var record tls.RecordHeaderError
	if errors.As(err, &unknown) || errors.As(err, &hostname) || errors.As(err, &invalid) || errors.As(err, &record) {
		return DeliveryAuthentication
	}
	return DeliveryTransient
}

func validEndpointPath(path string) bool {
	if path == "" {
		return true
	}
	if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\\\r\n") || strings.Contains(path, "//") {
		return false
	}
	for _, segment := range strings.Split(path, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func validEndpointHost(endpoint *url.URL) bool {
	host := endpoint.Hostname()
	if host == "" || strings.Contains(host, "%") {
		return false
	}
	if port := endpoint.Port(); port != "" {
		value, err := strconv.Atoi(port)
		if err != nil || value < 1 || value > 65535 {
			return false
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return true
	}
	if len(host) > 253 || strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if !endpointDNSLabel.MatchString(label) {
			return false
		}
	}
	return true
}

func wipe(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func dialResolved(ctx context.Context, network, address string, resolver ipResolver, dial contextDialer) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, ErrTransport
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrTransport
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return nil, ErrTransport
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 || len(ips) > 64 {
		return nil, ErrTransport
	}
	for _, candidate := range ips {
		if candidate.Zone != "" || unsafeIP(candidate.IP) {
			return nil, ErrTransport
		}
	}
	return dial(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
}

func unsafeIP(ip net.IP) bool {
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
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"), netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func parseRetryAfter(value string) time.Duration {
	seconds, err := strconv.ParseUint(value, 10, 32)
	if err != nil || seconds > 86_400 {
		return 0
	}
	return time.Duration(seconds) * time.Second
}

// Uploader performs one explicit delivery attempt. Scheduling and retries are
// caller-owned so a single call can never conceal additional network effects.
type Uploader struct {
	Queue   *Queue
	Binding Binding
	Clock   func() time.Time
	Send    func(context.Context, p.ReconciliationRecord) (VerifiedReceipt, error)
}

func (u Uploader) Attempt(ctx context.Context) error {
	if u.Queue == nil || u.Clock == nil || u.Send == nil || !validBinding(u.Binding) {
		return ErrUnsafeRecord
	}
	now := u.Clock().UTC()
	record, err := u.Queue.Claim(ctx, u.Binding, now)
	if err != nil {
		return err
	}
	receipt, sendErr := u.Send(ctx, record)
	if sendErr != nil {
		class := DeliveryTransient
		var delivery *DeliveryError
		if errors.As(sendErr, &delivery) {
			class = delivery.Class
		}
		var persistErr error
		if class == DeliveryTransient || class == DeliveryRateLimit {
			minimum := time.Duration(0)
			if delivery != nil {
				minimum = delivery.RetryAfter
			}
			_, persistErr = u.Queue.impl.fail(ctx, u.Binding, record.ReconciliationID, u.Clock().UTC(), true, minimum)
		} else {
			persistErr = u.Queue.impl.hold(ctx, u.Binding, record.ReconciliationID, class)
		}
		if persistErr != nil {
			return errors.Join(safeError(sendErr), persistErr)
		}
		if delivery != nil {
			return delivery
		}
		return safeError(sendErr)
	}
	_, err = u.Queue.Acknowledge(ctx, u.Binding, record.ReconciliationID, receipt)
	return err
}
