// SPDX-License-Identifier: MIT
package decision

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	guardconfig "github.com/rogerchucker/palonexus-sdk/guard/internal/config"
	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

func action() protocol.ActionRequest {
	return protocol.ActionRequest{
		SchemaVersion: "1", ActionID: "act_01J5ABCDEFGHJKMNPQRSTVWXY0",
		RequestID: "req_01J5ABCDEFGHJKMNPQRSTVWXY0", CorrelationID: "corr_01J5ABCDEFGHJKMNPQRSTVWXY0",
		IdempotencyKey: "authz_01J5ABCDEFGHJKMNPQRSTVWXY0",
		Adapter:        protocol.Adapter{ID: "codex", Version: "0.2.0-alpha.1", HostVersion: "0.145.0"},
		Task:           protocol.TaskBinding{TaskID: "task_01J5ABCDEFGHJKMNPQRSTVWXY0", SessionID: "session_01J5ABCDEFGHJKMNPQRSTVWXY0"},
		Action:         protocol.ActionNameFileWrite,
		Target:         protocol.ActionTarget{Kind: protocol.TargetKindLocalAction, Service: "workspace", Resource: "path:/workspace/deploy/production.yaml", ResourceHash: "sha256:7fcdf880e7ace656f9936da7c355726f97ca513c61896ad04d20aa87f1322b81"},
		SideEffect:     protocol.SideEffectWrite, OccurredAt: "2026-07-25T20:00:00Z",
		Context: protocol.ActionContext{},
	}
}

func validDecision(t *testing.T, request protocol.ActionRequest, outcome protocol.DecisionOutcome) []byte {
	t.Helper()
	scope, err := ClientScopeHash(request)
	if err != nil {
		t.Fatal(err)
	}
	d := protocol.AuthorizationDecision{
		SchemaVersion: "1", RequestID: request.RequestID, DecisionID: "dec_01J5ABCDEFGHJKMNPQRSTVWXY0",
		CorrelationID: request.CorrelationID, Outcome: outcome, ReasonCode: "policy_denied",
		DisplayReason: "Request evaluated.", ClientScopeHash: scope,
		AuthoritativeScopeHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		PolicyRevision:         "policy_42", ServerTime: "2026-07-25T20:00:01Z",
		ExpiresAt: "2026-07-25T20:05:00Z", AuditRef: "audit_01J5ABCDEFGHJKMNPQRSTVWXY0",
		Cache: protocol.CacheDirective{Cacheable: false},
	}
	if outcome == protocol.DecisionOutcomeApprovalRequired {
		d.Approval = &protocol.ApprovalSummary{ApprovalID: "apr_01J5ABCDEFGHJKMNPQRSTVWXY0", Status: protocol.ApprovalStatusPending, ExpiresAt: "2026-07-25T20:15:00Z"}
	}
	b, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func testClient(t *testing.T, handler http.Handler) (*Client, *httptest.Server) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	client := clientForTLSServer(t, server, Options{
		AccessToken:  func(context.Context) ([]byte, error) { return []byte("secret-token"), nil },
		Now:          func() time.Time { return time.Date(2026, 7, 25, 20, 0, 2, 0, time.UTC) },
		MaxClockSkew: time.Minute,
	}, "/v1/decisions")
	return client, server
}

func clientForTLSServer(t *testing.T, server *httptest.Server, options Options, path string) *Client {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, port, err := net.SplitHostPort(parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	options.Endpoint = "https://example.com:" + port + path
	if options.TLS.RootCAs == nil {
		pool := x509.NewCertPool()
		pool.AddCert(server.Certificate())
		options.TLS.RootCAs = pool
	}
	target := server.Listener.Addr().String()
	controls := transportControls{
		resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		}),
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, network, target)
		},
	}
	client, err := newWithNetworkForTesting(options, controls)
	if err != nil {
		t.Fatal(err)
	}
	return client
}

func TestClientSendsOneAuthenticatedBoundRequestAndReturnsAllow(t *testing.T) {
	var calls atomic.Int32
	request := action()
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/v1/decisions" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer secret-token" {
			t.Errorf("authorization = %q", got)
		}
		if got := r.Header.Get("Content-Type"); got != "application/json" {
			t.Errorf("content type = %q", got)
		}
		if got := r.Header.Get("Accept-Encoding"); got != "identity" {
			t.Errorf("accept encoding = %q", got)
		}
		if got := r.Header.Get("Idempotency-Key"); got != string(request.IdempotencyKey) {
			t.Errorf("idempotency key = %q", got)
		}
		if got := r.Header.Get("X-Palonexus-Protocol-Version"); got != "1" {
			t.Errorf("protocol version = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		var got protocol.ActionRequest
		if err := json.Unmarshal(body, &got); err != nil || got.RequestID != request.RequestID {
			t.Errorf("bad body: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
	}))
	defer server.Close()
	got, err := client.Decide(context.Background(), request)
	if err != nil || got.Outcome != protocol.DecisionOutcomeAllow {
		t.Fatalf("Decide = %#v, %v", got, err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestClientNeverCachesAllow(t *testing.T) {
	var calls atomic.Int32
	request := action()
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
	}))
	defer server.Close()
	for range 2 {
		if _, err := client.Decide(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d; allow was cached", calls.Load())
	}
}

func TestAuthorizationRequestIsSingleUseDespiteIdempotencyHeader(t *testing.T) {
	var calls atomic.Int32
	client := clientWithRoundTripper(
		Options{
			Endpoint:    "https://example.com/v1/authorization/decisions",
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
		},
		roundTripFunc(func(request *http.Request) (*http.Response, error) {
			calls.Add(1)
			if request.GetBody != nil {
				t.Fatal("rewindable body permits implicit net/http replay")
			}
			if request.ContentLength <= 0 || request.Header.Get("Idempotency-Key") == "" {
				t.Fatal("lost body length or protocol idempotency key")
			}
			return nil, errors.New("ambiguous completion")
		}),
	)
	if _, err := client.Decide(context.Background(), action()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("round trips = %d", calls.Load())
	}
}

func TestHTTP1ReusedConnectionFailureDoesNotReplayAuthorization(t *testing.T) {
	request := action()
	var calls atomic.Int32
	var firstPeer string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if r.ProtoMajor != 1 {
			t.Errorf("protocol = %s", r.Proto)
		}
		switch call {
		case 1:
			firstPeer = r.RemoteAddr
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
		case 2:
			if r.RemoteAddr != firstPeer {
				t.Errorf("connection was not reused: %s then %s", firstPeer, r.RemoteAddr)
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
		}
	}))
	defer server.Close()
	client := clientForTLSServer(t, server, Options{
		AccessToken:  func(context.Context) ([]byte, error) { return []byte("token"), nil },
		Now:          func() time.Time { return time.Date(2026, 7, 25, 20, 0, 2, 0, time.UTC) },
		MaxClockSkew: time.Minute,
	}, "")
	if _, err := client.Decide(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("ambiguous reused-connection result = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("authorization reached server %d times; implicit replay occurred", calls.Load())
	}
}

func TestHTTP2StreamResetDoesNotReplayAuthorization(t *testing.T) {
	request := action()
	var calls atomic.Int32
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if r.ProtoMajor != 2 {
			t.Errorf("protocol = %s", r.Proto)
		}
		switch call {
		case 1:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
		case 2:
			panic(http.ErrAbortHandler)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
		}
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := clientForTLSServer(t, server, Options{
		AccessToken:  func(context.Context) ([]byte, error) { return []byte("token"), nil },
		Now:          func() time.Time { return time.Date(2026, 7, 25, 20, 0, 2, 0, time.UTC) },
		MaxClockSkew: time.Minute,
	}, "")
	if _, err := client.Decide(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("stream-reset result = %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("authorization reached server %d times; implicit replay occurred", calls.Load())
	}
}

func TestClientScopeHashMatchesProtocolVector(t *testing.T) {
	got, err := ClientScopeHash(action())
	if err != nil {
		t.Fatal(err)
	}
	const want = "sha256:4b17607bdbf139c235cf7156a171225945a4736e9e733267a324d58574533b2e"
	if got != want {
		t.Fatalf("hash = %s, want %s", got, want)
	}
}

func TestClientScopeHashRejectsResourcePreimageMismatch(t *testing.T) {
	request := action()
	request.Target.Resource = "path:/workspace/other.yaml"
	if _, err := ClientScopeHash(request); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ClientScopeHash error = %v", err)
	}
}

func TestNewRequiresHTTPSAndVerifiedTLS(t *testing.T) {
	for _, endpoint := range []string{
		"http://example.com/v1/decisions",
		"https://user:pass@example.com/x",
		"https://example.com/x?q=1",
		"https://example.com/x#fragment",
		"https://example.com./x",
		"https://-invalid.example/x",
		"https://example.com:/x",
		"https://example.com:0/x",
		"https://example.com:65536/x",
		"https://例.example/x",
		"https://example.com/%2e%2e/private",
		"https://example.com/v1//decisions",
		"https://example.com/v1/../private",
		"https://example.com/v1\\private",
		"https://127.1/private",
		"https://2130706433/private",
		"https://017700000001/private",
		"https://0x7f000001/private",
		"https://example.com/\nprivate",
	} {
		if _, err := New(Options{Endpoint: endpoint, AccessToken: func(context.Context) ([]byte, error) { return []byte("x"), nil }}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("New(%q) error = %v", endpoint, err)
		}
	}
	for _, options := range []Options{
		{Endpoint: "https://example.com", AccessToken: func(context.Context) ([]byte, error) { return []byte("x"), nil }, Timeout: -time.Second},
		{Endpoint: "https://example.com", AccessToken: func(context.Context) ([]byte, error) { return []byte("x"), nil }, MaxClockSkew: -time.Second},
	} {
		if _, err := New(options); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("invalid bounds error = %v", err)
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer server.Close()
	client, err := New(Options{Endpoint: server.URL, AccessToken: func(context.Context) ([]byte, error) { return []byte("x"), nil }})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Decide(context.Background(), action())
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("TLS error = %v", err)
	}
}

func TestLoopbackHTTPRequiresConfigurationAndRuntimeOptIn(t *testing.T) {
	request := action()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
	}))
	defer server.Close()
	endpoint := server.URL + "/v1/authorization/decisions"
	body := func(local bool, decisionEndpoint string) string {
		return fmt.Sprintf(`{
			"decision_endpoint": %q,
			"oidc_issuer": "https://identity.example.com",
			"trusted_ca_file": "",
			"local_test_mode": %t,
			"routes": [{"target":"api.example.com","decision_endpoint":"https://decision.example.com"}]
		}`, decisionEndpoint, local)
	}
	write := func(content string) string {
		path := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if _, err := New(Options{
		Endpoint:    endpoint,
		AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("runtime-only local mode accepted: %v", err)
	}
	if _, err := guardconfig.Load(
		write(body(true, endpoint)),
		guardconfig.Options{},
	); err == nil {
		t.Fatal("config-only local mode accepted")
	}
	if _, err := guardconfig.Load(
		write(body(false, endpoint)),
		guardconfig.Options{AllowLocalTestMode: true},
	); err == nil {
		t.Fatal("runtime-only local mode accepted by config")
	}
	for _, unsafeEndpoint := range []string{
		strings.Replace(endpoint, "127.0.0.1", "localhost", 1),
		"http://192.0.2.1:8181/v1/authorization/decisions",
	} {
		if _, err := guardconfig.Load(
			write(body(true, unsafeEndpoint)),
			guardconfig.Options{AllowLocalTestMode: true},
		); err == nil {
			t.Fatalf("unsafe local endpoint accepted: %s", unsafeEndpoint)
		}
	}
	configuration, err := guardconfig.Load(
		write(body(true, endpoint)),
		guardconfig.Options{AllowLocalTestMode: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewFromConfig(configuration, Options{
		AccessToken:  func(context.Context) ([]byte, error) { return []byte("token"), nil },
		Now:          func() time.Time { return time.Date(2026, 7, 25, 20, 0, 2, 0, time.UTC) },
		MaxClockSkew: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Decide(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestCustomCAIsUsed(t *testing.T) {
	request := action()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client := clientForTLSServer(t, server, Options{
		TLS:         TLSOptions{RootCAs: pool},
		AccessToken: func(context.Context) ([]byte, error) { return []byte("x"), nil },
		Now:         func() time.Time { return time.Date(2026, 7, 25, 20, 0, 2, 0, time.UTC) },
	}, "")
	if _, err := client.Decide(context.Background(), request); err != nil {
		t.Fatal(err)
	}
}

func TestProductionTLSPathEnforcesTrustHostnameVersionsAndMTLS(t *testing.T) {
	request := action()
	now := func() time.Time { return time.Date(2026, 7, 25, 20, 0, 2, 0, time.UTC) }
	ca, caKey := testCA(t)
	rootPool := x509.NewCertPool()
	rootPool.AddCert(ca)
	serverCertificate := issueCertificate(t, ca, caKey, []string{"example.com"}, false)
	clientCertificate := issueCertificate(t, ca, caKey, nil, true)

	start := func(tlsConfig *tls.Config) *httptest.Server {
		server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
		}))
		server.TLS = tlsConfig
		server.StartTLS()
		return server
	}
	t.Run("trusted CA succeeds", func(t *testing.T) {
		server := start(&tls.Config{
			Certificates: []tls.Certificate{serverCertificate},
			MinVersion:   tls.VersionTLS12,
		})
		defer server.Close()
		client := clientForTLSServer(t, server, Options{
			TLS:         TLSOptions{RootCAs: rootPool},
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
			Now:         now,
		}, "")
		if _, err := client.Decide(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("wrong CA fails", func(t *testing.T) {
		server := start(&tls.Config{Certificates: []tls.Certificate{serverCertificate}})
		defer server.Close()
		client := clientForTLSServer(t, server, Options{
			TLS:         TLSOptions{RootCAs: x509.NewCertPool()},
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
			Now:         now,
		}, "")
		if _, err := client.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("hostname mismatch fails", func(t *testing.T) {
		wrongCertificate := issueCertificate(t, ca, caKey, []string{"wrong.example"}, false)
		server := start(&tls.Config{Certificates: []tls.Certificate{wrongCertificate}})
		defer server.Close()
		client := clientForTLSServer(t, server, Options{
			TLS:         TLSOptions{RootCAs: rootPool},
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
			Now:         now,
		}, "")
		if _, err := client.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("TLS below 1.2 fails", func(t *testing.T) {
		server := start(&tls.Config{
			Certificates: []tls.Certificate{serverCertificate},
			MaxVersion:   tls.VersionTLS11,
		})
		defer server.Close()
		client := clientForTLSServer(t, server, Options{
			TLS:         TLSOptions{RootCAs: rootPool},
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
			Now:         now,
		}, "")
		if _, err := client.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("configured TLS 1.3 minimum is honored", func(t *testing.T) {
		server := start(&tls.Config{
			Certificates: []tls.Certificate{serverCertificate},
			MinVersion:   tls.VersionTLS12,
			MaxVersion:   tls.VersionTLS12,
		})
		defer server.Close()
		client := clientForTLSServer(t, server, Options{
			TLS: TLSOptions{
				RootCAs: rootPool, MinVersion: tls.VersionTLS13,
			},
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
			Now:         now,
		}, "")
		if _, err := client.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("configured TLS maximum is honored", func(t *testing.T) {
		server := start(&tls.Config{
			Certificates: []tls.Certificate{serverCertificate},
			MinVersion:   tls.VersionTLS13,
		})
		defer server.Close()
		client := clientForTLSServer(t, server, Options{
			TLS: TLSOptions{
				RootCAs: rootPool, MaxVersion: tls.VersionTLS12,
			},
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
			Now:         now,
		}, "")
		if _, err := client.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("mTLS certificate is required and accepted", func(t *testing.T) {
		server := start(&tls.Config{
			Certificates: []tls.Certificate{serverCertificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    rootPool,
			MinVersion:   tls.VersionTLS12,
		})
		defer server.Close()
		without := clientForTLSServer(t, server, Options{
			TLS:         TLSOptions{RootCAs: rootPool},
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
			Now:         now,
		}, "")
		if _, err := without.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("missing certificate error = %v", err)
		}
		with := clientForTLSServer(t, server, Options{
			TLS: TLSOptions{
				RootCAs: rootPool, ClientCertificates: []tls.Certificate{clientCertificate},
			},
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
			Now:         now,
		}, "")
		if _, err := with.Decide(context.Background(), request); err != nil {
			t.Fatal(err)
		}
	})
}

func testCA(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "PaloNexus test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func issueCertificate(
	t *testing.T,
	ca *x509.Certificate,
	caKey *ecdsa.PrivateKey,
	dnsNames []string,
	client bool,
) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	usage := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if client {
		usage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "PaloNexus test peer"},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func TestOutcomesHaveTypedErrors(t *testing.T) {
	for _, tc := range []struct {
		outcome protocol.DecisionOutcome
		target  error
	}{
		{protocol.DecisionOutcomeDeny, ErrDenied},
		{protocol.DecisionOutcomeApprovalRequired, ErrApprovalRequired},
	} {
		t.Run(string(tc.outcome), func(t *testing.T) {
			request := action()
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(validDecision(t, request, tc.outcome))
			}))
			defer server.Close()
			got, err := client.Decide(context.Background(), request)
			if !errors.Is(err, tc.target) || got.Outcome != tc.outcome {
				t.Fatalf("got %#v, %v", got, err)
			}
			var outcome *OutcomeError
			if !errors.As(err, &outcome) || outcome.Decision.DecisionID != got.DecisionID {
				t.Fatalf("typed error = %#v", err)
			}
		})
	}
}

func TestMalformedMismatchTimeStatusAndContentTypeFailClosed(t *testing.T) {
	tests := []struct {
		name     string
		response func(t *testing.T, r protocol.ActionRequest, w http.ResponseWriter)
	}{
		{"malformed", func(_ *testing.T, _ protocol.ActionRequest, w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte("{"))
		}},
		{"wrong content type", func(t *testing.T, r protocol.ActionRequest, w http.ResponseWriter) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(validDecision(t, r, protocol.DecisionOutcomeAllow))
		}},
		{"unsupported charset", func(t *testing.T, r protocol.ActionRequest, w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json; charset=iso-8859-1")
			_, _ = w.Write(validDecision(t, r, protocol.DecisionOutcomeAllow))
		}},
		{"compressed", func(t *testing.T, r protocol.ActionRequest, w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(validDecision(t, r, protocol.DecisionOutcomeAllow))
		}},
		{"status", func(t *testing.T, r protocol.ActionRequest, w http.ResponseWriter) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(500)
			_, _ = w.Write(validDecision(t, r, protocol.DecisionOutcomeAllow))
		}},
		{"scope mismatch", func(t *testing.T, r protocol.ActionRequest, w http.ResponseWriter) {
			d := validDecision(t, r, protocol.DecisionOutcomeAllow)
			scope, _ := ClientScopeHash(r)
			d = []byte(strings.Replace(string(d), strings.TrimPrefix(string(scope), "sha256:"), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(d)
		}},
		{"expired", func(t *testing.T, r protocol.ActionRequest, w http.ResponseWriter) {
			d := validDecision(t, r, protocol.DecisionOutcomeAllow)
			d = []byte(strings.Replace(string(d), "2026-07-25T20:05:00Z", "2026-07-25T19:59:00Z", 1))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(d)
		}},
		{"request mismatch", func(t *testing.T, r protocol.ActionRequest, w http.ResponseWriter) {
			d := validDecision(t, r, protocol.DecisionOutcomeAllow)
			d = []byte(strings.Replace(string(d), string(r.RequestID), "req_01J5ABCDEFGHJKMNPQRSTVWXY1", 1))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(d)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := action()
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { tc.response(t, r, w) }))
			defer server.Close()
			got, err := client.Decide(context.Background(), r)
			if !errors.Is(err, ErrInvalidDecision) && !errors.Is(err, ErrUnavailable) {
				t.Fatalf("got %#v, %v", got, err)
			}
			if got.Outcome == protocol.DecisionOutcomeAllow {
				t.Fatal("fallback allow")
			}
		})
	}
}

func TestExactFractionalTimestampOrderingAndClockSkew(t *testing.T) {
	tests := []struct {
		name       string
		serverTime string
		expiresAt  string
	}{
		{"expiry differs after nanosecond precision", "2026-07-25T20:00:01.1234567891Z", "2026-07-25T20:00:01.1234567892Z"},
		{"server too old", "2026-07-25T19:58:59.9999999999Z", "2026-07-25T20:05:00Z"},
		{"server too new", "2026-07-25T20:01:02.0000000001Z", "2026-07-25T20:05:00Z"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := action()
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				document := validDecision(t, request, protocol.DecisionOutcomeAllow)
				document = []byte(strings.Replace(string(document), "2026-07-25T20:00:01Z", tc.serverTime, 1))
				document = []byte(strings.Replace(string(document), "2026-07-25T20:05:00Z", tc.expiresAt, 1))
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(document)
			}))
			defer server.Close()
			_, err := client.Decide(context.Background(), request)
			if tc.name == "expiry differs after nanosecond precision" {
				// The expiry is after server time exactly, but it is already
				// unusable relative to the trusted local clock.
				if !errors.Is(err, ErrInvalidDecision) {
					t.Fatalf("error = %v", err)
				}
			} else if !errors.Is(err, ErrInvalidDecision) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestBoundedResponseTimeoutCancellationOutageAndNoRetry(t *testing.T) {
	tests := []struct {
		name    string
		handler http.Handler
		context func() (context.Context, context.CancelFunc)
	}{
		{"oversize", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(make([]byte, MaxResponseBytes+1))
		}), func() (context.Context, context.CancelFunc) { return context.WithCancel(context.Background()) }},
		{"timeout", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { time.Sleep(100 * time.Millisecond) }), func() (context.Context, context.CancelFunc) {
			return context.WithTimeout(context.Background(), 10*time.Millisecond)
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); tc.handler.ServeHTTP(w, r) }))
			defer server.Close()
			ctx, cancel := tc.context()
			defer cancel()
			if _, err := client.Decide(ctx, action()); !errors.Is(err, ErrUnavailable) && !errors.Is(err, ErrInvalidDecision) {
				t.Fatalf("error = %v", err)
			}
			if tc.name == "oversize" && calls.Load() != 1 {
				t.Fatalf("calls = %d", calls.Load())
			}
			if tc.name == "timeout" && calls.Load() > 1 {
				t.Fatalf("calls = %d; request retried", calls.Load())
			}
		})
	}
	client, err := New(Options{Endpoint: "https://127.0.0.1:1", Timeout: 20 * time.Millisecond, AccessToken: func(context.Context) ([]byte, error) { return []byte("x"), nil }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Decide(context.Background(), action()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("outage error = %v", err)
	}
}

func TestRedirectProxyAndTokenPrivacy(t *testing.T) {
	request := action()
	redirected := atomic.Bool{}
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { redirected.Store(true) }))
	defer target.Close()
	source := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	client := clientForTLSServer(t, source, Options{AccessToken: func(context.Context) ([]byte, error) { return []byte("top-secret"), nil }}, "")
	_, err := client.Decide(context.Background(), request)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
	if redirected.Load() {
		t.Fatal("followed redirect")
	}
	if strings.Contains(err.Error(), "top-secret") {
		t.Fatal("token leaked")
	}
	rendered := []string{
		client.String(),
		client.GoString(),
		fmt.Sprintf("%v", client),
		fmt.Sprintf("%#v", client),
	}
	for _, value := range rendered {
		if strings.Contains(value, source.URL) || strings.Contains(value, "top-secret") {
			t.Fatalf("client rendering leaked configuration: %q", value)
		}
	}
}

func TestConcurrentCallsAreIndependentAndTokenErrorsAreSanitized(t *testing.T) {
	request := action()
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(validDecision(t, request, protocol.DecisionOutcomeAllow))
	}))
	defer server.Close()
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := client.Decide(context.Background(), request); err != nil {
				t.Errorf("Decide: %v", err)
			}
		}()
	}
	wg.Wait()
	bad := clientForTLSServer(t, server, Options{AccessToken: func(context.Context) ([]byte, error) {
		return nil, errors.New("secret credential value")
	}}, "")
	_, err := bad.Decide(context.Background(), request)
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "secret") {
		t.Fatalf("error = %v", err)
	}
	for _, token := range []string{" leading", "trailing ", "contains\tcontrol", "not bearer!"} {
		rejected := clientForTLSServer(t, server, Options{
			AccessToken: func(context.Context) ([]byte, error) { return []byte(token), nil },
		}, "")
		if _, err = rejected.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("token %q error = %v", token, err)
		}
	}
}

func TestUnavailableHasAnExportedTypedErrorAndNilContextFailsClosed(t *testing.T) {
	client := clientWithRoundTripper(
		Options{
			Endpoint:    "https://example.com",
			AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
		},
		roundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("private network detail")
		}),
	)
	_, err := client.Decide(context.Background(), action())
	var unavailable *UnavailableError
	if !errors.As(err, &unavailable) || !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %#v", err)
	}
	if strings.Contains(err.Error(), "private") {
		t.Fatalf("sensitive detail leaked: %v", err)
	}
	if _, err = client.Decide(nil, action()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("nil context error = %v", err)
	}
}

func TestCancellationBeforeCredentialLookupMakesNoAuthorityCall(t *testing.T) {
	var tokens atomic.Int32
	var calls atomic.Int32
	client := clientWithRoundTripper(
		Options{
			Endpoint: "https://example.com/v1/authorization/decisions",
			AccessToken: func(context.Context) ([]byte, error) {
				tokens.Add(1)
				return []byte("token"), nil
			},
		},
		roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls.Add(1)
			return nil, errors.New("must not call")
		}),
	)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := client.Decide(ctx, action()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
	if tokens.Load() != 0 || calls.Load() != 0 {
		t.Fatalf("tokens=%d calls=%d", tokens.Load(), calls.Load())
	}
}

func TestAdversarialResponseHeadersAndNilBodyFailClosedWithoutRetry(t *testing.T) {
	request := action()
	valid := validDecision(t, request, protocol.DecisionOutcomeAllow)
	tests := []struct {
		name     string
		response *http.Response
	}{
		{
			name: "duplicate content type",
			response: &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": {"application/json", "application/json"},
				},
				Body:          io.NopCloser(strings.NewReader(string(valid))),
				ContentLength: int64(len(valid)),
			},
		},
		{
			name: "ambiguous parameters",
			response: &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": {"application/json; charset=utf-8; profile=unknown"},
				},
				Body:          io.NopCloser(strings.NewReader(string(valid))),
				ContentLength: int64(len(valid)),
			},
		},
		{
			name: "nil body",
			response: &http.Response{
				StatusCode:    200,
				Header:        http.Header{"Content-Type": {"application/json"}},
				Body:          nil,
				ContentLength: 0,
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			client := clientWithRoundTripper(
				Options{
					Endpoint:    "https://example.com/v1/authorization/decisions",
					AccessToken: func(context.Context) ([]byte, error) { return []byte("token"), nil },
				},
				roundTripFunc(func(*http.Request) (*http.Response, error) {
					calls.Add(1)
					return tc.response, nil
				}),
			)
			if _, err := client.Decide(context.Background(), request); !errors.Is(err, ErrInvalidDecision) {
				t.Fatalf("error = %v", err)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls = %d", calls.Load())
			}
		})
	}
}

func TestOutcomeErrorFormattingDoesNotExposeDecisionExtensions(t *testing.T) {
	request := action()
	client, server := testClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		document := validDecision(t, request, protocol.DecisionOutcomeDeny)
		document = []byte(strings.Replace(string(document), `"cache":{"cacheable":false}`, `"cache":{"cacheable":false},"extensions":{"dev.palonexus.example.v1":{"ticket":"private-marker"}}`, 1))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(document)
	}))
	defer server.Close()
	_, err := client.Decide(context.Background(), request)
	if !errors.Is(err, ErrDenied) {
		t.Fatal(err)
	}
	for _, rendered := range []string{fmt.Sprintf("%v", err), fmt.Sprintf("%#v", err)} {
		if strings.Contains(rendered, "private-marker") {
			t.Fatalf("error rendering leaked response: %s", rendered)
		}
	}
}

func TestClientDoesNotMutateCallerTLSConfig(t *testing.T) {
	pool := x509.NewCertPool()
	client, err := newWithNetworkForTesting(Options{
		Endpoint:    "https://example.com",
		TLS:         TLSOptions{RootCAs: pool, MinVersion: tls.VersionTLS13},
		AccessToken: func(context.Context) ([]byte, error) { return []byte("x"), nil },
	}, transportControls{
		resolver: resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
			return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
		}),
		dial: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("unused")
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	transport := client.http.Transport.(*http.Transport)
	if transport.TLSClientConfig.RootCAs == pool {
		t.Fatal("retained mutable caller CA pool")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("weakened TLS minimum to %x", transport.TLSClientConfig.MinVersion)
	}
	if transport.Proxy != nil || !transport.DisableCompression {
		t.Fatal("ambient proxy or decompression remained enabled")
	}
}

func TestTLSOptionsRejectUnsafeOrAmbiguousConfiguration(t *testing.T) {
	token := func(context.Context) ([]byte, error) { return []byte("token"), nil }
	invalid := []TLSOptions{
		{MinVersion: tls.VersionTLS11},
		{MaxVersion: tls.VersionTLS11},
		{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS12},
		{ClientCertificates: []tls.Certificate{{}}},
		{ClientCertificates: make([]tls.Certificate, 9)},
	}
	for index, tlsOptions := range invalid {
		if _, err := New(Options{
			Endpoint: "https://example.com", TLS: tlsOptions, AccessToken: token,
		}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("case %d error = %v", index, err)
		}
	}
}

func TestOwnedCredentialBufferIsWipedAndHeaderReleasedImmediately(t *testing.T) {
	request := action()
	owned := []byte("private-token")
	var observed *http.Request
	client := clientWithRoundTripper(
		Options{
			Endpoint: "https://example.com/v1/authorization/decisions",
			AccessToken: func(context.Context) ([]byte, error) {
				return owned, nil
			},
			Now: func() time.Time {
				return time.Date(2026, 7, 25, 20, 0, 2, 0, time.UTC)
			},
		},
		roundTripFunc(func(incoming *http.Request) (*http.Response, error) {
			observed = incoming
			if incoming.Header.Get("Authorization") != "Bearer private-token" {
				t.Fatal("missing authorization at transport boundary")
			}
			document := validDecision(t, request, protocol.DecisionOutcomeAllow)
			return &http.Response{
				StatusCode:    http.StatusOK,
				Header:        http.Header{"Content-Type": {"application/json"}},
				Body:          io.NopCloser(strings.NewReader(string(document))),
				ContentLength: int64(len(document)),
			}, nil
		}),
	)
	if _, err := client.Decide(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	for index, value := range owned {
		if value != 0 {
			t.Fatalf("credential byte %d retained: %x", index, value)
		}
	}
	if observed == nil || observed.Header.Get("Authorization") != "" {
		t.Fatal("request retained authorization after RoundTrip")
	}

	invalid := []byte("bad token")
	rejected := clientWithRoundTripper(
		Options{
			Endpoint:    "https://example.com",
			AccessToken: func(context.Context) ([]byte, error) { return invalid, nil },
		},
		roundTripFunc(func(*http.Request) (*http.Response, error) {
			t.Fatal("invalid credential reached transport")
			return nil, nil
		}),
	)
	if _, err := rejected.Decide(context.Background(), request); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("invalid credential error = %v", err)
	}
	for index, value := range invalid {
		if value != 0 {
			t.Fatalf("invalid credential byte %d retained: %x", index, value)
		}
	}
}

func TestTimeoutBoundsCredentialAcquisitionBeforeNetwork(t *testing.T) {
	var networkCalls atomic.Int32
	client := clientWithRoundTripper(
		Options{
			Endpoint: "https://example.com",
			Timeout:  15 * time.Millisecond,
			AccessToken: func(ctx context.Context) ([]byte, error) {
				<-ctx.Done()
				return nil, ctx.Err()
			},
		},
		roundTripFunc(func(*http.Request) (*http.Response, error) {
			networkCalls.Add(1)
			return nil, errors.New("unexpected")
		}),
	)
	started := time.Now()
	if _, err := client.Decide(context.Background(), action()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("error = %v", err)
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("credential timeout took %s", elapsed)
	}
	if networkCalls.Load() != 0 {
		t.Fatal("network called after credential timeout")
	}
}

func TestUnsafeDestinationClassesAreRejected(t *testing.T) {
	for _, raw := range []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.1.1",
		"192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.10",
		"224.0.0.1", "240.0.0.1", "::", "::1", "64:ff9b:1::1",
		"100::1", "2001:db8::1", "2002::1", "fc00::1", "fe80::1", "ff02::1",
	} {
		if !unsafeIP(net.ParseIP(raw)) {
			t.Errorf("%s accepted", raw)
		}
	}
	if unsafeIP(net.ParseIP("8.8.8.8")) {
		t.Fatal("ordinary global address rejected")
	}
}

func TestResolverRejectsMixedAnswersAndPinsTheValidatedAddress(t *testing.T) {
	ctx := context.Background()
	var dialed string
	dial := func(context.Context, string, string) (net.Conn, error) {
		dialed = "called"
		return nil, errors.New("stop")
	}
	mixed := resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}, {IP: net.ParseIP("127.0.0.1")}}, nil
	})
	if _, err := dialResolved(ctx, "tcp", "decision.example:443", mixed, dial); err == nil || dialed != "" {
		t.Fatalf("mixed answer was dialed: %q, %v", dialed, err)
	}

	pinned := resolverFunc(func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}, nil
	})
	dial = func(_ context.Context, network, address string) (net.Conn, error) {
		dialed = network + " " + address
		return nil, errors.New("stop")
	}
	if _, err := dialResolved(ctx, "tcp", "decision.example:443", pinned, dial); err == nil {
		t.Fatal("expected sentinel dial failure")
	}
	if dialed != "tcp 8.8.8.8:443" {
		t.Fatalf("dialed %q", dialed)
	}
}

type resolverFunc func(context.Context, string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func clientWithRoundTripper(options Options, transport http.RoundTripper) *Client {
	now := options.Now
	if now == nil {
		now = func() time.Time { return time.Date(2026, 7, 25, 20, 0, 2, 0, time.UTC) }
	}
	timeout := options.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	skew := options.MaxClockSkew
	if skew == 0 {
		skew = time.Minute
	}
	return &Client{
		endpoint: options.Endpoint,
		http: &http.Client{
			Transport:     transport,
			Timeout:       timeout,
			CheckRedirect: rejectRedirect,
		},
		token: options.AccessToken, now: now, skew: skew, timeout: timeout,
	}
}

func TestHashHelperSanity(t *testing.T) {
	sum := sha256.Sum256([]byte("private"))
	if strings.Contains("sha256:"+hex.EncodeToString(sum[:]), "private") {
		t.Fatal("preimage leak")
	}
}
