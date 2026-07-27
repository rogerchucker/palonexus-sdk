//go:build darwin || linux

package reconcile

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	p "github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
	"golang.org/x/sys/unix"
)

func queueRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	return root
}

var (
	t0 = time.Date(2026, 7, 25, 20, 0, 2, 0, time.UTC)
	b1 = Binding{Tenant: "tenant-a", Subject: "subject-a"}
)

type testAuthority struct {
	subject string
	org     bool
}

type fixedResolver []net.IPAddr

func (r fixedResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) { return r, nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

type partialErrorReader struct {
	document []byte
	read     bool
}

func (r *partialErrorReader) Read(buffer []byte) (int, error) {
	if r.read {
		return 0, errors.New("injected body read failure")
	}
	r.read = true
	n := copy(buffer, r.document)
	return n, errors.New("injected body read failure")
}

func (a testAuthority) AuthorizeDiscard(_ context.Context, binding Binding, authority p.DiscardAuthorityType) error {
	if authority == p.DiscardAuthorityTypeAuthenticatedUser && binding.Subject == a.subject {
		return nil
	}
	if authority == p.DiscardAuthorityTypeOrganizationRetentionPolicy && a.org {
		return nil
	}
	return ErrUnauthorized
}
func (a testAuthority) AuthorizeManualRetry(_ context.Context, binding Binding) error {
	if binding.Subject == a.subject || a.org {
		return nil
	}
	return ErrUnauthorized
}

func pending() p.ReconciliationRecord {
	clientHash := p.SHA256Digest("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	serverHash := p.SHA256Digest("sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	decision := p.DecisionID("dec_01J5ABCDEFGHJKMNPQRSTVWXY0")
	return p.ReconciliationRecord{
		SchemaVersion: "1", ReconciliationID: "recon_01J5ABCDEFGHJKMNPQRSTVWXY0",
		ActionID: "act_01J5ABCDEFGHJKMNPQRSTVWXY0", RequestID: "req_01J5ABCDEFGHJKMNPQRSTVWXY0",
		DecisionID: &decision, CorrelationID: "corr_01J5ABCDEFGHJKMNPQRSTVWXY0",
		AuthorizationIdempotencyKey: "authz_01J5ABCDEFGHJKMNPQRSTVWXY0", ClientID: "registered-codex",
		Action: "file:write", TargetKind: "local-action", ClientScopeHash: &clientHash,
		AuthoritativeScopeHash: &serverHash, Outcome: "allow", ReasonCode: "policy_allowed",
		ObservedAt: p.RFC3339Timestamp(t0.Format(time.RFC3339)), BatchID: "batch_01J5ABCDEFGHJKMNPQRSTVWXY0",
		BatchSequence: 0, DeliveryPolicy: p.DeliveryPolicy{MaxAttempts: 3, MaxTotalAttempts: 5, BaseDelaySeconds: 5, MaxDelaySeconds: 60},
		AttemptCount: 0, DeliveryDisposition: p.DeliveryDispositionAutomatic, State: p.ReconciliationStatePending,
	}
}

func batchRecord(sequence int, suffix byte) p.ReconciliationRecord {
	record := pending()
	last := string(suffix)
	record.ReconciliationID = p.ReconciliationID("recon_01J5ABCDEFGHJKMNPQRSTVWXY" + last)
	record.ActionID = p.ActionID("act_01J5ABCDEFGHJKMNPQRSTVWXY" + last)
	record.RequestID = p.RequestID("req_01J5ABCDEFGHJKMNPQRSTVWXY" + last)
	record.CorrelationID = p.CorrelationID("corr_01J5ABCDEFGHJKMNPQRSTVWXY" + last)
	record.AuthorizationIdempotencyKey = p.AuthorizationIdempotencyKey("authz_01J5ABCDEFGHJKMNPQRSTVWXY" + last)
	record.BatchSequence = p.JSONInteger(sequence)
	return record
}

func testReceipt(record p.ReconciliationRecord, id p.ReceiptID, at time.Time) (VerifiedReceipt, error) {
	return mintVerifiedReceipt(record, id, at, at, b1, record.ClientID)
}

func TestQueueLifecycleDedupeCrashRecoveryAndConflict(t *testing.T) {
	ctx := context.Background()
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 8, MaxBytes: 1 << 20, Jitter: func(time.Duration) time.Duration { return time.Second }})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	record := pending()
	if err := q.Enqueue(ctx, b1, record); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(ctx, b1, record); err != nil {
		t.Fatalf("idempotent enqueue: %v", err)
	}
	changed := record
	changed.ReasonCode = "different_safe_reason"
	if err := q.Enqueue(ctx, b1, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("want conflict, got %v", err)
	}

	sending, err := q.Claim(ctx, b1, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if sending.State != p.ReconciliationStateSending || sending.AttemptCount != 1 {
		t.Fatalf("bad sending state: %+v", sending)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}

	q, err = Open(Config{Root: q.Root(), MaxRecords: 8, MaxBytes: 1 << 20, Jitter: func(time.Duration) time.Duration { return time.Second }})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	recovered, err := q.Get(ctx, b1, record.ReconciliationID)
	if err != nil {
		t.Fatal(err)
	}
	if recovered.State != p.ReconciliationStatePending || recovered.AttemptCount != 1 {
		t.Fatalf("bad recovery: %+v", recovered)
	}
}

func TestRetryWaitAndAcknowledgementAreDurable(t *testing.T) {
	ctx := context.Background()
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 8, MaxBytes: 1 << 20, Jitter: func(time.Duration) time.Duration { return time.Second }})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Enqueue(ctx, b1, pending()); err != nil {
		t.Fatal(err)
	}
	sending, err := q.Claim(ctx, b1, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	waiting, err := q.Fail(ctx, b1, sending.ReconciliationID, t0.Add(2*time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	if waiting.State != p.ReconciliationStateRetryWait || string(*waiting.NextAttemptAt) != t0.Add(8*time.Second).Format(time.RFC3339) {
		t.Fatalf("bad retry: %+v", waiting)
	}
	if _, err := q.Claim(ctx, b1, t0.Add(7*time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("want not ready, got %v", err)
	}
	sending, err = q.Claim(ctx, b1, t0.Add(8*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := testReceipt(sending, "receipt_01J5ABCDEFGHJKMNPQRSTVWXY0", t0.Add(9*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	acked, err := q.Acknowledge(ctx, b1, sending.ReconciliationID, receipt)
	if err != nil {
		t.Fatal(err)
	}
	if acked.State != p.ReconciliationStateAcknowledged {
		t.Fatalf("bad ack: %+v", acked)
	}
	again, err := q.Acknowledge(ctx, b1, sending.ReconciliationID, receipt)
	if err != nil || again.State != p.ReconciliationStateAcknowledged {
		t.Fatalf("ack loss retry: %v %+v", err, again)
	}
}

func TestUploaderMakesExactlyOneExplicitAttempt(t *testing.T) {
	ctx := context.Background()
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Enqueue(ctx, b1, pending()); err != nil {
		t.Fatal(err)
	}
	calls := 0
	u := Uploader{Queue: q, Binding: b1, Clock: func() time.Time { return t0.Add(time.Second) }, Send: func(context.Context, p.ReconciliationRecord) (VerifiedReceipt, error) {
		calls++
		return VerifiedReceipt{}, ErrTransport
	}}
	if err := u.Attempt(ctx); !errors.Is(err, ErrTransport) {
		t.Fatalf("want transport error, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("hidden retries: %d calls", calls)
	}
}

func TestHTTPTransportIsStrictBoundedAndRedactsAuthorization(t *testing.T) {
	record := pending()
	var gotAuth string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"receiptId":"receipt_01J5ABCDEFGHJKMNPQRSTVWXY0","reconciliationId":"recon_01J5ABCDEFGHJKMNPQRSTVWXY0","evidenceHash":"sha256:` +
			`ef28a07d036d06a118e72c15fe30347821a29f4e845769fee1f8e18c3ef11238","acknowledgedAt":"2026-07-25T20:00:05Z"}`))
	}))
	defer server.Close()
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	ownedToken := []byte("super-secret-bearer")
	transport, err := newHTTPTransportWithNetwork(HTTPConfig{Endpoint: server.URL, TrustedCAPEM: caPEM, Token: func(context.Context) ([]byte, error) {
		return ownedToken, nil
	}, Binding: b1, ClientID: "registered-codex"}, networkControls{
		resolver: fixedResolver{{IP: net.ParseIP("93.184.216.34")}},
		dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := transport.Send(context.Background(), record)
	if err != nil || receipt.ack.EvidenceHash != "sha256:ef28a07d036d06a118e72c15fe30347821a29f4e845769fee1f8e18c3ef11238" {
		t.Fatalf("protocol receipt rejected: %v %+v", err, receipt)
	}
	if gotAuth != "Bearer super-secret-bearer" {
		t.Fatalf("authorization not sent")
	}
	for _, value := range ownedToken {
		if value != 0 {
			t.Fatal("owned token was not wiped")
		}
	}
	if err != nil && strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("secret leaked: %v", err)
	}
}

func TestHTTPTransportRetriesAmbiguousPartialAcknowledgement(t *testing.T) {
	record := pending()
	hash, err := evidenceHash(record)
	if err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(p.ReconciliationAcknowledgement{
		ReceiptID: "receipt_01J5ABCDEFGHJKMNPQRSTVWXY0", ReconciliationID: record.ReconciliationID,
		EvidenceHash: hash, AcknowledgedAt: p.RFC3339Timestamp(t0.Add(3 * time.Second).Format(time.RFC3339)),
	})
	calls := 0
	transport := &HTTPTransport{
		endpoint: "https://api.example/reconcile",
		client: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			calls++
			var body io.ReadCloser
			if calls == 1 {
				body = io.NopCloser(&partialErrorReader{document: document[:len(document)/2]})
			} else {
				body = io.NopCloser(bytes.NewReader(document))
			}
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: body}, nil
		})},
		token:   func(context.Context) ([]byte, error) { return []byte("token"), nil },
		binding: b1, clientID: record.ClientID, clock: func() time.Time { return t0.Add(4 * time.Second) },
	}
	if _, err = transport.Send(context.Background(), record); !errors.Is(err, ErrTransport) {
		t.Fatalf("partial 2xx was not transient: %v", err)
	}
	receipt, err := transport.Send(context.Background(), record)
	if err != nil || receipt.ack.ReconciliationID != record.ReconciliationID || calls != 2 {
		t.Fatalf("identical retry not acknowledged: %#v %v calls=%d", receipt, err, calls)
	}
}

func TestHTTPTransportTokenProviderClassification(t *testing.T) {
	record := pending()
	base := HTTPTransport{endpoint: "https://api.example", client: http.DefaultClient, binding: b1, clientID: record.ClientID, clock: time.Now}
	base.token = func(context.Context) ([]byte, error) { return nil, errors.New("keystore unavailable") }
	if _, err := base.Send(context.Background(), record); !errors.Is(err, ErrTransport) {
		t.Fatalf("provider failure not transient: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	base.token = func(context.Context) ([]byte, error) { return nil, errors.New("provider observed cancellation") }
	if _, err := base.Send(ctx, record); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	base.token = func(context.Context) ([]byte, error) { return []byte("bad\nvalue"), nil }
	var delivery *DeliveryError
	if _, err := base.Send(context.Background(), record); !errors.As(err, &delivery) || delivery.Class != DeliveryAuthentication {
		t.Fatalf("invalid credential not authentication failure: %v", err)
	}
}

func TestDialResolvedRejectsEntireMixedDNSAnswerBeforeDial(t *testing.T) {
	called := false
	_, err := dialResolved(context.Background(), "tcp", "api.example:443",
		fixedResolver{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("127.0.0.1")}},
		func(context.Context, string, string) (net.Conn, error) {
			called = true
			return nil, errors.New("called")
		})
	if !errors.Is(err, ErrTransport) || called {
		t.Fatalf("mixed answer was dialed: %v called=%v", err, called)
	}
}

func TestUploaderStatusRedirectBodyAndProxyMatrix(t *testing.T) {
	cases := []struct {
		name   string
		status int
		class  DeliveryErrorClass
	}{
		{"auth", http.StatusUnauthorized, DeliveryAuthentication}, {"conflict", http.StatusConflict, DeliveryConflict},
		{"rate", http.StatusTooManyRequests, DeliveryRateLimit}, {"server", http.StatusServiceUnavailable, DeliveryTransient},
		{"rejected", http.StatusBadRequest, DeliveryRejected}, {"redirect", http.StatusFound, DeliveryRejected},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(tc.status) }))
			defer server.Close()
			ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			transport, err := newHTTPTransportWithNetwork(HTTPConfig{Endpoint: server.URL, TrustedCAPEM: ca,
				Token: func(context.Context) ([]byte, error) { return []byte("owned-token"), nil }, Binding: b1, ClientID: "registered-codex"},
				networkControls{resolver: fixedResolver{{IP: net.ParseIP("93.184.216.34")}}, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
				}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = transport.Send(context.Background(), pending())
			var delivery *DeliveryError
			if !errors.As(err, &delivery) || delivery.Class != tc.class {
				t.Fatalf("class: %v", err)
			}
			if calls != 1 {
				t.Fatalf("ambient replay/redirect: %d", calls)
			}
			httpTransport := transport.client.Transport.(*http.Transport)
			if httpTransport.Proxy != nil || !httpTransport.DisableKeepAlives || httpTransport.TLSClientConfig.MinVersion < 0x0303 {
				t.Fatal("unsafe transport")
			}
		})
	}
	t.Run("oversize success", func(t *testing.T) {
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(bytes.Repeat([]byte("x"), maxResponseBytes+1))
		}))
		defer server.Close()
		ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
		transport, err := newHTTPTransportWithNetwork(HTTPConfig{Endpoint: server.URL, TrustedCAPEM: ca, Token: func(context.Context) ([]byte, error) { return []byte("token"), nil }, Binding: b1, ClientID: "registered-codex"},
			networkControls{resolver: fixedResolver{{IP: net.ParseIP("93.184.216.34")}}, dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
			}})
		if err != nil {
			t.Fatal(err)
		}
		_, err = transport.Send(context.Background(), pending())
		var delivery *DeliveryError
		if !errors.As(err, &delivery) || delivery.Class != DeliveryRejected {
			t.Fatalf("oversize: %v", err)
		}
	})
}

func TestQueueRejectsUnsafeRootsAndRecordInodes(t *testing.T) {
	target := queueRoot(t)
	link := filepath.Join(t.TempDir(), "queue-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Root: link, MaxRecords: 8, MaxBytes: 1 << 20}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("symlink root accepted: %v", err)
	}
	if err := os.Chmod(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Root: target, MaxRecords: 8, MaxBytes: 1 << 20}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("permissive root accepted: %v", err)
	}

	root := queueRoot(t)
	q, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	id := pending().ReconciliationID
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(root, recordName(id))
	if err := os.Symlink(filepath.Join(root, "missing"), name); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}); err == nil {
		t.Fatal("record symlink accepted")
	}
}

func TestQueueBoundsCancellationAndAuthorizedDiscard(t *testing.T) {
	ctx := context.Background()
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 1, MaxBytes: 1 << 20, Authority: testAuthority{subject: b1.Subject}})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	record := pending()
	if err := q.Enqueue(ctx, b1, record); err != nil {
		t.Fatal(err)
	}
	other := record
	other.ReconciliationID = "recon_01J5ABCDEFGHJKMNPQRSTVWXY1"
	other.ActionID = "act_01J5ABCDEFGHJKMNPQRSTVWXY1"
	other.RequestID = "req_01J5ABCDEFGHJKMNPQRSTVWXY1"
	other.CorrelationID = "corr_01J5ABCDEFGHJKMNPQRSTVWXY1"
	other.AuthorizationIdempotencyKey = "authz_01J5ABCDEFGHJKMNPQRSTVWXY1"
	other.BatchID = "batch_01J5ABCDEFGHJKMNPQRSTVWXY1"
	if err := q.Enqueue(ctx, b1, other); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("want full, got %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := q.Get(cancelled, b1, record.ReconciliationID); !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancellation, got %v", err)
	}
	if _, err := q.Discard(ctx, b1, record.ReconciliationID, t0.Add(time.Minute), p.DiscardAuthorityTypeOrganizationRetentionPolicy, "retention_window_elapsed"); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("untrusted policy discard: %v", err)
	}
	discarded, err := q.Discard(ctx, b1, record.ReconciliationID, t0.Add(time.Minute), p.DiscardAuthorityTypeAuthenticatedUser, "user_retention_request")
	if err != nil || discarded.State != p.ReconciliationStateDiscarded {
		t.Fatalf("discard: %v %+v", err, discarded)
	}
}

func TestOpenRecoversEverySendingRecordBeforeUse(t *testing.T) {
	root := queueRoot(t)
	config := Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}
	q, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	first := pending()
	second := pending()
	second.ReconciliationID = "recon_01J5ABCDEFGHJKMNPQRSTVWXY1"
	second.ActionID = "act_01J5ABCDEFGHJKMNPQRSTVWXY1"
	second.RequestID = "req_01J5ABCDEFGHJKMNPQRSTVWXY1"
	second.CorrelationID = "corr_01J5ABCDEFGHJKMNPQRSTVWXY1"
	second.AuthorizationIdempotencyKey = "authz_01J5ABCDEFGHJKMNPQRSTVWXY1"
	second.BatchID = "batch_01J5ABCDEFGHJKMNPQRSTVWXY1"
	for _, record := range []p.ReconciliationRecord{first, second} {
		if err := q.Enqueue(context.Background(), b1, record); err != nil {
			t.Fatal(err)
		}
		if _, err := q.Claim(context.Background(), b1, t0.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	for _, record := range []p.ReconciliationRecord{first, second} {
		got, getErr := q.Get(context.Background(), b1, record.ReconciliationID)
		if getErr != nil || got.State != p.ReconciliationStatePending || got.AttemptCount != 1 {
			t.Fatalf("not recovered: %v %+v", getErr, got)
		}
	}
}

func TestAcknowledgementIdempotencyRequiresExactFullReceipt(t *testing.T) {
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Enqueue(context.Background(), b1, pending()); err != nil {
		t.Fatal(err)
	}
	sending, err := q.Claim(context.Background(), b1, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := testReceipt(sending, "receipt_01J5ABCDEFGHJKMNPQRSTVWXY0", t0.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Acknowledge(context.Background(), b1, sending.ReconciliationID, receipt); err != nil {
		t.Fatal(err)
	}
	changed, err := mintVerifiedReceipt(sending, "receipt_01J5ABCDEFGHJKMNPQRSTVWXY0", t0.Add(3*time.Second), t0.Add(3*time.Second), b1, sending.ClientID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Acknowledge(context.Background(), b1, sending.ReconciliationID, changed); !errors.Is(err, ErrConflict) {
		t.Fatalf("nonidentical receipt accepted: %v", err)
	}
}

func TestManualRetryRequiresTrustedAuthorityAndHonorsTotalLimit(t *testing.T) {
	auth := testAuthority{subject: b1.Subject}
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 8, MaxBytes: 1 << 20, Authority: auth})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	record := pending()
	record.DeliveryPolicy.MaxAttempts = 1
	record.DeliveryPolicy.MaxTotalAttempts = 2
	if err := q.Enqueue(context.Background(), b1, record); err != nil {
		t.Fatal(err)
	}
	sending, err := q.Claim(context.Background(), b1, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	manual, err := q.Fail(context.Background(), b1, sending.ReconciliationID, t0.Add(2*time.Second), true)
	if err != nil {
		t.Fatal(err)
	}
	if manual.DeliveryDisposition != p.DeliveryDispositionManualIntervention {
		t.Fatalf("not manual: %+v", manual)
	}
	retried, err := q.ManualRetry(context.Background(), b1, record.ReconciliationID, t0.Add(3*time.Second))
	if err != nil || retried.State != p.ReconciliationStateSending || retried.AttemptCount != 2 {
		t.Fatalf("retry: %v %+v", err, retried)
	}
	if _, err := q.Fail(context.Background(), b1, record.ReconciliationID, t0.Add(4*time.Second), true); err != nil {
		t.Fatal(err)
	}
	if _, err := q.ManualRetry(context.Background(), b1, record.ReconciliationID, t0.Add(5*time.Second)); !errors.Is(err, ErrAttemptLimit) {
		t.Fatalf("total limit bypassed: %v", err)
	}
}

func TestTwoQueueHandlesSerializeOneClaim(t *testing.T) {
	root := queueRoot(t)
	config := Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}
	first, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.Enqueue(context.Background(), b1, pending()); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, q := range []*Queue{first, second} {
		wg.Add(1)
		go func(queue *Queue) {
			defer wg.Done()
			_, claimErr := queue.Claim(context.Background(), b1, t0.Add(time.Second))
			results <- claimErr
		}(q)
	}
	wg.Wait()
	close(results)
	success, blocked := 0, 0
	for claimErr := range results {
		if claimErr == nil {
			success++
		} else if errors.Is(claimErr, ErrNotReady) {
			blocked++
		} else {
			t.Fatalf("unexpected claim: %v", claimErr)
		}
	}
	if success != 1 || blocked != 1 {
		t.Fatalf("claims success=%d blocked=%d", success, blocked)
	}
}

func TestCorruptRecordIsQuarantinedAndNeverSelected(t *testing.T) {
	root := queueRoot(t)
	config := Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}
	q, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	record := pending()
	if err := q.Enqueue(context.Background(), b1, record); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, recordName(record.ReconciliationID))
	if err := os.WriteFile(path, []byte(`{"version":1,"record":"corrupt"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(config); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("corruption did not fail closed: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("corrupt live record remains: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		found = found || strings.HasPrefix(entry.Name(), ".quarantine-")
	}
	if !found {
		t.Fatal("corrupt record was not quarantined")
	}
	q, err = Open(config)
	if err != nil {
		t.Fatalf("quarantined queue did not recover: %v", err)
	}
	defer q.Close()
	if _, err := q.Claim(context.Background(), b1, t0.Add(time.Second)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("quarantined evidence selected: %v", err)
	}
}

func FuzzReconciliationRecordValidation(f *testing.F) {
	seed, _ := json.Marshal(pending())
	f.Add(seed)
	f.Add([]byte(`{"authorization":"Bearer secret"}`))
	f.Fuzz(func(t *testing.T, document []byte) {
		var record p.ReconciliationRecord
		if json.Unmarshal(document, &record) != nil {
			return
		}
		_, _ = validateRecord(record, maxRecordBytesDefault)
	})
}

func FuzzBatchTransactionValidation(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"version":1,"oldRecordDigest":"secret","newEnvelope":{"holdClass":"token"}}`))
	f.Fuzz(func(t *testing.T, document []byte) {
		if len(document) > int(maxTransactionBytes) {
			return
		}
		var transaction batchTransaction
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&transaction) != nil {
			return
		}
		_ = validateTransactionShape(transaction, 128, maxRecordBytesDefault)
	})
}

func TestOrderedBatchCheckpointRejectsGapsAndResumesPrunedPrefix(t *testing.T) {
	root := queueRoot(t)
	config := Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}
	q, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if err := q.Enqueue(context.Background(), b1, batchRecord(1, '1')); !errors.Is(err, ErrConflict) {
		t.Fatalf("gap accepted: %v", err)
	}
	first, second := batchRecord(0, '0'), batchRecord(1, '1')
	if err := q.Enqueue(context.Background(), b1, first); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(context.Background(), b1, second); err != nil {
		t.Fatal(err)
	}
	duplicate := batchRecord(1, '2')
	if err := q.Enqueue(context.Background(), b1, duplicate); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate sequence accepted: %v", err)
	}
	sending, err := q.Claim(context.Background(), b1, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if sending.ReconciliationID != first.ReconciliationID {
		t.Fatalf("reordered batch: %s", sending.ReconciliationID)
	}
	receipt, err := testReceipt(sending, "receipt_01J5ABCDEFGHJKMNPQRSTVWXY0", t0.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.Acknowledge(context.Background(), b1, sending.ReconciliationID, receipt); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, recordName(first.ReconciliationID))); err != nil {
		t.Fatal(err)
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	next, err := q.Claim(context.Background(), b1, t0.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if next.ReconciliationID != second.ReconciliationID {
		t.Fatalf("pruned checkpoint resumed wrong record: %s", next.ReconciliationID)
	}
}

func TestAckTransactionRecoversCrashBetweenRecordAndCheckpoint(t *testing.T) {
	root := queueRoot(t)
	config := Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}
	q, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	record := pending()
	if err := q.Enqueue(context.Background(), b1, record); err != nil {
		t.Fatal(err)
	}
	sending, err := q.Claim(context.Background(), b1, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := testReceipt(sending, "receipt_01J5ABCDEFGHJKMNPQRSTVWXY0", t0.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	impl := q.impl.(*unixQueue)
	impl.afterTransactionRecord = func() error { return errors.New("simulated crash") }
	if _, err = q.Acknowledge(context.Background(), b1, sending.ReconciliationID, receipt); err == nil {
		t.Fatal("fault did not interrupt transaction")
	}
	if err := q.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	recovered, err := q.Get(context.Background(), b1, record.ReconciliationID)
	if err != nil || recovered.State != p.ReconciliationStateAcknowledged {
		t.Fatalf("transaction not recovered: %v %+v", err, recovered)
	}
}

func TestPermanentDeliveryErrorIsHeldUntilAuthorizedManualRetry(t *testing.T) {
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 8, MaxBytes: 1 << 20, Authority: testAuthority{subject: b1.Subject}})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	record := pending()
	if err := q.Enqueue(context.Background(), b1, record); err != nil {
		t.Fatal(err)
	}
	uploader := Uploader{Queue: q, Binding: b1, Clock: func() time.Time { return t0.Add(time.Second) },
		Send: func(context.Context, p.ReconciliationRecord) (VerifiedReceipt, error) {
			return VerifiedReceipt{}, &DeliveryError{Class: DeliveryAuthentication}
		}}
	if err := uploader.Attempt(context.Background()); !errors.Is(err, ErrRejected) {
		t.Fatalf("typed permanent error lost: %v", err)
	}
	class, err := q.HeldError(context.Background(), b1, record.ReconciliationID)
	if err != nil || class != DeliveryAuthentication {
		t.Fatalf("hold: %v %s", err, class)
	}
	if _, err := q.Claim(context.Background(), b1, t0.Add(2*time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("held item retried: %v", err)
	}
	if _, err := q.ManualRetry(context.Background(), b1, record.ReconciliationID, t0.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidSuccessfulReceiptIsDurablyHeld(t *testing.T) {
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	record := pending()
	if err = q.Enqueue(context.Background(), b1, record); err != nil {
		t.Fatal(err)
	}
	sending, err := q.Claim(context.Background(), b1, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Acknowledge(context.Background(), b1, sending.ReconciliationID, VerifiedReceipt{}); !errors.Is(err, ErrRejected) {
		t.Fatalf("invalid receipt error: %v", err)
	}
	if class, holdErr := q.HeldError(context.Background(), b1, record.ReconciliationID); holdErr != nil || class != DeliveryRejected {
		t.Fatalf("not held: %v %s", holdErr, class)
	}
	if _, err = q.Claim(context.Background(), b1, t0.Add(2*time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("invalid ack retried: %v", err)
	}
}

func TestNonRetryableFailureIsDurablyHeld(t *testing.T) {
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	record := pending()
	if err = q.Enqueue(context.Background(), b1, record); err != nil {
		t.Fatal(err)
	}
	sending, err := q.Claim(context.Background(), b1, t0.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = q.Fail(context.Background(), b1, sending.ReconciliationID, t0.Add(2*time.Second), false); err != nil {
		t.Fatal(err)
	}
	if _, err = q.Claim(context.Background(), b1, t0.Add(3*time.Second)); !errors.Is(err, ErrNotReady) {
		t.Fatalf("nonretryable failure retried: %v", err)
	}
}

func TestDiscardRejectsNonFinalBatchItemAndLastSurvivesRestart(t *testing.T) {
	root := queueRoot(t)
	config := Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20, Authority: testAuthority{subject: b1.Subject}}
	q, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	first, second := batchRecord(0, '0'), batchRecord(1, '1')
	if err = q.Enqueue(context.Background(), b1, first); err != nil {
		t.Fatal(err)
	}
	if err = q.Enqueue(context.Background(), b1, second); err != nil {
		t.Fatal(err)
	}
	if _, err = q.Discard(context.Background(), b1, first.ReconciliationID, t0.Add(time.Minute), p.DiscardAuthorityTypeAuthenticatedUser, "user_retention_request"); !errors.Is(err, ErrConflict) {
		t.Fatalf("non-final discard: %v", err)
	}
	if _, err = q.Discard(context.Background(), b1, second.ReconciliationID, t0.Add(time.Minute), p.DiscardAuthorityTypeAuthenticatedUser, "user_retention_request"); err != nil {
		t.Fatal(err)
	}
	if err = q.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	next, err := q.Claim(context.Background(), b1, t0.Add(2*time.Minute))
	if err != nil || next.ReconciliationID != first.ReconciliationID {
		t.Fatalf("restart ordering: %v %s", err, next.ReconciliationID)
	}
}

func TestSemanticValidationRejectsCrossFieldAndTimestampViolations(t *testing.T) {
	cases := []p.ReconciliationRecord{}
	base := pending()
	bad := base
	stamp1 := p.RFC3339Timestamp(t0.Add(-time.Second).Format(time.RFC3339))
	bad.AttemptCount = 1
	bad.LastAttemptAt = &stamp1
	bad.State = p.ReconciliationStateSending
	cases = append(cases, bad)
	bad = base
	bad.AttemptCount = 3
	stamp2 := p.RFC3339Timestamp(t0.Add(time.Second).Format(time.RFC3339))
	bad.LastAttemptAt = &stamp2
	cases = append(cases, bad)
	bad = base
	bad.DeliveryDisposition = p.DeliveryDispositionManualIntervention
	reason := "attempt_limit_reached"
	bad.ManualReasonCode = &reason
	cases = append(cases, bad)
	for index, record := range cases {
		if _, err := validateRecord(record, maxRecordBytesDefault); err == nil {
			t.Fatalf("case %d accepted", index)
		}
	}
}

func TestCommittedReconciliationVectorsMatchQueueValidator(t *testing.T) {
	root := filepath.Join("..", "..", "..", "protocol", "test-vectors", "reconciliation")
	valid, err := filepath.Glob(filepath.Join(root, "valid", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := filepath.Glob(filepath.Join(root, "invalid", "*.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range valid {
		document, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		record, parseErr := p.ParseReconciliationRecord(document)
		if parseErr != nil {
			t.Fatalf("%s: %v", path, parseErr)
		}
		if _, validateErr := validateRecord(record, maxRecordBytesDefault); validateErr != nil {
			t.Fatalf("%s: %v", path, validateErr)
		}
	}
	for _, path := range invalid {
		document, readErr := os.ReadFile(path)
		if readErr != nil {
			t.Fatal(readErr)
		}
		record, parseErr := p.ParseReconciliationRecord(document)
		if parseErr == nil {
			if _, validateErr := validateRecord(record, maxRecordBytesDefault); validateErr == nil {
				t.Fatalf("invalid accepted: %s", path)
			}
		}
	}
}

func TestCloseWaitsForActiveOperationsWithoutFDReuse(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		q, err := Open(Config{Root: queueRoot(t), MaxRecords: 8, MaxBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		if err := q.Enqueue(context.Background(), b1, pending()); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for count := 0; count < 20; count++ {
					_, _ = q.Get(context.Background(), b1, pending().ReconciliationID)
					runtime.Gosched()
				}
			}()
		}
		wg.Add(1)
		go func() { defer wg.Done(); _ = q.Close() }()
		wg.Wait()
	}
}

func TestRootReplacementPreventsOldAndNewHandlesBothCommitting(t *testing.T) {
	parent := queueRoot(t)
	root := filepath.Join(parent, "queue")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	config := Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}
	old, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	displaced := filepath.Join(parent, "displaced")
	if err = os.Rename(root, displaced); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	fresh, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err = old.Enqueue(context.Background(), b1, pending()); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("old root committed: %v", err)
	}
	if err = fresh.Enqueue(context.Background(), b1, pending()); err != nil {
		t.Fatalf("fresh root failed: %v", err)
	}
}

func TestEnqueueCapacityAndFaultRecoverAtomically(t *testing.T) {
	root := queueRoot(t)
	tooSmall := Config{Root: root, MaxRecords: 8, MaxBytes: transitionReserveBytes + 128}
	q, err := Open(tooSmall)
	if err != nil {
		t.Fatal(err)
	}
	if err = q.Enqueue(context.Background(), b1, pending()); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("near-cap accepted: %v", err)
	}
	if _, err = os.Stat(filepath.Join(root, checkpointName(pending().BatchID))); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan checkpoint: %v", err)
	}
	_ = q.Close()

	root = queueRoot(t)
	config := Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}
	q, err = Open(config)
	if err != nil {
		t.Fatal(err)
	}
	q.impl.(*unixQueue).afterCheckpointCreate = func() error { return errors.New("fault") }
	if err = q.Enqueue(context.Background(), b1, pending()); err == nil {
		t.Fatal("fault ignored")
	}
	q.impl.(*unixQueue).afterCheckpointCreate = nil
	conflicting := batchRecord(0, '1')
	if err = q.Enqueue(context.Background(), b1, conflicting); !errors.Is(err, ErrConflict) {
		t.Fatalf("same handle did not recover/fence journal: %v", err)
	}
	if got, getErr := q.Get(context.Background(), b1, pending().ReconciliationID); getErr != nil ||
		got.ReconciliationID != pending().ReconciliationID {
		t.Fatalf("same-handle recovery lost original: %#v %v", got, getErr)
	}
	entries, listErr := os.ReadDir(root)
	if listErr != nil {
		t.Fatal(listErr)
	}
	transactionCount := 0
	for _, entry := range entries {
		if isTransactionName(entry.Name()) {
			transactionCount++
		}
	}
	if transactionCount != 0 {
		t.Fatalf("repeated recovery left %d journals", transactionCount)
	}
	_ = q.Close()
	q, err = Open(config)
	if err != nil {
		t.Fatalf("recover journal: %v", err)
	}
	defer q.Close()
	if got, getErr := q.Get(context.Background(), b1, pending().ReconciliationID); getErr != nil ||
		got.ReconciliationID != pending().ReconciliationID {
		t.Fatalf("recover enqueue: %#v, %v", got, getErr)
	}
}

func TestDiscardedLaterSequencePermanentlyBlocksEarlierDiscard(t *testing.T) {
	root := queueRoot(t)
	config := Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20, Authority: testAuthority{subject: b1.Subject}}
	q, err := Open(config)
	if err != nil {
		t.Fatal(err)
	}
	first, final := batchRecord(0, '0'), batchRecord(1, '1')
	if err = q.Enqueue(context.Background(), b1, first); err != nil {
		t.Fatal(err)
	}
	if err = q.Enqueue(context.Background(), b1, final); err != nil {
		t.Fatal(err)
	}
	if _, err = q.Discard(context.Background(), b1, final.ReconciliationID, t0.Add(time.Second),
		p.DiscardAuthorityTypeAuthenticatedUser, "user_requested"); err != nil {
		t.Fatalf("discard final: %v", err)
	}
	if _, err = q.Discard(context.Background(), b1, first.ReconciliationID, t0.Add(2*time.Second),
		p.DiscardAuthorityTypeAuthenticatedUser, "user_requested"); !errors.Is(err, ErrConflict) {
		t.Fatalf("earlier discard accepted: %v", err)
	}
	if err = q.Close(); err != nil {
		t.Fatal(err)
	}
	q, err = Open(config)
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	if _, err = q.Discard(context.Background(), b1, first.ReconciliationID, t0.Add(3*time.Second),
		p.DiscardAuthorityTypeAuthenticatedUser, "user_requested"); !errors.Is(err, ErrConflict) {
		t.Fatalf("earlier discard accepted after restart: %v", err)
	}
}

func TestImmutableRootLockCannotBeBypassedByReplacingMetadataLock(t *testing.T) {
	root := queueRoot(t)
	q, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(rootFD)
	if err = unix.Flock(rootFD, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	defer unix.Flock(rootFD, unix.LOCK_UN)
	lockPath := filepath.Join(root, ".queue.lock")
	if err = os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(lockPath, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if err = q.Enqueue(ctx, b1, pending()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("replaceable metadata lock bypassed root inode lock: %v", err)
	}
}

func TestTransactionRemovalPreservesReplacementAndReportsAmbiguity(t *testing.T) {
	root := queueRoot(t)
	q, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	replacement := []byte(`{"replacement":"must-not-be-unlinked"}`)
	impl := q.impl.(*unixQueue)
	impl.beforeTransactionRemove = func(name string) error {
		impl.beforeTransactionRemove = nil
		path := filepath.Join(root, name)
		if err := os.Rename(path, filepath.Join(root, ".captured-original")); err != nil {
			return err
		}
		return os.WriteFile(path, replacement, 0o600)
	}
	if err = q.Enqueue(context.Background(), b1, pending()); !errors.Is(err, ErrDurabilityIndeterminate) {
		t.Fatalf("replacement race was not ambiguous: %v", err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), ".done-") {
			continue
		}
		document, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
		if readErr != nil {
			t.Fatal(readErr)
		}
		if bytes.Equal(document, replacement) {
			found = true
		}
	}
	if !found {
		t.Fatal("replacement transaction was deleted")
	}
}

func TestCraftedEnqueueJournalCannotCreateSequenceGapBeforeFailing(t *testing.T) {
	root := queueRoot(t)
	q, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer q.Close()
	first := batchRecord(0, '0')
	if err = q.Enqueue(context.Background(), b1, first); err != nil {
		t.Fatal(err)
	}
	impl := q.impl.(*unixQueue)
	checkpoint, err := impl.readCheckpoint(first.BatchID)
	if err != nil {
		t.Fatal(err)
	}
	gapped := batchRecord(2, '2')
	hash, err := evidenceHash(gapped)
	if err != nil {
		t.Fatal(err)
	}
	env := diskEnvelope{Version: envelopeVersion, TenantHash: hashBinding(b1, true),
		SubjectHash: hashBinding(b1, false), EvidenceHash: hash, Record: gapped}
	transaction := batchTransaction{
		Version: envelopeVersion, Operation: "enqueue", RecordName: recordName(gapped.ReconciliationID),
		CheckpointName: checkpointName(gapped.BatchID), OldCheckpointDigest: hex.EncodeToString(checkpoint.digest[:]),
		NewEnvelope: env, NewCheckpoint: checkpoint,
	}
	document, _ := json.Marshal(transaction)
	name := ".txn-00000000000000000000000000000001"
	if err = impl.atomicWrite(context.Background(), name, document, nil); err != nil {
		t.Fatal(err)
	}
	persisted, snapshot, err := impl.readSafeFile(name, maxTransactionBytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := decodeBatchTransaction(persisted)
	if err != nil {
		t.Fatal(err)
	}
	if err = impl.applyTransaction(context.Background(), name, parsed, snapshot); !errors.Is(err, ErrConflict) {
		t.Fatalf("crafted gap journal accepted: %v", err)
	}
	if _, err = impl.read(recordName(gapped.ReconciliationID)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("crafted record mutated queue before rejection: %v", err)
	}
	after, err := impl.readCheckpoint(first.BatchID)
	if err != nil || after.digest != checkpoint.digest {
		t.Fatalf("checkpoint mutated before rejection: %v", err)
	}
}

func TestQueueRejectsHardlinkFIFOAndUnsafeControlFiles(t *testing.T) {
	t.Run("hardlink record", func(t *testing.T) {
		root := queueRoot(t)
		q, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20})
		if err != nil {
			t.Fatal(err)
		}
		if err = q.Enqueue(context.Background(), b1, pending()); err != nil {
			t.Fatal(err)
		}
		_ = q.Close()
		path := filepath.Join(root, recordName(pending().ReconciliationID))
		if err = os.Link(path, filepath.Join(root, "outside-link")); err != nil {
			t.Fatal(err)
		}
		if _, err = Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}); err == nil {
			t.Fatal("hardlink accepted")
		}
	})
	t.Run("fifo record", func(t *testing.T) {
		root := queueRoot(t)
		path := filepath.Join(root, recordName(pending().ReconciliationID))
		if err := unix.Mkfifo(path, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}); err == nil {
			t.Fatal("fifo accepted")
		}
	})
	t.Run("fifo lock", func(t *testing.T) {
		root := queueRoot(t)
		if err := unix.Mkfifo(filepath.Join(root, ".queue.lock"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}); err == nil {
			t.Fatal("fifo lock accepted")
		}
	})
	t.Run("unsafe temp permissions", func(t *testing.T) {
		root := queueRoot(t)
		if err := os.WriteFile(filepath.Join(root, ".tmp-0123456789abcdef0123456789abcdef"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}); err == nil {
			t.Fatal("unsafe temp accepted")
		}
	})
	t.Run("unsafe quarantine permissions", func(t *testing.T) {
		root := queueRoot(t)
		name := ".quarantine-" + strings.Repeat("a", 64) + "-" + strings.Repeat("b", 32)
		if err := os.WriteFile(filepath.Join(root, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(Config{Root: root, MaxRecords: 8, MaxBytes: 1 << 20}); err == nil {
			t.Fatal("unsafe quarantine accepted")
		}
	})
}
