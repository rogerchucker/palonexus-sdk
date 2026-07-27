//go:build darwin || linux

package reconcile

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	p "github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
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
	recovered, err := q.Recover(ctx, b1, t0.Add(2*time.Second))
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
	receipt, err := NewReceipt(sending, "receipt_01J5ABCDEFGHJKMNPQRSTVWXY0", t0.Add(9*time.Second), b1, "registered-codex")
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
	u := Uploader{Queue: q, Binding: b1, Clock: func() time.Time { return t0.Add(time.Second) }, Send: func(context.Context, p.ReconciliationRecord) (Receipt, error) {
		calls++
		return Receipt{}, ErrTransport
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
	transport, err := NewHTTPTransport(HTTPConfig{Endpoint: server.URL, Client: server.Client(), Token: func(context.Context) (string, error) {
		return "super-secret-bearer", nil
	}, Binding: b1, ClientID: "registered-codex"})
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := transport.Send(context.Background(), record)
	if err != nil || receipt.EvidenceHash != "sha256:ef28a07d036d06a118e72c15fe30347821a29f4e845769fee1f8e18c3ef11238" {
		t.Fatalf("protocol receipt rejected: %v %+v", err, receipt)
	}
	if gotAuth != "Bearer super-secret-bearer" {
		t.Fatalf("authorization not sent")
	}
	if err != nil && strings.Contains(err.Error(), "super-secret") {
		t.Fatalf("secret leaked: %v", err)
	}
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
	q, err := Open(Config{Root: queueRoot(t), MaxRecords: 1, MaxBytes: 1 << 20})
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
	if err := q.Enqueue(ctx, b1, other); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("want full, got %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := q.Get(cancelled, b1, record.ReconciliationID); !errors.Is(err, context.Canceled) {
		t.Fatalf("want cancellation, got %v", err)
	}
	if _, err := q.Discard(ctx, b1, record.ReconciliationID, t0.Add(time.Minute), p.DiscardAuthorityTypeOrganizationRetentionPolicy, "retention_window_elapsed", false); !errors.Is(err, ErrRejected) {
		t.Fatalf("untrusted policy discard: %v", err)
	}
	discarded, err := q.Discard(ctx, b1, record.ReconciliationID, t0.Add(time.Minute), p.DiscardAuthorityTypeAuthenticatedUser, "user_retention_request", false)
	if err != nil || discarded.State != p.ReconciliationStateDiscarded {
		t.Fatalf("discard: %v %+v", err, discarded)
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
