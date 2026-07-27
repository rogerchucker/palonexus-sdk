// Package reconcile provides a durable, bounded, at-least-once evidence queue.
// It persists only the closed reconciliation protocol record; raw resources,
// request bodies, credentials, and arbitrary server responses have no place in
// this API or its on-disk envelope.
package reconcile

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/normalize"
	p "github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

var (
	ErrNotFound                = errors.New("reconciliation record not found")
	ErrNotReady                = errors.New("reconciliation record is not ready")
	ErrConflict                = errors.New("reconciliation idempotency conflict")
	ErrCorrupt                 = errors.New("reconciliation queue is corrupt")
	ErrUnsafePath              = errors.New("unsafe reconciliation queue path")
	ErrUnsafeRecord            = errors.New("unsafe reconciliation record")
	ErrQueueFull               = errors.New("reconciliation queue capacity exceeded")
	ErrClosed                  = errors.New("reconciliation queue is closed")
	ErrTransport               = errors.New("reconciliation transport unavailable")
	ErrRejected                = errors.New("reconciliation upload rejected")
	ErrUnauthorized            = errors.New("reconciliation authority required")
	ErrAttemptLimit            = errors.New("reconciliation attempt limit reached")
	ErrDurabilityIndeterminate = errors.New("reconciliation durability indeterminate")
)

const (
	maxRecordBytesDefault = 65_536
	maxResponseBytes      = 16_384
)

type Binding struct {
	Tenant  string
	Subject string
}

type DeliveryErrorClass string

const (
	DeliveryTransient      DeliveryErrorClass = "transient"
	DeliveryRateLimit      DeliveryErrorClass = "rate_limit"
	DeliveryRejected       DeliveryErrorClass = "rejected"
	DeliveryConflict       DeliveryErrorClass = "conflict"
	DeliveryAuthentication DeliveryErrorClass = "authentication"
)

type DeliveryError struct {
	Class      DeliveryErrorClass
	RetryAfter time.Duration
}

func (e *DeliveryError) Error() string { return "reconciliation delivery " + string(e.Class) }
func (e *DeliveryError) Unwrap() error {
	if e != nil && (e.Class == DeliveryTransient || e.Class == DeliveryRateLimit) {
		return ErrTransport
	}
	if e != nil && e.Class == DeliveryConflict {
		return ErrConflict
	}
	return ErrRejected
}

type Config struct {
	Root           string
	MaxRecords     int
	MaxBytes       int64
	MaxRecordBytes int
	Jitter         func(time.Duration) time.Duration
	Authority      AuthorityVerifier
}

// AuthorityVerifier is implemented by the authenticated session/policy layer.
// Queue callers cannot substitute a boolean authority claim; the queue invokes
// this trusted dependency for every privileged transition.
type AuthorityVerifier interface {
	AuthorizeDiscard(context.Context, Binding, p.DiscardAuthorityType) error
	AuthorizeManualRetry(context.Context, Binding) error
}

type Queue struct {
	impl queueImpl
	root string
}

type receiptSeal struct{}

var hardenedReceiptSeal = &receiptSeal{}

// VerifiedReceipt is opaque outside this package. Only the hardened transport
// (or a trusted in-package verifier seam) can mint a value accepted by Queue.
type VerifiedReceipt struct {
	ack        p.ReconciliationAcknowledgement
	tenant     string
	clientID   string
	verifiedAt time.Time
	seal       *receiptSeal
}

type queueImpl interface {
	enqueue(context.Context, Binding, p.ReconciliationRecord) error
	claim(context.Context, Binding, time.Time) (p.ReconciliationRecord, error)
	recover(context.Context, Binding, time.Time) (p.ReconciliationRecord, error)
	fail(context.Context, Binding, p.ReconciliationID, time.Time, bool, time.Duration) (p.ReconciliationRecord, error)
	ack(context.Context, Binding, p.ReconciliationID, VerifiedReceipt) (p.ReconciliationRecord, error)
	discard(context.Context, Binding, p.ReconciliationID, time.Time, p.DiscardAuthorityType, string, bool) (p.ReconciliationRecord, error)
	manualRetry(context.Context, Binding, p.ReconciliationID, time.Time) (p.ReconciliationRecord, error)
	hold(context.Context, Binding, p.ReconciliationID, DeliveryErrorClass) error
	held(context.Context, Binding, p.ReconciliationID) (DeliveryErrorClass, error)
	get(context.Context, Binding, p.ReconciliationID) (p.ReconciliationRecord, error)
	close() error
}

func Open(config Config) (*Queue, error) {
	if config.MaxRecords <= 0 || config.MaxRecords > 100_000 || config.MaxBytes <= 0 || config.MaxBytes > 1<<30 {
		return nil, ErrUnsafePath
	}
	if config.MaxRecordBytes == 0 {
		config.MaxRecordBytes = maxRecordBytesDefault
	}
	if config.MaxRecordBytes < 1024 || config.MaxRecordBytes > maxRecordBytesDefault {
		return nil, ErrUnsafePath
	}
	if config.Jitter == nil {
		config.Jitter = func(time.Duration) time.Duration { return 0 }
	}
	impl, err := openQueue(config)
	if err != nil {
		return nil, err
	}
	return &Queue{impl: impl, root: config.Root}, nil
}

func (q *Queue) Root() string {
	if q == nil {
		return ""
	}
	return q.root
}
func (q *Queue) Close() error {
	if q == nil || q.impl == nil {
		return ErrClosed
	}
	return q.impl.close()
}
func (q *Queue) Enqueue(ctx context.Context, b Binding, r p.ReconciliationRecord) error {
	if q == nil || q.impl == nil {
		return ErrClosed
	}
	return q.impl.enqueue(ctx, b, r)
}
func (q *Queue) Claim(ctx context.Context, b Binding, now time.Time) (p.ReconciliationRecord, error) {
	if q == nil || q.impl == nil {
		return p.ReconciliationRecord{}, ErrClosed
	}
	return q.impl.claim(ctx, b, now)
}
func (q *Queue) Recover(ctx context.Context, b Binding, now time.Time) (p.ReconciliationRecord, error) {
	if q == nil || q.impl == nil {
		return p.ReconciliationRecord{}, ErrClosed
	}
	return q.impl.recover(ctx, b, now)
}
func (q *Queue) Fail(ctx context.Context, b Binding, id p.ReconciliationID, now time.Time, retryable bool) (p.ReconciliationRecord, error) {
	if q == nil || q.impl == nil {
		return p.ReconciliationRecord{}, ErrClosed
	}
	return q.impl.fail(ctx, b, id, now, retryable, 0)
}
func (q *Queue) Acknowledge(ctx context.Context, b Binding, id p.ReconciliationID, receipt VerifiedReceipt) (p.ReconciliationRecord, error) {
	if q == nil || q.impl == nil {
		return p.ReconciliationRecord{}, ErrClosed
	}
	result, err := q.impl.ack(ctx, b, id, receipt)
	if err != nil && (errors.Is(err, ErrRejected) || errors.Is(err, ErrConflict)) {
		class := DeliveryRejected
		if errors.Is(err, ErrConflict) {
			class = DeliveryConflict
		}
		deliveryErr := &DeliveryError{Class: class}
		if holdErr := q.impl.hold(ctx, b, id, class); holdErr != nil {
			return result, errors.Join(deliveryErr, holdErr)
		}
		return result, deliveryErr
	}
	return result, err
}
func (q *Queue) Discard(ctx context.Context, b Binding, id p.ReconciliationID, now time.Time, authority p.DiscardAuthorityType, reason string) (p.ReconciliationRecord, error) {
	if q == nil || q.impl == nil {
		return p.ReconciliationRecord{}, ErrClosed
	}
	return q.impl.discard(ctx, b, id, now, authority, reason, false)
}
func (q *Queue) ManualRetry(ctx context.Context, b Binding, id p.ReconciliationID, now time.Time) (p.ReconciliationRecord, error) {
	if q == nil || q.impl == nil {
		return p.ReconciliationRecord{}, ErrClosed
	}
	return q.impl.manualRetry(ctx, b, id, now)
}
func (q *Queue) HeldError(ctx context.Context, b Binding, id p.ReconciliationID) (DeliveryErrorClass, error) {
	if q == nil || q.impl == nil {
		return "", ErrClosed
	}
	return q.impl.held(ctx, b, id)
}
func (q *Queue) Get(ctx context.Context, b Binding, id p.ReconciliationID) (p.ReconciliationRecord, error) {
	if q == nil || q.impl == nil {
		return p.ReconciliationRecord{}, ErrClosed
	}
	return q.impl.get(ctx, b, id)
}

var (
	bindingPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]{0,127}$`)
	safeReason  = regexp.MustCompile(`^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$`)
	receiptID   = regexp.MustCompile(`^receipt_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
)

func validBinding(b Binding) bool {
	return bindingPart.MatchString(b.Tenant) && bindingPart.MatchString(b.Subject)
}

func parseTime(value p.RFC3339Timestamp) (time.Time, error) {
	if len(value) == 0 || len(value) > 128 {
		return time.Time{}, ErrUnsafeRecord
	}
	result, err := time.Parse(time.RFC3339Nano, string(value))
	if err != nil {
		return time.Time{}, ErrUnsafeRecord
	}
	return result, nil
}

func validateRecord(record p.ReconciliationRecord, max int) ([]byte, error) {
	wire, err := json.Marshal(record)
	if err != nil || len(wire) > max {
		return nil, ErrUnsafeRecord
	}
	parsed, err := p.ParseReconciliationRecord(wire)
	if err != nil {
		return nil, ErrUnsafeRecord
	}
	if parsed.Extensions != nil && len(*parsed.Extensions) != 0 {
		return nil, ErrUnsafeRecord
	}
	if !safeReason.MatchString(parsed.ReasonCode) {
		return nil, ErrUnsafeRecord
	}
	observed, err := parseTime(parsed.ObservedAt)
	if err != nil {
		return nil, err
	}
	policy := parsed.DeliveryPolicy
	if policy.MaxAttempts < 1 || policy.MaxAttempts > 100 || policy.MaxTotalAttempts < policy.MaxAttempts ||
		policy.MaxTotalAttempts > 100 || policy.BaseDelaySeconds < 1 || policy.BaseDelaySeconds > 3600 ||
		policy.MaxDelaySeconds < policy.BaseDelaySeconds || policy.MaxDelaySeconds > 86400 ||
		parsed.AttemptCount < 0 || parsed.AttemptCount > policy.MaxTotalAttempts {
		return nil, ErrUnsafeRecord
	}
	if parsed.LastAttemptAt != nil {
		last, e := parseTime(*parsed.LastAttemptAt)
		if e != nil || last.Before(observed) {
			return nil, ErrUnsafeRecord
		}
	}
	if (parsed.AttemptCount == 0) != (parsed.LastAttemptAt == nil) {
		return nil, ErrUnsafeRecord
	}
	if parsed.DeliveryDisposition == p.DeliveryDispositionAutomatic && parsed.AttemptCount > policy.MaxAttempts {
		return nil, ErrUnsafeRecord
	}
	if parsed.DeliveryDisposition == p.DeliveryDispositionManualIntervention && parsed.AttemptCount < policy.MaxAttempts {
		return nil, ErrUnsafeRecord
	}
	if parsed.State == p.ReconciliationStatePending &&
		parsed.DeliveryDisposition == p.DeliveryDispositionAutomatic && parsed.AttemptCount >= policy.MaxAttempts {
		return nil, ErrUnsafeRecord
	}
	if parsed.State == p.ReconciliationStateRetryWait && parsed.AttemptCount >= policy.MaxAttempts {
		return nil, ErrUnsafeRecord
	}
	if parsed.NextAttemptAt != nil {
		next, e := parseTime(*parsed.NextAttemptAt)
		if e != nil || parsed.LastAttemptAt == nil || !next.After(timeMust(parsed.LastAttemptAt)) {
			return nil, ErrUnsafeRecord
		}
	}
	if parsed.AcknowledgedAt != nil {
		acknowledged, e := parseTime(*parsed.AcknowledgedAt)
		if e != nil || parsed.LastAttemptAt == nil || acknowledged.Before(timeMust(parsed.LastAttemptAt)) {
			return nil, ErrUnsafeRecord
		}
	}
	if parsed.DiscardedAt != nil {
		discarded, e := parseTime(*parsed.DiscardedAt)
		if e != nil || discarded.Before(observed) {
			return nil, ErrUnsafeRecord
		}
	}
	if parsed.State == p.ReconciliationStateAcknowledged {
		if parsed.Acknowledgement == nil || parsed.AcknowledgedAt == nil {
			return nil, ErrUnsafeRecord
		}
		hash, hashErr := evidenceHashUnchecked(parsed)
		left, leftErr := parseTime(parsed.Acknowledgement.AcknowledgedAt)
		right, rightErr := parseTime(*parsed.AcknowledgedAt)
		if hashErr != nil || leftErr != nil || rightErr != nil ||
			parsed.Acknowledgement.ReconciliationID != parsed.ReconciliationID ||
			parsed.Acknowledgement.EvidenceHash != hash || !left.Equal(right) {
			return nil, ErrUnsafeRecord
		}
	}
	return wire, nil
}

func evidenceHash(record p.ReconciliationRecord) (p.SHA256Digest, error) {
	if _, err := validateRecord(record, maxRecordBytesDefault); err != nil {
		return "", err
	}
	return evidenceHashUnchecked(record)
}

func evidenceHashUnchecked(record p.ReconciliationRecord) (p.SHA256Digest, error) {
	// State fields are deliberately excluded, matching the protocol's immutable evidence body.
	body := struct {
		SchemaVersion               p.SchemaVersion               `json:"schemaVersion"`
		ReconciliationID            p.ReconciliationID            `json:"reconciliationId"`
		ActionID                    p.ActionID                    `json:"actionId"`
		RequestID                   p.RequestID                   `json:"requestId"`
		DecisionID                  *p.DecisionID                 `json:"decisionId,omitempty"`
		CorrelationID               p.CorrelationID               `json:"correlationId"`
		AuthorizationIdempotencyKey p.AuthorizationIdempotencyKey `json:"authorizationIdempotencyKey"`
		ClientID                    string                        `json:"clientId"`
		Action                      p.ActionName                  `json:"action"`
		TargetKind                  p.TargetKind                  `json:"targetKind"`
		ClientScopeHash             *p.SHA256Digest               `json:"clientScopeHash,omitempty"`
		AuthoritativeScopeHash      *p.SHA256Digest               `json:"authoritativeScopeHash,omitempty"`
		Outcome                     p.ReconciliationOutcome       `json:"outcome"`
		ReasonCode                  string                        `json:"reasonCode"`
		ObservedAt                  p.RFC3339Timestamp            `json:"observedAt"`
		BatchID                     p.BatchID                     `json:"batchId"`
		BatchSequence               p.JSONInteger                 `json:"batchSequence"`
		DeliveryPolicy              p.DeliveryPolicy              `json:"deliveryPolicy"`
		Extensions                  *map[string]any               `json:"extensions,omitempty"`
	}{record.SchemaVersion, record.ReconciliationID, record.ActionID, record.RequestID, record.DecisionID,
		record.CorrelationID, record.AuthorizationIdempotencyKey, record.ClientID, record.Action, record.TargetKind,
		record.ClientScopeHash, record.AuthoritativeScopeHash, record.Outcome, record.ReasonCode, record.ObservedAt,
		record.BatchID, record.BatchSequence, record.DeliveryPolicy, record.Extensions}
	wire, err := json.Marshal(body)
	if err != nil {
		return "", ErrUnsafeRecord
	}
	canonical, err := normalize.CanonicalJSON(wire)
	if err != nil {
		return "", ErrUnsafeRecord
	}
	sum := sha256.Sum256(canonical)
	return p.SHA256Digest("sha256:" + hex.EncodeToString(sum[:])), nil
}

func mintVerifiedReceipt(record p.ReconciliationRecord, id p.ReceiptID, at, verifiedAt time.Time, binding Binding, clientID string) (VerifiedReceipt, error) {
	if !validBinding(binding) || !receiptID.MatchString(string(id)) || clientID != record.ClientID ||
		at.IsZero() || verifiedAt.IsZero() || at.After(verifiedAt) || at.Before(timeMust(record.LastAttemptAt)) {
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
	}
	hash, err := evidenceHash(record)
	if err != nil {
		return VerifiedReceipt{}, &DeliveryError{Class: DeliveryRejected}
	}
	return VerifiedReceipt{ack: p.ReconciliationAcknowledgement{ReceiptID: id, ReconciliationID: record.ReconciliationID,
		EvidenceHash: hash, AcknowledgedAt: p.RFC3339Timestamp(at.UTC().Format(time.RFC3339Nano))},
		tenant: binding.Tenant, clientID: clientID, verifiedAt: verifiedAt.UTC(), seal: hardenedReceiptSeal}, nil
}

func timeMust(value *p.RFC3339Timestamp) time.Time {
	if value == nil {
		return time.Time{}
	}
	result, _ := time.Parse(time.RFC3339Nano, string(*value))
	return result
}

func retryDelay(record p.ReconciliationRecord, jitter func(time.Duration) time.Duration) (time.Duration, error) {
	if record.AttemptCount < 1 {
		return 0, ErrUnsafeRecord
	}
	exp := math.Min(float64(record.AttemptCount-1), 62)
	base := time.Duration(record.DeliveryPolicy.BaseDelaySeconds) * time.Second
	maximum := time.Duration(record.DeliveryPolicy.MaxDelaySeconds) * time.Second
	delay := time.Duration(float64(base) * math.Pow(2, exp))
	if delay > maximum || delay < 0 {
		delay = maximum
	}
	extra := jitter(delay)
	if extra < 0 || extra > maximum-delay {
		return 0, ErrUnsafeRecord
	}
	return delay + extra, nil
}

func safeError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, context.Canceled):
		return context.Canceled
	case errors.Is(err, context.DeadlineExceeded):
		return context.DeadlineExceeded
	case errors.Is(err, ErrTransport):
		return ErrTransport
	case errors.Is(err, ErrRejected):
		return ErrRejected
	default:
		return fmt.Errorf("%w", ErrTransport)
	}
}
