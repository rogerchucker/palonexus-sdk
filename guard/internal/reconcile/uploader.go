package reconcile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	p "github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

type HTTPConfig struct {
	Endpoint string
	Client   *http.Client
	Token    func(context.Context) (string, error)
	Binding  Binding
	ClientID string
}

type HTTPTransport struct {
	endpoint string
	client   *http.Client
	token    func(context.Context) (string, error)
	binding  Binding
	clientID string
}

func NewHTTPTransport(config HTTPConfig) (*HTTPTransport, error) {
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "https" || endpoint.Host == "" || endpoint.User != nil ||
		endpoint.Fragment != "" || endpoint.RawQuery != "" || !validBinding(config.Binding) || config.ClientID == "" || config.Token == nil {
		return nil, ErrUnsafeRecord
	}
	client := config.Client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	} else {
		copy := *client
		if copy.Timeout <= 0 || copy.Timeout > 60*time.Second {
			copy.Timeout = 10 * time.Second
		}
		client = &copy
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &HTTPTransport{endpoint: endpoint.String(), client: client, token: config.Token, binding: config.Binding, clientID: config.ClientID}, nil
}

func (t *HTTPTransport) Send(ctx context.Context, record p.ReconciliationRecord) (Receipt, error) {
	if t == nil || record.ClientID != t.clientID {
		return Receipt{}, ErrRejected
	}
	body, err := validateRecord(record, maxRecordBytesDefault)
	if err != nil {
		return Receipt{}, err
	}
	token, err := t.token(ctx)
	if err != nil || token == "" || strings.ContainsAny(token, "\r\n") || len(token) > 8192 {
		return Receipt{}, ErrTransport
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, t.endpoint, bytes.NewReader(body))
	if err != nil {
		return Receipt{}, ErrTransport
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := t.client.Do(request)
	if err != nil {
		return Receipt{}, safeError(err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 ||
		!strings.HasPrefix(strings.ToLower(response.Header.Get("Content-Type")), "application/json") {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxResponseBytes))
		return Receipt{}, ErrRejected
	}
	document, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil || len(document) > maxResponseBytes {
		return Receipt{}, ErrRejected
	}
	var public p.ReconciliationAcknowledgement
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&public) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Receipt{}, ErrRejected
	}
	hash, err := evidenceHash(record)
	if err != nil || public.ReconciliationID != record.ReconciliationID || public.EvidenceHash != hash {
		return Receipt{}, ErrRejected
	}
	at, err := parseTime(public.AcknowledgedAt)
	if err != nil {
		return Receipt{}, ErrRejected
	}
	return NewReceipt(record, public.ReceiptID, at, t.binding, t.clientID)
}

// Uploader performs one explicit delivery attempt. Scheduling and retries are
// caller-owned so a single call can never conceal additional network effects.
type Uploader struct {
	Queue   *Queue
	Binding Binding
	Clock   func() time.Time
	Send    func(context.Context, p.ReconciliationRecord) (Receipt, error)
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
		_, persistErr := u.Queue.Fail(ctx, u.Binding, record.ReconciliationID, u.Clock().UTC(), true)
		if persistErr != nil {
			return errors.Join(safeError(sendErr), persistErr)
		}
		return safeError(sendErr)
	}
	_, err = u.Queue.Acknowledge(ctx, u.Binding, record.ReconciliationID, receipt)
	return err
}
