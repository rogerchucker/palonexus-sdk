// SPDX-License-Identifier: MIT
// Package guard composes the local guard's fail-closed authorization pipeline.
package guard

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"regexp"
	"strings"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/decision"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/normalize"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/routing"
	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

// NormalizationRequest is deliberately opaque at this layer. A host adapter
// selects a normalizer for the action kind; the guard pipeline never logs,
// serializes, or returns Opaque.
type NormalizationRequest struct {
	Kind    protocol.TargetKind
	Service string
	Opaque  any
}

// Input contains caller-visible action metadata. Adapter is diagnostic only.
// Authenticated identity is obtained independently through SessionSource.
type Input struct {
	Normalization NormalizationRequest
	RouteTarget   string
	Action        protocol.ActionRequest
}

// AuthenticatedSession is supplied only by the trusted login/session boundary.
// It is never populated from Action.Adapter, Action.Extensions, or Opaque.
type AuthenticatedSession struct {
	TenantID  string
	AccountID string
	ClientID  string
	SessionID protocol.SessionID
}

type Normalizer interface {
	Normalize(context.Context, NormalizationRequest) (normalize.Prepared, error)
}

type SessionSource interface {
	Current(context.Context) (AuthenticatedSession, error)
}

type RouteResolver interface {
	Resolve(string) (routing.Route, error)
}

// DecisionRequest binds the authenticated identity and selected authority to
// the protocol action without placing trusted identity in caller-controlled
// protocol fields.
type DecisionRequest struct {
	Destination string
	Session     AuthenticatedSession
	Action      protocol.ActionRequest
}

type Decider interface {
	Decide(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error)
}

// ProtocolClient is implemented directly by *decision.Client.
type ProtocolClient interface {
	Decide(context.Context, protocol.ActionRequest) (protocol.AuthorizationDecision, error)
}

// ClientSelector returns a client already bound to the selected authority and
// authenticated session. It must not derive session fields from the action.
type ClientSelector interface {
	Client(context.Context, string, AuthenticatedSession) (ProtocolClient, error)
}

type RemoteDecider struct{ clients ClientSelector }

func NewRemoteDecider(clients ClientSelector) *RemoteDecider {
	if isNil(clients) {
		return nil
	}
	return &RemoteDecider{clients: clients}
}

func (d *RemoteDecider) Decide(
	ctx context.Context,
	request DecisionRequest,
) (protocol.AuthorizationDecision, error) {
	if d == nil || ctx == nil || ctx.Err() != nil {
		return protocol.AuthorizationDecision{}, decision.ErrUnavailable
	}
	client, err := d.clients.Client(ctx, request.Destination, request.Session)
	if err != nil || isNil(client) || ctx.Err() != nil {
		return protocol.AuthorizationDecision{}, decision.ErrUnavailable
	}
	// Exactly one call: neither this adapter nor Checker contains retry, cache,
	// or fallback behavior.
	return client.Decide(ctx, request.Action)
}

var ErrNoSession = errors.New("no authenticated session")

type Outcome string

const (
	OutcomeAllow            Outcome = "allow"
	OutcomeDeny             Outcome = "deny"
	OutcomeApprovalRequired Outcome = "approval_required"
	OutcomeError            Outcome = "error"
)

type Code string

const (
	CodeAllowed                  Code = "allowed"
	CodePolicyDenied             Code = "policy_denied"
	CodeApprovalRequired         Code = "approval_required"
	CodeInvalidRequest           Code = "invalid_request"
	CodeMissingIdentity          Code = "missing_identity"
	CodeUnknownRoute             Code = "unknown_route"
	CodeAuthorizationUnavailable Code = "authorization_unavailable"
	CodeInvalidDecision          Code = "invalid_decision"
)

// Result is safe to render or serialize. It intentionally contains neither
// raw normalization input nor the executor-bound value in normalize.Prepared.
type Result struct {
	Allowed                bool                  `json:"allowed"`
	Outcome                Outcome               `json:"outcome"`
	Code                   Code                  `json:"code"`
	SafeMessage            protocol.SafeText     `json:"safeMessage"`
	RequestID              protocol.RequestID    `json:"requestId,omitempty"`
	DecisionID             protocol.DecisionID   `json:"decisionId,omitempty"`
	ApprovalID             protocol.ApprovalID   `json:"approvalId,omitempty"`
	AuditRef               protocol.AuditRef     `json:"auditRef,omitempty"`
	ClientScopeHash        protocol.SHA256Digest `json:"clientScopeHash,omitempty"`
	AuthoritativeScopeHash protocol.SHA256Digest `json:"authoritativeScopeHash,omitempty"`
}

func (r Result) String() string {
	return fmt.Sprintf(
		"guard.Result{allowed:%t outcome:%s code:%s requestId:%s decisionId:%s}",
		r.Allowed, r.Outcome, r.Code, r.RequestID, r.DecisionID,
	)
}

func (r Result) GoString() string { return r.String() }

func (r Result) LogValue() slog.Value {
	return slog.GroupValue(
		slog.Bool("allowed", r.Allowed),
		slog.String("outcome", string(r.Outcome)),
		slog.String("code", string(r.Code)),
		slog.String("requestId", string(r.RequestID)),
		slog.String("decisionId", string(r.DecisionID)),
	)
}

type Checker struct {
	normalizer Normalizer
	sessions   SessionSource
	routes     RouteResolver
	decider    Decider
}

func New(normalizer Normalizer, sessions SessionSource, routes RouteResolver, decider Decider) *Checker {
	if isNil(normalizer) || isNil(sessions) || isNil(routes) || isNil(decider) {
		return nil
	}
	return &Checker{normalizer: normalizer, sessions: sessions, routes: routes, decider: decider}
}

func isNil(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	default:
		return false
	}
}

var trustedClient = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
var sessionID = regexp.MustCompile(`^session_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)

func validTrustedText(value string) bool {
	if value == "" || len(value) > normalize.MaxStringBytes {
		return false
	}
	for _, character := range value {
		if character <= 0x1f || character >= 0x7f && character <= 0x9f ||
			character == 0x061c || character == 0x200e || character == 0x200f ||
			character >= 0x2028 && character <= 0x202e ||
			character >= 0x2066 && character <= 0x2069 {
			return false
		}
	}
	return true
}

func validateSession(session AuthenticatedSession) bool {
	return validTrustedText(session.TenantID) &&
		validTrustedText(session.AccountID) &&
		trustedClient.MatchString(session.ClientID) &&
		sessionID.MatchString(string(session.SessionID))
}

func (c *Checker) Check(ctx context.Context, input Input) Result {
	if c == nil || ctx == nil || ctx.Err() != nil {
		return failure(CodeAuthorizationUnavailable)
	}

	prepared, err := c.normalizer.Normalize(ctx, input.Normalization)
	if err != nil {
		if ctx.Err() != nil {
			return failure(CodeAuthorizationUnavailable)
		}
		return failure(CodeInvalidRequest)
	}
	if ctx.Err() != nil {
		return failure(CodeAuthorizationUnavailable)
	}

	session, err := c.sessions.Current(ctx)
	if err != nil {
		if ctx.Err() != nil {
			return failure(CodeAuthorizationUnavailable)
		}
		if errors.Is(err, ErrNoSession) {
			return failure(CodeMissingIdentity)
		}
		return failure(CodeAuthorizationUnavailable)
	}
	if !validateSession(session) {
		return failure(CodeMissingIdentity)
	}
	if ctx.Err() != nil {
		return failure(CodeAuthorizationUnavailable)
	}

	route, err := c.routes.Resolve(input.RouteTarget)
	if err != nil || route.Destination == "" {
		if ctx.Err() != nil {
			return failure(CodeAuthorizationUnavailable)
		}
		return failure(CodeUnknownRoute)
	}
	if ctx.Err() != nil {
		return failure(CodeAuthorizationUnavailable)
	}

	target, err := prepared.Target(input.Normalization.Kind, input.Normalization.Service)
	if err != nil {
		return failure(CodeInvalidRequest)
	}
	action := input.Action
	action.Target = target
	if err := action.ValidateStructural(); err != nil {
		return failure(CodeInvalidRequest)
	}
	// The client-visible hash includes the diagnostic adapter label. Trusted
	// tenant/account/client identity remains out-of-band and is available only
	// to the authenticated transport/server authoritative-scope calculation.
	if _, err := decision.ClientScopeHash(action); err != nil {
		return failure(CodeInvalidRequest)
	}

	value, decideErr := c.decider.Decide(ctx, DecisionRequest{
		Destination: route.Destination,
		Session:     session,
		Action:      action,
	})
	if ctx.Err() != nil {
		return failure(CodeAuthorizationUnavailable)
	}
	return renderDecision(action, value, decideErr)
}

func renderDecision(
	request protocol.ActionRequest,
	value protocol.AuthorizationDecision,
	err error,
) Result {
	if err != nil {
		var outcome *decision.OutcomeError
		if errors.As(err, &outcome) {
			if !reflect.DeepEqual(outcome.Decision, value) ||
				!validDecisionForRequest(request, value) {
				return failure(CodeInvalidDecision)
			}
			switch value.Outcome {
			case protocol.DecisionOutcomeDeny:
				return verifiedResult(value, OutcomeDeny, CodePolicyDenied, false)
			case protocol.DecisionOutcomeApprovalRequired:
				if value.Approval == nil {
					return failure(CodeInvalidDecision)
				}
				return verifiedResult(value, OutcomeApprovalRequired, CodeApprovalRequired, false)
			default:
				return failure(CodeInvalidDecision)
			}
		}
		if errors.Is(err, decision.ErrInvalidRequest) {
			return failure(CodeInvalidRequest)
		}
		if errors.Is(err, decision.ErrInvalidDecision) {
			return failure(CodeInvalidDecision)
		}
		return failure(CodeAuthorizationUnavailable)
	}
	if value.Outcome != protocol.DecisionOutcomeAllow {
		return failure(CodeInvalidDecision)
	}
	if !validDecisionForRequest(request, value) {
		return failure(CodeInvalidDecision)
	}
	return verifiedResult(value, OutcomeAllow, CodeAllowed, true)
}

func validDecisionForRequest(request protocol.ActionRequest, value protocol.AuthorizationDecision) bool {
	if err := value.ValidateStructural(); err != nil {
		return false
	}
	scope, err := decision.ClientScopeHash(request)
	return err == nil &&
		value.RequestID == request.RequestID &&
		value.CorrelationID == request.CorrelationID &&
		value.ClientScopeHash == scope &&
		value.AuthoritativeScopeHash != ""
}

func verifiedResult(
	value protocol.AuthorizationDecision,
	outcome Outcome,
	code Code,
	allowed bool,
) Result {
	if !validSafeDisplay(value.DisplayReason) {
		return failure(CodeInvalidDecision)
	}
	result := Result{
		Allowed: allowed, Outcome: outcome, Code: code, SafeMessage: outcomeMessage(outcome),
		RequestID: value.RequestID, DecisionID: value.DecisionID, AuditRef: value.AuditRef,
		ClientScopeHash: value.ClientScopeHash, AuthoritativeScopeHash: value.AuthoritativeScopeHash,
	}
	if value.Approval != nil {
		result.ApprovalID = value.Approval.ApprovalID
	}
	return result
}

func outcomeMessage(outcome Outcome) protocol.SafeText {
	switch outcome {
	case OutcomeAllow:
		return "The action is authorized."
	case OutcomeDeny:
		return "Current policy denies this action."
	case OutcomeApprovalRequired:
		return "Approval is required before this action can run."
	default:
		return "The request was not authorized."
	}
}

func validSafeDisplay(value protocol.SafeText) bool {
	text := string(value)
	return text != "" && len(text) <= 512 && !strings.ContainsAny(text, "\x00\r\n")
}

func failure(code Code) Result {
	message := protocol.SafeText("The request was not authorized.")
	switch code {
	case CodeInvalidRequest:
		message = "The request is invalid."
	case CodeMissingIdentity:
		message = "Identity is required."
	case CodeUnknownRoute:
		message = "No authorization route is configured."
	case CodeInvalidDecision:
		message = "The authorization decision is invalid."
	case CodeAuthorizationUnavailable:
		message = "Authorization is temporarily unavailable."
	}
	return Result{Outcome: OutcomeError, Code: code, SafeMessage: message}
}
