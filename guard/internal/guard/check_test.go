// SPDX-License-Identifier: MIT
package guard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/decision"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/normalize"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/routing"
	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

type normalizerFunc func(context.Context, NormalizationRequest) (normalize.Prepared, error)

func (f normalizerFunc) Normalize(ctx context.Context, request NormalizationRequest) (normalize.Prepared, error) {
	return f(ctx, request)
}

type sessionSourceFunc func(context.Context) (AuthenticatedSession, error)

func (f sessionSourceFunc) Current(ctx context.Context) (AuthenticatedSession, error) {
	return f(ctx)
}

type routeResolverFunc func(context.Context, string) (routing.Route, error)

func (f routeResolverFunc) Resolve(
	ctx context.Context,
	target string,
) (routing.Route, error) {
	return f(ctx, target)
}

type deciderFunc func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error)

func (f deciderFunc) Decide(ctx context.Context, request DecisionRequest) (protocol.AuthorizationDecision, error) {
	return f(ctx, request)
}

type clientSelectorFunc func(context.Context, string, AuthenticatedSession) (ProtocolClient, error)

func (f clientSelectorFunc) Client(
	ctx context.Context,
	destination string,
	session AuthenticatedSession,
) (ProtocolClient, error) {
	return f(ctx, destination, session)
}

type protocolClientFunc func(context.Context, protocol.ActionRequest) (protocol.AuthorizationDecision, error)

func (f protocolClientFunc) Decide(
	ctx context.Context,
	request protocol.ActionRequest,
) (protocol.AuthorizationDecision, error) {
	return f(ctx, request)
}

type wrappedError struct{ inner error }

func (wrappedError) Error() string   { return "wrapped decision failure" }
func (e wrappedError) Unwrap() error { return e.inner }

type adversarialAsError struct{}

func (adversarialAsError) Error() string { return "adversarial decision failure" }
func (adversarialAsError) As(target any) bool {
	slot, ok := target.(**decision.OutcomeError)
	if !ok {
		return false
	}
	*slot = nil
	return true
}

type typedNilContext struct{}

func (*typedNilContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*typedNilContext) Done() <-chan struct{}       { return nil }
func (*typedNilContext) Err() error {
	panic("typed nil context Err must not be called")
}
func (*typedNilContext) Value(any) any { return nil }

func validInput() Input {
	return Input{
		Normalization: NormalizationRequest{
			Kind: protocol.TargetKindMCPTool, Service: "github",
			Opaque: json.RawMessage(`{"token":"raw-secret","title":"safe"}`),
		},
		RouteTarget: "github.example.com",
		Action: protocol.ActionRequest{
			SchemaVersion:  "1",
			ActionID:       "act_01J5ABCDEFGHJKMNPQRSTVWXY0",
			RequestID:      "req_01J5ABCDEFGHJKMNPQRSTVWXY0",
			CorrelationID:  "corr_01J5ABCDEFGHJKMNPQRSTVWXY0",
			IdempotencyKey: "authz_01J5ABCDEFGHJKMNPQRSTVWXY0",
			Adapter: protocol.Adapter{
				ID: "caller-claims-privileged", Version: "0.2.0-alpha.1", HostVersion: "0.145.0",
			},
			Task: protocol.TaskBinding{
				TaskID: "task_01J5ABCDEFGHJKMNPQRSTVWXY0", SessionID: "session_01J5ABCDEFGHJKMNPQRSTVWXY0",
			},
			Action:     protocol.ActionNameMCPCall,
			SideEffect: protocol.SideEffectExternal,
			OccurredAt: "2026-07-25T20:01:00Z",
			Context: protocol.ActionContext{
				ToolName: ptrSafe("github.create_issue"),
			},
		},
	}
}

func ptrSafe(value protocol.SafeText) *protocol.SafeText { return &value }

func validSession() AuthenticatedSession {
	return AuthenticatedSession{
		TenantID: "tenant-a", AccountID: "account-a", ClientID: "registered-codex",
		SessionID: "session_01J5ABCDEFGHJKMNPQRSTVWXYZ",
	}
}

func validPrepared(t *testing.T) normalize.Prepared {
	t.Helper()
	value, err := normalize.MCPJSON("github", "issues.create", []byte(`{"token":"raw-secret","title":"safe"}`))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func validDecision(request protocol.ActionRequest, outcome protocol.DecisionOutcome) protocol.AuthorizationDecision {
	scope, _ := decision.ClientScopeHash(request)
	result := protocol.AuthorizationDecision{
		SchemaVersion: "1", RequestID: request.RequestID,
		DecisionID:    "dec_01J5ABCDEFGHJKMNPQRSTVWXY0",
		CorrelationID: request.CorrelationID, Outcome: outcome,
		ReasonCode: "policy_result", DisplayReason: "Request evaluated.",
		ClientScopeHash:        scope,
		AuthoritativeScopeHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		PolicyRevision:         "policy_v1", ServerTime: "2026-07-25T20:01:01Z",
		ExpiresAt: "2026-07-25T20:02:01Z", AuditRef: "audit_01J5ABCDEFGHJKMNPQRSTVWXY0",
		Cache: protocol.CacheDirective{Cacheable: false},
	}
	if outcome == protocol.DecisionOutcomeApprovalRequired {
		result.Approval = &protocol.ApprovalSummary{
			ApprovalID: "apr_01J5ABCDEFGHJKMNPQRSTVWXY0",
			Status:     protocol.ApprovalStatusPending, ExpiresAt: "2026-07-25T20:03:01Z",
		}
	}
	return result
}

func pipeline(t *testing.T, decide deciderFunc) *Checker {
	t.Helper()
	prepared := validPrepared(t)
	return New(
		normalizerFunc(func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
			return prepared, nil
		}),
		sessionSourceFunc(func(context.Context) (AuthenticatedSession, error) {
			return validSession(), nil
		}),
		routeResolverFunc(func(_ context.Context, target string) (routing.Route, error) {
			return routing.Route{Target: target, Destination: "https://decision.example/v1/authorize"}, nil
		}),
		decide,
	)
}

func TestCheckRunsPipelineAndBindsTrustedIdentityAndNormalizedTarget(t *testing.T) {
	var calls int
	checker := pipeline(t, func(ctx context.Context, envelope DecisionRequest) (protocol.AuthorizationDecision, error) {
		calls++
		if ctx == nil {
			t.Fatal("nil context")
		}
		if envelope.Destination != "https://decision.example/v1/authorize" {
			t.Fatalf("destination = %q", envelope.Destination)
		}
		if envelope.Session != validSession() {
			t.Fatalf("session = %#v", envelope.Session)
		}
		if envelope.Action.Adapter.ID != "caller-claims-privileged" {
			t.Fatalf("diagnostic adapter lost: %#v", envelope.Action.Adapter)
		}
		if strings.Contains(fmt.Sprintf("%#v", envelope.Session), "caller-claims") {
			t.Fatal("caller adapter influenced authenticated session")
		}
		if envelope.Action.Target.Service != "github" ||
			envelope.Action.Target.Kind != protocol.TargetKindMCPTool ||
			!strings.HasPrefix(string(envelope.Action.Target.Resource), "mcp:github/issues.create#sha256:") {
			t.Fatalf("target = %#v", envelope.Action.Target)
		}
		if _, err := decision.ClientScopeHash(envelope.Action); err != nil {
			t.Fatalf("invalid resource/scope binding: %v", err)
		}
		return validDecision(envelope.Action, protocol.DecisionOutcomeAllow), nil
	})

	result := checker.Check(context.Background(), validInput())
	if calls != 1 || !result.Allowed || result.Outcome != OutcomeAllow {
		t.Fatalf("result = %#v, calls = %d", result, calls)
	}
}

func TestOutboundActionUsesExplicitScalarAllowlistAndDropsCallerPayloads(t *testing.T) {
	const secret = "SECRET-SENTINEL-MUST-NOT-LEAVE-GUARD"
	input := validInput()
	input.Normalization.Opaque = map[string]any{
		"raw": []any{map[string]any{"deep": secret}},
	}
	causation := protocol.CausationID("dec_01J5ABCDEFGHJKMNPQRSTVWXY9")
	approval := protocol.ApprovalID("apr_01J5ABCDEFGHJKMNPQRSTVWXY9")
	input.Action.CausationID = &causation
	input.Action.ResumeFromApprovalID = &approval
	input.Action.Adapter.Extensions = &map[string]any{
		"dev.palonexus.secret.v1": map[string]any{"nested": []any{secret}},
	}
	input.Action.Task.Extensions = &map[string]any{
		"dev.palonexus.secret.v1": secret,
	}
	input.Action.Target = protocol.ActionTarget{
		Kind: protocol.TargetKindTool, Service: "attacker.example",
		Resource:     protocol.SafeText(secret),
		ResourceHash: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Extensions:   &map[string]any{"dev.palonexus.secret.v1": secret},
	}
	input.Action.Context = protocol.ActionContext{
		Cwd: ptrSafe(secret), Repository: ptrSafe(secret), ToolName: ptrSafe(secret),
		SafeDisplay: ptrSafe(secret),
		Extensions:  &map[string]any{"dev.palonexus.secret.v1": []any{secret}},
	}
	input.Action.Extensions = &map[string]any{
		"dev.palonexus.secret.v1": map[string]any{"deep": map[string]any{"value": secret}},
	}

	checker := pipeline(t, func(_ context.Context, envelope DecisionRequest) (protocol.AuthorizationDecision, error) {
		wire, err := json.Marshal(envelope.Action)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(wire), secret) {
			t.Fatalf("caller payload reached authority: %s", wire)
		}
		action := envelope.Action
		if action.SchemaVersion != input.Action.SchemaVersion ||
			action.ActionID != input.Action.ActionID ||
			action.RequestID != input.Action.RequestID ||
			action.CorrelationID != input.Action.CorrelationID ||
			action.IdempotencyKey != input.Action.IdempotencyKey ||
			action.Adapter.ID != input.Action.Adapter.ID ||
			action.Adapter.Version != input.Action.Adapter.Version ||
			action.Adapter.HostVersion != input.Action.Adapter.HostVersion ||
			action.Task.TaskID != input.Action.Task.TaskID ||
			action.Task.SessionID != input.Action.Task.SessionID ||
			action.Action != input.Action.Action ||
			action.SideEffect != input.Action.SideEffect ||
			action.OccurredAt != input.Action.OccurredAt {
			t.Fatalf("required scalar binding drifted: %#v", action)
		}
		if action.CausationID == nil || *action.CausationID != causation ||
			action.ResumeFromApprovalID == nil || *action.ResumeFromApprovalID != approval {
			t.Fatalf("optional scalar binding drifted: %#v", action)
		}
		if action.Adapter.Extensions != nil || action.Task.Extensions != nil ||
			action.Target.Extensions != nil || action.Extensions != nil ||
			action.Context != (protocol.ActionContext{}) {
			t.Fatalf("caller-owned nested values survived: %#v", action)
		}
		if _, err := decision.ClientScopeHash(action); err != nil {
			t.Fatalf("sanitized action is invalid: %v", err)
		}
		return validDecision(action, protocol.DecisionOutcomeAllow), nil
	})
	if got := checker.Check(context.Background(), input); !got.Allowed {
		t.Fatalf("result = %#v", got)
	}
}

func TestCheckCallsDecideExactlyOnceAndNeverUsesAnOfflineAllow(t *testing.T) {
	var calls atomic.Int32
	checker := pipeline(t, func(_ context.Context, request DecisionRequest) (protocol.AuthorizationDecision, error) {
		call := calls.Add(1)
		if call == 1 {
			return validDecision(request.Action, protocol.DecisionOutcomeAllow), nil
		}
		return protocol.AuthorizationDecision{}, decision.ErrUnavailable
	})
	input := validInput()
	if result := checker.Check(context.Background(), input); !result.Allowed {
		t.Fatalf("first = %#v", result)
	}
	if result := checker.Check(context.Background(), input); result.Allowed || result.Code != CodeAuthorizationUnavailable {
		t.Fatalf("second used fallback/cache: %#v", result)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestRemoteDeciderSelectsAuthenticatedClientAndUsesProductionDecisionSignature(t *testing.T) {
	var selected, called int
	remote := NewRemoteDecider(clientSelectorFunc(func(
		_ context.Context,
		destination string,
		session AuthenticatedSession,
	) (ProtocolClient, error) {
		selected++
		if destination != "https://decision.example/v1/authorize" || session != validSession() {
			t.Fatalf("selection = %q %#v", destination, session)
		}
		return protocolClientFunc(func(_ context.Context, request protocol.ActionRequest) (protocol.AuthorizationDecision, error) {
			called++
			return validDecision(request, protocol.DecisionOutcomeAllow), nil
		}), nil
	}))
	result := New(
		normalizerFunc(func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
			return validPrepared(t), nil
		}),
		sessionSourceFunc(func(context.Context) (AuthenticatedSession, error) { return validSession(), nil }),
		routeResolverFunc(func(_ context.Context, target string) (routing.Route, error) {
			return routing.Route{Target: target, Destination: "https://decision.example/v1/authorize"}, nil
		}),
		remote,
	).Check(context.Background(), validInput())
	if !result.Allowed || selected != 1 || called != 1 {
		t.Fatalf("result %#v selected %d called %d", result, selected, called)
	}
}

func TestCheckMapsVerifiedOutcomesDeterministically(t *testing.T) {
	tests := []struct {
		outcome protocol.DecisionOutcome
		want    Outcome
		allowed bool
	}{
		{protocol.DecisionOutcomeAllow, OutcomeAllow, true},
		{protocol.DecisionOutcomeDeny, OutcomeDeny, false},
		{protocol.DecisionOutcomeApprovalRequired, OutcomeApprovalRequired, false},
	}
	for _, test := range tests {
		t.Run(string(test.outcome), func(t *testing.T) {
			checker := pipeline(t, func(_ context.Context, request DecisionRequest) (protocol.AuthorizationDecision, error) {
				value := validDecision(request.Action, test.outcome)
				if test.outcome == protocol.DecisionOutcomeAllow {
					return value, nil
				}
				return value, &decision.OutcomeError{Decision: value}
			})
			got := checker.Check(context.Background(), validInput())
			if got.Outcome != test.want || got.Allowed != test.allowed ||
				got.DecisionID == "" || got.ClientScopeHash == "" || got.AuthoritativeScopeHash == "" {
				t.Fatalf("result = %#v", got)
			}
			if test.outcome == protocol.DecisionOutcomeApprovalRequired && got.ApprovalID == "" {
				t.Fatal("approval id missing")
			}
		})
	}
}

func TestCheckFailsClosedBeforeDecision(t *testing.T) {
	tests := []struct {
		name    string
		normal  normalizerFunc
		session sessionSourceFunc
		route   routeResolverFunc
		code    Code
	}{
		{
			name: "normalization", normal: func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
				return normalize.Prepared{}, errors.New("normalization contained raw-secret")
			},
			session: func(context.Context) (AuthenticatedSession, error) { return validSession(), nil },
			route:   func(context.Context, string) (routing.Route, error) { return routing.Route{}, nil },
			code:    CodeInvalidRequest,
		},
		{
			name: "missing login", normal: func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
				return validPrepared(t), nil
			},
			session: func(context.Context) (AuthenticatedSession, error) { return AuthenticatedSession{}, ErrNoSession },
			route:   func(context.Context, string) (routing.Route, error) { return routing.Route{}, nil },
			code:    CodeMissingIdentity,
		},
		{
			name: "unknown route", normal: func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
				return validPrepared(t), nil
			},
			session: func(context.Context) (AuthenticatedSession, error) { return validSession(), nil },
			route: func(context.Context, string) (routing.Route, error) {
				return routing.Route{}, routing.ErrUnknownTarget
			},
			code: CodeUnknownRoute,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var calls int
			checker := New(test.normal, test.session, test.route,
				deciderFunc(func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
					calls++
					return protocol.AuthorizationDecision{}, nil
				}))
			got := checker.Check(context.Background(), validInput())
			if got.Allowed || got.Outcome != OutcomeError || got.Code != test.code || calls != 0 {
				t.Fatalf("result = %#v, calls = %d", got, calls)
			}
		})
	}
}

func TestSessionStoreOutageIsNotMisreportedAsMissingLogin(t *testing.T) {
	checker := New(
		normalizerFunc(func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
			return validPrepared(t), nil
		}),
		sessionSourceFunc(func(context.Context) (AuthenticatedSession, error) {
			return AuthenticatedSession{}, errors.New("storage outage with raw-secret")
		}),
		routeResolverFunc(func(context.Context, string) (routing.Route, error) {
			t.Fatal("route called")
			return routing.Route{}, nil
		}),
		deciderFunc(func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
			t.Fatal("decide called")
			return protocol.AuthorizationDecision{}, nil
		}),
	)
	got := checker.Check(context.Background(), validInput())
	if got.Allowed || got.Code != CodeAuthorizationUnavailable {
		t.Fatalf("result = %#v", got)
	}
}

func TestCheckFailsClosedOnDecisionFailuresAndMalformedCombinations(t *testing.T) {
	tests := []struct {
		name string
		fn   deciderFunc
		code Code
	}{
		{"outage", func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
			return protocol.AuthorizationDecision{}, decision.ErrUnavailable
		}, CodeAuthorizationUnavailable},
		{"invalid", func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
			return protocol.AuthorizationDecision{}, decision.ErrInvalidDecision
		}, CodeInvalidDecision},
		{"allow with error", func(_ context.Context, request DecisionRequest) (protocol.AuthorizationDecision, error) {
			return validDecision(request.Action, protocol.DecisionOutcomeAllow), errors.New("raw-secret upstream")
		}, CodeAuthorizationUnavailable},
		{"deny without typed error", func(_ context.Context, request DecisionRequest) (protocol.AuthorizationDecision, error) {
			return validDecision(request.Action, protocol.DecisionOutcomeDeny), nil
		}, CodeInvalidDecision},
		{"unknown outcome", func(_ context.Context, request DecisionRequest) (protocol.AuthorizationDecision, error) {
			value := validDecision(request.Action, protocol.DecisionOutcomeAllow)
			value.Outcome = "surprise"
			return value, nil
		}, CodeInvalidDecision},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := pipeline(t, test.fn).Check(context.Background(), validInput())
			if got.Allowed || got.Outcome != OutcomeError || got.Code != test.code {
				t.Fatalf("result = %#v", got)
			}
		})
	}
}

func TestTypedNilOutcomeErrorsFailClosedWithoutPanic(t *testing.T) {
	var typedNil *decision.OutcomeError
	for _, test := range []struct {
		name string
		err  error
	}{
		{"direct", typedNil},
		{"wrapped", wrappedError{inner: typedNil}},
		{"multiply wrapped", wrappedError{inner: wrappedError{inner: typedNil}}},
		{"adversarial As", adversarialAsError{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := pipeline(t, func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
				return protocol.AuthorizationDecision{}, test.err
			}).Check(context.Background(), validInput())
			if got.Allowed || got.Outcome != OutcomeError || got.Code != CodeInvalidDecision {
				t.Fatalf("result = %#v", got)
			}
		})
	}
}

func TestCheckRejectsInvalidTrustedIdentityAndCannotSourceItFromAdapter(t *testing.T) {
	input := validInput()
	input.Action.Adapter.ID = "registered-admin"
	for _, session := range []AuthenticatedSession{
		{},
		{TenantID: "tenant-a", AccountID: "account-a", ClientID: "registered-admin\n", SessionID: validSession().SessionID},
		{TenantID: "tenant\nadmin", AccountID: "account-a", ClientID: "registered-admin", SessionID: validSession().SessionID},
	} {
		var calls int
		checker := New(
			normalizerFunc(func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
				return validPrepared(t), nil
			}),
			sessionSourceFunc(func(context.Context) (AuthenticatedSession, error) { return session, nil }),
			routeResolverFunc(func(context.Context, string) (routing.Route, error) {
				return routing.Route{Destination: "https://decision.example"}, nil
			}),
			deciderFunc(func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
				calls++
				return protocol.AuthorizationDecision{}, nil
			}),
		)
		got := checker.Check(context.Background(), input)
		if got.Allowed || got.Code != CodeMissingIdentity || calls != 0 {
			t.Fatalf("session %#v: result %#v, calls %d", session, got, calls)
		}
	}
}

func TestResultAndDiagnosticsNeverExposeRawOrExecutionValues(t *testing.T) {
	checker := pipeline(t, func(_ context.Context, request DecisionRequest) (protocol.AuthorizationDecision, error) {
		value := validDecision(request.Action, protocol.DecisionOutcomeDeny)
		// Even a structurally safe server string is not trusted to avoid
		// reflecting request material.
		value.DisplayReason = "raw-secret"
		return value, &decision.OutcomeError{Decision: value}
	})
	result := checker.Check(context.Background(), validInput())
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{string(encoded), fmt.Sprint(result), fmt.Sprintf("%#v", result)} {
		if strings.Contains(rendered, "raw-secret") || strings.Contains(rendered, `"title":"safe"`) ||
			strings.Contains(rendered, "caller-claims-privileged") ||
			strings.Contains(rendered, "tenant-a") || strings.Contains(rendered, "account-a") ||
			strings.Contains(rendered, "registered-codex") {
			t.Fatalf("sensitive input escaped: %s", rendered)
		}
	}
}

func TestCancellationStopsEachStageAndNeverAllows(t *testing.T) {
	stages := []string{"normalize", "session", "route", "decide"}
	for _, stage := range stages {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			var decideCalls atomic.Int32
			block := func(ctx context.Context) {
				cancel()
				<-ctx.Done()
			}
			checker := New(
				normalizerFunc(func(ctx context.Context, _ NormalizationRequest) (normalize.Prepared, error) {
					if stage == "normalize" {
						block(ctx)
					}
					return validPrepared(t), ctx.Err()
				}),
				sessionSourceFunc(func(ctx context.Context) (AuthenticatedSession, error) {
					if stage == "session" {
						block(ctx)
					}
					return validSession(), ctx.Err()
				}),
				routeResolverFunc(func(_ context.Context, target string) (routing.Route, error) {
					if stage == "route" {
						cancel()
					}
					return routing.Route{Target: target, Destination: "https://decision.example"}, nil
				}),
				deciderFunc(func(ctx context.Context, _ DecisionRequest) (protocol.AuthorizationDecision, error) {
					decideCalls.Add(1)
					if stage == "decide" {
						block(ctx)
					}
					return protocol.AuthorizationDecision{}, ctx.Err()
				}),
			)
			got := checker.Check(ctx, validInput())
			if got.Allowed || got.Code != CodeAuthorizationUnavailable {
				t.Fatalf("result = %#v", got)
			}
			if stage != "decide" && decideCalls.Load() != 0 {
				t.Fatalf("decision calls = %d", decideCalls.Load())
			}
		})
	}
}

func TestBlockingRouteResolverHonorsCancellationWithoutDetachedWork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	returned := make(chan struct{})
	checker := New(
		normalizerFunc(func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
			return validPrepared(t), nil
		}),
		sessionSourceFunc(func(context.Context) (AuthenticatedSession, error) { return validSession(), nil }),
		routeResolverFunc(func(ctx context.Context, _ string) (routing.Route, error) {
			close(started)
			defer close(returned)
			<-ctx.Done()
			return routing.Route{}, ctx.Err()
		}),
		deciderFunc(func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
			t.Fatal("decide called")
			return protocol.AuthorizationDecision{}, nil
		}),
	)
	result := make(chan Result, 1)
	go func() { result <- checker.Check(ctx, validInput()) }()
	<-started
	cancel()
	select {
	case got := <-result:
		if got.Allowed || got.Code != CodeAuthorizationUnavailable {
			t.Fatalf("result = %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("check did not return after route cancellation")
	}
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("route work leaked after check returned")
	}
}

func TestRouteResolverAlwaysReceivesBoundedCallerContext(t *testing.T) {
	now := time.Now()
	checker := New(
		normalizerFunc(func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
			return validPrepared(t), nil
		}),
		sessionSourceFunc(func(context.Context) (AuthenticatedSession, error) { return validSession(), nil }),
		routeResolverFunc(func(ctx context.Context, target string) (routing.Route, error) {
			deadline, ok := ctx.Deadline()
			if !ok || deadline.Before(now) || deadline.After(now.Add(MaxCheckDuration+time.Second)) {
				t.Fatalf("resolver deadline = %v, present = %t", deadline, ok)
			}
			return routing.Route{Target: target, Destination: "https://decision.example"}, nil
		}),
		deciderFunc(func(_ context.Context, request DecisionRequest) (protocol.AuthorizationDecision, error) {
			return validDecision(request.Action, protocol.DecisionOutcomeAllow), nil
		}),
	)
	if got := checker.Check(context.Background(), validInput()); !got.Allowed {
		t.Fatalf("result = %#v", got)
	}
}

func TestTableRouteResolverAdaptsProductionRoutingTableAndHonorsContext(t *testing.T) {
	table, err := routing.New([]routing.Route{{
		Target: "github.example.com", Destination: "https://decision.example",
	}})
	if err != nil {
		t.Fatal(err)
	}
	resolver := NewTableRouteResolver(table)
	route, err := resolver.Resolve(context.Background(), "GITHUB.EXAMPLE.COM.")
	if err != nil || route.Destination != "https://decision.example" {
		t.Fatalf("route %#v, error %v", route, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.Resolve(ctx, "github.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled error = %v", err)
	}
	if NewTableRouteResolver(nil) != nil {
		t.Fatal("nil routing table accepted")
	}
}

func TestCheckIsRaceSafeForConcurrentActions(t *testing.T) {
	var calls atomic.Int32
	checker := pipeline(t, func(_ context.Context, request DecisionRequest) (protocol.AuthorizationDecision, error) {
		calls.Add(1)
		return validDecision(request.Action, protocol.DecisionOutcomeAllow), nil
	})
	const workers = 64
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			if got := checker.Check(context.Background(), validInput()); !got.Allowed {
				t.Errorf("result = %#v", got)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != workers {
		t.Fatalf("calls = %d", calls.Load())
	}
}

func TestNewRejectsMissingDependenciesAndNilContextFailsClosed(t *testing.T) {
	if New(nil, nil, nil, nil) != nil {
		t.Fatal("accepted missing dependencies")
	}
	checker := pipeline(t, func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
		t.Fatal("decide called")
		return protocol.AuthorizationDecision{}, nil
	})
	if got := checker.Check(nil, validInput()); got.Allowed || got.Code != CodeAuthorizationUnavailable {
		t.Fatalf("result = %#v", got)
	}
}

func TestTypedNilContextsFailClosedWithoutCallingMethods(t *testing.T) {
	var ctx *typedNilContext
	var calls atomic.Int32
	checker := pipeline(t, func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
		calls.Add(1)
		return protocol.AuthorizationDecision{}, nil
	})
	if got := checker.Check(ctx, validInput()); got.Allowed || got.Code != CodeAuthorizationUnavailable {
		t.Fatalf("check result = %#v", got)
	}
	remote := NewRemoteDecider(clientSelectorFunc(func(
		context.Context, string, AuthenticatedSession,
	) (ProtocolClient, error) {
		calls.Add(1)
		return nil, nil
	}))
	if _, err := remote.Decide(ctx, DecisionRequest{}); !errors.Is(err, decision.ErrUnavailable) {
		t.Fatalf("remote error = %v", err)
	}
	if calls.Load() != 0 {
		t.Fatalf("downstream calls = %d", calls.Load())
	}
}

func TestDeadlineAlreadyExpiredSkipsPipeline(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	var calls int
	checker := New(
		normalizerFunc(func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
			calls++
			return validPrepared(t), nil
		}),
		sessionSourceFunc(func(context.Context) (AuthenticatedSession, error) { return validSession(), nil }),
		routeResolverFunc(func(context.Context, string) (routing.Route, error) {
			return routing.Route{}, nil
		}),
		deciderFunc(func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
			return protocol.AuthorizationDecision{}, nil
		}),
	)
	if got := checker.Check(ctx, validInput()); got.Allowed || got.Code != CodeAuthorizationUnavailable || calls != 0 {
		t.Fatalf("result %#v calls %d", got, calls)
	}
}
