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

type routeResolverFunc func(string) (routing.Route, error)

func (f routeResolverFunc) Resolve(target string) (routing.Route, error) { return f(target) }

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
		routeResolverFunc(func(target string) (routing.Route, error) {
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
		routeResolverFunc(func(target string) (routing.Route, error) {
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
			route:   func(string) (routing.Route, error) { return routing.Route{}, nil },
			code:    CodeInvalidRequest,
		},
		{
			name: "missing login", normal: func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
				return validPrepared(t), nil
			},
			session: func(context.Context) (AuthenticatedSession, error) { return AuthenticatedSession{}, ErrNoSession },
			route:   func(string) (routing.Route, error) { return routing.Route{}, nil },
			code:    CodeMissingIdentity,
		},
		{
			name: "unknown route", normal: func(context.Context, NormalizationRequest) (normalize.Prepared, error) {
				return validPrepared(t), nil
			},
			session: func(context.Context) (AuthenticatedSession, error) { return validSession(), nil },
			route:   func(string) (routing.Route, error) { return routing.Route{}, routing.ErrUnknownTarget },
			code:    CodeUnknownRoute,
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
		routeResolverFunc(func(string) (routing.Route, error) {
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
			routeResolverFunc(func(string) (routing.Route, error) {
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
				routeResolverFunc(func(target string) (routing.Route, error) {
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
		routeResolverFunc(func(string) (routing.Route, error) { return routing.Route{}, nil }),
		deciderFunc(func(context.Context, DecisionRequest) (protocol.AuthorizationDecision, error) {
			return protocol.AuthorizationDecision{}, nil
		}),
	)
	if got := checker.Check(ctx, validInput()); got.Allowed || got.Code != CodeAuthorizationUnavailable || calls != 0 {
		t.Fatalf("result %#v calls %d", got, calls)
	}
}
