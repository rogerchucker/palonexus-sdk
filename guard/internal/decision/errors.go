// SPDX-License-Identifier: MIT
package decision

import (
	"errors"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

var (
	ErrInvalidConfig    = errors.New("decision client configuration is invalid")
	ErrInvalidRequest   = errors.New("decision request is invalid")
	ErrUnavailable      = errors.New("authorization service unavailable")
	ErrInvalidDecision  = errors.New("authorization service returned an invalid decision")
	ErrDenied           = errors.New("authorization denied")
	ErrApprovalRequired = errors.New("authorization approval required")
)

// UnavailableError is the redacted, fail-closed result of any credential,
// cancellation, timeout, DNS, TLS, connection, or authority outage.
// It deliberately retains no underlying error or request data.
type UnavailableError struct{}

func (*UnavailableError) Error() string { return ErrUnavailable.Error() }
func (*UnavailableError) Is(target error) bool {
	return target == ErrUnavailable
}

func unavailable() error { return &UnavailableError{} }

// OutcomeError preserves a verified non-allow decision without converting it
// into transport availability or malformed-response failure.
type OutcomeError struct {
	Decision protocol.AuthorizationDecision
}

func (e *OutcomeError) Error() string {
	if e.Decision.Outcome == protocol.DecisionOutcomeApprovalRequired {
		return ErrApprovalRequired.Error()
	}
	return ErrDenied.Error()
}

func (e *OutcomeError) GoString() string { return e.Error() }

func (e *OutcomeError) Is(target error) bool {
	if e.Decision.Outcome == protocol.DecisionOutcomeApprovalRequired {
		return target == ErrApprovalRequired
	}
	return target == ErrDenied
}
