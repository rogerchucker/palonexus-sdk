// Package state persists only typed, non-secret local guard metadata.
package state

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

var (
	ErrNotFound                = errors.New("state record not found")
	ErrUnsafePath              = errors.New("unsafe state path")
	ErrUnsafePermissions       = errors.New("unsafe state permissions")
	ErrUnsafeOwner             = errors.New("unsafe state owner")
	ErrUnsafePayload           = errors.New("unsafe state metadata")
	ErrInvalidBinding          = errors.New("invalid state binding")
	ErrCorrupt                 = errors.New("corrupt or unsupported state record")
	ErrUnsupported             = errors.New("secure state store unsupported on this operating system")
	ErrDurabilityIndeterminate = errors.New("state commit durability is indeterminate")
)

const (
	CurrentVersion  = 1
	MaxBindingBytes = 128
)

type Kind string

const (
	KindRouting        Kind = "routing"
	KindSession        Kind = "session"
	KindReconciliation Kind = "reconciliation"
)

type Binding struct {
	Tenant  string
	Account string
}

// Metadata is deliberately closed and cannot carry tokens, arbitrary JSON,
// raw tool input, commands, URLs, headers, or file contents.
type Metadata struct {
	Kind             Kind      `json:"kind"`
	RouteID          string    `json:"routeId,omitempty"`
	SessionID        string    `json:"sessionId,omitempty"`
	ReconciliationID string    `json:"reconciliationId,omitempty"`
	ReferenceHash    string    `json:"referenceHash,omitempty"`
	ExpiresAt        time.Time `json:"expiresAt,omitempty"`
}

type storeImpl interface {
	PutMetadata(context.Context, Binding, Metadata) error
	GetMetadata(context.Context, Binding, Kind) (Metadata, error)
	DeleteAccount(context.Context, Binding) error
	Close() error
	recordName(Binding, Kind) (string, error)
}

type Store struct{ impl storeImpl }

func New(root string) (*Store, error) {
	impl, err := newStore(root)
	if err != nil {
		return nil, err
	}
	return &Store{impl: impl}, nil
}

func (s *Store) PutMetadata(ctx context.Context, binding Binding, metadata Metadata) error {
	if s == nil || s.impl == nil {
		return ErrUnsupported
	}
	return s.impl.PutMetadata(ctx, binding, metadata)
}

func (s *Store) GetMetadata(ctx context.Context, binding Binding, kind Kind) (Metadata, error) {
	if s == nil || s.impl == nil {
		return Metadata{}, ErrUnsupported
	}
	return s.impl.GetMetadata(ctx, binding, kind)
}

func (s *Store) DeleteAccount(ctx context.Context, binding Binding) error {
	if s == nil || s.impl == nil {
		return ErrUnsupported
	}
	return s.impl.DeleteAccount(ctx, binding)
}

func (s *Store) Close() error {
	if s == nil || s.impl == nil {
		return ErrUnsupported
	}
	return s.impl.Close()
}

func (s *Store) recordName(binding Binding, kind Kind) (string, error) {
	if s == nil || s.impl == nil {
		return "", ErrUnsupported
	}
	return s.impl.recordName(binding, kind)
}

var (
	routeIDPattern = regexp.MustCompile(`^route-[a-z0-9][a-z0-9-]{0,62}$`)
	sessionPattern = regexp.MustCompile(`^session_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	reconPattern   = regexp.MustCompile(`^recon_[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	hashPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

func validateMetadata(metadata Metadata) error {
	if containsSecretIndicator(metadata.RouteID) || containsSecretIndicator(metadata.SessionID) ||
		containsSecretIndicator(metadata.ReconciliationID) || containsSecretIndicator(metadata.ReferenceHash) {
		return ErrUnsafePayload
	}
	switch metadata.Kind {
	case KindRouting:
		if len(metadata.RouteID) > 48 || !routeIDPattern.MatchString(metadata.RouteID) || metadata.SessionID != "" ||
			metadata.ReconciliationID != "" || metadata.ReferenceHash != "" || !metadata.ExpiresAt.IsZero() {
			return ErrUnsafePayload
		}
	case KindSession:
		if !sessionPattern.MatchString(metadata.SessionID) || metadata.RouteID != "" ||
			metadata.ReconciliationID != "" || metadata.ReferenceHash != "" || metadata.ExpiresAt.IsZero() {
			return ErrUnsafePayload
		}
	case KindReconciliation:
		if !reconPattern.MatchString(metadata.ReconciliationID) || !hashPattern.MatchString(metadata.ReferenceHash) ||
			metadata.RouteID != "" || metadata.SessionID != "" || !metadata.ExpiresAt.IsZero() {
			return ErrUnsafePayload
		}
	default:
		return ErrUnsafePayload
	}
	return nil
}

func containsSecretIndicator(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"token", "secret", "password", "credential", "authorization", "cookie", "api_key",
		"apikey", "privatekey", "private_key", "bearer ", "eyj", "raw-tool", "raw-command", "session/",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if len(value) >= 48 {
		unique := make(map[rune]struct{})
		for _, character := range value {
			unique[character] = struct{}{}
		}
		if len(unique) >= 20 {
			return true
		}
	}
	return false
}

func validBinding(binding Binding) bool {
	return validBindingPart(binding.Tenant) && validBindingPart(binding.Account)
}

func validBindingPart(value string) bool {
	if len(value) == 0 || len(value) > MaxBindingBytes || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validKind(kind Kind) bool {
	return kind == KindRouting || kind == KindSession || kind == KindReconciliation
}
