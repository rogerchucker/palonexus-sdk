// Package keystore keeps guard credentials in the current user's native
// operating-system secret store. It never falls back to a plaintext file.
package keystore

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"regexp"
	"sync"
	"unicode"
	"unicode/utf8"
)

var (
	ErrNotFound      = errors.New("credential not found")
	ErrUnavailable   = errors.New("credential store unavailable")
	ErrUnsupported   = errors.New("credential store unsupported on this operating system")
	ErrInvalidKey    = errors.New("invalid credential binding")
	ErrInvalidSecret = errors.New("invalid credential secret")
	ErrTestingOnly   = errors.New("encrypted file credential store is testing-only and disabled")
)

const (
	MaxBindingBytes = 128
	MaxSecretBytes  = 1 << 20
)

var serviceName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)

// Key binds a credential to both the authenticated tenant and account. A
// credential stored for one tenant cannot be selected by account name alone.
type Key struct {
	Tenant  string
	Account string
}

// Backend is the minimal native-secret-store contract. Implementations must
// copy inputs they retain and return a caller-owned byte slice from Get.
type Backend interface {
	Put(context.Context, string, string, []byte) error
	Get(context.Context, string, string) ([]byte, error)
	Delete(context.Context, string, string) error
}

// Store validates and namespaces all backend access.
type Store struct {
	service string
	backend Backend
}

func New(service string, backend Backend) (*Store, error) {
	if !serviceName.MatchString(service) || backend == nil {
		return nil, ErrInvalidKey
	}
	return &Store{service: service, backend: backend}, nil
}

func (s *Store) Put(ctx context.Context, key Key, secret []byte) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if len(secret) == 0 || len(secret) > MaxSecretBytes {
		return ErrInvalidSecret
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	copyOfSecret := append([]byte(nil), secret...)
	defer Zero(copyOfSecret)
	if err := s.backend.Put(ctx, s.service, accountName(key), copyOfSecret); err != nil {
		return sanitizeBackendError(err)
	}
	return nil
}

func (s *Store) Get(ctx context.Context, key Key) ([]byte, error) {
	if err := validateKey(key); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	temporary, err := s.backend.Get(ctx, s.service, accountName(key))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			_ = s.backend.Delete(ctx, s.service, legacyAccountName(key))
		}
		return nil, sanitizeBackendError(err)
	}
	defer Zero(temporary)
	if len(temporary) == 0 || len(temporary) > MaxSecretBytes {
		return nil, ErrUnavailable
	}
	result := append([]byte(nil), temporary...)
	if err := ctx.Err(); err != nil {
		Zero(result)
		return nil, err
	}
	return result, nil
}

func (s *Store) Delete(ctx context.Context, key Key) error {
	if err := validateKey(key); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.backend.Delete(ctx, s.service, accountName(key)); err != nil {
		return sanitizeBackendError(err)
	}
	if err := s.backend.Delete(ctx, s.service, legacyAccountName(key)); err != nil {
		return sanitizeBackendError(err)
	}
	return nil
}

func legacyAccountName(key Key) string { return key.Tenant + ":" + key.Account }

func validateKey(key Key) error {
	if !validBindingPart(key.Tenant) || !validBindingPart(key.Account) {
		return ErrInvalidKey
	}
	return nil
}

func accountName(key Key) string {
	hasher := sha256.New()
	hasher.Write([]byte("palonexus-keystore-binding-v1\x00"))
	var length [2]byte
	binary.BigEndian.PutUint16(length[:], uint16(len(key.Tenant)))
	hasher.Write(length[:])
	hasher.Write([]byte(key.Tenant))
	binary.BigEndian.PutUint16(length[:], uint16(len(key.Account)))
	hasher.Write(length[:])
	hasher.Write([]byte(key.Account))
	return "pnx1:" + hex.EncodeToString(hasher.Sum(nil))
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

func sanitizeBackendError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrNotFound):
		return ErrNotFound
	case errors.Is(err, ErrUnsupported):
		return ErrUnsupported
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return err
	default:
		return ErrUnavailable
	}
}

// Zero overwrites a secret buffer. Go cannot guarantee that compiler/runtime
// copies are also erased; callers should nevertheless keep credential buffers
// short-lived and call Zero as soon as practical.
func Zero(secret []byte) {
	for index := range secret {
		secret[index] = 0
	}
}

// MemoryBackend is an explicit fake for tests. It is never selected by
// NativeBackend.
type MemoryBackend struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

func NewMemoryBackendForTesting() *MemoryBackend {
	return &MemoryBackend{secrets: make(map[string][]byte)}
}

func (b *MemoryBackend) Put(ctx context.Context, service, account string, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	value := append([]byte(nil), secret...)
	b.mu.Lock()
	defer b.mu.Unlock()
	if previous := b.secrets[service+"\x00"+account]; previous != nil {
		Zero(previous)
	}
	b.secrets[service+"\x00"+account] = value
	return nil
}

func (b *MemoryBackend) Get(ctx context.Context, service, account string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	value, ok := b.secrets[service+"\x00"+account]
	if !ok {
		return nil, ErrNotFound
	}
	return append([]byte(nil), value...), nil
}

func (b *MemoryBackend) Delete(ctx context.Context, service, account string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	name := service + "\x00" + account
	Zero(b.secrets[name])
	delete(b.secrets, name)
	return nil
}

type unavailableBackend struct{}

func UnavailableBackend(error) Backend { return unavailableBackend{} }
func (unavailableBackend) Put(context.Context, string, string, []byte) error {
	return ErrUnavailable
}
func (unavailableBackend) Get(context.Context, string, string) ([]byte, error) {
	return nil, ErrUnavailable
}
func (unavailableBackend) Delete(context.Context, string, string) error {
	return ErrUnavailable
}

type EncryptedFileOptions struct {
	Root             string
	Key              []byte
	EnableForTesting bool
}

// NewEncryptedFileBackend is deliberately unavailable unless a test explicitly
// opts in. Production callers must use NativeBackend.
func NewEncryptedFileBackend(options EncryptedFileOptions) (Backend, error) {
	if !options.EnableForTesting {
		return nil, ErrTestingOnly
	}
	return newEncryptedFileBackend(options)
}
