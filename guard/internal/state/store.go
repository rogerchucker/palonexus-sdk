//go:build darwin || linux

// Package state persists non-secret guard metadata with user-only permissions,
// cross-process locking, and atomic durable replacement. Credentials and raw
// tool inputs do not belong in this store.
package state

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var (
	ErrNotFound          = errors.New("state record not found")
	ErrUnsafePath        = errors.New("unsafe state path")
	ErrUnsafePermissions = errors.New("unsafe state permissions")
	ErrUnsafeOwner       = errors.New("unsafe state owner")
	ErrUnsafePayload     = errors.New("unsafe state payload")
	ErrInvalidBinding    = errors.New("invalid state binding")
	ErrCorrupt           = errors.New("corrupt or unsupported state record")
)

const (
	currentVersion = 1
	maxPayloadSize = 1 << 20
)

var bindingPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$`)

type Binding struct {
	Tenant  string
	Account string
}

type Store struct {
	root string
}

type envelope struct {
	Version int             `json:"version"`
	Tenant  string          `json:"tenant"`
	Account string          `json:"account"`
	Kind    string          `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}

func New(root string) (*Store, error) {
	if root == "" || !filepath.IsAbs(root) {
		return nil, ErrUnsafePath
	}
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(root, 0o700); err != nil {
			return nil, ErrUnsafePath
		}
		info, err = os.Lstat(root)
	}
	if err != nil {
		return nil, ErrUnsafePath
	}
	if err := validateDirectory(info); err != nil {
		return nil, err
	}
	return &Store{root: filepath.Clean(root)}, nil
}

func (s *Store) Put(ctx context.Context, binding Binding, kind string, payload json.RawMessage) error {
	if err := validate(binding, kind); err != nil {
		return err
	}
	safePayload, err := validatePayload(payload)
	if err != nil {
		return err
	}
	return s.withLock(ctx, func() error {
		path, err := s.recordPath(binding, kind)
		if err != nil {
			return err
		}
		if err := validateExistingRecord(path); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		document, err := json.Marshal(envelope{
			Version: currentVersion,
			Tenant:  binding.Tenant,
			Account: binding.Account,
			Kind:    kind,
			Payload: safePayload,
		})
		if err != nil {
			return ErrUnsafePayload
		}
		return s.atomicWrite(path, document)
	})
}

func (s *Store) Get(ctx context.Context, binding Binding, kind string) (json.RawMessage, error) {
	if err := validate(binding, kind); err != nil {
		return nil, err
	}
	var result json.RawMessage
	err := s.withLock(ctx, func() error {
		path, err := s.recordPath(binding, kind)
		if err != nil {
			return err
		}
		record, err := readEnvelope(path)
		if err != nil {
			return err
		}
		if record.Tenant != binding.Tenant || record.Account != binding.Account || record.Kind != kind {
			return ErrCorrupt
		}
		result = append(json.RawMessage(nil), record.Payload...)
		return nil
	})
	return result, err
}

// DeleteAccount removes all safe local state for exactly one tenant/account
// binding. It is idempotent and is intended for logout.
func (s *Store) DeleteAccount(ctx context.Context, binding Binding) error {
	if err := validate(binding, "account"); err != nil {
		return err
	}
	return s.withLock(ctx, func() error {
		entries, err := os.ReadDir(s.root)
		if err != nil {
			return ErrUnsafePath
		}
		changed := false
		for _, entry := range entries {
			if entry.Name() == ".lock" || strings.HasPrefix(entry.Name(), ".state-") {
				continue
			}
			path := filepath.Join(s.root, entry.Name())
			record, err := readEnvelope(path)
			if err != nil {
				return err
			}
			if record.Tenant == binding.Tenant && record.Account == binding.Account {
				if err := os.Remove(path); err != nil {
					return ErrUnsafePath
				}
				changed = true
			}
		}
		if changed {
			return syncDirectory(s.root)
		}
		return nil
	})
}

func (s *Store) recordPath(binding Binding, kind string) (string, error) {
	if err := validate(binding, kind); err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(binding.Tenant + "\x00" + binding.Account + "\x00" + kind))
	return filepath.Join(s.root, "state-"+hex.EncodeToString(sum[:])+".json"), nil
}

func (s *Store) withLock(ctx context.Context, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	info, err := os.Lstat(s.root)
	if err != nil {
		return ErrUnsafePath
	}
	if err := validateDirectory(info); err != nil {
		return err
	}
	lockPath := filepath.Join(s.root, ".lock")
	fd, err := unix.Open(lockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrUnsafePath
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	defer lock.Close()
	if err := validateOpenFile(lock, 0o600); err != nil {
		return err
	}
	for {
		err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return ErrUnsafePath
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer unix.Flock(fd, unix.LOCK_UN) //nolint:errcheck // closing also releases the advisory lock
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}

func (s *Store) atomicWrite(destination string, document []byte) error {
	temporary, err := os.CreateTemp(s.root, ".state-*")
	if err != nil {
		return ErrUnsafePath
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return ErrUnsafePermissions
	}
	if _, err := temporary.Write(document); err != nil {
		temporary.Close()
		return ErrUnsafePath
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return ErrUnsafePath
	}
	if err := temporary.Close(); err != nil {
		return ErrUnsafePath
	}
	if err := validateExistingRecord(destination); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return ErrUnsafePath
	}
	if err := os.Chmod(destination, 0o600); err != nil {
		return ErrUnsafePermissions
	}
	return syncDirectory(s.root)
}

func readEnvelope(path string) (envelope, error) {
	if err := validateExistingRecord(path); err != nil {
		if errors.Is(err, ErrNotFound) {
			return envelope{}, ErrNotFound
		}
		return envelope{}, err
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if errors.Is(err, os.ErrNotExist) {
		return envelope{}, ErrNotFound
	}
	if err != nil {
		return envelope{}, ErrUnsafePath
	}
	defer file.Close()
	if err := validateOpenFile(file, 0o600); err != nil {
		return envelope{}, err
	}
	limited := io.LimitReader(file, maxPayloadSize+4096)
	decoder := json.NewDecoder(limited)
	decoder.DisallowUnknownFields()
	var record envelope
	if err := decoder.Decode(&record); err != nil {
		return envelope{}, ErrCorrupt
	}
	if err := ensureEOF(decoder); err != nil {
		return envelope{}, ErrCorrupt
	}
	if record.Version != currentVersion || validate(Binding{record.Tenant, record.Account}, record.Kind) != nil {
		return envelope{}, ErrCorrupt
	}
	safePayload, err := validatePayload(record.Payload)
	if err != nil {
		return envelope{}, ErrCorrupt
	}
	record.Payload = safePayload
	return record, nil
}

func validateExistingRecord(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return ErrUnsafePath
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	if info.Mode().Perm() != 0o600 {
		return ErrUnsafePermissions
	}
	return validateOwner(info)
}

func validateDirectory(info os.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return ErrUnsafePath
	}
	if info.Mode().Perm() != 0o700 {
		return ErrUnsafePermissions
	}
	return validateOwner(info)
}

func validateOpenFile(file *os.File, mode os.FileMode) error {
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrUnsafePath
	}
	if info.Mode().Perm() != mode {
		return ErrUnsafePermissions
	}
	return validateOwner(info)
}

func validateOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return ErrUnsafeOwner
	}
	return nil
}

func validate(binding Binding, kind string) error {
	if !bindingPart.MatchString(binding.Tenant) ||
		!bindingPart.MatchString(binding.Account) ||
		!bindingPart.MatchString(kind) {
		return ErrInvalidBinding
	}
	return nil
}

func validatePayload(payload json.RawMessage) (json.RawMessage, error) {
	if len(payload) == 0 || len(payload) > maxPayloadSize {
		return nil, ErrUnsafePayload
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil || ensureEOF(decoder) != nil {
		return nil, ErrUnsafePayload
	}
	if containsSecretField(value) {
		return nil, ErrUnsafePayload
	}
	canonical, err := json.Marshal(value)
	if err != nil {
		return nil, ErrUnsafePayload
	}
	return canonical, nil
}

func containsSecretField(value any) bool {
	switch typed := value.(type) {
	case map[string]any:
		for name, child := range typed {
			normalized := strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(name))
			if strings.Contains(normalized, "token") ||
				strings.Contains(normalized, "secret") ||
				strings.Contains(normalized, "password") ||
				strings.Contains(normalized, "credential") ||
				normalized == "authorization" ||
				normalized == "cookie" ||
				normalized == "privatekey" {
				return true
			}
			if containsSecretField(child) {
				return true
			}
		}
	case []any:
		for _, child := range typed {
			if containsSecretField(child) {
				return true
			}
		}
	}
	return false
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return ErrCorrupt
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return ErrUnsafePath
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return ErrUnsafePath
	}
	return nil
}
