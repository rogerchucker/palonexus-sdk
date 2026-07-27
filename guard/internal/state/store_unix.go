//go:build darwin || linux

package state

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const maxDocumentBytes = 16 * 1024

var (
	recordNamePattern = regexp.MustCompile(`^state-[0-9a-f]{64}\.json$`)
	tempNamePattern   = regexp.MustCompile(`^\.state-tmp-[0-9a-f]{32}$`)
)

type wireEnvelope struct {
	Version  *int     `json:"version"`
	Tenant   string   `json:"tenant"`
	Account  string   `json:"account"`
	Metadata Metadata `json:"metadata"`
}

type unixStore struct {
	rootFD int
	gate   chan struct{}
	mu     sync.Mutex
	closed bool
	faults unixFaults
}

type unixFaults struct {
	write        func(*os.File, []byte) (int, error)
	syncFile     func(*os.File) error
	rename       func(int, string, int, string) error
	syncDir      func(int) error
	unlink       func(int, string) error
	afterLock    func()
	beforeRename func()
	afterRename  func()
}

func newStore(root string) (storeImpl, error) {
	fd, err := openTrustedRoot(root)
	if err != nil {
		return nil, err
	}
	store := &unixStore{rootFD: fd, gate: make(chan struct{}, 1)}
	store.gate <- struct{}{}
	return store, nil
}

func openTrustedRoot(root string) (int, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
		return -1, ErrUnsafePath
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(root), string(filepath.Separator)), string(filepath.Separator))
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, ErrUnsafePath
	}
	if err := validateAncestorFD(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	for index, part := range parts {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && index == len(parts)-1 {
			if mkdirErr := unix.Mkdirat(fd, part, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				unix.Close(fd)
				return -1, ErrUnsafePath
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			unix.Close(fd)
			return -1, ErrUnsafePath
		}
		if err := validateAncestorFD(next); err != nil {
			unix.Close(next)
			unix.Close(fd)
			return -1, err
		}
		unix.Close(fd)
		fd = next
	}
	if err := validateDirectoryFD(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func validateAncestorFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrUnsafePath
	}
	if stat.Mode&0o022 != 0 {
		return ErrUnsafePermissions
	}
	if int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid() {
		return ErrUnsafeOwner
	}
	return nil
}

func (s *unixStore) PutMetadata(ctx context.Context, binding Binding, metadata Metadata) error {
	if !validBinding(binding) {
		return ErrInvalidBinding
	}
	if err := validateMetadata(metadata); err != nil {
		return err
	}
	return s.withLock(ctx, func() error {
		name, _ := s.recordName(binding, metadata.Kind)
		version := CurrentVersion
		document, err := json.Marshal(wireEnvelope{
			Version: &version, Tenant: binding.Tenant, Account: binding.Account, Metadata: metadata,
		})
		if err != nil {
			return ErrUnsafePayload
		}
		return s.atomicWrite(ctx, name, document)
	})
}

func (s *unixStore) GetMetadata(ctx context.Context, binding Binding, kind Kind) (Metadata, error) {
	if !validBinding(binding) || !validKind(kind) {
		return Metadata{}, ErrInvalidBinding
	}
	var result Metadata
	err := s.withLock(ctx, func() error {
		name, _ := s.recordName(binding, kind)
		document, err := s.readRaw(name)
		if err != nil {
			return err
		}
		record, migrated, err := decodeAndMigrate(document)
		if err != nil {
			return err
		}
		if record.Tenant != binding.Tenant || record.Account != binding.Account || record.Metadata.Kind != kind {
			return ErrCorrupt
		}
		result = record.Metadata
		if migrated {
			version := CurrentVersion
			record.Version = &version
			rewrite, err := json.Marshal(record)
			if err != nil {
				return ErrCorrupt
			}
			return s.atomicWrite(ctx, name, rewrite)
		}
		return nil
	})
	return result, err
}

func (s *unixStore) DeleteAccount(ctx context.Context, binding Binding) error {
	if !validBinding(binding) {
		return ErrInvalidBinding
	}
	return s.withLock(ctx, func() error {
		names := make([]string, 0, 3)
		for _, kind := range []Kind{KindRouting, KindSession, KindReconciliation} {
			name, _ := s.recordName(binding, kind)
			err := rejectUnsafeExistingAt(s.rootFD, name)
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
			names = append(names, name)
		}
		return s.deleteNamesLocked(ctx, names)
	})
}

func (s *unixStore) DeleteMetadata(ctx context.Context, binding Binding, kind Kind) error {
	if !validBinding(binding) || !validKind(kind) {
		return ErrInvalidBinding
	}
	return s.withLock(ctx, func() error {
		name, _ := s.recordName(binding, kind)
		if err := rejectUnsafeExistingAt(s.rootFD, name); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		return s.deleteNamesLocked(ctx, []string{name})
	})
}

func (s *unixStore) WithSessionTransaction(ctx context.Context, binding Binding, transaction SessionTransaction) error {
	if !validBinding(binding) || transaction == nil {
		return ErrInvalidBinding
	}
	return s.withLock(ctx, func() error {
		name, _ := s.recordName(binding, KindSession)
		var current Metadata
		found := false
		document, err := s.readRaw(name)
		if err == nil {
			record, _, decodeErr := decodeAndMigrate(document)
			if decodeErr != nil || record.Tenant != binding.Tenant || record.Account != binding.Account ||
				record.Metadata.Kind != KindSession {
				return ErrCorrupt
			}
			current, found = record.Metadata, true
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		next, err := transaction(current, found)
		if err != nil {
			return err
		}
		if next == nil {
			return s.deleteNamesLocked(ctx, []string{name})
		}
		if next.Kind != KindSession || validateMetadata(*next) != nil {
			return ErrUnsafePayload
		}
		version := CurrentVersion
		wire, err := json.Marshal(wireEnvelope{
			Version: &version, Tenant: binding.Tenant, Account: binding.Account, Metadata: *next,
		})
		if err != nil {
			return ErrUnsafePayload
		}
		return s.atomicWrite(ctx, name, wire)
	})
}

func (s *unixStore) deleteNamesLocked(ctx context.Context, names []string) error {
	deleted := false
	for _, name := range names {
		if !deleted {
			if err := ctx.Err(); err != nil {
				return err
			}
		}
		var err error
		if s.faults.unlink != nil {
			err = s.faults.unlink(s.rootFD, name)
		} else {
			err = unlinkRegularAt(s.rootFD, name)
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			if deleted {
				return ErrDurabilityIndeterminate
			}
			return err
		}
		deleted = deleted || err == nil
	}
	syncDir := syncRoot
	if s.faults.syncDir != nil {
		syncDir = s.faults.syncDir
	}
	if err := syncDir(s.rootFD); err != nil {
		if deleted {
			return ErrDurabilityIndeterminate
		}
		return err
	}
	return nil
}

func (s *unixStore) Close() error {
	<-s.gate
	defer func() { s.gate <- struct{}{} }()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if err := unix.Close(s.rootFD); err != nil {
		return ErrUnsafePath
	}
	s.rootFD = -1
	return nil
}

func (s *unixStore) withLock(ctx context.Context, operation func() error) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.gate:
	}
	defer func() { s.gate <- struct{}{} }()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return ErrUnsafePath
	}
	fd := s.rootFD
	s.mu.Unlock()
	if err := validateDirectoryFD(fd); err != nil {
		return fmt.Errorf("validate state root: %w", err)
	}
	lockFD, err := unix.Openat(
		fd,
		".lock",
		unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if errors.Is(err, unix.EEXIST) {
		lockFD, err = unix.Openat(fd, ".lock", unix.O_RDWR|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	}
	if err != nil {
		return fmt.Errorf("open state lock: %w", ErrUnsafePath)
	}
	defer unix.Close(lockFD)
	if err := validateFileFD(lockFD); err != nil {
		return fmt.Errorf("validate state lock: %w", err)
	}
	for {
		err = unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			return fmt.Errorf("acquire state lock: %w", ErrUnsafePath)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer unix.Flock(lockFD, unix.LOCK_UN) //nolint:errcheck
	if s.faults.afterLock != nil {
		s.faults.afterLock()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := s.cleanupTemps(); err != nil {
		return fmt.Errorf("clean state temporaries: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}

func (s *unixStore) recordName(binding Binding, kind Kind) (string, error) {
	if !validBinding(binding) || !validKind(kind) {
		return "", ErrInvalidBinding
	}
	hasher := sha256.New()
	hasher.Write([]byte("palonexus-state-binding-v1\x00"))
	var length [2]byte
	for _, part := range []string{binding.Tenant, binding.Account, string(kind)} {
		binary.BigEndian.PutUint16(length[:], uint16(len(part)))
		hasher.Write(length[:])
		hasher.Write([]byte(part))
	}
	return "state-" + hex.EncodeToString(hasher.Sum(nil)) + ".json", nil
}

func (s *unixStore) atomicWrite(ctx context.Context, name string, document []byte) error {
	if !recordNamePattern.MatchString(name) || len(document) > maxDocumentBytes {
		return ErrUnsafePath
	}
	if err := rejectUnsafeExistingAt(s.rootFD, name); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	var random [16]byte
	if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
		return ErrUnsafePath
	}
	temp := ".state-tmp-" + hex.EncodeToString(random[:])
	tempFD, err := unix.Openat(s.rootFD, temp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrUnsafePath
	}
	file := os.NewFile(uintptr(tempFD), temp)
	renamed := false
	defer func() {
		file.Close()
		if !renamed {
			_ = unix.Unlinkat(s.rootFD, temp, 0)
		}
	}()
	write := file.Write
	if s.faults.write != nil {
		write = func(document []byte) (int, error) { return s.faults.write(file, document) }
	}
	if _, err := write(document); err != nil {
		return ErrUnsafePath
	}
	syncFile := file.Sync
	if s.faults.syncFile != nil {
		syncFile = func() error { return s.faults.syncFile(file) }
	}
	if err := syncFile(); err != nil {
		return ErrUnsafePath
	}
	if err := rejectUnsafeExistingAt(s.rootFD, name); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if s.faults.beforeRename != nil {
		s.faults.beforeRename()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	rename := unix.Renameat
	if s.faults.rename != nil {
		rename = s.faults.rename
	}
	if err := rename(s.rootFD, temp, s.rootFD, name); err != nil {
		return ErrUnsafePath
	}
	renamed = true
	if s.faults.afterRename != nil {
		s.faults.afterRename()
	}
	syncDir := unix.Fsync
	if s.faults.syncDir != nil {
		syncDir = s.faults.syncDir
	}
	if err := syncDir(s.rootFD); err != nil {
		return ErrDurabilityIndeterminate
	}
	return nil
}

func (s *unixStore) readRaw(name string) ([]byte, error) {
	if !recordNamePattern.MatchString(name) {
		return nil, ErrUnsafePath
	}
	fd, err := unix.Openat(s.rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, ErrUnsafePath
	}
	if err := validateFileFD(fd); err != nil {
		unix.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	document, err := io.ReadAll(io.LimitReader(file, maxDocumentBytes+1))
	if err != nil || len(document) > maxDocumentBytes {
		return nil, ErrCorrupt
	}
	return document, nil
}

func decodeAndMigrate(document []byte) (wireEnvelope, bool, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var record wireEnvelope
	if err := decoder.Decode(&record); err != nil {
		return wireEnvelope{}, false, ErrCorrupt
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return wireEnvelope{}, false, ErrCorrupt
	}
	if record.Version == nil || (*record.Version != 0 && *record.Version != CurrentVersion) ||
		!validBinding(Binding{record.Tenant, record.Account}) || validateMetadata(record.Metadata) != nil {
		return wireEnvelope{}, false, ErrCorrupt
	}
	return record, *record.Version == 0, nil
}

func (s *unixStore) cleanupTemps() error {
	duplicate, err := unix.Openat(s.rootFD, ".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnsafePath
	}
	directory := os.NewFile(uintptr(duplicate), "state-root")
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return ErrUnsafePath
	}
	for _, entry := range entries {
		if tempNamePattern.MatchString(entry.Name()) {
			err := unlinkRegularAt(s.rootFD, entry.Name())
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
	}
	return nil
}

func validateDirectoryFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		return ErrUnsafePath
	}
	if stat.Mode&0o777 != 0o700 {
		return ErrUnsafePermissions
	}
	if int(stat.Uid) != os.Geteuid() {
		return ErrUnsafeOwner
	}
	return nil
}

func validateFileFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return ErrUnsafePath
	}
	if stat.Mode&0o777 != 0o600 {
		return ErrUnsafePermissions
	}
	if int(stat.Uid) != os.Geteuid() {
		return ErrUnsafeOwner
	}
	return nil
}

func rejectUnsafeExistingAt(rootFD int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(rootFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return ErrNotFound
	}
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return ErrUnsafePath
	}
	if stat.Mode&0o777 != 0o600 {
		return ErrUnsafePermissions
	}
	if int(stat.Uid) != os.Geteuid() {
		return ErrUnsafeOwner
	}
	return nil
}

func unlinkRegularAt(rootFD int, name string) error {
	if err := rejectUnsafeExistingAt(rootFD, name); err != nil {
		return err
	}
	if err := unix.Unlinkat(rootFD, name, 0); err != nil {
		return ErrUnsafePath
	}
	return nil
}

func syncRoot(fd int) error {
	if err := unix.Fsync(fd); err != nil {
		return ErrUnsafePath
	}
	return nil
}
