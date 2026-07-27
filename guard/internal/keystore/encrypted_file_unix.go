//go:build darwin || linux

package keystore

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var encryptedRecordName = regexp.MustCompile(`^credential-[0-9a-f]{64}\.enc$`)

const maxEncryptedDocumentBytes = encryptedDocumentVersionBytes + 12 + MaxSecretBytes + 16

type unixEncryptedFiles struct {
	rootFD int
	gate   chan struct{}
}

func newEncryptedFiles(root string) (encryptedFiles, error) {
	fd, err := openEncryptedRoot(root)
	if err != nil {
		return nil, err
	}
	files := &unixEncryptedFiles{rootFD: fd, gate: make(chan struct{}, 1)}
	files.gate <- struct{}{}
	return files, nil
}

func openEncryptedRoot(root string) (int, error) {
	if root == "" || !filepath.IsAbs(root) || filepath.Clean(root) == string(filepath.Separator) {
		return -1, ErrUnavailable
	}
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(root), string(filepath.Separator)), string(filepath.Separator))
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, ErrUnavailable
	}
	if err := validateEncryptedAncestorFD(fd); err != nil {
		unix.Close(fd)
		return -1, err
	}
	for index, part := range parts {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && index == len(parts)-1 {
			if mkdirErr := unix.Mkdirat(fd, part, 0o700); mkdirErr != nil {
				unix.Close(fd)
				return -1, ErrUnavailable
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			unix.Close(fd)
			return -1, ErrUnavailable
		}
		if err := validateEncryptedAncestorFD(next); err != nil {
			unix.Close(next)
			unix.Close(fd)
			return -1, err
		}
		unix.Close(fd)
		fd = next
	}
	if err := validateEncryptedFD(fd, true); err != nil {
		unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

func validateEncryptedAncestorFD(fd int) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil ||
		stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Mode&0o022 != 0 ||
		(int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid()) {
		return ErrUnavailable
	}
	return nil
}

func (f *unixEncryptedFiles) Put(ctx context.Context, name string, document []byte) error {
	if !encryptedRecordName.MatchString(name) {
		return ErrUnavailable
	}
	return f.withLock(ctx, func() error {
		if err := validateEncryptedExisting(f.rootFD, name); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		var random [16]byte
		if _, err := io.ReadFull(rand.Reader, random[:]); err != nil {
			return ErrUnavailable
		}
		temp := ".credential-tmp-" + hex.EncodeToString(random[:])
		fd, err := unix.Openat(f.rootFD, temp,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return ErrUnavailable
		}
		file := os.NewFile(uintptr(fd), temp)
		renamed := false
		defer func() {
			file.Close()
			if !renamed {
				_ = unix.Unlinkat(f.rootFD, temp, 0)
			}
		}()
		if _, err := file.Write(document); err != nil {
			return ErrUnavailable
		}
		if err := file.Sync(); err != nil {
			return ErrUnavailable
		}
		if err := validateEncryptedExisting(f.rootFD, name); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := unix.Renameat(f.rootFD, temp, f.rootFD, name); err != nil {
			return ErrUnavailable
		}
		renamed = true
		return encryptedSyncRoot(f.rootFD)
	})
}

func (f *unixEncryptedFiles) Get(ctx context.Context, name string) ([]byte, error) {
	if !encryptedRecordName.MatchString(name) {
		return nil, ErrUnavailable
	}
	var result []byte
	err := f.withLock(ctx, func() error {
		fd, err := unix.Openat(f.rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ENOENT) {
			return ErrNotFound
		}
		if err != nil {
			return ErrUnavailable
		}
		if err := validateEncryptedFD(fd, false); err != nil {
			unix.Close(fd)
			return err
		}
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()
		result, err = io.ReadAll(io.LimitReader(file, maxEncryptedDocumentBytes+1))
		if err != nil {
			return ErrUnavailable
		}
		if len(result) > maxEncryptedDocumentBytes {
			Zero(result)
			result = nil
			return ErrUnavailable
		}
		if err := ctx.Err(); err != nil {
			Zero(result)
			result = nil
			return err
		}
		return nil
	})
	return result, err
}

func (f *unixEncryptedFiles) Delete(ctx context.Context, name string) error {
	if !encryptedRecordName.MatchString(name) {
		return ErrUnavailable
	}
	return f.withLock(ctx, func() error {
		err := validateEncryptedExisting(f.rootFD, name)
		if errors.Is(err, ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := unix.Unlinkat(f.rootFD, name, 0); err != nil {
			return ErrUnavailable
		}
		return encryptedSyncRoot(f.rootFD)
	})
}

func (f *unixEncryptedFiles) withLock(ctx context.Context, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-f.gate:
	}
	defer func() { f.gate <- struct{}{} }()
	if err := ctx.Err(); err != nil {
		return err
	}
	lockFD, err := unix.Openat(f.rootFD, ".lock",
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrUnavailable
	}
	defer unix.Close(lockFD)
	if err := validateEncryptedFD(lockFD, false); err != nil {
		return err
	}
	for {
		err = unix.Flock(lockFD, unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EAGAIN) && !errors.Is(err, unix.EWOULDBLOCK) {
			return ErrUnavailable
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	defer unix.Flock(lockFD, unix.LOCK_UN) //nolint:errcheck
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}

func validateEncryptedExisting(rootFD int, name string) error {
	var stat unix.Stat_t
	err := unix.Fstatat(rootFD, name, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return ErrNotFound
	}
	if err != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Mode&0o777 != 0o600 || int(stat.Uid) != os.Geteuid() {
		return ErrUnavailable
	}
	return nil
}

func validateEncryptedFD(fd int, directory bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return ErrUnavailable
	}
	wantType, wantMode := uint32(unix.S_IFREG), uint32(0o600)
	if directory {
		wantType, wantMode = unix.S_IFDIR, 0o700
	}
	mode := uint32(stat.Mode)
	if mode&unix.S_IFMT != wantType || mode&0o777 != wantMode || int(stat.Uid) != os.Geteuid() {
		return ErrUnavailable
	}
	return nil
}

func encryptedSyncRoot(fd int) error {
	if err := unix.Fsync(fd); err != nil {
		return ErrUnavailable
	}
	return nil
}
