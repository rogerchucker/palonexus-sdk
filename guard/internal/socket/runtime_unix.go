// SPDX-License-Identifier: MIT
//go:build unix

package socket

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func prepareRuntimeDir(path string) (*os.File, os.FileInfo, error) {
	created := false
	if err := os.Mkdir(path, 0o700); err == nil {
		created = true
	} else if !errors.Is(err, os.ErrExist) {
		return nil, nil, fmt.Errorf("socket: create runtime directory: %w", err)
	}
	// An extreme caller umask may create the directory without owner search
	// permission. Restrict the directory before opening it; the subsequent
	// O_NOFOLLOW open and inode checks detect pathname replacement.
	if created {
		if err := os.Chmod(path, 0o700); err != nil {
			return nil, nil, fmt.Errorf("socket: initialize runtime permissions: %w", err)
		}
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("socket: securely open runtime directory: %w", err)
	}
	dir := os.NewFile(uintptr(fd), path)
	info, err := dir.Stat()
	if err != nil {
		_ = dir.Close()
		return nil, nil, fmt.Errorf("socket: inspect runtime directory: %w", err)
	}
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		_ = dir.Close()
		return nil, nil, errors.New("socket: runtime directory must be user-only")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != currentUID() {
		_ = dir.Close()
		return nil, nil, errors.New("socket: runtime directory has wrong owner")
	}
	// Make creation-mode independent of the caller's umask.
	if err := dir.Chmod(0o700); err != nil {
		_ = dir.Close()
		return nil, nil, fmt.Errorf("socket: restrict runtime directory: %w", err)
	}
	info, err = dir.Stat()
	return dir, info, err
}

func verifyRuntimeDir(dir *os.File, path string, expected os.FileInfo) error {
	anchored, err := dir.Stat()
	if err != nil {
		return fmt.Errorf("socket: runtime directory descriptor: %w", err)
	}
	named, err := os.Lstat(path)
	if err != nil || named.Mode()&os.ModeSymlink != 0 || !named.IsDir() ||
		!os.SameFile(anchored, expected) || !os.SameFile(named, expected) {
		return errors.New("socket: runtime directory was replaced")
	}
	anchoredStat, anchoredOK := anchored.Sys().(*syscall.Stat_t)
	namedStat, namedOK := named.Sys().(*syscall.Stat_t)
	if !anchoredOK || !namedOK || anchoredStat.Uid != currentUID() ||
		namedStat.Uid != currentUID() || anchored.Mode().Perm() != 0o700 ||
		named.Mode().Perm() != 0o700 {
		return errors.New("socket: runtime directory security changed")
	}
	return nil
}

func currentUID() uint32 { return uint32(os.Getuid()) }

type fileIdentity struct {
	device uint64
	inode  uint64
}

type nodeInfo struct {
	identity fileIdentity
	mode     uint32
	uid      uint32
	nlink    uint64
}

func inspectAt(dir *os.File, name string) (nodeInfo, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(
		int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW,
	); err != nil {
		return nodeInfo{}, err
	}
	return nodeInfo{
		identity: fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)},
		mode:     uint32(stat.Mode),
		uid:      stat.Uid,
		nlink:    uint64(stat.Nlink),
	}, nil
}

func verifyListenerFD(listener *net.UnixListener, expectedPath string) error {
	raw, err := listener.SyscallConn()
	if err != nil {
		return fmt.Errorf("socket: listener descriptor: %w", err)
	}
	var controlErr error
	if err := raw.Control(func(fd uintptr) {
		var stat unix.Stat_t
		if controlErr = unix.Fstat(int(fd), &stat); controlErr != nil {
			return
		}
		if uint32(stat.Mode)&0o170000 != unix.S_IFSOCK {
			controlErr = errors.New("listener descriptor is not a socket")
			return
		}
		address, socketErr := unix.Getsockname(int(fd))
		if socketErr != nil {
			controlErr = socketErr
			return
		}
		unixAddress, ok := address.(*unix.SockaddrUnix)
		if !ok || unixAddress.Name != expectedPath {
			controlErr = errors.New("listener descriptor has unexpected local path")
		}
	}); err != nil {
		return fmt.Errorf("socket: inspect listener descriptor: %w", err)
	}
	if controlErr != nil {
		return fmt.Errorf("socket: inspect listener descriptor: %w", controlErr)
	}
	return nil
}

func chmodAt(dir *os.File, name string, mode uint32) error {
	return unix.Fchmodat(
		int(dir.Fd()), name, mode, unix.AT_SYMLINK_NOFOLLOW,
	)
}

func acquireServerLock(dir *os.File, name string) (*os.File, fileIdentity, error) {
	fd, err := unix.Openat(
		int(dir.Fd()), name,
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0o600,
	)
	if err != nil {
		return nil, fileIdentity{}, fmt.Errorf("socket: open lifecycle lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), name)
	fail := func(err error) (*os.File, fileIdentity, error) {
		_ = lock.Close()
		return nil, fileIdentity{}, err
	}
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fail(errors.New("socket: lifecycle lock is not a regular file"))
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != currentUID() {
		return fail(errors.New("socket: lifecycle lock has wrong owner"))
	}
	if err := lock.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("socket: restrict lifecycle lock: %w", err))
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return fail(errors.New("socket: guard is already active"))
		}
		return fail(fmt.Errorf("socket: lock lifecycle: %w", err))
	}
	identity, err := identityFromFile(lock)
	if err != nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return fail(err)
	}
	return lock, identity, nil
}

func identityFromFile(file *os.File) (fileIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return fileIdentity{}, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fileIdentity{}, errors.New("socket: unavailable file identity")
	}
	return fileIdentity{device: uint64(stat.Dev), inode: uint64(stat.Ino)}, nil
}

func verifyLockPath(dir *os.File, name string, identity fileIdentity) error {
	node, err := inspectAt(dir, name)
	if err != nil || node.identity != identity || node.mode&unix.S_IFMT != unix.S_IFREG ||
		node.uid != currentUID() || node.mode&0o777 != 0o600 {
		return errors.New("socket: lifecycle lock pathname was replaced")
	}
	return nil
}

func releaseServerLock(lock *os.File) error {
	unlockErr := unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	closeErr := lock.Close()
	if unlockErr != nil {
		return fmt.Errorf("socket: unlock lifecycle: %w", unlockErr)
	}
	return closeErr
}

const maxLifecycleRecord = 1024

func readLifecycleRecord(dir *os.File, name string) (*lifecycleRecord, error) {
	fd, err := unix.Openat(
		int(dir.Fd()), name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0,
	)
	if errors.Is(err, unix.ENOENT) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("socket: open lifecycle journal: %w", err)
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() < 2 || info.Size() > maxLifecycleRecord {
		return nil, errors.New("socket: invalid lifecycle journal inode")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != currentUID() {
		return nil, errors.New("socket: lifecycle journal has wrong owner")
	}
	document := make([]byte, info.Size())
	if _, err := io.ReadFull(file, document); err != nil {
		return nil, fmt.Errorf("socket: read lifecycle journal: %w", err)
	}
	decoder := json.NewDecoder(strings.NewReader(string(document)))
	decoder.DisallowUnknownFields()
	var record lifecycleRecord
	if err := decoder.Decode(&record); err != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		record.validate() != nil {
		return nil, errors.New("socket: corrupt lifecycle journal")
	}
	return &record, nil
}

func writeLifecycleRecord(
	dir *os.File,
	name string,
	record lifecycleRecord,
	fault func(string),
) error {
	if record.Generation == "" {
		var generation [16]byte
		if _, err := rand.Read(generation[:]); err != nil {
			return fmt.Errorf("socket: lifecycle generation: %w", err)
		}
		record.Generation = hex.EncodeToString(generation[:])
	}
	if err := record.validate(); err != nil {
		return err
	}
	document, err := json.Marshal(record)
	if err != nil || len(document) > maxLifecycleRecord {
		return errors.New("socket: invalid lifecycle journal")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("socket: lifecycle temp nonce: %w", err)
	}
	tempName := "." + name + ".tmp-" + record.Generation + "-" +
		hex.EncodeToString(nonce[:])
	fd, err := unix.Openat(
		int(dir.Fd()), tempName,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0o600,
	)
	if err != nil {
		return fmt.Errorf("socket: create lifecycle temp: %w", err)
	}
	temp := os.NewFile(uintptr(fd), tempName)
	tempIdentity, identityErr := identityFromFile(temp)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		if identityErr == nil {
			_ = removeOwnedRegularAt(dir, tempName, tempIdentity)
		}
		return fmt.Errorf("socket: restrict lifecycle temp: %w", err)
	}
	cleanup := func() {
		_ = temp.Close()
		if identityErr == nil {
			_ = removeOwnedRegularAt(dir, tempName, tempIdentity)
		}
	}
	if fault != nil {
		fault("journal_before_write")
	}
	if err := writeAllFile(temp, document); err != nil {
		cleanup()
		return err
	}
	if fault != nil {
		fault("journal_after_write")
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("socket: sync lifecycle temp: %w", err)
	}
	if fault != nil {
		fault("journal_after_fsync")
	}
	if err := temp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("socket: close lifecycle temp: %w", err)
	}
	if fault != nil {
		fault("journal_before_rename")
	}
	if err := unix.Renameat(int(dir.Fd()), tempName, int(dir.Fd()), name); err != nil {
		cleanup()
		return fmt.Errorf("socket: commit lifecycle journal: %w", err)
	}
	if fault != nil {
		fault("journal_after_rename")
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("socket: sync lifecycle journal directory: %w", err)
	}
	if fault != nil {
		fault("journal_after_dirsync")
	}
	return nil
}

func cleanupLifecycleTemps(dir *os.File, journalName, _ string) error {
	duplicate, err := unix.Dup(int(dir.Fd()))
	if err != nil {
		return fmt.Errorf("socket: duplicate runtime directory: %w", err)
	}
	scan := os.NewFile(uintptr(duplicate), "lifecycle-temp-scan")
	defer scan.Close()
	names, err := scan.Readdirnames(257)
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("socket: scan lifecycle temps: %w", err)
	}
	if len(names) > 256 {
		return errors.New("socket: runtime directory entry limit exceeded")
	}
	prefix := "." + journalName + ".tmp-"
	count := 0
	for _, name := range names {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		count++
		if count > 64 {
			return errors.New("socket: too many lifecycle temp artifacts")
		}
		return &RecoveryAmbiguousError{Artifact: name}
	}
	return nil
}

func writeAllFile(file *os.File, document []byte) error {
	for len(document) != 0 {
		count, err := file.Write(document)
		if err != nil {
			return fmt.Errorf("socket: write lifecycle temp: %w", err)
		}
		if count == 0 {
			return errors.New("socket: short lifecycle write")
		}
		document = document[count:]
	}
	return nil
}

func removeOwnedAt(dir *os.File, name string, expected fileIdentity) error {
	return removeOwnedModeAt(dir, name, expected, unix.S_IFSOCK)
}

func removeOwnedRegularAt(dir *os.File, name string, expected fileIdentity) error {
	return removeOwnedModeAt(dir, name, expected, unix.S_IFREG)
}

func removeOwnedModeAt(
	dir *os.File,
	name string,
	expected fileIdentity,
	expectedMode uint32,
) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("socket: cleanup nonce: %w", err)
	}
	quarantine := "." + name + ".cleanup-" + hex.EncodeToString(nonce[:])
	dirfd := int(dir.Fd())
	if err := renameNoReplace(dirfd, name, quarantine); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return fmt.Errorf("socket: quarantine cleanup target: %w", err)
	}
	var stat unix.Stat_t
	if err := unix.Fstatat(dirfd, quarantine, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		_ = renameNoReplace(dirfd, quarantine, name)
		return fmt.Errorf("socket: inspect quarantined target: %w", err)
	}
	if uint64(stat.Dev) != expected.device || uint64(stat.Ino) != expected.inode ||
		uint32(stat.Mode)&unix.S_IFMT != expectedMode {
		restoreErr := renameNoReplace(dirfd, quarantine, name)
		if restoreErr != nil {
			return fmt.Errorf("socket: path replaced; replacement preserved as %s", quarantine)
		}
		return errors.New("socket: path replaced; refusing cleanup")
	}
	if err := unix.Unlinkat(dirfd, quarantine, 0); err != nil {
		return fmt.Errorf("socket: cleanup: %w", err)
	}
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("socket: sync cleanup: %w", err)
	}
	return nil
}
