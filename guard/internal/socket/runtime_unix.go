// SPDX-License-Identifier: MIT
//go:build unix

package socket

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
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
	return unix.Fchmodat(int(dir.Fd()), name, mode, 0)
}

func acquireServerLock(dir *os.File, name string) (*os.File, *fileIdentity, error) {
	fd, err := unix.Openat(
		int(dir.Fd()), name,
		unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK,
		0o600,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("socket: open lifecycle lock: %w", err)
	}
	lock := os.NewFile(uintptr(fd), name)
	fail := func(err error) (*os.File, *fileIdentity, error) {
		_ = lock.Close()
		return nil, nil, err
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
	record, err := readLockIdentity(lock)
	if err != nil {
		_ = unix.Flock(fd, unix.LOCK_UN)
		return fail(err)
	}
	return lock, record, nil
}

func readLockIdentity(lock *os.File) (*fileIdentity, error) {
	var document [128]byte
	count, err := lock.ReadAt(document[:], 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("socket: read lifecycle record: %w", err)
	}
	text := strings.TrimSpace(string(document[:count]))
	if text == "" {
		return nil, nil
	}
	fields := strings.Fields(text)
	if len(fields) != 3 || fields[0] != "v1" {
		return nil, errors.New("socket: invalid lifecycle record")
	}
	device, err := strconv.ParseUint(fields[1], 16, 64)
	if err != nil {
		return nil, errors.New("socket: invalid lifecycle record")
	}
	inode, err := strconv.ParseUint(fields[2], 16, 64)
	if err != nil {
		return nil, errors.New("socket: invalid lifecycle record")
	}
	return &fileIdentity{device: device, inode: inode}, nil
}

func writeLockIdentity(lock *os.File, identity *fileIdentity) error {
	if err := lock.Truncate(0); err != nil {
		return fmt.Errorf("socket: truncate lifecycle record: %w", err)
	}
	if identity != nil {
		document := []byte(fmt.Sprintf("v1 %x %x\n", identity.device, identity.inode))
		if _, err := lock.WriteAt(document, 0); err != nil {
			return fmt.Errorf("socket: write lifecycle record: %w", err)
		}
	}
	if err := lock.Sync(); err != nil {
		return fmt.Errorf("socket: sync lifecycle record: %w", err)
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

func removeOwnedAt(dir *os.File, name string, expected fileIdentity) error {
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
		stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
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
