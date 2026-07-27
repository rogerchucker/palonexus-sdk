// SPDX-License-Identifier: MIT
// Package socket implements the guard's local, fail-closed NDJSON transport.
package socket

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

const (
	DefaultSocketName  = "guard.sock"
	defaultMaxRequest  = 1 << 20
	defaultIOTimeout   = 5 * time.Second
	defaultMaxClients  = 64
	defaultMaxHandlers = 16
	hardMaxConcurrency = 256
)

// Handler must honor context cancellation. The server bounds detached handlers
// that ignore cancellation, but cannot forcibly terminate Go code.
type Handler func(context.Context, []byte) ([]byte, error)
type ControlHandler func(context.Context, []byte) ([]byte, bool)

type CloseError struct {
	Operation string
	Err       error
}

func (err *CloseError) Error() string {
	return "socket: close " + err.Operation + ": " + err.Err.Error()
}

func (err *CloseError) Unwrap() error { return err.Err }

var ErrRecoveryAmbiguous = errors.New("socket: recovery requires manual cleanup")
var ErrProbeUntrusted = errors.New("socket: peer readiness could not be proven")

type RecoveryAmbiguousError struct {
	Artifact string
}

func (err *RecoveryAmbiguousError) Error() string {
	return "socket: recovery cannot prove ownership of " + err.Artifact
}

func (err *RecoveryAmbiguousError) Unwrap() error { return ErrRecoveryAmbiguous }

type Config struct {
	RuntimeDir            string
	SocketName            string
	MaxRequestBytes       int
	MaxConcurrentClients  int
	MaxConcurrentHandlers int
	IOTimeout             time.Duration
	RequestTimeout        time.Duration
	Handler               Handler
	ControlHandler        ControlHandler
	// beforeBind is a test seam for exercising pathname replacement races.
	beforeBind func()
	// afterValidationBeforeBind exercises the final pathname race window.
	afterValidationBeforeBind func()
	// peerUID is a test seam for exercising credential rejection.
	peerUID func(net.Conn) (uint32, error)
	// afterAccept exercises shutdown between accept and handler registration.
	afterAccept func()
	// onClosing synchronizes shutdown race tests after the registration gate closes.
	onClosing func()
	// beforeListenerProof exercises replacement after anchored publication.
	beforeListenerProof func(string)
	// afterStageBind exercises replacement before anchored inspection.
	afterStageBind func(string)
	// beforeStageChmod exercises replacement before no-follow permission changes.
	beforeStageChmod func(string)
	// fault is a test-only crash seam at durable lifecycle boundaries.
	fault func(string)
	// closeFault injects retryable close failures at lifecycle boundaries.
	closeFault func(string) error
}

type Server struct {
	listener     *net.UnixListener
	dir          *os.File
	lock         *os.File
	lockName     string
	lockID       fileIdentity
	journal      string
	dirInfo      os.FileInfo
	path         string
	boundID      fileIdentity
	cfg          Config
	clientSlots  chan struct{}
	handlerSlots chan struct{}

	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
	acceptMu  sync.Mutex
	closing   bool
}

type lifecycleRecord struct {
	Version    int    `json:"version"`
	Phase      string `json:"phase"`
	Generation string `json:"generation,omitempty"`
	StageName  string `json:"stageName,omitempty"`
	FinalName  string `json:"finalName"`
	Device     uint64 `json:"device,omitempty"`
	Inode      uint64 `json:"inode,omitempty"`
}

func (record lifecycleRecord) validate() error {
	if record.Version != 1 || filepath.Base(record.FinalName) != record.FinalName ||
		record.FinalName == "." {
		return errors.New("socket: invalid lifecycle journal")
	}
	if record.Generation != "" {
		if len(record.Generation) != 32 {
			return errors.New("socket: invalid lifecycle generation")
		}
		if _, err := hex.DecodeString(record.Generation); err != nil {
			return errors.New("socket: invalid lifecycle generation")
		}
	}
	switch record.Phase {
	case "clean":
		if record.StageName != "" || record.Device != 0 || record.Inode != 0 {
			return errors.New("socket: invalid clean lifecycle journal")
		}
	case "preparing":
		if record.Generation == "" || filepath.Base(record.StageName) != record.StageName ||
			record.StageName == "." || record.Device != 0 || record.Inode != 0 {
			return errors.New("socket: invalid preparing lifecycle journal")
		}
	case "staged", "published":
		if filepath.Base(record.StageName) != record.StageName ||
			record.StageName == "." || record.Generation == "" ||
			record.Device == 0 || record.Inode == 0 {
			return errors.New("socket: invalid active lifecycle journal")
		}
	default:
		return errors.New("socket: invalid lifecycle phase")
	}
	return nil
}

func cleanLifecycle(finalName string) lifecycleRecord {
	return lifecycleRecord{Version: 1, Phase: "clean", FinalName: finalName}
}

func New(cfg Config) (*Server, error) {
	if cfg.RuntimeDir == "" {
		return nil, errors.New("socket: runtime directory is required")
	}
	if cfg.Handler == nil {
		return nil, errors.New("socket: handler is required")
	}
	if cfg.SocketName == "" {
		cfg.SocketName = DefaultSocketName
	}
	if filepath.Base(cfg.SocketName) != cfg.SocketName || cfg.SocketName == "." {
		return nil, errors.New("socket: invalid socket name")
	}
	if cfg.MaxRequestBytes == 0 {
		cfg.MaxRequestBytes = defaultMaxRequest
	}
	if cfg.MaxRequestBytes < 1 || cfg.MaxRequestBytes > defaultMaxRequest {
		return nil, errors.New("socket: invalid request size limit")
	}
	if cfg.MaxConcurrentClients == 0 {
		cfg.MaxConcurrentClients = defaultMaxClients
	}
	if cfg.MaxConcurrentHandlers == 0 {
		cfg.MaxConcurrentHandlers = defaultMaxHandlers
	}
	if cfg.MaxConcurrentClients < 1 || cfg.MaxConcurrentClients > hardMaxConcurrency ||
		cfg.MaxConcurrentHandlers < 1 || cfg.MaxConcurrentHandlers > hardMaxConcurrency {
		return nil, errors.New("socket: invalid concurrency limit")
	}
	if cfg.IOTimeout <= 0 {
		cfg.IOTimeout = defaultIOTimeout
	}
	if cfg.RequestTimeout <= 0 {
		cfg.RequestTimeout = cfg.IOTimeout
	}
	if cfg.peerUID == nil {
		cfg.peerUID = peerUID
	}

	dir, dirInfo, err := prepareRuntimeDir(cfg.RuntimeDir)
	if err != nil {
		return nil, err
	}
	lockName := "." + cfg.SocketName + ".lock"
	journalName := "." + cfg.SocketName + ".lifecycle"
	lock, lockID, err := acquireServerLock(dir, lockName)
	if err != nil {
		_ = dir.Close()
		return nil, err
	}
	if err := verifyLockPath(dir, lockName, lockID); err != nil {
		_ = releaseServerLock(lock)
		_ = dir.Close()
		return nil, err
	}
	fail := func(err error) (*Server, error) {
		_ = releaseServerLock(lock)
		_ = dir.Close()
		return nil, err
	}
	if err := cleanupLifecycleTemps(dir, journalName, cfg.SocketName); err != nil {
		return fail(err)
	}
	path := filepath.Join(cfg.RuntimeDir, cfg.SocketName)
	record, err := readLifecycleRecord(dir, journalName)
	if err != nil {
		return fail(err)
	}
	if err := recoverLifecycle(
		cfg, dir, dirInfo, lockName, lockID, journalName, record,
	); err != nil {
		return fail(err)
	}
	if err := verifyRuntimeDir(dir, cfg.RuntimeDir, dirInfo); err != nil {
		return fail(err)
	}
	if cfg.beforeBind != nil {
		cfg.beforeBind()
	}
	if err := verifyRuntimeDir(dir, cfg.RuntimeDir, dirInfo); err != nil {
		return fail(err)
	}
	if cfg.afterValidationBeforeBind != nil {
		cfg.afterValidationBeforeBind()
	}
	stageName, err := randomStageName()
	if err != nil {
		return fail(err)
	}
	generation, err := randomGeneration()
	if err != nil {
		return fail(err)
	}
	preparingRecord := lifecycleRecord{
		Version: 1, Phase: "preparing", Generation: generation,
		StageName: stageName, FinalName: cfg.SocketName,
	}
	if err := writeLifecycleRecord(dir, journalName, preparingRecord, cfg.fault); err != nil {
		return fail(err)
	}
	if cfg.fault != nil {
		cfg.fault("after_preparing")
	}
	stagePath := filepath.Join(cfg.RuntimeDir, stageName)
	// Unix has no portable bindat. Bind an unpublished random staging name,
	// then require that exact vnode to exist beneath the held directory FD.
	// Only an anchored, no-replace rename publishes the fixed client path. If
	// pathname resolution was redirected, the anchored lookup fails and this
	// listener is never published or served.
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: stagePath, Net: "unix"})
	if err != nil {
		return fail(fmt.Errorf("socket: bind: %w", err))
	}
	// The standard library otherwise unlinks the pathname unconditionally on
	// Close, which could delete an attacker replacement. Cleanup below is
	// identity checked instead.
	listener.SetUnlinkOnClose(false)
	if cfg.fault != nil {
		cfg.fault("after_bind")
	}
	if err := verifyListenerFD(listener, stagePath); err != nil {
		_ = listener.Close()
		return fail(err)
	}
	if cfg.beforeStageChmod != nil {
		cfg.beforeStageChmod(stagePath)
	}
	// Make the staged listener connectable even under an all-masking umask.
	// Identity and ownership are still established by the anchored inspection
	// below; the process-bound proof prevents a replacement from advancing.
	if err := chmodAt(dir, stageName, 0o600); err != nil {
		_ = listener.Close()
		return fail(fmt.Errorf("socket: initialize staged permissions: %w", err))
	}
	if cfg.fault != nil {
		cfg.fault("after_stage_chmod")
	}
	if cfg.afterStageBind != nil {
		cfg.afterStageBind(stagePath)
	}
	if err := proveListenerPath(listener, stagePath, cfg.IOTimeout); err != nil {
		_ = listener.Close()
		return fail(err)
	}
	if cfg.fault != nil {
		cfg.fault("after_stage_proof")
	}
	publishedName := stageName
	var boundID fileIdentity
	cleanupListener := func(err error) (*Server, error) {
		_ = listener.Close()
		removed := false
		if boundID != (fileIdentity{}) {
			removed = removeOwnedAt(dir, publishedName, boundID) == nil
		}
		if removed && verifyRuntimeDir(dir, cfg.RuntimeDir, dirInfo) == nil &&
			verifyLockPath(dir, lockName, lockID) == nil {
			_ = writeLifecycleRecord(
				dir, journalName, cleanLifecycle(cfg.SocketName), nil,
			)
		}
		return fail(err)
	}
	staged, err := inspectAt(dir, stageName)
	if err != nil || staged.mode&unixSocketMode() != unixSocketMode() ||
		staged.uid != currentUID() {
		return cleanupListener(errors.New("socket: staged listener is outside the anchored runtime directory"))
	}
	boundID = staged.identity
	if err := chmodAt(dir, stageName, 0o600); err != nil {
		return cleanupListener(fmt.Errorf("socket: restrict permissions: %w", err))
	}
	staged, err = inspectAt(dir, stageName)
	if err != nil || !securePublishedSocket(staged, boundID) {
		return cleanupListener(errors.New("socket: staged listener security mismatch"))
	}
	stagedRecord := lifecycleRecord{
		Version: 1, Phase: "staged", Generation: generation, StageName: stageName,
		FinalName: cfg.SocketName, Device: boundID.device, Inode: boundID.inode,
	}
	if err := verifyLockPath(dir, lockName, lockID); err != nil {
		return cleanupListener(err)
	}
	if err := writeLifecycleRecord(
		dir, journalName, stagedRecord, cfg.fault,
	); err != nil {
		return cleanupListener(err)
	}
	if err := verifyLockPath(dir, lockName, lockID); err != nil {
		return cleanupListener(err)
	}
	if cfg.fault != nil {
		cfg.fault("before_publish")
	}
	if err := renameNoReplace(int(dir.Fd()), stageName, cfg.SocketName); err != nil {
		return cleanupListener(fmt.Errorf("socket: publish listener: %w", err))
	}
	publishedName = cfg.SocketName
	if cfg.fault != nil {
		cfg.fault("after_publish")
	}
	if err := dir.Sync(); err != nil {
		return cleanupListener(fmt.Errorf("socket: sync published listener: %w", err))
	}
	if cfg.fault != nil {
		cfg.fault("after_publish_dirsync")
	}
	published, err := inspectAt(dir, cfg.SocketName)
	if err != nil || !securePublishedSocket(published, boundID) {
		return cleanupListener(errors.New("socket: published listener identity mismatch"))
	}
	publishedRecord := stagedRecord
	publishedRecord.Phase = "published"
	if err := verifyLockPath(dir, lockName, lockID); err != nil {
		return cleanupListener(err)
	}
	if err := writeLifecycleRecord(
		dir, journalName, publishedRecord, cfg.fault,
	); err != nil {
		return cleanupListener(err)
	}
	if err := verifyRuntimeDir(dir, cfg.RuntimeDir, dirInfo); err != nil {
		return cleanupListener(err)
	}
	if cfg.beforeListenerProof != nil {
		cfg.beforeListenerProof(path)
	}
	if err := proveListenerPath(listener, path, cfg.IOTimeout); err != nil {
		return cleanupListener(err)
	}
	finalNode, err := inspectAt(dir, cfg.SocketName)
	if err != nil || !securePublishedSocket(finalNode, boundID) {
		return cleanupListener(errors.New("socket: listener path changed after proof"))
	}
	if err := verifyLockPath(dir, lockName, lockID); err != nil {
		return cleanupListener(err)
	}
	return &Server{
		listener: listener, dir: dir, lock: lock, lockName: lockName,
		lockID: lockID, journal: journalName, dirInfo: dirInfo, path: path,
		boundID: boundID, cfg: cfg,
		clientSlots:  make(chan struct{}, cfg.MaxConcurrentClients),
		handlerSlots: make(chan struct{}, cfg.MaxConcurrentHandlers),
	}, nil
}

func randomStageName() (string, error) {
	var nonce [6]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("socket: stage nonce: %w", err)
	}
	return ".s" + base64.RawURLEncoding.EncodeToString(nonce[:]), nil
}

func randomGeneration() (string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("socket: generation nonce: %w", err)
	}
	return hex.EncodeToString(nonce[:]), nil
}

func unixSocketMode() uint32 { return 0o140000 }

func ownedStaleSocket(node nodeInfo, record *fileIdentity) bool {
	return record != nil && node.identity == *record &&
		securePublishedSocket(node, *record)
}

type probeResult int

const (
	probeRefused probeResult = iota
	probeActive
	probeAmbiguous
)

func recoverLifecycle(
	cfg Config,
	dir *os.File,
	dirInfo os.FileInfo,
	lockName string,
	lockID fileIdentity,
	journalName string,
	record *lifecycleRecord,
) error {
	if record == nil {
		if _, err := inspectAt(dir, cfg.SocketName); err == nil {
			return errors.New("socket: unjournaled socket path exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("socket: inspect unjournaled path: %w", err)
		}
		return writeLifecycleRecord(
			dir, journalName, cleanLifecycle(cfg.SocketName), nil,
		)
	}
	if record.FinalName != cfg.SocketName {
		return errors.New("socket: lifecycle journal targets another socket")
	}
	if record.Phase == "clean" {
		if _, err := inspectAt(dir, cfg.SocketName); err == nil {
			return errors.New("socket: socket path exists without active lifecycle intent")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("socket: inspect clean path: %w", err)
		}
		return nil
	}
	if record.Phase == "preparing" {
		if _, err := inspectAt(dir, record.FinalName); err == nil {
			return errors.New("socket: final path exists during preparation")
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("socket: inspect preparing final path: %w", err)
		}
		node, err := inspectAt(dir, record.StageName)
		if errors.Is(err, os.ErrNotExist) {
			return writeLifecycleRecord(
				dir, journalName, cleanLifecycle(cfg.SocketName), nil,
			)
		}
		if err != nil || node.mode&0o170000 != unixSocketMode() ||
			node.uid != currentUID() || node.nlink != 1 {
			return errors.New("socket: ambiguous preparing lifecycle candidate")
		}
		return &RecoveryAmbiguousError{Artifact: record.StageName}
	}
	expected := fileIdentity{device: record.Device, inode: record.Inode}
	type candidate struct {
		name string
		node nodeInfo
	}
	var candidates []candidate
	for _, name := range []string{record.StageName, record.FinalName} {
		node, err := inspectAt(dir, name)
		if err == nil {
			if node.identity != expected {
				return errors.New("socket: lifecycle pathname inode mismatch")
			}
			candidates = append(candidates, candidate{name: name, node: node})
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("socket: inspect lifecycle candidate: %w", err)
		}
	}
	if len(candidates) == 0 {
		return writeLifecycleRecord(
			dir, journalName, cleanLifecycle(cfg.SocketName), nil,
		)
	}
	if len(candidates) != 1 || !securePublishedSocket(candidates[0].node, expected) {
		return errors.New("socket: ambiguous lifecycle candidates")
	}
	if err := verifyRuntimeDir(dir, cfg.RuntimeDir, dirInfo); err != nil {
		return err
	}
	if err := verifyLockPath(dir, lockName, lockID); err != nil {
		return err
	}
	path := filepath.Join(cfg.RuntimeDir, candidates[0].name)
	if probeGuard(path, cfg.IOTimeout) != probeRefused {
		return errors.New("socket: lifecycle candidate may still be active")
	}
	if err := verifyRuntimeDir(dir, cfg.RuntimeDir, dirInfo); err != nil {
		return err
	}
	if err := verifyLockPath(dir, lockName, lockID); err != nil {
		return err
	}
	current, err := inspectAt(dir, candidates[0].name)
	if err != nil || !securePublishedSocket(current, expected) {
		return errors.New("socket: lifecycle candidate changed after active probe")
	}
	if err := removeOwnedAt(dir, candidates[0].name, expected); err != nil {
		return err
	}
	return writeLifecycleRecord(
		dir, journalName, cleanLifecycle(cfg.SocketName), nil,
	)
}

const (
	challengeField    = "_palonexusGuardChallenge"
	challengePIDField = "serverPid"
)

func probeGuard(path string, timeout time.Duration) probeResult {
	_, result := probeGuardPID(path, timeout)
	return result
}

// Probe verifies that path reaches a live PaloNexus guard owned by the current
// user and returns the kernel-authenticated peer PID. It never classifies a
// malformed, unreachable, or wrong-user peer as ready.
func Probe(path string, timeout time.Duration) (int, error) {
	pid, result := probeGuardPID(path, timeout)
	if result != probeActive {
		return 0, ErrProbeUntrusted
	}
	return pid, nil
}

func probeGuardPID(path string, timeout time.Duration) (int, probeResult) {
	if timeout <= 0 || timeout > time.Second {
		timeout = time.Second
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return 0, probeAmbiguous
	}
	value := base64.RawURLEncoding.EncodeToString(nonce[:])
	request, _ := json.Marshal(map[string]string{challengeField: value})
	request = append(request, '\n')
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		var operation *net.OpError
		if errors.As(err, &operation) && errors.Is(operation.Err, syscall.ECONNREFUSED) {
			return 0, probeRefused
		}
		return 0, probeAmbiguous
	}
	defer conn.Close()
	uid, err := peerUID(conn)
	if err != nil || uid != currentUID() {
		return 0, probeAmbiguous
	}
	connectedPID, err := peerPID(conn)
	if err != nil || connectedPID <= 0 {
		return 0, probeAmbiguous
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(request); err != nil {
		return 0, probeAmbiguous
	}
	response, err := bufio.NewReaderSize(conn, 256).ReadBytes('\n')
	if err != nil || len(response) > 256 || len(response) < 2 ||
		response[len(response)-1] != '\n' {
		return 0, probeAmbiguous
	}
	object, err := decodeTopLevelObject(response[:len(response)-1])
	if err != nil || len(object) != 2 {
		return 0, probeAmbiguous
	}
	var returned string
	var claimedPID int
	if json.Unmarshal(object[challengeField], &returned) != nil ||
		json.Unmarshal(object[challengePIDField], &claimedPID) != nil ||
		returned != value || claimedPID <= 0 || claimedPID != connectedPID {
		return 0, probeAmbiguous
	}
	return connectedPID, probeActive
}

func challengeResponse(frame []byte) ([]byte, bool) {
	if len(frame) < 2 || len(frame) > 256 || frame[len(frame)-1] != '\n' {
		return nil, false
	}
	object, err := decodeTopLevelObject(frame[:len(frame)-1])
	if err != nil || len(object) != 1 {
		return nil, false
	}
	raw, ok := object[challengeField]
	if !ok {
		return nil, false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return nil, false
	}
	nonce, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(nonce) != 32 {
		return nil, false
	}
	response, _ := json.Marshal(struct {
		Challenge string `json:"_palonexusGuardChallenge"`
		ServerPID int    `json:"serverPid"`
	}{
		Challenge: value,
		ServerPID: os.Getpid(),
	})
	return append(response, '\n'), true
}

func securePublishedSocket(node nodeInfo, identity fileIdentity) bool {
	return node.identity == identity && node.mode&0o170000 == unixSocketMode() &&
		node.mode&0o777 == 0o600 && node.uid == currentUID()
}

func proveListenerPath(listener *net.UnixListener, path string, timeout time.Duration) error {
	if timeout > time.Second {
		timeout = time.Second
	}
	if timeout <= 0 {
		timeout = time.Second
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("socket: proof nonce: %w", err)
	}
	if err := listener.SetDeadline(time.Now().Add(timeout)); err != nil {
		return fmt.Errorf("socket: proof deadline: %w", err)
	}
	defer listener.SetDeadline(time.Time{})
	clientDone := make(chan error, 1)
	go func() {
		conn, err := net.DialTimeout("unix", path, timeout)
		if err != nil {
			clientDone <- err
			return
		}
		defer conn.Close()
		uid, credentialErr := peerUID(conn)
		if credentialErr != nil || uid != currentUID() {
			clientDone <- errors.New("socket proof peer UID mismatch")
			return
		}
		pid, credentialErr := peerPID(conn)
		if credentialErr != nil || pid != os.Getpid() {
			clientDone <- errors.New("socket proof peer PID mismatch")
			return
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if _, err = conn.Write(nonce[:]); err == nil {
			var echoed [len(nonce)]byte
			_, err = io.ReadFull(conn, echoed[:])
			if err == nil && echoed != nonce {
				err = errors.New("socket proof response mismatch")
			}
		}
		clientDone <- err
	}()
	conn, err := listener.AcceptUnix()
	if err != nil {
		<-clientDone
		return fmt.Errorf("socket: listener proof accept: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	uid, credentialErr := peerUID(conn)
	if credentialErr != nil || uid != currentUID() {
		_ = conn.Close()
		<-clientDone
		return errors.New("socket: listener proof peer UID mismatch")
	}
	pid, credentialErr := peerPID(conn)
	if credentialErr != nil || pid != os.Getpid() {
		_ = conn.Close()
		<-clientDone
		return errors.New("socket: listener proof peer PID mismatch")
	}
	var received [len(nonce)]byte
	_, readErr := io.ReadFull(conn, received[:])
	if readErr == nil && received != nonce {
		readErr = errors.New("socket proof request mismatch")
	}
	if readErr == nil {
		_, readErr = conn.Write(received[:])
	}
	_ = conn.Close()
	clientErr := <-clientDone
	if readErr != nil || clientErr != nil {
		return errors.New("socket: published path does not reach the bound listener")
	}
	return nil
}

func (s *Server) Path() string { return s.path }

func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("socket: nil context")
	}
	defer s.Close()
	s.acceptMu.Lock()
	if s.closing {
		s.acceptMu.Unlock()
		return nil
	}
	if err := verifyRuntimeDir(s.dir, filepath.Dir(s.path), s.dirInfo); err != nil {
		s.acceptMu.Unlock()
		return err
	}
	current, err := inspectAt(s.dir, filepath.Base(s.path))
	if err != nil || !securePublishedSocket(current, s.boundID) {
		s.acceptMu.Unlock()
		return errors.New("socket: bound path was replaced before serving")
	}
	s.acceptMu.Unlock()
	stop := context.AfterFunc(ctx, func() { _ = s.listener.Close() })
	defer stop()
	for {
		conn, err := s.listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				s.wg.Wait()
				return nil
			}
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				continue
			}
			return fmt.Errorf("socket: accept: %w", err)
		}
		if s.cfg.afterAccept != nil {
			s.cfg.afterAccept()
		}
		select {
		case s.clientSlots <- struct{}{}:
		default:
			s.write(conn, failure(
				protocol.ProtocolErrorCodeAuthorizationUnavailable, true,
			))
			_ = conn.Close()
			continue
		}
		s.acceptMu.Lock()
		if s.closing {
			s.acceptMu.Unlock()
			<-s.clientSlots
			_ = conn.Close()
			return nil
		}
		s.wg.Add(1)
		s.acceptMu.Unlock()
		go func() {
			defer s.wg.Done()
			defer func() { <-s.clientSlots }()
			s.handle(ctx, conn)
		}()
	}
}

func (s *Server) handle(parent context.Context, conn *net.UnixConn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(s.cfg.IOTimeout))
	uid, err := s.cfg.peerUID(conn)
	if err != nil || uid != currentUID() {
		s.write(conn, failure(protocol.ProtocolErrorCodeAuthenticationFailed, false))
		return
	}
	reader := bufio.NewReaderSize(conn, min(s.cfg.MaxRequestBytes+2, 64<<10))
	frame, err := readFrame(reader, s.cfg.MaxRequestBytes)
	if err != nil {
		s.write(conn, failure(protocol.ProtocolErrorCodeInvalidRequest, false))
		return
	}
	if response, ok := challengeResponse(frame); ok {
		s.write(conn, response)
		return
	}
	ctx, cancel := context.WithTimeout(parent, s.cfg.RequestTimeout)
	defer cancel()
	if s.cfg.ControlHandler != nil {
		if response, handled := s.cfg.ControlHandler(ctx, frame[:len(frame)-1]); handled {
			s.write(conn, normalizeHandlerResponse(response, s.cfg.MaxRequestBytes))
			return
		}
	}
	response := processFrameLimited(
		ctx, frame, s.cfg.MaxRequestBytes, s.cfg.Handler, s.handlerSlots,
	)
	s.write(conn, response)
}

func (s *Server) write(conn *net.UnixConn, response []byte) {
	_ = conn.SetWriteDeadline(time.Now().Add(s.cfg.IOTimeout))
	for len(response) != 0 {
		written, err := conn.Write(response)
		if err != nil || written == 0 {
			return
		}
		response = response[written:]
	}
}

func readFrame(reader *bufio.Reader, maximum int) ([]byte, error) {
	var frame []byte
	for len(frame) <= maximum {
		part, err := reader.ReadSlice('\n')
		frame = append(frame, part...)
		if err == nil {
			if len(frame) > maximum+1 || len(frame) == 1 {
				return nil, errors.New("invalid frame size")
			}
			return frame, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("unterminated frame")
			}
			return nil, err
		}
	}
	return nil, errors.New("frame too large")
}

func processFrame(ctx context.Context, frame []byte, maximum int, handler Handler) []byte {
	return processFrameLimited(ctx, frame, maximum, handler, nil)
}

func processFrameLimited(
	ctx context.Context,
	frame []byte,
	maximum int,
	handler Handler,
	handlerSlots chan struct{},
) []byte {
	if len(frame) < 2 || len(frame) > maximum+1 || frame[len(frame)-1] != '\n' ||
		bytes.IndexByte(frame[:len(frame)-1], '\n') >= 0 {
		return failure(protocol.ProtocolErrorCodeInvalidRequest, false)
	}
	document := frame[:len(frame)-1]
	envelope, err := decodeTopLevelObject(document)
	if err != nil {
		return failure(protocol.ProtocolErrorCodeInvalidRequest, false)
	}
	rawVersion, ok := envelope["schemaVersion"]
	if !ok {
		return failure(protocol.ProtocolErrorCodeInvalidRequest, false)
	}
	var version string
	if json.Unmarshal(rawVersion, &version) != nil {
		return failure(protocol.ProtocolErrorCodeInvalidRequest, false)
	}
	if version != "1" {
		return failure(protocol.ProtocolErrorCodeUnsupportedProtocol, false)
	}
	if _, err := protocol.ParseActionRequest(document); err != nil {
		return failure(protocol.ProtocolErrorCodeInvalidRequest, false)
	}
	type handlerResult struct {
		response []byte
		err      error
	}
	if handlerSlots != nil {
		select {
		case handlerSlots <- struct{}{}:
		default:
			return failure(protocol.ProtocolErrorCodeAuthorizationUnavailable, true)
		}
	}
	resultChannel := make(chan handlerResult, 1)
	go func() {
		if handlerSlots != nil {
			defer func() { <-handlerSlots }()
		}
		result := handlerResult{}
		defer func() {
			if recover() != nil {
				result.response = nil
				result.err = errors.New("handler panic")
			}
			resultChannel <- result
		}()
		result.response, result.err = handler(ctx, document)
	}()
	var result handlerResult
	select {
	case result = <-resultChannel:
	case <-ctx.Done():
		return failure(protocol.ProtocolErrorCodeAuthorizationUnavailable, true)
	}
	if result.err != nil {
		return failure(protocol.ProtocolErrorCodeAuthorizationUnavailable, true)
	}
	return normalizeHandlerResponse(result.response, maximum)
}

func normalizeHandlerResponse(response []byte, maximum int) []byte {
	response = bytes.TrimSpace(response)
	if len(response) == 0 || len(response) > maximum || !json.Valid(response) {
		return failure(protocol.ProtocolErrorCodeInvalidDecision, false)
	}
	if _, decisionErr := protocol.ParseAuthorizationDecision(response); decisionErr != nil {
		if _, protocolErr := protocol.ParseProtocolError(response); protocolErr != nil {
			return failure(protocol.ProtocolErrorCodeInvalidDecision, false)
		}
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, response); err != nil || compact.Len() > maximum {
		return failure(protocol.ProtocolErrorCodeInvalidDecision, false)
	}
	return append(compact.Bytes(), '\n')
}

// ProcessFrame applies the exact production socket framing, protocol, handler,
// timeout, and response-validation boundary without opening a socket.
func ProcessFrame(
	ctx context.Context,
	document []byte,
	maximum int,
	handler Handler,
) []byte {
	if maximum == 0 {
		maximum = defaultMaxRequest
	}
	if ctx == nil || handler == nil || maximum < 1 || maximum > defaultMaxRequest {
		return failure(protocol.ProtocolErrorCodeAuthorizationUnavailable, true)
	}
	frame := append(append([]byte(nil), document...), '\n')
	return processFrameLimited(ctx, frame, maximum, handler, nil)
}

func decodeTopLevelObject(document []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(document))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("invalid JSON object")
	}
	value := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err = decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok {
			return nil, errors.New("invalid JSON object key")
		}
		if _, duplicate := value[name]; duplicate {
			return nil, errors.New("duplicate JSON object key")
		}
		var field json.RawMessage
		if err := decoder.Decode(&field); err != nil {
			return nil, err
		}
		value[name] = field
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("unterminated JSON object")
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("trailing JSON value")
	}
	return value, nil
}

func failure(code protocol.ProtocolErrorCode, retryable bool) []byte {
	messages := map[protocol.ProtocolErrorCode]protocol.SafeText{
		protocol.ProtocolErrorCodeInvalidRequest:           "The request is invalid.",
		protocol.ProtocolErrorCodeUnsupportedProtocol:      "The protocol version is unsupported.",
		protocol.ProtocolErrorCodeAuthenticationFailed:     "Authentication failed.",
		protocol.ProtocolErrorCodeAuthorizationUnavailable: "Authorization is temporarily unavailable.",
		protocol.ProtocolErrorCodeInvalidDecision:          "The authorization decision is invalid.",
	}
	if code == protocol.ProtocolErrorCodeAuthorizationUnavailable {
		retryable = true
	} else {
		retryable = false
	}
	value := protocol.ProtocolError{
		SchemaVersion: "1",
		Code:          code,
		SafeMessage:   messages[code],
		Retryable:     retryable,
	}
	document, _ := json.Marshal(value)
	return append(document, '\n')
}

func (s *Server) Close() error {
	s.closeOnce.Do(func() {
		failClose := func(operation string, err error) {
			if s.closeErr == nil && err != nil {
				s.closeErr = &CloseError{Operation: operation, Err: err}
			}
		}
		s.acceptMu.Lock()
		s.closing = true
		if s.cfg.onClosing != nil {
			s.cfg.onClosing()
		}
		listenErr := s.listener.Close()
		s.acceptMu.Unlock()
		s.wg.Wait()
		if listenErr != nil && !errors.Is(listenErr, net.ErrClosed) {
			failClose("listener", listenErr)
		}
		if s.closeErr == nil {
			failClose("runtime verification",
				verifyRuntimeDir(s.dir, filepath.Dir(s.path), s.dirInfo))
		}
		if s.closeErr == nil {
			failClose("lock verification",
				verifyLockPath(s.dir, s.lockName, s.lockID))
		}
		if s.closeErr == nil {
			if s.cfg.closeFault != nil {
				failClose("fault before removal", s.cfg.closeFault("before_remove"))
			}
		}
		if s.closeErr == nil {
			failClose("socket removal",
				removeOwnedAt(s.dir, filepath.Base(s.path), s.boundID))
		}
		if s.closeErr == nil {
			if s.cfg.closeFault != nil {
				failClose("fault after removal", s.cfg.closeFault("after_remove"))
			}
		}
		if s.closeErr == nil {
			if s.cfg.closeFault != nil {
				failClose("fault before clean transition", s.cfg.closeFault("before_clean"))
			}
		}
		if s.closeErr == nil {
			failClose("journal transition", writeLifecycleRecord(
				s.dir, s.journal, cleanLifecycle(filepath.Base(s.path)), nil,
			))
		}
		failClose("lock release", releaseServerLock(s.lock))
		failClose("runtime directory", s.dir.Close())
	})
	return s.closeErr
}

// crashForTest simulates process death: descriptors close, while the
// inode-bound lifecycle record and socket pathname remain for restart recovery.
func (s *Server) crashForTest() error {
	s.closeOnce.Do(func() {
		s.acceptMu.Lock()
		s.closing = true
		if s.cfg.onClosing != nil {
			s.cfg.onClosing()
		}
		listenErr := s.listener.Close()
		s.acceptMu.Unlock()
		s.wg.Wait()
		lockErr := releaseServerLock(s.lock)
		dirErr := s.dir.Close()
		if listenErr != nil && !errors.Is(listenErr, net.ErrClosed) {
			s.closeErr = listenErr
		} else if lockErr != nil {
			s.closeErr = lockErr
		} else {
			s.closeErr = dirErr
		}
	})
	return s.closeErr
}
