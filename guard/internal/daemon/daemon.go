// SPDX-License-Identifier: MIT
//go:build darwin || linux

// Package daemon manages the per-user PaloNexus guard process.
package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/socket"
	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
	"golang.org/x/sys/unix"
)

const (
	lifecycleVersion = 1
	stateName        = ".daemon.state"
	startLockName    = ".daemon.start.lock"
	logName          = "daemon.log"
	socketName       = socket.DefaultSocketName
	maxStateBytes    = 16 << 10
	maxFrameBytes    = 1 << 20
	defaultStartup   = 5 * time.Second
	defaultStop      = 3 * time.Second
	defaultKill      = 2 * time.Second
	maxOneShot       = 5 * time.Second
	maxOneShotActive = 16
)

var (
	ErrUnavailable      = errors.New("daemon: authorization unavailable")
	ErrUnsafeRuntime    = errors.New("daemon: unsafe runtime state")
	ErrUnsafeExecutable = errors.New("daemon: unsafe executable")
	ErrUnprovenProcess  = errors.New("daemon: process identity is not proven")
)

type Config struct {
	RuntimeDir           string
	Handler              socket.Handler
	Executable           string
	Arguments            []string
	ChildEnv             []string
	ConfigurationDigest  string
	StartupTimeout       time.Duration
	StopTimeout          time.Duration
	KillTimeout          time.Duration
	afterSocketPublished func()
	afterLaunchVerified  func(string)
}

type Status struct {
	Running bool
	PID     int
}

type lifecycleState struct {
	Version    int    `json:"version"`
	PID        int    `json:"pid"`
	Token      string `json:"token"`
	Executable string `json:"executable"`
	Device     uint64 `json:"device"`
	Inode      uint64 `json:"inode"`
	Mode       uint32 `json:"mode"`
	UID        uint32 `json:"uid"`
	BinaryHash string `json:"binaryHash"`
	LaunchHash string `json:"launchHash"`
	StartToken string `json:"startToken"`
}

type Manager struct {
	cfg          Config
	launch       executableIdentity
	launchHash   string
	environment  []string
	oneShotSlots chan struct{}
	mu           sync.Mutex
}

func New(cfg Config) (*Manager, error) {
	if cfg.RuntimeDir == "" || !filepath.IsAbs(cfg.RuntimeDir) ||
		filepath.Clean(cfg.RuntimeDir) == string(filepath.Separator) || cfg.Handler == nil {
		return nil, ErrUnsafeRuntime
	}
	var launch executableIdentity
	if cfg.Executable != "" {
		canonical, err := filepath.EvalSymlinks(cfg.Executable)
		if err != nil {
			return nil, ErrUnsafeExecutable
		}
		cfg.Executable = canonical
		cfg.ChildEnv = ensureLaunchSource(cfg.ChildEnv, canonical)
		identity, launchErr := validateLaunch(
			cfg.Executable, cfg.Arguments, cfg.ChildEnv,
		)
		if launchErr != nil {
			return nil, launchErr
		}
		launch = identity
	} else if source := os.Getenv("PALONEXUS_DAEMON_SOURCE"); source != "" {
		cfg.ChildEnv = ensureLaunchSource(cfg.ChildEnv, source)
	}
	if cfg.ConfigurationDigest != "" && !validHexDigest(cfg.ConfigurationDigest) {
		return nil, ErrUnsafeExecutable
	}
	if cfg.StartupTimeout == 0 {
		cfg.StartupTimeout = defaultStartup
	}
	if cfg.StopTimeout == 0 {
		cfg.StopTimeout = defaultStop
	}
	if cfg.KillTimeout == 0 {
		cfg.KillTimeout = defaultKill
	}
	if cfg.StartupTimeout <= 0 || cfg.StartupTimeout > 30*time.Second ||
		cfg.StopTimeout <= 0 || cfg.StopTimeout > 30*time.Second ||
		cfg.KillTimeout <= 0 || cfg.KillTimeout > 30*time.Second {
		return nil, ErrUnsafeRuntime
	}
	dir, err := openRuntime(cfg.RuntimeDir, true)
	if err != nil {
		return nil, err
	}
	if closeErr := dir.Close(); closeErr != nil {
		return nil, ErrUnsafeRuntime
	}
	environment := append(safeBaseEnvironment(), cfg.ChildEnv...)
	return &Manager{
		cfg: cloneConfig(cfg), launch: launch,
		launchHash: canonicalLaunchHash(
			launch.Digest, cfg.Arguments, environment, cfg.ConfigurationDigest,
		),
		environment:  append([]string(nil), environment...),
		oneShotSlots: make(chan struct{}, maxOneShotActive),
	}, nil
}

func cloneConfig(cfg Config) Config {
	cfg.Arguments = append([]string(nil), cfg.Arguments...)
	cfg.ChildEnv = append([]string(nil), cfg.ChildEnv...)
	return cfg
}

func ensureLaunchSource(environment []string, source string) []string {
	for _, assignment := range environment {
		if strings.HasPrefix(assignment, "PALONEXUS_DAEMON_SOURCE=") {
			return environment
		}
	}
	return append(environment, "PALONEXUS_DAEMON_SOURCE="+source)
}

func (m *Manager) Run(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	defer cleanupRunningExecutable(m.cfg.RuntimeDir)
	runCtx, cancel := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer cancel()
	token, err := randomToken()
	if err != nil {
		return ErrUnavailable
	}
	handler := func(requestCtx context.Context, document []byte) ([]byte, error) {
		return m.cfg.Handler(requestCtx, document)
	}
	server, err := socket.New(socket.Config{
		RuntimeDir: m.cfg.RuntimeDir,
		SocketName: socketName,
		Handler:    handler,
		ControlHandler: func(_ context.Context, document []byte) ([]byte, bool) {
			if !isStopRequest(document, token) {
				return nil, false
			}
			cancel()
			return marshalFailure(), true
		},
		RequestTimeout: maxOneShot,
	})
	if err != nil {
		return classifyRuntime(err)
	}
	if m.cfg.afterSocketPublished != nil {
		m.cfg.afterSocketPublished()
	}
	executable, identity, err := currentExecutableIdentity()
	if err != nil {
		_ = server.Close()
		return ErrUnsafeExecutable
	}
	startToken, err := processStartToken(os.Getpid())
	if err != nil {
		_ = server.Close()
		return ErrUnprovenProcess
	}
	state := lifecycleState{
		Version: lifecycleVersion, PID: os.Getpid(), Token: token,
		Executable: executable, Device: identity.Device, Inode: identity.Inode,
		Mode: identity.Mode, UID: identity.UID, BinaryHash: identity.Digest,
		LaunchHash: canonicalLaunchHash(
			identity.Digest, m.cfg.Arguments, m.environment, m.cfg.ConfigurationDigest,
		),
		StartToken: startToken,
	}
	dir, err := openRuntime(m.cfg.RuntimeDir, false)
	if err != nil {
		_ = server.Close()
		return err
	}
	if err := writeState(dir, state); err != nil {
		_ = dir.Close()
		_ = server.Close()
		return err
	}
	serveErr := server.Serve(runCtx)
	removeErr := removeStateIfOwned(dir, state)
	closeErr := dir.Close()
	if serveErr != nil {
		return classifyRuntime(serveErr)
	}
	if removeErr != nil || closeErr != nil {
		return ErrUnsafeRuntime
	}
	return nil
}

func (m *Manager) Status(ctx context.Context) (Status, error) {
	if m == nil || ctx == nil {
		return Status{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return Status{}, err
	}
	dir, err := openRuntime(m.cfg.RuntimeDir, false)
	if err != nil {
		return Status{}, err
	}
	defer dir.Close()
	state, err := readState(dir)
	if errors.Is(err, os.ErrNotExist) {
		candidate, candidateErr := recoverableSocketCandidate(dir)
		if candidateErr != nil {
			return Status{}, candidateErr
		}
		if candidate {
			return Status{}, ErrUnavailable
		}
		return Status{}, nil
	}
	if err != nil {
		return Status{}, err
	}
	if !m.stateMatchesLaunch(state) {
		return Status{}, ErrUnprovenProcess
	}
	pid, probeErr := socket.Probe(filepath.Join(m.cfg.RuntimeDir, socketName), probeBudget(ctx))
	if probeErr != nil {
		if stateMatchesProcess(state) {
			return Status{}, ErrUnavailable
		}
		if processExists(state.PID) {
			return Status{}, ErrUnprovenProcess
		}
		return Status{}, nil
	}
	if pid != state.PID {
		return Status{}, ErrUnprovenProcess
	}
	if !stateMatchesProcess(state) {
		return Status{}, ErrUnprovenProcess
	}
	return Status{Running: true, PID: pid}, nil
}

func (m *Manager) Running(ctx context.Context) (bool, error) {
	status, err := m.Status(ctx)
	return status.Running, err
}

func (m *Manager) Stop(ctx context.Context) error {
	if m == nil || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir, err := openRuntime(m.cfg.RuntimeDir, false)
	if err != nil {
		return err
	}
	state, err := readState(dir)
	if errors.Is(err, os.ErrNotExist) {
		_ = dir.Close()
		return nil
	}
	if err != nil {
		_ = dir.Close()
		return err
	}
	if !m.stateMatchesLaunch(state) || !stateMatchesProcess(state) {
		_ = dir.Close()
		return ErrUnprovenProcess
	}
	path := filepath.Join(m.cfg.RuntimeDir, socketName)
	pid, err := socket.Probe(path, probeBudget(ctx))
	if err != nil || pid != state.PID {
		_ = dir.Close()
		return ErrUnprovenProcess
	}
	if err := sendStop(ctx, path, state.Token); err != nil {
		_ = dir.Close()
		return ErrUnprovenProcess
	}
	if waitStopped(ctx, path, state.PID, m.cfg.StopTimeout) {
		_ = removeStateIfOwned(dir, state)
		_ = dir.Close()
		return nil
	}
	if err := signalProven(path, state, syscall.SIGTERM); err != nil {
		_ = dir.Close()
		return err
	}
	if waitStopped(ctx, path, state.PID, m.cfg.KillTimeout) {
		_ = removeStateIfOwned(dir, state)
		_ = dir.Close()
		return nil
	}
	if err := signalProven(path, state, syscall.SIGKILL); err != nil {
		_ = dir.Close()
		return err
	}
	if !waitStopped(ctx, path, state.PID, m.cfg.KillTimeout) {
		_ = dir.Close()
		return ErrUnavailable
	}
	_ = removeStateIfOwned(dir, state)
	_ = dir.Close()
	return nil
}

func (m *Manager) Check(ctx context.Context, document []byte, oneShot bool) ([]byte, error) {
	if m == nil || ctx == nil {
		return nil, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(document) == 0 || len(document) > maxFrameBytes ||
		bytes.IndexByte(document, '\n') >= 0 {
		return nil, ErrUnavailable
	}
	if oneShot {
		return m.checkOneShot(ctx, document)
	}
	if err := m.Start(ctx); err != nil {
		return nil, ErrUnavailable
	}
	path := filepath.Join(m.cfg.RuntimeDir, socketName)
	if _, err := socket.Probe(path, probeBudget(ctx)); err != nil {
		return nil, ErrUnavailable
	}
	return exchange(ctx, path, document)
}

func (m *Manager) checkOneShot(ctx context.Context, document []byte) ([]byte, error) {
	if _, err := protocol.ParseActionRequest(document); err != nil {
		bounded, cancel := context.WithTimeout(ctx, maxOneShot)
		defer cancel()
		response := socket.ProcessFrame(bounded, document, maxFrameBytes, m.cfg.Handler)
		return validateResponse(bytes.TrimSuffix(response, []byte{'\n'}))
	}
	select {
	case m.oneShotSlots <- struct{}{}:
	default:
		return nil, ErrUnavailable
	}
	bounded, cancel := context.WithTimeout(ctx, maxOneShot)
	defer cancel()
	wrapped := func(handlerCtx context.Context, input []byte) ([]byte, error) {
		defer func() { <-m.oneShotSlots }()
		return m.cfg.Handler(handlerCtx, input)
	}
	response := socket.ProcessFrame(bounded, document, maxFrameBytes, wrapped)
	if err := bounded.Err(); err != nil {
		return nil, err
	}
	return validateResponse(bytes.TrimSuffix(response, []byte{'\n'}))
}

func validateResponse(response []byte) ([]byte, error) {
	response = bytes.TrimSpace(response)
	if len(response) == 0 || len(response) > maxFrameBytes || !json.Valid(response) {
		return nil, ErrUnavailable
	}
	if _, err := protocol.ParseAuthorizationDecision(response); err != nil {
		if _, protocolErr := protocol.ParseProtocolError(response); protocolErr != nil {
			return nil, ErrUnavailable
		}
	}
	return append([]byte(nil), response...), nil
}

func exchange(ctx context.Context, path string, document []byte) ([]byte, error) {
	deadline := time.Now().Add(maxOneShot)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	dialer := net.Dialer{Timeout: probeBudget(ctx)}
	conn, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	frame := append(append([]byte(nil), document...), '\n')
	if _, err := conn.Write(frame); err != nil {
		return nil, ErrUnavailable
	}
	reader := bufio.NewReaderSize(conn, 64<<10)
	response, err := reader.ReadSlice('\n')
	if err != nil || len(response) < 2 || len(response) > maxFrameBytes+1 {
		return nil, ErrUnavailable
	}
	if _, err := reader.Peek(1); err == nil {
		return nil, ErrUnavailable
	} else if !errors.Is(err, io.EOF) {
		// A socket remains open for no second response; one response is enough.
	}
	return validateResponse(response[:len(response)-1])
}

func marshalFailure() []byte {
	document, _ := json.Marshal(protocol.ProtocolError{
		SchemaVersion: "1",
		Code:          protocol.ProtocolErrorCodeAuthorizationUnavailable,
		SafeMessage:   "Authorization is temporarily unavailable.",
		Retryable:     true,
	})
	return document
}

func isStopRequest(document []byte, token string) bool {
	var request struct {
		SchemaVersion string `json:"schemaVersion"`
		Control       string `json:"_palonexusDaemonControl"`
		Token         string `json:"token"`
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	return decoder.Decode(&request) == nil && request.SchemaVersion == "1" &&
		request.Control == "stop" && request.Token == token
}

func sendStop(ctx context.Context, path, token string) error {
	document, _ := json.Marshal(struct {
		SchemaVersion string `json:"schemaVersion"`
		Control       string `json:"_palonexusDaemonControl"`
		Token         string `json:"token"`
	}{"1", "stop", token})
	_, err := exchange(ctx, path, document)
	return err
}

func (m *Manager) stateMatchesLaunch(state lifecycleState) bool {
	return m.cfg.Executable == "" ||
		state.Executable == m.cfg.Executable &&
			state.BinaryHash == m.launch.Digest &&
			state.LaunchHash == m.launchHash
}

func stateMatchesProcess(state lifecycleState) bool {
	device, inode, err := processIdentity(state.PID)
	startToken, startErr := processStartToken(state.PID)
	return err == nil && startErr == nil && device == state.Device &&
		inode == state.Inode && startToken == state.StartToken
}

func signalProven(path string, state lifecycleState, signal syscall.Signal) error {
	current, err := socket.Probe(path, time.Second)
	if err != nil {
		if !processExists(state.PID) {
			return nil
		}
		return ErrUnprovenProcess
	}
	if current != state.PID || !stateMatchesProcess(state) {
		return ErrUnprovenProcess
	}
	return signalStableProcess(state, signal)
}

func waitStopped(ctx context.Context, path string, pid int, maximum time.Duration) bool {
	timer := time.NewTimer(maximum)
	defer timer.Stop()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := socket.Probe(path, 100*time.Millisecond); err != nil && !processExists(pid) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return false
		case <-ticker.C:
		}
	}
}

func probeBudget(ctx context.Context) time.Duration {
	const maximum = time.Second
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining < maximum {
			if remaining <= 0 {
				return time.Millisecond
			}
			return remaining
		}
	}
	return maximum
}

func randomToken() (string, error) {
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(value[:]), nil
}

func classifyRuntime(err error) error {
	if errors.Is(err, socket.ErrRecoveryAmbiguous) {
		return err
	}
	return ErrUnsafeRuntime
}

type executableIdentity struct {
	Device uint64
	Inode  uint64
	Mode   uint32
	UID    uint32
	Digest string
}

func currentExecutableIdentity() (string, executableIdentity, error) {
	path, err := runningExecutablePath()
	if err != nil {
		return "", executableIdentity{}, err
	}
	identity, err := inspectRunningExecutable(path)
	if source := os.Getenv("PALONEXUS_DAEMON_SOURCE"); source != "" {
		path = source
	}
	return path, identity, err
}

func validateLaunch(
	executable string,
	arguments, environment []string,
) (executableIdentity, error) {
	if !filepath.IsAbs(executable) || filepath.Clean(executable) == string(filepath.Separator) ||
		strings.ContainsRune(executable, 0) {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	info, err := os.Lstat(executable)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&0o022 != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (int(stat.Uid) != os.Geteuid() && stat.Uid != 0) || stat.Nlink != 1 {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	// Scripts delegate interpretation to a mutable shebang target. The daemon
	// launcher accepts only native executables.
	file, err := os.Open(executable)
	if err != nil {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	var header [2]byte
	_, readErr := io.ReadFull(file, header[:])
	_ = file.Close()
	if readErr != nil || string(header[:]) == "#!" {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	if len(arguments) > 128 || len(environment) > 128 {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	for _, value := range arguments {
		if value == "" || len(value) > 4096 || strings.ContainsRune(value, 0) ||
			strings.ContainsAny(value, "\r\n") {
			return executableIdentity{}, ErrUnsafeExecutable
		}
	}
	seenEnvironment := make(map[string]struct{}, len(environment))
	for _, assignment := range environment {
		if assignment == "" || len(assignment) > 4096 ||
			strings.ContainsRune(assignment, 0) || strings.ContainsAny(assignment, "\r\n") {
			return executableIdentity{}, ErrUnsafeExecutable
		}
		name, value, ok := strings.Cut(assignment, "=")
		if !ok || value == "" || !validChildEnvironmentName(name) {
			return executableIdentity{}, ErrUnsafeExecutable
		}
		if _, duplicate := seenEnvironment[name]; duplicate {
			return executableIdentity{}, ErrUnsafeExecutable
		}
		seenEnvironment[name] = struct{}{}
	}
	return inspectExecutable(executable)
}

func inspectExecutable(path string) (executableIdentity, error) {
	file, err := os.Open(path)
	if err != nil {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	defer file.Close()
	return inspectExecutableFile(file)
}

func inspectExecutableFile(file *os.File) (executableIdentity, error) {
	info, err := file.Stat()
	if err != nil {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || info.Mode()&0o022 != 0 ||
		info.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 ||
		(int(stat.Uid) != os.Geteuid() && stat.Uid != 0) || stat.Nlink != 1 {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, file); err != nil {
		return executableIdentity{}, ErrUnsafeExecutable
	}
	return executableIdentity{
		Device: uint64(stat.Dev), Inode: uint64(stat.Ino),
		Mode: uint32(stat.Mode), UID: stat.Uid,
		Digest: hex.EncodeToString(hasher.Sum(nil)),
	}, nil
}

func canonicalLaunchHash(
	binaryDigest string,
	arguments, environment []string,
	configurationDigest string,
) string {
	hasher := sha256.New()
	writeHashField(hasher, "palonexus-daemon-launch-v1")
	writeHashField(hasher, binaryDigest)
	for _, argument := range arguments {
		writeHashField(hasher, argument)
	}
	sortedEnvironment := append([]string(nil), environment...)
	sort.Strings(sortedEnvironment)
	for _, assignment := range sortedEnvironment {
		writeHashField(hasher, assignment)
	}
	writeHashField(hasher, configurationDigest)
	return hex.EncodeToString(hasher.Sum(nil))
}

func writeHashField(writer io.Writer, value string) {
	var length [8]byte
	binary.BigEndian.PutUint64(length[:], uint64(len(value)))
	_, _ = writer.Write(length[:])
	_, _ = io.WriteString(writer, value)
}

func validHexDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func validChildEnvironmentName(name string) bool {
	const prefix = "PALONEXUS_"
	if !strings.HasPrefix(name, prefix) || len(name) <= len(prefix) || len(name) > 64 {
		return false
	}
	for _, character := range name[len(prefix):] {
		if character != '_' && (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func openRuntime(path string, create bool) (*os.File, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) || clean == string(filepath.Separator) {
		return nil, ErrUnsafeRuntime
	}
	parts := strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator))
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, ErrUnsafeRuntime
	}
	for index, part := range parts {
		next, openErr := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(openErr, unix.ENOENT) && create && index == len(parts)-1 {
			if mkdirErr := unix.Mkdirat(fd, part, 0o700); mkdirErr != nil && !errors.Is(mkdirErr, unix.EEXIST) {
				_ = unix.Close(fd)
				return nil, ErrUnsafeRuntime
			}
			next, openErr = unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if openErr != nil {
			_ = unix.Close(fd)
			return nil, ErrUnsafeRuntime
		}
		if err := validateDirectoryFD(next, index == len(parts)-1); err != nil {
			_ = unix.Close(next)
			_ = unix.Close(fd)
			return nil, err
		}
		_ = unix.Close(fd)
		fd = next
	}
	return os.NewFile(uintptr(fd), clean), nil
}

func validateDirectoryFD(fd int, final bool) error {
	var stat unix.Stat_t
	if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		(int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid()) {
		return ErrUnsafeRuntime
	}
	if final {
		if stat.Mode&0o077 != 0 || int(stat.Uid) != os.Geteuid() {
			return ErrUnsafeRuntime
		}
	} else if stat.Mode&0o022 != 0 {
		// Root-owned sticky directories such as /tmp are safe traversal
		// anchors: the sticky bit prevents another user from replacing the
		// current user's next component. Every descendant is still opened
		// through the held directory descriptor with O_NOFOLLOW.
		if stat.Uid != 0 || stat.Mode&unix.S_ISVTX == 0 {
			return ErrUnsafeRuntime
		}
	}
	return nil
}

type fileID struct{ device, inode uint64 }

func inspectRegularAt(dir *os.File, name string) (fileID, error) {
	var stat unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return fileID{}, os.ErrNotExist
		}
		return fileID{}, ErrUnsafeRuntime
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG || stat.Mode&0o077 != 0 ||
		int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return fileID{}, ErrUnsafeRuntime
	}
	return fileID{uint64(stat.Dev), uint64(stat.Ino)}, nil
}

func readState(dir *os.File) (lifecycleState, error) {
	if _, err := inspectRegularAt(dir, stateName); err != nil {
		return lifecycleState{}, err
	}
	fd, err := unix.Openat(int(dir.Fd()), stateName, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return lifecycleState{}, ErrUnsafeRuntime
	}
	file := os.NewFile(uintptr(fd), stateName)
	defer file.Close()
	var opened unix.Stat_t
	if unix.Fstat(fd, &opened) != nil || opened.Mode&unix.S_IFMT != unix.S_IFREG ||
		opened.Mode&0o077 != 0 || int(opened.Uid) != os.Geteuid() ||
		opened.Nlink != 1 {
		return lifecycleState{}, ErrUnsafeRuntime
	}
	limited := io.LimitReader(file, maxStateBytes+1)
	document, err := io.ReadAll(limited)
	if err != nil || len(document) > maxStateBytes {
		return lifecycleState{}, ErrUnsafeRuntime
	}
	var value lifecycleState
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil || decoder.Decode(&struct{}{}) != io.EOF ||
		value.Version != lifecycleVersion || value.PID <= 0 || len(value.Token) != 64 ||
		value.Executable == "" || len(value.Executable) > 4096 ||
		!filepath.IsAbs(value.Executable) || filepath.Clean(value.Executable) != value.Executable ||
		strings.ContainsAny(value.Executable, "\x00\r\n") ||
		value.Device == 0 || value.Inode == 0 || value.Mode == 0 ||
		!validHexDigest(value.BinaryHash) || !validHexDigest(value.LaunchHash) ||
		value.StartToken == "" || len(value.StartToken) > 128 ||
		strings.ContainsAny(value.StartToken, "\x00\r\n") {
		return lifecycleState{}, ErrUnsafeRuntime
	}
	if _, err := hex.DecodeString(value.Token); err != nil {
		return lifecycleState{}, ErrUnsafeRuntime
	}
	return value, nil
}

func writeState(dir *os.File, value lifecycleState) error {
	if _, err := inspectRegularAt(dir, stateName); err == nil {
		return ErrUnsafeRuntime
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	document, err := json.Marshal(value)
	if err != nil || len(document) > maxStateBytes {
		return ErrUnsafeRuntime
	}
	token, err := randomToken()
	if err != nil {
		return ErrUnsafeRuntime
	}
	temp := ".daemon-state-" + token
	fd, err := unix.Openat(int(dir.Fd()), temp,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return ErrUnsafeRuntime
	}
	file := os.NewFile(uintptr(fd), temp)
	ok := false
	defer func() {
		_ = file.Close()
		if !ok {
			_ = unix.Unlinkat(int(dir.Fd()), temp, 0)
		}
	}()
	if _, err := file.Write(document); err != nil || file.Sync() != nil || file.Close() != nil {
		return ErrUnsafeRuntime
	}
	if err := unix.Linkat(int(dir.Fd()), temp, int(dir.Fd()), stateName, 0); err != nil {
		return ErrUnsafeRuntime
	}
	if err := unix.Unlinkat(int(dir.Fd()), temp, 0); err != nil {
		return ErrUnsafeRuntime
	}
	if err := unix.Fsync(int(dir.Fd())); err != nil {
		return ErrUnsafeRuntime
	}
	ok = true
	return nil
}

func removeStateIfOwned(dir *os.File, expected lifecycleState) error {
	current, err := readState(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || current.Token != expected.Token || current.PID != expected.PID {
		return ErrUnsafeRuntime
	}
	if err := unix.Unlinkat(int(dir.Fd()), stateName, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return ErrUnsafeRuntime
	}
	if err := unix.Fsync(int(dir.Fd())); err != nil {
		return ErrUnsafeRuntime
	}
	return nil
}

func existsAt(dir *os.File, name string) bool {
	var stat unix.Stat_t
	return unix.Fstatat(int(dir.Fd()), name, &stat, unix.AT_SYMLINK_NOFOLLOW) == nil
}

func recoverableSocketCandidate(dir *os.File) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), socketName, &stat, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil {
		return false, ErrUnsafeRuntime
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFSOCK || stat.Mode&0o777 != 0o600 ||
		int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return false, ErrUnsafeRuntime
	}
	return true, nil
}
