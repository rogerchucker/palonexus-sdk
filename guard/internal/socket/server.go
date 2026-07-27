// SPDX-License-Identifier: MIT
// Package socket implements the guard's local, fail-closed NDJSON transport.
package socket

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

const (
	DefaultSocketName = "guard.sock"
	defaultMaxRequest = 1 << 20
	defaultIOTimeout  = 5 * time.Second
)

type Handler func(context.Context, []byte) ([]byte, error)

type Config struct {
	RuntimeDir      string
	SocketName      string
	MaxRequestBytes int
	IOTimeout       time.Duration
	RequestTimeout  time.Duration
	Handler         Handler
	// beforeBind is a test seam for exercising pathname replacement races.
	beforeBind func()
	// peerUID is a test seam for exercising credential rejection.
	peerUID func(net.Conn) (uint32, error)
}

type Server struct {
	listener *net.UnixListener
	dir      *os.File
	dirInfo  os.FileInfo
	path     string
	bound    os.FileInfo
	boundID  fileIdentity
	cfg      Config

	closeOnce sync.Once
	closeErr  error
	wg        sync.WaitGroup
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
	if cfg.MaxRequestBytes < 1 || cfg.MaxRequestBytes > 16<<20 {
		return nil, errors.New("socket: invalid request size limit")
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
	fail := func(err error) (*Server, error) {
		_ = dir.Close()
		return nil, err
	}
	path := filepath.Join(cfg.RuntimeDir, cfg.SocketName)
	if _, err := os.Lstat(path); err == nil {
		return fail(errors.New("socket: path already exists"))
	} else if !errors.Is(err, os.ErrNotExist) {
		return fail(fmt.Errorf("socket: inspect path: %w", err))
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
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return fail(fmt.Errorf("socket: bind: %w", err))
	}
	// The standard library otherwise unlinks the pathname unconditionally on
	// Close, which could delete an attacker replacement. Cleanup below is
	// identity checked instead.
	listener.SetUnlinkOnClose(false)
	bound, err := os.Lstat(path)
	if err != nil || bound.Mode()&os.ModeSocket == 0 {
		_ = listener.Close()
		_ = dir.Close()
		return nil, errors.New("socket: bound path verification failed")
	}
	boundID, err := identityFromInfo(bound)
	if err != nil {
		_ = listener.Close()
		_ = dir.Close()
		return nil, err
	}
	cleanupListener := func(err error) (*Server, error) {
		_ = listener.Close()
		_ = removeOwnedAt(dir, cfg.SocketName, boundID)
		_ = dir.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return cleanupListener(fmt.Errorf("socket: restrict permissions: %w", err))
	}
	restricted, err := os.Lstat(path)
	if err != nil || !os.SameFile(restricted, bound) ||
		restricted.Mode()&os.ModeSocket == 0 || restricted.Mode().Perm() != 0o600 {
		return cleanupListener(errors.New("socket: bound path verification failed"))
	}
	if err := verifyRuntimeDir(dir, cfg.RuntimeDir, dirInfo); err != nil {
		return cleanupListener(err)
	}
	return &Server{
		listener: listener, dir: dir, dirInfo: dirInfo, path: path, bound: restricted,
		boundID: boundID, cfg: cfg,
	}, nil
}

func (s *Server) Path() string { return s.path }

func (s *Server) Serve(ctx context.Context) error {
	if ctx == nil {
		return errors.New("socket: nil context")
	}
	defer s.Close()
	if err := verifyRuntimeDir(s.dir, filepath.Dir(s.path), s.dirInfo); err != nil {
		return err
	}
	current, err := os.Lstat(s.path)
	if err != nil || !os.SameFile(current, s.bound) || current.Mode()&os.ModeSocket == 0 {
		return errors.New("socket: bound path was replaced before serving")
	}
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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
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
	ctx, cancel := context.WithTimeout(parent, s.cfg.RequestTimeout)
	defer cancel()
	response := processFrame(ctx, frame, s.cfg.MaxRequestBytes, s.cfg.Handler)
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
	type handlerResult struct {
		response []byte
		err      error
	}
	resultChannel := make(chan handlerResult, 1)
	go func() {
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
	response := result.response
	response = bytes.TrimSpace(response)
	if len(response) == 0 || len(response) > maximum || !json.Valid(response) {
		return failure(protocol.ProtocolErrorCodeInvalidDecision, false)
	}
	return append(append([]byte(nil), response...), '\n')
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
		listenErr := s.listener.Close()
		s.wg.Wait()
		runtimeErr := verifyRuntimeDir(s.dir, filepath.Dir(s.path), s.dirInfo)
		if err := removeOwnedAt(s.dir, filepath.Base(s.path), s.boundID); err != nil {
			s.closeErr = err
		} else if runtimeErr != nil {
			s.closeErr = runtimeErr
		} else if listenErr != nil && !errors.Is(listenErr, net.ErrClosed) {
			s.closeErr = listenErr
		}
		if err := s.dir.Close(); s.closeErr == nil && err != nil {
			s.closeErr = err
		}
	})
	return s.closeErr
}
