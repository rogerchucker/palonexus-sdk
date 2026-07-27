// SPDX-License-Identifier: MIT
//go:build unix

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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
	"golang.org/x/sys/unix"
)

func echoHandler(_ context.Context, request []byte) ([]byte, error) {
	return bytes.TrimSpace(failure(
		protocol.ProtocolErrorCodeInvalidRequest, false,
	)), nil
}

func validActionFrame(t *testing.T) string {
	t.Helper()
	document, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "protocol", "test-vectors", "action", "valid", "file-write.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, document); err != nil {
		t.Fatal(err)
	}
	if _, err := protocol.ParseActionRequest(compact.Bytes()); err != nil {
		t.Fatalf("valid action fixture: %v", err)
	}
	return compact.String() + "\n"
}

func startTestServer(t *testing.T, mutate func(*Config)) (*Server, string) {
	t.Helper()
	root, err := os.MkdirTemp("", "pn-sock-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	cfg := Config{RuntimeDir: filepath.Join(root, "run"), Handler: echoHandler}
	if mutate != nil {
		mutate(&cfg)
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = srv.Close()
	})
	go func() { _ = srv.Serve(ctx) }()
	return srv, srv.Path()
}

func exchange(t *testing.T, path string, request string) []byte {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestRuntimeDirectoryAndSocketAreUserOnly(t *testing.T) {
	_, path := startTestServer(t, nil)
	for _, target := range []string{filepath.Dir(path), path} {
		info, err := os.Lstat(target)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("%s is accessible by another user: %o", target, info.Mode().Perm())
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != uint32(os.Getuid()) {
			t.Fatalf("%s is not owned by the current user", target)
		}
	}
}

func TestPermissionsAreIndependentOfUmask(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-umask-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	previous := syscall.Umask(0o777)
	defer syscall.Umask(previous)
	srv, err := New(Config{RuntimeDir: filepath.Join(root, "run"), Handler: echoHandler})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	path := srv.Path()
	dirInfo, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	socketInfo, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 || socketInfo.Mode().Perm() != 0o600 {
		t.Fatalf("permissions depend on umask: dir=%o socket=%o",
			dirInfo.Mode().Perm(), socketInfo.Mode().Perm())
	}
}

func TestOneRequestOneResponseNDJSON(t *testing.T) {
	_, path := startTestServer(t, nil)
	got := exchange(t, path, `{"schemaVersion":"1","value":"ok"}`+"\n")
	if _, err := protocol.ParseProtocolError(got); err != nil {
		t.Fatalf("unexpected response %q: %v", got, err)
	}
}

func TestHandlerResponseIsOneCompactPhysicalLine(t *testing.T) {
	_, path := startTestServer(t, func(c *Config) {
		c.Handler = func(context.Context, []byte) ([]byte, error) {
			return []byte("{\n  \"schemaVersion\": \"1\",\n" +
				"  \"code\": \"invalid_request\",\n" +
				"  \"safeMessage\": \"The request is invalid.\",\n" +
				"  \"retryable\": false\n}"), nil
		}
	})
	got := exchange(t, path, validActionFrame(t))
	if string(got) != `{"schemaVersion":"1","code":"invalid_request","safeMessage":"The request is invalid.","retryable":false}`+"\n" {
		t.Fatalf("response is not compact NDJSON: %q", got)
	}
}

func TestHandlerResponseMustBeAProtocolDecisionOrError(t *testing.T) {
	invalid := [][]byte{
		[]byte(`null`),
		[]byte(`[]`),
		[]byte(`{"schemaVersion":"1","schemaVersion":"1"}`),
		[]byte(`{"code":"invalid_request"}`),
		[]byte(`{"schemaVersion":"2"}`),
		[]byte(`{"schemaVersion":"1","value":"not-a-decision"}`),
	}
	for _, response := range invalid {
		t.Run(string(response), func(t *testing.T) {
			_, path := startTestServer(t, func(c *Config) {
				c.Handler = func(context.Context, []byte) ([]byte, error) {
					return response, nil
				}
			})
			document := exchange(t, path, validActionFrame(t))
			failure, err := protocol.ParseProtocolError(document)
			if err != nil || failure.Code != protocol.ProtocolErrorCodeInvalidDecision {
				t.Fatalf("invalid handler response escaped: %s, %v", document, err)
			}
		})
	}
	validDecision := []byte(`{"schemaVersion":"1","requestId":"req_01J5ABCDEFGHJKMNPQRSTVWXY0","decisionId":"dec_01J5ABCDEFGHJKMNPQRSTVWXY0","correlationId":"corr_01J5ABCDEFGHJKMNPQRSTVWXY0","outcome":"allow","reasonCode":"policy_allowed","displayReason":"The action is authorized.","clientScopeHash":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","authoritativeScopeHash":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","policyRevision":"policy_42","serverTime":"2026-07-25T20:00:01Z","expiresAt":"2026-07-25T20:05:00Z","auditRef":"audit_01J5ABCDEFGHJKMNPQRSTVWXY0","cache":{"cacheable":false}}`)
	_, path := startTestServer(t, func(c *Config) {
		c.Handler = func(context.Context, []byte) ([]byte, error) {
			return validDecision, nil
		}
	})
	document := exchange(t, path, validActionFrame(t))
	if _, err := protocol.ParseAuthorizationDecision(document); err != nil {
		t.Fatalf("valid decision was rejected: %s, %v", document, err)
	}
}

func TestMalformedUnknownMajorAndOversizedRequestsFailClosed(t *testing.T) {
	_, path := startTestServer(t, func(c *Config) { c.MaxRequestBytes = 64 })
	for _, request := range []string{
		"{\n",
		`{"schemaVersion":"2"}` + "\n",
		`{"schemaVersion":"1","padding":"` + string(make([]byte, 80)) + `"}` + "\n",
	} {
		response := exchange(t, path, request)
		failure, err := protocol.ParseProtocolError(response)
		if err != nil {
			t.Fatalf("response is not structured: %s: %v", response, err)
		}
		if failure.SchemaVersion != "1" || failure.Code == "" || failure.Retryable {
			t.Fatalf("not fail-closed: %#v", failure)
		}
	}
}

func TestDuplicateTopLevelKeysAreMalformed(t *testing.T) {
	_, path := startTestServer(t, nil)
	response := exchange(t, path,
		`{"schemaVersion":"2","schemaVersion":"1"}`+"\n")
	failure, err := protocol.ParseProtocolError(response)
	if err != nil {
		t.Fatalf("duplicate key was not rejected: %s: %v", response, err)
	}
	if failure.Code != protocol.ProtocolErrorCodeInvalidRequest {
		t.Fatalf("wrong duplicate-key failure: %#v", failure)
	}
}

func TestHandlerErrorsNeverLeakCredentials(t *testing.T) {
	const secret = "Bearer super-secret-token"
	_, path := startTestServer(t, func(c *Config) {
		c.Handler = func(context.Context, []byte) ([]byte, error) {
			return nil, errors.New(secret)
		}
	})
	response := exchange(t, path, validActionFrame(t))
	if bytes.Contains(response, []byte(secret)) {
		t.Fatalf("credential leaked in response: %s", response)
	}
	failure, err := protocol.ParseProtocolError(response)
	if err != nil || failure.Code != protocol.ProtocolErrorCodeAuthorizationUnavailable {
		t.Fatalf("invalid safe failure: %#v, %v", failure, err)
	}
}

func TestConcurrentClients(t *testing.T) {
	_, path := startTestServer(t, nil)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := exchange(t, path, validActionFrame(t)); len(got) == 0 {
				t.Error("empty response")
			}
		}()
	}
	wg.Wait()
}

func TestPeerUIDMismatchFailsClosedBeforeHandler(t *testing.T) {
	called := false
	_, path := startTestServer(t, func(c *Config) {
		c.peerUID = func(net.Conn) (uint32, error) {
			return uint32(os.Getuid()) + 1, nil
		}
		c.Handler = func(context.Context, []byte) ([]byte, error) {
			called = true
			return []byte(`{"schemaVersion":"1"}`), nil
		}
	})
	response := exchange(t, path, validActionFrame(t))
	failure, err := protocol.ParseProtocolError(response)
	if err != nil {
		t.Fatal(err)
	}
	if failure.Code != protocol.ProtocolErrorCodeAuthenticationFailed || called {
		t.Fatalf("peer mismatch was not rejected before handler: %#v, called=%v", failure, called)
	}
}

func TestCloseRemovesOnlyOwnedSocketAndUnblocksServe(t *testing.T) {
	srv, path := startTestServer(t, nil)
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains: %v", err)
	}
}

func TestServeContextCancellationCleansUpSocket(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-stop-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	srv, err := New(Config{RuntimeDir: filepath.Join(root, "run"), Handler: echoHandler})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx) }()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(srv.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket remains after shutdown: %v", err)
	}
}

func TestRejectsUnsafeRuntimeAndPreexistingSocketPaths(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-unsafe-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	realDir := filepath.Join(root, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(root, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if _, err := New(Config{RuntimeDir: linkDir, Handler: echoHandler}); err == nil {
		t.Fatal("accepted symlinked runtime directory")
	}

	kinds := []struct {
		name string
		make func(string) error
	}{
		{"regular", func(p string) error { return os.WriteFile(p, []byte("x"), 0o600) }},
		{"fifo", func(p string) error { return makeFIFO(p) }},
		{"symlink", func(p string) error { return os.Symlink("elsewhere", p) }},
	}
	for _, kind := range kinds {
		t.Run(kind.name, func(t *testing.T) {
			dir := filepath.Join(root, kind.name)
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := kind.make(filepath.Join(dir, DefaultSocketName)); err != nil {
				t.Fatal(err)
			}
			if _, err := New(Config{RuntimeDir: dir, Handler: echoHandler}); err == nil {
				t.Fatalf("accepted pre-existing %s", kind.name)
			}
		})
	}

	t.Run("socket", func(t *testing.T) {
		dir := filepath.Join(root, "existing-socket")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		listener, err := net.Listen("unix", filepath.Join(dir, DefaultSocketName))
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		if _, err := New(Config{RuntimeDir: dir, Handler: echoHandler}); err == nil {
			t.Fatal("accepted pre-existing socket")
		}
	})

	t.Run("device", func(t *testing.T) {
		dir := filepath.Join(root, "existing-device")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		device := filepath.Join(dir, DefaultSocketName)
		err := unix.Mknod(device, unix.S_IFCHR|0o600, int(unix.Mkdev(1, 3)))
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			t.Skip("kernel denied unprivileged device inode creation")
		}
		if err != nil {
			t.Fatalf("device capability probe failed: %v", err)
		}
		if _, err := New(Config{RuntimeDir: dir, Handler: echoHandler}); err == nil {
			t.Fatal("accepted pre-existing device inode")
		}
		if info, err := os.Lstat(device); err != nil || info.Mode()&os.ModeDevice == 0 {
			t.Fatalf("device inode was removed: %v", err)
		}
	})
}

func TestOwnedStaleModeClassifierRejectsEveryNonSocketInode(t *testing.T) {
	identity := fileIdentity{device: 7, inode: 9}
	record := identity
	for name, mode := range map[string]uint32{
		"regular":   unix.S_IFREG | 0o600,
		"directory": unix.S_IFDIR | 0o700,
		"fifo":      unix.S_IFIFO | 0o600,
		"character": unix.S_IFCHR | 0o600,
		"block":     unix.S_IFBLK | 0o600,
		"symlink":   unix.S_IFLNK | 0o777,
	} {
		t.Run(name, func(t *testing.T) {
			node := nodeInfo{identity: identity, mode: mode, uid: uint32(os.Getuid())}
			if ownedStaleSocket(node, &record) {
				t.Fatalf("classified %s as an owned stale socket", name)
			}
		})
	}
	socket := nodeInfo{
		identity: identity, mode: unix.S_IFSOCK | 0o600, uid: uint32(os.Getuid()),
	}
	if !ownedStaleSocket(socket, &record) {
		t.Fatal("rejected matching owned socket")
	}
}

func TestCleanupNeverUnlinksReplacement(t *testing.T) {
	srv, path := startTestServer(t, nil)
	_ = exchange(t, path, validActionFrame(t))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err == nil {
		t.Fatal("replacement was not reported")
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatalf("replacement was removed or changed: %q, %v", data, err)
	}
}

func TestRuntimeDirectoryReplacementBeforeBindIsRejected(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-race-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "run")
	cfg := Config{RuntimeDir: dir, Handler: echoHandler}
	cfg.beforeBind = func() {
		if err := os.Rename(dir, dir+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if srv, err := New(cfg); err == nil {
		_ = srv.Close()
		t.Fatal("accepted replaced runtime directory")
	}
}

func TestReplacementAfterLastValidationBeforeBindIsRejected(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-bind-race-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "run")
	cfg := Config{RuntimeDir: dir, Handler: echoHandler}
	cfg.afterValidationBeforeBind = func() {
		if err := os.Rename(dir, dir+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if srv, err := New(cfg); err == nil {
		_ = srv.Close()
		t.Fatal("accepted replacement after final validation")
	}
}

func TestPublishedPathMustReachActualListener(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-proof-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "run")
	var replacement *net.UnixListener
	cfg := Config{
		RuntimeDir: dir, Handler: echoHandler, IOTimeout: 30 * time.Millisecond,
	}
	cfg.beforeListenerProof = func(path string) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		var err error
		replacement, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		replacement.SetUnlinkOnClose(false)
	}
	if srv, err := New(cfg); err == nil {
		_ = srv.Close()
		t.Fatal("accepted a pathname routed to a different listener")
	}
	if replacement == nil {
		t.Fatal("replacement hook did not run")
	}
	defer replacement.Close()
	info, err := os.Lstat(filepath.Join(dir, DefaultSocketName))
	if err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("listener replacement was removed: %v", err)
	}
}

func TestLifecycleProofHasIndependentMinimumBudget(t *testing.T) {
	for iteration := range 100 {
		root, err := os.MkdirTemp("", "pl-")
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, "run")
		server, err := New(Config{
			RuntimeDir: dir,
			SocketName: DefaultSocketName,
			Handler:    echoHandler,
			IOTimeout:  time.Nanosecond,
		})
		if err != nil {
			t.Fatalf("iteration %d: %v", iteration, err)
		}
		if err := server.Close(); err != nil {
			t.Fatalf("iteration %d close: %v", iteration, err)
		}
		if err := os.RemoveAll(root); err != nil {
			t.Fatalf("iteration %d cleanup: %v", iteration, err)
		}
	}
}

func TestRuntimeDirectoryPermissionChangeBeforeBindIsRejected(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-mode-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "run")
	cfg := Config{RuntimeDir: dir, Handler: echoHandler}
	cfg.beforeBind = func() {
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if srv, err := New(cfg); err == nil {
		_ = srv.Close()
		t.Fatal("accepted runtime directory after unsafe mode change")
	}
}

func TestRuntimeDirectorySwapDuringCleanupPreservesReplacement(t *testing.T) {
	srv, path := startTestServer(t, nil)
	dir := filepath.Dir(path)
	old := dir + ".original"
	if err := os.Rename(dir, old); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, filepath.Base(path))
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	closeErr := srv.Close()
	if closeErr == nil {
		t.Fatal("runtime replacement was not reported")
	}
	var typed *CloseError
	if !errors.As(closeErr, &typed) {
		t.Fatalf("close error is not typed: %T", closeErr)
	}
	if data, err := os.ReadFile(replacement); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement changed: %q, %v", data, err)
	}
	oldDir, _, err := prepareRuntimeDir(old)
	if err != nil {
		t.Fatal(err)
	}
	defer oldDir.Close()
	record, err := readLifecycleRecord(oldDir, "."+DefaultSocketName+".lifecycle")
	if err != nil || record == nil || record.Phase != "published" {
		t.Fatalf("close erased retryable ownership record: %#v, %v", record, err)
	}
}

func TestCloseFaultRetainsDurableOwnershipForRestart(t *testing.T) {
	for _, point := range []string{"before_remove", "after_remove", "before_clean"} {
		t.Run(point, func(t *testing.T) {
			root, err := os.MkdirTemp("", "pn-close-fault-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			dir := filepath.Join(root, "run")
			srv, err := New(Config{
				RuntimeDir: dir,
				Handler:    echoHandler,
				closeFault: func(actual string) error {
					if actual == point {
						return errors.New("injected close fault")
					}
					return nil
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			closeErr := srv.Close()
			var typed *CloseError
			if !errors.As(closeErr, &typed) {
				t.Fatalf("close fault was not typed: %v", closeErr)
			}
			dirFile, _, err := prepareRuntimeDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			record, err := readLifecycleRecord(
				dirFile, "."+DefaultSocketName+".lifecycle",
			)
			_ = dirFile.Close()
			if err != nil || record == nil || record.Phase != "published" {
				t.Fatalf("ownership record was erased: %#v, %v", record, err)
			}
			restarted, err := New(Config{
				RuntimeDir: dir, Handler: echoHandler,
				IOTimeout: 50 * time.Millisecond,
			})
			if err != nil {
				t.Fatalf("restart could not retry cleanup: %v", err)
			}
			if err := restarted.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCancellationProducesBoundedFailure(t *testing.T) {
	_, path := startTestServer(t, func(c *Config) {
		c.Handler = func(ctx context.Context, _ []byte) ([]byte, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		c.RequestTimeout = 20 * time.Millisecond
	})
	start := time.Now()
	response := exchange(t, path, validActionFrame(t))
	if time.Since(start) > time.Second {
		t.Fatal("request did not terminate")
	}
	var failure protocol.ProtocolError
	if json.Unmarshal(response, &failure) != nil || !failure.Retryable {
		t.Fatalf("expected retryable structured failure: %s", response)
	}
}

func TestRequestDeadlineDoesNotDependOnHandlerCooperation(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	_, path := startTestServer(t, func(c *Config) {
		c.Handler = func(context.Context, []byte) ([]byte, error) {
			<-release
			return []byte(`{"schemaVersion":"1"}`), nil
		}
		c.RequestTimeout = 20 * time.Millisecond
	})
	start := time.Now()
	response := exchange(t, path, validActionFrame(t))
	if time.Since(start) > time.Second {
		t.Fatal("uncooperative handler held the connection")
	}
	var failure protocol.ProtocolError
	if json.Unmarshal(response, &failure) != nil || !failure.Retryable {
		t.Fatalf("expected retryable structured failure: %s", response)
	}
}

func TestUncooperativeHandlersAreStrictlyBounded(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	runtime.GC()
	var memoryBefore runtime.MemStats
	runtime.ReadMemStats(&memoryBefore)
	before := runtime.NumGoroutine()
	fdBefore := openFDCount(t)
	_, path := startTestServer(t, func(c *Config) {
		c.MaxConcurrentClients = 8
		c.MaxConcurrentHandlers = 2
		c.RequestTimeout = 5 * time.Millisecond
		c.Handler = func(context.Context, []byte) ([]byte, error) {
			calls.Add(1)
			<-release
			return bytes.TrimSpace(failure(
				protocol.ProtocolErrorCodeAuthorizationUnavailable, true,
			)), nil
		}
	})
	for i := 0; i < 200; i++ {
		response := exchange(t, path, validActionFrame(t))
		failure, err := protocol.ParseProtocolError(response)
		if err != nil || failure.Code != protocol.ProtocolErrorCodeAuthorizationUnavailable {
			t.Fatalf("request %d did not fail closed: %s, %v", i, response, err)
		}
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("started %d detached handlers, want 2", got)
	}
	if growth := runtime.NumGoroutine() - before; growth > 16 {
		t.Fatalf("goroutine growth %d is not bounded", growth)
	}
	if growth := openFDCount(t) - fdBefore; growth > 16 {
		t.Fatalf("file descriptor growth %d is not bounded", growth)
	}
	runtime.GC()
	var memoryAfter runtime.MemStats
	runtime.ReadMemStats(&memoryAfter)
	if growth := int64(memoryAfter.HeapAlloc) - int64(memoryBefore.HeapAlloc); growth > 16<<20 {
		t.Fatalf("heap growth %d is not bounded", growth)
	}
	close(release)
}

func TestClientAdmissionIsBoundedBeforeReading(t *testing.T) {
	srv, path := startTestServer(t, func(c *Config) {
		c.MaxConcurrentClients = 2
		c.MaxConcurrentHandlers = 1
		c.IOTimeout = time.Second
	})
	var held []net.Conn
	for i := 0; i < 2; i++ {
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, conn)
	}
	defer func() {
		for _, conn := range held {
			_ = conn.Close()
		}
	}()
	deadline := time.Now().Add(time.Second)
	for len(srv.clientSlots) != 2 && time.Now().Before(deadline) {
		runtime.Gosched()
	}
	if len(srv.clientSlots) != 2 {
		t.Fatal("held clients were not admitted")
	}
	start := time.Now()
	response := exchange(t, path, validActionFrame(t))
	if time.Since(start) > 250*time.Millisecond {
		t.Fatal("client admission waited for a read slot")
	}
	failure, err := protocol.ParseProtocolError(response)
	if err != nil || failure.Code != protocol.ProtocolErrorCodeAuthorizationUnavailable {
		t.Fatalf("overload was not fail closed: %s, %v", response, err)
	}
}

func openFDCount(t *testing.T) int {
	t.Helper()
	for _, directory := range []string{"/dev/fd", "/proc/self/fd"} {
		entries, err := os.ReadDir(directory)
		if err == nil {
			return len(entries)
		}
	}
	t.Skip("platform does not expose process file descriptors")
	return 0
}

func TestReadTimeoutReturnsStructuredFailure(t *testing.T) {
	_, path := startTestServer(t, func(c *Config) {
		c.IOTimeout = 20 * time.Millisecond
	})
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	response, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		t.Fatalf("read timeout was not structured: %v", err)
	}
	failure, err := protocol.ParseProtocolError(response)
	if err != nil || failure.Code != protocol.ProtocolErrorCodeInvalidRequest {
		t.Fatalf("invalid safe timeout failure: %#v, %v", failure, err)
	}
}

func TestCloseBetweenAcceptAndRegistrationStartsNoHandler(t *testing.T) {
	accepted := make(chan struct{})
	closeStarted := make(chan struct{})
	release := make(chan struct{})
	handlerCalled := make(chan struct{}, 1)
	srv, path := startTestServer(t, func(c *Config) {
		c.afterAccept = func() {
			close(accepted)
			<-release
		}
		c.onClosing = func() { close(closeStarted) }
		c.Handler = func(context.Context, []byte) ([]byte, error) {
			handlerCalled <- struct{}{}
			return []byte(`{"schemaVersion":"1"}`), nil
		}
	})
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	<-accepted
	closed := make(chan error, 1)
	go func() { closed <- srv.Close() }()
	<-closeStarted
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	_, _ = conn.Write([]byte(`{"schemaVersion":"1"}` + "\n"))
	select {
	case <-handlerCalled:
		t.Fatal("handler started after Close began")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestCrashRestartRecoversOnlyOwnedStaleSocket(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-crash-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	cfg := Config{RuntimeDir: filepath.Join(root, "run"), Handler: echoHandler}
	first, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	stalePath := first.Path()
	if err := first.crashForTest(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stalePath); err != nil {
		t.Fatalf("crash did not leave a stale socket: %v", err)
	}
	restarted, err := New(cfg)
	if err != nil {
		t.Fatalf("owned stale socket was not recovered: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = restarted.Serve(ctx) }()
	defer restarted.Close()
	_ = exchange(t, restarted.Path(), validActionFrame(t))
}

func TestActiveSocketAndStaleReplacementAreNeverRemoved(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-active-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	cfg := Config{RuntimeDir: filepath.Join(root, "run"), Handler: echoHandler}
	active, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if _, err := New(cfg); err == nil {
		t.Fatal("second server replaced an active listener")
	}
	if info, err := os.Lstat(active.Path()); err != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("active socket was removed: %v", err)
	}
	if err := active.crashForTest(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(active.Path()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(active.Path(), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(cfg); err == nil {
		t.Fatal("stale ownership record authorized a replacement inode")
	}
	if data, err := os.ReadFile(active.Path()); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement was removed: %q, %v", data, err)
	}
}

func TestImmutableLockRecordIsNeverTruncated(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-lock-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "run")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(dir, "."+DefaultSocketName+".lock")
	const sentinel = "immutable-lock-inode\n"
	if err := os.WriteFile(lockPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Config{RuntimeDir: dir, Handler: echoHandler})
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	data, err := os.ReadFile(lockPath)
	if err != nil || string(data) != sentinel {
		t.Fatalf("lock record was mutated: %q, %v", data, err)
	}
}

func TestCopiedLockAndJournalCannotDeleteActiveListener(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-copy-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "run")
	cfg := Config{RuntimeDir: dir, Handler: echoHandler, IOTimeout: 50 * time.Millisecond}
	active, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = active.Serve(ctx) }()
	_ = exchange(t, active.Path(), validActionFrame(t))

	lockPath := filepath.Join(dir, "."+DefaultSocketName+".lock")
	if err := os.Remove(lockPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, []byte("copied lock\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if replacement, err := New(cfg); err == nil {
		_ = replacement.Close()
		t.Fatal("copied lock and journal deleted an active listener")
	}
	_ = exchange(t, active.Path(), validActionFrame(t))
}

func TestLifecycleChallengeIsPeerBoundAndNeverReachesHandler(t *testing.T) {
	called := make(chan struct{}, 1)
	_, path := startTestServer(t, func(c *Config) {
		c.IOTimeout = 50 * time.Millisecond
		c.Handler = func(context.Context, []byte) ([]byte, error) {
			called <- struct{}{}
			return []byte(`{"schemaVersion":"1"}`), nil
		}
	})
	if result := probeGuard(path, 50*time.Millisecond); result != probeActive {
		t.Fatalf("same-UID challenge was not answered: %v", result)
	}
	select {
	case <-called:
		t.Fatal("internal challenge reached the normal request handler")
	default:
	}

	_, mismatchedPath := startTestServer(t, func(c *Config) {
		c.IOTimeout = 50 * time.Millisecond
		c.peerUID = func(net.Conn) (uint32, error) {
			return uint32(os.Getuid()) + 1, nil
		}
	})
	if result := probeGuard(mismatchedPath, 50*time.Millisecond); result == probeActive {
		t.Fatal("challenge ignored peer UID")
	}
}

type relayProcess struct {
	command *exec.Cmd
	done    <-chan struct{}
	waitErr *error
}

func startRelayHelper(t *testing.T, upstream, target, mode string) relayProcess {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestSocketRelayHelper$")
	command.Env = append(os.Environ(),
		"PALONEXUS_SOCKET_RELAY_UPSTREAM="+upstream,
		"PALONEXUS_SOCKET_RELAY_TARGET="+target,
		"PALONEXUS_SOCKET_RELAY_MODE="+mode,
	)
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	command.Stderr = os.Stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	ready, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || ready != "ready\n" {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("relay helper did not become ready: %q, %v", ready, err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = command.Wait()
		close(done)
	}()
	t.Cleanup(func() {
		select {
		case <-done:
			return
		default:
			_ = command.Process.Kill()
			<-done
		}
	})
	return relayProcess{command: command, done: done, waitErr: &waitErr}
}

func TestSocketRelayHelper(t *testing.T) {
	upstreamPath := os.Getenv("PALONEXUS_SOCKET_RELAY_UPSTREAM")
	if upstreamPath == "" {
		return
	}
	targetPath := os.Getenv("PALONEXUS_SOCKET_RELAY_TARGET")
	upstream, err := net.Dial("unix", upstreamPath)
	if err != nil {
		t.Fatal(err)
	}
	defer upstream.Close()
	if os.Getenv("PALONEXUS_SOCKET_RELAY_MODE") == "replace" {
		if err := os.Remove(targetPath); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.ListenUnix(
		"unix", &net.UnixAddr{Name: targetPath, Net: "unix"},
	)
	if err != nil {
		t.Fatal(err)
	}
	listener.SetUnlinkOnClose(false)
	defer listener.Close()
	fmt.Println("ready")
	downstream, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer downstream.Close()
	done := make(chan struct{}, 2)
	relay := func(dst io.Writer, src io.Reader) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go relay(upstream, downstream)
	go relay(downstream, upstream)
	<-done
}

func TestLifecycleChallengeRejectsCrossProcessRelay(t *testing.T) {
	_, upstream := startTestServer(t, func(c *Config) {
		c.IOTimeout = 200 * time.Millisecond
	})
	root, err := os.MkdirTemp("", "pn-relay-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	proxy := filepath.Join(root, "proxy.sock")
	startRelayHelper(t, upstream, proxy, "proxy")
	if result := probeGuard(proxy, 200*time.Millisecond); result != probeAmbiguous {
		t.Fatalf("relayed challenge result %v, want ambiguous", result)
	}
}

func TestStageProofRejectsCrossProcessRelayAndPreservesDecoy(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-stage-relay-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	var stagePath string
	var relay relayProcess
	_, err = New(Config{
		RuntimeDir: filepath.Join(root, "run"),
		Handler:    echoHandler,
		IOTimeout:  200 * time.Millisecond,
		afterStageBind: func(path string) {
			stagePath = path
			relay = startRelayHelper(t, path, path, "replace")
		},
	})
	if err == nil {
		t.Fatal("cross-process stage relay was accepted")
	}
	if relay.command == nil {
		t.Fatalf("stage relay was not started: %v", err)
	}
	select {
	case <-relay.done:
		if *relay.waitErr != nil {
			t.Fatalf("relay helper did not observe the real listener closing: %v", *relay.waitErr)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("real staged listener remained open after rejected proof")
	}
	info, statErr := os.Lstat(stagePath)
	if statErr != nil {
		t.Fatalf("decoy was removed: %v", statErr)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("preserved decoy mode %v, want socket", info.Mode())
	}
}

func TestStagePermissionChangeNeverFollowsSymlink(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-stage-mode-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	target := filepath.Join(root, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0o640); err != nil {
		t.Fatal(err)
	}
	var stagePath string
	_, err = New(Config{
		RuntimeDir: filepath.Join(root, "run"),
		Handler:    echoHandler,
		beforeStageChmod: func(path string) {
			stagePath = path
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
		},
	})
	if err == nil {
		t.Fatal("symlink replacement was accepted")
	}
	info, statErr := os.Stat(target)
	if statErr != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("symlink target mode changed: %v, %v", info, statErr)
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil || string(data) != "unchanged" {
		t.Fatalf("symlink target content changed: %q, %v", data, readErr)
	}
	replacement, linkErr := os.Lstat(stagePath)
	if linkErr != nil || replacement.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replacement was not preserved: %v", linkErr)
	}
}

func TestLifecycleCrashHelper(t *testing.T) {
	point := os.Getenv("PALONEXUS_SOCKET_CRASH_POINT")
	if point == "" {
		return
	}
	cfg := Config{
		RuntimeDir: os.Getenv("PALONEXUS_SOCKET_CRASH_DIR"),
		Handler:    echoHandler,
		IOTimeout:  100 * time.Millisecond,
		fault: func(actual string) {
			if actual == point {
				process, _ := os.FindProcess(os.Getpid())
				_ = process.Kill()
			}
		},
	}
	_, _ = New(cfg)
	t.Fatalf("fault point %q was not reached", point)
}

func runLifecycleCrash(t *testing.T, point, dir string) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestLifecycleCrashHelper$")
	command.Env = append(os.Environ(),
		"PALONEXUS_SOCKET_CRASH_POINT="+point,
		"PALONEXUS_SOCKET_CRASH_DIR="+dir,
	)
	if err := command.Run(); err == nil {
		t.Fatalf("helper was not killed at %s", point)
	}
}

func TestPreparingRecoveryPreservesUnprovenReplacementSocket(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-preparing-replace-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "run")
	runLifecycleCrash(t, "after_preparing", dir)
	dirFile, _, err := prepareRuntimeDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	record, err := readLifecycleRecord(dirFile, "."+DefaultSocketName+".lifecycle")
	_ = dirFile.Close()
	if err != nil || record == nil || record.Phase != "preparing" {
		t.Fatalf("missing preparing record: %#v, %v", record, err)
	}
	stagePath := filepath.Join(dir, record.StageName)
	replacement, err := net.ListenUnix("unix", &net.UnixAddr{Name: stagePath, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	replacement.SetUnlinkOnClose(false)
	defer replacement.Close()
	_, err = New(Config{RuntimeDir: dir, Handler: echoHandler})
	if !errors.Is(err, ErrRecoveryAmbiguous) {
		t.Fatalf("unproven preparing node was not ambiguous: %v", err)
	}
	info, statErr := os.Lstat(stagePath)
	if statErr != nil || info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("unproven replacement was removed: %v", statErr)
	}
}

func TestLifecycleTempReplacementIsPreservedAsAmbiguous(t *testing.T) {
	root, err := os.MkdirTemp("", "pn-temp-replace-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	dir := filepath.Join(root, "run")
	runLifecycleCrash(t, "journal_after_write", dir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var tempPath string
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".lifecycle.tmp-") {
			tempPath = filepath.Join(dir, entry.Name())
			break
		}
	}
	if tempPath == "" {
		t.Fatal("crash did not leave a lifecycle temp")
	}
	if err := os.Remove(tempPath); err != nil {
		t.Fatal(err)
	}
	const sentinel = "attacker replacement"
	if err := os.WriteFile(tempPath, []byte(sentinel), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = New(Config{RuntimeDir: dir, Handler: echoHandler})
	if !errors.Is(err, ErrRecoveryAmbiguous) {
		t.Fatalf("unproven lifecycle temp was not ambiguous: %v", err)
	}
	data, readErr := os.ReadFile(tempPath)
	if readErr != nil || string(data) != sentinel {
		t.Fatalf("lifecycle temp replacement changed: %q, %v", data, readErr)
	}
}

func TestSIGKILLAtLifecycleBoundariesRecoversOnReopen(t *testing.T) {
	points := []struct {
		name      string
		ambiguous bool
	}{
		{"journal_before_write", true},
		{"journal_after_write", true},
		{"journal_after_fsync", true},
		{"journal_before_rename", true},
		{"journal_after_rename", false},
		{"journal_after_dirsync", false},
		{"after_preparing", false},
		{"after_bind", true},
		{"after_stage_chmod", true},
		{"after_stage_proof", true},
		{"before_publish", false},
		{"after_publish", false},
		{"after_publish_dirsync", false},
	}
	for _, point := range points {
		t.Run(point.name, func(t *testing.T) {
			root, err := os.MkdirTemp("", "pn-kill-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(root)
			dir := filepath.Join(root, "run")
			runLifecycleCrash(t, point.name, dir)
			cfg := Config{
				RuntimeDir: dir, Handler: echoHandler,
				IOTimeout: 100 * time.Millisecond,
			}
			restarted, err := New(cfg)
			if err != nil {
				if restarted != nil {
					_ = restarted.Close()
				}
				if !errors.Is(err, ErrRecoveryAmbiguous) {
					t.Fatalf("unsafe recovery failure after %s: %v", point.name, err)
				}
				return
			}
			if point.ambiguous {
				_ = restarted.Close()
				t.Fatalf("unproven artifact was automatically removed after %s", point.name)
			}
			if err := restarted.Close(); err != nil {
				t.Fatalf("cleanup failed after %s: %v", point.name, err)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				switch entry.Name() {
				case "." + DefaultSocketName + ".lock",
					"." + DefaultSocketName + ".lifecycle":
					continue
				}
				t.Fatalf("orphan artifact after %s: %s", point.name, entry.Name())
			}
		})
	}
}
