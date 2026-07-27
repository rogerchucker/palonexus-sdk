// SPDX-License-Identifier: MIT
//go:build unix

package socket

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
	"golang.org/x/sys/unix"
)

func echoHandler(_ context.Context, request []byte) ([]byte, error) {
	var value map[string]any
	if err := json.Unmarshal(request, &value); err != nil {
		return nil, err
	}
	return json.Marshal(value)
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
	if string(got) != `{"schemaVersion":"1","value":"ok"}`+"\n" {
		t.Fatalf("unexpected response %q", got)
	}
}

func TestHandlerResponseIsOneCompactPhysicalLine(t *testing.T) {
	_, path := startTestServer(t, func(c *Config) {
		c.Handler = func(context.Context, []byte) ([]byte, error) {
			return []byte("{\n  \"schemaVersion\": \"1\",\n  \"value\": \"ok\"\n}"), nil
		}
	})
	got := exchange(t, path, `{"schemaVersion":"1"}`+"\n")
	if string(got) != `{"schemaVersion":"1","value":"ok"}`+"\n" {
		t.Fatalf("response is not compact NDJSON: %q", got)
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
	response := exchange(t, path, `{"schemaVersion":"1"}`+"\n")
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
			if got := exchange(t, path, `{"schemaVersion":"1"}`+"\n"); len(got) == 0 {
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
	response := exchange(t, path, `{"schemaVersion":"1"}`+"\n")
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
	_ = exchange(t, path, `{"schemaVersion":"1"}`+"\n")
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
	if err := srv.Close(); err == nil {
		t.Fatal("runtime replacement was not reported")
	}
	if data, err := os.ReadFile(replacement); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement changed: %q, %v", data, err)
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
	response := exchange(t, path, `{"schemaVersion":"1"}`+"\n")
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
	response := exchange(t, path, `{"schemaVersion":"1"}`+"\n")
	if time.Since(start) > time.Second {
		t.Fatal("uncooperative handler held the connection")
	}
	var failure protocol.ProtocolError
	if json.Unmarshal(response, &failure) != nil || !failure.Retryable {
		t.Fatalf("expected retryable structured failure: %s", response)
	}
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
	_ = exchange(t, restarted.Path(), `{"schemaVersion":"1"}`+"\n")
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
