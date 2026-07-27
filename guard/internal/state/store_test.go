//go:build darwin || linux

package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestTypedMetadataRoundTripsForEachAllowlistedKind(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	binding := Binding{Tenant: "租户", Account: "account:a"}
	records := []Metadata{
		{Kind: KindRouting, RouteID: "route-primary"},
		{
			Kind:      KindSession,
			SessionID: "session_01ARZ3NDEKTSV4RRFFQ69G5FAV",
			ExpiresAt: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
		},
		{
			Kind:             KindReconciliation,
			ReconciliationID: "recon_01ARZ3NDEKTSV4RRFFQ69G5FAV",
			ReferenceHash:    "sha256:" + strings.Repeat("a", 64),
		},
	}
	for _, record := range records {
		if err := store.PutMetadata(context.Background(), binding, record); err != nil {
			t.Fatalf("PutMetadata(%s): %v", record.Kind, err)
		}
		got, err := store.GetMetadata(context.Background(), binding, record.Kind)
		if err != nil {
			t.Fatalf("GetMetadata(%s): %v", record.Kind, err)
		}
		if got != record {
			t.Fatalf("round trip = %#v, want %#v", got, record)
		}
	}
}

func TestTypedMetadataRejectsSecretAndRawInputByConstruction(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	binding := Binding{Tenant: "tenant", Account: "account"}
	rejected := []Metadata{
		{Kind: KindRouting, RouteID: "value=raw-secret"},
		{Kind: KindRouting, RouteID: "session/raw-tool-input"},
		{Kind: KindSession, SessionID: "api_key_raw-secret", ExpiresAt: time.Now().UTC()},
		{Kind: KindSession, SessionID: "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.signature", ExpiresAt: time.Now().UTC()},
		{Kind: KindReconciliation, ReconciliationID: "neutral-raw-command", ReferenceHash: "raw-secret"},
		{Kind: KindRouting, RouteID: "route-abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnop"},
	}
	for _, metadata := range rejected {
		err := store.PutMetadata(context.Background(), binding, metadata)
		if !errors.Is(err, ErrUnsafePayload) {
			t.Fatalf("PutMetadata(%#v) = %v, want ErrUnsafePayload", metadata, err)
		}
		if strings.Contains(err.Error(), "raw-secret") {
			t.Fatalf("error reflected secret: %v", err)
		}
	}
}

func TestBindingPathsAreInjectiveAndDoNotExposeUnicode(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	bindings := []Binding{
		{Tenant: "a:b", Account: "c"},
		{Tenant: "a", Account: "b:c"},
		{Tenant: "租户", Account: "δοκιμή"},
	}
	seen := map[string]struct{}{}
	for _, binding := range bindings {
		name, err := store.recordName(binding, KindRouting)
		if err != nil {
			t.Fatal(err)
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("record name collision: %q", name)
		}
		seen[name] = struct{}{}
		if binding.Tenant == "租户" &&
			(strings.Contains(name, binding.Tenant) || strings.Contains(name, binding.Account)) {
			t.Fatalf("record name exposed binding: %q", name)
		}
	}
}

func TestStoreMigratesBenignVersionZeroMetadataToCurrentVersion(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	binding := Binding{Tenant: "tenant", Account: "account"}
	name, err := store.recordName(binding, KindRouting)
	if err != nil {
		t.Fatal(err)
	}
	writeAnchoredTestRecord(t, store, name, []byte(
		`{"version":0,"tenant":"tenant","account":"account","metadata":{"kind":"routing","routeId":"route-primary"}}`,
	))
	got, err := store.GetMetadata(context.Background(), binding, KindRouting)
	if err != nil || got.RouteID != "route-primary" {
		t.Fatalf("migration = %#v, %v", got, err)
	}
	onDisk := readAnchoredTestRecord(t, store, name)
	if !strings.Contains(string(onDisk), `"version":1`) {
		t.Fatalf("migration was not durably rewritten: %s", onDisk)
	}
}

func TestUnknownVersionAndLegacyRawPayloadFailClosed(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	binding := Binding{Tenant: "tenant", Account: "account"}
	name, err := store.recordName(binding, KindRouting)
	if err != nil {
		t.Fatal(err)
	}
	for _, document := range []string{
		`{"version":2,"tenant":"tenant","account":"account","metadata":{"kind":"routing","routeId":"route-primary"}}`,
		`{"version":0,"tenant":"tenant","account":"account","payload":{"value":"raw-tool-input"}}`,
	} {
		writeAnchoredTestRecord(t, store, name, []byte(document))
		if _, err := store.GetMetadata(context.Background(), binding, KindRouting); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("GetMetadata(%s) = %v, want ErrCorrupt", document, err)
		}
	}
}

func TestStoreAnchorsRootAndRejectsSymlinkAncestorsAndRecords(t *testing.T) {
	t.Parallel()
	base := canonicalTempDir(t)
	realParent := filepath.Join(base, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkParent := filepath.Join(base, "link")
	if err := os.Symlink(realParent, symlinkParent); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(symlinkParent, "state")); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("New through symlink ancestor = %v", err)
	}

	root := filepath.Join(realParent, "state")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	binding := Binding{Tenant: "tenant", Account: "account"}
	name, err := store.recordName(binding, KindRouting)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "outside"), filepath.Join(root, name)); err != nil {
		t.Fatal(err)
	}
	if err := store.PutMetadata(context.Background(), binding, Metadata{Kind: KindRouting, RouteID: "route-primary"}); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("PutMetadata over symlink = %v", err)
	}
}

func TestStoreRejectsWritableAncestor(t *testing.T) {
	t.Parallel()
	base := canonicalTempDir(t)
	writable := filepath.Join(base, "writable")
	if err := os.Mkdir(writable, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(writable, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := New(filepath.Join(writable, "state")); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("New through writable ancestor = %v", err)
	}
}

func TestStoreRequiresUserOnlyDirectoryAndFileModes(t *testing.T) {
	t.Parallel()
	base := canonicalTempDir(t)
	permissive := filepath.Join(base, "permissive")
	if err := os.Mkdir(permissive, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := New(permissive); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("New permissive root = %v", err)
	}
	store, err := New(filepath.Join(base, "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	binding := Binding{Tenant: "tenant", Account: "account"}
	if err := store.PutMetadata(
		context.Background(),
		binding,
		Metadata{Kind: KindRouting, RouteID: "route-primary"},
	); err != nil {
		t.Fatal(err)
	}
	name, err := store.recordName(binding, KindRouting)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(base, "state", name), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetMetadata(context.Background(), binding, KindRouting); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("GetMetadata permissive file = %v", err)
	}
}

func TestRootRenameSwapCannotRedirectAnchoredWrites(t *testing.T) {
	t.Parallel()
	base := canonicalTempDir(t)
	root := filepath.Join(base, "state")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	anchored := filepath.Join(base, "anchored")
	if err := os.Rename(root, anchored); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.PutMetadata(context.Background(), Binding{Tenant: "tenant", Account: "account"}, Metadata{Kind: KindRouting, RouteID: "route-primary"}); err != nil {
		t.Fatal(err)
	}
	newEntries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(newEntries) != 0 {
		t.Fatal("anchored store wrote into attacker replacement root")
	}
	oldEntries, err := os.ReadDir(anchored)
	if err != nil || len(oldEntries) == 0 {
		t.Fatalf("anchored directory not written: %v", err)
	}
}

func TestLogoutDeletesCorruptScopedRecordsAndIgnoresJunk(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	binding := Binding{Tenant: "tenant", Account: "account"}
	scoped, err := store.recordName(binding, KindSession)
	if err != nil {
		t.Fatal(err)
	}
	writeAnchoredTestRecord(t, store, scoped, []byte(`corrupt`))
	writeAnchoredTestRecord(t, store, "unrelated-junk", []byte(`do-not-touch`))
	if err := store.DeleteAccount(context.Background(), binding); err != nil {
		t.Fatal(err)
	}
	if _, err := store.GetMetadata(context.Background(), binding, KindSession); !errors.Is(err, ErrNotFound) {
		t.Fatalf("scoped corrupt record survived: %v", err)
	}
	if got := readAnchoredTestRecord(t, store, "unrelated-junk"); string(got) != "do-not-touch" {
		t.Fatalf("junk changed: %q", got)
	}
}

func TestCleanupTempsUsesIndependentDirectoryOffset(t *testing.T) {
	store := newTestStore(t)
	impl := store.impl.(*unixStore)
	first := ".state-tmp-11111111111111111111111111111111"
	second := ".state-tmp-22222222222222222222222222222222"
	writeAnchoredTestRecord(t, store, first, []byte("first"))
	if err := impl.cleanupTemps(); err != nil {
		t.Fatal(err)
	}
	writeAnchoredTestRecord(t, store, second, []byte("second"))
	if err := impl.cleanupTemps(); err != nil {
		t.Fatal(err)
	}
	if err := unix.Fstatat(impl.rootFD, second, &unix.Stat_t{}, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(err, unix.ENOENT) {
		t.Fatalf("later orphan survived cleanup: %v", err)
	}
}

func TestStoreSerializesAcrossProcesses(t *testing.T) {
	root := filepath.Join(canonicalTempDir(t), "state")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	var commands []*exec.Cmd
	var outputs []*bytes.Buffer
	for index := 0; index < 6; index++ {
		command := exec.Command(os.Args[0], "-test.run=^TestStateProcessHelper$")
		output := new(bytes.Buffer)
		command.Stdout = output
		command.Stderr = output
		command.Env = append(os.Environ(),
			"PALONEXUS_STATE_HELPER=1",
			"PALONEXUS_STATE_ROOT="+root,
			"PALONEXUS_STATE_ROUTE=route-"+string(rune('a'+index)),
		)
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, command)
		outputs = append(outputs, output)
	}
	for index, command := range commands {
		if err := command.Wait(); err != nil {
			t.Fatalf("helper %d: %v\n%s", index, err, outputs[index].String())
		}
	}
	store, err = New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	got, err := store.GetMetadata(context.Background(), Binding{Tenant: "tenant", Account: "account"}, KindRouting)
	if err != nil || !strings.HasPrefix(got.RouteID, "route-") {
		t.Fatalf("cross-process record = %#v, %v", got, err)
	}
}

func TestAtomicWriteFaultBoundariesAndIndeterminateDurability(t *testing.T) {
	t.Parallel()
	binding := Binding{Tenant: "tenant", Account: "account"}
	metadata := Metadata{Kind: KindRouting, RouteID: "route-primary"}
	injected := errors.New("injected")
	for _, stage := range []string{"write", "file-sync", "rename"} {
		store := newTestStore(t)
		impl := store.impl.(*unixStore)
		switch stage {
		case "write":
			impl.faults.write = func(*os.File, []byte) (int, error) { return 0, injected }
		case "file-sync":
			impl.faults.syncFile = func(*os.File) error { return injected }
		case "rename":
			impl.faults.rename = func(int, string, int, string) error { return injected }
		}
		if err := store.PutMetadata(context.Background(), binding, metadata); err == nil ||
			errors.Is(err, ErrDurabilityIndeterminate) {
			t.Fatalf("%s failure = %v, want definite precommit failure", stage, err)
		}
		impl.faults = unixFaults{}
		if _, err := store.GetMetadata(context.Background(), binding, KindRouting); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s failure committed a record: %v", stage, err)
		}
	}

	store := newTestStore(t)
	impl := store.impl.(*unixStore)
	impl.faults.syncDir = func(int) error { return injected }
	err := store.PutMetadata(context.Background(), binding, metadata)
	if !errors.Is(err, ErrDurabilityIndeterminate) {
		t.Fatalf("post-rename fsync = %v, want ErrDurabilityIndeterminate", err)
	}
	impl.faults = unixFaults{}
	got, err := store.GetMetadata(context.Background(), binding, KindRouting)
	if err != nil || got != metadata {
		t.Fatalf("indeterminate write did not expose committed record: %#v, %v", got, err)
	}
}

func TestDeleteAccountCancellationAndFaultBoundaries(t *testing.T) {
	binding := Binding{Tenant: "tenant", Account: "account"}
	putAll := func(t *testing.T, store *Store) {
		t.Helper()
		for _, metadata := range []Metadata{
			{Kind: KindRouting, RouteID: "route-primary"},
			{Kind: KindSession, SessionID: "session_01ARZ3NDEKTSV4RRFFQ69G5FAV", ExpiresAt: time.Now().UTC().Add(time.Hour)},
			{Kind: KindReconciliation, ReconciliationID: "recon_01ARZ3NDEKTSV4RRFFQ69G5FAV", ReferenceHash: "sha256:" + strings.Repeat("a", 64)},
		} {
			if err := store.PutMetadata(context.Background(), binding, metadata); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("canceled-after-flock", func(t *testing.T) {
		store := newTestStore(t)
		putAll(t, store)
		ctx, cancel := context.WithCancel(context.Background())
		impl := store.impl.(*unixStore)
		impl.faults.afterLock = cancel
		for attempt := 0; attempt < 2; attempt++ {
			if err := store.DeleteAccount(ctx, binding); !errors.Is(err, context.Canceled) {
				t.Fatalf("attempt %d = %v", attempt, err)
			}
		}
		impl.faults = unixFaults{}
		if _, err := store.GetMetadata(context.Background(), binding, KindRouting); err != nil {
			t.Fatalf("canceled delete mutated state: %v", err)
		}
	})
	t.Run("unlink-failure", func(t *testing.T) {
		store := newTestStore(t)
		putAll(t, store)
		injected := errors.New("unlink")
		impl := store.impl.(*unixStore)
		impl.faults.unlink = func(int, string) error { return injected }
		if err := store.DeleteAccount(context.Background(), binding); !errors.Is(err, injected) {
			t.Fatalf("unlink failure = %v", err)
		}
	})
	t.Run("late-cancel-finishes", func(t *testing.T) {
		store := newTestStore(t)
		putAll(t, store)
		ctx, cancel := context.WithCancel(context.Background())
		impl := store.impl.(*unixStore)
		calls := 0
		impl.faults.unlink = func(fd int, name string) error {
			calls++
			err := unlinkRegularAt(fd, name)
			if calls == 1 {
				cancel()
			}
			return err
		}
		if err := store.DeleteAccount(ctx, binding); err != nil || calls != 3 {
			t.Fatalf("late cancellation = %v, calls=%d", err, calls)
		}
	})
	t.Run("later-unlink-indeterminate", func(t *testing.T) {
		store := newTestStore(t)
		putAll(t, store)
		impl := store.impl.(*unixStore)
		calls := 0
		impl.faults.unlink = func(fd int, name string) error {
			calls++
			if calls == 2 {
				return errors.New("second unlink")
			}
			return unlinkRegularAt(fd, name)
		}
		if err := store.DeleteAccount(context.Background(), binding); !errors.Is(err, ErrDurabilityIndeterminate) {
			t.Fatalf("later unlink = %v", err)
		}
	})
	t.Run("directory-sync-indeterminate", func(t *testing.T) {
		store := newTestStore(t)
		putAll(t, store)
		impl := store.impl.(*unixStore)
		impl.faults.syncDir = func(int) error { return errors.New("sync") }
		if err := store.DeleteAccount(context.Background(), binding); !errors.Is(err, ErrDurabilityIndeterminate) {
			t.Fatalf("sync failure = %v", err)
		}
	})
}

func TestCancellationBeforeAndAfterCommitBoundary(t *testing.T) {
	t.Parallel()
	binding := Binding{Tenant: "tenant", Account: "account"}
	metadata := Metadata{Kind: KindRouting, RouteID: "route-primary"}

	store := newTestStore(t)
	impl := store.impl.(*unixStore)
	ctx, cancel := context.WithCancel(context.Background())
	impl.faults.beforeRename = cancel
	if err := store.PutMetadata(ctx, binding, metadata); !errors.Is(err, context.Canceled) {
		t.Fatalf("precommit cancellation = %v", err)
	}
	impl.faults = unixFaults{}
	if _, err := store.GetMetadata(context.Background(), binding, KindRouting); !errors.Is(err, ErrNotFound) {
		t.Fatalf("precommit cancellation wrote a record: %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	impl.faults.afterRename = cancel
	if err := store.PutMetadata(ctx, binding, metadata); err != nil {
		t.Fatalf("completed commit reported late cancellation: %v", err)
	}
	impl.faults = unixFaults{}
	if _, err := store.GetMetadata(context.Background(), binding, KindRouting); err != nil {
		t.Fatalf("postcommit record missing: %v", err)
	}
}

func TestStateProcessHelper(t *testing.T) {
	if os.Getenv("PALONEXUS_STATE_HELPER") != "1" {
		t.Skip("helper")
	}
	store, err := New(os.Getenv("PALONEXUS_STATE_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.PutMetadata(
		context.Background(),
		Binding{Tenant: "tenant", Account: "account"},
		Metadata{Kind: KindRouting, RouteID: os.Getenv("PALONEXUS_STATE_ROUTE")},
	); err != nil {
		t.Fatal(err)
	}
}

func newTestStore(t *testing.T) *Store {
	t.Helper()
	store, err := New(filepath.Join(canonicalTempDir(t), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := store.Close(); err != nil {
			t.Error(err)
		}
	})
	return store
}

func canonicalTempDir(t *testing.T) string {
	t.Helper()
	path, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func writeAnchoredTestRecord(t *testing.T, store *Store, name string, document []byte) {
	t.Helper()
	if err := store.writeRawForTesting(name, document); err != nil {
		t.Fatal(err)
	}
}

func readAnchoredTestRecord(t *testing.T, store *Store, name string) []byte {
	t.Helper()
	document, err := store.readRawForTesting(name)
	if err != nil {
		t.Fatal(err)
	}
	var compact json.RawMessage = document
	return compact
}

func (s *Store) writeRawForTesting(name string, document []byte) error {
	impl := s.impl.(*unixStore)
	return impl.withLock(context.Background(), func() error {
		fd, err := unix.Openat(impl.rootFD, name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_TRUNC|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
		if err != nil {
			return ErrUnsafePath
		}
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()
		if _, err := file.Write(document); err != nil {
			return ErrUnsafePath
		}
		if err := file.Sync(); err != nil {
			return ErrUnsafePath
		}
		return syncRoot(impl.rootFD)
	})
}

func (s *Store) readRawForTesting(name string) ([]byte, error) {
	impl := s.impl.(*unixStore)
	var result []byte
	err := impl.withLock(context.Background(), func() error {
		fd, err := unix.Openat(impl.rootFD, name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), name)
		defer file.Close()
		result, err = io.ReadAll(file)
		return err
	})
	return result, err
}

func TestSessionTransactionSerializesAcrossStoreInstancesAndPreservesRouting(t *testing.T) {
	root := filepath.Join(canonicalTempDir(t), "state")
	first, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	binding := Binding{Tenant: "tenant", Account: "account"}
	if err := first.PutMetadata(context.Background(), binding, Metadata{Kind: KindRouting, RouteID: "route-default"}); err != nil {
		t.Fatal(err)
	}
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		done <- first.WithSessionTransaction(context.Background(), binding, func(Metadata, bool) (*Metadata, error) {
			close(entered)
			<-release
			next := Metadata{Kind: KindSession, SessionID: "session_00000000000000000000000000", Generation: 1, ExpiresAt: time.Now().Add(time.Hour)}
			return &next, nil
		})
	}()
	<-entered
	secondEntered := make(chan struct{})
	secondDone := make(chan struct{})
	go func() {
		_ = second.WithSessionTransaction(context.Background(), binding, func(Metadata, bool) (*Metadata, error) {
			close(secondEntered)
			return nil, nil
		})
		close(secondDone)
	}()
	select {
	case <-secondEntered:
		t.Fatal("second store entered transaction before first released")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second transaction did not acquire lock")
	}
	<-secondDone
	if _, err := first.GetMetadata(context.Background(), binding, KindRouting); err != nil {
		t.Fatalf("session transaction damaged routing metadata: %v", err)
	}
}
