package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestStoreAtomicRoundTripAndBinding(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "state")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Tenant: "tenant-a", Account: "user-a"}
	payload := json.RawMessage(`{"decision":"deny","sequence":1}`)
	if err := store.Put(context.Background(), binding, "reconciliation", payload); err != nil {
		t.Fatal(err)
	}
	payload[13] = 'X'
	got, err := store.Get(context.Background(), binding, "reconciliation")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"decision":"deny","sequence":1}` {
		t.Fatalf("Get = %s", got)
	}
	if _, err := store.Get(context.Background(), Binding{Tenant: "tenant-b", Account: "user-a"}, "reconciliation"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant Get = %v", err)
	}
	assertMode(t, root, 0o700)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.Name() == ".lock" {
			continue
		}
		assertMode(t, filepath.Join(root, entry.Name()), 0o600)
	}
}

func TestStoreRejectsSymlinkRootAndRecord(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(base, "root-link")
	if err := os.Symlink(target, rootLink); err != nil {
		t.Fatal(err)
	}
	if _, err := New(rootLink); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("New(symlink) = %v, want ErrUnsafePath", err)
	}

	root := filepath.Join(base, "state")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Tenant: "tenant", Account: "account"}
	recordPath, err := store.recordPath(binding, "session")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, recordPath); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), binding, "session", json.RawMessage(`{}`)); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Put(symlink) = %v, want ErrUnsafePath", err)
	}
}

func TestStoreRejectsPermissiveAndNonRegularRecord(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "state")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Tenant: "tenant", Account: "account"}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := store.Put(context.Background(), binding, "session", json.RawMessage(`{}`)); !errors.Is(err, ErrUnsafePermissions) {
		t.Fatalf("Put with permissive root = %v", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	recordPath, err := store.recordPath(binding, "session")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(recordPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(context.Background(), binding, "session"); !errors.Is(err, ErrUnsafePath) {
		t.Fatalf("Get(directory) = %v, want ErrUnsafePath", err)
	}
}

func TestStoreCorruptionAndUnknownVersionFailClosed(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "state")
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Tenant: "tenant", Account: "account"}
	recordPath, err := store.recordPath(binding, "session")
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range [][]byte{
		[]byte(`not-json`),
		[]byte(`{"version":2,"tenant":"tenant","account":"account","kind":"session","payload":{}}`),
		[]byte(`{"version":1,"tenant":"other","account":"account","kind":"session","payload":{}}`),
	} {
		if err := os.WriteFile(recordPath, content, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Get(context.Background(), binding, "session"); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Get(%s) = %v, want ErrCorrupt", content, err)
		}
	}
}

func TestStoreRejectsSensitiveOrInvalidPayloadWithoutReflection(t *testing.T) {
	t.Parallel()
	store, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "raw-secret-token"
	for _, payload := range []json.RawMessage{
		json.RawMessage(`{"access_token":"` + secret + `"}`),
		json.RawMessage(`{"nested":{"refreshToken":"` + secret + `"}}`),
		json.RawMessage(`not-json-` + secret),
	} {
		err := store.Put(context.Background(), Binding{Tenant: "tenant", Account: "account"}, "session", payload)
		if !errors.Is(err, ErrUnsafePayload) {
			t.Fatalf("Put(%s) = %v, want ErrUnsafePayload", payload, err)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error reflected secret: %v", err)
		}
	}
}

func TestDeleteAccountRemovesOnlyBoundRecords(t *testing.T) {
	t.Parallel()
	store, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	left := Binding{Tenant: "tenant-a", Account: "user"}
	right := Binding{Tenant: "tenant-b", Account: "user"}
	for _, binding := range []Binding{left, right} {
		if err := store.Put(ctx, binding, "session", json.RawMessage(`{"status":"active"}`)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.DeleteAccount(ctx, left); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Get(ctx, left, "session"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted Get = %v", err)
	}
	if _, err := store.Get(ctx, right, "session"); err != nil {
		t.Fatalf("other tenant record removed: %v", err)
	}
}

func TestConcurrentStoresProduceWholeRecords(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "state")
	first, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	binding := Binding{Tenant: "tenant", Account: "account"}
	left := json.RawMessage(`{"writer":"left","padding":"` + strings.Repeat("a", 4096) + `"}`)
	right := json.RawMessage(`{"writer":"right","padding":"` + strings.Repeat("b", 4096) + `"}`)

	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		for index, candidate := range []struct {
			store   *Store
			payload json.RawMessage
		}{{first, left}, {second, right}} {
			wg.Add(1)
			go func(index int, candidate struct {
				store   *Store
				payload json.RawMessage
			}) {
				defer wg.Done()
				if err := candidate.store.Put(context.Background(), binding, "session", candidate.payload); err != nil {
					t.Errorf("writer %d: %v", index, err)
				}
			}(index, candidate)
		}
	}
	wg.Wait()
	got, err := first.Get(context.Background(), binding, "session")
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Writer  string `json:"writer"`
		Padding string `json:"padding"`
	}
	if err := json.Unmarshal(got, &decoded); err != nil {
		t.Fatalf("concurrent write produced invalid JSON: %v", err)
	}
	if (decoded.Writer != "left" || decoded.Padding != strings.Repeat("a", 4096)) &&
		(decoded.Writer != "right" || decoded.Padding != strings.Repeat("b", 4096)) {
		t.Fatal("concurrent write produced a torn record")
	}
}

func TestCancelledContextFailsClosed(t *testing.T) {
	t.Parallel()
	store, err := New(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Put(ctx, Binding{Tenant: "tenant", Account: "account"}, "session", json.RawMessage(`{}`)); !errors.Is(err, context.Canceled) {
		t.Fatalf("Put = %v, want context.Canceled", err)
	}
}

func TestStoreSerializesAtomicWritesAcrossProcesses(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	if _, err := New(root); err != nil {
		t.Fatal(err)
	}
	type child struct {
		command *exec.Cmd
		output  *bytes.Buffer
	}
	var commands []child
	for index := 0; index < 8; index++ {
		command := exec.Command(os.Args[0], "-test.run=^TestStateStoreProcessHelper$")
		command.Env = append(os.Environ(),
			"PALONEXUS_STATE_HELPER=1",
			"PALONEXUS_STATE_ROOT="+root,
			"PALONEXUS_STATE_WRITER="+string(rune('a'+index)),
		)
		output := new(bytes.Buffer)
		command.Stdout = output
		command.Stderr = output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		commands = append(commands, child{command: command, output: output})
	}
	for _, child := range commands {
		if err := child.command.Wait(); err != nil {
			t.Fatalf("child failed: %v: %s", err, child.output)
		}
	}
	store, err := New(root)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(context.Background(), Binding{Tenant: "tenant", Account: "account"}, "session")
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]string
	if err := json.Unmarshal(got, &decoded); err != nil || len(decoded["writer"]) != 1 {
		t.Fatalf("cross-process result = %s, %v", got, err)
	}
}

func TestStateStoreProcessHelper(t *testing.T) {
	if os.Getenv("PALONEXUS_STATE_HELPER") != "1" {
		t.Skip("helper process")
	}
	store, err := New(os.Getenv("PALONEXUS_STATE_ROOT"))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(map[string]string{"writer": os.Getenv("PALONEXUS_STATE_WRITER")})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put(
		context.Background(),
		Binding{Tenant: "tenant", Account: "account"},
		"session",
		payload,
	); err != nil {
		t.Fatal(err)
	}
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s mode = %o, want %o", filepath.Base(path), got, want)
	}
}
