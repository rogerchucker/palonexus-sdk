// SPDX-License-Identifier: MIT
//go:build darwin || linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/decision"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/keystore"
	"github.com/rogerchucker/palonexus-sdk/guard/internal/state"
	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

func TestBuiltBinaryDaemonLifecycleAndOneShot(t *testing.T) {
	if runtime.GOOS == "darwin" {
		t.Skip("Darwin exact-descriptor daemon launch is unsupported and fails closed")
	}
	var calls atomic.Int32
	var outage atomic.Bool
	var selected atomic.Value
	selected.Store(protocol.DecisionOutcomeAllow)
	decisionServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		if outage.Load() {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		var action protocol.ActionRequest
		if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer access-token" ||
			json.NewDecoder(request.Body).Decode(&action) != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		scope, err := decision.ClientScopeHash(action)
		if err != nil {
			http.Error(w, "invalid", http.StatusBadRequest)
			return
		}
		outcome := selected.Load().(protocol.DecisionOutcome)
		now := time.Now().UTC()
		value := protocol.AuthorizationDecision{
			SchemaVersion: "1", RequestID: action.RequestID,
			DecisionID:    "dec_01J5ABCDEFGHJKMNPQRSTVWXY0",
			CorrelationID: action.CorrelationID, Outcome: outcome,
			ReasonCode: "policy_result", DisplayReason: "Request evaluated.",
			ClientScopeHash:        scope,
			AuthoritativeScopeHash: "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
			PolicyRevision:         "policy_42", ServerTime: protocol.RFC3339Timestamp(now.Format(time.RFC3339Nano)),
			ExpiresAt: protocol.RFC3339Timestamp(now.Add(5 * time.Minute).Format(time.RFC3339Nano)),
			AuditRef:  "audit_01J5ABCDEFGHJKMNPQRSTVWXY0",
			Cache:     protocol.CacheDirective{Cacheable: false},
		}
		if outcome == protocol.DecisionOutcomeApprovalRequired {
			value.Approval = &protocol.ApprovalSummary{
				ApprovalID: "apr_01J5ABCDEFGHJKMNPQRSTVWXY0",
				Status:     protocol.ApprovalStatusPending,
				ExpiresAt:  protocol.RFC3339Timestamp(now.Add(10 * time.Minute).Format(time.RFC3339Nano)),
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(value)
	}))
	defer decisionServer.Close()

	binary := buildBinary(t)
	root, err := os.MkdirTemp("", "pn-main-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, _ = filepath.EvalSymlinks(root)
	configPath := filepath.Join(root, "config.json")
	caPath := filepath.Join(root, "ca.pem")
	originalCA := pem.EncodeToMemory(&pem.Block{
		Type: "CERTIFICATE", Bytes: decisionServer.Certificate().Raw,
	})
	if err := os.WriteFile(caPath, originalCA, 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(root, "credential.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf(`{
	  "decision_endpoint":%q,
	  "oidc_issuer":"http://127.0.0.1:65533",
	  "trusted_ca_file":%q,
	  "local_test_mode":true,
	  "tenant_id":"tenant-a",
	  "account_id":"account-a",
	  "client_id":"codex",
	  "state_dir":%q,
	  "credential_service":"palonexus-test",
	  "test_credential_root":%q,
	  "test_credential_key_file":%q,
	  "routes":[{"target":"api.example.com","decision_endpoint":%q}]
	}`, decisionServer.URL, caPath, filepath.Join(root, "state"),
		filepath.Join(root, "credentials"), keyPath, decisionServer.URL)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	runtimeDir := filepath.Join(root, "run")
	environment := append(os.Environ(),
		"PALONEXUS_CONFIG="+configPath,
		"PALONEXUS_RUNTIME_DIR="+runtimeDir,
		"PALONEXUS_ALLOW_LOCAL_TEST_MODE=1",
	)
	t.Setenv("PALONEXUS_CONFIG", configPath)
	t.Setenv("PALONEXUS_RUNTIME_DIR", runtimeDir)
	t.Setenv("PALONEXUS_ALLOW_LOCAL_TEST_MODE", "1")
	if _, err := productionManager(); err != nil {
		t.Fatalf("production manager: %v", err)
	}
	run := func(input string, arguments ...string) (int, string, string) {
		command := exec.Command(binary, arguments...)
		command.Env = environment
		command.Stdin = strings.NewReader(input)
		var stdout, stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		err := command.Run()
		if err == nil {
			return 0, stdout.String(), stderr.String()
		}
		var exit *exec.ExitError
		if !strings.Contains(err.Error(), "exit status") || !errorAs(err, &exit) {
			t.Fatalf("%v", err)
		}
		return exit.ExitCode(), stdout.String(), stderr.String()
	}
	if code, stdout, stderr := run("", "guard", "start"); code != 0 ||
		stdout != "guard started\n" || stderr != "" {
		log, logErr := os.ReadFile(filepath.Join(runtimeDir, "daemon.log"))
		entries, _ := os.ReadDir(runtimeDir)
		t.Fatalf("start: %d %q %q log=%q logErr=%v entries=%v",
			code, stdout, stderr, log, logErr, entries)
	}
	t.Cleanup(func() { _, _, _ = run("", "guard", "stop") })
	if code, stdout, stderr := run("", "status"); code != 0 ||
		stdout != "guard running\n" || stderr != "" {
		t.Fatalf("status: %d %q %q", code, stdout, stderr)
	}
	action, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "protocol", "test-vectors", "action", "valid", "file-write.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var actionEnvelope protocol.ActionRequest
	if err := json.Unmarshal(action, &actionEnvelope); err != nil {
		t.Fatal(err)
	}
	actionEnvelope.Target.Service = "api.example.com"
	action, err = json.Marshal(actionEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, action); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := run(compact.String()+"\n", "guard", "check", "--one-shot")
	if code != 0 || stderr != "" {
		t.Fatalf("one-shot: %d %q %q", code, stdout, stderr)
	}
	failure, err := protocol.ParseProtocolError([]byte(stdout))
	if err != nil || failure.Code != protocol.ProtocolErrorCodeAuthenticationFailed {
		t.Fatalf("one-shot response: %s, %v", stdout, err)
	}
	code, stdout, stderr = run(compact.String()+"\n", "guard", "check")
	if code != 0 || stderr != "" {
		t.Fatalf("daemon check: %d %q %q", code, stdout, stderr)
	}
	daemonFailure, err := protocol.ParseProtocolError([]byte(stdout))
	if err != nil || daemonFailure.Code != failure.Code {
		t.Fatalf("daemon/one-shot mismatch: %s vs %s, %v", stdout, failure.Code, err)
	}

	seedBuiltBinarySession(
		t, filepath.Join(root, "state"), filepath.Join(root, "credentials"),
		bytes.Repeat([]byte{0x42}, 32),
	)
	for _, outcome := range []protocol.DecisionOutcome{
		protocol.DecisionOutcomeAllow,
		protocol.DecisionOutcomeDeny,
		protocol.DecisionOutcomeApprovalRequired,
	} {
		selected.Store(outcome)
		for _, arguments := range [][]string{
			{"guard", "check", "--one-shot"},
			{"guard", "check"},
		} {
			before := calls.Load()
			code, stdout, stderr = run(compact.String()+"\n", arguments...)
			if code != 0 || stderr != "" {
				t.Fatalf("%s %v: %d %q %q", outcome, arguments, code, stdout, stderr)
			}
			got, parseErr := protocol.ParseAuthorizationDecision([]byte(stdout))
			if parseErr != nil || got.Outcome != outcome {
				t.Fatalf("%s %v response: %s, %v calls=%d", outcome, arguments, stdout, parseErr, calls.Load())
			}
			if delta := calls.Load() - before; delta != 1 {
				t.Fatalf("%s %v decision calls = %d", outcome, arguments, delta)
			}
		}
	}
	replacementPEM := append(append([]byte(nil), originalCA...), '\n')
	if err := os.WriteFile(caPath, replacementPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := run("", "status"); code != 1 || stdout != "" ||
		stderr != "palonexus: guard: unavailable\n" {
		t.Fatalf("changed CA accepted stale daemon: %d %q %q", code, stdout, stderr)
	}
	if err := os.WriteFile(caPath, originalCA, 0o600); err != nil {
		t.Fatal(err)
	}
	outage.Store(true)
	for _, arguments := range [][]string{{"guard", "check", "--one-shot"}, {"guard", "check"}} {
		before := calls.Load()
		code, stdout, stderr = run(compact.String()+"\n", arguments...)
		if code != 0 || stderr != "" {
			t.Fatalf("outage %v: %d %q %q", arguments, code, stdout, stderr)
		}
		outage, parseErr := protocol.ParseProtocolError([]byte(stdout))
		if parseErr != nil || outage.Code != protocol.ProtocolErrorCodeAuthorizationUnavailable {
			t.Fatalf("outage %v response: %s, %v", arguments, stdout, parseErr)
		}
		if delta := calls.Load() - before; delta != 1 {
			t.Fatalf("outage %v accepted attempts = %d", arguments, delta)
		}
	}
	if code, stdout, stderr := run("", "guard", "stop"); code != 0 ||
		stdout != "guard stopped\n" || stderr != "" {
		t.Fatalf("stop: %d %q %q", code, stdout, stderr)
	}
}

func TestBuiltBinaryDarwinDaemonLaunchFailsClosed(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-specific descriptor execution capability")
	}
	binary := buildBinary(t)
	root, err := os.MkdirTemp("", "pn-darwin-main-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, _ = filepath.EvalSymlinks(root)
	keyPath := filepath.Join(root, "credential.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x42}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(root, "config.json")
	config := fmt.Sprintf(`{
	  "decision_endpoint":"http://127.0.0.1:65534",
	  "oidc_issuer":"http://127.0.0.1:65533",
	  "local_test_mode":true,
	  "tenant_id":"tenant-a","account_id":"account-a","client_id":"codex",
	  "state_dir":%q,"credential_service":"palonexus-test",
	  "test_credential_root":%q,"test_credential_key_file":%q,
	  "routes":[{"target":"api.example.com","decision_endpoint":"http://127.0.0.1:65534"}]
	}`, filepath.Join(root, "state"), filepath.Join(root, "credentials"), keyPath)
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(binary, "guard", "start")
	command.Env = append(os.Environ(),
		"PALONEXUS_CONFIG="+configPath,
		"PALONEXUS_RUNTIME_DIR="+filepath.Join(root, "run"),
		"PALONEXUS_ALLOW_LOCAL_TEST_MODE=1",
	)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err = command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 || stdout.Len() != 0 ||
		stderr.String() != "palonexus: guard: unavailable\n" {
		t.Fatalf("Darwin daemon launch: %v %q %q", err, stdout.String(), stderr.String())
	}
}

func seedBuiltBinarySession(
	t *testing.T,
	stateRoot string,
	credentialRoot string,
	key []byte,
) {
	t.Helper()
	metadata, err := state.New(stateRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer metadata.Close()
	backend, err := keystore.NewEncryptedFileBackend(keystore.EncryptedFileOptions{
		Root: credentialRoot, Key: key, EnableForTesting: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := keystore.New("palonexus-test", backend)
	if err != nil {
		t.Fatal(err)
	}
	defer credentials.Close()
	sessionID := "session_01J5ABCDEFGHJKMNPQRSTVWXY0"
	expires := time.Now().Add(time.Hour).UTC()
	if err := metadata.PutMetadata(
		context.Background(), state.Binding{Tenant: "tenant-a", Account: "account-a"},
		state.Metadata{
			Kind: state.KindSession, SessionID: sessionID, ExpiresAt: expires, Generation: 1,
		},
	); err != nil {
		t.Fatal(err)
	}
	document, _ := json.Marshal(map[string]any{
		"SessionID": sessionID, "Subject": "subject-a", "Nonce": "nonce",
		"AccessToken": "access-token", "RefreshToken": "refresh-token", "ExpiresAt": expires,
	})
	accountHash := sha256.Sum256([]byte("account-a"))
	credentialKey := keystore.Key{
		Tenant:  "tenant-a",
		Account: "oidc-session-" + base64.RawURLEncoding.EncodeToString(accountHash[:]) + "-" + sessionID,
	}
	if err := credentials.Put(context.Background(), credentialKey, document); err != nil {
		t.Fatal(err)
	}
}

func TestBuiltBinaryInvalidConfigurationFailsClosed(t *testing.T) {
	binary := buildBinary(t)
	command := exec.Command(binary, "guard", "start")
	command.Env = append(os.Environ(),
		"PALONEXUS_CONFIG="+filepath.Join(t.TempDir(), "missing.json"),
		"PALONEXUS_RUNTIME_DIR="+filepath.Join(t.TempDir(), "run"),
	)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	var exit *exec.ExitError
	if !errorAs(err, &exit) || exit.ExitCode() != 1 || stdout.Len() != 0 ||
		stderr.String() != "palonexus: guard: unavailable\n" {
		t.Fatalf("invalid config: %v %q %q", err, stdout.String(), stderr.String())
	}
}

func buildBinary(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "palonexus")
	command := exec.Command("go", "build", "-o", path, ".")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build: %v: %s", err, output)
	}
	return path
}

func errorAs(err error, target any) bool {
	return err != nil && errors.As(err, target)
}
