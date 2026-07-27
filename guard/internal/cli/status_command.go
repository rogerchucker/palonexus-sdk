// SPDX-License-Identifier: MIT

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type runtimeStatus struct {
	Authenticated bool
	Ready         bool
}

var statusRuntime = defaultRuntimeStatus

func runStatusCommand(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "--json" {
		return invalidArguments(stderr, "status")
	}
	status := statusRuntime(context.Background())
	document := struct {
		Name            string `json:"name"`
		Version         string `json:"version"`
		ProtocolVersion string `json:"protocolVersion"`
		Authenticated   bool   `json:"authenticated"`
		Ready           bool   `json:"ready"`
		LoginRequired   bool   `json:"loginRequired"`
	}{
		Name: "palonexus", Version: Version, ProtocolVersion: "1.0",
		Authenticated: status.Authenticated, Ready: status.Ready,
		LoginRequired: !status.Authenticated,
	}
	data, err := json.Marshal(document)
	if err != nil {
		_, _ = io.WriteString(stderr, "palonexus: status unavailable\n")
		return 1
	}
	_, _ = fmt.Fprintf(stdout, "%s\n", data)
	return 0
}

func defaultRuntimeStatus(ctx context.Context) runtimeStatus {
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return runtimeStatus{}
	}
	return runtimeStatus{
		Authenticated: hasLiveSession(filepath.Join(home, ".palonexus", "state")),
		Ready:         daemonReady(ctx, filepath.Join(home, ".palonexus", "run", "guard.sock")),
	}
}

func daemonReady(ctx context.Context, path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
		return false
	}
	dialer := net.Dialer{Timeout: 250 * time.Millisecond}
	connection, err := dialer.DialContext(ctx, "unix", path)
	if err != nil {
		return false
	}
	return connection.Close() == nil
}

func hasLiveSession(root string) bool {
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) > 4096 {
		return false
	}
	now := time.Now()
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 ||
			!strings.HasPrefix(entry.Name(), "state-") || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
		if readErr != nil || len(data) > 64*1024 {
			continue
		}
		var record struct {
			Version  int `json:"version"`
			Metadata struct {
				Kind       string    `json:"kind"`
				ExpiresAt  time.Time `json:"expiresAt"`
				Tombstoned bool      `json:"tombstoned"`
			} `json:"metadata"`
		}
		if json.Unmarshal(data, &record) == nil && record.Version == 1 &&
			record.Metadata.Kind == "session" && !record.Metadata.Tombstoned &&
			record.Metadata.ExpiresAt.After(now) {
			return true
		}
	}
	return false
}
