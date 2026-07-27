// SPDX-License-Identifier: MIT
package normalize

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

func loadVector(t *testing.T, name string, target any) {
	t.Helper()
	document, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "protocol", "test-vectors", "canonicalization", name+".json",
	))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(document, target); err != nil {
		t.Fatal(err)
	}
}

func TestEveryApplicableCommittedCanonicalizationVector(t *testing.T) {
	t.Run("duplicate keys", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Raw []string `json:"rawJson"`
			} `json:"inputs"`
		}
		loadVector(t, "duplicate-keys", &vector)
		for _, raw := range vector.Inputs.Raw {
			if _, err := CanonicalJSON([]byte(raw)); err == nil {
				t.Fatal("accepted committed duplicate-key vector")
			}
		}
	})

	t.Run("numeric portability", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Accepted []string `json:"acceptedJson"`
				Rejected []string `json:"rejectedJson"`
			} `json:"inputs"`
			Expected struct {
				Canonical []string `json:"canonical"`
			} `json:"expected"`
		}
		loadVector(t, "numeric-portability", &vector)
		for index, raw := range vector.Inputs.Accepted {
			got, err := CanonicalJSON([]byte(raw))
			if err != nil || string(got) != vector.Expected.Canonical[index] {
				t.Fatalf("numeric vector mismatch: %s, %v", got, err)
			}
		}
		for _, raw := range vector.Inputs.Rejected {
			if _, err := CanonicalJSON([]byte(raw)); err == nil {
				t.Fatal("accepted rejected numeric vector")
			}
		}
	})

	t.Run("missing versus null", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Missing string `json:"missingJson"`
				Null    string `json:"nullJson"`
			} `json:"inputs"`
			Expected struct {
				Missing string `json:"missingCanonical"`
				Null    string `json:"nullCanonical"`
			} `json:"expected"`
		}
		loadVector(t, "missing-vs-null", &vector)
		missing, err1 := CanonicalJSON([]byte(vector.Inputs.Missing))
		nullValue, err2 := CanonicalJSON([]byte(vector.Inputs.Null))
		if err1 != nil || err2 != nil || string(missing) != vector.Expected.Missing ||
			string(nullValue) != vector.Expected.Null || string(missing) == string(nullValue) {
			t.Fatal("missing/null committed vector mismatch")
		}
	})

	t.Run("paths", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Cases []struct {
					Path string `json:"path"`
					Cwd  string `json:"cwd"`
				} `json:"cases"`
				Collisions []struct {
					Left  string `json:"left"`
					Right string `json:"right"`
					Cwd   string `json:"cwd"`
				} `json:"collisionPairs"`
			} `json:"inputs"`
			Expected struct {
				Canonical []string `json:"canonical"`
			} `json:"expected"`
		}
		loadVector(t, "path-traversal-symlink-policy", &vector)
		for index, input := range vector.Inputs.Cases {
			got, err := Path(input.Path, input.Cwd)
			if err != nil || got.SensitiveExecution() != vector.Expected.Canonical[index] {
				t.Fatal("path committed vector mismatch")
			}
		}
		for _, pair := range vector.Inputs.Collisions {
			left, err1 := Path(pair.Left, pair.Cwd)
			right, err2 := Path(pair.Right, pair.Cwd)
			if err1 != nil || err2 != nil || left.Resource != right.Resource {
				t.Fatal("path collision committed vector mismatch")
			}
		}
	})

	t.Run("IDNA", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Accepted []string `json:"accepted"`
				Rejected []string `json:"rejected"`
			} `json:"inputs"`
			Expected struct {
				Canonical []string `json:"canonical"`
			} `json:"expected"`
		}
		loadVector(t, "idna2008-a-label", &vector)
		for index, raw := range vector.Inputs.Accepted {
			got, err := URL(raw, nil)
			if err != nil || got.SensitiveExecution() != vector.Expected.Canonical[index] {
				t.Fatal("IDNA committed vector mismatch")
			}
		}
		for _, raw := range vector.Inputs.Rejected {
			if _, err := URL(raw, nil); err == nil {
				t.Fatal("accepted rejected IDNA vector")
			}
		}
	})

	t.Run("MCP", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Left   string `json:"leftJson"`
				Right  string `json:"rightJson"`
				Server string `json:"server"`
				Tool   string `json:"tool"`
			} `json:"inputs"`
			Expected struct {
				Resource string `json:"leftResource"`
			} `json:"expected"`
		}
		loadVector(t, "mcp-nested-json", &vector)
		left, err1 := MCPJSON(vector.Inputs.Server, vector.Inputs.Tool, []byte(vector.Inputs.Left))
		right, err2 := MCPJSON(vector.Inputs.Server, vector.Inputs.Tool, []byte(vector.Inputs.Right))
		if err1 != nil || err2 != nil || string(left.Resource) != vector.Expected.Resource ||
			left.Resource != right.Resource {
			t.Fatal("MCP committed vector mismatch")
		}
	})

	t.Run("shell", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Names  []string `json:"additionalSensitiveNames"`
				First  string   `json:"first"`
				Second string   `json:"second"`
			} `json:"inputs"`
			Expected struct {
				First  any `json:"first"`
				Second any `json:"second"`
			} `json:"expected"`
		}
		loadVector(t, "shell-redaction-collision-resistance", &vector)
		first, err1 := Shell(vector.Inputs.First, vector.Inputs.Names)
		second, err2 := Shell(vector.Inputs.Second, vector.Inputs.Names)
		wantFirst, _ := canonicalNative(vector.Expected.First)
		wantSecond, _ := canonicalNative(vector.Expected.Second)
		if err1 != nil || err2 != nil || string(first.Resource) != string(wantFirst) ||
			string(second.Resource) != string(wantSecond) || first.Resource == second.Resource {
			t.Fatal("shell committed vector mismatch")
		}
	})

	t.Run("URL normalization", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Accepted   []string `json:"accepted"`
				Rejected   []string `json:"rejected"`
				Collisions []struct {
					Left  string `json:"left"`
					Right string `json:"right"`
				} `json:"collisionPairs"`
			} `json:"inputs"`
			Expected struct {
				Canonical  []string `json:"canonical"`
				Collisions []struct {
					Equal bool `json:"equal"`
				} `json:"collisions"`
			} `json:"expected"`
		}
		loadVector(t, "url-normalization-policy", &vector)
		for index, raw := range vector.Inputs.Accepted {
			got, err := URL(raw, nil)
			if err != nil {
				t.Fatal(err)
			}
			var safe struct {
				URL string `json:"url"`
			}
			if json.Unmarshal([]byte(got.Resource), &safe) != nil ||
				safe.URL != vector.Expected.Canonical[index] {
				t.Fatal("URL committed vector mismatch")
			}
		}
		for _, raw := range vector.Inputs.Rejected {
			if _, err := URL(raw, nil); err == nil {
				t.Fatal("accepted rejected URL vector")
			}
		}
		for index, pair := range vector.Inputs.Collisions {
			left, err1 := URL(pair.Left, nil)
			right, err2 := URL(pair.Right, nil)
			equal := err1 == nil && err2 == nil && left.Resource == right.Resource
			if equal != vector.Expected.Collisions[index].Equal {
				t.Fatal("URL collision committed vector mismatch")
			}
		}
	})

	t.Run("URL credential binding", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				First  string `json:"first"`
				Second string `json:"second"`
			} `json:"inputs"`
			Expected struct {
				URLs []string `json:"diagnosticUrls"`
			} `json:"expected"`
		}
		loadVector(t, "url-credential-binding", &vector)
		first, err1 := URL(vector.Inputs.First, nil)
		second, err2 := URL(vector.Inputs.Second, nil)
		var firstSafe, secondSafe struct {
			URL string `json:"url"`
		}
		_ = json.Unmarshal([]byte(first.Resource), &firstSafe)
		_ = json.Unmarshal([]byte(second.Resource), &secondSafe)
		if err1 != nil || err2 != nil || firstSafe.URL != vector.Expected.URLs[0] ||
			secondSafe.URL != vector.Expected.URLs[1] || first.Resource == second.Resource {
			t.Fatal("URL credential committed vector mismatch")
		}
	})

	t.Run("Unicode", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Left      string `json:"leftJson"`
				Right     string `json:"rightJson"`
				Scalar    string `json:"scalarOrderJson"`
				Cwd       string `json:"cwd"`
				PathNFC   string `json:"pathNfc"`
				PathNFD   string `json:"pathNfd"`
				ShellNFC  string `json:"shellNfc"`
				ShellNFD  string `json:"shellNfd"`
				URLNFC    string `json:"urlNfc"`
				URLNFD    string `json:"urlNfd"`
				MCPLeft   string `json:"mcpLeftJson"`
				MCPRight  string `json:"mcpRightJson"`
				MCPServer string `json:"mcpServer"`
				MCPTool   string `json:"mcpTool"`
			} `json:"inputs"`
			Expected struct {
				Canonical string   `json:"canonicalUtf8"`
				Scalar    string   `json:"scalarOrderCanonical"`
				Paths     []string `json:"pathExecutions"`
				Shells    []string `json:"shellExecutions"`
				URLs      []string `json:"urlExecutions"`
				MCP       []string `json:"mcpResources"`
			} `json:"expected"`
		}
		loadVector(t, "unicode-equivalence", &vector)
		left, err1 := CanonicalJSON([]byte(vector.Inputs.Left))
		right, err2 := CanonicalJSON([]byte(vector.Inputs.Right))
		if err1 != nil || err2 != nil || string(left) != vector.Expected.Canonical ||
			!reflect.DeepEqual(left, right) {
			t.Fatal("Unicode committed vector mismatch")
		}
		scalar, err := CanonicalJSON([]byte(vector.Inputs.Scalar))
		if err != nil || string(scalar) != vector.Expected.Scalar {
			t.Fatal("Unicode scalar-order vector mismatch")
		}
		pathNFC, err1 := Path(vector.Inputs.PathNFC, vector.Inputs.Cwd)
		pathNFD, err2 := Path(vector.Inputs.PathNFD, vector.Inputs.Cwd)
		if err1 != nil || err2 != nil ||
			pathNFC.SensitiveExecution() != vector.Expected.Paths[0] ||
			pathNFD.SensitiveExecution() != vector.Expected.Paths[1] ||
			pathNFC.Resource != pathNFD.Resource {
			t.Fatal("Unicode path vector mismatch")
		}
		shellNFC, err1 := Shell(vector.Inputs.ShellNFC, nil)
		shellNFD, err2 := Shell(vector.Inputs.ShellNFD, nil)
		if err1 != nil || err2 != nil ||
			shellNFC.SensitiveExecution() != vector.Expected.Shells[0] ||
			shellNFD.SensitiveExecution() != vector.Expected.Shells[1] ||
			shellNFC.Resource != shellNFD.Resource {
			t.Fatal("Unicode shell vector mismatch")
		}
		urlNFC, err1 := URL(vector.Inputs.URLNFC, nil)
		urlNFD, err2 := URL(vector.Inputs.URLNFD, nil)
		if err1 != nil || err2 != nil ||
			urlNFC.SensitiveExecution() != vector.Expected.URLs[0] ||
			urlNFD.SensitiveExecution() != vector.Expected.URLs[1] ||
			urlNFC.Resource != urlNFD.Resource {
			t.Fatal("Unicode URL vector mismatch")
		}
		mcpNFC, err1 := MCPJSON(
			vector.Inputs.MCPServer, vector.Inputs.MCPTool, []byte(vector.Inputs.MCPLeft),
		)
		mcpNFD, err2 := MCPJSON(
			vector.Inputs.MCPServer, vector.Inputs.MCPTool, []byte(vector.Inputs.MCPRight),
		)
		if err1 != nil || err2 != nil ||
			string(mcpNFC.Resource) != vector.Expected.MCP[0] ||
			string(mcpNFD.Resource) != vector.Expected.MCP[1] ||
			mcpNFC.Resource != mcpNFD.Resource {
			t.Fatal("Unicode MCP vector mismatch")
		}
	})

	t.Run("resource preimage", func(t *testing.T) {
		var vector struct {
			Inputs struct {
				Target struct {
					Kind     protocol.TargetKind `json:"kind"`
					Service  string              `json:"service"`
					Resource protocol.SafeText   `json:"resource"`
				} `json:"target"`
			} `json:"inputs"`
			Expected struct {
				Hash protocol.SHA256Digest `json:"resourceHash"`
			} `json:"expected"`
		}
		loadVector(t, "resource-preimage-binding", &vector)
		preparedValue := Prepared{Resource: vector.Inputs.Target.Resource}
		target, err := preparedValue.Target(vector.Inputs.Target.Kind, vector.Inputs.Target.Service)
		if err != nil || target.ResourceHash != vector.Expected.Hash {
			t.Fatal("resource preimage committed vector mismatch")
		}
	})

	t.Run("scope-only vector deliberately outside normalizer", func(t *testing.T) {
		var vector struct {
			Case string `json:"case"`
		}
		loadVector(t, "adapter-client-trust-boundary", &vector)
		if vector.Case != "adapter-client-trust-boundary" {
			t.Fatal("scope-only vector mapping drifted")
		}
		// Client/authoritative scope hashing is not a Task 3 normalizer API.
		// Its committed vector is executed by the protocol/Python suites.
	})
}
