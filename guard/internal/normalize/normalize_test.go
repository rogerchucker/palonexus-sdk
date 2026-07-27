// SPDX-License-Identifier: MIT
package normalize

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
)

func TestPathMatchesProtocolVector(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path, cwd, want string
	}{
		{"src/../deploy/./production.yaml", "/workspace/project", "/workspace/project/deploy/production.yaml"},
		{"../../shared/policy.rego", "/workspace/project", "/shared/policy.rego"},
		{"/workspace/link/../secret.txt", "/workspace/project", "/workspace/secret.txt"},
		{"Cafe\u0301.txt", "/workspace", "/workspace/Café.txt"},
	}
	for _, tc := range cases {
		got, err := Path(tc.path, tc.cwd)
		if err != nil || got.Execution != tc.want || string(got.Resource) != "path:"+tc.want {
			t.Fatalf("Path(%q): got %#v, %v; want %q", tc.path, got, err, tc.want)
		}
	}
}

func TestPathRejectsAmbiguousAndMalformedValuesWithoutReflection(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ path, cwd string }{
		{"secret\x00value", "/workspace"},
		{`C:\secret-value`, "/workspace"},
		{"secret-value", "relative"},
		{string([]byte{0xff}), "/workspace"},
	} {
		_, err := Path(tc.path, tc.cwd)
		if err == nil {
			t.Fatalf("accepted malformed path")
		}
		if strings.Contains(err.Error(), "secret-value") {
			t.Fatalf("error reflected raw path: %v", err)
		}
	}
}

func TestURLMatchesProtocolVectorAndKeepsExecutionSecretPrivate(t *testing.T) {
	t.Parallel()
	got, err := URL("HTTPS://Example.COM:443/a/../b?z=last&token=raw-secret&a=2&a=1#fragment", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Execution != "https://example.com/b?a=2&a=1&token=raw-secret&z=last" {
		t.Fatalf("unexpected execution URL: %#v", got.Execution)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", got, got), "raw-secret") {
		t.Fatal("log-safe prepared representation exposed execution secret")
	}
	resource := string(got.Resource)
	if strings.Contains(resource, "raw-secret") || !strings.Contains(resource, "token=%5BREDACTED%5D") {
		t.Fatalf("resource is not safely redacted: %s", resource)
	}
	gotAgain, err := URL(got.Execution.(string), nil)
	if err != nil || gotAgain.Resource != got.Resource || gotAgain.Execution != got.Execution {
		t.Fatalf("URL normalization is not idempotent: %#v, %v", gotAgain, err)
	}
}

func TestNumericPortabilityVector(t *testing.T) {
	t.Parallel()
	accepted := map[string]string{
		"1.2300": "1.23",
		"1e3":    "1000",
		"-0.000": "0",
		"1e-3":   "0.001",
	}
	for raw, want := range accepted {
		got, err := CanonicalJSON([]byte(raw))
		if err != nil || string(got) != want {
			t.Fatalf("CanonicalJSON(%s): got %s, %v; want %s", raw, got, err, want)
		}
	}
	rejected := []string{
		"NaN", "1e309", "1e-309",
		"1." + strings.Repeat("2", 129),
		"1e999999999999999999999999999999999999",
	}
	for _, raw := range rejected {
		if _, err := CanonicalJSON([]byte(raw)); err == nil {
			t.Fatalf("accepted non-portable number: %s", raw)
		}
	}
}

func TestURLRejectsProtocolVectorFailures(t *testing.T) {
	t.Parallel()
	values := []string{
		"https://user:raw-secret@example.com/",
		"https://example.com./",
		"https://bad_host.example/",
		"https://127.1/",
		"https://[2001:db8::1]/",
		"https:\\\\example.com\\path",
		"https://example.com/%zz/raw-secret",
	}
	for _, value := range values {
		if _, err := URL(value, nil); err == nil {
			t.Fatalf("accepted invalid URL")
		} else if strings.Contains(err.Error(), "raw-secret") {
			t.Fatalf("error reflected URL secret: %v", err)
		}
	}
}

func TestShellRedactsSecretsAndBindsRawCommand(t *testing.T) {
	t.Parallel()
	left, err := Shell(`curl -H "Authorization: Bearer raw-secret" "https://example.com/run?token=raw-secret" --password raw-secret`, nil)
	if err != nil {
		t.Fatal(err)
	}
	right, err := Shell(`curl -H "Authorization: Bearer other-secret" "https://example.com/run?token=other-secret" --password other-secret`, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(left.Resource), "raw-secret") {
		t.Fatalf("resource leaked shell secret: %s", left.Resource)
	}
	if left.Resource == right.Resource {
		t.Fatal("different commands collided after redaction")
	}
	if left.Execution != `curl -H "Authorization: Bearer raw-secret" "https://example.com/run?token=raw-secret" --password raw-secret` {
		t.Fatal("prepared execution was not retained privately")
	}
}

func TestShellMatchesCollisionResistanceVector(t *testing.T) {
	t.Parallel()
	got, err := Shell(
		"deploy --tenant-secret alpha TENANT_SECRET=bravo "+
			"--tenant-secret=charlie --token mandatory",
		[]string{"tenant_secret"},
	)
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"commandHash":"sha256:cb48c8d9b796578f503e3643fcb84944aaa2d85294ba8281d6e4867ca6d46010","tokens":["deploy","--tenant-secret","[REDACTED]","TENANT_SECRET=[REDACTED]","--tenant-secret=[REDACTED]","--token","[REDACTED]"]}`
	if string(got.Resource) != want {
		t.Fatalf("shell vector mismatch: %s", got.Resource)
	}
}

func TestShellTokenizerDoesNotInterpretCommentsOrOperators(t *testing.T) {
	t.Parallel()
	got, err := Shell(`echo # literal && printf ok`, nil)
	if err != nil {
		t.Fatal(err)
	}
	var resource struct {
		Tokens []string `json:"tokens"`
	}
	if err := json.Unmarshal([]byte(got.Resource), &resource); err != nil {
		t.Fatal(err)
	}
	want := []string{"echo", "#", "literal", "&&", "printf", "ok"}
	if fmt.Sprint(resource.Tokens) != fmt.Sprint(want) {
		t.Fatalf("shell input was semantically parsed: got %v, want %v", resource.Tokens, want)
	}
}

func TestMCPMatchesNestedJSONVectorAndRejectsDuplicateNormalizedKeys(t *testing.T) {
	t.Parallel()
	left := []byte(`{"labels":["security","agent"],"issue":{"title":"Cafe\u0301","priority":1.0}}`)
	right := []byte(`{"issue":{"priority":1,"title":"Café"},"labels":["security","agent"]}`)
	a, err := MCPJSON("github", "issues.create", left)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MCPJSON("github", "issues.create", right)
	if err != nil {
		t.Fatal(err)
	}
	const want = "mcp:github/issues.create#sha256:d7a5ab6559d5c4c9c8214b30cb0197d0a21dd025bc0d51e6d9886c8ac1b5e4af"
	if string(a.Resource) != want || a.Resource != b.Resource {
		t.Fatalf("MCP vector mismatch: %q / %q", a.Resource, b.Resource)
	}
	if _, err := MCPJSON("github", "issues.create", []byte(`{"e\u0301":1,"é":2}`)); err == nil {
		t.Fatal("accepted duplicate NFC keys")
	}
}

func TestUnicodeVectorUsesNFCAndScalarOrder(t *testing.T) {
	t.Parallel()
	canonical, err := CanonicalJSON([]byte("{\"\\ud800\\udc00\":2,\"\\ue000\":1}"))
	if err != nil {
		t.Fatal(err)
	}
	if string(canonical) != "{\"\":1,\"𐀀\":2}" {
		t.Fatalf("wrong scalar order or encoding: %s", canonical)
	}
	left, err := CanonicalJSON([]byte(`{"e\u0301":"Cafe\u0301","z":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if string(left) != `{"z":1,"é":"Café"}` {
		t.Fatalf("NFC mismatch: %s", left)
	}
	pinned151, err := CanonicalJSON([]byte(`{"value":"𮯰"}`))
	if err != nil || string(pinned151) != `{"value":"𮯰"}` {
		t.Fatalf("Unicode 15.1 assigned scalar rejected: %s, %v", pinned151, err)
	}
	direct, err := CanonicalJSON([]byte(`{"value":"<&>"}`))
	if err != nil || string(direct) != `{"value":"<&>"}` {
		t.Fatalf("canonical JSON escaped safe Unicode/HTML characters: %s, %v", direct, err)
	}
}

func TestIDNA2008Vector(t *testing.T) {
	t.Parallel()
	accepted := map[string]string{
		"https://example.com/":           "https://example.com/",
		"https://XN--BCHER-KVA.example/": "https://xn--bcher-kva.example/",
		"https://xn--8g0n.example/":      "https://xn--8g0n.example/",
	}
	for raw, want := range accepted {
		got, err := URL(raw, nil)
		if err != nil || got.Execution != want {
			t.Fatalf("URL IDNA accepted vector: got %#v, %v; want %s", got, err, want)
		}
	}
	for _, raw := range []string{
		"https://xn--a.example/",
		"https://xn--0.example/",
		"https://xn--a-ecp.example/",
		"https://xn--1ug.example/",
	} {
		if _, err := URL(raw, nil); err == nil {
			t.Fatal("accepted invalid IDNA A-label")
		}
	}
}

func TestMixedPercentRunKeepsReservedBytesEncoded(t *testing.T) {
	t.Parallel()
	got, err := URL("https://example.com/%C3%A9%2F", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Execution != "https://example.com/%C3%A9%2F" {
		t.Fatalf("reserved escape was decoded: %s", got.Execution)
	}
}

func TestURLQueryIgnoresEmptySeparatorsLikeReference(t *testing.T) {
	t.Parallel()
	got, err := URL("https://example.com/?b=2&&a=1&", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Execution != "https://example.com/?a=1&b=2" {
		t.Fatalf("empty query separator changed scope: %s", got.Execution)
	}
}

func TestURLRejectsEmptyAndNoncanonicalPorts(t *testing.T) {
	t.Parallel()
	for _, raw := range []string{
		"https://example.com:/",
		"https://example.com:0443/",
		"https://example.com:0/",
		"https://example.com:65536/",
	} {
		if _, err := URL(raw, nil); err == nil {
			t.Fatalf("accepted invalid port syntax")
		}
	}
}

func TestCanonicalJSONLimitsAndMalformedInputs(t *testing.T) {
	t.Parallel()
	for name, input := range map[string][]byte{
		"utf8":     {0xff},
		"trailing": []byte(`{"a":1} trailing`),
		"nan":      []byte(`{"x":NaN}`),
		"depth":    []byte(strings.Repeat("[", 33) + "0" + strings.Repeat("]", 33)),
		"string":   []byte(`{"x":"` + strings.Repeat("a", MaxStringBytes+1) + `"}`),
		"input":    []byte(strings.Repeat(" ", MaxJSONBytes+1)),
	} {
		if _, err := CanonicalJSON(input); err == nil {
			t.Fatalf("accepted malformed or over-limit JSON: %s", name)
		}
	}
}

func TestPreparedTargetUsesProtocolTypesAndDeterministicResourceHash(t *testing.T) {
	t.Parallel()
	prepared, err := Path("a", "/workspace")
	if err != nil {
		t.Fatal(err)
	}
	left, err := prepared.Target(protocol.TargetKindLocalAction, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	right, err := prepared.Target(protocol.TargetKindLocalAction, "workspace")
	if err != nil {
		t.Fatal(err)
	}
	if left != right || left.ResourceHash == "" {
		t.Fatalf("target is not deterministic: %#v / %#v", left, right)
	}
}

func TestCommittedCanonicalizationVectorsRemainReadable(t *testing.T) {
	t.Parallel()
	root := filepath.Join("..", "..", "..", "protocol", "test-vectors", "canonicalization")
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 10 {
		t.Fatal("canonicalization vector corpus unexpectedly incomplete")
	}
	for _, entry := range entries {
		data, readErr := os.ReadFile(filepath.Join(root, entry.Name()))
		if readErr != nil || !json.Valid(data) {
			t.Fatalf("invalid vector %s: %v", entry.Name(), readErr)
		}
	}
}

func TestErrorsAreClassifiableWithoutUnsafeDetails(t *testing.T) {
	t.Parallel()
	_, err := URL("https://example.com/?token=raw-secret%zz", nil)
	var canonicalErr *Error
	if !errors.As(err, &canonicalErr) || canonicalErr.Code == "" {
		t.Fatalf("missing classifiable canonical error: %v", err)
	}
	if strings.Contains(err.Error(), "raw-secret") {
		t.Fatalf("unsafe error: %v", err)
	}
}
