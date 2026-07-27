// SPDX-License-Identifier: MIT
package normalize

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
		if err != nil || got.SensitiveExecution() != tc.want || string(got.Resource) != "path:"+tc.want {
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
	if got.SensitiveExecution() != "https://example.com/b?a=2&a=1&token=raw-secret&z=last" {
		t.Fatalf("unexpected execution URL")
	}
	if strings.Contains(fmt.Sprintf("%v %#v", got, got), "raw-secret") {
		t.Fatal("log-safe prepared representation exposed execution secret")
	}
	resource := string(got.Resource)
	if strings.Contains(resource, "raw-secret") || !strings.Contains(resource, "token=%5BREDACTED%5D") {
		t.Fatalf("resource is not safely redacted: %s", resource)
	}
	gotAgain, err := URL(got.SensitiveExecution().(string), nil)
	if err != nil || gotAgain.Resource != got.Resource || gotAgain.SensitiveExecution() != got.SensitiveExecution() {
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
	if left.SensitiveExecution() != `curl -H "Authorization: Bearer raw-secret" "https://example.com/run?token=raw-secret" --password raw-secret` {
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

func TestShellTokenizerMatchesFrozenPOSIXCorpus(t *testing.T) {
	t.Parallel()
	cases := []struct {
		command string
		want    []string
	}{
		{"", nil},
		{" \t\r\n ", nil},
		{`'' "" a''b`, []string{"", "", "ab"}},
		{`echo # literal && printf ok`, []string{"echo", "#", "literal", "&&", "printf", "ok"}},
		{`a\ b c`, []string{"a b", "c"}},
		{`a\\b`, []string{`a\b`}},
		{`\# x`, []string{"#", "x"}},
		{`"a\"b"`, []string{`a"b`}},
		{`"a\\b"`, []string{`a\b`}},
		{`"a\qb"`, []string{`a\qb`}},
		{`"a\$b"`, []string{`a\$b`}},
		{`'a\b'`, []string{`a\b`}},
		{"a\u00a0b a\u2003b", []string{"a\u00a0b", "a\u2003b"}},
	}
	for _, tc := range cases {
		got, err := tokenizeShell(tc.command)
		if err != nil || fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Fatalf("tokenizeShell corpus mismatch: got %q, %v; want %q", got, err, tc.want)
		}
	}
	for _, malformed := range []string{`echo \`, `echo 'unterminated`, `echo "unterminated`} {
		if _, err := tokenizeShell(malformed); err == nil {
			t.Fatal("accepted malformed shell quoting")
		}
	}
}

func TestShellTokenizerDifferentialAgainstPythonReference(t *testing.T) {
	commands := []string{
		"", `'' "" a''b`, `echo # literal && printf ok`, `a\ b c`,
		`"a\"b"`, `"a\\b"`, `"a\qb"`, `"a\$b"`, `'a\b'`,
		"a\u00a0b a\u2003b", "line\\\ncontinued",
		`echo \`, `echo 'unterminated`, `echo "unterminated`,
	}
	input, err := json.Marshal(commands)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	script := `import json,sys
from protocol.reference.canonicalize import canonicalize_shell
items=json.load(sys.stdin)
print(json.dumps([canonicalize_shell(x)["tokens"] for x in items]))`
	command := exec.CommandContext(
		ctx, "uv", "run", "--frozen", "--offline", "--no-sync",
		"python", "-c", script,
	)
	command.Dir = filepath.Join("..", "..", "..")
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("Python differential oracle failed: %v", err)
	}
	if len(output) > 64*1024 {
		t.Fatal("Python differential oracle output exceeded bound")
	}
	var expected [][]string
	if err := json.Unmarshal(output, &expected); err != nil || len(expected) != len(commands) {
		t.Fatalf("invalid Python differential output: %v", err)
	}
	for index, shellCommand := range commands {
		got, tokenErr := tokenizeShell(shellCommand)
		if tokenErr != nil {
			got = []string{"[UNPARSEABLE]"}
		}
		if fmt.Sprint(got) != fmt.Sprint(expected[index]) {
			t.Fatalf("shell parity mismatch at %d: got %q, want %q", index, got, expected[index])
		}
	}
}

func TestResourceDifferentialAgainstPythonReference(t *testing.T) {
	const script = `import json,sys
from protocol.reference.canonicalize import (
 canonical_json,parse_json,prepare_mcp_resource,prepare_path_resource,prepare_url_resource
)
data=json.load(sys.stdin)
mcp=prepare_mcp_resource(data["server"],data["tool"],parse_json(data["mcp"]))
path=prepare_path_resource(data["path"],cwd=data["cwd"])
url=prepare_url_resource(data["url"])
print(json.dumps({
 "json":canonical_json(parse_json(data["json"])).decode(),
 "mcp_resource":mcp.resource,
 "path_resource":path.resource,"path_execution":path.execution,
 "url_resource":url.resource,"url_execution":url.execution,
}))`
	input := map[string]string{
		"json":   `{"e\u0301":"Cafe\u0301","n":1.0}`,
		"server": "github", "tool": "issues.create",
		"mcp":  `{"title":"Cafe\u0301","priority":1.0}`,
		"path": `src/../Café.txt`, "cwd": "/workspace",
		"url": `HTTPS://Example.COM:443/a/../Caf%C3%A9?token=raw-secret&b=2&a=1`,
	}
	encoded, _ := json.Marshal(input)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx, "uv", "run", "--frozen", "--offline", "--no-sync",
		"python", "-c", script,
	)
	command.Dir = filepath.Join("..", "..", "..")
	command.Stdin = bytes.NewReader(encoded)
	output, err := command.Output()
	if err != nil || len(output) > 64*1024 {
		t.Fatalf("bounded Python resource oracle failed: %v", err)
	}
	var expected struct {
		JSON          string `json:"json"`
		MCPResource   string `json:"mcp_resource"`
		PathResource  string `json:"path_resource"`
		PathExecution string `json:"path_execution"`
		URLResource   string `json:"url_resource"`
		URLExecution  string `json:"url_execution"`
	}
	if err := json.Unmarshal(output, &expected); err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalJSON([]byte(input["json"]))
	if err != nil || string(canonical) != expected.JSON {
		t.Fatal("canonical JSON differs from Python reference")
	}
	mcp, err := MCPJSON(input["server"], input["tool"], []byte(input["mcp"]))
	if err != nil || string(mcp.Resource) != expected.MCPResource {
		t.Fatal("MCP differs from Python reference")
	}
	pathValue, err := Path(input["path"], input["cwd"])
	if err != nil || string(pathValue.Resource) != expected.PathResource ||
		pathValue.SensitiveExecution() != expected.PathExecution {
		t.Fatal("path differs from Python reference")
	}
	urlValue, err := URL(input["url"], nil)
	if err != nil || string(urlValue.Resource) != expected.URLResource ||
		urlValue.SensitiveExecution() != expected.URLExecution {
		t.Fatal("URL differs from Python reference")
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
		if err != nil || got.SensitiveExecution() != want {
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

func TestIDNAUnicode151ExceptionComposesWithOtherwiseValidScalars(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string]string{
		"https://xn--a-8n62a.example/":  "https://xn--a-8n62a.example/",
		"https://xn--a-7n62a.example/":  "https://xn--a-7n62a.example/",
		"https://xn--fiq4244n.example/": "https://xn--fiq4244n.example/",
	} {
		got, err := URL(raw, nil)
		if err != nil || got.SensitiveExecution() != want {
			t.Fatalf("mixed Unicode 15.1 IDNA label rejected: %v", err)
		}
	}
	for _, raw := range []string{
		"https://xn--a-ugnv4543a.example/",
		"https://xn--1ugy703z.example/",
	} {
		if _, err := URL(raw, nil); err == nil {
			t.Fatal("accepted context-invalid mixed IDNA label")
		}
	}
}

func TestMixedPercentRunKeepsReservedBytesEncoded(t *testing.T) {
	t.Parallel()
	got, err := URL("https://example.com/%C3%A9%2F", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.SensitiveExecution() != "https://example.com/%C3%A9%2F" {
		t.Fatalf("reserved escape was decoded")
	}
}

func TestURLQueryIgnoresEmptySeparatorsLikeReference(t *testing.T) {
	t.Parallel()
	got, err := URL("https://example.com/?b=2&&a=1&", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.SensitiveExecution() != "https://example.com/?a=1&b=2" {
		t.Fatalf("empty query separator changed scope")
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

func TestPreparedStructuredRepresentationsNeverExposeExecution(t *testing.T) {
	t.Parallel()
	for name, prepare := range map[string]func() (Prepared, error){
		"url": func() (Prepared, error) {
			return URL("https://example.com/?token=raw-url-secret", nil)
		},
		"shell": func() (Prepared, error) {
			return Shell("deploy --token raw-shell-secret", nil)
		},
		"mcp": func() (Prepared, error) {
			return MCPJSON("github", "issues.create", []byte(`{"token":"raw-mcp-secret"}`))
		},
	} {
		prepared, err := prepare()
		if err != nil {
			t.Fatal(err)
		}
		jsonValue, err := json.Marshal(prepared)
		if err != nil {
			t.Fatal(err)
		}
		var logOutput bytes.Buffer
		logger := slog.New(slog.NewJSONHandler(&logOutput, nil))
		logger.Info("prepared", "value", prepared)
		diagnostics := string(jsonValue) + logOutput.String() + fmt.Sprintf("%v %#v", prepared, prepared)
		if strings.Contains(diagnostics, "raw-") {
			t.Fatalf("%s structured representation leaked execution: %s", name, diagnostics)
		}
		if strings.Contains(string(jsonValue), `"execution":`) {
			t.Fatalf("%s JSON exposed execution field", name)
		}
	}
}

func TestMCPExecutionAccessIsDeeplyIsolatedFromMutation(t *testing.T) {
	t.Parallel()
	prepared, err := MCPJSON(
		"github",
		"issues.create",
		[]byte(`{"nested":{"token":"original"},"items":[{"value":1},2]}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	authorizedResource := prepared.Resource
	first, ok := prepared.SensitiveExecution().(MCPExecution)
	if !ok {
		t.Fatalf("MCP execution does not use the typed boundary: %T", prepared.SensitiveExecution())
	}
	first.Server = "attacker"
	first.Tool = "delete"
	firstInput := first.Input.(map[string]any)
	firstInput["nested"].(map[string]any)["token"] = "mutated"
	firstInput["items"].([]any)[0].(map[string]any)["value"] = json.Number("999")
	firstInput["items"] = append(firstInput["items"].([]any), "extra")

	second := prepared.SensitiveExecution().(MCPExecution)
	if second.Server != "github" || second.Tool != "issues.create" {
		t.Fatal("MCP execution identity aliased caller mutation")
	}
	secondInput := second.Input.(map[string]any)
	if secondInput["nested"].(map[string]any)["token"] != "original" ||
		len(secondInput["items"].([]any)) != 2 ||
		secondInput["items"].([]any)[0].(map[string]any)["value"] != json.Number("1") {
		t.Fatal("nested MCP execution graph aliased caller mutation")
	}
	if prepared.Resource != authorizedResource {
		t.Fatal("execution mutation changed authorized resource")
	}
	reencoded, err := canonicalNative(second.Input)
	if err != nil {
		t.Fatal(err)
	}
	reprepared, err := MCPJSON(second.Server, second.Tool, reencoded)
	if err != nil || reprepared.Resource != authorizedResource {
		t.Fatal("executor-bound MCP value no longer corresponds to authorized resource")
	}
}

func TestScalarExecutionAccessCannotAliasMutableState(t *testing.T) {
	t.Parallel()
	for _, prepare := range []func() (Prepared, error){
		func() (Prepared, error) { return URL("https://example.com/", nil) },
		func() (Prepared, error) { return Shell("echo ok", nil) },
	} {
		prepared, err := prepare()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := prepared.SensitiveExecution().(string); !ok {
			t.Fatalf("scalar execution is unexpectedly mutable: %T", prepared.SensitiveExecution())
		}
	}
}

func TestPublicShellResourceMatchesPythonAndGeneratedSchema(t *testing.T) {
	commands := []string{
		`echo "a\q"`,
		`printf '' ""`,
		`echo \`,
		`echo "unterminated`,
	}
	input, _ := json.Marshal(commands)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const script = `import json,sys
from protocol.reference.canonicalize import prepare_shell_resource
print(json.dumps([prepare_shell_resource(x).resource for x in json.load(sys.stdin)]))`
	command := exec.CommandContext(
		ctx, "uv", "run", "--frozen", "--offline", "--no-sync",
		"python", "-c", script,
	)
	command.Dir = filepath.Join("..", "..", "..")
	command.Stdin = bytes.NewReader(input)
	output, err := command.Output()
	if err != nil || len(output) > 64*1024 {
		t.Fatalf("bounded Python shell resource oracle failed: %v", err)
	}
	var expected []string
	if err := json.Unmarshal(output, &expected); err != nil {
		t.Fatal(err)
	}
	for index, shellCommand := range commands {
		prepared, err := Shell(shellCommand, nil)
		if err != nil {
			t.Fatalf("public Shell rejected parity-valid input: %v", err)
		}
		if string(prepared.Resource) != expected[index] {
			t.Fatalf("public Shell resource differs from Python at %d", index)
		}
		assertTargetParses(t, prepared, protocol.TargetKindLocalAction, "workspace")
	}
}

func assertTargetParses(
	t *testing.T,
	prepared Prepared,
	kind protocol.TargetKind,
	service string,
) {
	t.Helper()
	target, err := prepared.Target(kind, service)
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.ReadFile(filepath.Join(
		"..", "..", "..", "protocol", "test-vectors", "action", "valid", "file-write.json",
	))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	_ = json.Unmarshal(fixture, &document)
	targetJSON, _ := json.Marshal(target)
	var targetValue any
	_ = json.Unmarshal(targetJSON, &targetValue)
	document["target"] = targetValue
	encoded, _ := json.Marshal(document)
	if _, err := protocol.ParseActionRequest(encoded); err != nil {
		t.Fatalf("prepared target violates generated schema: %v", err)
	}
}

func TestTargetEnforcesGeneratedSchemaConstraints(t *testing.T) {
	t.Parallel()
	prepared, err := Path("file", "/workspace")
	if err != nil {
		t.Fatal(err)
	}
	validServices := []string{"a", "service-name", "api.example.com", strings.Repeat("a", 63) + ".com"}
	for _, service := range validServices {
		if _, err := prepared.Target(protocol.TargetKindLocalAction, service); err != nil {
			t.Fatalf("rejected valid service: %v", err)
		}
	}
	for _, kind := range []protocol.TargetKind{"", "unknown", "LOCAL-ACTION"} {
		if _, err := prepared.Target(kind, "workspace"); err == nil {
			t.Fatal("accepted unknown target kind")
		}
	}
	for _, service := range []string{
		"", "-bad", "bad-", "Bad", "bad_name", "a..b",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a", 254),
		"bad\x00name",
	} {
		if _, err := prepared.Target(protocol.TargetKindLocalAction, service); err == nil {
			t.Fatal("accepted invalid target service")
		}
	}
	for _, resource := range []protocol.SafeText{
		"", "resource:\x00unsafe", protocol.SafeText(strings.Repeat("x", 2049)),
	} {
		unsafe := Prepared{Resource: resource, execution: "private"}
		if _, err := unsafe.Target(protocol.TargetKindLocalAction, "workspace"); err == nil {
			t.Fatal("accepted resource outside generated schema")
		}
	}
}

func TestConstructorsRejectResourcesOutsideActionTargetSchema(t *testing.T) {
	t.Parallel()
	if _, err := Path(strings.Repeat("a", 2048), "/"); err == nil {
		t.Fatal("path constructor emitted overlong resource")
	}
	if _, err := Shell(strings.Repeat("x ", 1500), nil); err == nil {
		t.Fatal("shell constructor emitted overlong resource")
	}
}

func TestTargetRoundTripsThroughGeneratedActionParser(t *testing.T) {
	t.Parallel()
	prepared, err := Path("deploy.yaml", "/workspace")
	if err != nil {
		t.Fatal(err)
	}
	assertTargetParses(t, prepared, protocol.TargetKindLocalAction, "workspace")
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
