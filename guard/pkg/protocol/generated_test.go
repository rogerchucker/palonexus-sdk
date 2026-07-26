// SPDX-License-Identifier: MIT

package protocol

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"testing"
)

func repeatedElements(value []byte, count int) [][]byte {
	result := make([][]byte, count)
	for index := range result {
		result[index] = value
	}
	return result
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate generated protocol test")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), "..", "..", ".."))
}

func vectorPaths(t *testing.T, kind, validity string) []string {
	t.Helper()
	pattern := filepath.Join(
		repositoryRoot(t),
		"protocol",
		"test-vectors",
		kind,
		validity,
		"*.json",
	)
	paths, err := filepath.Glob(pattern)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		t.Fatalf("no %s %s vectors", kind, validity)
	}
	return paths
}

func readVector(t *testing.T, path string) []byte {
	t.Helper()
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func assertJSONEquivalent(t *testing.T, expected, actual []byte) {
	t.Helper()
	decode := func(document []byte) any {
		decoder := json.NewDecoder(bytes.NewReader(document))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	expectedValue := decode(expected)
	actualValue := decode(actual)
	if !exactJSONEqual(expectedValue, actualValue) {
		t.Fatalf("JSON differs:\nexpected %s\nactual   %s", expected, actual)
	}
}

func exactJSONEqual(left, right any) bool {
	switch typedLeft := left.(type) {
	case json.Number:
		typedRight, ok := right.(json.Number)
		if !ok {
			return false
		}
		leftNumber, leftOK := new(big.Rat).SetString(typedLeft.String())
		rightNumber, rightOK := new(big.Rat).SetString(typedRight.String())
		return leftOK && rightOK && leftNumber.Cmp(rightNumber) == 0
	case map[string]any:
		typedRight, ok := right.(map[string]any)
		if !ok || len(typedLeft) != len(typedRight) {
			return false
		}
		for key, child := range typedLeft {
			other, exists := typedRight[key]
			if !exists || !exactJSONEqual(child, other) {
				return false
			}
		}
		return true
	case []any:
		typedRight, ok := right.([]any)
		if !ok || len(typedLeft) != len(typedRight) {
			return false
		}
		for index, child := range typedLeft {
			if !exactJSONEqual(child, typedRight[index]) {
				return false
			}
		}
		return true
	default:
		return reflect.DeepEqual(left, right)
	}
}

func TestGeneratedModelsRoundTripValidVectors(t *testing.T) {
	tests := []struct {
		kind  string
		parse func([]byte) (any, error)
	}{
		{"action", func(value []byte) (any, error) { return ParseActionRequest(value) }},
		{"decision", func(value []byte) (any, error) { return ParseAuthorizationDecision(value) }},
		{"approval", func(value []byte) (any, error) { return ParseApprovalRecord(value) }},
		{"error", func(value []byte) (any, error) { return ParseProtocolError(value) }},
		{"reconciliation", func(value []byte) (any, error) { return ParseReconciliationRecord(value) }},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			for _, path := range vectorPaths(t, test.kind, "valid") {
				value := readVector(t, path)
				model, err := test.parse(value)
				if err != nil {
					t.Fatalf("%s: %v", path, err)
				}
				encoded, err := json.Marshal(model)
				if err != nil {
					t.Fatalf("%s: %v", path, err)
				}
				assertJSONEquivalent(t, value, encoded)
			}
		})
	}
}

func TestGeneratedModelsRejectInvalidStructuralVectors(t *testing.T) {
	tests := []struct {
		kind  string
		parse func([]byte) (any, error)
	}{
		{"action", func(value []byte) (any, error) { return ParseActionRequest(value) }},
		{"decision", func(value []byte) (any, error) { return ParseAuthorizationDecision(value) }},
		{"approval", func(value []byte) (any, error) { return ParseApprovalRecord(value) }},
		{"error", func(value []byte) (any, error) { return ParseProtocolError(value) }},
		{"reconciliation", func(value []byte) (any, error) { return ParseReconciliationRecord(value) }},
	}
	for _, test := range tests {
		t.Run(test.kind, func(t *testing.T) {
			for _, path := range vectorPaths(t, test.kind, "invalid") {
				if _, err := test.parse(readVector(t, path)); err == nil {
					t.Fatalf("%s: invalid vector was accepted", path)
				}
			}
		})
	}
}

func TestSemanticValidationBoundaryIsExplicit(t *testing.T) {
	path := filepath.Join(
		repositoryRoot(t),
		"protocol",
		"test-vectors",
		"decision",
		"semantic-invalid",
		"invalid-time-order.json",
	)
	if _, err := ParseAuthorizationDecision(readVector(t, path)); err != nil {
		t.Fatalf("structurally valid semantic fixture was rejected: %v", err)
	}
	if SemanticValidationReference != "protocol/reference/validate.py" {
		t.Fatalf("semantic validation reference drifted: %s", SemanticValidationReference)
	}
}

func TestWireSafeTypesAndEnumsCompile(t *testing.T) {
	var _ ActionID = ActionID("act_01J5ABCDEFGHJKMNPQRSTVWXY0")
	var _ RequestID = RequestID("req_01J5ABCDEFGHJKMNPQRSTVWXY0")
	var _ SHA256Digest = SHA256Digest(
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	)
	var _ RFC3339Timestamp = RFC3339Timestamp("2026-07-25T20:00:00Z")

	if ActionNameFileWrite != ActionName("file:write") {
		t.Fatal("action enum JSON value drifted")
	}
	if ActionNameMCPCall != ActionName("mcp:call") {
		t.Fatal("MCP action enum JSON value drifted")
	}
	if DecisionOutcomeApprovalRequired != DecisionOutcome("approval_required") {
		t.Fatal("decision outcome enum JSON value drifted")
	}
	if ProtocolErrorCodeMissingIdentity != ProtocolErrorCode("missing_identity") {
		t.Fatal("error enum JSON value drifted")
	}
}

func TestOptionalEmptyObjectsRemainPresent(t *testing.T) {
	path := vectorPaths(t, "action", "valid")[0]
	var document map[string]any
	if err := json.Unmarshal(readVector(t, path), &document); err != nil {
		t.Fatal(err)
	}
	document["extensions"] = map[string]any{}
	for _, name := range []string{"adapter", "task", "target", "context"} {
		document[name].(map[string]any)["extensions"] = map[string]any{}
	}
	wire, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}

	model, err := ParseActionRequest(wire)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}

	assertJSONEquivalent(t, wire, encoded)
	for _, fragment := range [][]byte{
		[]byte(`"extensions":{}`),
	} {
		if count := bytes.Count(encoded, fragment); count != 5 {
			t.Fatalf("expected five present empty extension objects, got %d: %s", count, encoded)
		}
	}

	cases := []struct {
		kind   string
		path   string
		nested []string
		parse  func([]byte) (any, error)
	}{
		{
			"decision",
			"protocol/test-vectors/decision/valid/approval-required.json",
			[]string{"approval"},
			func(value []byte) (any, error) { return ParseAuthorizationDecision(value) },
		},
		{
			"approval",
			"protocol/test-vectors/approval/valid/pending.json",
			nil,
			func(value []byte) (any, error) { return ParseApprovalRecord(value) },
		},
		{
			"error",
			"protocol/test-vectors/error/valid/authorization-unavailable.json",
			nil,
			func(value []byte) (any, error) { return ParseProtocolError(value) },
		},
		{
			"reconciliation",
			"protocol/test-vectors/reconciliation/valid/pending.json",
			nil,
			func(value []byte) (any, error) { return ParseReconciliationRecord(value) },
		},
	}
	for _, test := range cases {
		t.Run(test.kind, func(t *testing.T) {
			var document map[string]any
			source := readVector(t, filepath.Join(repositoryRoot(t), test.path))
			if err := json.Unmarshal(source, &document); err != nil {
				t.Fatal(err)
			}
			document["extensions"] = map[string]any{}
			for _, field := range test.nested {
				document[field].(map[string]any)["extensions"] = map[string]any{}
			}
			wire, err := json.Marshal(document)
			if err != nil {
				t.Fatal(err)
			}
			model, err := test.parse(wire)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(model)
			if err != nil {
				t.Fatal(err)
			}
			assertJSONEquivalent(t, wire, encoded)
		})
	}
}

func TestExtremeExponentAndLeapSecondParity(t *testing.T) {
	source := readVector(t, filepath.Join(
		repositoryRoot(t),
		"protocol/test-vectors/action/valid/file-write.json",
	))
	leap := bytes.ReplaceAll(
		source,
		[]byte("2026-07-25T20:00:00Z"),
		[]byte("2026-07-25T20:00:60Z"),
	)
	if _, err := ParseActionRequest(leap); err != nil {
		t.Fatalf("schema-valid RFC3339 leap second rejected: %v", err)
	}

	extreme := bytes.ReplaceAll(
		source,
		[]byte(`"ticket": "EXAMPLE-42"`),
		[]byte(`"ticket": "EXAMPLE-42", "extreme": 1e999999999999999999999999999999999999`),
	)
	if _, err := ParseActionRequest(extreme); err == nil ||
		err.Error() != "invalid_json_number" {
		t.Fatalf("extreme exponent error = %v, want invalid_json_number", err)
	}
}

func TestIntegralJSONNumbersNormalizeWithoutFloatRounding(t *testing.T) {
	path := filepath.Join(
		repositoryRoot(t),
		"protocol/test-vectors/reconciliation/valid/pending.json",
	)
	wire := readVector(t, path)
	wire = bytes.Replace(wire, []byte(`"batchSequence": 0`), []byte(`"batchSequence": 0e0`), 1)
	wire = bytes.Replace(wire, []byte(`"attemptCount": 0`), []byte(`"attemptCount": 0.0`), 1)
	wire = bytes.Replace(wire, []byte(`"maxAttempts": 3`), []byte(`"maxAttempts": 3.0`), 1)

	model, err := ParseReconciliationRecord(wire)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}

	for _, fragment := range [][]byte{
		[]byte(`"batchSequence":0`),
		[]byte(`"attemptCount":0`),
		[]byte(`"maxAttempts":3`),
	} {
		if !bytes.Contains(encoded, fragment) {
			t.Fatalf("normalized integer missing %s in %s", fragment, encoded)
		}
	}
	invalid := bytes.Replace(wire, []byte(`"batchSequence": 0e0`), []byte(`"batchSequence": 0.5`), 1)
	if _, err := ParseReconciliationRecord(invalid); err == nil {
		t.Fatal("non-integral schema integer was accepted")
	}
}

func TestExtensionNumbersRemainExact(t *testing.T) {
	path := filepath.Join(
		repositoryRoot(t),
		"protocol/test-vectors/action/valid/file-write.json",
	)
	wire := readVector(t, path)
	wire = bytes.Replace(
		wire,
		[]byte(`"ticket": "EXAMPLE-42"`),
		[]byte(`"large": 9007199254740993, "decimal": 0.123456789012345678901234567890123456789`),
		1,
	)

	model, err := ParseActionRequest(wire)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(model)
	if err != nil {
		t.Fatal(err)
	}
	for _, number := range [][]byte{
		[]byte("9007199254740993"),
		[]byte("0.123456789012345678901234567890123456789"),
	} {
		if !bytes.Contains(encoded, number) {
			t.Fatalf("exact number %s missing from %s", number, encoded)
		}
	}
	extension := (*model.Extensions)["dev.palonexus.example.v1"].(map[string]any)
	large, ok := new(big.Rat).SetString(extension["large"].(json.Number).String())
	if !ok || large.Cmp(new(big.Rat).SetInt64(9007199254740993)) != 0 {
		t.Fatalf("large integer rounded: %#v", extension["large"])
	}
}

func TestStrictWireParserRejectsHostileInputs(t *testing.T) {
	deep := append([]byte(`{"schemaVersion":"1","extensions":{"dev.test.v1":`), bytes.Repeat([]byte("["), 40)...)
	deep = append(deep, '0')
	deep = append(deep, bytes.Repeat([]byte("]"), 40)...)
	deep = append(deep, []byte("}}")...)
	arrayLimit := append(
		[]byte(`{"schemaVersion":"1","extensions":{"dev.test.v1":[`),
		bytes.Join(repeatedElements([]byte("0"), 1025), []byte(","))...,
	)
	arrayLimit = append(arrayLimit, []byte("]}}")...)
	var keyLimit bytes.Buffer
	keyLimit.WriteString(`{"schemaVersion":"1","extensions":{"dev.test.v1":{`)
	for index := 0; index < 1025; index++ {
		if index > 0 {
			keyLimit.WriteByte(',')
		}
		keyLimit.WriteString(`"k`)
		keyLimit.WriteString(strconv.Itoa(index))
		keyLimit.WriteString(`":0`)
	}
	keyLimit.WriteString("}}}")
	nodes := append(
		[]byte(`{"schemaVersion":"1","extensions":{"dev.test.v1":[`),
		bytes.Join(repeatedElements([]byte("[0,0,0,0]"), 1024), []byte(","))...,
	)
	nodes = append(nodes, []byte("]}}")...)
	tests := []struct {
		name string
		wire []byte
		code string
	}{
		{"duplicate", []byte(`{"schemaVersion":"1","schemaVersion":"1"}`), "duplicate_json_key"},
		{"nested-duplicate", []byte(`{"adapter":{"id":"a","id":"b"}}`), "duplicate_json_key"},
		{"utf8", []byte{'{', '"', 0xff, '"', ':', '1', '}'}, "invalid_utf8"},
		{"surrogate", []byte(`{"schemaVersion":"\ud800"}`), "invalid_utf8"},
		{"depth", deep, "nesting_too_deep"},
		{"number", append(append([]byte(`{"schemaVersion":"1","extensions":{"dev.test.v1":`), bytes.Repeat([]byte("9"), 513)...), []byte("}}")...), "numeric_token_too_long"},
		{"array-limit", arrayLimit, "collection_limit_exceeded"},
		{"key-limit", keyLimit.Bytes(), "collection_limit_exceeded"},
		{"string-limit", append(append([]byte(`{"schemaVersion":"1","extensions":{"dev.test.v1":"`), bytes.Repeat([]byte("x"), 8193)...), []byte(`"}}`)...), "string_too_large"},
		{"nodes", nodes, "node_limit_exceeded"},
		{"size", bytes.Repeat([]byte(" "), 65537), "wire_too_large"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := ParseActionRequest(test.wire)
			if err == nil || !bytes.Contains([]byte(err.Error()), []byte(test.code)) {
				t.Fatalf("got %v, want %s", err, test.code)
			}
		})
	}
}

func TestMarshalAndValidateRejectDirectInvalidConstruction(t *testing.T) {
	path := filepath.Join(
		repositoryRoot(t),
		"protocol/test-vectors/action/valid/file-write.json",
	)
	model, err := ParseActionRequest(readVector(t, path))
	if err != nil {
		t.Fatal(err)
	}
	model.Action = ActionName("not:registered")

	if err := model.ValidateStructural(); err == nil {
		t.Fatal("ValidateStructural accepted invalid direct construction")
	}
	if _, err := json.Marshal(model); err == nil {
		t.Fatal("MarshalJSON accepted invalid direct construction")
	}
}

func TestTimestampBoundaryMatchesTask5(t *testing.T) {
	path := filepath.Join(
		repositoryRoot(t),
		"protocol/test-vectors/action/valid/file-write.json",
	)
	wire := readVector(t, path)
	precise := bytes.Replace(
		wire,
		[]byte("2026-07-25T20:00:00Z"),
		[]byte("2026-07-25T20:00:59.123456789123456789+23:59"),
		1,
	)
	if _, err := ParseActionRequest(precise); err != nil {
		t.Fatalf("accepted Task5 timestamp rejected: %v", err)
	}
	for _, timestamp := range []string{
		"2026-02-30T20:00:00Z",
		"2026-07-25T20:00:00+24:00",
	} {
		invalid := bytes.Replace(
			wire,
			[]byte("2026-07-25T20:00:00Z"),
			[]byte(timestamp),
			1,
		)
		if _, err := ParseActionRequest(invalid); err == nil {
			t.Fatalf("invalid timestamp accepted: %s", timestamp)
		}
	}
}
