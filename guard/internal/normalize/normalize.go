// SPDX-License-Identifier: MIT
// Package normalize prepares typed action resources without executing or
// inspecting them. Errors contain stable codes and never echo raw input.
package normalize

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/rogerchucker/palonexus-sdk/guard/pkg/protocol"
	"golang.org/x/net/idna"
	"golang.org/x/text/unicode/norm"
)

const (
	MaxJSONBytes   = 65_536
	MaxStringBytes = 8_192
	maxDepth       = 32
	maxObjectKeys  = 256
	maxArrayItems  = 1_024
	redacted       = "[REDACTED]"
)

type Error struct{ Code string }

func (e *Error) Error() string { return "canonicalization failed: " + e.Code }

func fail(code string) error { return &Error{Code: code} }

type Prepared struct {
	Resource  protocol.SafeText `json:"resource"`
	execution any
}

// FromSafeResource reconstructs a prepared, non-executable resource received
// over the local guard protocol. It validates the same safe-display boundary
// and never creates executor-bound data.
func FromSafeResource(resource protocol.SafeText) (Prepared, error) {
	result := Prepared{Resource: resource}
	if err := validateResource(resource); err != nil {
		return Prepared{}, err
	}
	return result, nil
}

// MCPExecution is a detached executor-bound MCP invocation.
type MCPExecution struct {
	Server string
	Tool   string
	Input  any
}

// SensitiveExecution returns the exact normalized value the host must execute.
// It may contain credentials or raw tool input and MUST NOT be logged,
// serialized, reflected, or included in errors.
func (p Prepared) SensitiveExecution() any {
	if execution, ok := p.execution.(MCPExecution); ok {
		return MCPExecution{
			Server: execution.Server,
			Tool:   execution.Tool,
			Input:  copyJSONValue(execution.Input),
		}
	}
	return p.execution
}

func copyJSONValue(value any) any {
	switch item := value.(type) {
	case map[string]any:
		result := make(map[string]any, len(item))
		for key, child := range item {
			result[key] = copyJSONValue(child)
		}
		return result
	case []any:
		result := make([]any, len(item))
		for index, child := range item {
			result[index] = copyJSONValue(child)
		}
		return result
	case string, json.Number, bool, nil:
		return item
	default:
		// MCPJSON creates only the closed JSON value set above.
		return nil
	}
}

// String is intentionally diagnostic-only and never renders Execution.
func (p Prepared) String() string {
	return "Prepared{Resource:" + string(p.Resource) + ", Execution:[PRIVATE]}"
}

// GoString keeps %#v log formatting from exposing Execution.
func (p Prepared) GoString() string { return p.String() }

func (p Prepared) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Resource protocol.SafeText `json:"resource"`
	}{Resource: p.Resource})
}

func (p Prepared) LogValue() slog.Value {
	return slog.GroupValue(slog.String("resource", string(p.Resource)))
}

// Target derives the protocol target and its typed resource-preimage hash.
func (p Prepared) Target(kind protocol.TargetKind, service string) (protocol.ActionTarget, error) {
	if !validTargetKind(kind) {
		return protocol.ActionTarget{}, fail("invalid_target_kind")
	}
	if !validService(service) {
		return protocol.ActionTarget{}, fail("invalid_service")
	}
	if err := validateResource(p.Resource); err != nil {
		return protocol.ActionTarget{}, err
	}
	preimage := map[string]any{
		"preimageType": "palonexus.resource", "preimageVersion": "1",
		"kind": string(kind), "service": service, "resource": string(p.Resource),
	}
	encoded, err := canonicalNative(preimage)
	if err != nil {
		return protocol.ActionTarget{}, err
	}
	return protocol.ActionTarget{
		Kind: kind, Service: service, Resource: p.Resource,
		ResourceHash: protocol.SHA256Digest(hashBytes(encoded)),
	}, nil
}

var servicePattern = regexp.MustCompile(
	`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$`,
)

func validTargetKind(kind protocol.TargetKind) bool {
	return kind == protocol.TargetKindLocalAction ||
		kind == protocol.TargetKindMCPTool ||
		kind == protocol.TargetKindTool
}

func validService(service string) bool {
	return utf8.ValidString(service) && utf8.RuneCountInString(service) <= 253 &&
		!hasUnsafeText(service) && servicePattern.MatchString(service)
}

func hasUnsafeText(value string) bool {
	for _, r := range value {
		if r <= 0x1f || r >= 0x7f && r <= 0x9f ||
			r == 0x061c || r == 0x200e || r == 0x200f ||
			r >= 0x2028 && r <= 0x202e || r >= 0x2066 && r <= 0x2069 {
			return true
		}
	}
	return false
}

func validateResource(resource protocol.SafeText) error {
	value := string(resource)
	if !utf8.ValidString(value) || value == "" ||
		utf8.RuneCountInString(value) > 2048 || hasUnsafeText(value) {
		return fail("invalid_resource")
	}
	return nil
}

func prepared(resource []byte, execution any) (Prepared, error) {
	result := Prepared{Resource: protocol.SafeText(resource), execution: execution}
	if err := validateResource(result.Resource); err != nil {
		return Prepared{}, err
	}
	return result, nil
}

func normalizeString(value, code string) (string, error) {
	if !utf8.ValidString(value) {
		return "", fail(code)
	}
	value = norm.NFC.String(value)
	if len([]byte(value)) > MaxStringBytes {
		return "", fail("string_too_large")
	}
	for _, r := range value {
		if r >= 0xd800 && r <= 0xdfff ||
			(unicode.Is(unicode.Cn, r) && (r < 0x2EBF0 || r > 0x2EE5D)) {
			return "", fail(code)
		}
	}
	return value, nil
}

func Path(value, cwd string) (Prepared, error) {
	value, err := normalizeString(value, "invalid_path")
	if err != nil {
		return Prepared{}, err
	}
	cwd, err = normalizeString(cwd, "invalid_path")
	if err != nil {
		return Prepared{}, err
	}
	if strings.ContainsAny(value, "\x00\\") || strings.ContainsAny(cwd, "\x00\\") {
		return Prepared{}, fail("unsupported_path_syntax")
	}
	if !strings.HasPrefix(cwd, "/") {
		return Prepared{}, fail("cwd_not_absolute")
	}
	if !strings.HasPrefix(value, "/") {
		value = path.Join(cwd, value)
	} else {
		value = path.Clean(value)
	}
	if value == "." {
		value = "/"
	}
	return prepared([]byte("path:"+value), value)
}

func hashBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type objectPair struct {
	key string
	val any
}
type orderedObject []objectPair

// CanonicalJSON strictly parses and canonicalizes JSON without float rounding.
func CanonicalJSON(input []byte) ([]byte, error) {
	if len(input) > MaxJSONBytes {
		return nil, fail("input_too_large")
	}
	if !utf8.Valid(input) {
		return nil, fail("invalid_json")
	}
	decoder := json.NewDecoder(bytes.NewReader(input))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, err
	}
	if token, tokenErr := decoder.Token(); tokenErr != io.EOF || token != nil {
		return nil, fail("invalid_json")
	}
	output, err := encodeValue(value, 0)
	if err != nil {
		return nil, err
	}
	if len(output) > MaxJSONBytes {
		return nil, fail("input_too_large")
	}
	return output, nil
}

func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > maxDepth {
		return nil, fail("nesting_too_deep")
	}
	token, err := d.Token()
	if err != nil {
		return nil, fail("invalid_json")
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			pairs := orderedObject{}
			seen := map[string]struct{}{}
			for d.More() {
				keyToken, keyErr := d.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok {
					return nil, fail("invalid_json")
				}
				key, keyErr = normalizeString(key, "invalid_string")
				if keyErr != nil {
					return nil, keyErr
				}
				if _, exists := seen[key]; exists {
					return nil, fail("duplicate_key")
				}
				seen[key] = struct{}{}
				if len(seen) > maxObjectKeys {
					return nil, fail("too_many_object_keys")
				}
				item, itemErr := decodeValue(d, depth+1)
				if itemErr != nil {
					return nil, itemErr
				}
				pairs = append(pairs, objectPair{key, item})
			}
			if _, err = d.Token(); err != nil {
				return nil, fail("invalid_json")
			}
			return pairs, nil
		case '[':
			items := []any{}
			for d.More() {
				if len(items) >= maxArrayItems {
					return nil, fail("too_many_array_items")
				}
				item, itemErr := decodeValue(d, depth+1)
				if itemErr != nil {
					return nil, itemErr
				}
				items = append(items, item)
			}
			if _, err = d.Token(); err != nil {
				return nil, fail("invalid_json")
			}
			return items, nil
		}
		return nil, fail("invalid_json")
	case string:
		return normalizeString(value, "invalid_string")
	case json.Number:
		normalized, normalizeErr := normalizeNumber(string(value))
		if normalizeErr != nil {
			return nil, normalizeErr
		}
		return json.Number(normalized), nil
	case bool, nil:
		return value, nil
	default:
		return nil, fail("invalid_json")
	}
}

var decimalPattern = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)(?:\.([0-9]+))?(?:[eE]([+-]?[0-9]+))?$`)

func normalizeNumber(raw string) (string, error) {
	match := decimalPattern.FindStringSubmatch(raw)
	if match == nil {
		return "", fail("invalid_number")
	}
	negative := strings.HasPrefix(raw, "-")
	unsigned := strings.TrimPrefix(raw, "-")
	expIndex := strings.IndexAny(unsigned, "eE")
	exponent := 0
	if expIndex >= 0 {
		parsed, err := strconv.Atoi(unsigned[expIndex+1:])
		if err != nil || parsed < -100000 || parsed > 100000 {
			return "", fail("number_out_of_range")
		}
		exponent = parsed
		unsigned = unsigned[:expIndex]
	}
	dot := strings.IndexByte(unsigned, '.')
	fracDigits := 0
	if dot >= 0 {
		fracDigits = len(unsigned) - dot - 1
		unsigned = unsigned[:dot] + unsigned[dot+1:]
	}
	digits := strings.TrimLeft(unsigned, "0")
	if digits == "" {
		return "0", nil
	}
	digits = strings.TrimRight(digits, "0")
	trailing := len(strings.TrimLeft(unsigned, "0")) - len(digits)
	exponent = exponent - fracDigits + trailing
	if len(digits) > 128 {
		return "", fail("number_too_precise")
	}
	adjusted := exponent + len(digits) - 1
	if exponent < -435 || exponent > 308 || adjusted < -308 || adjusted > 308 {
		return "", fail("number_out_of_range")
	}
	var result string
	if exponent >= 0 {
		result = digits + strings.Repeat("0", exponent)
	} else {
		point := len(digits) + exponent
		if point > 0 {
			result = digits[:point] + "." + digits[point:]
		} else {
			result = "0." + strings.Repeat("0", -point) + digits
		}
	}
	if negative {
		result = "-" + result
	}
	return result, nil
}

func encodeValue(value any, depth int) ([]byte, error) {
	if depth > maxDepth {
		return nil, fail("nesting_too_deep")
	}
	switch item := value.(type) {
	case orderedObject:
		sort.Slice(item, func(i, j int) bool { return item[i].key < item[j].key })
		var b bytes.Buffer
		b.WriteByte('{')
		for i, pair := range item {
			if i > 0 {
				b.WriteByte(',')
			}
			b.Write(quoteJSONString(pair.key))
			b.WriteByte(':')
			encoded, err := encodeValue(pair.val, depth+1)
			if err != nil {
				return nil, err
			}
			b.Write(encoded)
		}
		b.WriteByte('}')
		return b.Bytes(), nil
	case []any:
		var b bytes.Buffer
		b.WriteByte('[')
		for i, child := range item {
			if i > 0 {
				b.WriteByte(',')
			}
			encoded, err := encodeValue(child, depth+1)
			if err != nil {
				return nil, err
			}
			b.Write(encoded)
		}
		b.WriteByte(']')
		return b.Bytes(), nil
	case string:
		return quoteJSONString(item), nil
	case json.Number:
		return []byte(item), nil
	case bool:
		if item {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case nil:
		return []byte("null"), nil
	default:
		return nil, fail("unsupported_value")
	}
}

func quoteJSONString(value string) []byte {
	var output bytes.Buffer
	output.WriteByte('"')
	for _, r := range value {
		switch r {
		case '"':
			output.WriteString(`\"`)
		case '\\':
			output.WriteString(`\\`)
		case '\b':
			output.WriteString(`\b`)
		case '\f':
			output.WriteString(`\f`)
		case '\n':
			output.WriteString(`\n`)
		case '\r':
			output.WriteString(`\r`)
		case '\t':
			output.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(&output, `\u%04x`, r)
			} else {
				output.WriteRune(r)
			}
		}
	}
	output.WriteByte('"')
	return output.Bytes()
}

func canonicalNative(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, fail("unsupported_value")
	}
	return CanonicalJSON(raw)
}

var (
	dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	numeric  = regexp.MustCompile(`^[0-9.]+$`)
	idna2008 = idna.New(
		idna.ValidateLabels(true),
		idna.StrictDomainName(true),
		idna.BidiRule(),
		idna.VerifyDNSLength(true),
	)
)

func URL(value string, additionalSensitive []string) (Prepared, error) {
	execution, err := canonicalURL(value, additionalSensitive, false)
	if err != nil {
		return Prepared{}, err
	}
	diagnostic, err := canonicalURL(value, additionalSensitive, true)
	if err != nil {
		return Prepared{}, err
	}
	executionPreimage, err := canonicalNative(map[string]any{
		"preimageType": "palonexus.url-execution", "preimageVersion": "1", "url": execution,
	})
	if err != nil {
		return Prepared{}, err
	}
	resource, err := canonicalNative(map[string]any{
		"executionHash": hashBytes(executionPreimage), "url": diagnostic,
	})
	if err != nil {
		return Prepared{}, err
	}
	return prepared(resource, execution)
}

func canonicalURL(raw string, additional []string, hide bool) (string, error) {
	raw, err := normalizeString(raw, "invalid_url")
	if err != nil {
		return "", err
	}
	if strings.Contains(raw, "\\") || hasControl(raw) {
		return "", fail("invalid_url")
	}
	parsed, parseErr := url.Parse(raw)
	if parseErr != nil || (parsed.Scheme != "http" && parsed.Scheme != "https" && strings.ToLower(parsed.Scheme) != "http" && strings.ToLower(parsed.Scheme) != "https") {
		return "", fail("unsupported_url_scheme")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if parsed.User != nil || strings.Contains(parsed.Host, "@") {
		return "", fail("url_userinfo")
	}
	if strings.ContainsAny(parsed.Host, "%[]") {
		return "", fail("invalid_url_host")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", fail("noncanonical_url_port")
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "" {
		return "", fail("missing_url_host")
	}
	if strings.HasSuffix(host, ".") {
		return "", fail("noncanonical_url_host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if strings.Contains(host, ":") {
			return "", fail("unsupported_ipv6")
		}
		if ip.String() != host {
			return "", fail("ambiguous_numeric_host")
		}
	} else {
		if numeric.MatchString(host) {
			return "", fail("ambiguous_numeric_host")
		}
		if len(host) > 253 {
			return "", fail("invalid_url_host")
		}
		for _, label := range strings.Split(host, ".") {
			if !dnsLabel.MatchString(label) {
				return "", fail("invalid_url_host")
			}
			if strings.HasPrefix(label, "xn--") {
				decoded, decodeErr := idna2008.ToUnicode(label)
				reencoded, encodeErr := idna2008.ToASCII(decoded)
				if (decodeErr != nil && !unicode151AssignedIDNALabel(decoded)) ||
					encodeErr != nil || strings.ToLower(reencoded) != label {
					return "", fail("invalid_url_host")
				}
			}
		}
	}
	port := parsed.Port()
	if port != "" {
		if len(port) > 1 && port[0] == '0' {
			return "", fail("noncanonical_url_port")
		}
		portNumber, portErr := strconv.Atoi(port)
		if portErr != nil || portNumber < 1 || portNumber > 65535 {
			return "", fail("invalid_url_port")
		}
		if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
			port = ""
		}
	}
	authority := host
	if port != "" {
		authority += ":" + port
	}
	normalizedPath, pathErr := normalizeURLPath(parsed.EscapedPath())
	if pathErr != nil {
		return "", pathErr
	}
	query, queryErr := normalizeQuery(parsed.RawQuery, additional, hide)
	if queryErr != nil {
		return "", queryErr
	}
	result := scheme + "://" + authority + normalizedPath
	if query != "" {
		result += "?" + query
	}
	return result, nil
}

// Go's x/net tables can lag the protocol-pinned Unicode 15.1 table. CJK
// Unified Ideographs Extension I is the only newly assigned IDNA PVALID range
// needed by the committed v1 vectors; permit it only after exact punycode
// decode/re-encode.
func unicode151AssignedIDNALabel(value string) bool {
	if value == "" {
		return false
	}
	hasExtensionI := false
	var compatible strings.Builder
	for _, r := range value {
		if r >= 0x2EBF0 && r <= 0x2EE5D {
			hasExtensionI = true
			// Extension-I scalars share the IDNA properties of established
			// unified ideographs. Substitute one only for x/net's context,
			// bidi, and label validation; exact original punycode round-trip
			// remains mandatory at the caller.
			compatible.WriteRune('中')
		} else {
			compatible.WriteRune(r)
		}
	}
	if !hasExtensionI {
		return false
	}
	_, err := idna2008.ToASCII(compatible.String())
	return err == nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return true
		}
	}
	return false
}

func normalizeURLPath(raw string) (string, error) {
	if raw == "" {
		return "/", nil
	}
	normalized, err := normalizePercent(raw, "/:@!$&'()*+,;=-._~")
	if err != nil {
		return "", err
	}
	segments := strings.Split(normalized, "/")
	stack := make([]string, 0, len(segments))
	for _, segment := range segments {
		switch segment {
		case ".":
			continue
		case "..":
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
		default:
			stack = append(stack, segment)
		}
	}
	result := strings.Join(stack, "/")
	if result == "" {
		return "/", nil
	}
	return result, nil
}

func normalizePercent(raw, safe string) (string, error) {
	var decoded strings.Builder
	for i := 0; i < len(raw); {
		if raw[i] != '%' {
			decoded.WriteByte(raw[i])
			i++
			continue
		}
		first, next, parseErr := percentByte(raw, i)
		if parseErr != nil {
			return "", parseErr
		}
		i = next
		if first < 0x80 {
			if first < 0x20 || first == 0x7f {
				return "", fail("invalid_url")
			}
			if strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~", rune(first)) {
				decoded.WriteByte(first)
			} else {
				fmt.Fprintf(&decoded, "%%%02X", first)
			}
			continue
		}
		width := utf8SequenceWidth(first)
		if width == 0 {
			return "", fail("invalid_url_utf8")
		}
		sequence := []byte{first}
		for len(sequence) < width {
			if i >= len(raw) || raw[i] != '%' {
				return "", fail("invalid_url_utf8")
			}
			item, following, itemErr := percentByte(raw, i)
			if itemErr != nil {
				return "", itemErr
			}
			sequence = append(sequence, item)
			i = following
		}
		if !utf8.Valid(sequence) {
			return "", fail("invalid_url_utf8")
		}
		decoded.Write(sequence)
	}
	value, err := normalizeString(decoded.String(), "invalid_url")
	if err != nil || hasControl(value) {
		return "", fail("invalid_url")
	}
	var output strings.Builder
	for _, r := range value {
		if r < 128 && (strings.ContainsRune(safe, r) || strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789", r) || r == '%') {
			output.WriteRune(r)
		} else {
			for _, b := range []byte(string(r)) {
				fmt.Fprintf(&output, "%%%02X", b)
			}
		}
	}
	return output.String(), nil
}

func percentByte(raw string, offset int) (byte, int, error) {
	if offset+2 >= len(raw) || raw[offset] != '%' {
		return 0, offset, fail("invalid_percent_encoding")
	}
	value, err := strconv.ParseUint(raw[offset+1:offset+3], 16, 8)
	if err != nil {
		return 0, offset, fail("invalid_percent_encoding")
	}
	return byte(value), offset + 3, nil
}

func utf8SequenceWidth(first byte) int {
	switch {
	case first >= 0xc2 && first <= 0xdf:
		return 2
	case first >= 0xe0 && first <= 0xef:
		return 3
	case first >= 0xf0 && first <= 0xf4:
		return 4
	default:
		return 0
	}
}

func sensitiveSet(additional []string) (map[string]struct{}, error) {
	defaults := []string{"access-key", "access-token", "api-key", "apikey", "authorization", "code", "cookie", "credential", "password", "proxy-authorization", "secret", "signature", "token"}
	result := map[string]struct{}{}
	for _, name := range append(defaults, additional...) {
		normalized, err := normalizeString(name, "invalid_sensitive_name")
		if err != nil {
			return nil, err
		}
		normalized = strings.ReplaceAll(strings.ToLower(strings.TrimLeft(strings.TrimSpace(normalized), "-")), "_", "-")
		if len(normalized) < 1 || len(normalized) > 64 {
			return nil, fail("invalid_sensitive_name")
		}
		for _, r := range normalized {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return nil, fail("invalid_sensitive_name")
			}
		}
		result[normalized] = struct{}{}
	}
	return result, nil
}

func normalizeQuery(raw string, additional []string, hide bool) (string, error) {
	names, err := sensitiveSet(additional)
	if err != nil {
		return "", err
	}
	type pair struct {
		key, value string
		index      int
	}
	var pairs []pair
	if raw != "" {
		for index, field := range strings.Split(raw, "&") {
			if field == "" {
				continue
			}
			keyRaw, valueRaw, _ := strings.Cut(field, "=")
			keyRaw = strings.ReplaceAll(keyRaw, "+", " ")
			valueRaw = strings.ReplaceAll(valueRaw, "+", " ")
			key, keyErr := normalizePercent(keyRaw, "-._~")
			value, valueErr := normalizePercent(valueRaw, "-._~")
			if keyErr != nil || valueErr != nil {
				return "", fail("invalid_url_utf8")
			}
			decodedKey, _ := url.PathUnescape(key)
			normalizedName := strings.ReplaceAll(strings.ToLower(decodedKey), "_", "-")
			if _, secret := names[normalizedName]; hide && secret {
				value = "%5BREDACTED%5D"
			}
			pairs = append(pairs, pair{key, value, index})
		}
	}
	sort.SliceStable(pairs, func(i, j int) bool {
		ki, _ := url.PathUnescape(pairs[i].key)
		kj, _ := url.PathUnescape(pairs[j].key)
		return ki < kj
	})
	rendered := make([]string, len(pairs))
	for i, pair := range pairs {
		rendered[i] = pair.key + "=" + pair.value
	}
	return strings.Join(rendered, "&"), nil
}

func Shell(command string, additional []string) (Prepared, error) {
	command, err := normalizeString(command, "invalid_shell_command")
	if err != nil {
		return Prepared{}, err
	}
	names, err := sensitiveSet(additional)
	if err != nil {
		return Prepared{}, err
	}
	tokens, tokenErr := tokenizeShell(command)
	if tokenErr != nil {
		tokens = []string{"[UNPARSEABLE]"}
	} else {
		tokens = redactShellTokens(tokens, names)
	}
	resource, err := canonicalNative(map[string]any{
		"commandHash": hashBytes([]byte(command)), "tokens": tokens,
	})
	if err != nil {
		return Prepared{}, err
	}
	return prepared(resource, command)
}

// tokenizeShell performs only POSIX quote/escape/whitespace tokenization.
// It deliberately does not recognize comments, operators, variables, globs,
// substitutions, or any other executable shell grammar.
func tokenizeShell(command string) ([]string, error) {
	var tokens []string
	var current strings.Builder
	inSingle, inDouble, escaped, escapedInDouble, started := false, false, false, false, false
	for _, r := range command {
		if escaped {
			if escapedInDouble && r != '"' && r != '\\' {
				current.WriteByte('\\')
			}
			current.WriteRune(r)
			escaped = false
			escapedInDouble = false
			started = true
			continue
		}
		switch {
		case inSingle:
			if r == '\'' {
				inSingle = false
			} else {
				current.WriteRune(r)
			}
			started = true
		case inDouble:
			switch r {
			case '"':
				inDouble = false
			case '\\':
				escaped = true
				escapedInDouble = true
			default:
				current.WriteRune(r)
			}
			started = true
		default:
			switch {
			case r == '\\':
				escaped = true
				started = true
			case r == '\'':
				inSingle = true
				started = true
			case r == '"':
				inDouble = true
				started = true
			case r == ' ' || r == '\t' || r == '\r' || r == '\n':
				if started {
					tokens = append(tokens, current.String())
					current.Reset()
					started = false
				}
			default:
				current.WriteRune(r)
				started = true
			}
		}
	}
	if escaped || inSingle || inDouble {
		return nil, fail("invalid_shell_syntax")
	}
	if started {
		tokens = append(tokens, current.String())
	}
	return tokens, nil
}

func redactShellTokens(tokens []string, names map[string]struct{}) []string {
	output := make([]string, 0, len(tokens)+1)
	redactNext := false
	headerNext := false
	for _, token := range tokens {
		if redactNext || headerNext {
			output = append(output, redacted)
			redactNext, headerNext = false, false
			continue
		}
		if token == "-H" || token == "--header" {
			output = append(output, token)
			headerNext = true
			continue
		}
		if strings.HasPrefix(token, "--header=") {
			output = append(output, "--header="+redacted)
			continue
		}
		if strings.HasPrefix(token, "-H") && len(token) > 2 {
			output = append(output, "-H"+redacted)
			continue
		}
		name, value, assignment := strings.Cut(token, "=")
		normalizedName := strings.ReplaceAll(strings.ToLower(strings.TrimLeft(name, "-")), "_", "-")
		if _, secret := names[normalizedName]; secret {
			if assignment {
				output = append(output, name+"="+redacted)
			} else {
				output = append(output, token)
				redactNext = true
			}
			continue
		}
		if strings.HasPrefix(strings.ToLower(token), "http://") || strings.HasPrefix(strings.ToLower(token), "https://") {
			sensitive := make([]string, 0, len(names))
			for item := range names {
				sensitive = append(sensitive, item)
			}
			safe, err := canonicalURL(token, sensitive, true)
			if err != nil {
				output = append(output, "[URL]")
			} else {
				output = append(output, safe)
			}
			continue
		}
		lower := strings.ToLower(token)
		if strings.HasPrefix(lower, "authorization:") || strings.HasPrefix(lower, "cookie:") || strings.HasPrefix(lower, "proxy-authorization:") || strings.HasPrefix(lower, "set-cookie:") {
			prefix, _, _ := strings.Cut(token, ":")
			output = append(output, strings.TrimSpace(prefix)+": "+redacted)
			continue
		}
		_ = value
		output = append(output, token)
	}
	if redactNext || headerNext {
		output = append(output, redacted)
	}
	return output
}

func MCPJSON(server, tool string, input []byte) (Prepared, error) {
	server, err := normalizeString(server, "invalid_mcp_name")
	if err != nil {
		return Prepared{}, err
	}
	tool, err = normalizeString(tool, "invalid_mcp_name")
	if err != nil {
		return Prepared{}, err
	}
	validName := regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	if !validName.MatchString(server) || !validName.MatchString(tool) {
		return Prepared{}, fail("invalid_mcp_name")
	}
	canonical, err := CanonicalJSON(input)
	if err != nil {
		return Prepared{}, err
	}
	var executionInput any
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if err := decoder.Decode(&executionInput); err != nil {
		return Prepared{}, fail("invalid_json")
	}
	return prepared(
		[]byte("mcp:"+server+"/"+tool+"#"+hashBytes(canonical)),
		MCPExecution{Server: server, Tool: tool, Input: executionInput},
	)
}
