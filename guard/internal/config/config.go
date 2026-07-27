// Package config loads the guard's strict, immutable JSON configuration.
package config

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/rogerchucker/palonexus-sdk/guard/internal/routing"
)

const maxConfigBytes = 1 << 20

// Options contains process-owned security opt-ins. Local test mode requires
// both this opt-in and local_test_mode in the file.
type Options struct {
	AllowLocalTestMode bool
}

// Route is a configured target-to-decision-endpoint mapping.
type Route struct {
	Target           string `json:"target"`
	DecisionEndpoint string `json:"decision_endpoint"`
}

type fileConfig struct {
	DecisionEndpoint string  `json:"decision_endpoint"`
	OIDCIssuer       string  `json:"oidc_issuer"`
	TrustedCAFile    string  `json:"trusted_ca_file"`
	LocalTestMode    bool    `json:"local_test_mode"`
	Routes           []Route `json:"routes"`
}

// Config exposes immutable values through accessors. Slices are copied.
type Config struct {
	decisionEndpoint string
	oidcIssuer       string
	trustedCAPEM     []byte
	localTestMode    bool
	routes           []Route
}

func (c *Config) DecisionEndpoint() string { return c.decisionEndpoint }
func (c *Config) OIDCIssuer() string       { return c.oidcIssuer }
func (c *Config) LocalTestMode() bool      { return c.localTestMode }
func (c *Config) Routes() []Route          { return append([]Route(nil), c.routes...) }

// TrustedCAPEM returns a defensive copy of CA certificates read from the
// securely validated descriptor. TLS consumers must use this retained material
// rather than reopening the configured path.
func (c *Config) TrustedCAPEM() []byte { return append([]byte(nil), c.trustedCAPEM...) }

// Load securely opens, validates, and decodes a configuration file.
//
// Supported release platforms are Unix-like. O_NOFOLLOW plus validation of the
// opened inode prevents final-component symlink substitution. Complete
// protection against privileged parent-directory replacement requires
// platform-specific openat2-style APIs and is outside this file's boundary;
// callers must place configuration beneath a user-owned, non-writable-by-others
// directory.
func Load(path string, options Options) (*Config, error) {
	data, err := readValidatedFile(path, fileKindConfig)
	if err != nil {
		return nil, fmt.Errorf("load config: %w", err)
	}
	if err := rejectDuplicateKeys(data); err != nil {
		return nil, errors.New("load config: invalid JSON structure")
	}

	var raw fileConfig
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return nil, errors.New("load config: invalid JSON")
	}
	if err := requireEOF(decoder); err != nil {
		return nil, errors.New("load config: trailing JSON")
	}

	localAllowed := raw.LocalTestMode && options.AllowLocalTestMode
	if raw.LocalTestMode != localAllowed {
		return nil, errors.New("load config: local test mode requires explicit runtime opt-in")
	}
	if err := validateEndpoint(raw.DecisionEndpoint, localAllowed); err != nil {
		return nil, errors.New("load config: invalid decision endpoint")
	}
	if err := validateEndpoint(raw.OIDCIssuer, localAllowed); err != nil {
		return nil, errors.New("load config: invalid OIDC issuer")
	}
	compiledRoutes := make([]routing.Route, 0, len(raw.Routes))
	for _, route := range raw.Routes {
		if err := validateEndpoint(route.DecisionEndpoint, localAllowed); err != nil {
			return nil, errors.New("load config: invalid route endpoint")
		}
		compiledRoutes = append(compiledRoutes, routing.Route{
			Target:      route.Target,
			Destination: route.DecisionEndpoint,
		})
	}
	if _, err := routing.New(compiledRoutes); err != nil {
		return nil, errors.New("load config: invalid or ambiguous routes")
	}
	var trustedCAPEM []byte
	if raw.TrustedCAFile != "" {
		trustedCAPEM, err = readValidatedFile(raw.TrustedCAFile, fileKindCA)
		if err != nil {
			return nil, fmt.Errorf("load config: invalid trusted CA: %w", err)
		}
		if err := validateCertificates(trustedCAPEM); err != nil {
			return nil, errors.New("load config: invalid trusted CA material")
		}
	}

	return &Config{
		decisionEndpoint: raw.DecisionEndpoint,
		oidcIssuer:       raw.OIDCIssuer,
		trustedCAPEM:     append([]byte(nil), trustedCAPEM...),
		localTestMode:    localAllowed,
		routes:           append([]Route(nil), raw.Routes...),
	}, nil
}

func validateEndpoint(raw string, localAllowed bool) error {
	for _, character := range raw {
		if character <= 0x1f || character == 0x7f {
			return errors.New("invalid endpoint")
		}
	}
	parsed, err := url.Parse(raw)
	if err != nil || !parsed.IsAbs() || parsed.Opaque != "" ||
		parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("invalid endpoint")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return errors.New("invalid endpoint")
	}
	if port := parsed.Port(); port != "" {
		number, portErr := strconv.Atoi(port)
		if portErr != nil || number < 1 || number > 65535 {
			return errors.New("invalid endpoint")
		}
	}
	if parsed.Scheme == "https" {
		return nil
	}
	if parsed.Scheme != "http" || !localAllowed {
		return errors.New("TLS required")
	}
	host := parsed.Hostname()
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("local endpoint required")
	}
	return nil
}

func validateCertificates(data []byte) error {
	rest := data
	count := 0
	for len(bytes.TrimSpace(rest)) != 0 {
		rest = bytes.TrimSpace(rest)
		if !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return errors.New("unexpected data outside certificate PEM")
		}
		block, remaining := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return errors.New("invalid certificate PEM")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errors.New("invalid X.509 certificate")
		}
		if !certificate.BasicConstraintsValid || !certificate.IsCA {
			return errors.New("certificate is not a CA")
		}
		if certificate.KeyUsage != 0 && certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return errors.New("certificate cannot sign certificates")
		}
		count++
		rest = remaining
	}
	if count == 0 {
		return errors.New("no certificates")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		return errors.New("certificate bundle is unusable")
	}
	return nil
}

type fileKind uint8

const (
	fileKindConfig fileKind = iota
	fileKindCA
)

func readValidatedFile(path string, kind fileKind) ([]byte, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("secure configuration reads are unsupported on this platform")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("secure file open failed")
	}
	file := os.NewFile(uintptr(fd), "validated-file")
	defer file.Close()

	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, errors.New("file is not regular")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() {
		return nil, errors.New("file owner is unsafe")
	}
	permissions := info.Mode().Perm()
	if kind == fileKindConfig && permissions&0o077 != 0 {
		return nil, errors.New("config permissions are unsafe")
	}
	if kind == fileKindCA && permissions&0o022 != 0 {
		return nil, errors.New("trusted CA permissions are unsafe")
	}
	reader := io.LimitReader(file, maxConfigBytes+1)
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, errors.New("file read failed")
	}
	if len(data) > maxConfigBytes {
		return nil, errors.New("file is too large")
	}
	return data, nil
}

func requireEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("additional JSON value")
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var walk func() error
	walk = func() error {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		delimiter, isDelimiter := token.(json.Delim)
		if !isDelimiter {
			return nil
		}
		switch delimiter {
		case '{':
			seen := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("non-string object key")
				}
				if _, exists := seen[key]; exists {
					return errors.New("duplicate object key")
				}
				seen[key] = struct{}{}
				if err := walk(); err != nil {
					return err
				}
			}
		case '[':
			for decoder.More() {
				if err := walk(); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := walk(); err != nil {
		return err
	}
	return requireEOF(decoder)
}
