package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func validConfig(endpoint string) string {
	return `{
		"decision_endpoint": "` + endpoint + `",
		"oidc_issuer": "https://identity.example.com",
		"trusted_ca_file": "",
		"local_test_mode": false,
		"routes": [{"target":"api.example.com","decision_endpoint":"https://decision.example.com"}]
	}`
}

func testCertificatePEM(t *testing.T) []byte {
	return testCertificateWithUsagePEM(t, true, x509.KeyUsageCertSign)
}

func testCertificateWithUsagePEM(t *testing.T, isCA bool, usage x509.KeyUsage) []byte {
	return testCertificatePEMOptions(t, isCA, true, usage)
}

func testCertificatePEMOptions(
	t *testing.T,
	isCA bool,
	basicConstraintsValid bool,
	usage x509.KeyUsage,
) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "test CA " + serial.String()},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  isCA,
		BasicConstraintsValid: basicConstraintsValid,
		KeyUsage:              usage,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestLoadAcceptsHTTPSAndReturnsImmutableCopies(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig("https://decision.example.com")), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.DecisionEndpoint(); got != "https://decision.example.com" {
		t.Fatalf("endpoint = %q", got)
	}
	routes := cfg.Routes()
	routes[0].Target = "changed.example.com"
	if got := cfg.Routes()[0].Target; got != "api.example.com" {
		t.Fatalf("caller mutated loaded config: %q", got)
	}
}

func TestLoadRetainsProductionIdentityAndSecurityDigestIncludesCABytes(t *testing.T) {
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, testCertificatePEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(
		validConfig("https://decision.example.com"),
		`"trusted_ca_file": ""`,
		`"trusted_ca_file": "`+ca+`",
		"tenant_id":"tenant-a",
		"account_id":"account-a",
		"client_id":"codex",
		"state_dir":"/var/lib/palonexus-state"`,
		1,
	)
	cfg, err := Load(writeConfig(t, body), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TenantID() != "tenant-a" || cfg.AccountID() != "account-a" ||
		cfg.ClientID() != "codex" || cfg.StateDir() != "/var/lib/palonexus-state" {
		t.Fatalf("identity configuration not retained")
	}
	before := cfg.Digest()
	mutated := append([]byte(nil), testCertificatePEM(t)...)
	if err := os.WriteFile(ca, mutated, 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := Load(writeConfig(t, strings.Replace(body, ca, ca, 1)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if before == after.Digest() {
		t.Fatal("trusted CA bytes were omitted from security digest")
	}
}

func TestLoadRejectsNonHTTPSEndpoints(t *testing.T) {
	for _, endpoint := range []string{
		"http://decision.example.com",
		"ftp://decision.example.com",
		"//decision.example.com",
		"https://user:secret@decision.example.com",
	} {
		t.Run(endpoint, func(t *testing.T) {
			_, err := Load(writeConfig(t, validConfig(endpoint)), Options{})
			if err == nil {
				t.Fatal("expected rejection")
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaked URL credentials: %v", err)
			}
		})
	}
}

func TestLocalHTTPRequiresConfigAndRuntimeOptInAndLoopback(t *testing.T) {
	body := strings.Replace(validConfig("http://127.0.0.1:8181"), `"local_test_mode": false`, `"local_test_mode": true`, 1)
	if _, err := Load(writeConfig(t, body), Options{}); err == nil {
		t.Fatal("config alone must not enable local HTTP")
	}
	cfg, err := Load(writeConfig(t, body), Options{AllowLocalTestMode: true})
	if err != nil {
		t.Fatalf("explicit local mode: %v", err)
	}
	if !cfg.LocalTestMode() {
		t.Fatal("local mode not retained")
	}

	remote := strings.Replace(body, "127.0.0.1", "192.0.2.1", 1)
	if _, err := Load(writeConfig(t, remote), Options{AllowLocalTestMode: true}); err == nil {
		t.Fatal("local mode must not permit remote plaintext endpoints")
	}

	localhost := strings.Replace(body, "127.0.0.1", "localhost", 1)
	if _, err := Load(writeConfig(t, localhost), Options{AllowLocalTestMode: true}); err == nil {
		t.Fatal("local mode must require an IP literal")
	}
	for _, endpoint := range []string{"http://127.7.8.9:8181", "http://[::1]:8181"} {
		candidate := strings.Replace(body, "http://127.0.0.1:8181", endpoint, 1)
		if _, err := Load(writeConfig(t, candidate), Options{AllowLocalTestMode: true}); err != nil {
			t.Fatalf("loopback literal %q rejected: %v", endpoint, err)
		}
	}
}

func TestLoadRejectsUnknownDuplicateAndMalformedJSON(t *testing.T) {
	cases := []string{
		`{"decision_endpoint":"https://a.example","oidc_issuer":"https://i.example","unknown":true}`,
		`{"decision_endpoint":"https://a.example","decision_endpoint":"https://b.example","oidc_issuer":"https://i.example"}`,
		`{"decision_endpoint":"https://a.example",`,
	}
	for _, body := range cases {
		if _, err := Load(writeConfig(t, body), Options{}); err == nil {
			t.Fatalf("accepted invalid config: %s", body)
		}
	}
}

func TestLoadValidatesTrustedCA(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	original := testCertificatePEM(t)
	if err := os.WriteFile(ca, original, 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(validConfig("https://decision.example.com"), `"trusted_ca_file": ""`, `"trusted_ca_file": "`+ca+`"`, 1)
	cfg, err := Load(writeConfig(t, body), Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := cfg.TrustedCAPEM()
	if string(got) != string(original) {
		t.Fatal("loaded CA material differs")
	}
	got[0] ^= 0xff
	if string(cfg.TrustedCAPEM()) != string(original) {
		t.Fatal("caller mutated retained CA material")
	}

	if err := os.Chmod(ca, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(writeConfig(t, body), Options{}); err == nil {
		t.Fatal("accepted group/world-writable CA")
	}
}

func TestLoadRejectsEmptyAndMalformedTrustedCA(t *testing.T) {
	for _, data := range [][]byte{
		nil,
		[]byte("not PEM"),
		[]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}),
	} {
		ca := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(ca, data, 0o600); err != nil {
			t.Fatal(err)
		}
		body := strings.Replace(validConfig("https://decision.example.com"), `"trusted_ca_file": ""`, `"trusted_ca_file": "`+ca+`"`, 1)
		if _, err := Load(writeConfig(t, body), Options{}); err == nil {
			t.Fatal("accepted invalid CA material")
		}
	}
}

func TestLoadRejectsJunkAndNonCATrustAnchors(t *testing.T) {
	valid := testCertificatePEM(t)
	leaf := testCertificateWithUsagePEM(t, false, x509.KeyUsageDigitalSignature)
	caWithoutBasicConstraints := testCertificatePEMOptions(t, true, false, x509.KeyUsageCertSign)
	caWithoutSigningUsage := testCertificateWithUsagePEM(t, true, x509.KeyUsageDigitalSignature)
	cases := [][]byte{
		append([]byte("junk-prefix"), valid...),
		append(append(append([]byte(nil), valid...), []byte("\ninter-block-junk\n")...), valid...),
		leaf,
		caWithoutBasicConstraints,
		caWithoutSigningUsage,
		append(append([]byte(nil), valid...), leaf...),
	}
	for _, data := range cases {
		ca := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(ca, data, 0o600); err != nil {
			t.Fatal(err)
		}
		body := strings.Replace(validConfig("https://decision.example.com"), `"trusted_ca_file": ""`, `"trusted_ca_file": "`+ca+`"`, 1)
		if _, err := Load(writeConfig(t, body), Options{}); err == nil {
			t.Fatal("accepted invalid trust-anchor bundle")
		}
	}
}

func TestLoadAcceptsWhitespaceSeparatedMultipleCAsConsumableByCertPool(t *testing.T) {
	first := testCertificatePEM(t)
	second := testCertificateWithUsagePEM(t, true, 0)
	bundle := append(append(append([]byte(" \n\t"), first...), []byte("\n\n")...), second...)
	bundle = append(bundle, []byte(" \n")...)
	ca := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(ca, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(validConfig("https://decision.example.com"), `"trusted_ca_file": ""`, `"trusted_ca_file": "`+ca+`"`, 1)
	cfg, err := Load(writeConfig(t, body), Options{})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(cfg.TrustedCAPEM()) {
		t.Fatal("retained CA material cannot populate a fresh CertPool")
	}
}

func TestLoadedTrustedCAIsIndependentOfPathReplacement(t *testing.T) {
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.pem")
	original := testCertificatePEM(t)
	if err := os.WriteFile(ca, original, 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(validConfig("https://decision.example.com"), `"trusted_ca_file": ""`, `"trusted_ca_file": "`+ca+`"`, 1)
	cfg, err := Load(writeConfig(t, body), Options{})
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.pem")
	if err := os.WriteFile(replacement, []byte("attacker bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(ca, ca+".old"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, ca); err != nil {
		t.Fatal(err)
	}
	if string(cfg.TrustedCAPEM()) != string(original) {
		t.Fatal("retained CA followed replaced path")
	}
}

func TestLoadRejectsAmbiguousEndpointAuthoritiesAndPorts(t *testing.T) {
	endpoints := []string{
		"https://:443",
		"https://example.com:",
		"https://example.com:notaport",
		"https://example.com:0",
		"https://example.com:65536",
		"https://%65xample.com",
		"https://example.com%0a.evil",
		"https://example.com/\x00",
	}
	for _, endpoint := range endpoints {
		t.Run(endpoint, func(t *testing.T) {
			if _, err := Load(writeConfig(t, validConfig(endpoint)), Options{}); err == nil {
				t.Fatal("accepted ambiguous endpoint")
			}
		})
	}
}

func TestLoadRejectsUnsafeConfigPermissionsAndSymlinks(t *testing.T) {
	path := writeConfig(t, validConfig("https://decision.example.com"))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path, Options{}); err == nil {
		t.Fatal("accepted config readable by other users")
	}

	target := writeConfig(t, validConfig("https://decision.example.com"))
	link := filepath.Join(t.TempDir(), "config-link")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skip("symlink creation unavailable")
		}
		t.Fatal(err)
	}
	if _, err := Load(link, Options{}); err == nil {
		t.Fatal("accepted symlink config")
	}
}

func TestLoadRejectsTrailingJSON(t *testing.T) {
	path := writeConfig(t, validConfig("https://decision.example.com")+"\n{}")
	if _, err := Load(path, Options{}); err == nil {
		t.Fatal("accepted multiple JSON values")
	}
}

func TestLoadUsesRoutingGrammarAndRejectsAmbiguity(t *testing.T) {
	wildcard := strings.Replace(validConfig("https://decision.example.com"), `"target":"api.example.com"`, `"target":"*.example.com"`, 1)
	if _, err := Load(writeConfig(t, wildcard), Options{}); err != nil {
		t.Fatalf("wildcard route rejected: %v", err)
	}

	ambiguous := strings.Replace(
		validConfig("https://decision.example.com"),
		`{"target":"api.example.com","decision_endpoint":"https://decision.example.com"}`,
		`{"target":"API.example.com","decision_endpoint":"https://decision.example.com"},{"target":"api.example.com.","decision_endpoint":"https://other.example.com"}`,
		1,
	)
	if _, err := Load(writeConfig(t, ambiguous), Options{}); err == nil {
		t.Fatal("accepted ambiguous normalized routes")
	}
}
