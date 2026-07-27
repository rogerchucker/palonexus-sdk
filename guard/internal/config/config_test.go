package config

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
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
	if err := os.WriteFile(ca, []byte("not-secret-ca-data"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(validConfig("https://decision.example.com"), `"trusted_ca_file": ""`, `"trusted_ca_file": "`+ca+`"`, 1)
	cfg, err := Load(writeConfig(t, body), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.TrustedCAFile() != ca {
		t.Fatalf("CA path = %q", cfg.TrustedCAFile())
	}

	if err := os.Chmod(ca, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(writeConfig(t, body), Options{}); err == nil {
		t.Fatal("accepted group/world-writable CA")
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
