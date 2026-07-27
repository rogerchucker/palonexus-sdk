// SPDX-License-Identifier: MIT
package normalize

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func FuzzCanonicalJSON(f *testing.F) {
	f.Add([]byte(`{"a":"Café","n":1.0}`))
	f.Add([]byte(`{"e\u0301":1,"é":2}`))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, input []byte) {
		output, err := CanonicalJSON(input)
		if err != nil {
			if len(err.Error()) > 128 {
				t.Fatal("unbounded error")
			}
			return
		}
		if len(output) > MaxJSONBytes {
			t.Fatal("unbounded canonical output")
		}
		again, err := CanonicalJSON(output)
		if err != nil || string(again) != string(output) {
			t.Fatalf("canonicalization is not idempotent")
		}
	})
}

func FuzzShellNoSecretReflection(f *testing.F) {
	f.Add("echo ok", "raw-secret")
	f.Add("curl --token raw-secret", "raw-secret")
	f.Fuzz(func(t *testing.T, prefix, secretInput string) {
		secret := "pnx-secret-" + hex.EncodeToString([]byte(secretInput))
		if len(prefix)+len(secret) > MaxStringBytes {
			return
		}
		command := prefix + " --token " + secret
		got, err := Shell(command, nil)
		if err != nil {
			if strings.Contains(err.Error(), secret) {
				t.Fatal("error reflected secret")
			}
			return
		}
		var resource struct {
			Tokens []string `json:"tokens"`
		}
		if json.Unmarshal([]byte(got.Resource), &resource) != nil {
			t.Fatal("resource is not valid JSON")
		}
		for index, token := range resource.Tokens {
			if token == "--token" && (index+1 >= len(resource.Tokens) || resource.Tokens[index+1] != redacted) {
				t.Fatal("sensitive option value was not redacted")
			}
			if strings.HasPrefix(token, "--token=") && token != "--token="+redacted {
				t.Fatal("inline sensitive option value was not redacted")
			}
		}
		if len(got.Resource) > MaxJSONBytes {
			t.Fatal("unbounded resource")
		}
	})
}
