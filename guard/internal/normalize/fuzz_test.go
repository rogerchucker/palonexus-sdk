// SPDX-License-Identifier: MIT
package normalize

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
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
	f.Fuzz(func(t *testing.T, prefixInput, secretInput string) {
		prefix := "prefix-" + hex.EncodeToString([]byte(prefixInput))
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
		serialized, marshalErr := json.Marshal(got)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		diagnostic := string(serialized) + fmt.Sprintf("%v %#v", got, got)
		if strings.Contains(diagnostic, secret) {
			t.Fatal("structured diagnostic reflected secret")
		}
	})
}

func FuzzShellRedactionRetainsCollisionBinding(f *testing.F) {
	f.Add([]byte("alpha"), []byte("bravo"))
	f.Fuzz(func(t *testing.T, leftInput, rightInput []byte) {
		leftSecret := "pnx-left-" + hex.EncodeToString(leftInput)
		rightSecret := "pnx-right-" + hex.EncodeToString(rightInput)
		if len(leftSecret)+len(rightSecret) > MaxStringBytes {
			return
		}
		left, leftErr := Shell("deploy --token "+leftSecret, nil)
		right, rightErr := Shell("deploy --token "+rightSecret, nil)
		if leftErr != nil || rightErr != nil {
			t.Fatalf("bounded ASCII secrets failed normalization")
		}
		if left.Resource == right.Resource {
			t.Fatal("different executions collided after redaction")
		}
		var leftResource, rightResource struct {
			Tokens []string `json:"tokens"`
		}
		if json.Unmarshal([]byte(left.Resource), &leftResource) != nil ||
			json.Unmarshal([]byte(right.Resource), &rightResource) != nil {
			t.Fatal("invalid shell resources")
		}
		if fmt.Sprint(leftResource.Tokens) != fmt.Sprint(rightResource.Tokens) {
			t.Fatal("secret values changed redacted diagnostics")
		}
	})
}
