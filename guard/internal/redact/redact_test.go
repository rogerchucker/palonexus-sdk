// SPDX-License-Identifier: MIT
package redact

import (
	"strings"
	"testing"
)

func TestTextRedactsCredentialsDeterministically(t *testing.T) {
	t.Parallel()
	input := "Authorization: Bearer raw-secret token=raw-secret password: raw-secret https://example.com/?api_key=raw-secret"
	got := Text(input)
	if strings.Contains(got, "raw-secret") {
		t.Fatalf("secret leaked: %s", got)
	}
	if got != Text(got) {
		t.Fatal("redaction is not idempotent")
	}
}

func TestErrorNeverReflectsRawValue(t *testing.T) {
	t.Parallel()
	err := Error("invalid credential", "raw-secret")
	if strings.Contains(err.Error(), "raw-secret") || err.Error() != "invalid credential" {
		t.Fatalf("unsafe error: %v", err)
	}
}
