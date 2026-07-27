// SPDX-License-Identifier: MIT
// Package redact provides log-safe, best-effort removal of common credentials.
// Callers must still avoid passing raw action input to logs.
package redact

import (
	"errors"
	"regexp"
	"strings"
)

const Replacement = "[REDACTED]"

var credentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(authorization\s*:\s*)(?:bearer\s+)?[^\s,;]+`),
	regexp.MustCompile(`(?i)\b(access[_-]?key|access[_-]?token|api[_-]?key|apikey|authorization|code|cookie|credential|password|proxy-authorization|secret|signature|token)(\s*[:=]\s*)[^\s&,;]+`),
	regexp.MustCompile(`(?i)([?&](?:access[_-]?key|access[_-]?token|api[_-]?key|apikey|authorization|code|credential|password|secret|signature|token)=)[^&#\s]*`),
}

// Text returns a deterministic, idempotent diagnostic string. It is a safety
// backstop, not a reason to log raw inputs in the first place.
func Text(value string) string {
	result := value
	for _, pattern := range credentialPatterns {
		result = pattern.ReplaceAllStringFunc(result, func(match string) string {
			if strings.Contains(match, Replacement) {
				return match
			}
			index := strings.LastIndexAny(match, ":=")
			if index < 0 {
				return Replacement
			}
			return match[:index+1] + Replacement
		})
	}
	return result
}

// Error deliberately ignores unsafe detail and returns only a caller-owned
// fixed message.
func Error(message string, _ ...string) error {
	return errors.New(Text(message))
}
