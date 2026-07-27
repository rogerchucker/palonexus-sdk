// Package routing compiles configured target patterns into a deterministic,
// fail-closed lookup table.
package routing

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

var (
	ErrAmbiguousRoute = errors.New("ambiguous route")
	ErrInvalidTarget  = errors.New("invalid target")
	ErrUnknownTarget  = errors.New("unknown target")
)

// Route maps a normalized target or wildcard target to a destination.
type Route struct {
	Target      string
	Destination string
}

// Table is immutable after construction.
type Table struct {
	exact     map[string]Route
	wildcards []compiledWildcard
}

type compiledWildcard struct {
	suffix string
	route  Route
}

// New validates and compiles routes. Duplicate normalized patterns are
// rejected even when their destinations happen to agree.
func New(routes []Route) (*Table, error) {
	table := &Table{exact: make(map[string]Route)}
	seen := make(map[string]struct{}, len(routes))
	for _, route := range routes {
		pattern, wildcard, err := normalizePattern(route.Target)
		if err != nil || route.Destination == "" {
			return nil, ErrInvalidTarget
		}
		if _, exists := seen[pattern]; exists {
			return nil, ErrAmbiguousRoute
		}
		seen[pattern] = struct{}{}
		route.Target = pattern
		if wildcard {
			table.wildcards = append(table.wildcards, compiledWildcard{
				suffix: strings.TrimPrefix(pattern, "*"),
				route:  route,
			})
		} else {
			table.exact[pattern] = route
		}
	}
	sort.Slice(table.wildcards, func(i, j int) bool {
		if len(table.wildcards[i].suffix) != len(table.wildcards[j].suffix) {
			return len(table.wildcards[i].suffix) > len(table.wildcards[j].suffix)
		}
		return table.wildcards[i].suffix < table.wildcards[j].suffix
	})
	return table, nil
}

// Resolve returns the exact route, then the most-specific matching wildcard.
func (t *Table) Resolve(target string) (Route, error) {
	normalized, err := NormalizeTarget(target)
	if err != nil {
		return Route{}, ErrInvalidTarget
	}
	if route, ok := t.exact[normalized]; ok {
		return route, nil
	}
	for _, candidate := range t.wildcards {
		if strings.HasSuffix(normalized, candidate.suffix) &&
			len(normalized) > len(candidate.suffix) {
			return candidate.route, nil
		}
	}
	return Route{}, ErrUnknownTarget
}

// NormalizeTarget normalizes an ASCII DNS target. URL, path, port, wildcard,
// control-character, and non-DNS inputs are rejected.
func NormalizeTarget(target string) (string, error) {
	if target == "" || target != strings.TrimSpace(target) {
		return "", ErrInvalidTarget
	}
	target = strings.ToLower(strings.TrimSuffix(target, "."))
	if len(target) == 0 || len(target) > 253 || strings.ContainsAny(target, ":/\\\x00") {
		return "", ErrInvalidTarget
	}
	labels := strings.Split(target, ".")
	if len(labels) < 2 {
		return "", ErrInvalidTarget
	}
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 ||
			label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrInvalidTarget
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return "", ErrInvalidTarget
			}
		}
	}
	return target, nil
}

func normalizePattern(pattern string) (normalized string, wildcard bool, err error) {
	if strings.HasPrefix(pattern, "*.") {
		suffix, normalizeErr := NormalizeTarget(strings.TrimPrefix(pattern, "*."))
		if normalizeErr != nil || !strings.Contains(suffix, ".") {
			return "", false, ErrInvalidTarget
		}
		return "*." + suffix, true, nil
	}
	if strings.Contains(pattern, "*") {
		return "", false, ErrInvalidTarget
	}
	normalized, err = NormalizeTarget(pattern)
	if err != nil {
		return "", false, fmt.Errorf("%w", ErrInvalidTarget)
	}
	return normalized, false, nil
}
