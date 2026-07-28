package routing

import (
	"errors"
	"testing"
)

func TestResolveUsesExactBeforeMostSpecificWildcard(t *testing.T) {
	table, err := New([]Route{
		{Target: "*.example.com", Destination: "general"},
		{Target: "*.svc.example.com", Destination: "service"},
		{Target: "api.svc.example.com", Destination: "exact"},
	})
	if err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]string{
		"API.SVC.EXAMPLE.COM.": "exact",
		"job.svc.example.com":  "service",
		"www.example.com":      "general",
	} {
		got, err := table.Resolve(target)
		if err != nil {
			t.Fatalf("Resolve(%q): %v", target, err)
		}
		if got.Destination != want {
			t.Fatalf("Resolve(%q) = %q, want %q", target, got.Destination, want)
		}
	}
}

func TestNewRejectsAmbiguousNormalizedRoutes(t *testing.T) {
	for _, routes := range [][]Route{
		{{Target: "API.example.com", Destination: "a"}, {Target: "api.example.com.", Destination: "b"}},
		{{Target: "*.EXAMPLE.com", Destination: "a"}, {Target: "*.example.com.", Destination: "b"}},
	} {
		if _, err := New(routes); !errors.Is(err, ErrAmbiguousRoute) {
			t.Fatalf("error = %v, want ErrAmbiguousRoute", err)
		}
	}
}

func TestResolveUnknownTargetFailsClosed(t *testing.T) {
	table, err := New([]Route{{Target: "api.example.com", Destination: "decision"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Resolve("unknown.example.com"); !errors.Is(err, ErrUnknownTarget) {
		t.Fatalf("error = %v, want ErrUnknownTarget", err)
	}
}

func TestTargetValidationRejectsNonCanonicalOrDangerousInputs(t *testing.T) {
	bad := []string{
		"",
		"https://api.example.com",
		"api.example.com/path",
		"api.example.com:443",
		"api..example.com",
		"-api.example.com",
		"api_example.com",
		"*.com",
		"*.*.example.com",
		"api.example.com\x00.evil",
	}
	for _, target := range bad {
		t.Run(target, func(t *testing.T) {
			if _, err := NormalizeTarget(target); err == nil {
				t.Fatal("expected invalid target")
			}
		})
	}
}

func TestWildcardDoesNotMatchApexOrMultipleSemantics(t *testing.T) {
	table, err := New([]Route{{Target: "*.example.com", Destination: "wild"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := table.Resolve("example.com"); !errors.Is(err, ErrUnknownTarget) {
		t.Fatalf("apex error = %v", err)
	}
	if got, err := table.Resolve("deep.api.example.com"); err != nil || got.Destination != "wild" {
		t.Fatalf("subdomain wildcard: got=%+v err=%v", got, err)
	}
}
