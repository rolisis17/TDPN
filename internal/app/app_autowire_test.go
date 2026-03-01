package app

import (
	"os"
	"strings"
	"testing"
)

func TestAutoWireRoleURLsIssuerFromAddr(t *testing.T) {
	t.Setenv("ISSUER_ADDR", "127.0.0.1:8782")
	t.Setenv("ISSUER_URL", "")

	autoWireRoleURLs(Roles{Issuer: true, Entry: true})

	if got := getenvTrimmed("ISSUER_URL"); got != "http://127.0.0.1:8782" {
		t.Fatalf("expected ISSUER_URL auto-wired, got %q", got)
	}
}

func TestAutoWireRoleURLsDoesNotOverrideExplicit(t *testing.T) {
	t.Setenv("ISSUER_ADDR", "127.0.0.1:8782")
	t.Setenv("ISSUER_URL", "http://issuer.example:9000")

	autoWireRoleURLs(Roles{Issuer: true, Exit: true})

	if got := getenvTrimmed("ISSUER_URL"); got != "http://issuer.example:9000" {
		t.Fatalf("expected explicit ISSUER_URL preserved, got %q", got)
	}
}

func TestAutoWireRoleURLsClientDirectoryEntryExit(t *testing.T) {
	t.Setenv("DIRECTORY_ADDR", "127.0.0.1:8781")
	t.Setenv("ENTRY_ADDR", "127.0.0.1:8783")
	t.Setenv("EXIT_ADDR", "127.0.0.1:8784")
	t.Setenv("DIRECTORY_URL", "")
	t.Setenv("ENTRY_URL", "")
	t.Setenv("EXIT_CONTROL_URL", "")

	autoWireRoleURLs(Roles{Client: true, Directory: true, Entry: true, Exit: true})

	if got := getenvTrimmed("DIRECTORY_URL"); got != "http://127.0.0.1:8781" {
		t.Fatalf("expected DIRECTORY_URL auto-wired, got %q", got)
	}
	if got := getenvTrimmed("ENTRY_URL"); got != "http://127.0.0.1:8783" {
		t.Fatalf("expected ENTRY_URL auto-wired, got %q", got)
	}
	if got := getenvTrimmed("EXIT_CONTROL_URL"); got != "http://127.0.0.1:8784" {
		t.Fatalf("expected EXIT_CONTROL_URL auto-wired, got %q", got)
	}
}

func getenvTrimmed(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}
