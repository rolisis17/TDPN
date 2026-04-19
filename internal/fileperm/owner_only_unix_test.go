//go:build !windows

package fileperm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateOwnerOnlyUnixAccepts0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if err := ValidateOwnerOnly(path, info); err != nil {
		t.Fatalf("ValidateOwnerOnly returned error: %v", err)
	}
}

func TestValidateOwnerOnlyUnixRejects0644(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.key")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat file: %v", err)
	}
	if err := ValidateOwnerOnly(path, info); err == nil {
		t.Fatalf("expected permission validation error")
	}
}
