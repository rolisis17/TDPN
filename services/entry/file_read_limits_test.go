package entry

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadTrustedKeysRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "trusted_keys.txt")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), int(trustedDirectoryKeysFileMaxBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized trusted key file: %v", err)
	}
	if _, err := loadTrustedKeys(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized trusted key file rejection, got %v", err)
	}
}

func TestReadFileBoundedRejectsSymlink(t *testing.T) {
	tempDir := t.TempDir()
	targetPath := filepath.Join(tempDir, "target.txt")
	if err := os.WriteFile(targetPath, []byte("ok"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	symlinkPath := filepath.Join(tempDir, "link.txt")
	if err := os.Symlink(targetPath, symlinkPath); err != nil {
		t.Skipf("symlink not supported in this environment: %v", err)
	}
	if _, err := readFileBounded(symlinkPath, 64); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}
