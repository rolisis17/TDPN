package directory

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateKeypairRejectsOversizedPrivateKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "directory.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), int(directoryPrivateKeyMaxBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized key: %v", err)
	}
	s := &Service{privateKeyPath: path}
	if _, _, err := s.loadOrCreateKeypair(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized private key rejection, got %v", err)
	}
}

func TestLoadPreviousPubKeysRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "previous_pubkeys.txt")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), int(directoryPreviousPubKeysFileMaxBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized previous pubkeys file: %v", err)
	}
	if _, err := loadPreviousPubKeys(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized previous pubkeys rejection, got %v", err)
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
