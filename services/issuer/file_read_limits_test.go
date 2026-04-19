package issuer

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateKeypairRejectsOversizedPrivateKeyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer.key")
	if err := os.WriteFile(path, bytes.Repeat([]byte("a"), int(issuerPrivateKeyFileMaxBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized key: %v", err)
	}
	s := &Service{privateKeyPath: path}
	if _, _, err := s.loadOrCreateKeypair(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized private key rejection, got %v", err)
	}
}

func TestLoadAdminSigningKeysRejectsOversizedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin_keys.txt")
	if err := os.WriteFile(path, bytes.Repeat([]byte("k"), int(issuerAdminKeysFileMaxBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized admin keys file: %v", err)
	}
	s := &Service{adminKeysFile: path}
	if err := s.loadAdminSigningKeys(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized admin signing key file rejection, got %v", err)
	}
}

func TestLoadSubjectsRejectsOversizedStateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subjects.json")
	if err := os.WriteFile(path, bytes.Repeat([]byte("{"), int(issuerStateFileMaxBytes+1)), 0o600); err != nil {
		t.Fatalf("write oversized subjects file: %v", err)
	}
	s := &Service{subjectsFile: path}
	if err := s.loadSubjects(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized subjects file rejection, got %v", err)
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
