package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFileStoreRejectsInvalidEvidenceSnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnslashing.json")
	payload := `{"evidence":{"bad":{"EvidenceID":"e-1","Kind":"objective","ViolationType":"double-sign"}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected invalid evidence snapshot to fail")
	}
	if !strings.Contains(err.Error(), "invalid evidence") {
		t.Fatalf("expected invalid evidence validation error, got: %v", err)
	}
}
