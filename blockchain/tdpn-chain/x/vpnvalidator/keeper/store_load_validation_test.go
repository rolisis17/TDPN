package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFileStoreRejectsInvalidStatusRecordSnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnvalidator.json")
	payload := `{"status_records":{"bad":{"StatusID":"status-1","ValidatorID":"validator-1","LifecycleStatus":"unknown","EvidenceHeight":1}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected invalid status record snapshot to fail")
	}
	if !strings.Contains(err.Error(), "invalid status record") {
		t.Fatalf("expected invalid status record validation error, got: %v", err)
	}
}
