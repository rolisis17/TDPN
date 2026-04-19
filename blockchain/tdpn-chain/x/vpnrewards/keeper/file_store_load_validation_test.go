package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFileStoreRejectsConflictingCanonicalAccrualSnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnrewards.json")
	payload := `{"accruals":{"legacy-a":{"AccrualID":" Acc-1 ","ProviderID":"provider-a","Amount":10},"legacy-b":{"AccrualID":"acc-1","ProviderID":"provider-b","Amount":10}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected conflicting canonical accrual snapshot to fail")
	}
	if !strings.Contains(err.Error(), "conflicting accrual entries") {
		t.Fatalf("expected conflicting accrual validation error, got: %v", err)
	}
}
