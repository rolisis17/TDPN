package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFileStoreRejectsConflictingCanonicalAuthorizationSnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnsponsor.json")
	payload := `{"authorizations":{"legacy-a":{"AuthorizationID":" Auth-1 ","SponsorID":"sponsor-1","AppID":"app-1","MaxCredits":10},"legacy-b":{"AuthorizationID":"auth-1","SponsorID":"sponsor-1","AppID":"app-1","MaxCredits":20}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected conflicting canonical authorization snapshot to fail")
	}
	if !strings.Contains(err.Error(), "conflicting authorization entries") {
		t.Fatalf("expected conflicting authorization validation error, got: %v", err)
	}
}
