package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFileStoreRejectsConflictingCanonicalReservationSnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnbilling-state.json")
	payload := `{"reservations":[{"ReservationID":" Res-1 ","SessionID":"sess-a","Amount":10},{"ReservationID":"res-1","SessionID":"sess-b","Amount":10}]}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected conflicting canonical reservation snapshot to fail")
	}
	if !strings.Contains(err.Error(), "conflicting reservation entries") {
		t.Fatalf("expected conflicting reservation validation error, got: %v", err)
	}
}
