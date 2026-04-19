package keeper

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

func TestFileStorePersistsAcrossReopen(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "vpnbilling-state.json")

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	reservation := types.CreditReservation{
		ReservationID: "res-1",
		SponsorID:     "sponsor-1",
		SessionID:     "session-1",
		AssetDenom:    "usdc",
		Amount:        100,
		CreatedAtUnix: 111,
	}
	settlement := types.SettlementRecord{
		SettlementID:  "set-1",
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		BilledAmount:  80,
		UsageBytes:    2048,
		AssetDenom:    "usdc",
		SettledAtUnix: 222,
	}

	store.UpsertReservation(reservation)
	store.UpsertSettlement(settlement)

	if _, err := os.Stat(storePath); err != nil {
		t.Fatalf("expected persisted file to exist, stat error: %v", err)
	}

	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore reopen returned unexpected error: %v", err)
	}

	gotReservation, ok := reopened.GetReservation(reservation.ReservationID)
	if !ok {
		t.Fatal("expected reservation after reopening file store")
	}
	if gotReservation != reservation {
		t.Fatalf("expected reopened reservation %+v, got %+v", reservation, gotReservation)
	}

	gotSettlement, ok := reopened.GetSettlement(settlement.SettlementID)
	if !ok {
		t.Fatal("expected settlement after reopening file store")
	}
	if gotSettlement != settlement {
		t.Fatalf("expected reopened settlement %+v, got %+v", settlement, gotSettlement)
	}

	updatedReservation := reservation
	updatedReservation.Amount = 130
	reopened.UpsertReservation(updatedReservation)

	reopenedAgain, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore second reopen returned unexpected error: %v", err)
	}

	updated, ok := reopenedAgain.GetReservation(updatedReservation.ReservationID)
	if !ok {
		t.Fatal("expected updated reservation after second reopen")
	}
	if updated.Amount != updatedReservation.Amount {
		t.Fatalf("expected amount %d after second reopen, got %d", updatedReservation.Amount, updated.Amount)
	}
}

func TestNewFileStoreInvalidPath(t *testing.T) {
	t.Parallel()

	if _, err := NewFileStore(""); err == nil {
		t.Fatal("expected error for empty file store path")
	}

	tempDir := t.TempDir()
	blockerFile := filepath.Join(tempDir, "not-a-dir")
	if err := os.WriteFile(blockerFile, []byte("blocker"), 0o600); err != nil {
		t.Fatalf("write blocker file: %v", err)
	}

	if _, err := NewFileStore(filepath.Join(blockerFile, "state.json")); err == nil {
		t.Fatal("expected error when parent path is a file")
	}
}

func TestNewFileStoreAcceptsEmptyExistingFile(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "vpnbilling-state.json")
	if err := os.WriteFile(storePath, []byte{}, 0o600); err != nil {
		t.Fatalf("write empty state file: %v", err)
	}

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error for empty file: %v", err)
	}

	if got := store.ListReservations(); len(got) != 0 {
		t.Fatalf("expected no reservations from empty file, got %d", len(got))
	}
	if got := store.ListSettlements(); len(got) != 0 {
		t.Fatalf("expected no settlements from empty file, got %d", len(got))
	}
}

func TestNewFileStoreRejectsMalformedJSON(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "vpnbilling-state.json")
	if err := os.WriteFile(storePath, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("write malformed state file: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected malformed JSON to return an error")
	}
	if !strings.Contains(err.Error(), "decode file store state") {
		t.Fatalf("expected decode error context, got: %v", err)
	}
}

func TestFileStorePersistsDeterministicSortedSnapshot(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "vpnbilling-state.json")

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	store.UpsertReservation(types.CreditReservation{ReservationID: "res-20", SessionID: "sess-20", Amount: 20})
	store.UpsertReservation(types.CreditReservation{ReservationID: "res-01", SessionID: "sess-01", Amount: 1})
	store.UpsertSettlement(types.SettlementRecord{SettlementID: "set-20", SessionID: "sess-20", BilledAmount: 20})
	store.UpsertSettlement(types.SettlementRecord{SettlementID: "set-01", SessionID: "sess-01", BilledAmount: 1})

	payload, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read persisted snapshot: %v", err)
	}

	var snapshot fileStoreSnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		t.Fatalf("decode persisted snapshot: %v", err)
	}
	if len(snapshot.Reservations) != 2 {
		t.Fatalf("expected 2 reservations in snapshot, got %d", len(snapshot.Reservations))
	}
	if len(snapshot.Settlements) != 2 {
		t.Fatalf("expected 2 settlements in snapshot, got %d", len(snapshot.Settlements))
	}
	if snapshot.Reservations[0].ReservationID != "res-01" || snapshot.Reservations[1].ReservationID != "res-20" {
		t.Fatalf("expected sorted reservation ids [res-01 res-20], got [%s %s]", snapshot.Reservations[0].ReservationID, snapshot.Reservations[1].ReservationID)
	}
	if snapshot.Settlements[0].SettlementID != "set-01" || snapshot.Settlements[1].SettlementID != "set-20" {
		t.Fatalf("expected sorted settlement ids [set-01 set-20], got [%s %s]", snapshot.Settlements[0].SettlementID, snapshot.Settlements[1].SettlementID)
	}

	tmpFiles, err := filepath.Glob(filepath.Join(tempDir, "vpnbilling-state.json.tmp-*"))
	if err != nil {
		t.Fatalf("glob temp files: %v", err)
	}
	if len(tmpFiles) != 0 {
		t.Fatalf("expected no leftover temp files after atomic write, found %d: %v", len(tmpFiles), tmpFiles)
	}
}

func TestFileStoreUpsertReservationWithErrorRollsBackOnPersistFailure(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "vpnbilling-state.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	// Point to a non-existent parent so persist fails.
	store.path = filepath.Join(tempDir, "missing-parent", "vpnbilling-state.json")
	reservation := types.CreditReservation{
		ReservationID: "res-fail",
		SessionID:     "sess-fail",
		Amount:        1,
	}
	if err := store.UpsertReservationWithError(reservation); err == nil {
		t.Fatal("expected UpsertReservationWithError to fail when persist path parent is missing")
	}
	if _, ok := store.GetReservation(reservation.ReservationID); ok {
		t.Fatal("expected reservation to be rolled back after persist failure")
	}
}

func TestFileStoreAtomicFinalizeRollsBackOnPersistFailure(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	storePath := filepath.Join(tempDir, "vpnbilling-state.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	initialReservation := types.CreditReservation{
		ReservationID: "res-atomic-fail",
		SessionID:     "sess-atomic-fail",
		AssetDenom:    "uusdc",
		Amount:        100,
		Status:        chaintypes.ReconciliationPending,
	}
	if err := store.UpsertReservationWithError(initialReservation); err != nil {
		t.Fatalf("UpsertReservationWithError returned unexpected error: %v", err)
	}

	updatedReservation := initialReservation
	updatedReservation.Status = chaintypes.ReconciliationConfirmed
	settlement := types.SettlementRecord{
		SettlementID:   "set-atomic-fail",
		ReservationID:  initialReservation.ReservationID,
		SessionID:      initialReservation.SessionID,
		BilledAmount:   10,
		AssetDenom:     initialReservation.AssetDenom,
		OperationState: chaintypes.ReconciliationSubmitted,
	}

	// Point to a non-existent parent so persist fails.
	store.path = filepath.Join(tempDir, "missing-parent", "vpnbilling-state.json")
	if err := store.UpsertSettlementAndAdvanceReservationWithError(settlement, updatedReservation); err == nil {
		t.Fatal("expected UpsertSettlementAndAdvanceReservationWithError to fail when persist path parent is missing")
	}

	gotReservation, ok := store.GetReservation(initialReservation.ReservationID)
	if !ok {
		t.Fatal("expected reservation to remain after failed atomic finalize")
	}
	if gotReservation.Status != initialReservation.Status {
		t.Fatalf("expected reservation status %q after rollback, got %q", initialReservation.Status, gotReservation.Status)
	}
	if _, ok := store.GetSettlement(settlement.SettlementID); ok {
		t.Fatal("expected settlement to be rolled back after failed atomic finalize")
	}
}
