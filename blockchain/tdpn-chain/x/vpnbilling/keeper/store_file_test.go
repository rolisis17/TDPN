package keeper

import (
	"os"
	"path/filepath"
	"testing"

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
