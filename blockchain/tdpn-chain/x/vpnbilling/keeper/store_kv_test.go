package keeper

import (
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

func TestKVStoreUpsertGetList(t *testing.T) {
	t.Parallel()

	store := NewKVStore(kvtypes.NewMapStore())

	reservation := types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		AssetDenom:    "uusdc",
		Amount:        42,
		Status:        chaintypes.ReconciliationPending,
	}
	store.UpsertReservation(reservation)

	gotReservation, ok := store.GetReservation(reservation.ReservationID)
	if !ok {
		t.Fatal("expected reservation to exist")
	}
	if gotReservation != reservation {
		t.Fatalf("expected reservation %+v, got %+v", reservation, gotReservation)
	}

	settlement := types.SettlementRecord{
		SettlementID:   "set-1",
		ReservationID:  reservation.ReservationID,
		SessionID:      reservation.SessionID,
		BilledAmount:   10,
		AssetDenom:     "uusdc",
		OperationState: chaintypes.ReconciliationSubmitted,
	}
	store.UpsertSettlement(settlement)

	gotSettlement, ok := store.GetSettlement(settlement.SettlementID)
	if !ok {
		t.Fatal("expected settlement to exist")
	}
	if gotSettlement != settlement {
		t.Fatalf("expected settlement %+v, got %+v", settlement, gotSettlement)
	}

	reservations := store.ListReservations()
	if len(reservations) != 1 {
		t.Fatalf("expected 1 reservation, got %d", len(reservations))
	}
	if reservations[0] != reservation {
		t.Fatalf("expected list reservation %+v, got %+v", reservation, reservations[0])
	}

	settlements := store.ListSettlements()
	if len(settlements) != 1 {
		t.Fatalf("expected 1 settlement, got %d", len(settlements))
	}
	if settlements[0] != settlement {
		t.Fatalf("expected list settlement %+v, got %+v", settlement, settlements[0])
	}
}

func TestNewKVStoreNilFallsBackToMapStore(t *testing.T) {
	t.Parallel()

	store := NewKVStore(nil)

	record := types.CreditReservation{
		ReservationID: "res-fallback",
		SessionID:     "sess-fallback",
		Amount:        7,
	}
	store.UpsertReservation(record)

	got, ok := store.GetReservation(record.ReservationID)
	if !ok {
		t.Fatal("expected reservation from nil-store fallback")
	}
	if got != record {
		t.Fatalf("expected reservation %+v, got %+v", record, got)
	}
}

func TestKVStoreMalformedPayloadsFailSoft(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	validReservation := types.CreditReservation{
		ReservationID: "res-ok",
		SessionID:     "sess-ok",
		AssetDenom:    "uusdc",
		Amount:        5,
		Status:        chaintypes.ReconciliationPending,
	}
	store.UpsertReservation(validReservation)
	backend.Set(reservationKey("res-bad"), []byte("{"))

	if _, ok := store.GetReservation("res-bad"); ok {
		t.Fatal("expected malformed reservation payload lookup to fail")
	}
	gotReservation, ok := store.GetReservation(validReservation.ReservationID)
	if !ok {
		t.Fatal("expected valid reservation lookup to succeed")
	}
	if gotReservation != validReservation {
		t.Fatalf("expected valid reservation %+v, got %+v", validReservation, gotReservation)
	}

	reservations := store.ListReservations()
	if len(reservations) != 1 {
		t.Fatalf("expected malformed reservation payload to be skipped, got %d records", len(reservations))
	}
	if reservations[0] != validReservation {
		t.Fatalf("expected only valid reservation %+v, got %+v", validReservation, reservations[0])
	}

	validSettlement := types.SettlementRecord{
		SettlementID:   "set-ok",
		ReservationID:  validReservation.ReservationID,
		SessionID:      validReservation.SessionID,
		BilledAmount:   3,
		AssetDenom:     "uusdc",
		OperationState: chaintypes.ReconciliationSubmitted,
	}
	store.UpsertSettlement(validSettlement)
	backend.Set(settlementKey("set-bad"), []byte("{"))

	if _, ok := store.GetSettlement("set-bad"); ok {
		t.Fatal("expected malformed settlement payload lookup to fail")
	}
	gotSettlement, ok := store.GetSettlement(validSettlement.SettlementID)
	if !ok {
		t.Fatal("expected valid settlement lookup to succeed")
	}
	if gotSettlement != validSettlement {
		t.Fatalf("expected valid settlement %+v, got %+v", validSettlement, gotSettlement)
	}

	settlements := store.ListSettlements()
	if len(settlements) != 1 {
		t.Fatalf("expected malformed settlement payload to be skipped, got %d records", len(settlements))
	}
	if settlements[0] != validSettlement {
		t.Fatalf("expected only valid settlement %+v, got %+v", validSettlement, settlements[0])
	}
}
