package keeper

import (
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

type trackingStore struct {
	reservations map[string]types.CreditReservation
	settlements  map[string]types.SettlementRecord

	upsertReservationCalls int
	getReservationCalls    int
	upsertSettlementCalls  int
	getSettlementCalls     int
}

func newTrackingStore() *trackingStore {
	return &trackingStore{
		reservations: make(map[string]types.CreditReservation),
		settlements:  make(map[string]types.SettlementRecord),
	}
}

func (s *trackingStore) UpsertReservation(record types.CreditReservation) {
	s.upsertReservationCalls++
	s.reservations[record.ReservationID] = record
}

func (s *trackingStore) GetReservation(reservationID string) (types.CreditReservation, bool) {
	s.getReservationCalls++
	record, ok := s.reservations[reservationID]
	return record, ok
}

func (s *trackingStore) ListReservations() []types.CreditReservation {
	records := make([]types.CreditReservation, 0, len(s.reservations))
	for _, record := range s.reservations {
		records = append(records, record)
	}
	return records
}

func (s *trackingStore) UpsertSettlement(record types.SettlementRecord) {
	s.upsertSettlementCalls++
	s.settlements[record.SettlementID] = record
}

func (s *trackingStore) GetSettlement(settlementID string) (types.SettlementRecord, bool) {
	s.getSettlementCalls++
	record, ok := s.settlements[settlementID]
	return record, ok
}

func (s *trackingStore) ListSettlements() []types.SettlementRecord {
	records := make([]types.SettlementRecord, 0, len(s.settlements))
	for _, record := range s.settlements {
		records = append(records, record)
	}
	return records
}

func TestNewKeeperWithStoreNilFallsBackToInMemory(t *testing.T) {
	t.Parallel()

	k := NewKeeperWithStore(nil)

	record := types.CreditReservation{
		ReservationID: "res-fallback",
		SessionID:     "sess-fallback",
		Amount:        1,
	}
	k.UpsertReservation(record)

	got, ok := k.GetReservation(record.ReservationID)
	if !ok {
		t.Fatal("expected reservation to be present with nil-store fallback")
	}
	if got.ReservationID != record.ReservationID {
		t.Fatalf("expected reservation id %q, got %q", record.ReservationID, got.ReservationID)
	}
}

func TestKeeperDelegatesUpsertAndGetToCustomStore(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	reservation := types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		Amount:        100,
	}
	k.UpsertReservation(reservation)

	if store.upsertReservationCalls != 1 {
		t.Fatalf("expected 1 reservation upsert call, got %d", store.upsertReservationCalls)
	}

	gotReservation, ok := k.GetReservation(reservation.ReservationID)
	if !ok {
		t.Fatal("expected reservation from custom store")
	}
	if gotReservation.Amount != reservation.Amount {
		t.Fatalf("expected reservation amount %d, got %d", reservation.Amount, gotReservation.Amount)
	}
	if store.getReservationCalls != 1 {
		t.Fatalf("expected 1 reservation get call, got %d", store.getReservationCalls)
	}

	settlement := types.SettlementRecord{
		SettlementID: "set-1",
		SessionID:    "sess-1",
		BilledAmount: 50,
	}
	k.UpsertSettlement(settlement)

	if store.upsertSettlementCalls != 1 {
		t.Fatalf("expected 1 settlement upsert call, got %d", store.upsertSettlementCalls)
	}

	gotSettlement, ok := k.GetSettlement(settlement.SettlementID)
	if !ok {
		t.Fatal("expected settlement from custom store")
	}
	if gotSettlement.BilledAmount != settlement.BilledAmount {
		t.Fatalf("expected billed amount %d, got %d", settlement.BilledAmount, gotSettlement.BilledAmount)
	}
	if store.getSettlementCalls != 1 {
		t.Fatalf("expected 1 settlement get call, got %d", store.getSettlementCalls)
	}
}

func TestKeeperCreateAndFinalizeUseCustomStoreWithStatusProgression(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	reservation, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		AssetDenom:    "uusdc",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}
	if reservation.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected reservation status %q, got %q", chaintypes.ReconciliationPending, reservation.Status)
	}
	if store.upsertReservationCalls == 0 || store.getReservationCalls == 0 {
		t.Fatalf("expected create path to touch custom reservation store, got upsert=%d get=%d", store.upsertReservationCalls, store.getReservationCalls)
	}

	_, err = k.FinalizeSettlement(types.SettlementRecord{
		SettlementID:  "set-1",
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		BilledAmount:  10,
		AssetDenom:    reservation.AssetDenom,
	})
	if err != nil {
		t.Fatalf("FinalizeSettlement returned unexpected error: %v", err)
	}
	if store.upsertSettlementCalls == 0 || store.getSettlementCalls == 0 {
		t.Fatalf("expected finalize path to touch custom settlement store, got upsert=%d get=%d", store.upsertSettlementCalls, store.getSettlementCalls)
	}

	updated, ok := k.GetReservation(reservation.ReservationID)
	if !ok {
		t.Fatal("expected reservation to exist after finalize")
	}
	if updated.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected reservation status %q after finalize, got %q", chaintypes.ReconciliationConfirmed, updated.Status)
	}
}
