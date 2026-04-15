package module

import (
	"errors"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnbilling/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

func TestQueryServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewQueryServer(k)

	_, reservationErr := server.GetReservation(GetReservationRequest{ReservationID: "res-nil"})
	if !errors.Is(reservationErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for reservation query, got %v", reservationErr)
	}

	_, settlementErr := server.GetSettlement(GetSettlementRequest{SettlementID: "set-nil"})
	if !errors.Is(settlementErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for settlement query, got %v", settlementErr)
	}

	_, listReservationErr := server.ListReservations(ListReservationsRequest{})
	if !errors.Is(listReservationErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list reservations query, got %v", listReservationErr)
	}

	_, listSettlementErr := server.ListSettlements(ListSettlementsRequest{})
	if !errors.Is(listSettlementErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list settlements query, got %v", listSettlementErr)
	}
}

func TestQueryServerNotFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewQueryServer(&k)

	_, reservationErr := server.GetReservation(GetReservationRequest{ReservationID: "res-missing"})
	if !errors.Is(reservationErr, ErrReservationNotFound) {
		t.Fatalf("expected ErrReservationNotFound, got %v", reservationErr)
	}

	_, settlementErr := server.GetSettlement(GetSettlementRequest{SettlementID: "set-missing"})
	if !errors.Is(settlementErr, ErrSettlementNotFound) {
		t.Fatalf("expected ErrSettlementNotFound, got %v", settlementErr)
	}
}

func TestQueryServerFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	expectedReservation := types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		Amount:        10,
	}
	expectedSettlement := types.SettlementRecord{
		SettlementID:  "set-1",
		ReservationID: "res-1",
		SessionID:     "sess-1",
		BilledAmount:  5,
	}
	k.UpsertReservation(expectedReservation)
	k.UpsertSettlement(expectedSettlement)

	server := NewQueryServer(&k)

	reservationResp, reservationErr := server.GetReservation(GetReservationRequest{ReservationID: "res-1"})
	if reservationErr != nil {
		t.Fatalf("expected reservation query success, got %v", reservationErr)
	}
	if reservationResp.Reservation.ReservationID != expectedReservation.ReservationID {
		t.Fatalf("unexpected reservation id: %q", reservationResp.Reservation.ReservationID)
	}

	settlementResp, settlementErr := server.GetSettlement(GetSettlementRequest{SettlementID: "set-1"})
	if settlementErr != nil {
		t.Fatalf("expected settlement query success, got %v", settlementErr)
	}
	if settlementResp.Settlement.SettlementID != expectedSettlement.SettlementID {
		t.Fatalf("unexpected settlement id: %q", settlementResp.Settlement.SettlementID)
	}
}

func TestQueryServerListNonEmpty(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertReservation(types.CreditReservation{ReservationID: "res-20", SessionID: "sess-20", Amount: 20})
	k.UpsertReservation(types.CreditReservation{ReservationID: "res-01", SessionID: "sess-01", Amount: 1})
	k.UpsertSettlement(types.SettlementRecord{SettlementID: "set-20", SessionID: "sess-20", BilledAmount: 20})
	k.UpsertSettlement(types.SettlementRecord{SettlementID: "set-01", SessionID: "sess-01", BilledAmount: 1})

	server := NewQueryServer(&k)

	reservations, err := server.ListReservations(ListReservationsRequest{})
	if err != nil {
		t.Fatalf("expected list reservations success, got %v", err)
	}
	if len(reservations.Reservations) != 2 {
		t.Fatalf("expected 2 reservations, got %d", len(reservations.Reservations))
	}
	if reservations.Reservations[0].ReservationID != "res-01" || reservations.Reservations[1].ReservationID != "res-20" {
		t.Fatalf("expected reservations sorted by id, got %q then %q", reservations.Reservations[0].ReservationID, reservations.Reservations[1].ReservationID)
	}

	settlements, err := server.ListSettlements(ListSettlementsRequest{})
	if err != nil {
		t.Fatalf("expected list settlements success, got %v", err)
	}
	if len(settlements.Settlements) != 2 {
		t.Fatalf("expected 2 settlements, got %d", len(settlements.Settlements))
	}
	if settlements.Settlements[0].SettlementID != "set-01" || settlements.Settlements[1].SettlementID != "set-20" {
		t.Fatalf("expected settlements sorted by id, got %q then %q", settlements.Settlements[0].SettlementID, settlements.Settlements[1].SettlementID)
	}
}
