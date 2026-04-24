package module

import (
	"errors"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnbilling/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

func TestMsgServerReserveCreditsHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-1",
			SponsorID:     "sponsor-1",
			SessionID:     "sess-1",
			AssetDenom:    "uusdc",
			Amount:        250,
		},
	}

	resp, err := server.ReserveCredits(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first reservation")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first reservation")
	}
	if resp.Reservation.ReservationID != req.Reservation.ReservationID {
		t.Fatalf("unexpected reservation id %q", resp.Reservation.ReservationID)
	}
}

func TestMsgServerReserveCreditsIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-2",
			SponsorID:     "sponsor-2",
			SessionID:     "sess-2",
			AssetDenom:    "utdpn",
			Amount:        125,
		},
	}

	if _, err := server.ReserveCredits(req); err != nil {
		t.Fatalf("first reserve failed: %v", err)
	}

	resp, err := server.ReserveCredits(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed reservation")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed reservation")
	}
}

func TestMsgServerReserveCreditsInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.ReserveCredits(ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "",
			SessionID:     "sess-3",
			Amount:        100,
		},
	})
	if err == nil {
		t.Fatal("expected invalid reservation error")
	}
	if !errors.Is(err, ErrInvalidReservation) {
		t.Fatalf("expected ErrInvalidReservation, got %v", err)
	}
}

func TestMsgServerReserveCreditsConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	base := ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-4",
			SponsorID:     "sponsor-4",
			SessionID:     "sess-4",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	}
	if _, err := server.ReserveCredits(base); err != nil {
		t.Fatalf("seed reservation failed: %v", err)
	}

	conflict := base
	conflict.Reservation.Amount = 101
	resp, err := server.ReserveCredits(conflict)
	if err == nil {
		t.Fatal("expected reservation conflict error")
	}
	if !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("expected ErrReservationConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerFinalizeUsageHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	resReq := ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-5",
			SponsorID:     "sponsor-5",
			SessionID:     "sess-5",
			AssetDenom:    "uusdc",
			Amount:        500,
		},
	}
	if _, err := server.ReserveCredits(resReq); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	finalReq := FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:   "set-5",
			ReservationID:  "res-5",
			SessionID:      "sess-5",
			BilledAmount:   400,
			UsageBytes:     1024,
			AssetDenom:     "uusdc",
			OperationState: "confirmed",
		},
	}

	resp, err := server.FinalizeUsage(finalReq)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first settlement")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first settlement")
	}
	if resp.Settlement.SettlementID != "set-5" {
		t.Fatalf("unexpected settlement id %q", resp.Settlement.SettlementID)
	}
}

func TestMsgServerFinalizeUsageIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.ReserveCredits(ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-6",
			SessionID:     "sess-6",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	req := FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "set-6",
			ReservationID: "res-6",
			SessionID:     "sess-6",
			BilledAmount:  80,
			AssetDenom:    "uusdc",
		},
	}
	if _, err := server.FinalizeUsage(req); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}

	resp, err := server.FinalizeUsage(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed finalize")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed finalize")
	}
}

func TestMsgServerFinalizeUsageInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.FinalizeUsage(FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "",
			ReservationID: "res-7",
			SessionID:     "sess-7",
			BilledAmount:  10,
		},
	})
	if err == nil {
		t.Fatal("expected invalid settlement error")
	}
	if !errors.Is(err, ErrInvalidSettlement) {
		t.Fatalf("expected ErrInvalidSettlement, got %v", err)
	}
}

func TestMsgServerFinalizeUsageConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.ReserveCredits(ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-8",
			SessionID:     "sess-8",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	req := FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "set-8",
			ReservationID: "res-8",
			SessionID:     "sess-8",
			BilledAmount:  75,
			AssetDenom:    "uusdc",
		},
	}
	if _, err := server.FinalizeUsage(req); err != nil {
		t.Fatalf("first finalize failed: %v", err)
	}

	conflict := req
	conflict.Settlement.BilledAmount = 74
	resp, err := server.FinalizeUsage(conflict)
	if err == nil {
		t.Fatal("expected settlement conflict error")
	}
	if !errors.Is(err, ErrSettlementConflict) {
		t.Fatalf("expected ErrSettlementConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerFinalizeUsageMissingReservationPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.FinalizeUsage(FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "set-9",
			ReservationID: "does-not-exist",
			SessionID:     "sess-9",
			BilledAmount:  10,
			AssetDenom:    "uusdc",
		},
	})
	if err == nil {
		t.Fatal("expected reservation not found error")
	}
	if !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("expected ErrReservationNotFound, got %v", err)
	}
}

func TestMsgServerFinalizeUsageSessionMismatchPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.ReserveCredits(ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-10",
			SessionID:     "sess-10",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	_, err := server.FinalizeUsage(FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "set-10",
			ReservationID: "res-10",
			SessionID:     "sess-10-other",
			BilledAmount:  10,
			AssetDenom:    "uusdc",
		},
	})
	if err == nil {
		t.Fatal("expected invalid settlement error for session mismatch")
	}
	if !errors.Is(err, ErrInvalidSettlement) {
		t.Fatalf("expected ErrInvalidSettlement, got %v", err)
	}
}

func TestMsgServerFinalizeUsageNegativeUsageBytesPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.ReserveCredits(ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-negative-usage-msg",
			SessionID:     "sess-negative-usage-msg",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	_, err := server.FinalizeUsage(FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "set-negative-usage-msg",
			ReservationID: "res-negative-usage-msg",
			SessionID:     "sess-negative-usage-msg",
			BilledAmount:  10,
			UsageBytes:    -1,
			AssetDenom:    "uusdc",
		},
	})
	if err == nil {
		t.Fatal("expected invalid settlement error for negative usage bytes")
	}
	if !errors.Is(err, ErrInvalidSettlement) {
		t.Fatalf("expected ErrInvalidSettlement, got %v", err)
	}
}

func TestMsgServerFinalizeUsageEmptyAssetDenomPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.ReserveCredits(ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-empty-denom-msg",
			SessionID:     "sess-empty-denom-msg",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	_, err := server.FinalizeUsage(FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "set-empty-denom-msg",
			ReservationID: "res-empty-denom-msg",
			SessionID:     "sess-empty-denom-msg",
			BilledAmount:  10,
			AssetDenom:    " \n\t ",
		},
	})
	if err == nil {
		t.Fatal("expected invalid settlement error for empty asset denom")
	}
	if !errors.Is(err, ErrInvalidSettlement) {
		t.Fatalf("expected ErrInvalidSettlement, got %v", err)
	}
}

func TestMsgServerFinalizeUsageAssetDenomMismatchPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.ReserveCredits(ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-11",
			SessionID:     "sess-11",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	_, err := server.FinalizeUsage(FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "set-11",
			ReservationID: "res-11",
			SessionID:     "sess-11",
			BilledAmount:  10,
			AssetDenom:    "utdpn",
		},
	})
	if err == nil {
		t.Fatal("expected invalid settlement error for asset denom mismatch")
	}
	if !errors.Is(err, ErrInvalidSettlement) {
		t.Fatalf("expected ErrInvalidSettlement, got %v", err)
	}
}

func TestMsgServerFinalizeUsageOverchargePropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.ReserveCredits(ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-12",
			SessionID:     "sess-12",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	_, err := server.FinalizeUsage(FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "set-12",
			ReservationID: "res-12",
			SessionID:     "sess-12",
			BilledAmount:  101,
			AssetDenom:    "uusdc",
		},
	})
	if err == nil {
		t.Fatal("expected invalid settlement error for overcharge")
	}
	if !errors.Is(err, ErrInvalidSettlement) {
		t.Fatalf("expected ErrInvalidSettlement, got %v", err)
	}
}

func TestMsgServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewMsgServer(k)

	_, reserveErr := server.ReserveCredits(ReserveCreditsRequest{
		Reservation: types.CreditReservation{
			ReservationID: "res-nil",
			SessionID:     "sess-nil",
			Amount:        1,
		},
	})
	if !errors.Is(reserveErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on reserve, got %v", reserveErr)
	}

	_, finalizeErr := server.FinalizeUsage(FinalizeUsageRequest{
		Settlement: types.SettlementRecord{
			SettlementID:  "set-nil",
			ReservationID: "res-nil",
			SessionID:     "sess-nil",
			BilledAmount:  1,
		},
	})
	if !errors.Is(finalizeErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on finalize, got %v", finalizeErr)
	}
}
