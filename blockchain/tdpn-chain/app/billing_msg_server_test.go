package app

import (
	"context"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

func TestBillingMsgServer_AccessorAndHappyPath(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.BillingMsgServer()

	reservation := billingtypes.CreditReservation{
		ReservationID: "res-1",
		SponsorID:     "sponsor-1",
		SessionID:     "session-1",
		AssetDenom:    "utdpn",
		Amount:        100,
	}
	createResp, err := server.CreateReservation(context.Background(), BillingCreateReservationRequest{Record: reservation})
	if err != nil {
		t.Fatalf("expected create reservation to succeed, got error: %v", err)
	}
	if createResp.Replay {
		t.Fatal("expected first create reservation call to not be replay")
	}
	if createResp.Reservation.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default reservation status %q, got %q", chaintypes.ReconciliationPending, createResp.Reservation.Status)
	}

	finalize := billingtypes.SettlementRecord{
		SettlementID:  "set-1",
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		BilledAmount:  50,
		UsageBytes:    2048,
		AssetDenom:    "utdpn",
	}
	finalizeResp, err := server.FinalizeSettlement(context.Background(), BillingFinalizeSettlementRequest{Record: finalize})
	if err != nil {
		t.Fatalf("expected finalize settlement to succeed, got error: %v", err)
	}
	if finalizeResp.Replay {
		t.Fatal("expected first finalize settlement call to not be replay")
	}
	if finalizeResp.Settlement.OperationState != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default settlement status %q, got %q", chaintypes.ReconciliationSubmitted, finalizeResp.Settlement.OperationState)
	}
}

func TestBillingMsgServer_CreateReservationReplayAndConflict(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.BillingMsgServer()

	reservation := billingtypes.CreditReservation{
		ReservationID: "res-replay",
		SponsorID:     "sponsor-1",
		SessionID:     "session-1",
		AssetDenom:    "usdc",
		Amount:        25,
		Status:        chaintypes.ReconciliationPending,
	}

	_, err := server.CreateReservation(context.Background(), BillingCreateReservationRequest{Record: reservation})
	if err != nil {
		t.Fatalf("expected initial create reservation to succeed, got error: %v", err)
	}

	replayResp, err := server.CreateReservation(context.Background(), BillingCreateReservationRequest{Record: reservation})
	if err != nil {
		t.Fatalf("expected replay create reservation to succeed, got error: %v", err)
	}
	if !replayResp.Replay {
		t.Fatal("expected duplicate create reservation to report replay=true")
	}

	conflict := reservation
	conflict.Amount = 30
	_, err = server.CreateReservation(context.Background(), BillingCreateReservationRequest{Record: conflict})
	if err == nil {
		t.Fatal("expected conflicting replay create reservation to fail")
	}
	if !strings.Contains(err.Error(), "reservation conflict") {
		t.Fatalf("expected reservation replay conflict error, got: %v", err)
	}
}

func TestBillingMsgServer_FinalizeSettlementReplayAndMissingReservation(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.BillingMsgServer()

	settlement := billingtypes.SettlementRecord{
		SettlementID:  "set-missing-reservation",
		ReservationID: "missing",
		SessionID:     "session-1",
		BilledAmount:  5,
		UsageBytes:    1024,
		AssetDenom:    "utdpn",
	}
	_, err := server.FinalizeSettlement(context.Background(), BillingFinalizeSettlementRequest{Record: settlement})
	if err == nil {
		t.Fatal("expected finalize settlement with missing reservation to fail")
	}
	if !strings.Contains(err.Error(), "reservation not found") {
		t.Fatalf("expected missing reservation error, got: %v", err)
	}

	reservation := billingtypes.CreditReservation{
		ReservationID: settlement.ReservationID,
		SessionID:     settlement.SessionID,
		AssetDenom:    settlement.AssetDenom,
		Amount:        10,
		Status:        chaintypes.ReconciliationPending,
	}
	if _, err := server.CreateReservation(context.Background(), BillingCreateReservationRequest{Record: reservation}); err != nil {
		t.Fatalf("expected reservation create to succeed, got error: %v", err)
	}

	_, err = server.FinalizeSettlement(context.Background(), BillingFinalizeSettlementRequest{Record: settlement})
	if err != nil {
		t.Fatalf("expected initial finalize settlement to succeed, got error: %v", err)
	}

	replayResp, err := server.FinalizeSettlement(context.Background(), BillingFinalizeSettlementRequest{Record: settlement})
	if err != nil {
		t.Fatalf("expected replay finalize settlement to succeed, got error: %v", err)
	}
	if !replayResp.Replay {
		t.Fatal("expected duplicate finalize settlement to report replay=true")
	}

	conflict := settlement
	conflict.BilledAmount = 6
	_, err = server.FinalizeSettlement(context.Background(), BillingFinalizeSettlementRequest{Record: conflict})
	if err == nil {
		t.Fatal("expected conflicting replay finalize settlement to fail")
	}
	if !strings.Contains(err.Error(), "settlement conflict") {
		t.Fatalf("expected settlement replay conflict error, got: %v", err)
	}
}

func TestBillingMsgServer_NilScaffoldReturnsUnwiredServer(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.BillingMsgServer()

	_, err := server.CreateReservation(context.Background(), BillingCreateReservationRequest{
		Record: billingtypes.CreditReservation{
			ReservationID: "res-1",
			SessionID:     "session-1",
			Amount:        1,
		},
	})
	if err == nil {
		t.Fatal("expected nil scaffold server to fail with unwired keeper")
	}
	if !strings.Contains(err.Error(), "vpnbilling keeper is not wired") {
		t.Fatalf("expected unwired keeper error, got: %v", err)
	}
}
