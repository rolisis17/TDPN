package module

import (
	"context"
	"errors"
	"testing"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

func TestProtoMsgServerAdapterReserveCredits(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoMsgServerAdapter(&k)

	resp, err := adapter.ReserveCredits(context.Background(), &pb.MsgReserveCreditsRequest{
		Reservation: &pb.CreditReservation{
			ReservationId: "res-adapter-1",
			SponsorId:     "sponsor-1",
			SessionId:     "sess-1",
			AssetDenom:    "uusdc",
			Amount:        100,
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.GetReservation().GetReservationId() != "res-adapter-1" {
		t.Fatalf("unexpected reservation id %q", resp.GetReservation().GetReservationId())
	}
	if resp.GetIdempotentReplay() {
		t.Fatal("expected idempotent_replay=false for first reserve")
	}
	if resp.GetConflict() {
		t.Fatal("expected conflict=false for successful reserve")
	}
	if resp.GetReservation().GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING {
		t.Fatalf("expected pending status, got %v", resp.GetReservation().GetStatus())
	}
}

func TestProtoMsgServerAdapterFinalizeUsage(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoMsgServerAdapter(&k)

	if _, err := adapter.ReserveCredits(context.Background(), &pb.MsgReserveCreditsRequest{
		Reservation: &pb.CreditReservation{
			ReservationId: "res-adapter-2",
			SessionId:     "sess-2",
			Amount:        100,
		},
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	resp, err := adapter.FinalizeUsage(context.Background(), &pb.MsgFinalizeUsageRequest{
		Settlement: &pb.SettlementRecord{
			SettlementId:  "set-adapter-2",
			ReservationId: "res-adapter-2",
			SessionId:     "sess-2",
			BilledAmount:  60,
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.GetSettlement().GetSettlementId() != "set-adapter-2" {
		t.Fatalf("unexpected settlement id %q", resp.GetSettlement().GetSettlementId())
	}
	if resp.GetIdempotentReplay() {
		t.Fatal("expected idempotent_replay=false for first finalize")
	}
	if resp.GetConflict() {
		t.Fatal("expected conflict=false for successful finalize")
	}
	if resp.GetSettlement().GetOperationState() != pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED {
		t.Fatalf("expected submitted operation state, got %v", resp.GetSettlement().GetOperationState())
	}
}

func TestProtoMsgServerAdapterReserveCreditsConflict(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoMsgServerAdapter(&k)

	seed := &pb.MsgReserveCreditsRequest{
		Reservation: &pb.CreditReservation{
			ReservationId: "res-adapter-3",
			SessionId:     "sess-3",
			Amount:        100,
		},
	}
	if _, err := adapter.ReserveCredits(context.Background(), seed); err != nil {
		t.Fatalf("seed reserve failed: %v", err)
	}

	resp, err := adapter.ReserveCredits(context.Background(), &pb.MsgReserveCreditsRequest{
		Reservation: &pb.CreditReservation{
			ReservationId: "res-adapter-3",
			SessionId:     "sess-3",
			Amount:        101,
		},
	})
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !errors.Is(err, ErrReservationConflict) {
		t.Fatalf("expected ErrReservationConflict, got %v", err)
	}
	if !resp.GetConflict() {
		t.Fatal("expected conflict=true on conflicting replay")
	}
}

func TestProtoQueryServerAdapterGetNotFoundReturnsFoundFalse(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoQueryServerAdapter(&k)

	reservationResp, err := adapter.CreditReservation(context.Background(), &pb.QueryCreditReservationRequest{
		ReservationId: "missing-res",
	})
	if err != nil {
		t.Fatalf("expected nil error on missing reservation, got %v", err)
	}
	if reservationResp.GetFound() {
		t.Fatal("expected found=false for missing reservation")
	}

	settlementResp, err := adapter.SettlementRecord(context.Background(), &pb.QuerySettlementRecordRequest{
		SettlementId: "missing-set",
	})
	if err != nil {
		t.Fatalf("expected nil error on missing settlement, got %v", err)
	}
	if settlementResp.GetFound() {
		t.Fatal("expected found=false for missing settlement")
	}
}

func TestProtoQueryServerAdapterGetAndList(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertReservation(types.CreditReservation{
		ReservationID: "res-adapter-10",
		SessionID:     "sess-10",
		Amount:        10,
	})
	k.UpsertSettlement(types.SettlementRecord{
		SettlementID:  "set-adapter-10",
		ReservationID: "res-adapter-10",
		SessionID:     "sess-10",
		BilledAmount:  9,
	})

	adapter := NewProtoQueryServerAdapter(&k)

	reservationResp, err := adapter.CreditReservation(context.Background(), &pb.QueryCreditReservationRequest{
		ReservationId: "res-adapter-10",
	})
	if err != nil {
		t.Fatalf("expected reservation query success, got %v", err)
	}
	if !reservationResp.GetFound() {
		t.Fatal("expected found=true for existing reservation")
	}
	if reservationResp.GetReservation().GetReservationId() != "res-adapter-10" {
		t.Fatalf("unexpected reservation id %q", reservationResp.GetReservation().GetReservationId())
	}

	settlementResp, err := adapter.SettlementRecord(context.Background(), &pb.QuerySettlementRecordRequest{
		SettlementId: "set-adapter-10",
	})
	if err != nil {
		t.Fatalf("expected settlement query success, got %v", err)
	}
	if !settlementResp.GetFound() {
		t.Fatal("expected found=true for existing settlement")
	}
	if settlementResp.GetSettlement().GetSettlementId() != "set-adapter-10" {
		t.Fatalf("unexpected settlement id %q", settlementResp.GetSettlement().GetSettlementId())
	}

	listReservationsResp, err := adapter.ListCreditReservations(context.Background(), &pb.QueryListCreditReservationsRequest{})
	if err != nil {
		t.Fatalf("expected list reservations success, got %v", err)
	}
	if len(listReservationsResp.GetReservations()) != 1 {
		t.Fatalf("expected 1 reservation, got %d", len(listReservationsResp.GetReservations()))
	}

	listSettlementsResp, err := adapter.ListSettlementRecords(context.Background(), &pb.QueryListSettlementRecordsRequest{})
	if err != nil {
		t.Fatalf("expected list settlements success, got %v", err)
	}
	if len(listSettlementsResp.GetSettlements()) != 1 {
		t.Fatalf("expected 1 settlement, got %d", len(listSettlementsResp.GetSettlements()))
	}
}
