package module

import (
	"context"
	"errors"
	"testing"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
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

func TestProtoGrpcAdaptersCanonicalizeReserveOnWriteAndMixedCaseQuery(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewProtoMsgServerAdapter(&k)
	queryAdapter := NewProtoQueryServerAdapter(&k)

	reserveResp, err := msgAdapter.ReserveCredits(context.Background(), &pb.MsgReserveCreditsRequest{
		Reservation: &pb.CreditReservation{
			ReservationId: "  ReS-Canonical-Adapter-1  ",
			SponsorId:     "  SpOnSoR-Canonical-Adapter-1  ",
			SessionId:     "  SeSs-Canonical-Adapter-1  ",
			AssetDenom:    "  UuSdC  ",
			Amount:        125,
		},
	})
	if err != nil {
		t.Fatalf("expected reserve success, got %v", err)
	}
	if reserveResp.GetReservation() == nil {
		t.Fatal("expected reservation in reserve response")
	}
	if reserveResp.GetReservation().GetReservationId() != "res-canonical-adapter-1" {
		t.Fatalf("expected canonical reservation id %q, got %q", "res-canonical-adapter-1", reserveResp.GetReservation().GetReservationId())
	}
	if reserveResp.GetReservation().GetSponsorId() != "sponsor-canonical-adapter-1" {
		t.Fatalf("expected canonical sponsor id %q, got %q", "sponsor-canonical-adapter-1", reserveResp.GetReservation().GetSponsorId())
	}
	if reserveResp.GetReservation().GetSessionId() != "sess-canonical-adapter-1" {
		t.Fatalf("expected canonical session id %q, got %q", "sess-canonical-adapter-1", reserveResp.GetReservation().GetSessionId())
	}
	if reserveResp.GetReservation().GetAssetDenom() != "uusdc" {
		t.Fatalf("expected canonical asset denom %q, got %q", "uusdc", reserveResp.GetReservation().GetAssetDenom())
	}
	if reserveResp.GetReservation().GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING {
		t.Fatalf("expected pending status after canonicalized reserve, got %v", reserveResp.GetReservation().GetStatus())
	}
	if reserveResp.GetConflict() {
		t.Fatal("expected conflict=false on first reserve")
	}
	if reserveResp.GetIdempotentReplay() {
		t.Fatal("expected idempotent_replay=false on first reserve")
	}

	queryResp, err := queryAdapter.CreditReservation(context.Background(), &pb.QueryCreditReservationRequest{
		ReservationId: "  RES-CANONICAL-ADAPTER-1  ",
	})
	if err != nil {
		t.Fatalf("expected reservation query success, got %v", err)
	}
	if !queryResp.GetFound() {
		t.Fatal("expected found=true for mixed-case reservation query")
	}
	if queryResp.GetReservation() == nil {
		t.Fatal("expected reservation in query response")
	}
	if queryResp.GetReservation().GetReservationId() != "res-canonical-adapter-1" {
		t.Fatalf("expected canonical reservation id %q from query, got %q", "res-canonical-adapter-1", queryResp.GetReservation().GetReservationId())
	}
	if queryResp.GetReservation().GetAssetDenom() != "uusdc" {
		t.Fatalf("expected canonical asset denom %q from query, got %q", "uusdc", queryResp.GetReservation().GetAssetDenom())
	}
}

func TestProtoGrpcAdaptersCanonicalizeFinalizeUsageOnWriteAndMixedCaseQuery(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewProtoMsgServerAdapter(&k)
	queryAdapter := NewProtoQueryServerAdapter(&k)

	if _, err := msgAdapter.ReserveCredits(context.Background(), &pb.MsgReserveCreditsRequest{
		Reservation: &pb.CreditReservation{
			ReservationId: "  ReS-Finalize-Canonical-Adapter-1  ",
			SponsorId:     "  SpOnSoR-Finalize-Canonical-Adapter-1  ",
			SessionId:     "  SeSs-Finalize-Canonical-Adapter-1  ",
			AssetDenom:    "  UuSdC  ",
			Amount:        250,
		},
	}); err != nil {
		t.Fatalf("reserve failed: %v", err)
	}

	finalizeResp, err := msgAdapter.FinalizeUsage(context.Background(), &pb.MsgFinalizeUsageRequest{
		Settlement: &pb.SettlementRecord{
			SettlementId:  "  SeT-Finalize-Canonical-Adapter-1  ",
			ReservationId: "  RES-FINALIZE-CANONICAL-ADAPTER-1  ",
			SessionId:     "  SeSs-Finalize-Canonical-Adapter-1  ",
			AssetDenom:    "  UuSdC  ",
			BilledAmount:  200,
			UsageBytes:    4096,
		},
	})
	if err != nil {
		t.Fatalf("expected finalize success, got %v", err)
	}
	if finalizeResp.GetSettlement() == nil {
		t.Fatal("expected settlement in finalize response")
	}
	if finalizeResp.GetSettlement().GetSettlementId() != "set-finalize-canonical-adapter-1" {
		t.Fatalf("expected canonical settlement id %q, got %q", "set-finalize-canonical-adapter-1", finalizeResp.GetSettlement().GetSettlementId())
	}
	if finalizeResp.GetSettlement().GetReservationId() != "res-finalize-canonical-adapter-1" {
		t.Fatalf("expected canonical reservation id %q, got %q", "res-finalize-canonical-adapter-1", finalizeResp.GetSettlement().GetReservationId())
	}
	if finalizeResp.GetSettlement().GetSessionId() != "sess-finalize-canonical-adapter-1" {
		t.Fatalf("expected canonical session id %q, got %q", "sess-finalize-canonical-adapter-1", finalizeResp.GetSettlement().GetSessionId())
	}
	if finalizeResp.GetSettlement().GetAssetDenom() != "uusdc" {
		t.Fatalf("expected canonical asset denom %q, got %q", "uusdc", finalizeResp.GetSettlement().GetAssetDenom())
	}
	if finalizeResp.GetSettlement().GetOperationState() != pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED {
		t.Fatalf("expected submitted operation state after canonicalized finalize, got %v", finalizeResp.GetSettlement().GetOperationState())
	}
	if finalizeResp.GetConflict() {
		t.Fatal("expected conflict=false on first finalize")
	}
	if finalizeResp.GetIdempotentReplay() {
		t.Fatal("expected idempotent_replay=false on first finalize")
	}

	queryResp, err := queryAdapter.SettlementRecord(context.Background(), &pb.QuerySettlementRecordRequest{
		SettlementId: "  SET-FINALIZE-CANONICAL-ADAPTER-1  ",
	})
	if err != nil {
		t.Fatalf("expected settlement query success, got %v", err)
	}
	if !queryResp.GetFound() {
		t.Fatal("expected found=true for mixed-case settlement query")
	}
	if queryResp.GetSettlement() == nil {
		t.Fatal("expected settlement in query response")
	}
	if queryResp.GetSettlement().GetSettlementId() != "set-finalize-canonical-adapter-1" {
		t.Fatalf("expected canonical settlement id %q from query, got %q", "set-finalize-canonical-adapter-1", queryResp.GetSettlement().GetSettlementId())
	}
	if queryResp.GetSettlement().GetReservationId() != "res-finalize-canonical-adapter-1" {
		t.Fatalf("expected canonical reservation id %q from query, got %q", "res-finalize-canonical-adapter-1", queryResp.GetSettlement().GetReservationId())
	}
	if queryResp.GetSettlement().GetSessionId() != "sess-finalize-canonical-adapter-1" {
		t.Fatalf("expected canonical session id %q from query, got %q", "sess-finalize-canonical-adapter-1", queryResp.GetSettlement().GetSessionId())
	}
	if queryResp.GetSettlement().GetAssetDenom() != "uusdc" {
		t.Fatalf("expected canonical asset denom %q from query, got %q", "uusdc", queryResp.GetSettlement().GetAssetDenom())
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

func TestProtoMsgServerAdapterNilRequestsMapToValidationErrors(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoMsgServerAdapter(&k)

	reserveResp, reserveErr := adapter.ReserveCredits(context.Background(), nil)
	if !errors.Is(reserveErr, ErrInvalidReservation) {
		t.Fatalf("expected ErrInvalidReservation for nil reserve request, got %v", reserveErr)
	}
	if reserveResp.GetConflict() {
		t.Fatal("expected conflict=false for invalid nil reserve request")
	}

	finalizeResp, finalizeErr := adapter.FinalizeUsage(context.Background(), nil)
	if !errors.Is(finalizeErr, ErrInvalidSettlement) {
		t.Fatalf("expected ErrInvalidSettlement for nil finalize request, got %v", finalizeErr)
	}
	if finalizeResp.GetConflict() {
		t.Fatal("expected conflict=false for invalid nil finalize request")
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

func TestProtoQueryServerAdapterNilKeeperErrorsAreNotMappedToFoundFalse(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	adapter := NewProtoQueryServerAdapter(k)

	reservationResp, reservationErr := adapter.CreditReservation(context.Background(), &pb.QueryCreditReservationRequest{
		ReservationId: "res-nil-keeper",
	})
	if !errors.Is(reservationErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for reservation query, got %v", reservationErr)
	}
	if reservationResp != nil {
		t.Fatalf("expected nil reservation response on ErrNilKeeper, got %+v", reservationResp)
	}

	settlementResp, settlementErr := adapter.SettlementRecord(context.Background(), &pb.QuerySettlementRecordRequest{
		SettlementId: "set-nil-keeper",
	})
	if !errors.Is(settlementErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for settlement query, got %v", settlementErr)
	}
	if settlementResp != nil {
		t.Fatalf("expected nil settlement response on ErrNilKeeper, got %+v", settlementResp)
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

func TestFromProtoStatusCoversExplicitEnumsAndDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  pb.ReconciliationStatus
		expect chaintypes.ReconciliationStatus
	}{
		{
			name:   "pending",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
			expect: chaintypes.ReconciliationPending,
		},
		{
			name:   "submitted",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
			expect: chaintypes.ReconciliationSubmitted,
		},
		{
			name:   "confirmed",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
			expect: chaintypes.ReconciliationConfirmed,
		},
		{
			name:   "failed",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
			expect: chaintypes.ReconciliationFailed,
		},
		{
			name:   "unspecified defaults empty",
			input:  pb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
			expect: "",
		},
		{
			name:   "unknown numeric defaults empty",
			input:  pb.ReconciliationStatus(99),
			expect: "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := fromProtoStatus(tc.input)
			if got != tc.expect {
				t.Fatalf("fromProtoStatus(%v): expected %q, got %q", tc.input, tc.expect, got)
			}
		})
	}
}

func TestToProtoStatusCoversExplicitEnumsAndDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  chaintypes.ReconciliationStatus
		expect pb.ReconciliationStatus
	}{
		{
			name:   "pending",
			input:  chaintypes.ReconciliationPending,
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
		},
		{
			name:   "submitted",
			input:  chaintypes.ReconciliationSubmitted,
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
		{
			name:   "confirmed",
			input:  chaintypes.ReconciliationConfirmed,
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
		},
		{
			name:   "failed",
			input:  chaintypes.ReconciliationFailed,
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
		},
		{
			name:   "empty defaults unspecified",
			input:  "",
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
		},
		{
			name:   "unknown string defaults unspecified",
			input:  chaintypes.ReconciliationStatus("mystery"),
			expect: pb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := toProtoStatus(tc.input)
			if got != tc.expect {
				t.Fatalf("toProtoStatus(%q): expected %v, got %v", tc.input, tc.expect, got)
			}
		})
	}
}

func TestProtoQueryServerAdapterNilRequestsUseDefaultLookupPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoQueryServerAdapter(&k)

	reservationResp, err := adapter.CreditReservation(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected nil error for nil reservation query request, got %v", err)
	}
	if reservationResp.GetFound() {
		t.Fatal("expected found=false for nil reservation query request")
	}

	settlementResp, err := adapter.SettlementRecord(context.Background(), nil)
	if err != nil {
		t.Fatalf("expected nil error for nil settlement query request, got %v", err)
	}
	if settlementResp.GetFound() {
		t.Fatal("expected found=false for nil settlement query request")
	}
}
