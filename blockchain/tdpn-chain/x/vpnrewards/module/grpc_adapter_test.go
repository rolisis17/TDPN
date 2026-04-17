package module

import (
	"context"
	"errors"
	"testing"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnrewards/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

func TestGRPCMsgAdapterRecordFlow(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgAdapter(NewMsgServer(&k))

	accrualResp, err := adapter.RecordAccrual(context.Background(), &pb.MsgRecordAccrualRequest{
		Accrual: &pb.RewardAccrual{
			AccrualId:      "acc-grpc-1",
			SessionId:      "sess-grpc-1",
			ProviderId:     "provider-grpc-1",
			AssetDenom:     "uusdc",
			Amount:         100,
			OperationState: pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
	})
	if err != nil {
		t.Fatalf("expected record accrual success, got %v", err)
	}
	if accrualResp.GetAccrual().GetAccrualId() != "acc-grpc-1" {
		t.Fatalf("unexpected accrual id: %q", accrualResp.GetAccrual().GetAccrualId())
	}
	if accrualResp.GetAccrual().GetOperationState() != pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED {
		t.Fatalf("expected submitted accrual state, got %v", accrualResp.GetAccrual().GetOperationState())
	}

	distributionResp, err := adapter.RecordDistribution(context.Background(), &pb.MsgRecordDistributionRequest{
		Distribution: &pb.DistributionRecord{
			DistributionId: "dist-grpc-1",
			AccrualId:      "acc-grpc-1",
			PayoutRef:      "payout-grpc-1",
		},
	})
	if err != nil {
		t.Fatalf("expected record distribution success, got %v", err)
	}
	if distributionResp.GetDistribution().GetDistributionId() != "dist-grpc-1" {
		t.Fatalf("unexpected distribution id: %q", distributionResp.GetDistribution().GetDistributionId())
	}
	if distributionResp.GetDistribution().GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED {
		t.Fatalf("expected default submitted distribution status, got %v", distributionResp.GetDistribution().GetStatus())
	}
}

func TestGRPCAdaptersAccrualCanonicalWriteAndMixedCaseQuery(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgAdapter(NewMsgServer(&k))
	queryAdapter := NewGRPCQueryAdapter(NewQueryServer(&k))

	recordResp, err := msgAdapter.RecordAccrual(context.Background(), &pb.MsgRecordAccrualRequest{
		Accrual: &pb.RewardAccrual{
			AccrualId:      "  AcCrUaL-GRPC-Canonical-1  ",
			SessionId:      "  SeSsIoN-GRPC-Canonical-1  ",
			ProviderId:     "  PrOvIdEr-GRPC-Canonical-1  ",
			AssetDenom:     "  UUSDC  ",
			Amount:         77,
			OperationState: pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
	})
	if err != nil {
		t.Fatalf("expected record accrual success, got %v", err)
	}
	if recordResp.GetAccrual() == nil {
		t.Fatal("expected accrual in record response")
	}
	if recordResp.GetAccrual().GetAccrualId() != "accrual-grpc-canonical-1" {
		t.Fatalf("expected canonical accrual_id %q, got %q", "accrual-grpc-canonical-1", recordResp.GetAccrual().GetAccrualId())
	}
	if recordResp.GetAccrual().GetSessionId() != "session-grpc-canonical-1" {
		t.Fatalf("expected canonical session_id %q, got %q", "session-grpc-canonical-1", recordResp.GetAccrual().GetSessionId())
	}
	if recordResp.GetAccrual().GetProviderId() != "provider-grpc-canonical-1" {
		t.Fatalf("expected canonical provider_id %q, got %q", "provider-grpc-canonical-1", recordResp.GetAccrual().GetProviderId())
	}
	if recordResp.GetAccrual().GetAssetDenom() != "uusdc" {
		t.Fatalf("expected canonical asset_denom %q, got %q", "uusdc", recordResp.GetAccrual().GetAssetDenom())
	}

	queryResp, err := queryAdapter.RewardAccrual(context.Background(), &pb.QueryRewardAccrualRequest{
		AccrualId: "  ACCRUAL-GRPC-CANONICAL-1  ",
	})
	if err != nil {
		t.Fatalf("expected mixed-case accrual query success, got %v", err)
	}
	if !queryResp.GetFound() {
		t.Fatal("expected found=true for mixed-case accrual query")
	}
	if queryResp.GetAccrual() == nil {
		t.Fatal("expected accrual in query response")
	}
	if queryResp.GetAccrual().GetAccrualId() != "accrual-grpc-canonical-1" {
		t.Fatalf("expected canonical queried accrual_id %q, got %q", "accrual-grpc-canonical-1", queryResp.GetAccrual().GetAccrualId())
	}
	if queryResp.GetAccrual().GetSessionId() != "session-grpc-canonical-1" {
		t.Fatalf("expected canonical queried session_id %q, got %q", "session-grpc-canonical-1", queryResp.GetAccrual().GetSessionId())
	}
	if queryResp.GetAccrual().GetProviderId() != "provider-grpc-canonical-1" {
		t.Fatalf("expected canonical queried provider_id %q, got %q", "provider-grpc-canonical-1", queryResp.GetAccrual().GetProviderId())
	}
	if queryResp.GetAccrual().GetAssetDenom() != "uusdc" {
		t.Fatalf("expected canonical queried asset_denom %q, got %q", "uusdc", queryResp.GetAccrual().GetAssetDenom())
	}
}

func TestGRPCAdaptersDistributionCanonicalWriteAndMixedCaseQuery(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgAdapter(NewMsgServer(&k))
	queryAdapter := NewGRPCQueryAdapter(NewQueryServer(&k))

	_, err := msgAdapter.RecordAccrual(context.Background(), &pb.MsgRecordAccrualRequest{
		Accrual: &pb.RewardAccrual{
			AccrualId:      "  AcCrUaL-DIST-GRPC-Canonical-1  ",
			SessionId:      "session-dist-grpc-canonical-1",
			ProviderId:     "provider-dist-grpc-canonical-1",
			AssetDenom:     "uusdc",
			Amount:         88,
			OperationState: pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
	})
	if err != nil {
		t.Fatalf("expected seed accrual success, got %v", err)
	}

	recordResp, err := msgAdapter.RecordDistribution(context.Background(), &pb.MsgRecordDistributionRequest{
		Distribution: &pb.DistributionRecord{
			DistributionId: "  DiSt-GRPC-Canonical-1  ",
			AccrualId:      "  ACCRUAL-DIST-GRPC-CANONICAL-1  ",
			PayoutRef:      "payout-dist-grpc-canonical-1",
		},
	})
	if err != nil {
		t.Fatalf("expected record distribution success, got %v", err)
	}
	if recordResp.GetDistribution() == nil {
		t.Fatal("expected distribution in record response")
	}
	if recordResp.GetDistribution().GetDistributionId() != "dist-grpc-canonical-1" {
		t.Fatalf("expected canonical distribution_id %q, got %q", "dist-grpc-canonical-1", recordResp.GetDistribution().GetDistributionId())
	}
	if recordResp.GetDistribution().GetAccrualId() != "accrual-dist-grpc-canonical-1" {
		t.Fatalf("expected canonical accrual_id %q, got %q", "accrual-dist-grpc-canonical-1", recordResp.GetDistribution().GetAccrualId())
	}

	queryResp, err := queryAdapter.DistributionRecord(context.Background(), &pb.QueryDistributionRecordRequest{
		DistributionId: "  DIST-GRPC-CANONICAL-1  ",
	})
	if err != nil {
		t.Fatalf("expected mixed-case distribution query success, got %v", err)
	}
	if !queryResp.GetFound() {
		t.Fatal("expected found=true for mixed-case distribution query")
	}
	if queryResp.GetDistribution() == nil {
		t.Fatal("expected distribution in query response")
	}
	if queryResp.GetDistribution().GetDistributionId() != "dist-grpc-canonical-1" {
		t.Fatalf("expected canonical queried distribution_id %q, got %q", "dist-grpc-canonical-1", queryResp.GetDistribution().GetDistributionId())
	}
	if queryResp.GetDistribution().GetAccrualId() != "accrual-dist-grpc-canonical-1" {
		t.Fatalf("expected canonical queried accrual_id %q, got %q", "accrual-dist-grpc-canonical-1", queryResp.GetDistribution().GetAccrualId())
	}
}

func TestGRPCMsgAdapterRecordDistributionMissingAccrualClassification(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgAdapter(NewMsgServer(&k))

	resp, err := adapter.RecordDistribution(context.Background(), &pb.MsgRecordDistributionRequest{
		Distribution: &pb.DistributionRecord{
			DistributionId: "dist-grpc-missing-accrual",
			AccrualId:      "acc-grpc-missing",
			PayoutRef:      "payout-grpc-missing-accrual",
		},
	})
	if err == nil {
		t.Fatal("expected missing accrual error")
	}
	if !errors.Is(err, ErrAccrualNotFound) {
		t.Fatalf("expected ErrAccrualNotFound, got %v", err)
	}
	if resp != nil {
		t.Fatalf("expected nil response on error, got %+v", resp)
	}
}

func TestGRPCQueryAdapterNotFoundReturnsFoundFalse(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCQueryAdapter(NewQueryServer(&k))

	accrualResp, err := adapter.RewardAccrual(context.Background(), &pb.QueryRewardAccrualRequest{AccrualId: "missing"})
	if err != nil {
		t.Fatalf("expected no error on missing accrual query, got %v", err)
	}
	if accrualResp.GetFound() {
		t.Fatal("expected missing accrual query to return found=false")
	}

	distributionResp, err := adapter.DistributionRecord(context.Background(), &pb.QueryDistributionRecordRequest{DistributionId: "missing"})
	if err != nil {
		t.Fatalf("expected no error on missing distribution query, got %v", err)
	}
	if distributionResp.GetFound() {
		t.Fatal("expected missing distribution query to return found=false")
	}
}

func TestGRPCQueryAdapterListMethods(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertAccrual(types.RewardAccrual{
		AccrualID:      "acc-grpc-20",
		ProviderID:     "provider-grpc",
		Amount:         20,
		OperationState: chaintypes.ReconciliationPending,
	})
	k.UpsertAccrual(types.RewardAccrual{
		AccrualID:      "acc-grpc-03",
		ProviderID:     "provider-grpc",
		Amount:         3,
		OperationState: chaintypes.ReconciliationConfirmed,
	})
	k.UpsertDistribution(types.DistributionRecord{
		DistributionID: "dist-grpc-20",
		AccrualID:      "acc-grpc-20",
		PayoutRef:      "payout-grpc-20",
		Status:         chaintypes.ReconciliationSubmitted,
	})
	k.UpsertDistribution(types.DistributionRecord{
		DistributionID: "dist-grpc-03",
		AccrualID:      "acc-grpc-03",
		PayoutRef:      "payout-grpc-03",
		Status:         chaintypes.ReconciliationFailed,
	})

	adapter := NewGRPCQueryAdapter(NewQueryServer(&k))

	accrualsResp, err := adapter.ListRewardAccruals(context.Background(), &pb.QueryListRewardAccrualsRequest{})
	if err != nil {
		t.Fatalf("expected list reward accruals success, got %v", err)
	}
	if len(accrualsResp.GetAccruals()) != 2 {
		t.Fatalf("expected 2 accruals, got %d", len(accrualsResp.GetAccruals()))
	}
	if accrualsResp.GetAccruals()[0].GetAccrualId() != "acc-grpc-03" || accrualsResp.GetAccruals()[1].GetAccrualId() != "acc-grpc-20" {
		t.Fatalf("expected deterministic accrual ordering by ID, got %+v", accrualsResp.GetAccruals())
	}

	distributionsResp, err := adapter.ListDistributionRecords(context.Background(), &pb.QueryListDistributionRecordsRequest{})
	if err != nil {
		t.Fatalf("expected list distribution records success, got %v", err)
	}
	if len(distributionsResp.GetDistributions()) != 2 {
		t.Fatalf("expected 2 distributions, got %d", len(distributionsResp.GetDistributions()))
	}
	if distributionsResp.GetDistributions()[0].GetDistributionId() != "dist-grpc-03" || distributionsResp.GetDistributions()[1].GetDistributionId() != "dist-grpc-20" {
		t.Fatalf("expected deterministic distribution ordering by ID, got %+v", distributionsResp.GetDistributions())
	}
}

func TestGRPCAdaptersNilKeeperPropagation(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	msgAdapter := NewGRPCMsgAdapter(NewMsgServer(k))
	queryAdapter := NewGRPCQueryAdapter(NewQueryServer(k))

	_, accrueErr := msgAdapter.RecordAccrual(context.Background(), &pb.MsgRecordAccrualRequest{
		Accrual: &pb.RewardAccrual{
			AccrualId:  "acc-grpc-nil",
			ProviderId: "provider-grpc-nil",
		},
	})
	if !errors.Is(accrueErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from msg adapter, got %v", accrueErr)
	}

	_, getErr := queryAdapter.RewardAccrual(context.Background(), &pb.QueryRewardAccrualRequest{AccrualId: "acc-grpc-nil"})
	if !errors.Is(getErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from query adapter get, got %v", getErr)
	}

	_, listErr := queryAdapter.ListRewardAccruals(context.Background(), &pb.QueryListRewardAccrualsRequest{})
	if !errors.Is(listErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from query adapter list, got %v", listErr)
	}
}

func TestStatusMappingFromAndToProtoCoversExplicitAndDefaultBranches(t *testing.T) {
	t.Parallel()

	fromProtoCases := []struct {
		name string
		in   pb.ReconciliationStatus
		want chaintypes.ReconciliationStatus
	}{
		{
			name: "pending",
			in:   pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
			want: chaintypes.ReconciliationPending,
		},
		{
			name: "submitted",
			in:   pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
			want: chaintypes.ReconciliationSubmitted,
		},
		{
			name: "confirmed",
			in:   pb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
			want: chaintypes.ReconciliationConfirmed,
		},
		{
			name: "failed",
			in:   pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
			want: chaintypes.ReconciliationFailed,
		},
		{
			name: "default-unspecified",
			in:   pb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
			want: "",
		},
	}
	for _, tc := range fromProtoCases {
		tc := tc
		t.Run("fromProto/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := protoStatusToModule(tc.in)
			if got != tc.want {
				t.Fatalf("protoStatusToModule(%v): expected %q, got %q", tc.in, tc.want, got)
			}
		})
	}

	toProtoCases := []struct {
		name string
		in   chaintypes.ReconciliationStatus
		want pb.ReconciliationStatus
	}{
		{
			name: "pending",
			in:   chaintypes.ReconciliationPending,
			want: pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
		},
		{
			name: "submitted",
			in:   chaintypes.ReconciliationSubmitted,
			want: pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
		{
			name: "confirmed",
			in:   chaintypes.ReconciliationConfirmed,
			want: pb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
		},
		{
			name: "failed",
			in:   chaintypes.ReconciliationFailed,
			want: pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
		},
		{
			name: "default-empty",
			in:   "",
			want: pb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
		},
	}
	for _, tc := range toProtoCases {
		tc := tc
		t.Run("toProto/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := moduleStatusToProto(tc.in)
			if got != tc.want {
				t.Fatalf("moduleStatusToProto(%q): expected %v, got %v", tc.in, tc.want, got)
			}
		})
	}
}
