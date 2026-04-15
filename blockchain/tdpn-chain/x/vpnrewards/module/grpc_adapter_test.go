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
