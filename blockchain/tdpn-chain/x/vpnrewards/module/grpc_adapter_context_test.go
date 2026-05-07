package module

import (
	"errors"
	"testing"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnrewards/v1"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
)

func TestGRPCAdaptersNilContextDoesNotPanic(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgAdapter(NewMsgServer(&k))
	queryAdapter := NewGRPCQueryAdapter(NewQueryServer(&k))

	_, accrualErr := msgAdapter.RecordAccrual(nil, nil)
	if !errors.Is(accrualErr, ErrInvalidAccrual) {
		t.Fatalf("expected ErrInvalidAccrual for nil context/request, got %v", accrualErr)
	}

	_, distributionErr := msgAdapter.RecordDistribution(nil, nil)
	if !errors.Is(distributionErr, ErrInvalidDistribution) {
		t.Fatalf("expected ErrInvalidDistribution for nil context/request, got %v", distributionErr)
	}

	accrualResp, err := queryAdapter.RewardAccrual(nil, nil)
	if err != nil {
		t.Fatalf("expected nil error for nil-context missing accrual query, got %v", err)
	}
	if accrualResp.GetFound() {
		t.Fatal("expected found=false for nil-context missing accrual query")
	}

	distributionResp, err := queryAdapter.DistributionRecord(nil, nil)
	if err != nil {
		t.Fatalf("expected nil error for nil-context missing distribution query, got %v", err)
	}
	if distributionResp.GetFound() {
		t.Fatal("expected found=false for nil-context missing distribution query")
	}

	listAccrualsResp, err := queryAdapter.ListRewardAccruals(nil, &pb.QueryListRewardAccrualsRequest{})
	if err != nil {
		t.Fatalf("expected nil error for nil-context accrual list, got %v", err)
	}
	if len(listAccrualsResp.GetAccruals()) != 0 {
		t.Fatalf("expected empty accrual list, got %d", len(listAccrualsResp.GetAccruals()))
	}

	listDistributionsResp, err := queryAdapter.ListDistributionRecords(nil, &pb.QueryListDistributionRecordsRequest{})
	if err != nil {
		t.Fatalf("expected nil error for nil-context distribution list, got %v", err)
	}
	if len(listDistributionsResp.GetDistributions()) != 0 {
		t.Fatalf("expected empty distribution list, got %d", len(listDistributionsResp.GetDistributions()))
	}
}
