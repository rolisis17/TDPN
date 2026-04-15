package keeper

import (
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

func TestKVStoreUpsertGetList(t *testing.T) {
	t.Parallel()

	store := NewKVStore(kvtypes.NewMapStore())

	accrual := types.RewardAccrual{
		AccrualID:      "acc-1",
		SessionID:      "sess-1",
		ProviderID:     "provider-1",
		AssetDenom:     "uusdc",
		Amount:         77,
		OperationState: chaintypes.ReconciliationPending,
	}
	store.UpsertAccrual(accrual)

	gotAccrual, ok := store.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatal("expected accrual to exist")
	}
	if gotAccrual != accrual {
		t.Fatalf("expected accrual %+v, got %+v", accrual, gotAccrual)
	}

	distribution := types.DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-1",
		Status:         chaintypes.ReconciliationSubmitted,
	}
	store.UpsertDistribution(distribution)

	gotDistribution, ok := store.GetDistribution(distribution.DistributionID)
	if !ok {
		t.Fatal("expected distribution to exist")
	}
	if gotDistribution != distribution {
		t.Fatalf("expected distribution %+v, got %+v", distribution, gotDistribution)
	}

	accruals := store.ListAccruals()
	if len(accruals) != 1 {
		t.Fatalf("expected 1 accrual, got %d", len(accruals))
	}
	if accruals[0] != accrual {
		t.Fatalf("expected list accrual %+v, got %+v", accrual, accruals[0])
	}

	distributions := store.ListDistributions()
	if len(distributions) != 1 {
		t.Fatalf("expected 1 distribution, got %d", len(distributions))
	}
	if distributions[0] != distribution {
		t.Fatalf("expected list distribution %+v, got %+v", distribution, distributions[0])
	}
}
