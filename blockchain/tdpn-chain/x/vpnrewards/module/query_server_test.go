package module

import (
	"errors"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

func TestQueryServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewQueryServer(k)

	_, accrualErr := server.GetAccrual(GetAccrualRequest{AccrualID: "acc-nil"})
	if !errors.Is(accrualErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for accrual query, got %v", accrualErr)
	}

	_, distributionErr := server.GetDistribution(GetDistributionRequest{DistributionID: "dist-nil"})
	if !errors.Is(distributionErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for distribution query, got %v", distributionErr)
	}

	_, listAccrualsErr := server.ListAccruals(ListAccrualsRequest{})
	if !errors.Is(listAccrualsErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list accruals query, got %v", listAccrualsErr)
	}

	_, listDistributionsErr := server.ListDistributions(ListDistributionsRequest{})
	if !errors.Is(listDistributionsErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list distributions query, got %v", listDistributionsErr)
	}
}

func TestQueryServerNotFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewQueryServer(&k)

	_, accrualErr := server.GetAccrual(GetAccrualRequest{AccrualID: "acc-missing"})
	if !errors.Is(accrualErr, ErrAccrualNotFound) {
		t.Fatalf("expected ErrAccrualNotFound, got %v", accrualErr)
	}

	_, distributionErr := server.GetDistribution(GetDistributionRequest{DistributionID: "dist-missing"})
	if !errors.Is(distributionErr, ErrDistributionNotFound) {
		t.Fatalf("expected ErrDistributionNotFound, got %v", distributionErr)
	}
}

func TestQueryServerFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	expectedAccrual := types.RewardAccrual{
		AccrualID:  "acc-1",
		ProviderID: "provider-1",
		Amount:     42,
	}
	expectedDistribution := types.DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      "acc-1",
	}
	k.UpsertAccrual(expectedAccrual)
	k.UpsertDistribution(expectedDistribution)

	server := NewQueryServer(&k)

	accrualResp, accrualErr := server.GetAccrual(GetAccrualRequest{AccrualID: "acc-1"})
	if accrualErr != nil {
		t.Fatalf("expected accrual query success, got %v", accrualErr)
	}
	if accrualResp.Accrual.AccrualID != expectedAccrual.AccrualID {
		t.Fatalf("unexpected accrual id: %q", accrualResp.Accrual.AccrualID)
	}

	distributionResp, distributionErr := server.GetDistribution(GetDistributionRequest{DistributionID: "dist-1"})
	if distributionErr != nil {
		t.Fatalf("expected distribution query success, got %v", distributionErr)
	}
	if distributionResp.Distribution.DistributionID != expectedDistribution.DistributionID {
		t.Fatalf("unexpected distribution id: %q", distributionResp.Distribution.DistributionID)
	}
}

func TestQueryServerListNonEmpty(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertAccrual(types.RewardAccrual{
		AccrualID:  "acc-20",
		ProviderID: "provider-1",
		Amount:     20,
	})
	k.UpsertAccrual(types.RewardAccrual{
		AccrualID:  "acc-03",
		ProviderID: "provider-1",
		Amount:     3,
	})
	k.UpsertDistribution(types.DistributionRecord{
		DistributionID: "dist-20",
		AccrualID:      "acc-20",
		PayoutRef:      "payout-20",
	})
	k.UpsertDistribution(types.DistributionRecord{
		DistributionID: "dist-03",
		AccrualID:      "acc-03",
		PayoutRef:      "payout-03",
	})

	server := NewQueryServer(&k)

	accrualResp, err := server.ListAccruals(ListAccrualsRequest{})
	if err != nil {
		t.Fatalf("expected list accruals success, got %v", err)
	}
	if len(accrualResp.Accruals) != 2 {
		t.Fatalf("expected 2 accruals, got %d", len(accrualResp.Accruals))
	}
	if accrualResp.Accruals[0].AccrualID != "acc-03" || accrualResp.Accruals[1].AccrualID != "acc-20" {
		t.Fatalf("expected deterministic accrual ordering by ID, got %+v", accrualResp.Accruals)
	}

	distributionResp, err := server.ListDistributions(ListDistributionsRequest{})
	if err != nil {
		t.Fatalf("expected list distributions success, got %v", err)
	}
	if len(distributionResp.Distributions) != 2 {
		t.Fatalf("expected 2 distributions, got %d", len(distributionResp.Distributions))
	}
	if distributionResp.Distributions[0].DistributionID != "dist-03" || distributionResp.Distributions[1].DistributionID != "dist-20" {
		t.Fatalf("expected deterministic distribution ordering by ID, got %+v", distributionResp.Distributions)
	}
}
