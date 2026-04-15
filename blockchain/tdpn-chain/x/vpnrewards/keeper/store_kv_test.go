package keeper

import (
	"encoding/json"
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

func TestKVStoreListSkipsCorruptEntries(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	validAccrual := types.RewardAccrual{
		AccrualID:      "acc-good",
		ProviderID:     "provider-1",
		Amount:         9,
		OperationState: chaintypes.ReconciliationPending,
	}
	store.UpsertAccrual(validAccrual)
	backend.Set([]byte(accrualPrefix+"acc-bad"), []byte("{not-json"))

	validDistribution := types.DistributionRecord{
		DistributionID: "dist-good",
		AccrualID:      validAccrual.AccrualID,
		PayoutRef:      "payout-good",
		Status:         chaintypes.ReconciliationSubmitted,
	}
	store.UpsertDistribution(validDistribution)
	backend.Set([]byte(distributionPrefix+"dist-bad"), []byte("{not-json"))

	accruals := store.ListAccruals()
	if len(accruals) != 1 {
		t.Fatalf("expected only valid accrual to be listed, got %d entries", len(accruals))
	}
	if accruals[0] != validAccrual {
		t.Fatalf("expected listed accrual %+v, got %+v", validAccrual, accruals[0])
	}

	distributions := store.ListDistributions()
	if len(distributions) != 1 {
		t.Fatalf("expected only valid distribution to be listed, got %d entries", len(distributions))
	}
	if distributions[0] != validDistribution {
		t.Fatalf("expected listed distribution %+v, got %+v", validDistribution, distributions[0])
	}

	if _, ok := store.GetAccrual("acc-bad"); ok {
		t.Fatal("expected corrupt accrual payload to be unreadable")
	}
	if _, ok := store.GetDistribution("dist-bad"); ok {
		t.Fatal("expected corrupt distribution payload to be unreadable")
	}
}

func TestNewKVStoreNilFallbackAndPrefixIsolation(t *testing.T) {
	t.Parallel()

	store := NewKVStore(nil)

	accrual := types.RewardAccrual{
		AccrualID:      "acc-fallback",
		ProviderID:     "provider-fallback",
		Amount:         5,
		OperationState: chaintypes.ReconciliationPending,
	}
	store.UpsertAccrual(accrual)

	distribution := types.DistributionRecord{
		DistributionID: "dist-fallback",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-fallback",
		Status:         chaintypes.ReconciliationSubmitted,
	}
	store.UpsertDistribution(distribution)

	gotAccrual, ok := store.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatal("expected accrual to be readable from nil-store fallback")
	}
	if gotAccrual != accrual {
		t.Fatalf("expected fallback accrual %+v, got %+v", accrual, gotAccrual)
	}

	gotDistribution, ok := store.GetDistribution(distribution.DistributionID)
	if !ok {
		t.Fatal("expected distribution to be readable from nil-store fallback")
	}
	if gotDistribution != distribution {
		t.Fatalf("expected fallback distribution %+v, got %+v", distribution, gotDistribution)
	}

	// Inject data under unrelated prefix directly into the backing MapStore and ensure
	// vpnrewards prefix scans do not pick it up.
	shadowStore := kvtypes.NewMapStore()
	payload, err := json.Marshal(accrual)
	if err != nil {
		t.Fatalf("failed to marshal accrual fixture: %v", err)
	}
	shadowStore.Set([]byte("other/acc-fallback"), payload)
	shadowKV := NewKVStore(shadowStore)

	if got := len(shadowKV.ListAccruals()); got != 0 {
		t.Fatalf("expected no accruals from unrelated prefix, got %d", got)
	}
	if got := len(shadowKV.ListDistributions()); got != 0 {
		t.Fatalf("expected no distributions from unrelated prefix, got %d", got)
	}
}
