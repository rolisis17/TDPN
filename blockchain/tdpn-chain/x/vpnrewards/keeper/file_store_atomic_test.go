package keeper

import (
	"errors"
	"path/filepath"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

func TestKeeperRecordDistributionFileStoreUsesSingleAtomicPersist(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnrewards.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	k := NewKeeperWithStore(store)
	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "acc-file-atomic-1",
		SessionID:      "sess-file-atomic-1",
		ProviderID:     "provider-file-atomic-1",
		Amount:         101,
		OperationState: chaintypes.ReconciliationSubmitted,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	persistCalls := 0
	store.persistHook = func() error {
		persistCalls++
		return nil
	}

	distributionID := "dist-file-atomic-1"
	if _, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: distributionID,
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-file-atomic-1",
	}); err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}

	if persistCalls != 1 {
		t.Fatalf("expected exactly one persist call for atomic record, got %d", persistCalls)
	}

	accrualAfter, ok := k.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatalf("expected accrual %q to exist after recording distribution", accrual.AccrualID)
	}
	if accrualAfter.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected accrual state %q after distribution, got %q", chaintypes.ReconciliationConfirmed, accrualAfter.OperationState)
	}

	if _, ok := k.GetDistribution(distributionID); !ok {
		t.Fatalf("expected distribution %q to be stored", distributionID)
	}
}

func TestKeeperRecordDistributionFileStoreFailureInjectionCannotOrphanAccrualAdvance(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnrewards.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	k := NewKeeperWithStore(store)
	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "acc-file-atomic-failsafe",
		SessionID:      "sess-file-atomic-failsafe",
		ProviderID:     "provider-file-atomic-failsafe",
		Amount:         202,
		OperationState: chaintypes.ReconciliationSubmitted,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	persistCalls := 0
	store.persistHook = func() error {
		persistCalls++
		// Force all writes after the first persist attempt to fail. The atomic
		// file-store path must still only perform one persist for this operation.
		if persistCalls >= 2 {
			return errors.New("forced persist failure after first attempt")
		}
		return nil
	}

	distributionID := "dist-file-atomic-failsafe"
	if _, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: distributionID,
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-file-atomic-failsafe",
	}); err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}

	if persistCalls != 1 {
		t.Fatalf("expected exactly one persist call despite late-phase failure injection, got %d", persistCalls)
	}

	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopening file store returned unexpected error: %v", err)
	}

	durableAccrual, ok := reopened.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatalf("expected durable accrual %q after record", accrual.AccrualID)
	}
	if durableAccrual.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected durable accrual state %q, got %q", chaintypes.ReconciliationConfirmed, durableAccrual.OperationState)
	}

	durableDistribution, ok := reopened.GetDistribution(distributionID)
	if !ok {
		t.Fatalf("expected durable distribution %q after record", distributionID)
	}
	if durableDistribution.AccrualID != accrual.AccrualID {
		t.Fatalf("expected durable distribution accrual id %q, got %q", accrual.AccrualID, durableDistribution.AccrualID)
	}
}

func TestKeeperRecordDistributionFileStoreAtomicPersistFailureRollsBackDurably(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnrewards.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	k := NewKeeperWithStore(store)
	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "acc-file-atomic-failure",
		SessionID:      "sess-file-atomic-failure",
		ProviderID:     "provider-file-atomic-failure",
		Amount:         303,
		OperationState: chaintypes.ReconciliationSubmitted,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	failed := false
	store.persistHook = func() error {
		if !failed {
			failed = true
			return errors.New("forced atomic persist failure")
		}
		return nil
	}

	distributionID := "dist-file-atomic-failure"
	if _, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: distributionID,
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-file-atomic-failure",
	}); err == nil {
		t.Fatal("expected RecordDistribution to fail when atomic persist fails")
	}

	accrualAfter, ok := k.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatalf("expected accrual %q to remain available after failed record", accrual.AccrualID)
	}
	if accrualAfter.OperationState != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected accrual state %q after failed record, got %q", chaintypes.ReconciliationSubmitted, accrualAfter.OperationState)
	}

	if _, ok := k.GetDistribution(distributionID); ok {
		t.Fatalf("expected distribution %q to be absent after failed record", distributionID)
	}

	store.persistHook = nil
	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopening file store returned unexpected error: %v", err)
	}

	durableAccrual, ok := reopened.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatalf("expected durable accrual %q after failed record", accrual.AccrualID)
	}
	if durableAccrual.OperationState != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected durable accrual state %q, got %q", chaintypes.ReconciliationSubmitted, durableAccrual.OperationState)
	}

	if _, ok := reopened.GetDistribution(distributionID); ok {
		t.Fatalf("expected durable distribution %q to be absent after failed record", distributionID)
	}
}
