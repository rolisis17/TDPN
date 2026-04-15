package keeper

import (
	"fmt"
	"sort"
	"sync"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

// Keeper is a placeholder implementation that will be swapped to Cosmos stores.
type Keeper struct {
	mu    sync.RWMutex
	store KeeperStore
}

func NewKeeper() Keeper {
	return NewKeeperWithStore(nil)
}

func NewKeeperWithStore(store KeeperStore) Keeper {
	if store == nil {
		store = NewInMemoryStore()
	}

	return Keeper{
		store: store,
	}
}

func (k *Keeper) UpsertAccrual(record types.RewardAccrual) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertAccrual(record)
}

// CreateAccrual inserts an accrual with idempotency semantics keyed by AccrualID.
func (k *Keeper) CreateAccrual(record types.RewardAccrual) (types.RewardAccrual, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.RewardAccrual{}, err
	}

	normalized := normalizeAccrual(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetAccrual(normalized.AccrualID)
	if ok {
		normalizedExisting := normalizeAccrual(existing)
		if !accrualRecordsEqual(normalizedExisting, normalized) {
			return types.RewardAccrual{}, conflictError("accrual", normalized.AccrualID)
		}
		// Normalize legacy records persisted via compatibility upserts.
		k.store.UpsertAccrual(normalizedExisting)
		return normalizedExisting, nil
	}

	k.store.UpsertAccrual(normalized)
	return normalized, nil
}

func (k *Keeper) GetAccrual(accrualID string) (types.RewardAccrual, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetAccrual(accrualID)
}

// ListAccruals returns all accrual records ordered by accrual ID ascending.
func (k *Keeper) ListAccruals() []types.RewardAccrual {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := k.store.ListAccruals()
	sort.Slice(records, func(i, j int) bool {
		return records[i].AccrualID < records[j].AccrualID
	})
	return records
}

func (k *Keeper) UpsertDistribution(record types.DistributionRecord) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertDistribution(record)
}

// RecordDistribution inserts a distribution with idempotency semantics keyed by DistributionID.
func (k *Keeper) RecordDistribution(record types.DistributionRecord) (types.DistributionRecord, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.DistributionRecord{}, err
	}

	normalized := normalizeDistribution(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetDistribution(normalized.DistributionID)
	if ok {
		normalizedExisting := normalizeDistribution(existing)
		if !distributionRecordsEqual(normalizedExisting, normalized) {
			return types.DistributionRecord{}, conflictError("distribution", normalized.DistributionID)
		}
		if _, accrualOK := k.store.GetAccrual(normalizedExisting.AccrualID); !accrualOK {
			return types.DistributionRecord{}, accrualNotFoundError(normalizedExisting.AccrualID)
		}
		// Normalize legacy records persisted via compatibility upserts.
		k.store.UpsertDistribution(normalizedExisting)
		k.advanceAccrualForDistributionLocked(normalizedExisting.AccrualID)
		return normalizedExisting, nil
	}

	if _, accrualOK := k.store.GetAccrual(normalized.AccrualID); !accrualOK {
		return types.DistributionRecord{}, accrualNotFoundError(normalized.AccrualID)
	}

	k.store.UpsertDistribution(normalized)
	k.advanceAccrualForDistributionLocked(normalized.AccrualID)
	return normalized, nil
}

func (k *Keeper) GetDistribution(distributionID string) (types.DistributionRecord, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetDistribution(distributionID)
}

// ListDistributions returns all distribution records ordered by distribution ID ascending.
func (k *Keeper) ListDistributions() []types.DistributionRecord {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := k.store.ListDistributions()
	sort.Slice(records, func(i, j int) bool {
		return records[i].DistributionID < records[j].DistributionID
	})
	return records
}

func (k *Keeper) advanceAccrualForDistributionLocked(accrualID string) {
	if accrualID == "" {
		return
	}
	accrual, ok := k.store.GetAccrual(accrualID)
	if !ok {
		return
	}

	normalized := normalizeAccrual(accrual)
	if normalized.OperationState == chaintypes.ReconciliationPending || normalized.OperationState == chaintypes.ReconciliationSubmitted {
		normalized.OperationState = chaintypes.ReconciliationConfirmed
	}
	k.store.UpsertAccrual(normalized)
}

func normalizeAccrual(record types.RewardAccrual) types.RewardAccrual {
	if record.OperationState == "" {
		record.OperationState = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeDistribution(record types.DistributionRecord) types.DistributionRecord {
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationSubmitted
	}
	return record
}

func accrualRecordsEqual(a, b types.RewardAccrual) bool {
	return a.AccrualID == b.AccrualID &&
		a.SessionID == b.SessionID &&
		a.ProviderID == b.ProviderID &&
		a.AssetDenom == b.AssetDenom &&
		a.Amount == b.Amount &&
		a.AccruedAtUnix == b.AccruedAtUnix &&
		a.OperationState == b.OperationState
}

func distributionRecordsEqual(a, b types.DistributionRecord) bool {
	return a.DistributionID == b.DistributionID &&
		a.AccrualID == b.AccrualID &&
		a.PayoutRef == b.PayoutRef &&
		a.DistributedAt == b.DistributedAt &&
		a.Status == b.Status
}

func conflictError(kind string, id string) error {
	return fmt.Errorf("%s %q already exists with conflicting fields", kind, id)
}

func accrualNotFoundError(accrualID string) error {
	return fmt.Errorf("accrual %q not found", accrualID)
}
