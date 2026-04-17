package keeper

import (
	"fmt"
	"sort"
	"sync"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

// Keeper defaults to in-memory storage and accepts pluggable stores (file-backed/KV adapters).
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
	normalized := normalizeAccrual(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertAccrual(normalized)
}

// CreateAccrual inserts an accrual with idempotency semantics keyed by AccrualID.
func (k *Keeper) CreateAccrual(record types.RewardAccrual) (types.RewardAccrual, error) {
	normalized := normalizeAccrual(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.RewardAccrual{}, err
	}

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
	normalizedID := normalizeAccrual(types.RewardAccrual{AccrualID: accrualID}).AccrualID

	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetAccrual(normalizedID)
	if !ok {
		return types.RewardAccrual{}, false
	}
	return normalizeAccrual(record), true
}

// ListAccruals returns all accrual records ordered by accrual ID ascending.
func (k *Keeper) ListAccruals() []types.RewardAccrual {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := k.store.ListAccruals()
	for i := range records {
		records[i] = normalizeAccrual(records[i])
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].AccrualID < records[j].AccrualID
	})
	return records
}

func (k *Keeper) UpsertDistribution(record types.DistributionRecord) {
	normalized := normalizeDistribution(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertDistribution(normalized)
}

// RecordDistribution inserts a distribution with idempotency semantics keyed by DistributionID.
func (k *Keeper) RecordDistribution(record types.DistributionRecord) (types.DistributionRecord, error) {
	normalized := normalizeDistribution(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.DistributionRecord{}, err
	}

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
	normalizedID := normalizeDistribution(types.DistributionRecord{DistributionID: distributionID}).DistributionID

	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetDistribution(normalizedID)
	if !ok {
		return types.DistributionRecord{}, false
	}
	return normalizeDistribution(record), true
}

// ListDistributions returns all distribution records ordered by distribution ID ascending.
func (k *Keeper) ListDistributions() []types.DistributionRecord {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := k.store.ListDistributions()
	for i := range records {
		records[i] = normalizeDistribution(records[i])
	}
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
	normalized := record.Canonicalize()
	if normalized.OperationState == "" {
		normalized.OperationState = chaintypes.ReconciliationPending
	}
	return normalized
}

func normalizeDistribution(record types.DistributionRecord) types.DistributionRecord {
	normalized := record.Canonicalize()
	if normalized.Status == "" {
		normalized.Status = chaintypes.ReconciliationSubmitted
	}
	return normalized
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
