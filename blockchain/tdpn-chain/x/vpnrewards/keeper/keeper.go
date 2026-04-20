package keeper

import (
	"fmt"
	"sort"
	"strings"
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
	_ = k.UpsertAccrualWithError(record)
}

func (k *Keeper) UpsertAccrualWithError(record types.RewardAccrual) error {
	normalized := normalizeAccrual(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertAccrualLocked(normalized)
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
		if err := k.upsertAccrualLocked(normalizedExisting); err != nil {
			return types.RewardAccrual{}, err
		}
		return normalizedExisting, nil
	}

	if err := k.upsertAccrualLocked(normalized); err != nil {
		return types.RewardAccrual{}, err
	}
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
	records, err := k.ListAccrualsWithError()
	if err != nil {
		return nil
	}
	return records
}

// ListAccrualsWithError returns all accrual records ordered by accrual ID ascending.
func (k *Keeper) ListAccrualsWithError() ([]types.RewardAccrual, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records, err := k.listAccrualsLocked()
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i] = normalizeAccrual(records[i])
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].AccrualID < records[j].AccrualID
	})
	return records, nil
}

func (k *Keeper) UpsertDistribution(record types.DistributionRecord) {
	_ = k.UpsertDistributionWithError(record)
}

func (k *Keeper) UpsertDistributionWithError(record types.DistributionRecord) error {
	normalized := normalizeDistribution(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertDistributionLocked(normalized)
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
		if err := k.upsertDistributionLocked(normalizedExisting); err != nil {
			return types.DistributionRecord{}, err
		}
		if err := k.advanceAccrualForDistributionLocked(normalizedExisting.AccrualID); err != nil {
			return types.DistributionRecord{}, err
		}
		return normalizedExisting, nil
	}

	if _, accrualOK := k.store.GetAccrual(normalized.AccrualID); !accrualOK {
		return types.DistributionRecord{}, accrualNotFoundError(normalized.AccrualID)
	}
	if byAccrual, found, err := k.distributionByAccrualLocked(normalized.AccrualID); err != nil {
		return types.DistributionRecord{}, err
	} else if found && byAccrual.DistributionID != normalized.DistributionID {
		return types.DistributionRecord{}, conflictError("distribution accrual_id", normalized.AccrualID)
	}

	if err := k.upsertDistributionLocked(normalized); err != nil {
		return types.DistributionRecord{}, err
	}
	if err := k.advanceAccrualForDistributionLocked(normalized.AccrualID); err != nil {
		return types.DistributionRecord{}, err
	}
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
	records, err := k.ListDistributionsWithError()
	if err != nil {
		return nil
	}
	return records
}

// ListDistributionsWithError returns all distribution records ordered by distribution ID ascending.
func (k *Keeper) ListDistributionsWithError() ([]types.DistributionRecord, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records, err := k.listDistributionsLocked()
	if err != nil {
		return nil, err
	}
	for i := range records {
		records[i] = normalizeDistribution(records[i])
	}
	sort.Slice(records, func(i, j int) bool {
		return records[i].DistributionID < records[j].DistributionID
	})
	return records, nil
}

func (k *Keeper) advanceAccrualForDistributionLocked(accrualID string) error {
	if accrualID == "" {
		return nil
	}
	accrual, ok := k.store.GetAccrual(accrualID)
	if !ok {
		return accrualNotFoundError(accrualID)
	}

	normalized := normalizeAccrual(accrual)
	if normalized.OperationState == chaintypes.ReconciliationPending || normalized.OperationState == chaintypes.ReconciliationSubmitted {
		normalized.OperationState = chaintypes.ReconciliationConfirmed
	}
	if err := k.upsertAccrualLocked(normalized); err != nil {
		return err
	}
	return nil
}

func (k *Keeper) upsertAccrualLocked(record types.RewardAccrual) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertAccrualWithError(record); err != nil {
			return fmt.Errorf("persist accrual %q: %w", record.AccrualID, err)
		}
		return nil
	}

	k.store.UpsertAccrual(record)
	return nil
}

func (k *Keeper) upsertDistributionLocked(record types.DistributionRecord) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertDistributionWithError(record); err != nil {
			return fmt.Errorf("persist distribution %q: %w", record.DistributionID, err)
		}
		return nil
	}

	k.store.UpsertDistribution(record)
	return nil
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

func (k *Keeper) distributionByAccrualLocked(accrualID string) (types.DistributionRecord, bool, error) {
	accrualID = strings.TrimSpace(accrualID)
	if accrualID == "" {
		return types.DistributionRecord{}, false, nil
	}
	records, err := k.listDistributionsLocked()
	if err != nil {
		return types.DistributionRecord{}, false, err
	}
	for _, record := range records {
		normalized := normalizeDistribution(record)
		if normalized.AccrualID == accrualID {
			return normalized, true, nil
		}
	}
	return types.DistributionRecord{}, false, nil
}

func (k *Keeper) listAccrualsLocked() ([]types.RewardAccrual, error) {
	if readAwareStore, ok := k.store.(KeeperStoreWithReadErrors); ok {
		records, err := readAwareStore.ListAccrualsWithError()
		if err != nil {
			return nil, fmt.Errorf("load accruals: %w", err)
		}
		return records, nil
	}
	return k.store.ListAccruals(), nil
}

func (k *Keeper) listDistributionsLocked() ([]types.DistributionRecord, error) {
	if readAwareStore, ok := k.store.(KeeperStoreWithReadErrors); ok {
		records, err := readAwareStore.ListDistributionsWithError()
		if err != nil {
			return nil, fmt.Errorf("load distributions: %w", err)
		}
		return records, nil
	}
	return k.store.ListDistributions(), nil
}

func conflictError(kind string, id string) error {
	return fmt.Errorf("%s %q already exists with conflicting fields", kind, id)
}

func accrualNotFoundError(accrualID string) error {
	return fmt.Errorf("accrual %q not found", accrualID)
}
