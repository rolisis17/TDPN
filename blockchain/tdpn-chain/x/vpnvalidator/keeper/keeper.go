package keeper

import (
	"fmt"
	"slices"
	"sync"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
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

func (k *Keeper) UpsertEligibility(record types.ValidatorEligibility) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertEligibility(record)
}

// CreateEligibility inserts eligibility with idempotency semantics keyed by ValidatorID.
func (k *Keeper) CreateEligibility(record types.ValidatorEligibility) (types.ValidatorEligibility, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.ValidatorEligibility{}, err
	}

	normalized := normalizeEligibility(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetEligibility(normalized.ValidatorID)
	if ok {
		normalizedExisting := normalizeEligibility(existing)
		if !eligibilityRecordsEqual(normalizedExisting, normalized) {
			return types.ValidatorEligibility{}, conflictError("validator eligibility", normalized.ValidatorID)
		}
		k.store.UpsertEligibility(normalizedExisting)
		return normalizedExisting, nil
	}

	k.store.UpsertEligibility(normalized)
	return normalized, nil
}

func (k *Keeper) GetEligibility(validatorID string) (types.ValidatorEligibility, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetEligibility(validatorID)
}

func (k *Keeper) ListEligibilities() []types.ValidatorEligibility {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := k.store.ListEligibilities()
	slices.SortFunc(records, func(a, b types.ValidatorEligibility) int {
		return compareByID(a.ValidatorID, b.ValidatorID)
	})
	return records
}

func (k *Keeper) UpsertStatusRecord(record types.ValidatorStatusRecord) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertStatusRecord(record)
}

// CreateStatusRecord inserts status with idempotency semantics keyed by StatusID.
func (k *Keeper) CreateStatusRecord(record types.ValidatorStatusRecord) (types.ValidatorStatusRecord, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.ValidatorStatusRecord{}, err
	}

	normalized := normalizeStatusRecord(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	eligibility, ok := k.store.GetEligibility(normalized.ValidatorID)
	if !ok {
		return types.ValidatorStatusRecord{}, eligibilityNotFoundError(normalized.ValidatorID)
	}
	if eligibility.ValidatorID != normalized.ValidatorID {
		return types.ValidatorStatusRecord{}, eligibilityMismatchError(normalized.ValidatorID, eligibility.ValidatorID)
	}

	existing, ok := k.store.GetStatusRecord(normalized.StatusID)
	if ok {
		normalizedExisting := normalizeStatusRecord(existing)
		if !statusRecordEqual(normalizedExisting, normalized) {
			return types.ValidatorStatusRecord{}, conflictError("validator status", normalized.StatusID)
		}
		k.store.UpsertStatusRecord(normalizedExisting)
		return normalizedExisting, nil
	}

	k.store.UpsertStatusRecord(normalized)
	return normalized, nil
}

func (k *Keeper) GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetStatusRecord(statusID)
}

func (k *Keeper) ListStatusRecords() []types.ValidatorStatusRecord {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := k.store.ListStatusRecords()
	slices.SortFunc(records, func(a, b types.ValidatorStatusRecord) int {
		return compareByID(a.StatusID, b.StatusID)
	})
	return records
}

func normalizeEligibility(record types.ValidatorEligibility) types.ValidatorEligibility {
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeStatusRecord(record types.ValidatorStatusRecord) types.ValidatorStatusRecord {
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationSubmitted
	}
	return record
}

func eligibilityRecordsEqual(a, b types.ValidatorEligibility) bool {
	return a.ValidatorID == b.ValidatorID &&
		a.OperatorAddress == b.OperatorAddress &&
		a.Eligible == b.Eligible &&
		a.PolicyReason == b.PolicyReason &&
		a.UpdatedAtUnix == b.UpdatedAtUnix &&
		a.Status == b.Status
}

func statusRecordEqual(a, b types.ValidatorStatusRecord) bool {
	return a.StatusID == b.StatusID &&
		a.ValidatorID == b.ValidatorID &&
		a.ConsensusAddress == b.ConsensusAddress &&
		a.LifecycleStatus == b.LifecycleStatus &&
		a.EvidenceHeight == b.EvidenceHeight &&
		a.EvidenceRef == b.EvidenceRef &&
		a.RecordedAtUnix == b.RecordedAtUnix &&
		a.Status == b.Status
}

func compareByID(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

func conflictError(kind string, id string) error {
	return fmt.Errorf("%s %q already exists with conflicting fields", kind, id)
}

func eligibilityNotFoundError(validatorID string) error {
	return fmt.Errorf("validator eligibility %q not found", validatorID)
}

func eligibilityMismatchError(recordValidatorID, eligibilityValidatorID string) error {
	return fmt.Errorf("validator status validator %q does not match eligibility %q", recordValidatorID, eligibilityValidatorID)
}
