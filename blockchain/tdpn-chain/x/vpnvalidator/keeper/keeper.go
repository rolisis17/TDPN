package keeper

import (
	"fmt"
	"slices"
	"strings"
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
	record = normalizeEligibility(record)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertEligibility(record)
}

// CreateEligibility inserts eligibility with idempotency semantics keyed by ValidatorID.
func (k *Keeper) CreateEligibility(record types.ValidatorEligibility) (types.ValidatorEligibility, error) {
	normalized := normalizeEligibility(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.ValidatorEligibility{}, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetEligibility(normalized.ValidatorID)
	if ok {
		normalizedExisting := normalizeEligibility(existing)
		if !eligibilityRecordsEqual(normalizedExisting, normalized) {
			return types.ValidatorEligibility{}, conflictError("validator eligibility", normalized.ValidatorID)
		}
	}

	existingByCanonical := listEligibilityByCanonicalID(k.store.ListEligibilities(), normalized.ValidatorID)
	if len(existingByCanonical) > 0 {
		for _, existingRecord := range existingByCanonical {
			if !eligibilityRecordsEqual(existingRecord, normalized) {
				return types.ValidatorEligibility{}, conflictError("validator eligibility", normalized.ValidatorID)
			}
		}
		k.store.UpsertEligibility(normalized)
		return normalized, nil
	}

	k.store.UpsertEligibility(normalized)
	return normalized, nil
}

func (k *Keeper) GetEligibility(validatorID string) (types.ValidatorEligibility, bool) {
	canonicalID := canonicalValidatorID(validatorID)

	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetEligibility(canonicalID)
	if !ok && validatorID != canonicalID {
		record, ok = k.store.GetEligibility(validatorID)
	}
	if !ok {
		trimmed := strings.TrimSpace(validatorID)
		if trimmed != "" && trimmed != canonicalID && trimmed != validatorID {
			record, ok = k.store.GetEligibility(trimmed)
		}
	}
	if !ok {
		record, ok = selectCompatibilityEligibilityRecord(k.store.ListEligibilities(), canonicalID)
		if !ok {
			return types.ValidatorEligibility{}, false
		}
	}
	return normalizeEligibility(record), true
}

func (k *Keeper) ListEligibilities() []types.ValidatorEligibility {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := dedupeCanonicalEligibilities(k.store.ListEligibilities())
	slices.SortFunc(records, func(a, b types.ValidatorEligibility) int {
		return compareByID(a.ValidatorID, b.ValidatorID)
	})
	return records
}

func (k *Keeper) UpsertStatusRecord(record types.ValidatorStatusRecord) {
	record = normalizeStatusRecord(record)
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertStatusRecord(record)
}

// CreateStatusRecord inserts status with idempotency semantics keyed by StatusID.
func (k *Keeper) CreateStatusRecord(record types.ValidatorStatusRecord) (types.ValidatorStatusRecord, error) {
	normalized := normalizeStatusRecord(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.ValidatorStatusRecord{}, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	eligibility, ok := k.store.GetEligibility(normalized.ValidatorID)
	if !ok {
		eligibility, ok = selectCompatibilityEligibilityRecord(k.store.ListEligibilities(), normalized.ValidatorID)
	}
	if !ok {
		return types.ValidatorStatusRecord{}, eligibilityNotFoundError(normalized.ValidatorID)
	}
	normalizedEligibility := normalizeEligibility(eligibility)
	if normalizedEligibility.ValidatorID != normalized.ValidatorID {
		return types.ValidatorStatusRecord{}, eligibilityMismatchError(normalized.ValidatorID, normalizedEligibility.ValidatorID)
	}

	existing, ok := k.store.GetStatusRecord(normalized.StatusID)
	if ok {
		normalizedExisting := normalizeStatusRecord(existing)
		if !statusRecordEqual(normalizedExisting, normalized) {
			return types.ValidatorStatusRecord{}, conflictError("validator status", normalized.StatusID)
		}
	}

	existingByCanonical := listStatusByCanonicalID(k.store.ListStatusRecords(), normalized.StatusID)
	if len(existingByCanonical) > 0 {
		for _, existingRecord := range existingByCanonical {
			if !statusRecordEqual(existingRecord, normalized) {
				return types.ValidatorStatusRecord{}, conflictError("validator status", normalized.StatusID)
			}
		}
		k.store.UpsertStatusRecord(normalized)
		return normalized, nil
	}

	k.store.UpsertStatusRecord(normalized)
	return normalized, nil
}

func (k *Keeper) GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool) {
	canonicalID := canonicalStatusID(statusID)

	k.mu.RLock()
	defer k.mu.RUnlock()

	record, ok := k.store.GetStatusRecord(canonicalID)
	if !ok && statusID != canonicalID {
		record, ok = k.store.GetStatusRecord(statusID)
	}
	if !ok {
		trimmed := strings.TrimSpace(statusID)
		if trimmed != "" && trimmed != canonicalID && trimmed != statusID {
			record, ok = k.store.GetStatusRecord(trimmed)
		}
	}
	if !ok {
		record, ok = selectCompatibilityStatusRecord(k.store.ListStatusRecords(), canonicalID)
		if !ok {
			return types.ValidatorStatusRecord{}, false
		}
	}
	return normalizeStatusRecord(record), true
}

func (k *Keeper) ListStatusRecords() []types.ValidatorStatusRecord {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := dedupeCanonicalStatusRecords(k.store.ListStatusRecords())
	slices.SortFunc(records, func(a, b types.ValidatorStatusRecord) int {
		return compareByID(a.StatusID, b.StatusID)
	})
	return records
}

// SelectEpochValidators applies deterministic bootstrap policy for stable and rotating seat selection.
func (k *Keeper) SelectEpochValidators(
	policy types.EpochSelectionPolicy,
	candidates []types.EpochValidatorCandidate,
) (types.EpochSelectionResult, error) {
	return types.SelectEpochValidators(policy, candidates)
}

func normalizeEligibility(record types.ValidatorEligibility) types.ValidatorEligibility {
	record = record.Canonicalize()
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeStatusRecord(record types.ValidatorStatusRecord) types.ValidatorStatusRecord {
	record = record.Canonicalize()
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationSubmitted
	}
	return record
}

func canonicalValidatorID(validatorID string) string {
	return (types.ValidatorEligibility{ValidatorID: validatorID}).Canonicalize().ValidatorID
}

func canonicalStatusID(statusID string) string {
	return (types.ValidatorStatusRecord{StatusID: statusID}).Canonicalize().StatusID
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

func listEligibilityByCanonicalID(records []types.ValidatorEligibility, canonicalValidatorID string) []types.ValidatorEligibility {
	matches := make([]types.ValidatorEligibility, 0)
	for _, record := range records {
		normalized := normalizeEligibility(record)
		if normalized.ValidatorID == canonicalValidatorID {
			matches = append(matches, normalized)
		}
	}
	return matches
}

func listStatusByCanonicalID(records []types.ValidatorStatusRecord, canonicalStatusID string) []types.ValidatorStatusRecord {
	matches := make([]types.ValidatorStatusRecord, 0)
	for _, record := range records {
		normalized := normalizeStatusRecord(record)
		if normalized.StatusID == canonicalStatusID {
			matches = append(matches, normalized)
		}
	}
	return matches
}

func selectCompatibilityEligibilityRecord(records []types.ValidatorEligibility, canonicalValidatorID string) (types.ValidatorEligibility, bool) {
	var selected types.ValidatorEligibility
	found := false

	for _, record := range records {
		normalized := normalizeEligibility(record)
		if normalized.ValidatorID != canonicalValidatorID {
			continue
		}
		if !found || compareEligibilityRecord(normalized, selected) < 0 {
			selected = normalized
			found = true
		}
	}

	return selected, found
}

func selectCompatibilityStatusRecord(records []types.ValidatorStatusRecord, canonicalStatusID string) (types.ValidatorStatusRecord, bool) {
	var selected types.ValidatorStatusRecord
	found := false

	for _, record := range records {
		normalized := normalizeStatusRecord(record)
		if normalized.StatusID != canonicalStatusID {
			continue
		}
		if !found || compareStatusRecord(normalized, selected) < 0 {
			selected = normalized
			found = true
		}
	}

	return selected, found
}

func dedupeCanonicalEligibilities(records []types.ValidatorEligibility) []types.ValidatorEligibility {
	dedupedByCanonicalID := make(map[string]types.ValidatorEligibility)

	for _, record := range records {
		normalized := normalizeEligibility(record)
		existing, ok := dedupedByCanonicalID[normalized.ValidatorID]
		if !ok || compareEligibilityRecord(normalized, existing) < 0 {
			dedupedByCanonicalID[normalized.ValidatorID] = normalized
		}
	}

	deduped := make([]types.ValidatorEligibility, 0, len(dedupedByCanonicalID))
	for _, record := range dedupedByCanonicalID {
		deduped = append(deduped, record)
	}

	return deduped
}

func dedupeCanonicalStatusRecords(records []types.ValidatorStatusRecord) []types.ValidatorStatusRecord {
	dedupedByCanonicalID := make(map[string]types.ValidatorStatusRecord)

	for _, record := range records {
		normalized := normalizeStatusRecord(record)
		existing, ok := dedupedByCanonicalID[normalized.StatusID]
		if !ok || compareStatusRecord(normalized, existing) < 0 {
			dedupedByCanonicalID[normalized.StatusID] = normalized
		}
	}

	deduped := make([]types.ValidatorStatusRecord, 0, len(dedupedByCanonicalID))
	for _, record := range dedupedByCanonicalID {
		deduped = append(deduped, record)
	}

	return deduped
}

func compareEligibilityRecord(a, b types.ValidatorEligibility) int {
	if cmp := compareByID(a.ValidatorID, b.ValidatorID); cmp != 0 {
		return cmp
	}
	if cmp := compareByID(a.OperatorAddress, b.OperatorAddress); cmp != 0 {
		return cmp
	}
	switch {
	case !a.Eligible && b.Eligible:
		return -1
	case a.Eligible && !b.Eligible:
		return 1
	}
	if cmp := compareByID(a.PolicyReason, b.PolicyReason); cmp != 0 {
		return cmp
	}
	switch {
	case a.UpdatedAtUnix < b.UpdatedAtUnix:
		return -1
	case a.UpdatedAtUnix > b.UpdatedAtUnix:
		return 1
	}
	return compareByID(string(a.Status), string(b.Status))
}

func compareStatusRecord(a, b types.ValidatorStatusRecord) int {
	if cmp := compareByID(a.StatusID, b.StatusID); cmp != 0 {
		return cmp
	}
	if cmp := compareByID(a.ValidatorID, b.ValidatorID); cmp != 0 {
		return cmp
	}
	if cmp := compareByID(a.ConsensusAddress, b.ConsensusAddress); cmp != 0 {
		return cmp
	}
	if cmp := compareByID(a.LifecycleStatus, b.LifecycleStatus); cmp != 0 {
		return cmp
	}
	switch {
	case a.EvidenceHeight < b.EvidenceHeight:
		return -1
	case a.EvidenceHeight > b.EvidenceHeight:
		return 1
	}
	if cmp := compareByID(a.EvidenceRef, b.EvidenceRef); cmp != 0 {
		return cmp
	}
	switch {
	case a.RecordedAtUnix < b.RecordedAtUnix:
		return -1
	case a.RecordedAtUnix > b.RecordedAtUnix:
		return 1
	}
	return compareByID(string(a.Status), string(b.Status))
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
