package keeper

import (
	"fmt"
	"sort"
	"sync"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
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

func (k *Keeper) UpsertEvidence(record types.SlashEvidence) {
	record.ViolationType = types.NormalizeViolationType(record.ViolationType)
	_ = k.UpsertEvidenceWithError(record)
}

func (k *Keeper) UpsertEvidenceWithError(record types.SlashEvidence) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	record.ViolationType = types.NormalizeViolationType(record.ViolationType)
	return k.upsertEvidenceLocked(record)
}

// SubmitEvidence inserts evidence with idempotency semantics keyed by EvidenceID.
func (k *Keeper) SubmitEvidence(record types.SlashEvidence) (types.SlashEvidence, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.SlashEvidence{}, err
	}

	normalized := normalizeEvidence(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetEvidence(normalized.EvidenceID)
	if ok {
		normalizedExisting := normalizeEvidence(existing)
		if !slashEvidenceRecordsEqual(normalizedExisting, normalized) {
			return types.SlashEvidence{}, conflictError("evidence", normalized.EvidenceID)
		}
		if err := k.upsertEvidenceLocked(normalizedExisting); err != nil {
			return types.SlashEvidence{}, err
		}
		return normalizedExisting, nil
	}

	if duplicateEvidence, ok, err := k.findEquivalentEvidenceLocked(normalized); err != nil {
		return types.SlashEvidence{}, err
	} else if ok {
		return types.SlashEvidence{}, evidenceReplayConflictError(normalized.EvidenceID, duplicateEvidence.EvidenceID)
	}

	if err := k.upsertEvidenceLocked(normalized); err != nil {
		return types.SlashEvidence{}, err
	}
	return normalized, nil
}

func (k *Keeper) GetEvidence(evidenceID string) (types.SlashEvidence, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetEvidence(evidenceID)
}

func (k *Keeper) ListEvidence() []types.SlashEvidence {
	k.mu.RLock()
	defer k.mu.RUnlock()

	evidence, err := k.listEvidenceLocked()
	if err != nil {
		return nil
	}
	sort.Slice(evidence, func(i, j int) bool {
		return evidence[i].EvidenceID < evidence[j].EvidenceID
	})
	return evidence
}

func (k *Keeper) UpsertPenalty(record types.PenaltyDecision) {
	_ = k.UpsertPenaltyWithError(record)
}

func (k *Keeper) UpsertPenaltyWithError(record types.PenaltyDecision) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertPenaltyLocked(record)
}

// ApplyPenalty inserts a penalty with idempotency semantics keyed by PenaltyID.
func (k *Keeper) ApplyPenalty(record types.PenaltyDecision) (types.PenaltyDecision, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.PenaltyDecision{}, err
	}

	normalized := normalizePenalty(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	evidence, ok := k.store.GetEvidence(normalized.EvidenceID)
	if !ok {
		return types.PenaltyDecision{}, missingEvidenceError(normalized.EvidenceID)
	}
	normalizedEvidence := normalizeEvidence(evidence)

	existing, ok := k.store.GetPenalty(normalized.PenaltyID)
	if ok {
		normalizedExisting := normalizePenalty(existing)
		if !penaltyRecordsEqual(normalizedExisting, normalized) {
			return types.PenaltyDecision{}, conflictError("penalty", normalized.PenaltyID)
		}
		if err := k.persistPenaltyWithEvidenceAdvanceLocked(normalizedExisting, normalizedEvidence); err != nil {
			return types.PenaltyDecision{}, err
		}
		return normalizedExisting, nil
	}

	if conflictingPenalty, ok, err := k.findPenaltyForEvidenceLocked(normalized.EvidenceID); err != nil {
		return types.PenaltyDecision{}, err
	} else if ok {
		return types.PenaltyDecision{}, penaltyEvidenceConflictError(normalized.EvidenceID, conflictingPenalty.PenaltyID)
	}

	if err := k.persistPenaltyWithEvidenceAdvanceLocked(normalized, normalizedEvidence); err != nil {
		return types.PenaltyDecision{}, err
	}
	return normalized, nil
}

func (k *Keeper) GetPenalty(penaltyID string) (types.PenaltyDecision, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetPenalty(penaltyID)
}

func (k *Keeper) ListPenalties() []types.PenaltyDecision {
	k.mu.RLock()
	defer k.mu.RUnlock()

	penalties, err := k.listPenaltiesLocked()
	if err != nil {
		return nil
	}
	sort.Slice(penalties, func(i, j int) bool {
		return penalties[i].PenaltyID < penalties[j].PenaltyID
	})
	return penalties
}

func (k *Keeper) persistPenaltyWithEvidenceAdvanceLocked(
	penalty types.PenaltyDecision,
	evidenceBefore types.SlashEvidence,
) error {
	evidenceAfter := advanceEvidenceStatusForPenalty(evidenceBefore)
	evidenceChanged := !slashEvidenceRecordsEqual(evidenceBefore, evidenceAfter)

	if evidenceChanged {
		if err := k.upsertEvidenceLocked(evidenceAfter); err != nil {
			return err
		}
	}

	if err := k.upsertPenaltyLocked(penalty); err != nil {
		if evidenceChanged {
			if rollbackErr := k.upsertEvidenceLocked(evidenceBefore); rollbackErr != nil {
				return fmt.Errorf("%w; rollback evidence %q failed: %v", err, evidenceBefore.EvidenceID, rollbackErr)
			}
		}
		return err
	}
	return nil
}

func advanceEvidenceStatusForPenalty(record types.SlashEvidence) types.SlashEvidence {
	normalized := normalizeEvidence(record)
	if normalized.Status == chaintypes.ReconciliationPending || normalized.Status == chaintypes.ReconciliationSubmitted {
		normalized.Status = chaintypes.ReconciliationConfirmed
	}
	return normalized
}

func (k *Keeper) findPenaltyForEvidenceLocked(evidenceID string) (types.PenaltyDecision, bool, error) {
	penalties, err := k.listPenaltiesLocked()
	if err != nil {
		return types.PenaltyDecision{}, false, err
	}
	for _, penalty := range penalties {
		normalized := normalizePenalty(penalty)
		if normalized.EvidenceID == evidenceID {
			return normalized, true, nil
		}
	}
	return types.PenaltyDecision{}, false, nil
}

func (k *Keeper) findEquivalentEvidenceLocked(candidate types.SlashEvidence) (types.SlashEvidence, bool, error) {
	evidenceRecords, err := k.listEvidenceLocked()
	if err != nil {
		return types.SlashEvidence{}, false, err
	}
	for _, evidence := range evidenceRecords {
		normalized := normalizeEvidence(evidence)
		if normalized.EvidenceID == candidate.EvidenceID {
			continue
		}
		if evidenceIncidentEqual(normalized, candidate) {
			return normalized, true, nil
		}
	}
	return types.SlashEvidence{}, false, nil
}

func (k *Keeper) listEvidenceLocked() ([]types.SlashEvidence, error) {
	if readAwareStore, ok := k.store.(KeeperStoreWithReadErrors); ok {
		records, err := readAwareStore.ListEvidenceWithError()
		if err != nil {
			return nil, fmt.Errorf("load evidence: %w", err)
		}
		return records, nil
	}
	return k.store.ListEvidence(), nil
}

func (k *Keeper) listPenaltiesLocked() ([]types.PenaltyDecision, error) {
	if readAwareStore, ok := k.store.(KeeperStoreWithReadErrors); ok {
		records, err := readAwareStore.ListPenaltiesWithError()
		if err != nil {
			return nil, fmt.Errorf("load penalties: %w", err)
		}
		return records, nil
	}
	return k.store.ListPenalties(), nil
}

func normalizeEvidence(record types.SlashEvidence) types.SlashEvidence {
	record.ViolationType = types.NormalizeViolationType(record.ViolationType)
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationSubmitted
	}
	return record
}

func normalizePenalty(record types.PenaltyDecision) types.PenaltyDecision {
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationSubmitted
	}
	return record
}

func (k *Keeper) upsertEvidenceLocked(record types.SlashEvidence) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertEvidenceWithError(record); err != nil {
			return fmt.Errorf("persist evidence %q: %w", record.EvidenceID, err)
		}
		return nil
	}

	k.store.UpsertEvidence(record)
	return nil
}

func (k *Keeper) upsertPenaltyLocked(record types.PenaltyDecision) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertPenaltyWithError(record); err != nil {
			return fmt.Errorf("persist penalty %q: %w", record.PenaltyID, err)
		}
		return nil
	}

	k.store.UpsertPenalty(record)
	return nil
}

func slashEvidenceRecordsEqual(a, b types.SlashEvidence) bool {
	return a.EvidenceID == b.EvidenceID &&
		a.SessionID == b.SessionID &&
		a.ProviderID == b.ProviderID &&
		a.ViolationType == b.ViolationType &&
		a.Kind == b.Kind &&
		a.ProofHash == b.ProofHash &&
		a.SubmittedAtUnix == b.SubmittedAtUnix &&
		a.Status == b.Status
}

func evidenceIncidentEqual(a, b types.SlashEvidence) bool {
	return types.CanonicalObjectiveEvidenceIdentity(a) == types.CanonicalObjectiveEvidenceIdentity(b)
}

func penaltyRecordsEqual(a, b types.PenaltyDecision) bool {
	return a.PenaltyID == b.PenaltyID &&
		a.EvidenceID == b.EvidenceID &&
		a.SlashBasisPoint == b.SlashBasisPoint &&
		a.Jailed == b.Jailed &&
		a.AppliedAtUnix == b.AppliedAtUnix &&
		a.Status == b.Status
}

func conflictError(kind string, id string) error {
	return fmt.Errorf("%s %q already exists with conflicting fields", kind, id)
}

func missingEvidenceError(evidenceID string) error {
	return fmt.Errorf("evidence %q not found", evidenceID)
}

func penaltyEvidenceConflictError(evidenceID string, existingPenaltyID string) error {
	return fmt.Errorf("evidence %q already has penalty %q", evidenceID, existingPenaltyID)
}

func evidenceReplayConflictError(evidenceID string, existingEvidenceID string) error {
	return fmt.Errorf("evidence %q duplicates already-recorded evidence %q", evidenceID, existingEvidenceID)
}
