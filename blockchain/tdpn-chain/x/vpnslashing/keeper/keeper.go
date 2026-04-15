package keeper

import (
	"fmt"
	"sort"
	"sync"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

// Keeper is an in-memory placeholder for evidence and penalty records.
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
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertEvidence(record)
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
		k.store.UpsertEvidence(normalizedExisting)
		return normalizedExisting, nil
	}

	k.store.UpsertEvidence(normalized)
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

	evidence := k.store.ListEvidence()
	sort.Slice(evidence, func(i, j int) bool {
		return evidence[i].EvidenceID < evidence[j].EvidenceID
	})
	return evidence
}

func (k *Keeper) UpsertPenalty(record types.PenaltyDecision) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertPenalty(record)
}

// ApplyPenalty inserts a penalty with idempotency semantics keyed by PenaltyID.
func (k *Keeper) ApplyPenalty(record types.PenaltyDecision) (types.PenaltyDecision, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.PenaltyDecision{}, err
	}

	normalized := normalizePenalty(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	if _, ok := k.store.GetEvidence(normalized.EvidenceID); !ok {
		return types.PenaltyDecision{}, missingEvidenceError(normalized.EvidenceID)
	}

	existing, ok := k.store.GetPenalty(normalized.PenaltyID)
	if ok {
		normalizedExisting := normalizePenalty(existing)
		if !penaltyRecordsEqual(normalizedExisting, normalized) {
			return types.PenaltyDecision{}, conflictError("penalty", normalized.PenaltyID)
		}
		k.store.UpsertPenalty(normalizedExisting)
		k.advanceEvidenceForPenaltyLocked(normalizedExisting.EvidenceID)
		return normalizedExisting, nil
	}

	k.store.UpsertPenalty(normalized)
	k.advanceEvidenceForPenaltyLocked(normalized.EvidenceID)
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

	penalties := k.store.ListPenalties()
	sort.Slice(penalties, func(i, j int) bool {
		return penalties[i].PenaltyID < penalties[j].PenaltyID
	})
	return penalties
}

func (k *Keeper) advanceEvidenceForPenaltyLocked(evidenceID string) {
	evidence, ok := k.store.GetEvidence(evidenceID)
	if !ok {
		return
	}

	normalized := normalizeEvidence(evidence)
	if normalized.Status == chaintypes.ReconciliationPending || normalized.Status == chaintypes.ReconciliationSubmitted {
		normalized.Status = chaintypes.ReconciliationConfirmed
	}
	k.store.UpsertEvidence(normalized)
}

func normalizeEvidence(record types.SlashEvidence) types.SlashEvidence {
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

func slashEvidenceRecordsEqual(a, b types.SlashEvidence) bool {
	return a.EvidenceID == b.EvidenceID &&
		a.SessionID == b.SessionID &&
		a.ProviderID == b.ProviderID &&
		a.Kind == b.Kind &&
		a.ProofHash == b.ProofHash &&
		a.SubmittedAtUnix == b.SubmittedAtUnix &&
		a.Status == b.Status
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
