package keeper

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
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

	return Keeper{store: store}
}

func (k *Keeper) UpsertPolicy(record types.GovernancePolicy) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertPolicy(record)
}

// CreatePolicy inserts a governance policy with idempotency semantics keyed by PolicyID.
func (k *Keeper) CreatePolicy(record types.GovernancePolicy) (types.GovernancePolicy, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.GovernancePolicy{}, err
	}

	normalized := normalizePolicy(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	existing, ok := k.store.GetPolicy(normalized.PolicyID)
	if ok {
		normalizedExisting := normalizePolicy(existing)
		if !policyRecordsEqual(normalizedExisting, normalized) {
			return types.GovernancePolicy{}, conflictError("policy", normalized.PolicyID)
		}
		k.store.UpsertPolicy(normalizedExisting)
		return normalizedExisting, nil
	}

	k.store.UpsertPolicy(normalized)
	return normalized, nil
}

func (k *Keeper) GetPolicy(policyID string) (types.GovernancePolicy, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetPolicy(policyID)
}

func (k *Keeper) ListPolicies() []types.GovernancePolicy {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := append([]types.GovernancePolicy(nil), k.store.ListPolicies()...)
	sort.Slice(records, func(i, j int) bool {
		return strings.Compare(records[i].PolicyID, records[j].PolicyID) < 0
	})
	return records
}

func (k *Keeper) UpsertDecision(record types.GovernanceDecision) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.store.UpsertDecision(record)
}

// RecordDecision inserts a governance decision with idempotency semantics keyed by DecisionID.
func (k *Keeper) RecordDecision(record types.GovernanceDecision) (types.GovernanceDecision, error) {
	if err := record.ValidateBasic(); err != nil {
		return types.GovernanceDecision{}, err
	}

	normalized := normalizeDecision(record)

	k.mu.Lock()
	defer k.mu.Unlock()

	if _, ok := k.store.GetPolicy(normalized.PolicyID); !ok {
		return types.GovernanceDecision{}, policyNotFoundError(normalized.PolicyID)
	}

	existing, ok := k.store.GetDecision(normalized.DecisionID)
	if ok {
		normalizedExisting := normalizeDecision(existing)
		if !decisionRecordsEqual(normalizedExisting, normalized) {
			return types.GovernanceDecision{}, conflictError("decision", normalized.DecisionID)
		}
		k.store.UpsertDecision(normalizedExisting)
		return normalizedExisting, nil
	}

	k.store.UpsertDecision(normalized)
	return normalized, nil
}

func (k *Keeper) GetDecision(decisionID string) (types.GovernanceDecision, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.store.GetDecision(decisionID)
}

func (k *Keeper) ListDecisions() []types.GovernanceDecision {
	k.mu.RLock()
	defer k.mu.RUnlock()

	records := append([]types.GovernanceDecision(nil), k.store.ListDecisions()...)
	sort.Slice(records, func(i, j int) bool {
		return strings.Compare(records[i].DecisionID, records[j].DecisionID) < 0
	})
	return records
}

func normalizePolicy(record types.GovernancePolicy) types.GovernancePolicy {
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeDecision(record types.GovernanceDecision) types.GovernanceDecision {
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	record.Outcome = strings.ToLower(strings.TrimSpace(record.Outcome))
	return record
}

func policyRecordsEqual(a, b types.GovernancePolicy) bool {
	return a.PolicyID == b.PolicyID &&
		a.Title == b.Title &&
		a.Description == b.Description &&
		a.Version == b.Version &&
		a.ActivatedAtUnix == b.ActivatedAtUnix &&
		a.Status == b.Status
}

func decisionRecordsEqual(a, b types.GovernanceDecision) bool {
	return a.DecisionID == b.DecisionID &&
		a.PolicyID == b.PolicyID &&
		a.ProposalID == b.ProposalID &&
		a.Outcome == b.Outcome &&
		a.Decider == b.Decider &&
		a.Reason == b.Reason &&
		a.DecidedAtUnix == b.DecidedAtUnix &&
		a.Status == b.Status
}

func conflictError(kind string, id string) error {
	return fmt.Errorf("%s %q already exists with conflicting fields", kind, id)
}

func policyNotFoundError(policyID string) error {
	return fmt.Errorf("policy %q not found", policyID)
}
