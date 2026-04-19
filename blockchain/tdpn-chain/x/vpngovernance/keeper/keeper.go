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
	record = normalizePolicy(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	_ = k.upsertPolicyLocked(record)
}

func (k *Keeper) UpsertPolicyWithError(record types.GovernancePolicy) error {
	record = normalizePolicy(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertPolicyLocked(record)
}

// CreatePolicy inserts a governance policy with idempotency semantics keyed by PolicyID.
func (k *Keeper) CreatePolicy(record types.GovernancePolicy) (types.GovernancePolicy, error) {
	normalized := normalizePolicy(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.GovernancePolicy{}, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	_, hasCanonicalKey := k.store.GetPolicy(normalized.PolicyID)
	matches := k.findPoliciesByCanonicalIDLocked(normalized.PolicyID)
	if len(matches) > 0 {
		for _, existing := range matches {
			normalizedExisting := normalizePolicy(existing)
			if !policyRecordsEqual(normalizedExisting, normalized) {
				return types.GovernancePolicy{}, conflictError("policy", normalized.PolicyID)
			}
		}

		// Avoid introducing duplicate logical IDs when only legacy keys exist.
		if hasCanonicalKey {
			if err := k.upsertPolicyLocked(normalized); err != nil {
				return types.GovernancePolicy{}, err
			}
		}
		return normalized, nil
	}

	if err := k.upsertPolicyLocked(normalized); err != nil {
		return types.GovernancePolicy{}, err
	}
	return normalized, nil
}

func (k *Keeper) GetPolicy(policyID string) (types.GovernancePolicy, bool) {
	normalizedID := canonicalPolicyID(policyID)
	if normalizedID == "" {
		return types.GovernancePolicy{}, false
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.getPolicyByIDCompatibleLocked(policyID, normalizedID)
}

func (k *Keeper) ListPolicies() []types.GovernancePolicy {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return dedupeAndSortPolicies(k.store.ListPolicies())
}

func (k *Keeper) UpsertDecision(record types.GovernanceDecision) {
	record = normalizeDecision(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	_ = k.upsertDecisionLocked(record)
}

func (k *Keeper) UpsertDecisionWithError(record types.GovernanceDecision) error {
	record = normalizeDecision(record)

	k.mu.Lock()
	defer k.mu.Unlock()
	return k.upsertDecisionLocked(record)
}

// RecordDecision inserts a governance decision with idempotency semantics keyed by DecisionID.
func (k *Keeper) RecordDecision(record types.GovernanceDecision) (types.GovernanceDecision, error) {
	normalized := normalizeDecision(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.GovernanceDecision{}, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	if _, ok := k.store.GetPolicy(normalized.PolicyID); !ok && len(k.findPoliciesByCanonicalIDLocked(normalized.PolicyID)) == 0 {
		return types.GovernanceDecision{}, policyNotFoundError(normalized.PolicyID)
	}

	_, hasCanonicalKey := k.store.GetDecision(normalized.DecisionID)
	matches := k.findDecisionsByCanonicalIDLocked(normalized.DecisionID)
	if len(matches) > 0 {
		for _, existing := range matches {
			normalizedExisting := normalizeDecision(existing)
			if !decisionRecordsEqual(normalizedExisting, normalized) {
				return types.GovernanceDecision{}, conflictError("decision", normalized.DecisionID)
			}
		}

		// Avoid introducing duplicate logical IDs when only legacy keys exist.
		if hasCanonicalKey {
			if err := k.upsertDecisionLocked(normalized); err != nil {
				return types.GovernanceDecision{}, err
			}
		}
		return normalized, nil
	}
	if existingByBusinessKey, found := k.decisionByPolicyProposalLocked(normalized.PolicyID, normalized.ProposalID); found {
		return types.GovernanceDecision{}, decisionBusinessKeyConflictError(normalized, existingByBusinessKey.DecisionID)
	}

	if err := k.upsertDecisionLocked(normalized); err != nil {
		return types.GovernanceDecision{}, err
	}
	return normalized, nil
}

func (k *Keeper) GetDecision(decisionID string) (types.GovernanceDecision, bool) {
	normalizedID := canonicalDecisionID(decisionID)
	if normalizedID == "" {
		return types.GovernanceDecision{}, false
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.getDecisionByIDCompatibleLocked(decisionID, normalizedID)
}

func (k *Keeper) ListDecisions() []types.GovernanceDecision {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return dedupeAndSortDecisions(k.store.ListDecisions())
}

// RecordAuditAction inserts an append-only governance admin action keyed by ActionID.
// Replaying the exact same record is idempotent, while divergent payloads conflict.
func (k *Keeper) RecordAuditAction(record types.GovernanceAuditAction) (types.GovernanceAuditAction, error) {
	normalized := normalizeAuditAction(record)
	if err := normalized.ValidateBasic(); err != nil {
		return types.GovernanceAuditAction{}, err
	}

	k.mu.Lock()
	defer k.mu.Unlock()

	_, hasCanonicalKey := k.store.GetAuditAction(normalized.ActionID)
	matches := k.findAuditActionsByCanonicalIDLocked(normalized.ActionID)
	if len(matches) > 0 {
		for _, existing := range matches {
			normalizedExisting := normalizeAuditAction(existing)
			if !auditActionRecordsEqual(normalizedExisting, normalized) {
				return types.GovernanceAuditAction{}, conflictError("audit action", normalized.ActionID)
			}
		}

		// Avoid introducing duplicate logical IDs when only legacy keys exist.
		if hasCanonicalKey {
			if err := k.putAuditActionLocked(normalized); err != nil {
				return types.GovernanceAuditAction{}, err
			}
		}
		return normalized, nil
	}

	if err := k.putAuditActionLocked(normalized); err != nil {
		return types.GovernanceAuditAction{}, err
	}
	return normalized, nil
}

func (k *Keeper) upsertPolicyLocked(record types.GovernancePolicy) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertPolicyWithError(record); err != nil {
			return fmt.Errorf("persist policy %q: %w", record.PolicyID, err)
		}
		return nil
	}

	k.store.UpsertPolicy(record)
	return nil
}

func (k *Keeper) upsertDecisionLocked(record types.GovernanceDecision) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.UpsertDecisionWithError(record); err != nil {
			return fmt.Errorf("persist decision %q: %w", record.DecisionID, err)
		}
		return nil
	}

	k.store.UpsertDecision(record)
	return nil
}

func (k *Keeper) putAuditActionLocked(record types.GovernanceAuditAction) error {
	if writeAwareStore, ok := k.store.(KeeperStoreWithWriteErrors); ok {
		if err := writeAwareStore.PutAuditActionWithError(record); err != nil {
			return fmt.Errorf("persist audit action %q: %w", record.ActionID, err)
		}
		return nil
	}

	k.store.PutAuditAction(record)
	return nil
}

func (k *Keeper) GetAuditAction(actionID string) (types.GovernanceAuditAction, bool) {
	normalizedID := canonicalAuditActionID(actionID)
	if normalizedID == "" {
		return types.GovernanceAuditAction{}, false
	}

	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.getAuditActionByIDCompatibleLocked(actionID, normalizedID)
}

func (k *Keeper) ListAuditActions() []types.GovernanceAuditAction {
	k.mu.RLock()
	defer k.mu.RUnlock()

	return dedupeAndSortAuditActions(k.store.ListAuditActions())
}

func (k *Keeper) findPoliciesByCanonicalIDLocked(policyID string) []types.GovernancePolicy {
	canonicalID := canonicalPolicyID(policyID)
	if canonicalID == "" {
		return nil
	}

	records := k.store.ListPolicies()
	matches := make([]types.GovernancePolicy, 0, len(records))
	for _, record := range records {
		if normalizePolicy(record).PolicyID == canonicalID {
			matches = append(matches, record)
		}
	}
	return matches
}

func (k *Keeper) findDecisionsByCanonicalIDLocked(decisionID string) []types.GovernanceDecision {
	canonicalID := canonicalDecisionID(decisionID)
	if canonicalID == "" {
		return nil
	}

	records := k.store.ListDecisions()
	matches := make([]types.GovernanceDecision, 0, len(records))
	for _, record := range records {
		if normalizeDecision(record).DecisionID == canonicalID {
			matches = append(matches, record)
		}
	}
	return matches
}

func (k *Keeper) decisionByPolicyProposalLocked(policyID, proposalID string) (types.GovernanceDecision, bool) {
	for _, record := range k.store.ListDecisions() {
		normalized := normalizeDecision(record)
		if normalized.PolicyID != policyID || normalized.ProposalID != proposalID {
			continue
		}
		return normalized, true
	}
	return types.GovernanceDecision{}, false
}

func (k *Keeper) findAuditActionsByCanonicalIDLocked(actionID string) []types.GovernanceAuditAction {
	canonicalID := canonicalAuditActionID(actionID)
	if canonicalID == "" {
		return nil
	}

	records := k.store.ListAuditActions()
	matches := make([]types.GovernanceAuditAction, 0, len(records))
	for _, record := range records {
		if normalizeAuditAction(record).ActionID == canonicalID {
			matches = append(matches, record)
		}
	}
	return matches
}

func (k *Keeper) getPolicyByIDCompatibleLocked(rawID, canonicalID string) (types.GovernancePolicy, bool) {
	if record, ok := k.store.GetPolicy(canonicalID); ok {
		normalized := normalizePolicy(record)
		if normalized.PolicyID == canonicalID {
			return normalized, true
		}
	}
	if rawID != canonicalID {
		if record, ok := k.store.GetPolicy(rawID); ok {
			normalized := normalizePolicy(record)
			if normalized.PolicyID == canonicalID {
				return normalized, true
			}
		}
	}
	return selectPolicyByCanonicalID(k.store.ListPolicies(), canonicalID)
}

func (k *Keeper) getDecisionByIDCompatibleLocked(rawID, canonicalID string) (types.GovernanceDecision, bool) {
	if record, ok := k.store.GetDecision(canonicalID); ok {
		normalized := normalizeDecision(record)
		if normalized.DecisionID == canonicalID {
			return normalized, true
		}
	}
	if rawID != canonicalID {
		if record, ok := k.store.GetDecision(rawID); ok {
			normalized := normalizeDecision(record)
			if normalized.DecisionID == canonicalID {
				return normalized, true
			}
		}
	}
	return selectDecisionByCanonicalID(k.store.ListDecisions(), canonicalID)
}

func (k *Keeper) getAuditActionByIDCompatibleLocked(rawID, canonicalID string) (types.GovernanceAuditAction, bool) {
	if record, ok := k.store.GetAuditAction(canonicalID); ok {
		normalized := normalizeAuditAction(record)
		if normalized.ActionID == canonicalID {
			return normalized, true
		}
	}
	if rawID != canonicalID {
		if record, ok := k.store.GetAuditAction(rawID); ok {
			normalized := normalizeAuditAction(record)
			if normalized.ActionID == canonicalID {
				return normalized, true
			}
		}
	}
	return selectAuditActionByCanonicalID(k.store.ListAuditActions(), canonicalID)
}

func dedupeAndSortPolicies(records []types.GovernancePolicy) []types.GovernancePolicy {
	byCanonicalID := make(map[string]types.GovernancePolicy, len(records))
	for _, record := range records {
		normalized := normalizePolicy(record)
		if normalized.PolicyID == "" {
			continue
		}

		existing, ok := byCanonicalID[normalized.PolicyID]
		if !ok || policySortLess(normalized, existing) {
			byCanonicalID[normalized.PolicyID] = normalized
		}
	}

	deduped := make([]types.GovernancePolicy, 0, len(byCanonicalID))
	for _, record := range byCanonicalID {
		deduped = append(deduped, record)
	}
	sort.Slice(deduped, func(i, j int) bool {
		return policySortLess(deduped[i], deduped[j])
	})
	return deduped
}

func dedupeAndSortDecisions(records []types.GovernanceDecision) []types.GovernanceDecision {
	byCanonicalID := make(map[string]types.GovernanceDecision, len(records))
	for _, record := range records {
		normalized := normalizeDecision(record)
		if normalized.DecisionID == "" {
			continue
		}

		existing, ok := byCanonicalID[normalized.DecisionID]
		if !ok || decisionSortLess(normalized, existing) {
			byCanonicalID[normalized.DecisionID] = normalized
		}
	}

	deduped := make([]types.GovernanceDecision, 0, len(byCanonicalID))
	for _, record := range byCanonicalID {
		deduped = append(deduped, record)
	}
	sort.Slice(deduped, func(i, j int) bool {
		return decisionSortLess(deduped[i], deduped[j])
	})
	return deduped
}

func dedupeAndSortAuditActions(records []types.GovernanceAuditAction) []types.GovernanceAuditAction {
	byCanonicalID := make(map[string]types.GovernanceAuditAction, len(records))
	for _, record := range records {
		normalized := normalizeAuditAction(record)
		if normalized.ActionID == "" {
			continue
		}

		existing, ok := byCanonicalID[normalized.ActionID]
		if !ok || auditActionSortLess(normalized, existing) {
			byCanonicalID[normalized.ActionID] = normalized
		}
	}

	deduped := make([]types.GovernanceAuditAction, 0, len(byCanonicalID))
	for _, record := range byCanonicalID {
		deduped = append(deduped, record)
	}
	sort.Slice(deduped, func(i, j int) bool {
		return auditActionSortLess(deduped[i], deduped[j])
	})
	return deduped
}

func selectPolicyByCanonicalID(records []types.GovernancePolicy, canonicalID string) (types.GovernancePolicy, bool) {
	var selected types.GovernancePolicy
	found := false
	for _, record := range records {
		normalized := normalizePolicy(record)
		if normalized.PolicyID != canonicalID {
			continue
		}
		if !found || policySortLess(normalized, selected) {
			selected = normalized
			found = true
		}
	}
	return selected, found
}

func selectDecisionByCanonicalID(records []types.GovernanceDecision, canonicalID string) (types.GovernanceDecision, bool) {
	var selected types.GovernanceDecision
	found := false
	for _, record := range records {
		normalized := normalizeDecision(record)
		if normalized.DecisionID != canonicalID {
			continue
		}
		if !found || decisionSortLess(normalized, selected) {
			selected = normalized
			found = true
		}
	}
	return selected, found
}

func selectAuditActionByCanonicalID(records []types.GovernanceAuditAction, canonicalID string) (types.GovernanceAuditAction, bool) {
	var selected types.GovernanceAuditAction
	found := false
	for _, record := range records {
		normalized := normalizeAuditAction(record)
		if normalized.ActionID != canonicalID {
			continue
		}
		if !found || auditActionSortLess(normalized, selected) {
			selected = normalized
			found = true
		}
	}
	return selected, found
}

func canonicalPolicyID(policyID string) string {
	return types.GovernancePolicy{PolicyID: policyID}.Canonicalize().PolicyID
}

func canonicalDecisionID(decisionID string) string {
	return types.GovernanceDecision{DecisionID: decisionID}.Canonicalize().DecisionID
}

func canonicalAuditActionID(actionID string) string {
	return types.GovernanceAuditAction{ActionID: actionID}.Canonicalize().ActionID
}

func policySortLess(a, b types.GovernancePolicy) bool {
	if cmp := strings.Compare(a.PolicyID, b.PolicyID); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.Title, b.Title); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.Description, b.Description); cmp != 0 {
		return cmp < 0
	}
	if a.Version != b.Version {
		return a.Version < b.Version
	}
	if a.ActivatedAtUnix != b.ActivatedAtUnix {
		return a.ActivatedAtUnix < b.ActivatedAtUnix
	}
	return strings.Compare(string(a.Status), string(b.Status)) < 0
}

func decisionSortLess(a, b types.GovernanceDecision) bool {
	if cmp := strings.Compare(a.DecisionID, b.DecisionID); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.PolicyID, b.PolicyID); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.ProposalID, b.ProposalID); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.Outcome, b.Outcome); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.Decider, b.Decider); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.Reason, b.Reason); cmp != 0 {
		return cmp < 0
	}
	if a.DecidedAtUnix != b.DecidedAtUnix {
		return a.DecidedAtUnix < b.DecidedAtUnix
	}
	return strings.Compare(string(a.Status), string(b.Status)) < 0
}

func auditActionSortLess(a, b types.GovernanceAuditAction) bool {
	if cmp := strings.Compare(a.ActionID, b.ActionID); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.Action, b.Action); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.Actor, b.Actor); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.Reason, b.Reason); cmp != 0 {
		return cmp < 0
	}
	if cmp := strings.Compare(a.EvidencePointer, b.EvidencePointer); cmp != 0 {
		return cmp < 0
	}
	return a.TimestampUnix < b.TimestampUnix
}

func normalizePolicy(record types.GovernancePolicy) types.GovernancePolicy {
	record = record.Canonicalize()
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeDecision(record types.GovernanceDecision) types.GovernanceDecision {
	record = record.Canonicalize()
	if record.Status == "" {
		record.Status = chaintypes.ReconciliationPending
	}
	return record
}

func normalizeAuditAction(record types.GovernanceAuditAction) types.GovernanceAuditAction {
	record = record.Canonicalize()
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

func auditActionRecordsEqual(a, b types.GovernanceAuditAction) bool {
	return a.ActionID == b.ActionID &&
		a.Action == b.Action &&
		a.Actor == b.Actor &&
		a.Reason == b.Reason &&
		a.EvidencePointer == b.EvidencePointer &&
		a.TimestampUnix == b.TimestampUnix
}

func conflictError(kind string, id string) error {
	return fmt.Errorf("%s %q already exists with conflicting fields", kind, id)
}

func decisionBusinessKeyConflictError(record types.GovernanceDecision, existingDecisionID string) error {
	return fmt.Errorf(
		"decision business key %q already exists with conflicting fields (existing decision %q)",
		decisionBusinessKeyID(record.PolicyID, record.ProposalID),
		existingDecisionID,
	)
}

func decisionBusinessKeyID(policyID, proposalID string) string {
	return fmt.Sprintf("policy=%q proposal=%q", policyID, proposalID)
}

func policyNotFoundError(policyID string) error {
	return fmt.Errorf("policy %q not found", policyID)
}
