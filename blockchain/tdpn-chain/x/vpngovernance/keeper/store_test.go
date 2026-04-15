package keeper

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

type trackingStore struct {
	policies     map[string]types.GovernancePolicy
	decisions    map[string]types.GovernanceDecision
	auditActions map[string]types.GovernanceAuditAction

	upsertPolicyCalls   int
	getPolicyCalls      int
	upsertDecisionCalls int
	getDecisionCalls    int
	listPolicyCalls     int
	listDecisionCalls   int
	putAuditCalls       int
	getAuditCalls       int
	listAuditCalls      int
}

func newTrackingStore() *trackingStore {
	return &trackingStore{
		policies:     make(map[string]types.GovernancePolicy),
		decisions:    make(map[string]types.GovernanceDecision),
		auditActions: make(map[string]types.GovernanceAuditAction),
	}
}

func (s *trackingStore) UpsertPolicy(record types.GovernancePolicy) {
	s.upsertPolicyCalls++
	s.policies[record.PolicyID] = record
}

func (s *trackingStore) GetPolicy(policyID string) (types.GovernancePolicy, bool) {
	s.getPolicyCalls++
	record, ok := s.policies[policyID]
	return record, ok
}

func (s *trackingStore) ListPolicies() []types.GovernancePolicy {
	s.listPolicyCalls++
	ids := make([]string, 0, len(s.policies))
	for id := range s.policies {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.GovernancePolicy, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.policies[id])
	}
	return records
}

func (s *trackingStore) UpsertDecision(record types.GovernanceDecision) {
	s.upsertDecisionCalls++
	s.decisions[record.DecisionID] = record
}

func (s *trackingStore) GetDecision(decisionID string) (types.GovernanceDecision, bool) {
	s.getDecisionCalls++
	record, ok := s.decisions[decisionID]
	return record, ok
}

func (s *trackingStore) ListDecisions() []types.GovernanceDecision {
	s.listDecisionCalls++
	ids := make([]string, 0, len(s.decisions))
	for id := range s.decisions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.GovernanceDecision, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.decisions[id])
	}
	return records
}

func (s *trackingStore) PutAuditAction(record types.GovernanceAuditAction) {
	s.putAuditCalls++
	s.auditActions[record.ActionID] = record
}

func (s *trackingStore) GetAuditAction(actionID string) (types.GovernanceAuditAction, bool) {
	s.getAuditCalls++
	record, ok := s.auditActions[actionID]
	return record, ok
}

func (s *trackingStore) ListAuditActions() []types.GovernanceAuditAction {
	s.listAuditCalls++
	ids := make([]string, 0, len(s.auditActions))
	for id := range s.auditActions {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.GovernanceAuditAction, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.auditActions[id])
	}
	return records
}

func TestNewKeeperWithStoreNilFallsBackToInMemory(t *testing.T) {
	t.Parallel()

	k := NewKeeperWithStore(nil)
	policy := types.GovernancePolicy{PolicyID: "policy-fallback", Title: "Fallback Policy", Version: 1, ActivatedAtUnix: 1}
	k.UpsertPolicy(policy)

	got, ok := k.GetPolicy(policy.PolicyID)
	if !ok {
		t.Fatal("expected policy to be present with nil-store fallback")
	}
	if got.PolicyID != policy.PolicyID {
		t.Fatalf("expected policy id %q, got %q", policy.PolicyID, got.PolicyID)
	}
}

func TestKeeperDelegatesUpsertAndGetToCustomStore(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	policy := types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy One", Version: 1, ActivatedAtUnix: 1}
	k.UpsertPolicy(policy)
	if store.upsertPolicyCalls != 1 {
		t.Fatalf("expected 1 policy upsert call, got %d", store.upsertPolicyCalls)
	}

	gotPolicy, ok := k.GetPolicy(policy.PolicyID)
	if !ok {
		t.Fatal("expected policy from custom store")
	}
	if gotPolicy.Title != policy.Title {
		t.Fatalf("expected title %q, got %q", policy.Title, gotPolicy.Title)
	}
	if store.getPolicyCalls != 1 {
		t.Fatalf("expected 1 policy get call, got %d", store.getPolicyCalls)
	}

	decision := types.GovernanceDecision{DecisionID: "decision-1", PolicyID: "policy-1", ProposalID: "proposal-1", Outcome: types.DecisionOutcomeApprove, Decider: "council", DecidedAtUnix: 1}
	k.UpsertDecision(decision)
	if store.upsertDecisionCalls != 1 {
		t.Fatalf("expected 1 decision upsert call, got %d", store.upsertDecisionCalls)
	}

	gotDecision, ok := k.GetDecision(decision.DecisionID)
	if !ok {
		t.Fatal("expected decision from custom store")
	}
	if gotDecision.DecisionID != decision.DecisionID {
		t.Fatalf("expected decision id %q, got %q", decision.DecisionID, gotDecision.DecisionID)
	}
	if store.getDecisionCalls != 1 {
		t.Fatalf("expected 1 decision get call, got %d", store.getDecisionCalls)
	}
}

func TestKeeperCreateAndRecordUseCustomStore(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	createdPolicy, err := k.CreatePolicy(types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy One", Version: 1, ActivatedAtUnix: 1})
	if err != nil {
		t.Fatalf("CreatePolicy returned unexpected error: %v", err)
	}
	if createdPolicy.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected policy status %q, got %q", chaintypes.ReconciliationPending, createdPolicy.Status)
	}
	if store.upsertPolicyCalls == 0 || store.getPolicyCalls == 0 {
		t.Fatalf("expected create path to touch custom policy store, got upsert=%d get=%d", store.upsertPolicyCalls, store.getPolicyCalls)
	}

	recordedDecision, err := k.RecordDecision(types.GovernanceDecision{DecisionID: "decision-1", PolicyID: createdPolicy.PolicyID, ProposalID: "proposal-1", Outcome: types.DecisionOutcomeApprove, Decider: "council", DecidedAtUnix: 1})
	if err != nil {
		t.Fatalf("RecordDecision returned unexpected error: %v", err)
	}
	if recordedDecision.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected decision status %q, got %q", chaintypes.ReconciliationPending, recordedDecision.Status)
	}
	if store.upsertDecisionCalls == 0 || store.getDecisionCalls == 0 {
		t.Fatalf("expected record path to touch custom decision store, got upsert=%d get=%d", store.upsertDecisionCalls, store.getDecisionCalls)
	}

	recordedAudit, err := k.RecordAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "incident response bootstrap",
		EvidencePointer: "ipfs://evidence/audit-1",
		TimestampUnix:   4102444800,
	})
	if err != nil {
		t.Fatalf("RecordAuditAction returned unexpected error: %v", err)
	}
	if recordedAudit.ActionID != "audit-1" {
		t.Fatalf("expected action id %q, got %q", "audit-1", recordedAudit.ActionID)
	}
	if store.putAuditCalls == 0 || store.getAuditCalls == 0 {
		t.Fatalf("expected record path to touch custom audit store, got put=%d get=%d", store.putAuditCalls, store.getAuditCalls)
	}
}

func TestNewFileStorePersistsAcrossReopen(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vpngovernance-store.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	policy := types.GovernancePolicy{PolicyID: "policy-persist", Title: "Persisted Policy", Version: 2, ActivatedAtUnix: 4102444800, Status: chaintypes.ReconciliationSubmitted}
	store.UpsertPolicy(policy)

	decision := types.GovernanceDecision{DecisionID: "decision-persist", PolicyID: policy.PolicyID, ProposalID: "proposal-persist", Outcome: types.DecisionOutcomeReject, Decider: "multisig", DecidedAtUnix: 4102444800, Status: chaintypes.ReconciliationConfirmed}
	store.UpsertDecision(decision)

	audit := types.GovernanceAuditAction{
		ActionID:        "audit-persist",
		Action:          "admin_disable_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "validated signed evidence",
		EvidencePointer: "ipfs://evidence/audit-persist",
		TimestampUnix:   4102444801,
	}
	store.PutAuditAction(audit)

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen NewFileStore returned unexpected error: %v", err)
	}

	gotPolicy, ok := reopened.GetPolicy(policy.PolicyID)
	if !ok {
		t.Fatal("expected persisted policy to be loaded after reopen")
	}
	if gotPolicy != policy {
		t.Fatalf("expected persisted policy %+v, got %+v", policy, gotPolicy)
	}

	gotDecision, ok := reopened.GetDecision(decision.DecisionID)
	if !ok {
		t.Fatal("expected persisted decision to be loaded after reopen")
	}
	if gotDecision != decision {
		t.Fatalf("expected persisted decision %+v, got %+v", decision, gotDecision)
	}

	gotAudit, ok := reopened.GetAuditAction(audit.ActionID)
	if !ok {
		t.Fatal("expected persisted audit action to be loaded after reopen")
	}
	if gotAudit != audit {
		t.Fatalf("expected persisted audit action %+v, got %+v", audit, gotAudit)
	}
}

func TestNewFileStoreInvalidPath(t *testing.T) {
	t.Parallel()

	_, err := NewFileStore(t.TempDir())
	if err == nil {
		t.Fatal("expected NewFileStore to fail for directory path")
	}
}

func TestFileStoreListOrderingAndGetPaths(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vpngovernance-store-ordering.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	policyIDs := []string{"policy-2", "policy-10", "policy-1"}
	for i, id := range policyIDs {
		store.UpsertPolicy(types.GovernancePolicy{PolicyID: id, Title: "Policy", Version: uint64(i + 1), ActivatedAtUnix: 4102444800, Status: chaintypes.ReconciliationPending})
	}

	decisionIDs := []string{"decision-2", "decision-10", "decision-1"}
	for i, id := range decisionIDs {
		store.UpsertDecision(types.GovernanceDecision{DecisionID: id, PolicyID: "policy-1", ProposalID: "proposal", Outcome: types.DecisionOutcomeApprove, Decider: "council", DecidedAtUnix: int64(4102444800 + i), Status: chaintypes.ReconciliationSubmitted})
	}

	auditIDs := []string{"audit-2", "audit-10", "audit-1"}
	for i, id := range auditIDs {
		store.PutAuditAction(types.GovernanceAuditAction{
			ActionID:        id,
			Action:          "admin_allow_validator",
			Actor:           "bootstrap-admin",
			Reason:          "bootstrap update",
			EvidencePointer: "ipfs://evidence/" + id,
			TimestampUnix:   int64(4102444800 + i),
		})
	}

	gotPolicies := store.ListPolicies()
	if len(gotPolicies) != len(policyIDs) {
		t.Fatalf("expected %d policies, got %d", len(policyIDs), len(gotPolicies))
	}
	expectedPolicyIDs := append([]string(nil), policyIDs...)
	sort.Strings(expectedPolicyIDs)
	for i, expectedID := range expectedPolicyIDs {
		if gotPolicies[i].PolicyID != expectedID {
			t.Fatalf("expected policy index %d to be %q, got %q", i, expectedID, gotPolicies[i].PolicyID)
		}
		if _, ok := store.GetPolicy(expectedID); !ok {
			t.Fatalf("expected GetPolicy(%q) to succeed", expectedID)
		}
	}

	gotDecisions := store.ListDecisions()
	if len(gotDecisions) != len(decisionIDs) {
		t.Fatalf("expected %d decisions, got %d", len(decisionIDs), len(gotDecisions))
	}
	expectedDecisionIDs := append([]string(nil), decisionIDs...)
	sort.Strings(expectedDecisionIDs)
	for i, expectedID := range expectedDecisionIDs {
		if gotDecisions[i].DecisionID != expectedID {
			t.Fatalf("expected decision index %d to be %q, got %q", i, expectedID, gotDecisions[i].DecisionID)
		}
		if _, ok := store.GetDecision(expectedID); !ok {
			t.Fatalf("expected GetDecision(%q) to succeed", expectedID)
		}
	}

	gotAuditActions := store.ListAuditActions()
	if len(gotAuditActions) != len(auditIDs) {
		t.Fatalf("expected %d audit actions, got %d", len(auditIDs), len(gotAuditActions))
	}
	expectedAuditIDs := append([]string(nil), auditIDs...)
	sort.Strings(expectedAuditIDs)
	for i, expectedID := range expectedAuditIDs {
		if gotAuditActions[i].ActionID != expectedID {
			t.Fatalf("expected audit action index %d to be %q, got %q", i, expectedID, gotAuditActions[i].ActionID)
		}
		if _, ok := store.GetAuditAction(expectedID); !ok {
			t.Fatalf("expected GetAuditAction(%q) to succeed", expectedID)
		}
	}
}

func TestFileStoreWhitespaceSnapshotLoadsAndPersists(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vpngovernance-store-whitespace.json")
	if err := os.WriteFile(path, []byte("  \n\t  "), 0o600); err != nil {
		t.Fatalf("write whitespace snapshot: %v", err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore with whitespace snapshot returned unexpected error: %v", err)
	}
	if got := store.ListPolicies(); len(got) != 0 {
		t.Fatalf("expected no policies from whitespace snapshot, got %d", len(got))
	}
	if got := store.ListDecisions(); len(got) != 0 {
		t.Fatalf("expected no decisions from whitespace snapshot, got %d", len(got))
	}
	if got := store.ListAuditActions(); len(got) != 0 {
		t.Fatalf("expected no audit actions from whitespace snapshot, got %d", len(got))
	}

	store.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-whitespace", Title: "Whitespace Policy", Version: 7, ActivatedAtUnix: 4102444800, Status: chaintypes.ReconciliationConfirmed})
	store.PutAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-whitespace",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin",
		Reason:          "whitespace bootstrap",
		EvidencePointer: "ipfs://evidence/audit-whitespace",
		TimestampUnix:   4102444800,
	})

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen NewFileStore returned unexpected error: %v", err)
	}
	got, ok := reopened.GetPolicy("policy-whitespace")
	if !ok {
		t.Fatal("expected persisted policy after whitespace bootstrap")
	}
	if got.PolicyID != "policy-whitespace" || got.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("unexpected persisted policy: %+v", got)
	}

	audit, ok := reopened.GetAuditAction("audit-whitespace")
	if !ok {
		t.Fatal("expected persisted audit action after whitespace bootstrap")
	}
	if audit.ActionID != "audit-whitespace" {
		t.Fatalf("unexpected persisted audit action: %+v", audit)
	}
}
