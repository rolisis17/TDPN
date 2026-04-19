package keeper

import (
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

func TestKVStoreUpsertGetList(t *testing.T) {
	t.Parallel()

	store := NewKVStore(kvtypes.NewMapStore())

	policy := types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy One", Version: 1, ActivatedAtUnix: 4102444800, Status: chaintypes.ReconciliationPending}
	store.UpsertPolicy(policy)

	gotPolicy, ok := store.GetPolicy(policy.PolicyID)
	if !ok {
		t.Fatal("expected policy to exist")
	}
	if gotPolicy != policy {
		t.Fatalf("expected policy %+v, got %+v", policy, gotPolicy)
	}

	decision := types.GovernanceDecision{DecisionID: "decision-1", PolicyID: policy.PolicyID, ProposalID: "proposal-1", Outcome: types.DecisionOutcomeApprove, Decider: "council", DecidedAtUnix: 4102444800, Status: chaintypes.ReconciliationSubmitted}
	store.UpsertDecision(decision)

	gotDecision, ok := store.GetDecision(decision.DecisionID)
	if !ok {
		t.Fatal("expected decision to exist")
	}
	if gotDecision != decision {
		t.Fatalf("expected decision %+v, got %+v", decision, gotDecision)
	}

	auditAction := types.GovernanceAuditAction{
		ActionID:        "audit-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "bootstrap policy update",
		EvidencePointer: "ipfs://evidence/audit-1",
		TimestampUnix:   4102444800,
	}
	store.PutAuditAction(auditAction)

	gotAudit, ok := store.GetAuditAction(auditAction.ActionID)
	if !ok {
		t.Fatal("expected audit action to exist")
	}
	if gotAudit != auditAction {
		t.Fatalf("expected audit action %+v, got %+v", auditAction, gotAudit)
	}

	policies := store.ListPolicies()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0] != policy {
		t.Fatalf("expected listed policy %+v, got %+v", policy, policies[0])
	}

	decisions := store.ListDecisions()
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	if decisions[0] != decision {
		t.Fatalf("expected listed decision %+v, got %+v", decision, decisions[0])
	}

	auditActions := store.ListAuditActions()
	if len(auditActions) != 1 {
		t.Fatalf("expected 1 audit action, got %d", len(auditActions))
	}
	if auditActions[0] != auditAction {
		t.Fatalf("expected listed audit action %+v, got %+v", auditAction, auditActions[0])
	}
}

func TestKVStoreListOrderingAndSkipsMalformedEntries(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	store.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-2", Title: "Policy", Version: 2, ActivatedAtUnix: 2, Status: chaintypes.ReconciliationPending})
	store.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy", Version: 1, ActivatedAtUnix: 1, Status: chaintypes.ReconciliationPending})
	backend.Set([]byte("policy/bad-json"), []byte("{not-valid-json"))

	store.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-2", PolicyID: "policy-2", ProposalID: "proposal-2", Outcome: types.DecisionOutcomeApprove, Decider: "c2", DecidedAtUnix: 2, Status: chaintypes.ReconciliationSubmitted})
	store.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-1", PolicyID: "policy-1", ProposalID: "proposal-1", Outcome: types.DecisionOutcomeReject, Decider: "c1", DecidedAtUnix: 1, Status: chaintypes.ReconciliationSubmitted})
	backend.Set([]byte("decision/bad-json"), []byte("{not-valid-json"))

	store.PutAuditAction(types.GovernanceAuditAction{ActionID: "audit-2", Action: "admin_allow_validator", Actor: "a2", Reason: "r2", EvidencePointer: "ipfs://a2", TimestampUnix: 2})
	store.PutAuditAction(types.GovernanceAuditAction{ActionID: "audit-1", Action: "admin_disable_validator", Actor: "a1", Reason: "r1", EvidencePointer: "ipfs://a1", TimestampUnix: 1})
	backend.Set([]byte("audit_action/bad-json"), []byte("{not-valid-json"))

	policies := store.ListPolicies()
	if len(policies) != 2 {
		t.Fatalf("expected 2 valid policies, got %d", len(policies))
	}
	if policies[0].PolicyID != "policy-1" || policies[1].PolicyID != "policy-2" {
		t.Fatalf("expected policy list ordered by key, got %+v", policies)
	}
	if _, ok := store.GetPolicy("bad-json"); ok {
		t.Fatal("expected malformed policy payload to be rejected by GetPolicy")
	}

	decisions := store.ListDecisions()
	if len(decisions) != 2 {
		t.Fatalf("expected 2 valid decisions, got %d", len(decisions))
	}
	if decisions[0].DecisionID != "decision-1" || decisions[1].DecisionID != "decision-2" {
		t.Fatalf("expected decision list ordered by key, got %+v", decisions)
	}
	if _, ok := store.GetDecision("bad-json"); ok {
		t.Fatal("expected malformed decision payload to be rejected by GetDecision")
	}

	auditActions := store.ListAuditActions()
	if len(auditActions) != 2 {
		t.Fatalf("expected 2 valid audit actions, got %d", len(auditActions))
	}
	if auditActions[0].ActionID != "audit-1" || auditActions[1].ActionID != "audit-2" {
		t.Fatalf("expected audit list ordered by key, got %+v", auditActions)
	}
	if _, ok := store.GetAuditAction("bad-json"); ok {
		t.Fatal("expected malformed audit payload to be rejected by GetAuditAction")
	}
}
