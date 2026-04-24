package module

import (
	"errors"
	"testing"

	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

func TestQueryServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewQueryServer(k)

	_, policyErr := server.GetPolicy(GetPolicyRequest{PolicyID: "policy-nil"})
	if !errors.Is(policyErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for policy query, got %v", policyErr)
	}

	_, decisionErr := server.GetDecision(GetDecisionRequest{DecisionID: "decision-nil"})
	if !errors.Is(decisionErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for decision query, got %v", decisionErr)
	}

	_, auditErr := server.GetAuditAction(GetAuditActionRequest{ActionID: "audit-nil"})
	if !errors.Is(auditErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for audit action query, got %v", auditErr)
	}

	_, listPoliciesErr := server.ListPolicies(ListPoliciesRequest{})
	if !errors.Is(listPoliciesErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list policies query, got %v", listPoliciesErr)
	}

	_, listDecisionsErr := server.ListDecisions(ListDecisionsRequest{})
	if !errors.Is(listDecisionsErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list decisions query, got %v", listDecisionsErr)
	}

	_, listAuditErr := server.ListAuditActions(ListAuditActionsRequest{})
	if !errors.Is(listAuditErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list audit actions query, got %v", listAuditErr)
	}
}

func TestQueryServerNotFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewQueryServer(&k)

	_, policyErr := server.GetPolicy(GetPolicyRequest{PolicyID: "policy-missing"})
	if !errors.Is(policyErr, ErrPolicyNotFound) {
		t.Fatalf("expected ErrPolicyNotFound, got %v", policyErr)
	}

	_, decisionErr := server.GetDecision(GetDecisionRequest{DecisionID: "decision-missing"})
	if !errors.Is(decisionErr, ErrDecisionNotFound) {
		t.Fatalf("expected ErrDecisionNotFound, got %v", decisionErr)
	}

	_, auditErr := server.GetAuditAction(GetAuditActionRequest{ActionID: "audit-missing"})
	if !errors.Is(auditErr, ErrAuditActionNotFound) {
		t.Fatalf("expected ErrAuditActionNotFound, got %v", auditErr)
	}
}

func TestQueryServerGetPolicyFailsClosedOnCorruptReadModel(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := keeper.NewKVStore(backend)
	k := keeper.NewKeeperWithStore(store)
	backend.Set([]byte("policy/policy-corrupt"), []byte("{"))

	server := NewQueryServer(&k)
	_, err := server.GetPolicy(GetPolicyRequest{PolicyID: "policy-corrupt"})
	if err == nil {
		t.Fatal("expected policy lookup to fail closed on corrupt read model")
	}
	if errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("expected corruption error, got not-found sentinel: %v", err)
	}
}

func TestQueryServerGetDecisionFailsClosedOnCorruptReadModel(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := keeper.NewKVStore(backend)
	k := keeper.NewKeeperWithStore(store)
	backend.Set([]byte("decision/decision-corrupt"), []byte("{"))

	server := NewQueryServer(&k)
	_, err := server.GetDecision(GetDecisionRequest{DecisionID: "decision-corrupt"})
	if err == nil {
		t.Fatal("expected decision lookup to fail closed on corrupt read model")
	}
	if errors.Is(err, ErrDecisionNotFound) {
		t.Fatalf("expected corruption error, got not-found sentinel: %v", err)
	}
}

func TestQueryServerGetAuditActionFailsClosedOnCorruptReadModel(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := keeper.NewKVStore(backend)
	k := keeper.NewKeeperWithStore(store)
	backend.Set([]byte("audit_action/audit-corrupt"), []byte("{"))

	server := NewQueryServer(&k)
	_, err := server.GetAuditAction(GetAuditActionRequest{ActionID: "audit-corrupt"})
	if err == nil {
		t.Fatal("expected audit-action lookup to fail closed on corrupt read model")
	}
	if errors.Is(err, ErrAuditActionNotFound) {
		t.Fatalf("expected corruption error, got not-found sentinel: %v", err)
	}
}

func TestQueryServerGetAuditActionFailsClosedOnInvalidReadModel(t *testing.T) {
	t.Parallel()

	store := keeper.NewInMemoryStore()
	store.PutAuditAction(types.GovernanceAuditAction{ActionID: "audit-invalid-read"})
	k := keeper.NewKeeperWithStore(store)

	server := NewQueryServer(&k)
	_, err := server.GetAuditAction(GetAuditActionRequest{ActionID: "audit-invalid-read"})
	if err == nil {
		t.Fatal("expected audit-action lookup to fail closed on invalid read model")
	}
	if errors.Is(err, ErrAuditActionNotFound) {
		t.Fatalf("expected validation error, got not-found sentinel: %v", err)
	}
}

func TestQueryServerGetPolicyFailsClosedOnInvalidStatusReadModel(t *testing.T) {
	t.Parallel()

	store := keeper.NewInMemoryStore()
	store.UpsertPolicy(types.GovernancePolicy{
		PolicyID:        "policy-invalid-status-read",
		Title:           "Policy Invalid Status Read",
		Version:         1,
		ActivatedAtUnix: 4102444800,
		Status:          "stalled",
	})
	k := keeper.NewKeeperWithStore(store)

	server := NewQueryServer(&k)
	_, err := server.GetPolicy(GetPolicyRequest{PolicyID: "policy-invalid-status-read"})
	if err == nil {
		t.Fatal("expected policy lookup to fail closed on invalid status")
	}
	if errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("expected validation error, got not-found sentinel: %v", err)
	}
}

func TestQueryServerGetDecisionFailsClosedOnInvalidStatusReadModel(t *testing.T) {
	t.Parallel()

	store := keeper.NewInMemoryStore()
	store.UpsertPolicy(types.GovernancePolicy{
		PolicyID:        "policy-decision-invalid-status-read",
		Title:           "Policy Decision Invalid Status Read",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	})
	store.UpsertDecision(types.GovernanceDecision{
		DecisionID:    "decision-invalid-status-read",
		PolicyID:      "policy-decision-invalid-status-read",
		ProposalID:    "proposal-invalid-status-read",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-invalid-status-read",
		Reason:        "seed invalid decision status",
		DecidedAtUnix: 4102444800,
		Status:        "stalled",
	})
	k := keeper.NewKeeperWithStore(store)

	server := NewQueryServer(&k)
	_, err := server.GetDecision(GetDecisionRequest{DecisionID: "decision-invalid-status-read"})
	if err == nil {
		t.Fatal("expected decision lookup to fail closed on invalid status")
	}
	if errors.Is(err, ErrDecisionNotFound) {
		t.Fatalf("expected validation error, got not-found sentinel: %v", err)
	}
}

func TestQueryServerFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	expectedPolicy := types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy One", Version: 1, ActivatedAtUnix: 4102444800}
	expectedDecision := types.GovernanceDecision{DecisionID: "decision-1", PolicyID: "policy-1", ProposalID: "proposal-1", Outcome: types.DecisionOutcomeApprove, Decider: "council", DecidedAtUnix: 4102444800}
	expectedAudit := types.GovernanceAuditAction{ActionID: "audit-1", Action: "admin_disable_validator", Actor: "admin", Reason: "reason", EvidencePointer: "ipfs://audit-1", TimestampUnix: 4102444800}
	k.UpsertPolicy(expectedPolicy)
	k.UpsertDecision(expectedDecision)
	if _, err := k.RecordAuditAction(expectedAudit); err != nil {
		t.Fatalf("expected audit action seed success, got %v", err)
	}

	server := NewQueryServer(&k)

	policyResp, policyErr := server.GetPolicy(GetPolicyRequest{PolicyID: "policy-1"})
	if policyErr != nil {
		t.Fatalf("expected policy query success, got %v", policyErr)
	}
	if policyResp.Policy.PolicyID != expectedPolicy.PolicyID {
		t.Fatalf("unexpected policy id: %q", policyResp.Policy.PolicyID)
	}

	decisionResp, decisionErr := server.GetDecision(GetDecisionRequest{DecisionID: "decision-1"})
	if decisionErr != nil {
		t.Fatalf("expected decision query success, got %v", decisionErr)
	}
	if decisionResp.Decision.DecisionID != expectedDecision.DecisionID {
		t.Fatalf("unexpected decision id: %q", decisionResp.Decision.DecisionID)
	}

	auditResp, auditErr := server.GetAuditAction(GetAuditActionRequest{ActionID: "audit-1"})
	if auditErr != nil {
		t.Fatalf("expected audit query success, got %v", auditErr)
	}
	if auditResp.Action.ActionID != expectedAudit.ActionID {
		t.Fatalf("unexpected audit action id: %q", auditResp.Action.ActionID)
	}
}

func TestQueryServerListNonEmpty(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-3", Title: "Policy Three", Version: 3, ActivatedAtUnix: 3})
	k.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy One", Version: 1, ActivatedAtUnix: 1})
	k.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-2", Title: "Policy Two", Version: 2, ActivatedAtUnix: 2})

	k.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-3", PolicyID: "policy-1", ProposalID: "proposal-3", Outcome: types.DecisionOutcomeApprove, Decider: "c3", DecidedAtUnix: 3})
	k.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-1", PolicyID: "policy-1", ProposalID: "proposal-1", Outcome: types.DecisionOutcomeReject, Decider: "c1", DecidedAtUnix: 1})
	k.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-2", PolicyID: "policy-1", ProposalID: "proposal-2", Outcome: types.DecisionOutcomeAbstain, Decider: "c2", DecidedAtUnix: 2})
	_, _ = k.RecordAuditAction(types.GovernanceAuditAction{ActionID: "audit-3", Action: "admin_allow_validator", Actor: "a3", Reason: "r3", EvidencePointer: "ipfs://a3", TimestampUnix: 3})
	_, _ = k.RecordAuditAction(types.GovernanceAuditAction{ActionID: "audit-1", Action: "admin_disable_validator", Actor: "a1", Reason: "r1", EvidencePointer: "ipfs://a1", TimestampUnix: 1})
	_, _ = k.RecordAuditAction(types.GovernanceAuditAction{ActionID: "audit-2", Action: "admin_disable_validator", Actor: "a2", Reason: "r2", EvidencePointer: "ipfs://a2", TimestampUnix: 2})

	server := NewQueryServer(&k)

	policiesResp, policiesErr := server.ListPolicies(ListPoliciesRequest{})
	if policiesErr != nil {
		t.Fatalf("expected list policies success, got %v", policiesErr)
	}
	if len(policiesResp.Policies) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(policiesResp.Policies))
	}
	if policiesResp.Policies[0].PolicyID != "policy-1" || policiesResp.Policies[1].PolicyID != "policy-2" || policiesResp.Policies[2].PolicyID != "policy-3" {
		t.Fatalf("expected sorted policy ids [policy-1 policy-2 policy-3], got [%s %s %s]", policiesResp.Policies[0].PolicyID, policiesResp.Policies[1].PolicyID, policiesResp.Policies[2].PolicyID)
	}

	decisionsResp, decisionsErr := server.ListDecisions(ListDecisionsRequest{})
	if decisionsErr != nil {
		t.Fatalf("expected list decisions success, got %v", decisionsErr)
	}
	if len(decisionsResp.Decisions) != 3 {
		t.Fatalf("expected 3 decisions, got %d", len(decisionsResp.Decisions))
	}
	if decisionsResp.Decisions[0].DecisionID != "decision-1" || decisionsResp.Decisions[1].DecisionID != "decision-2" || decisionsResp.Decisions[2].DecisionID != "decision-3" {
		t.Fatalf("expected sorted decision ids [decision-1 decision-2 decision-3], got [%s %s %s]", decisionsResp.Decisions[0].DecisionID, decisionsResp.Decisions[1].DecisionID, decisionsResp.Decisions[2].DecisionID)
	}

	auditResp, auditErr := server.ListAuditActions(ListAuditActionsRequest{})
	if auditErr != nil {
		t.Fatalf("expected list audit actions success, got %v", auditErr)
	}
	if len(auditResp.Actions) != 3 {
		t.Fatalf("expected 3 audit actions, got %d", len(auditResp.Actions))
	}
	if auditResp.Actions[0].ActionID != "audit-1" || auditResp.Actions[1].ActionID != "audit-2" || auditResp.Actions[2].ActionID != "audit-3" {
		t.Fatalf("expected sorted audit action ids [audit-1 audit-2 audit-3], got [%s %s %s]", auditResp.Actions[0].ActionID, auditResp.Actions[1].ActionID, auditResp.Actions[2].ActionID)
	}
}
