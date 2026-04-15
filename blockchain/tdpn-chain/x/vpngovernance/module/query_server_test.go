package module

import (
	"errors"
	"testing"

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

	_, listPoliciesErr := server.ListPolicies(ListPoliciesRequest{})
	if !errors.Is(listPoliciesErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list policies query, got %v", listPoliciesErr)
	}

	_, listDecisionsErr := server.ListDecisions(ListDecisionsRequest{})
	if !errors.Is(listDecisionsErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list decisions query, got %v", listDecisionsErr)
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
	if !errors.Is(decisionErr, errDecisionNotFound) {
		t.Fatalf("expected errDecisionNotFound, got %v", decisionErr)
	}
}

func TestQueryServerFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	expectedPolicy := types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy One", Version: 1, ActivatedAtUnix: 4102444800}
	expectedDecision := types.GovernanceDecision{DecisionID: "decision-1", PolicyID: "policy-1", ProposalID: "proposal-1", Outcome: types.DecisionOutcomeApprove, Decider: "council", DecidedAtUnix: 4102444800}
	k.UpsertPolicy(expectedPolicy)
	k.UpsertDecision(expectedDecision)

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
}
