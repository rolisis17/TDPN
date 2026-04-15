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
}
