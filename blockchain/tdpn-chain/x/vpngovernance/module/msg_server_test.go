package module

import (
	"errors"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

func TestMsgServerCreatePolicyHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	resp, err := server.CreatePolicy(CreatePolicyRequest{Policy: types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy One", Version: 1, ActivatedAtUnix: 4102444800}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first policy")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first policy")
	}
	if resp.Policy.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, resp.Policy.Status)
	}
}

func TestMsgServerCreatePolicyIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := CreatePolicyRequest{Policy: types.GovernancePolicy{PolicyID: "policy-2", Title: "Policy Two", Version: 1, ActivatedAtUnix: 4102444800}}
	if _, err := server.CreatePolicy(req); err != nil {
		t.Fatalf("first create failed: %v", err)
	}

	resp, err := server.CreatePolicy(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed policy")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed policy")
	}
}

func TestMsgServerCreatePolicyConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	base := CreatePolicyRequest{Policy: types.GovernancePolicy{PolicyID: "policy-3", Title: "Policy Three", Version: 1, ActivatedAtUnix: 4102444800}}
	if _, err := server.CreatePolicy(base); err != nil {
		t.Fatalf("seed create failed: %v", err)
	}

	conflict := base
	conflict.Policy.Title = "Policy Three Updated"
	resp, err := server.CreatePolicy(conflict)
	if err == nil {
		t.Fatal("expected policy conflict error")
	}
	if !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("expected ErrPolicyConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerCreatePolicyInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.CreatePolicy(CreatePolicyRequest{Policy: types.GovernancePolicy{PolicyID: "policy-invalid", Version: 1, ActivatedAtUnix: 4102444800}})
	if err == nil {
		t.Fatal("expected invalid policy error")
	}
	if !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("expected ErrInvalidPolicy, got %v", err)
	}
}

func TestMsgServerRecordDecisionHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.CreatePolicy(CreatePolicyRequest{Policy: types.GovernancePolicy{PolicyID: "policy-4", Title: "Policy Four", Version: 1, ActivatedAtUnix: 4102444800}}); err != nil {
		t.Fatalf("create policy failed: %v", err)
	}

	resp, err := server.RecordDecision(RecordDecisionRequest{Decision: types.GovernanceDecision{DecisionID: "decision-4", PolicyID: "policy-4", ProposalID: "proposal-4", Outcome: types.DecisionOutcomeApprove, Decider: "council-4", DecidedAtUnix: 4102444800}})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first decision")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first decision")
	}
	if resp.Decision.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, resp.Decision.Status)
	}
}

func TestMsgServerRecordDecisionIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.CreatePolicy(CreatePolicyRequest{Policy: types.GovernancePolicy{PolicyID: "policy-5", Title: "Policy Five", Version: 1, ActivatedAtUnix: 4102444800}}); err != nil {
		t.Fatalf("create policy failed: %v", err)
	}

	req := RecordDecisionRequest{Decision: types.GovernanceDecision{DecisionID: "decision-5", PolicyID: "policy-5", ProposalID: "proposal-5", Outcome: types.DecisionOutcomeReject, Decider: "council-5", DecidedAtUnix: 4102444800}}
	if _, err := server.RecordDecision(req); err != nil {
		t.Fatalf("first record failed: %v", err)
	}

	resp, err := server.RecordDecision(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed decision")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed decision")
	}
}

func TestMsgServerRecordDecisionConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.CreatePolicy(CreatePolicyRequest{Policy: types.GovernancePolicy{PolicyID: "policy-6", Title: "Policy Six", Version: 1, ActivatedAtUnix: 4102444800}}); err != nil {
		t.Fatalf("create policy failed: %v", err)
	}

	base := RecordDecisionRequest{Decision: types.GovernanceDecision{DecisionID: "decision-6", PolicyID: "policy-6", ProposalID: "proposal-6", Outcome: types.DecisionOutcomeApprove, Decider: "council-6", DecidedAtUnix: 4102444800}}
	if _, err := server.RecordDecision(base); err != nil {
		t.Fatalf("first record failed: %v", err)
	}

	conflict := base
	conflict.Decision.Outcome = types.DecisionOutcomeAbstain
	resp, err := server.RecordDecision(conflict)
	if err == nil {
		t.Fatal("expected decision conflict error")
	}
	if !errors.Is(err, ErrDecisionConflict) {
		t.Fatalf("expected ErrDecisionConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerRecordDecisionMissingPolicyPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.RecordDecision(RecordDecisionRequest{Decision: types.GovernanceDecision{DecisionID: "decision-missing-policy", PolicyID: "policy-missing", ProposalID: "proposal-missing", Outcome: types.DecisionOutcomeApprove, Decider: "council", DecidedAtUnix: 4102444800}})
	if err == nil {
		t.Fatal("expected missing policy error")
	}
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestMsgServerRecordDecisionInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.RecordDecision(RecordDecisionRequest{Decision: types.GovernanceDecision{DecisionID: "decision-invalid", PolicyID: "policy-invalid", ProposalID: "proposal-invalid", Outcome: "invalid", Decider: "council", DecidedAtUnix: 4102444800}})
	if err == nil {
		t.Fatal("expected invalid decision error")
	}
	if !errors.Is(err, ErrInvalidDecision) && !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("expected invalid decision or policy not found, got %v", err)
	}
}

func TestMsgServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewMsgServer(k)

	_, createErr := server.CreatePolicy(CreatePolicyRequest{Policy: types.GovernancePolicy{PolicyID: "policy-nil", Title: "Policy Nil", Version: 1, ActivatedAtUnix: 1}})
	if !errors.Is(createErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on create policy, got %v", createErr)
	}

	_, recordErr := server.RecordDecision(RecordDecisionRequest{Decision: types.GovernanceDecision{DecisionID: "decision-nil", PolicyID: "policy-nil", ProposalID: "proposal-nil", Outcome: types.DecisionOutcomeApprove, Decider: "council", DecidedAtUnix: 1}})
	if !errors.Is(recordErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on record decision, got %v", recordErr)
	}
}
