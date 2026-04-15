package module

import (
	"context"
	"errors"
	"testing"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpngovernance/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

func TestProtoMsgServerAdapterCreatePolicy(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoMsgServerAdapter(&k)

	resp, err := adapter.CreatePolicy(context.Background(), &pb.MsgCreatePolicyRequest{Policy: &pb.GovernancePolicy{PolicyId: "policy-1", Title: "Policy One", Version: 1, ActivatedAtUnix: 4102444800}})
	if err != nil {
		t.Fatalf("expected create policy success, got %v", err)
	}
	if resp.GetPolicy() == nil {
		t.Fatal("expected policy in response")
	}
	if resp.GetPolicy().GetPolicyId() != "policy-1" {
		t.Fatalf("expected policy_id policy-1, got %q", resp.GetPolicy().GetPolicyId())
	}
	if resp.GetConflict() {
		t.Fatal("expected conflict=false for successful create")
	}
}

func TestProtoMsgServerAdapterCreatePolicyConflict(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoMsgServerAdapter(&k)

	_, err := adapter.CreatePolicy(context.Background(), &pb.MsgCreatePolicyRequest{Policy: &pb.GovernancePolicy{PolicyId: "policy-conflict-1", Title: "Policy", Version: 1, ActivatedAtUnix: 4102444800}})
	if err != nil {
		t.Fatalf("seed create policy failed: %v", err)
	}

	resp, err := adapter.CreatePolicy(context.Background(), &pb.MsgCreatePolicyRequest{Policy: &pb.GovernancePolicy{PolicyId: "policy-conflict-1", Title: "Policy Updated", Version: 1, ActivatedAtUnix: 4102444800}})
	if err == nil {
		t.Fatal("expected policy conflict error")
	}
	if !errors.Is(err, ErrPolicyConflict) {
		t.Fatalf("expected ErrPolicyConflict, got %v", err)
	}
	if !resp.GetConflict() {
		t.Fatal("expected conflict=true on conflicting create")
	}
}

func TestProtoMsgServerAdapterRecordDecision(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoMsgServerAdapter(&k)

	if _, err := adapter.CreatePolicy(context.Background(), &pb.MsgCreatePolicyRequest{Policy: &pb.GovernancePolicy{PolicyId: "policy-2", Title: "Policy Two", Version: 1, ActivatedAtUnix: 4102444800}}); err != nil {
		t.Fatalf("create policy failed: %v", err)
	}

	resp, err := adapter.RecordDecision(context.Background(), &pb.MsgRecordDecisionRequest{Decision: &pb.GovernanceDecision{DecisionId: "decision-2", PolicyId: "policy-2", ProposalId: "proposal-2", Outcome: types.DecisionOutcomeApprove, Decider: "council-2", DecidedAtUnix: 4102444800}})
	if err != nil {
		t.Fatalf("expected record decision success, got %v", err)
	}
	if resp.GetDecision() == nil {
		t.Fatal("expected decision in response")
	}
	if resp.GetDecision().GetDecisionId() != "decision-2" {
		t.Fatalf("expected decision_id decision-2, got %q", resp.GetDecision().GetDecisionId())
	}
}

func TestProtoQueryServerAdapterNotFoundReturnsFoundFalse(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoQueryServerAdapter(&k)

	policyResp, err := adapter.GovernancePolicy(context.Background(), &pb.QueryGovernancePolicyRequest{PolicyId: "missing-policy"})
	if err != nil {
		t.Fatalf("expected nil error for missing policy lookup, got %v", err)
	}
	if policyResp.GetFound() {
		t.Fatal("expected found=false for missing policy")
	}

	decisionResp, err := adapter.GovernanceDecision(context.Background(), &pb.QueryGovernanceDecisionRequest{DecisionId: "missing-decision"})
	if err != nil {
		t.Fatalf("expected nil error for missing decision lookup, got %v", err)
	}
	if decisionResp.GetFound() {
		t.Fatal("expected found=false for missing decision")
	}
}

func TestProtoQueryServerAdapterGetAndList(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-10", Title: "Policy Ten", Version: 10, ActivatedAtUnix: 4102444800, Status: chaintypes.ReconciliationPending})
	k.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-10", PolicyID: "policy-10", ProposalID: "proposal-10", Outcome: types.DecisionOutcomeReject, Decider: "council-10", DecidedAtUnix: 4102444800, Status: chaintypes.ReconciliationSubmitted})

	adapter := NewProtoQueryServerAdapter(&k)

	policyResp, err := adapter.GovernancePolicy(context.Background(), &pb.QueryGovernancePolicyRequest{PolicyId: "policy-10"})
	if err != nil {
		t.Fatalf("expected policy lookup success, got %v", err)
	}
	if !policyResp.GetFound() {
		t.Fatal("expected found=true for policy lookup")
	}
	if policyResp.GetPolicy().GetPolicyId() != "policy-10" {
		t.Fatalf("expected policy_id policy-10, got %q", policyResp.GetPolicy().GetPolicyId())
	}

	decisionResp, err := adapter.GovernanceDecision(context.Background(), &pb.QueryGovernanceDecisionRequest{DecisionId: "decision-10"})
	if err != nil {
		t.Fatalf("expected decision lookup success, got %v", err)
	}
	if !decisionResp.GetFound() {
		t.Fatal("expected found=true for decision lookup")
	}
	if decisionResp.GetDecision().GetDecisionId() != "decision-10" {
		t.Fatalf("expected decision_id decision-10, got %q", decisionResp.GetDecision().GetDecisionId())
	}
	if decisionResp.GetDecision().GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED {
		t.Fatalf("expected submitted status, got %v", decisionResp.GetDecision().GetStatus())
	}

	listPoliciesResp, err := adapter.ListGovernancePolicies(context.Background(), &pb.QueryListGovernancePoliciesRequest{})
	if err != nil {
		t.Fatalf("expected list policies success, got %v", err)
	}
	if len(listPoliciesResp.GetPolicies()) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(listPoliciesResp.GetPolicies()))
	}

	listDecisionsResp, err := adapter.ListGovernanceDecisions(context.Background(), &pb.QueryListGovernanceDecisionsRequest{})
	if err != nil {
		t.Fatalf("expected list decisions success, got %v", err)
	}
	if len(listDecisionsResp.GetDecisions()) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(listDecisionsResp.GetDecisions()))
	}
}

func TestProtoAdaptersNilKeeperPropagatesErrNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	msgAdapter := NewProtoMsgServerAdapter(k)
	queryAdapter := NewProtoQueryServerAdapter(k)

	_, msgErr := msgAdapter.CreatePolicy(context.Background(), &pb.MsgCreatePolicyRequest{Policy: &pb.GovernancePolicy{PolicyId: "policy-nil", Title: "Policy Nil", Version: 1, ActivatedAtUnix: 1}})
	if !errors.Is(msgErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from msg adapter, got %v", msgErr)
	}

	_, queryErr := queryAdapter.ListGovernancePolicies(context.Background(), &pb.QueryListGovernancePoliciesRequest{})
	if !errors.Is(queryErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from query adapter, got %v", queryErr)
	}
}

func TestProtoAdaptersNilRequestsAreFailSafe(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewProtoMsgServerAdapter(&k)
	queryAdapter := NewProtoQueryServerAdapter(&k)

	_, createErr := msgAdapter.CreatePolicy(context.Background(), nil)
	if !errors.Is(createErr, ErrInvalidPolicy) {
		t.Fatalf("expected ErrInvalidPolicy for nil create request, got %v", createErr)
	}

	_, recordErr := msgAdapter.RecordDecision(context.Background(), nil)
	if !errors.Is(recordErr, ErrInvalidDecision) {
		t.Fatalf("expected ErrInvalidDecision for nil record request, got %v", recordErr)
	}

	policyResp, policyErr := queryAdapter.GovernancePolicy(context.Background(), nil)
	if policyErr != nil {
		t.Fatalf("expected nil error for nil policy query request, got %v", policyErr)
	}
	if policyResp.GetFound() {
		t.Fatal("expected found=false for nil policy query request")
	}
	if policyResp.GetPolicy() != nil {
		t.Fatal("expected nil policy when found=false")
	}

	decisionResp, decisionErr := queryAdapter.GovernanceDecision(context.Background(), nil)
	if decisionErr != nil {
		t.Fatalf("expected nil error for nil decision query request, got %v", decisionErr)
	}
	if decisionResp.GetFound() {
		t.Fatal("expected found=false for nil decision query request")
	}
	if decisionResp.GetDecision() != nil {
		t.Fatal("expected nil decision when found=false")
	}
}
