package module

import (
	"context"
	"errors"
	"testing"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpngovernance/v1"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

func TestProtoAdaptersCanceledContextFailsClosedAcrossSurface(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewProtoMsgServerAdapter(&k)
	queryAdapter := NewProtoQueryServerAdapter(&k)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, createErr := msgAdapter.CreatePolicy(ctx, &pb.MsgCreatePolicyRequest{
		Policy: &pb.GovernancePolicy{
			PolicyId:        "policy-canceled-context",
			Title:           "Canceled Context Policy",
			Version:         1,
			ActivatedAtUnix: 4102444800,
		},
	})
	if !errors.Is(createErr, context.Canceled) {
		t.Fatalf("expected context.Canceled from CreatePolicy, got %v", createErr)
	}
	if _, ok := k.GetPolicy("policy-canceled-context"); ok {
		t.Fatal("did not expect policy persistence on canceled context")
	}

	_, decisionErr := msgAdapter.RecordDecision(ctx, &pb.MsgRecordDecisionRequest{
		Decision: &pb.GovernanceDecision{
			DecisionId:    "decision-canceled-context",
			PolicyId:      "policy-canceled-context",
			ProposalId:    "proposal-canceled-context",
			Outcome:       types.DecisionOutcomeApprove,
			Decider:       "council-canceled-context",
			DecidedAtUnix: 4102444800,
		},
	})
	if !errors.Is(decisionErr, context.Canceled) {
		t.Fatalf("expected context.Canceled from RecordDecision, got %v", decisionErr)
	}
	if _, ok := k.GetDecision("decision-canceled-context"); ok {
		t.Fatal("did not expect decision persistence on canceled context")
	}

	_, auditErr := msgAdapter.RecordAuditAction(ctx, &pb.MsgRecordAuditActionRequest{
		Action: &pb.GovernanceAuditAction{
			ActionId:        "audit-canceled-context",
			Action:          "admin_allow_validator",
			Actor:           "admin-canceled-context",
			Reason:          "context canceled before commit",
			EvidencePointer: "ipfs://audit-canceled-context",
			TimestampUnix:   4102444800,
		},
	})
	if !errors.Is(auditErr, context.Canceled) {
		t.Fatalf("expected context.Canceled from RecordAuditAction, got %v", auditErr)
	}
	if _, ok := k.GetAuditAction("audit-canceled-context"); ok {
		t.Fatal("did not expect audit action persistence on canceled context")
	}

	k.UpsertPolicy(types.GovernancePolicy{
		PolicyID:        "policy-query-canceled",
		Title:           "Query Canceled Policy",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	})
	k.UpsertDecision(types.GovernanceDecision{
		DecisionID:    "decision-query-canceled",
		PolicyID:      "policy-query-canceled",
		ProposalID:    "proposal-query-canceled",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-query-canceled",
		DecidedAtUnix: 4102444800,
	})
	if _, err := k.RecordAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-query-canceled",
		Action:          "admin_allow_validator",
		Actor:           "admin-query-canceled",
		Reason:          "seed query record",
		EvidencePointer: "ipfs://audit-query-canceled",
		TimestampUnix:   4102444800,
	}); err != nil {
		t.Fatalf("seed audit action: %v", err)
	}

	if _, err := queryAdapter.GovernancePolicy(ctx, &pb.QueryGovernancePolicyRequest{PolicyId: "policy-query-canceled"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from GovernancePolicy, got %v", err)
	}
	if _, err := queryAdapter.GovernanceDecision(ctx, &pb.QueryGovernanceDecisionRequest{DecisionId: "decision-query-canceled"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from GovernanceDecision, got %v", err)
	}
	if _, err := queryAdapter.GovernanceAuditAction(ctx, &pb.QueryGovernanceAuditActionRequest{ActionId: "audit-query-canceled"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from GovernanceAuditAction, got %v", err)
	}
	if _, err := queryAdapter.ListGovernancePolicies(ctx, &pb.QueryListGovernancePoliciesRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from ListGovernancePolicies, got %v", err)
	}
	if _, err := queryAdapter.ListGovernanceDecisions(ctx, &pb.QueryListGovernanceDecisionsRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from ListGovernanceDecisions, got %v", err)
	}
	if _, err := queryAdapter.ListGovernanceAuditActions(ctx, &pb.QueryListGovernanceAuditActionsRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from ListGovernanceAuditActions, got %v", err)
	}
}
