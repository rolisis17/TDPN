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

func TestProtoGrpcAdaptersCanonicalizePolicyIDOnWriteAndMixedCaseQuery(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewProtoMsgServerAdapter(&k)
	queryAdapter := NewProtoQueryServerAdapter(&k)

	createResp, err := msgAdapter.CreatePolicy(context.Background(), &pb.MsgCreatePolicyRequest{
		Policy: &pb.GovernancePolicy{
			PolicyId:        "  PoLiCy-Canonical-Adapter-1  ",
			Title:           "Policy Canonical Adapter",
			Version:         1,
			ActivatedAtUnix: 4102444800,
		},
	})
	if err != nil {
		t.Fatalf("expected create policy success, got %v", err)
	}
	if createResp.GetPolicy() == nil {
		t.Fatal("expected policy in create response")
	}
	if createResp.GetPolicy().GetPolicyId() != "policy-canonical-adapter-1" {
		t.Fatalf("expected canonical policy id %q, got %q", "policy-canonical-adapter-1", createResp.GetPolicy().GetPolicyId())
	}
	if createResp.GetPolicy().GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING {
		t.Fatalf("expected pending status after canonicalized write, got %v", createResp.GetPolicy().GetStatus())
	}
	if createResp.GetConflict() {
		t.Fatal("expected conflict=false on first create")
	}
	if createResp.GetIdempotentReplay() {
		t.Fatal("expected idempotent_replay=false on first create")
	}

	queryResp, err := queryAdapter.GovernancePolicy(context.Background(), &pb.QueryGovernancePolicyRequest{PolicyId: "  POLICY-CANONICAL-ADAPTER-1  "})
	if err != nil {
		t.Fatalf("expected policy query success, got %v", err)
	}
	if !queryResp.GetFound() {
		t.Fatal("expected found=true for mixed-case canonical policy query")
	}
	if queryResp.GetPolicy() == nil {
		t.Fatal("expected policy in query response")
	}
	if queryResp.GetPolicy().GetPolicyId() != "policy-canonical-adapter-1" {
		t.Fatalf("expected canonical policy id %q from query, got %q", "policy-canonical-adapter-1", queryResp.GetPolicy().GetPolicyId())
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

func TestProtoGrpcAdaptersCanonicalizeDecisionIDOnWriteAndMixedCaseQuery(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewProtoMsgServerAdapter(&k)
	queryAdapter := NewProtoQueryServerAdapter(&k)

	if _, err := msgAdapter.CreatePolicy(context.Background(), &pb.MsgCreatePolicyRequest{
		Policy: &pb.GovernancePolicy{
			PolicyId:        "  PoLiCy-Decision-Adapter-1  ",
			Title:           "Policy For Decision Adapter",
			Version:         1,
			ActivatedAtUnix: 4102444800,
		},
	}); err != nil {
		t.Fatalf("expected seed policy create success, got %v", err)
	}

	recordResp, err := msgAdapter.RecordDecision(context.Background(), &pb.MsgRecordDecisionRequest{
		Decision: &pb.GovernanceDecision{
			DecisionId:    "  DeCiSiOn-Canonical-Adapter-1  ",
			PolicyId:      "  POLICY-DECISION-ADAPTER-1  ",
			ProposalId:    "  PrOpOsAl-Adapter-1  ",
			Outcome:       "  ApPrOvE  ",
			Decider:       "  CoUnCiL-Adapter-1  ",
			Reason:        "preserve reason text",
			DecidedAtUnix: 4102444800,
		},
	})
	if err != nil {
		t.Fatalf("expected record decision success, got %v", err)
	}
	if recordResp.GetDecision() == nil {
		t.Fatal("expected decision in record response")
	}
	if recordResp.GetDecision().GetDecisionId() != "decision-canonical-adapter-1" {
		t.Fatalf("expected canonical decision id %q, got %q", "decision-canonical-adapter-1", recordResp.GetDecision().GetDecisionId())
	}
	if recordResp.GetDecision().GetPolicyId() != "policy-decision-adapter-1" {
		t.Fatalf("expected canonical policy id %q, got %q", "policy-decision-adapter-1", recordResp.GetDecision().GetPolicyId())
	}
	if recordResp.GetDecision().GetProposalId() != "proposal-adapter-1" {
		t.Fatalf("expected canonical proposal id %q, got %q", "proposal-adapter-1", recordResp.GetDecision().GetProposalId())
	}
	if recordResp.GetDecision().GetOutcome() != types.DecisionOutcomeApprove {
		t.Fatalf("expected canonical outcome %q, got %q", types.DecisionOutcomeApprove, recordResp.GetDecision().GetOutcome())
	}
	if recordResp.GetDecision().GetDecider() != "council-adapter-1" {
		t.Fatalf("expected canonical decider %q, got %q", "council-adapter-1", recordResp.GetDecision().GetDecider())
	}
	if recordResp.GetDecision().GetStatus() != pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING {
		t.Fatalf("expected pending status after canonicalized write, got %v", recordResp.GetDecision().GetStatus())
	}
	if recordResp.GetConflict() {
		t.Fatal("expected conflict=false on first record decision")
	}
	if recordResp.GetIdempotentReplay() {
		t.Fatal("expected idempotent_replay=false on first record decision")
	}

	queryResp, err := queryAdapter.GovernanceDecision(context.Background(), &pb.QueryGovernanceDecisionRequest{DecisionId: "  DECISION-CANONICAL-ADAPTER-1  "})
	if err != nil {
		t.Fatalf("expected decision query success, got %v", err)
	}
	if !queryResp.GetFound() {
		t.Fatal("expected found=true for mixed-case canonical decision query")
	}
	if queryResp.GetDecision() == nil {
		t.Fatal("expected decision in query response")
	}
	if queryResp.GetDecision().GetDecisionId() != "decision-canonical-adapter-1" {
		t.Fatalf("expected canonical decision id %q from query, got %q", "decision-canonical-adapter-1", queryResp.GetDecision().GetDecisionId())
	}
}

func TestProtoMsgServerAdapterRecordAuditAction(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoMsgServerAdapter(&k)

	resp, err := adapter.RecordAuditAction(context.Background(), &pb.MsgRecordAuditActionRequest{Action: &pb.GovernanceAuditAction{
		ActionId:        "audit-1",
		Action:          "admin_disable_validator",
		Actor:           "admin-1",
		Reason:          "objective evidence verified",
		EvidencePointer: "ipfs://audit-1",
		TimestampUnix:   4102444800,
	}})
	if err != nil {
		t.Fatalf("expected record audit action success, got %v", err)
	}
	if resp.GetAction() == nil {
		t.Fatal("expected audit action in response")
	}
	if resp.GetAction().GetActionId() != "audit-1" {
		t.Fatalf("expected action_id audit-1, got %q", resp.GetAction().GetActionId())
	}
	if resp.GetConflict() {
		t.Fatal("expected conflict=false for successful record audit action")
	}
}

func TestProtoGrpcAdaptersCanonicalizeAuditActionIDOnWriteAndMixedCaseQuery(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewProtoMsgServerAdapter(&k)
	queryAdapter := NewProtoQueryServerAdapter(&k)

	recordResp, err := msgAdapter.RecordAuditAction(context.Background(), &pb.MsgRecordAuditActionRequest{
		Action: &pb.GovernanceAuditAction{
			ActionId:        "  AuDiT-Canonical-Adapter-1  ",
			Action:          "  AdMiN_AlLoW_VaLiDaToR  ",
			Actor:           "  BoOtStRaP-AdMiN-Adapter-1  ",
			Reason:          "preserve reason text",
			EvidencePointer: "  ipfs://Evidence/Audit-Canonical-Adapter-1  ",
			TimestampUnix:   4102444800,
		},
	})
	if err != nil {
		t.Fatalf("expected record audit action success, got %v", err)
	}
	if recordResp.GetAction() == nil {
		t.Fatal("expected action in record response")
	}
	if recordResp.GetAction().GetActionId() != "audit-canonical-adapter-1" {
		t.Fatalf("expected canonical action id %q, got %q", "audit-canonical-adapter-1", recordResp.GetAction().GetActionId())
	}
	if recordResp.GetAction().GetAction() != "admin_allow_validator" {
		t.Fatalf("expected canonical action %q, got %q", "admin_allow_validator", recordResp.GetAction().GetAction())
	}
	if recordResp.GetAction().GetActor() != "bootstrap-admin-adapter-1" {
		t.Fatalf("expected canonical actor %q, got %q", "bootstrap-admin-adapter-1", recordResp.GetAction().GetActor())
	}
	if recordResp.GetAction().GetEvidencePointer() != "ipfs://Evidence/Audit-Canonical-Adapter-1" {
		t.Fatalf("expected trimmed evidence pointer %q, got %q", "ipfs://Evidence/Audit-Canonical-Adapter-1", recordResp.GetAction().GetEvidencePointer())
	}
	if recordResp.GetConflict() {
		t.Fatal("expected conflict=false on first record audit action")
	}
	if recordResp.GetIdempotentReplay() {
		t.Fatal("expected idempotent_replay=false on first record audit action")
	}

	queryResp, err := queryAdapter.GovernanceAuditAction(context.Background(), &pb.QueryGovernanceAuditActionRequest{ActionId: "  AUDIT-CANONICAL-ADAPTER-1  "})
	if err != nil {
		t.Fatalf("expected audit query success, got %v", err)
	}
	if !queryResp.GetFound() {
		t.Fatal("expected found=true for mixed-case canonical audit query")
	}
	if queryResp.GetAction() == nil {
		t.Fatal("expected action in query response")
	}
	if queryResp.GetAction().GetActionId() != "audit-canonical-adapter-1" {
		t.Fatalf("expected canonical action id %q from query, got %q", "audit-canonical-adapter-1", queryResp.GetAction().GetActionId())
	}
}

func TestProtoMsgServerAdapterRecordAuditActionConflict(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewProtoMsgServerAdapter(&k)

	_, err := adapter.RecordAuditAction(context.Background(), &pb.MsgRecordAuditActionRequest{Action: &pb.GovernanceAuditAction{
		ActionId:        "audit-conflict-1",
		Action:          "admin_disable_validator",
		Actor:           "admin-1",
		Reason:          "reason-1",
		EvidencePointer: "ipfs://audit-conflict-1",
		TimestampUnix:   4102444800,
	}})
	if err != nil {
		t.Fatalf("seed record audit action failed: %v", err)
	}

	resp, err := adapter.RecordAuditAction(context.Background(), &pb.MsgRecordAuditActionRequest{Action: &pb.GovernanceAuditAction{
		ActionId:        "audit-conflict-1",
		Action:          "admin_disable_validator",
		Actor:           "admin-1",
		Reason:          "reason-2",
		EvidencePointer: "ipfs://audit-conflict-1",
		TimestampUnix:   4102444800,
	}})
	if err == nil {
		t.Fatal("expected audit action conflict error")
	}
	if !errors.Is(err, ErrAuditActionConflict) {
		t.Fatalf("expected ErrAuditActionConflict, got %v", err)
	}
	if !resp.GetConflict() {
		t.Fatal("expected conflict=true on conflicting audit action")
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

	auditResp, err := adapter.GovernanceAuditAction(context.Background(), &pb.QueryGovernanceAuditActionRequest{ActionId: "missing-audit"})
	if err != nil {
		t.Fatalf("expected nil error for missing audit lookup, got %v", err)
	}
	if auditResp.GetFound() {
		t.Fatal("expected found=false for missing audit action")
	}
}

func TestProtoQueryServerAdapterGetAndList(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-10", Title: "Policy Ten", Version: 10, ActivatedAtUnix: 4102444800, Status: chaintypes.ReconciliationPending})
	k.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-10", PolicyID: "policy-10", ProposalID: "proposal-10", Outcome: types.DecisionOutcomeReject, Decider: "council-10", DecidedAtUnix: 4102444800, Status: chaintypes.ReconciliationSubmitted})
	if _, err := k.RecordAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-10",
		Action:          "admin_allow_validator",
		Actor:           "admin-10",
		Reason:          "reason-10",
		EvidencePointer: "ipfs://audit-10",
		TimestampUnix:   4102444800,
	}); err != nil {
		t.Fatalf("expected seed audit action success, got %v", err)
	}

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

	auditResp, err := adapter.GovernanceAuditAction(context.Background(), &pb.QueryGovernanceAuditActionRequest{ActionId: "audit-10"})
	if err != nil {
		t.Fatalf("expected audit lookup success, got %v", err)
	}
	if !auditResp.GetFound() {
		t.Fatal("expected found=true for audit lookup")
	}
	if auditResp.GetAction().GetActionId() != "audit-10" {
		t.Fatalf("expected action_id audit-10, got %q", auditResp.GetAction().GetActionId())
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

	listAuditResp, err := adapter.ListGovernanceAuditActions(context.Background(), &pb.QueryListGovernanceAuditActionsRequest{})
	if err != nil {
		t.Fatalf("expected list audit actions success, got %v", err)
	}
	if len(listAuditResp.GetActions()) != 1 {
		t.Fatalf("expected 1 audit action, got %d", len(listAuditResp.GetActions()))
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

	_, recordAuditErr := msgAdapter.RecordAuditAction(context.Background(), nil)
	if !errors.Is(recordAuditErr, ErrInvalidAuditAction) {
		t.Fatalf("expected ErrInvalidAuditAction for nil audit request, got %v", recordAuditErr)
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

	auditResp, auditErr := queryAdapter.GovernanceAuditAction(context.Background(), nil)
	if auditErr != nil {
		t.Fatalf("expected nil error for nil audit query request, got %v", auditErr)
	}
	if auditResp.GetFound() {
		t.Fatal("expected found=false for nil audit query request")
	}
	if auditResp.GetAction() != nil {
		t.Fatal("expected nil audit action when found=false")
	}
}
