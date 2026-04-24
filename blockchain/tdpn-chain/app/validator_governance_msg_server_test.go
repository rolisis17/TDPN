package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	governancetypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
	validatortypes "github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestValidatorMsgServer_AccessorAndFlow(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.ValidatorMsgServer()

	eligibility := validatortypes.ValidatorEligibility{
		ValidatorID:     "val-msg-1",
		OperatorAddress: "op-msg-1",
		Eligible:        true,
		PolicyReason:    "bootstrap policy",
	}
	eligibilityResp, err := server.SetEligibility(context.Background(), ValidatorSetEligibilityRequest{Record: eligibility})
	if err != nil {
		t.Fatalf("expected set eligibility success, got %v", err)
	}
	if eligibilityResp.Replay {
		t.Fatal("expected first eligibility set to not be replay")
	}
	if eligibilityResp.Eligibility.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected eligibility status %q, got %q", chaintypes.ReconciliationPending, eligibilityResp.Eligibility.Status)
	}

	status := validatortypes.ValidatorStatusRecord{
		StatusID:        "status-msg-1",
		ValidatorID:     eligibility.ValidatorID,
		LifecycleStatus: validatortypes.ValidatorLifecycleActive,
		EvidenceHeight:  100,
		EvidenceRef:     "obj://validator/status-msg-1",
	}
	statusResp, err := server.RecordStatus(context.Background(), ValidatorRecordStatusRequest{Record: status})
	if err != nil {
		t.Fatalf("expected record status success, got %v", err)
	}
	if statusResp.Replay {
		t.Fatal("expected first status record to not be replay")
	}
	if statusResp.Status.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected status record status %q, got %q", chaintypes.ReconciliationSubmitted, statusResp.Status.Status)
	}

	replayResp, err := server.RecordStatus(context.Background(), ValidatorRecordStatusRequest{Record: status})
	if err != nil {
		t.Fatalf("expected replay status record success, got %v", err)
	}
	if !replayResp.Replay {
		t.Fatal("expected replay=true for duplicate status record")
	}
}

func TestValidatorMsgServer_MissingEligibility(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.ValidatorMsgServer()

	_, err := server.RecordStatus(context.Background(), ValidatorRecordStatusRequest{
		Record: validatortypes.ValidatorStatusRecord{
			StatusID:        "status-missing-eligibility",
			ValidatorID:     "missing-validator",
			LifecycleStatus: validatortypes.ValidatorLifecycleActive,
			EvidenceHeight:  1,
			EvidenceRef:     "obj://validator/missing",
		},
	})
	if err == nil {
		t.Fatal("expected missing validator eligibility error")
	}
	if !strings.Contains(err.Error(), "eligibility not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatorMsgServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.ValidatorMsgServer()

	_, err := server.SetEligibility(context.Background(), ValidatorSetEligibilityRequest{
		Record: validatortypes.ValidatorEligibility{
			ValidatorID:     "val-msg-nil",
			OperatorAddress: "op-msg-nil",
		},
	})
	if err == nil {
		t.Fatal("expected nil scaffold validator msg server error")
	}
	if !strings.Contains(err.Error(), "vpnvalidator keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidatorMsgServer_SetEligibilityHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.ValidatorMsgServer()

	eligibility := validatortypes.ValidatorEligibility{
		ValidatorID:     "val-msg-canceled-ctx-1",
		OperatorAddress: "op-msg-canceled-ctx-1",
		Eligible:        true,
		PolicyReason:    "bootstrap policy",
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.SetEligibility(canceledCtx, ValidatorSetEligibilityRequest{Record: eligibility}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.ValidatorModule.Keeper.GetEligibility(eligibility.ValidatorID); exists {
		t.Fatalf("expected no eligibility write on canceled context for validator %s", eligibility.ValidatorID)
	}
}

func TestValidatorMsgServer_RecordStatusHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.ValidatorMsgServer()

	eligibility := validatortypes.ValidatorEligibility{
		ValidatorID:     "val-msg-canceled-ctx-2",
		OperatorAddress: "op-msg-canceled-ctx-2",
		Eligible:        true,
		PolicyReason:    "bootstrap policy",
	}
	if _, err := server.SetEligibility(context.Background(), ValidatorSetEligibilityRequest{Record: eligibility}); err != nil {
		t.Fatalf("expected set eligibility success, got %v", err)
	}

	status := validatortypes.ValidatorStatusRecord{
		StatusID:        "status-msg-canceled-ctx-2",
		ValidatorID:     eligibility.ValidatorID,
		LifecycleStatus: validatortypes.ValidatorLifecycleActive,
		EvidenceHeight:  10,
		EvidenceRef:     "obj://validator/status-msg-canceled-ctx-2",
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.RecordStatus(canceledCtx, ValidatorRecordStatusRequest{Record: status}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.ValidatorModule.Keeper.GetStatusRecord(status.StatusID); exists {
		t.Fatalf("expected no status write on canceled context for status %s", status.StatusID)
	}
}

func TestGovernanceMsgServer_AccessorAndFlow(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.GovernanceMsgServer()

	policy := governancetypes.GovernancePolicy{
		PolicyID:        "policy-msg-1",
		Title:           "bootstrap policy",
		Description:     "phase 6 governance policy",
		Version:         1,
		ActivatedAtUnix: 1735689600,
	}
	policyResp, err := server.CreatePolicy(context.Background(), GovernanceCreatePolicyRequest{Record: policy})
	if err != nil {
		t.Fatalf("expected create policy success, got %v", err)
	}
	if policyResp.Replay {
		t.Fatal("expected first policy create to not be replay")
	}
	if policyResp.Policy.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected policy status %q, got %q", chaintypes.ReconciliationPending, policyResp.Policy.Status)
	}

	decision := governancetypes.GovernanceDecision{
		DecisionID:    "decision-msg-1",
		PolicyID:      policy.PolicyID,
		ProposalID:    "proposal-msg-1",
		Outcome:       governancetypes.DecisionOutcomeApprove,
		Decider:       "governance-council",
		Reason:        "objective threshold met",
		DecidedAtUnix: 1735689700,
	}
	decisionResp, err := server.RecordDecision(context.Background(), GovernanceRecordDecisionRequest{Record: decision})
	if err != nil {
		t.Fatalf("expected record decision success, got %v", err)
	}
	if decisionResp.Replay {
		t.Fatal("expected first decision record to not be replay")
	}
	if decisionResp.Decision.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected decision status %q, got %q", chaintypes.ReconciliationPending, decisionResp.Decision.Status)
	}

	action := governancetypes.GovernanceAuditAction{
		ActionID:        "action-msg-1",
		Action:          "admin_set_policy",
		Actor:           "bootstrap-multisig",
		Reason:          "emergency rollback",
		EvidencePointer: "obj://audit/action-msg-1",
		TimestampUnix:   1735689800,
	}
	actionResp, err := server.RecordAuditAction(context.Background(), GovernanceRecordAuditActionRequest{Record: action})
	if err != nil {
		t.Fatalf("expected record audit action success, got %v", err)
	}
	if actionResp.Replay {
		t.Fatal("expected first audit action record to not be replay")
	}

	replayResp, err := server.RecordAuditAction(context.Background(), GovernanceRecordAuditActionRequest{Record: action})
	if err != nil {
		t.Fatalf("expected replay audit action record success, got %v", err)
	}
	if !replayResp.Replay {
		t.Fatal("expected replay=true for duplicate audit action")
	}
}

func TestGovernanceMsgServer_MissingPolicy(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.GovernanceMsgServer()

	_, err := server.RecordDecision(context.Background(), GovernanceRecordDecisionRequest{
		Record: governancetypes.GovernanceDecision{
			DecisionID:    "decision-missing-policy",
			PolicyID:      "missing-policy",
			ProposalID:    "proposal-missing-policy",
			Outcome:       governancetypes.DecisionOutcomeReject,
			Decider:       "governance-council",
			Reason:        "policy missing",
			DecidedAtUnix: 1735689700,
		},
	})
	if err == nil {
		t.Fatal("expected missing policy error")
	}
	if !strings.Contains(err.Error(), "policy not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGovernanceMsgServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.GovernanceMsgServer()

	_, err := server.CreatePolicy(context.Background(), GovernanceCreatePolicyRequest{
		Record: governancetypes.GovernancePolicy{
			PolicyID:        "policy-msg-nil",
			Title:           "bootstrap policy",
			Version:         1,
			ActivatedAtUnix: 1735689600,
		},
	})
	if err == nil {
		t.Fatal("expected nil scaffold governance msg server error")
	}
	if !strings.Contains(err.Error(), "vpngovernance keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGovernanceMsgServer_CreatePolicyHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.GovernanceMsgServer()

	policy := governancetypes.GovernancePolicy{
		PolicyID:        "policy-msg-canceled-ctx-1",
		Title:           "bootstrap policy",
		Description:     "phase 6 governance policy",
		Version:         1,
		ActivatedAtUnix: 1735689600,
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.CreatePolicy(canceledCtx, GovernanceCreatePolicyRequest{Record: policy}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.GovernanceModule.Keeper.GetPolicy(policy.PolicyID); exists {
		t.Fatalf("expected no policy write on canceled context for policy %s", policy.PolicyID)
	}
}

func TestGovernanceMsgServer_RecordDecisionHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.GovernanceMsgServer()

	policy := governancetypes.GovernancePolicy{
		PolicyID:        "policy-msg-canceled-ctx-2",
		Title:           "bootstrap policy",
		Description:     "phase 6 governance policy",
		Version:         1,
		ActivatedAtUnix: 1735689600,
	}
	if _, err := server.CreatePolicy(context.Background(), GovernanceCreatePolicyRequest{Record: policy}); err != nil {
		t.Fatalf("expected create policy success, got %v", err)
	}

	decision := governancetypes.GovernanceDecision{
		DecisionID:    "decision-msg-canceled-ctx-2",
		PolicyID:      policy.PolicyID,
		ProposalID:    "proposal-msg-canceled-ctx-2",
		Outcome:       governancetypes.DecisionOutcomeApprove,
		Decider:       "governance-council",
		Reason:        "objective threshold met",
		DecidedAtUnix: 1735689700,
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.RecordDecision(canceledCtx, GovernanceRecordDecisionRequest{Record: decision}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.GovernanceModule.Keeper.GetDecision(decision.DecisionID); exists {
		t.Fatalf("expected no decision write on canceled context for decision %s", decision.DecisionID)
	}
}

func TestGovernanceMsgServer_RecordAuditActionHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.GovernanceMsgServer()

	action := governancetypes.GovernanceAuditAction{
		ActionID:        "action-msg-canceled-ctx-3",
		Action:          "admin_set_policy",
		Actor:           "bootstrap-multisig",
		Reason:          "emergency rollback",
		EvidencePointer: "obj://audit/action-msg-canceled-ctx-3",
		TimestampUnix:   1735689800,
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.RecordAuditAction(canceledCtx, GovernanceRecordAuditActionRequest{Record: action}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.GovernanceModule.Keeper.GetAuditAction(action.ActionID); exists {
		t.Fatalf("expected no audit action write on canceled context for action %s", action.ActionID)
	}
}
