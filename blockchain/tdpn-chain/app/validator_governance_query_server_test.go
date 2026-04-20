package app

import (
	"context"
	"strings"
	"testing"

	governancemodule "github.com/tdpn/tdpn-chain/x/vpngovernance/module"
	governancetypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
	validatormodule "github.com/tdpn/tdpn-chain/x/vpnvalidator/module"
	validatortypes "github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestValidatorQueryServer_AccessorHappyPathAndNotFound(t *testing.T) {
	scaffold := NewChainScaffold()
	queryServer := scaffold.ValidatorQueryServer()
	msgServer := validatormodule.NewMsgServer(scaffold.ValidatorModule.Keeper)

	missingEligibility, err := queryServer.GetEligibility(context.Background(), ValidatorGetEligibilityRequest{
		ValidatorID: "missing-validator",
	})
	if err != nil {
		t.Fatalf("expected missing validator eligibility query to succeed, got %v", err)
	}
	if missingEligibility.Found {
		t.Fatal("expected missing validator eligibility query to return found=false")
	}

	eligibility := validatortypes.ValidatorEligibility{
		ValidatorID:     "val-query-1",
		OperatorAddress: "op-query-1",
		Eligible:        true,
		PolicyReason:    "bootstrap policy",
	}
	if _, err := msgServer.SetValidatorEligibility(validatormodule.SetValidatorEligibilityRequest{Eligibility: eligibility}); err != nil {
		t.Fatalf("expected set validator eligibility to succeed, got %v", err)
	}

	foundEligibility, err := queryServer.GetEligibility(context.Background(), ValidatorGetEligibilityRequest{
		ValidatorID: eligibility.ValidatorID,
	})
	if err != nil {
		t.Fatalf("expected validator eligibility query to succeed, got %v", err)
	}
	if !foundEligibility.Found {
		t.Fatal("expected validator eligibility query to return found=true")
	}
	if foundEligibility.Eligibility.ValidatorID != eligibility.ValidatorID {
		t.Fatalf("expected validator id %q, got %q", eligibility.ValidatorID, foundEligibility.Eligibility.ValidatorID)
	}

	missingStatus, err := queryServer.GetStatusRecord(context.Background(), ValidatorGetStatusRecordRequest{
		StatusID: "missing-status",
	})
	if err != nil {
		t.Fatalf("expected missing validator status query to succeed, got %v", err)
	}
	if missingStatus.Found {
		t.Fatal("expected missing validator status query to return found=false")
	}

	status := validatortypes.ValidatorStatusRecord{
		StatusID:        "status-query-1",
		ValidatorID:     eligibility.ValidatorID,
		LifecycleStatus: validatortypes.ValidatorLifecycleActive,
		EvidenceHeight:  10,
		EvidenceRef:     "sha256:ce1ad56555311a8b138899bc99700d80aa1b55950daeab84a859a0c9f5fca6db",
	}
	if _, err := msgServer.RecordValidatorStatus(validatormodule.RecordValidatorStatusRequest{Record: status}); err != nil {
		t.Fatalf("expected record validator status to succeed, got %v", err)
	}

	foundStatus, err := queryServer.GetStatusRecord(context.Background(), ValidatorGetStatusRecordRequest{
		StatusID: status.StatusID,
	})
	if err != nil {
		t.Fatalf("expected validator status query to succeed, got %v", err)
	}
	if !foundStatus.Found {
		t.Fatal("expected validator status query to return found=true")
	}
	if foundStatus.Record.StatusID != status.StatusID {
		t.Fatalf("expected status id %q, got %q", status.StatusID, foundStatus.Record.StatusID)
	}

	anotherEligibility := validatortypes.ValidatorEligibility{
		ValidatorID:     "val-query-0",
		OperatorAddress: "op-query-0",
		Eligible:        false,
		PolicyReason:    "manual review",
	}
	if _, err := msgServer.SetValidatorEligibility(validatormodule.SetValidatorEligibilityRequest{Eligibility: anotherEligibility}); err != nil {
		t.Fatalf("expected set second validator eligibility to succeed, got %v", err)
	}

	anotherStatus := validatortypes.ValidatorStatusRecord{
		StatusID:        "status-query-0",
		ValidatorID:     anotherEligibility.ValidatorID,
		LifecycleStatus: validatortypes.ValidatorLifecycleJailed,
		EvidenceHeight:  20,
		EvidenceRef:     "obj://status-query-0",
	}
	if _, err := msgServer.RecordValidatorStatus(validatormodule.RecordValidatorStatusRequest{Record: anotherStatus}); err != nil {
		t.Fatalf("expected record second validator status to succeed, got %v", err)
	}

	eligibilityList, err := queryServer.ListEligibilities(context.Background(), ValidatorListEligibilitiesRequest{})
	if err != nil {
		t.Fatalf("expected validator eligibility list query to succeed, got %v", err)
	}
	if len(eligibilityList.Eligibilities) != 2 {
		t.Fatalf("expected 2 validator eligibilities, got %d", len(eligibilityList.Eligibilities))
	}
	if eligibilityList.Eligibilities[0].ValidatorID != "val-query-0" || eligibilityList.Eligibilities[1].ValidatorID != "val-query-1" {
		t.Fatalf("expected sorted validator ids [val-query-0 val-query-1], got [%s %s]",
			eligibilityList.Eligibilities[0].ValidatorID, eligibilityList.Eligibilities[1].ValidatorID)
	}

	statusList, err := queryServer.ListStatusRecords(context.Background(), ValidatorListStatusRecordsRequest{})
	if err != nil {
		t.Fatalf("expected validator status list query to succeed, got %v", err)
	}
	if len(statusList.Records) != 2 {
		t.Fatalf("expected 2 validator status records, got %d", len(statusList.Records))
	}
	if statusList.Records[0].StatusID != "status-query-0" || statusList.Records[1].StatusID != "status-query-1" {
		t.Fatalf("expected sorted status ids [status-query-0 status-query-1], got [%s %s]",
			statusList.Records[0].StatusID, statusList.Records[1].StatusID)
	}
}

func TestValidatorQueryServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.ValidatorQueryServer()

	_, err := server.GetEligibility(context.Background(), ValidatorGetEligibilityRequest{ValidatorID: "val-1"})
	if err == nil {
		t.Fatal("expected nil scaffold validator eligibility query to fail")
	}
	if !strings.Contains(err.Error(), "vpnvalidator keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.GetStatusRecord(context.Background(), ValidatorGetStatusRecordRequest{StatusID: "status-1"})
	if err == nil {
		t.Fatal("expected nil scaffold validator status query to fail")
	}
	if !strings.Contains(err.Error(), "vpnvalidator keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListEligibilities(context.Background(), ValidatorListEligibilitiesRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold validator eligibility list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnvalidator keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListStatusRecords(context.Background(), ValidatorListStatusRecordsRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold validator status list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnvalidator keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGovernanceQueryServer_AccessorHappyPathAndNotFound(t *testing.T) {
	scaffold := NewChainScaffold()
	queryServer := scaffold.GovernanceQueryServer()
	msgServer := governancemodule.NewMsgServer(scaffold.GovernanceModule.Keeper)

	missingPolicy, err := queryServer.GetPolicy(context.Background(), GovernanceGetPolicyRequest{
		PolicyID: "missing-policy",
	})
	if err != nil {
		t.Fatalf("expected missing governance policy query to succeed, got %v", err)
	}
	if missingPolicy.Found {
		t.Fatal("expected missing governance policy query to return found=false")
	}

	policy := governancetypes.GovernancePolicy{
		PolicyID:        "policy-query-1",
		Title:           "bootstrap-policy",
		Description:     "phase 6 governance policy",
		Version:         1,
		ActivatedAtUnix: 1735689600,
	}
	if _, err := msgServer.CreatePolicy(governancemodule.CreatePolicyRequest{Policy: policy}); err != nil {
		t.Fatalf("expected create policy to succeed, got %v", err)
	}

	foundPolicy, err := queryServer.GetPolicy(context.Background(), GovernanceGetPolicyRequest{
		PolicyID: policy.PolicyID,
	})
	if err != nil {
		t.Fatalf("expected policy query to succeed, got %v", err)
	}
	if !foundPolicy.Found {
		t.Fatal("expected policy query to return found=true")
	}
	if foundPolicy.Policy.PolicyID != policy.PolicyID {
		t.Fatalf("expected policy id %q, got %q", policy.PolicyID, foundPolicy.Policy.PolicyID)
	}

	missingDecision, err := queryServer.GetDecision(context.Background(), GovernanceGetDecisionRequest{
		DecisionID: "missing-decision",
	})
	if err != nil {
		t.Fatalf("expected missing governance decision query to succeed, got %v", err)
	}
	if missingDecision.Found {
		t.Fatal("expected missing governance decision query to return found=false")
	}

	decision := governancetypes.GovernanceDecision{
		DecisionID:    "decision-query-1",
		PolicyID:      policy.PolicyID,
		ProposalID:    "proposal-query-1",
		Outcome:       governancetypes.DecisionOutcomeApprove,
		Decider:       "governance-council",
		Reason:        "objective thresholds met",
		DecidedAtUnix: 1735689700,
	}
	if _, err := msgServer.RecordDecision(governancemodule.RecordDecisionRequest{Decision: decision}); err != nil {
		t.Fatalf("expected record decision to succeed, got %v", err)
	}

	foundDecision, err := queryServer.GetDecision(context.Background(), GovernanceGetDecisionRequest{
		DecisionID: decision.DecisionID,
	})
	if err != nil {
		t.Fatalf("expected decision query to succeed, got %v", err)
	}
	if !foundDecision.Found {
		t.Fatal("expected decision query to return found=true")
	}
	if foundDecision.Decision.DecisionID != decision.DecisionID {
		t.Fatalf("expected decision id %q, got %q", decision.DecisionID, foundDecision.Decision.DecisionID)
	}

	missingAction, err := queryServer.GetAuditAction(context.Background(), GovernanceGetAuditActionRequest{
		ActionID: "missing-action",
	})
	if err != nil {
		t.Fatalf("expected missing governance audit action query to succeed, got %v", err)
	}
	if missingAction.Found {
		t.Fatal("expected missing governance audit action query to return found=false")
	}

	action := governancetypes.GovernanceAuditAction{
		ActionID:        "action-query-1",
		Action:          "admin_set_policy",
		Actor:           "bootstrap-multisig",
		Reason:          "emergency rollback",
		EvidencePointer: "obj://audit/action-query-1",
		TimestampUnix:   1735689800,
	}
	if _, err := msgServer.RecordAuditAction(governancemodule.RecordAuditActionRequest{Action: action}); err != nil {
		t.Fatalf("expected record audit action to succeed, got %v", err)
	}

	foundAction, err := queryServer.GetAuditAction(context.Background(), GovernanceGetAuditActionRequest{
		ActionID: action.ActionID,
	})
	if err != nil {
		t.Fatalf("expected audit action query to succeed, got %v", err)
	}
	if !foundAction.Found {
		t.Fatal("expected audit action query to return found=true")
	}
	if foundAction.Action.ActionID != action.ActionID {
		t.Fatalf("expected action id %q, got %q", action.ActionID, foundAction.Action.ActionID)
	}

	anotherPolicy := governancetypes.GovernancePolicy{
		PolicyID:        "policy-query-0",
		Title:           "bootstrap-policy-0",
		Description:     "phase 6 governance policy baseline",
		Version:         1,
		ActivatedAtUnix: 1735689500,
	}
	if _, err := msgServer.CreatePolicy(governancemodule.CreatePolicyRequest{Policy: anotherPolicy}); err != nil {
		t.Fatalf("expected create second policy to succeed, got %v", err)
	}

	anotherDecision := governancetypes.GovernanceDecision{
		DecisionID:    "decision-query-0",
		PolicyID:      anotherPolicy.PolicyID,
		ProposalID:    "proposal-query-0",
		Outcome:       governancetypes.DecisionOutcomeReject,
		Decider:       "governance-council",
		Reason:        "insufficient objective evidence",
		DecidedAtUnix: 1735689601,
	}
	if _, err := msgServer.RecordDecision(governancemodule.RecordDecisionRequest{Decision: anotherDecision}); err != nil {
		t.Fatalf("expected record second decision to succeed, got %v", err)
	}

	anotherAction := governancetypes.GovernanceAuditAction{
		ActionID:        "action-query-0",
		Action:          "policy.bootstrap",
		Actor:           "bootstrap-multisig",
		Reason:          "initialization",
		EvidencePointer: "obj://audit/action-query-0",
		TimestampUnix:   1735689602,
	}
	if _, err := msgServer.RecordAuditAction(governancemodule.RecordAuditActionRequest{Action: anotherAction}); err != nil {
		t.Fatalf("expected record second audit action to succeed, got %v", err)
	}

	policyList, err := queryServer.ListPolicies(context.Background(), GovernanceListPoliciesRequest{})
	if err != nil {
		t.Fatalf("expected governance policy list query to succeed, got %v", err)
	}
	if len(policyList.Policies) != 2 {
		t.Fatalf("expected 2 governance policies, got %d", len(policyList.Policies))
	}
	if policyList.Policies[0].PolicyID != "policy-query-0" || policyList.Policies[1].PolicyID != "policy-query-1" {
		t.Fatalf("expected sorted policy ids [policy-query-0 policy-query-1], got [%s %s]",
			policyList.Policies[0].PolicyID, policyList.Policies[1].PolicyID)
	}

	decisionList, err := queryServer.ListDecisions(context.Background(), GovernanceListDecisionsRequest{})
	if err != nil {
		t.Fatalf("expected governance decision list query to succeed, got %v", err)
	}
	if len(decisionList.Decisions) != 2 {
		t.Fatalf("expected 2 governance decisions, got %d", len(decisionList.Decisions))
	}
	if decisionList.Decisions[0].DecisionID != "decision-query-0" || decisionList.Decisions[1].DecisionID != "decision-query-1" {
		t.Fatalf("expected sorted decision ids [decision-query-0 decision-query-1], got [%s %s]",
			decisionList.Decisions[0].DecisionID, decisionList.Decisions[1].DecisionID)
	}

	actionList, err := queryServer.ListAuditActions(context.Background(), GovernanceListAuditActionsRequest{})
	if err != nil {
		t.Fatalf("expected governance audit-action list query to succeed, got %v", err)
	}
	if len(actionList.Actions) != 2 {
		t.Fatalf("expected 2 governance audit actions, got %d", len(actionList.Actions))
	}
	if actionList.Actions[0].ActionID != "action-query-0" || actionList.Actions[1].ActionID != "action-query-1" {
		t.Fatalf("expected sorted action ids [action-query-0 action-query-1], got [%s %s]",
			actionList.Actions[0].ActionID, actionList.Actions[1].ActionID)
	}
}

func TestGovernanceQueryServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.GovernanceQueryServer()

	_, err := server.GetPolicy(context.Background(), GovernanceGetPolicyRequest{PolicyID: "policy-1"})
	if err == nil {
		t.Fatal("expected nil scaffold governance policy query to fail")
	}
	if !strings.Contains(err.Error(), "vpngovernance keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.GetDecision(context.Background(), GovernanceGetDecisionRequest{DecisionID: "decision-1"})
	if err == nil {
		t.Fatal("expected nil scaffold governance decision query to fail")
	}
	if !strings.Contains(err.Error(), "vpngovernance keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.GetAuditAction(context.Background(), GovernanceGetAuditActionRequest{ActionID: "action-1"})
	if err == nil {
		t.Fatal("expected nil scaffold governance audit action query to fail")
	}
	if !strings.Contains(err.Error(), "vpngovernance keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListPolicies(context.Background(), GovernanceListPoliciesRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold governance policy list query to fail")
	}
	if !strings.Contains(err.Error(), "vpngovernance keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListDecisions(context.Background(), GovernanceListDecisionsRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold governance decision list query to fail")
	}
	if !strings.Contains(err.Error(), "vpngovernance keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListAuditActions(context.Background(), GovernanceListAuditActionsRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold governance audit-action list query to fail")
	}
	if !strings.Contains(err.Error(), "vpngovernance keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}
