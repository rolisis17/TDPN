package types

import "testing"

func TestGovernancePolicyValidateBasic(t *testing.T) {
	t.Parallel()

	base := GovernancePolicy{
		PolicyID:        "policy-1",
		Title:           "Validator Eligibility Policy",
		Description:     "Bootstrap validator eligibility and voting rules",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	}

	tests := []struct {
		name    string
		record  GovernancePolicy
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing policy id",
			record:  GovernancePolicy{Title: base.Title, Version: base.Version, ActivatedAtUnix: base.ActivatedAtUnix},
			wantErr: "policy id is required",
		},
		{
			name:    "missing title",
			record:  GovernancePolicy{PolicyID: base.PolicyID, Version: base.Version, ActivatedAtUnix: base.ActivatedAtUnix},
			wantErr: "policy title is required",
		},
		{
			name:    "non-positive version",
			record:  GovernancePolicy{PolicyID: base.PolicyID, Title: base.Title, Version: 0, ActivatedAtUnix: base.ActivatedAtUnix},
			wantErr: "policy version must be positive",
		},
		{
			name:    "negative activated at",
			record:  GovernancePolicy{PolicyID: base.PolicyID, Title: base.Title, Version: base.Version, ActivatedAtUnix: -1},
			wantErr: "activated_at_unix cannot be negative",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.record.ValidateBasic()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}

func TestGovernanceDecisionValidateBasic(t *testing.T) {
	t.Parallel()

	base := GovernanceDecision{
		DecisionID:    "decision-1",
		PolicyID:      "policy-1",
		ProposalID:    "proposal-1",
		Outcome:       DecisionOutcomeApprove,
		Decider:       "council-multisig-1",
		Reason:        "bootstrap policy accepted",
		DecidedAtUnix: 4102444800,
	}

	tests := []struct {
		name    string
		record  GovernanceDecision
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing decision id",
			record:  GovernanceDecision{PolicyID: base.PolicyID, ProposalID: base.ProposalID, Outcome: base.Outcome, Decider: base.Decider, DecidedAtUnix: base.DecidedAtUnix},
			wantErr: "decision id is required",
		},
		{
			name:    "missing policy id",
			record:  GovernanceDecision{DecisionID: base.DecisionID, ProposalID: base.ProposalID, Outcome: base.Outcome, Decider: base.Decider, DecidedAtUnix: base.DecidedAtUnix},
			wantErr: "policy id is required",
		},
		{
			name:    "missing proposal id",
			record:  GovernanceDecision{DecisionID: base.DecisionID, PolicyID: base.PolicyID, Outcome: base.Outcome, Decider: base.Decider, DecidedAtUnix: base.DecidedAtUnix},
			wantErr: "proposal id is required",
		},
		{
			name:    "missing decider",
			record:  GovernanceDecision{DecisionID: base.DecisionID, PolicyID: base.PolicyID, ProposalID: base.ProposalID, Outcome: base.Outcome, DecidedAtUnix: base.DecidedAtUnix},
			wantErr: "decider is required",
		},
		{
			name:    "non-positive decided at",
			record:  GovernanceDecision{DecisionID: base.DecisionID, PolicyID: base.PolicyID, ProposalID: base.ProposalID, Outcome: base.Outcome, Decider: base.Decider, DecidedAtUnix: 0},
			wantErr: "decided_at_unix must be positive",
		},
		{
			name:    "invalid outcome",
			record:  GovernanceDecision{DecisionID: base.DecisionID, PolicyID: base.PolicyID, ProposalID: base.ProposalID, Outcome: "maybe", Decider: base.Decider, DecidedAtUnix: base.DecidedAtUnix},
			wantErr: "decision outcome must be approve, reject, or abstain",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.record.ValidateBasic()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}

func TestGovernanceAuditActionValidateBasic(t *testing.T) {
	t.Parallel()

	base := GovernanceAuditAction{
		ActionID:        "action-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "manual bootstrap allowlist",
		EvidencePointer: "ipfs://audit/action-1",
		TimestampUnix:   4102444800,
	}

	tests := []struct {
		name    string
		record  GovernanceAuditAction
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing action id",
			record:  GovernanceAuditAction{Action: base.Action, Actor: base.Actor, Reason: base.Reason, EvidencePointer: base.EvidencePointer, TimestampUnix: base.TimestampUnix},
			wantErr: "action id is required",
		},
		{
			name:    "missing action",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Actor: base.Actor, Reason: base.Reason, EvidencePointer: base.EvidencePointer, TimestampUnix: base.TimestampUnix},
			wantErr: "action is required",
		},
		{
			name:    "missing actor",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Action: base.Action, Reason: base.Reason, EvidencePointer: base.EvidencePointer, TimestampUnix: base.TimestampUnix},
			wantErr: "actor is required",
		},
		{
			name:    "missing reason",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Action: base.Action, Actor: base.Actor, EvidencePointer: base.EvidencePointer, TimestampUnix: base.TimestampUnix},
			wantErr: "reason is required",
		},
		{
			name:    "missing evidence pointer",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Action: base.Action, Actor: base.Actor, Reason: base.Reason, TimestampUnix: base.TimestampUnix},
			wantErr: "evidence pointer is required",
		},
		{
			name:    "non-positive timestamp",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Action: base.Action, Actor: base.Actor, Reason: base.Reason, EvidencePointer: base.EvidencePointer, TimestampUnix: 0},
			wantErr: "timestamp_unix must be positive",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.record.ValidateBasic()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}
