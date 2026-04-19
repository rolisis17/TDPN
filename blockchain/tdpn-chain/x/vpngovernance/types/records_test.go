package types

import (
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

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
			name:    "invalid action",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Action: "manual_review_only", Actor: base.Actor, Reason: base.Reason, EvidencePointer: base.EvidencePointer, TimestampUnix: base.TimestampUnix},
			wantErr: "action must be one of: admin_allow_validator, admin_disable_validator, admin_set_policy, admin_set_quorum, admin_rotate_key",
		},
		{
			name:    "legacy policy bootstrap alias",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Action: "policy.bootstrap", Actor: base.Actor, Reason: base.Reason, EvidencePointer: base.EvidencePointer, TimestampUnix: base.TimestampUnix},
			wantErr: "",
		},
		{
			name:    "legacy manual override alias",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Action: "manual_override", Actor: base.Actor, Reason: base.Reason, EvidencePointer: base.EvidencePointer, TimestampUnix: base.TimestampUnix},
			wantErr: "",
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
			name:    "invalid evidence pointer format",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Action: base.Action, Actor: base.Actor, Reason: base.Reason, EvidencePointer: "ftp://audit/action-1", TimestampUnix: base.TimestampUnix},
			wantErr: "evidence pointer must use objective format (sha256:<value>, obj://<value>, ipfs://<value>, or https://<value>)",
		},
		{
			name:    "evidence pointer too long",
			record:  GovernanceAuditAction{ActionID: base.ActionID, Action: base.Action, Actor: base.Actor, Reason: base.Reason, EvidencePointer: "ipfs://" + strings.Repeat("x", 1020), TimestampUnix: base.TimestampUnix},
			wantErr: "evidence pointer exceeds 1024 characters",
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

func TestGovernancePolicyCanonicalize(t *testing.T) {
	t.Parallel()

	record := GovernancePolicy{
		PolicyID:        "  PoLiCy-1  ",
		Title:           "  Keep Title Spacing  ",
		Description:     "  Keep Description Spacing  ",
		Version:         1,
		ActivatedAtUnix: 4102444800,
		Status:          " SuBmItTeD ",
	}

	got := record.Canonicalize()
	if got.PolicyID != "policy-1" {
		t.Fatalf("expected canonical policy id %q, got %q", "policy-1", got.PolicyID)
	}
	if got.Status != "submitted" {
		t.Fatalf("expected canonical status %q, got %q", "submitted", got.Status)
	}
	if got.Title != record.Title {
		t.Fatalf("expected title to be preserved, got %q vs %q", got.Title, record.Title)
	}
	if got.Description != record.Description {
		t.Fatalf("expected description to be preserved, got %q vs %q", got.Description, record.Description)
	}
}

func TestGovernanceDecisionCanonicalize(t *testing.T) {
	t.Parallel()

	record := GovernanceDecision{
		DecisionID:    "  DeCiSiOn-1  ",
		PolicyID:      "  PoLiCy-1  ",
		ProposalID:    "  PrOpOsAl-1  ",
		Outcome:       "  ApPrOvE  ",
		Decider:       "  CoUnCiL-MuLtIsIg  ",
		Reason:        "  Preserve Reason Spacing  ",
		DecidedAtUnix: 4102444800,
		Status:        " PeNdInG ",
	}

	got := record.Canonicalize()
	if got.DecisionID != "decision-1" {
		t.Fatalf("expected canonical decision id %q, got %q", "decision-1", got.DecisionID)
	}
	if got.PolicyID != "policy-1" {
		t.Fatalf("expected canonical policy id %q, got %q", "policy-1", got.PolicyID)
	}
	if got.ProposalID != "proposal-1" {
		t.Fatalf("expected canonical proposal id %q, got %q", "proposal-1", got.ProposalID)
	}
	if got.Outcome != DecisionOutcomeApprove {
		t.Fatalf("expected canonical outcome %q, got %q", DecisionOutcomeApprove, got.Outcome)
	}
	if got.Decider != "council-multisig" {
		t.Fatalf("expected canonical decider %q, got %q", "council-multisig", got.Decider)
	}
	if got.Status != "pending" {
		t.Fatalf("expected canonical status %q, got %q", "pending", got.Status)
	}
	if got.Reason != record.Reason {
		t.Fatalf("expected reason to be preserved, got %q vs %q", got.Reason, record.Reason)
	}
}

func TestGovernanceAuditActionCanonicalize(t *testing.T) {
	t.Parallel()

	record := GovernanceAuditAction{
		ActionID:        "  AuDiT-1  ",
		Action:          "  AdMiN_AlLoW_VaLiDaToR  ",
		Actor:           "  BoOtStRaP-AdMiN  ",
		Reason:          "  Preserve Reason Spacing  ",
		EvidencePointer: "  ipfs://Evidence/Audit-1  ",
		TimestampUnix:   4102444800,
	}

	got := record.Canonicalize()
	if got.ActionID != "audit-1" {
		t.Fatalf("expected canonical action id %q, got %q", "audit-1", got.ActionID)
	}
	if got.Action != "admin_allow_validator" {
		t.Fatalf("expected canonical action %q, got %q", "admin_allow_validator", got.Action)
	}
	if got.Actor != "bootstrap-admin" {
		t.Fatalf("expected canonical actor %q, got %q", "bootstrap-admin", got.Actor)
	}
	if got.EvidencePointer != "ipfs://Evidence/Audit-1" {
		t.Fatalf("expected evidence pointer trimming only, got %q", got.EvidencePointer)
	}
	if got.Reason != record.Reason {
		t.Fatalf("expected reason to be preserved, got %q vs %q", got.Reason, record.Reason)
	}
}

func TestCanonicalGovernanceAuditActionLegacyAliases(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "manual override underscore", in: "MANUAL_OVERRIDE", want: "admin_set_policy"},
		{name: "manual override hyphen", in: "manual-override", want: "admin_set_policy"},
		{name: "policy bootstrap dotted", in: "policy.bootstrap", want: "admin_set_policy"},
		{name: "policy bootstrap snake", in: "policy_bootstrap", want: "admin_set_policy"},
		{name: "already canonical", in: "admin_set_quorum", want: "admin_set_quorum"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := canonicalGovernanceAuditAction(tc.in); got != tc.want {
				t.Fatalf("canonicalGovernanceAuditAction(%q)=%q want=%q", tc.in, got, tc.want)
			}
		})
	}
}

func TestGovernanceCanonicalizeRetainsTerminalLifecycleStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   chaintypes.ReconciliationStatus
		want chaintypes.ReconciliationStatus
	}{
		{
			name: "confirmed",
			in:   " CONFIRMED ",
			want: chaintypes.ReconciliationConfirmed,
		},
		{
			name: "failed",
			in:   " FAILED ",
			want: chaintypes.ReconciliationFailed,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run("policy-"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := GovernancePolicy{
				PolicyID: "policy-terminal-1",
				Status:   tc.in,
			}.Canonicalize()
			if got.Status != tc.want {
				t.Fatalf("expected policy status %q, got %q", tc.want, got.Status)
			}
		})

		t.Run("decision-"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := GovernanceDecision{
				DecisionID: "decision-terminal-1",
				PolicyID:   "policy-terminal-1",
				ProposalID: "proposal-terminal-1",
				Outcome:    DecisionOutcomeApprove,
				Decider:    "bootstrap-council",
				Status:     tc.in,
			}.Canonicalize()
			if got.Status != tc.want {
				t.Fatalf("expected decision status %q, got %q", tc.want, got.Status)
			}
		})
	}
}
