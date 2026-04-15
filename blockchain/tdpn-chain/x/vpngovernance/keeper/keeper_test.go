package keeper

import (
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

func TestKeeperPolicyUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetPolicy("missing"); ok {
		t.Fatal("expected missing policy lookup to return ok=false")
	}

	initial := types.GovernancePolicy{
		PolicyID:        "policy-1",
		Title:           "Policy One",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	}
	k.UpsertPolicy(initial)

	got, ok := k.GetPolicy(initial.PolicyID)
	if !ok {
		t.Fatal("expected inserted policy to be found")
	}
	if got.Version != initial.Version {
		t.Fatalf("expected version %d, got %d", initial.Version, got.Version)
	}

	updated := initial
	updated.Version = 2
	k.UpsertPolicy(updated)

	got, ok = k.GetPolicy(initial.PolicyID)
	if !ok {
		t.Fatal("expected updated policy to be found")
	}
	if got.Version != updated.Version {
		t.Fatalf("expected updated version %d, got %d", updated.Version, got.Version)
	}
}

func TestKeeperDecisionUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetDecision("missing"); ok {
		t.Fatal("expected missing decision lookup to return ok=false")
	}

	initial := types.GovernanceDecision{
		DecisionID:    "decision-1",
		PolicyID:      "policy-1",
		ProposalID:    "proposal-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "multisig-1",
		DecidedAtUnix: 4102444800,
	}
	k.UpsertDecision(initial)

	got, ok := k.GetDecision(initial.DecisionID)
	if !ok {
		t.Fatal("expected inserted decision to be found")
	}
	if got.Outcome != initial.Outcome {
		t.Fatalf("expected outcome %q, got %q", initial.Outcome, got.Outcome)
	}

	updated := initial
	updated.Outcome = types.DecisionOutcomeReject
	k.UpsertDecision(updated)

	got, ok = k.GetDecision(initial.DecisionID)
	if !ok {
		t.Fatal("expected updated decision to be found")
	}
	if got.Outcome != updated.Outcome {
		t.Fatalf("expected updated outcome %q, got %q", updated.Outcome, got.Outcome)
	}
}

func TestKeeperCreatePolicyDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	input := types.GovernancePolicy{
		PolicyID:        "policy-1",
		Title:           "Policy One",
		Description:     "validator eligibility baseline",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	}

	created, err := k.CreatePolicy(input)
	if err != nil {
		t.Fatalf("CreatePolicy returned unexpected error: %v", err)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, created.Status)
	}

	idempotent, err := k.CreatePolicy(input)
	if err != nil {
		t.Fatalf("CreatePolicy idempotent replay returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent replay to return created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperCreatePolicyConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	initial := types.GovernancePolicy{
		PolicyID:        "policy-1",
		Title:           "Policy One",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	}
	if _, err := k.CreatePolicy(initial); err != nil {
		t.Fatalf("seed CreatePolicy failed: %v", err)
	}

	conflict := initial
	conflict.Title = "Policy One Updated"
	_, err := k.CreatePolicy(conflict)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error details, got %v", err)
	}
}

func TestKeeperCreatePolicyValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.CreatePolicy(types.GovernancePolicy{
		PolicyID:        "policy-1",
		Title:           "",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	})
	if err == nil {
		t.Fatal("expected validation error for missing title")
	}
}

func TestKeeperRecordDecisionDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreatePolicy(types.GovernancePolicy{
		PolicyID:        "policy-1",
		Title:           "Policy One",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	}); err != nil {
		t.Fatalf("CreatePolicy returned unexpected error: %v", err)
	}

	input := types.GovernanceDecision{
		DecisionID:    "decision-1",
		PolicyID:      "policy-1",
		ProposalID:    "proposal-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-1",
		Reason:        "bootstrap approved",
		DecidedAtUnix: 4102444800,
	}

	created, err := k.RecordDecision(input)
	if err != nil {
		t.Fatalf("RecordDecision returned unexpected error: %v", err)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, created.Status)
	}

	idempotent, err := k.RecordDecision(input)
	if err != nil {
		t.Fatalf("RecordDecision idempotent replay returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent replay to return created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperRecordDecisionConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreatePolicy(types.GovernancePolicy{
		PolicyID:        "policy-1",
		Title:           "Policy One",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	}); err != nil {
		t.Fatalf("CreatePolicy returned unexpected error: %v", err)
	}

	initial := types.GovernanceDecision{
		DecisionID:    "decision-1",
		PolicyID:      "policy-1",
		ProposalID:    "proposal-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-1",
		DecidedAtUnix: 4102444800,
	}
	if _, err := k.RecordDecision(initial); err != nil {
		t.Fatalf("seed RecordDecision failed: %v", err)
	}

	conflict := initial
	conflict.Outcome = types.DecisionOutcomeReject
	_, err := k.RecordDecision(conflict)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error details, got %v", err)
	}
}

func TestKeeperRecordDecisionValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.RecordDecision(types.GovernanceDecision{
		DecisionID:    "decision-1",
		PolicyID:      "policy-1",
		ProposalID:    "proposal-1",
		Outcome:       "invalid",
		Decider:       "council-1",
		DecidedAtUnix: 4102444800,
	})
	if err == nil {
		t.Fatal("expected validation error for invalid outcome")
	}
}

func TestKeeperRecordDecisionMissingPolicy(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.RecordDecision(types.GovernanceDecision{
		DecisionID:    "decision-1",
		PolicyID:      "missing-policy",
		ProposalID:    "proposal-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-1",
		DecidedAtUnix: 4102444800,
	})
	if err == nil {
		t.Fatal("expected missing policy error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing policy details, got %v", err)
	}
}

func TestKeeperListPoliciesDeterministicByPolicyID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-3", Title: "Policy 3", Version: 1, ActivatedAtUnix: 1})
	k.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy 1", Version: 1, ActivatedAtUnix: 1})
	k.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-2", Title: "Policy 2", Version: 1, ActivatedAtUnix: 1})

	list := k.ListPolicies()
	if len(list) != 3 {
		t.Fatalf("expected 3 policies, got %d", len(list))
	}
	if list[0].PolicyID != "policy-1" || list[1].PolicyID != "policy-2" || list[2].PolicyID != "policy-3" {
		t.Fatalf("expected sorted policy ids [policy-1 policy-2 policy-3], got [%s %s %s]", list[0].PolicyID, list[1].PolicyID, list[2].PolicyID)
	}
}

func TestKeeperListDecisionsDeterministicByDecisionID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-3", PolicyID: "policy-1", ProposalID: "proposal-3", Outcome: types.DecisionOutcomeApprove, Decider: "d-1", DecidedAtUnix: 3})
	k.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-1", PolicyID: "policy-1", ProposalID: "proposal-1", Outcome: types.DecisionOutcomeApprove, Decider: "d-1", DecidedAtUnix: 1})
	k.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-2", PolicyID: "policy-1", ProposalID: "proposal-2", Outcome: types.DecisionOutcomeReject, Decider: "d-2", DecidedAtUnix: 2})

	list := k.ListDecisions()
	if len(list) != 3 {
		t.Fatalf("expected 3 decisions, got %d", len(list))
	}
	if list[0].DecisionID != "decision-1" || list[1].DecisionID != "decision-2" || list[2].DecisionID != "decision-3" {
		t.Fatalf("expected sorted decision ids [decision-1 decision-2 decision-3], got [%s %s %s]", list[0].DecisionID, list[1].DecisionID, list[2].DecisionID)
	}
}

func TestKeeperRecordAuditActionDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	input := types.GovernanceAuditAction{
		ActionID:        "audit-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "bootstrap allowlist update",
		EvidencePointer: "ipfs://evidence/audit-1",
		TimestampUnix:   4102444800,
	}

	created, err := k.RecordAuditAction(input)
	if err != nil {
		t.Fatalf("RecordAuditAction returned unexpected error: %v", err)
	}
	if created.ActionID != input.ActionID {
		t.Fatalf("expected action id %q, got %q", input.ActionID, created.ActionID)
	}

	idempotent, err := k.RecordAuditAction(input)
	if err != nil {
		t.Fatalf("RecordAuditAction idempotent replay returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent replay to return created record, got %+v vs %+v", idempotent, created)
	}

	got, ok := k.GetAuditAction(input.ActionID)
	if !ok {
		t.Fatal("expected persisted audit action")
	}
	if got != created {
		t.Fatalf("expected stored audit action %+v, got %+v", created, got)
	}
}

func TestKeeperRecordAuditActionConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	initial := types.GovernanceAuditAction{
		ActionID:        "audit-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "bootstrap allowlist update",
		EvidencePointer: "ipfs://evidence/audit-1",
		TimestampUnix:   4102444800,
	}
	if _, err := k.RecordAuditAction(initial); err != nil {
		t.Fatalf("seed RecordAuditAction failed: %v", err)
	}

	conflict := initial
	conflict.Reason = "different reason"
	_, err := k.RecordAuditAction(conflict)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error details, got %v", err)
	}
}

func TestKeeperRecordAuditActionValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.RecordAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "",
		EvidencePointer: "ipfs://evidence/audit-1",
		TimestampUnix:   4102444800,
	})
	if err == nil {
		t.Fatal("expected validation error for missing reason")
	}
}

func TestKeeperListAuditActionsDeterministicByActionID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, _ = k.RecordAuditAction(types.GovernanceAuditAction{ActionID: "audit-3", Action: "admin_allow_validator", Actor: "admin-1", Reason: "r3", EvidencePointer: "ipfs://a3", TimestampUnix: 3})
	_, _ = k.RecordAuditAction(types.GovernanceAuditAction{ActionID: "audit-1", Action: "admin_disable_validator", Actor: "admin-1", Reason: "r1", EvidencePointer: "ipfs://a1", TimestampUnix: 1})
	_, _ = k.RecordAuditAction(types.GovernanceAuditAction{ActionID: "audit-2", Action: "admin_allow_validator", Actor: "admin-2", Reason: "r2", EvidencePointer: "ipfs://a2", TimestampUnix: 2})

	list := k.ListAuditActions()
	if len(list) != 3 {
		t.Fatalf("expected 3 audit actions, got %d", len(list))
	}
	if list[0].ActionID != "audit-1" || list[1].ActionID != "audit-2" || list[2].ActionID != "audit-3" {
		t.Fatalf("expected sorted audit ids [audit-1 audit-2 audit-3], got [%s %s %s]", list[0].ActionID, list[1].ActionID, list[2].ActionID)
	}
}
