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

func TestKeeperRecordDecisionRejectsDuplicatePolicyProposalAcrossDecisionIDs(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreatePolicy(types.GovernancePolicy{
		PolicyID:        "policy-dup-scope-1",
		Title:           "Policy Scope",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	}); err != nil {
		t.Fatalf("CreatePolicy returned unexpected error: %v", err)
	}

	if _, err := k.RecordDecision(types.GovernanceDecision{
		DecisionID:    "decision-dup-scope-1",
		PolicyID:      "policy-dup-scope-1",
		ProposalID:    "proposal-dup-scope-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-dup-scope-1",
		DecidedAtUnix: 4102444800,
	}); err != nil {
		t.Fatalf("RecordDecision returned unexpected error: %v", err)
	}

	_, err := k.RecordDecision(types.GovernanceDecision{
		DecisionID:    "decision-dup-scope-2",
		PolicyID:      "POLICY-DUP-SCOPE-1",
		ProposalID:    "PROPOSAL-DUP-SCOPE-1",
		Outcome:       types.DecisionOutcomeReject,
		Decider:       "council-dup-scope-1",
		DecidedAtUnix: 4102444801,
	})
	if err == nil {
		t.Fatal("expected conflict for duplicate policy/proposal decision business key")
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

func TestKeeperPolicyLegacyCompatibilityForCreateGetAndList(t *testing.T) {
	t.Parallel()

	store := NewInMemoryStore()
	store.UpsertPolicy(types.GovernancePolicy{
		PolicyID:        "PoLiCy-Legacy-1",
		Title:           "Legacy Policy",
		Description:     "legacy policy description",
		Version:         2,
		ActivatedAtUnix: 4102444800,
		Status:          " PeNdInG ",
	})

	k := NewKeeperWithStore(store)

	got, ok := k.GetPolicy(" policy-legacy-1 ")
	if !ok {
		t.Fatal("expected canonical lookup to resolve legacy mixed-case policy id")
	}
	if got.PolicyID != "policy-legacy-1" {
		t.Fatalf("expected canonical policy id %q, got %q", "policy-legacy-1", got.PolicyID)
	}
	if got.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected canonical status %q, got %q", chaintypes.ReconciliationPending, got.Status)
	}

	gotRaw, ok := k.GetPolicy("PoLiCy-Legacy-1")
	if !ok {
		t.Fatal("expected raw legacy lookup to resolve")
	}
	if gotRaw != got {
		t.Fatalf("expected raw and canonical lookups to return the same normalized record, got %+v vs %+v", gotRaw, got)
	}

	idempotent, err := k.CreatePolicy(types.GovernancePolicy{
		PolicyID:        "policy-legacy-1",
		Title:           "Legacy Policy",
		Description:     "legacy policy description",
		Version:         2,
		ActivatedAtUnix: 4102444800,
		Status:          "pending",
	})
	if err != nil {
		t.Fatalf("CreatePolicy idempotent replay on legacy record returned unexpected error: %v", err)
	}
	if idempotent != got {
		t.Fatalf("expected idempotent replay to return normalized record %+v, got %+v", got, idempotent)
	}
	if len(store.policies) != 1 {
		t.Fatalf("expected legacy idempotent replay to avoid duplicate keys, got %d keys", len(store.policies))
	}

	_, err = k.CreatePolicy(types.GovernancePolicy{
		PolicyID:        "policy-legacy-1",
		Title:           "Legacy Policy Changed",
		Description:     "legacy policy description",
		Version:         2,
		ActivatedAtUnix: 4102444800,
		Status:          "pending",
	})
	if err == nil {
		t.Fatal("expected conflict when legacy logical policy id exists with different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict details, got %v", err)
	}

	// Inject mixed-case/canonical duplicates to assert canonical dedupe and deterministic ordering.
	store.UpsertPolicy(types.GovernancePolicy{
		PolicyID:        "policy-legacy-1",
		Title:           "Legacy Policy",
		Description:     "legacy policy description",
		Version:         2,
		ActivatedAtUnix: 4102444800,
		Status:          chaintypes.ReconciliationPending,
	})
	store.UpsertPolicy(types.GovernancePolicy{
		PolicyID:        "PoLiCy-Z-1",
		Title:           "Policy Z",
		Version:         1,
		ActivatedAtUnix: 1,
		Status:          chaintypes.ReconciliationPending,
	})
	store.UpsertPolicy(types.GovernancePolicy{
		PolicyID:        "policy-a-1",
		Title:           "Policy A",
		Version:         1,
		ActivatedAtUnix: 1,
		Status:          chaintypes.ReconciliationPending,
	})

	list := k.ListPolicies()
	if len(list) != 3 {
		t.Fatalf("expected canonical-deduped policy list length 3, got %d", len(list))
	}
	if list[0].PolicyID != "policy-a-1" || list[1].PolicyID != "policy-legacy-1" || list[2].PolicyID != "policy-z-1" {
		t.Fatalf("expected canonical deterministic policy ids [policy-a-1 policy-legacy-1 policy-z-1], got [%s %s %s]", list[0].PolicyID, list[1].PolicyID, list[2].PolicyID)
	}
}

func TestKeeperDecisionLegacyCompatibilityForCreateGetAndList(t *testing.T) {
	t.Parallel()

	store := NewInMemoryStore()
	store.UpsertPolicy(types.GovernancePolicy{
		PolicyID:        "PoLiCy-Legacy-Decision-1",
		Title:           "Legacy Decision Policy",
		Version:         1,
		ActivatedAtUnix: 4102444800,
		Status:          chaintypes.ReconciliationPending,
	})
	store.UpsertDecision(types.GovernanceDecision{
		DecisionID:    "DeCiSiOn-Legacy-1",
		PolicyID:      "PoLiCy-Legacy-Decision-1",
		ProposalID:    "PrOpOsAl-Legacy-1",
		Outcome:       " ApPrOvE ",
		Decider:       " CoUnCiL-Legacy-1 ",
		Reason:        "  preserve reason spacing  ",
		DecidedAtUnix: 4102444800,
		Status:        " PeNdInG ",
	})

	k := NewKeeperWithStore(store)

	got, ok := k.GetDecision(" decision-legacy-1 ")
	if !ok {
		t.Fatal("expected canonical lookup to resolve legacy mixed-case decision id")
	}
	if got.DecisionID != "decision-legacy-1" {
		t.Fatalf("expected canonical decision id %q, got %q", "decision-legacy-1", got.DecisionID)
	}
	if got.PolicyID != "policy-legacy-decision-1" {
		t.Fatalf("expected canonical policy id %q, got %q", "policy-legacy-decision-1", got.PolicyID)
	}
	if got.ProposalID != "proposal-legacy-1" {
		t.Fatalf("expected canonical proposal id %q, got %q", "proposal-legacy-1", got.ProposalID)
	}
	if got.Outcome != types.DecisionOutcomeApprove {
		t.Fatalf("expected canonical outcome %q, got %q", types.DecisionOutcomeApprove, got.Outcome)
	}
	if got.Decider != "council-legacy-1" {
		t.Fatalf("expected canonical decider %q, got %q", "council-legacy-1", got.Decider)
	}
	if got.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected canonical status %q, got %q", chaintypes.ReconciliationPending, got.Status)
	}

	idempotent, err := k.RecordDecision(types.GovernanceDecision{
		DecisionID:    "decision-legacy-1",
		PolicyID:      "policy-legacy-decision-1",
		ProposalID:    "proposal-legacy-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-legacy-1",
		Reason:        "  preserve reason spacing  ",
		DecidedAtUnix: 4102444800,
		Status:        "pending",
	})
	if err != nil {
		t.Fatalf("RecordDecision idempotent replay on legacy record returned unexpected error: %v", err)
	}
	if idempotent != got {
		t.Fatalf("expected idempotent replay to return normalized record %+v, got %+v", got, idempotent)
	}
	if len(store.decisions) != 1 {
		t.Fatalf("expected legacy idempotent replay to avoid duplicate keys, got %d keys", len(store.decisions))
	}

	_, err = k.RecordDecision(types.GovernanceDecision{
		DecisionID:    "decision-legacy-1",
		PolicyID:      "policy-legacy-decision-1",
		ProposalID:    "proposal-legacy-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-legacy-1",
		Reason:        "changed reason",
		DecidedAtUnix: 4102444800,
		Status:        "pending",
	})
	if err == nil {
		t.Fatal("expected conflict when legacy logical decision id exists with different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict details, got %v", err)
	}

	created, err := k.RecordDecision(types.GovernanceDecision{
		DecisionID:    "decision-legacy-2",
		PolicyID:      "policy-legacy-decision-1",
		ProposalID:    "proposal-legacy-2",
		Outcome:       types.DecisionOutcomeReject,
		Decider:       "council-legacy-2",
		Reason:        "new decision against legacy policy",
		DecidedAtUnix: 4102444801,
		Status:        "submitted",
	})
	if err != nil {
		t.Fatalf("expected record against legacy mixed-case policy id to succeed, got %v", err)
	}
	if created.PolicyID != "policy-legacy-decision-1" {
		t.Fatalf("expected canonical policy id %q, got %q", "policy-legacy-decision-1", created.PolicyID)
	}

	// Inject mixed-case/canonical duplicates to assert canonical dedupe and deterministic ordering.
	store.UpsertDecision(types.GovernanceDecision{
		DecisionID:    "decision-legacy-1",
		PolicyID:      "policy-legacy-decision-1",
		ProposalID:    "proposal-legacy-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-legacy-1",
		Reason:        "  preserve reason spacing  ",
		DecidedAtUnix: 4102444800,
		Status:        chaintypes.ReconciliationPending,
	})
	store.UpsertDecision(types.GovernanceDecision{
		DecisionID:    "DeCiSiOn-Z-1",
		PolicyID:      "PoLiCy-Legacy-Decision-1",
		ProposalID:    "proposal-z-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-z-1",
		Reason:        "z",
		DecidedAtUnix: 3,
		Status:        chaintypes.ReconciliationPending,
	})
	store.UpsertDecision(types.GovernanceDecision{
		DecisionID:    "decision-a-1",
		PolicyID:      "policy-legacy-decision-1",
		ProposalID:    "proposal-a-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-a-1",
		Reason:        "a",
		DecidedAtUnix: 2,
		Status:        chaintypes.ReconciliationPending,
	})

	list := k.ListDecisions()
	if len(list) != 4 {
		t.Fatalf("expected canonical-deduped decision list length 4, got %d", len(list))
	}
	if list[0].DecisionID != "decision-a-1" || list[1].DecisionID != "decision-legacy-1" || list[2].DecisionID != "decision-legacy-2" || list[3].DecisionID != "decision-z-1" {
		t.Fatalf("expected canonical deterministic decision ids [decision-a-1 decision-legacy-1 decision-legacy-2 decision-z-1], got [%s %s %s %s]", list[0].DecisionID, list[1].DecisionID, list[2].DecisionID, list[3].DecisionID)
	}
}

func TestKeeperAuditActionLegacyCompatibilityForCreateGetAndList(t *testing.T) {
	t.Parallel()

	store := NewInMemoryStore()
	store.PutAuditAction(types.GovernanceAuditAction{
		ActionID:        "AuDiT-Legacy-1",
		Action:          " AdMiN_AlLoW_VaLiDaToR ",
		Actor:           " BoOtStRaP-AdMiN-1 ",
		Reason:          "  preserve reason spacing  ",
		EvidencePointer: " ipfs://Evidence/Audit-Legacy-1 ",
		TimestampUnix:   4102444800,
	})

	k := NewKeeperWithStore(store)

	got, ok := k.GetAuditAction(" audit-legacy-1 ")
	if !ok {
		t.Fatal("expected canonical lookup to resolve legacy mixed-case audit id")
	}
	if got.ActionID != "audit-legacy-1" {
		t.Fatalf("expected canonical action id %q, got %q", "audit-legacy-1", got.ActionID)
	}
	if got.Action != "admin_allow_validator" {
		t.Fatalf("expected canonical action %q, got %q", "admin_allow_validator", got.Action)
	}
	if got.Actor != "bootstrap-admin-1" {
		t.Fatalf("expected canonical actor %q, got %q", "bootstrap-admin-1", got.Actor)
	}
	if got.EvidencePointer != "ipfs://Evidence/Audit-Legacy-1" {
		t.Fatalf("expected trimmed evidence pointer, got %q", got.EvidencePointer)
	}

	idempotent, err := k.RecordAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-legacy-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "  preserve reason spacing  ",
		EvidencePointer: "ipfs://Evidence/Audit-Legacy-1",
		TimestampUnix:   4102444800,
	})
	if err != nil {
		t.Fatalf("RecordAuditAction idempotent replay on legacy record returned unexpected error: %v", err)
	}
	if idempotent != got {
		t.Fatalf("expected idempotent replay to return normalized record %+v, got %+v", got, idempotent)
	}
	if len(store.auditActions) != 1 {
		t.Fatalf("expected legacy idempotent replay to avoid duplicate keys, got %d keys", len(store.auditActions))
	}

	_, err = k.RecordAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-legacy-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "changed reason",
		EvidencePointer: "ipfs://Evidence/Audit-Legacy-1",
		TimestampUnix:   4102444800,
	})
	if err == nil {
		t.Fatal("expected conflict when legacy logical audit id exists with different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict details, got %v", err)
	}

	store.PutAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-legacy-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "  preserve reason spacing  ",
		EvidencePointer: "ipfs://Evidence/Audit-Legacy-1",
		TimestampUnix:   4102444800,
	})
	store.PutAuditAction(types.GovernanceAuditAction{
		ActionID:        "AuDiT-Z-1",
		Action:          "admin_allow_validator",
		Actor:           "admin-z-1",
		Reason:          "z",
		EvidencePointer: "ipfs://audit/z-1",
		TimestampUnix:   3,
	})
	store.PutAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-a-1",
		Action:          "admin_disable_validator",
		Actor:           "admin-a-1",
		Reason:          "a",
		EvidencePointer: "ipfs://audit/a-1",
		TimestampUnix:   2,
	})

	list := k.ListAuditActions()
	if len(list) != 3 {
		t.Fatalf("expected canonical-deduped audit list length 3, got %d", len(list))
	}
	if list[0].ActionID != "audit-a-1" || list[1].ActionID != "audit-legacy-1" || list[2].ActionID != "audit-z-1" {
		t.Fatalf("expected canonical deterministic audit ids [audit-a-1 audit-legacy-1 audit-z-1], got [%s %s %s]", list[0].ActionID, list[1].ActionID, list[2].ActionID)
	}
}

func TestKeeperCreatePolicyCanonicalBoundaries(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	input := types.GovernancePolicy{
		PolicyID:        "  PoLiCy-Canonical-1  ",
		Title:           "Policy Canonical One",
		Description:     "policy description kept as free text",
		Version:         1,
		ActivatedAtUnix: 4102444800,
		Status:          " PeNdInG ",
	}

	created, err := k.CreatePolicy(input)
	if err != nil {
		t.Fatalf("CreatePolicy returned unexpected error: %v", err)
	}
	if created.PolicyID != "policy-canonical-1" {
		t.Fatalf("expected canonical policy id %q, got %q", "policy-canonical-1", created.PolicyID)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected canonical status %q, got %q", chaintypes.ReconciliationPending, created.Status)
	}

	got, ok := k.GetPolicy("  POLICY-CANONICAL-1 ")
	if !ok {
		t.Fatal("expected policy lookup with whitespace/case variants to succeed")
	}
	if got != created {
		t.Fatalf("expected canonical get to return %+v, got %+v", created, got)
	}

	list := k.ListPolicies()
	if len(list) != 1 || list[0].PolicyID != "policy-canonical-1" {
		t.Fatalf("expected canonical policy list entry, got %+v", list)
	}

	replay := input
	replay.PolicyID = "policy-canonical-1"
	replay.Status = "pending"
	idempotent, err := k.CreatePolicy(replay)
	if err != nil {
		t.Fatalf("CreatePolicy replay returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent replay to return %+v, got %+v", created, idempotent)
	}

	conflict := replay
	conflict.PolicyID = " POLICY-CANONICAL-1 "
	conflict.Title = "Policy Canonical One Updated"
	_, err = k.CreatePolicy(conflict)
	if err == nil {
		t.Fatal("expected conflict on canonical policy id with divergent fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict details, got %v", err)
	}
}

func TestKeeperRecordDecisionCanonicalBoundaries(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreatePolicy(types.GovernancePolicy{
		PolicyID:        "  PoLiCy-Decision-1  ",
		Title:           "Policy Decision",
		Version:         1,
		ActivatedAtUnix: 4102444800,
	}); err != nil {
		t.Fatalf("CreatePolicy returned unexpected error: %v", err)
	}

	input := types.GovernanceDecision{
		DecisionID:    "  DeCiSiOn-Canonical-1  ",
		PolicyID:      " POLICY-DECISION-1 ",
		ProposalID:    "  PrOpOsAl-Canonical-1  ",
		Outcome:       "  ApPrOvE ",
		Decider:       "  CoUnCiL-Canonical  ",
		Reason:        "  preserve reason spacing  ",
		DecidedAtUnix: 4102444800,
		Status:        " PeNdInG ",
	}

	created, err := k.RecordDecision(input)
	if err != nil {
		t.Fatalf("RecordDecision returned unexpected error: %v", err)
	}
	if created.DecisionID != "decision-canonical-1" {
		t.Fatalf("expected canonical decision id %q, got %q", "decision-canonical-1", created.DecisionID)
	}
	if created.PolicyID != "policy-decision-1" {
		t.Fatalf("expected canonical policy id %q, got %q", "policy-decision-1", created.PolicyID)
	}
	if created.ProposalID != "proposal-canonical-1" {
		t.Fatalf("expected canonical proposal id %q, got %q", "proposal-canonical-1", created.ProposalID)
	}
	if created.Outcome != types.DecisionOutcomeApprove {
		t.Fatalf("expected canonical outcome %q, got %q", types.DecisionOutcomeApprove, created.Outcome)
	}
	if created.Decider != "council-canonical" {
		t.Fatalf("expected canonical decider %q, got %q", "council-canonical", created.Decider)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected canonical status %q, got %q", chaintypes.ReconciliationPending, created.Status)
	}
	if created.Reason != input.Reason {
		t.Fatalf("expected reason to be preserved, got %q vs %q", created.Reason, input.Reason)
	}

	got, ok := k.GetDecision(" DECISION-CANONICAL-1 ")
	if !ok {
		t.Fatal("expected decision lookup with whitespace/case variants to succeed")
	}
	if got != created {
		t.Fatalf("expected canonical get to return %+v, got %+v", created, got)
	}

	list := k.ListDecisions()
	if len(list) != 1 || list[0].DecisionID != "decision-canonical-1" {
		t.Fatalf("expected canonical decision list entry, got %+v", list)
	}

	replay := input
	replay.DecisionID = "decision-canonical-1"
	replay.PolicyID = "policy-decision-1"
	replay.ProposalID = "proposal-canonical-1"
	replay.Outcome = "approve"
	replay.Decider = "council-canonical"
	replay.Status = "pending"
	idempotent, err := k.RecordDecision(replay)
	if err != nil {
		t.Fatalf("RecordDecision replay returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent replay to return %+v, got %+v", created, idempotent)
	}

	conflict := replay
	conflict.DecisionID = " DECISION-CANONICAL-1 "
	conflict.Reason = strings.TrimSpace(replay.Reason)
	_, err = k.RecordDecision(conflict)
	if err == nil {
		t.Fatal("expected conflict when free-text reason changes")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict details, got %v", err)
	}
}

func TestKeeperRecordAuditActionCanonicalBoundaries(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	input := types.GovernanceAuditAction{
		ActionID:        "  AuDiT-Canonical-1  ",
		Action:          "  AdMiN_AlLoW_VaLiDaToR ",
		Actor:           "  BoOtStRaP-AdMiN-1  ",
		Reason:          "  preserve reason spacing  ",
		EvidencePointer: "  ipfs://Evidence/Audit-Canonical-1  ",
		TimestampUnix:   4102444800,
	}

	created, err := k.RecordAuditAction(input)
	if err != nil {
		t.Fatalf("RecordAuditAction returned unexpected error: %v", err)
	}
	if created.ActionID != "audit-canonical-1" {
		t.Fatalf("expected canonical action id %q, got %q", "audit-canonical-1", created.ActionID)
	}
	if created.Action != "admin_allow_validator" {
		t.Fatalf("expected canonical action %q, got %q", "admin_allow_validator", created.Action)
	}
	if created.Actor != "bootstrap-admin-1" {
		t.Fatalf("expected canonical actor %q, got %q", "bootstrap-admin-1", created.Actor)
	}
	if created.EvidencePointer != "ipfs://Evidence/Audit-Canonical-1" {
		t.Fatalf("expected evidence pointer trimming only, got %q", created.EvidencePointer)
	}
	if created.Reason != input.Reason {
		t.Fatalf("expected reason to be preserved, got %q vs %q", created.Reason, input.Reason)
	}

	got, ok := k.GetAuditAction(" AUDIT-CANONICAL-1 ")
	if !ok {
		t.Fatal("expected audit lookup with whitespace/case variants to succeed")
	}
	if got != created {
		t.Fatalf("expected canonical get to return %+v, got %+v", created, got)
	}

	list := k.ListAuditActions()
	if len(list) != 1 || list[0].ActionID != "audit-canonical-1" {
		t.Fatalf("expected canonical audit list entry, got %+v", list)
	}

	replay := input
	replay.ActionID = "audit-canonical-1"
	replay.Action = "admin_allow_validator"
	replay.Actor = "bootstrap-admin-1"
	replay.EvidencePointer = "ipfs://Evidence/Audit-Canonical-1"
	idempotent, err := k.RecordAuditAction(replay)
	if err != nil {
		t.Fatalf("RecordAuditAction replay returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent replay to return %+v, got %+v", created, idempotent)
	}

	conflict := replay
	conflict.ActionID = " AUDIT-CANONICAL-1 "
	conflict.Reason = strings.TrimSpace(replay.Reason)
	_, err = k.RecordAuditAction(conflict)
	if err == nil {
		t.Fatal("expected conflict when free-text reason changes")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict details, got %v", err)
	}
}
