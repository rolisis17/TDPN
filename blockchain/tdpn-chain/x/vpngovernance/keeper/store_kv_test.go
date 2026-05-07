package keeper

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

func TestKVStoreUpsertGetList(t *testing.T) {
	t.Parallel()

	store := NewKVStore(kvtypes.NewMapStore())

	policy := types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy One", Version: 1, ActivatedAtUnix: 4102444800, Status: chaintypes.ReconciliationPending}
	store.UpsertPolicy(policy)

	gotPolicy, ok := store.GetPolicy(policy.PolicyID)
	if !ok {
		t.Fatal("expected policy to exist")
	}
	if gotPolicy != policy {
		t.Fatalf("expected policy %+v, got %+v", policy, gotPolicy)
	}

	decision := types.GovernanceDecision{DecisionID: "decision-1", PolicyID: policy.PolicyID, ProposalID: "proposal-1", Outcome: types.DecisionOutcomeApprove, Decider: "council", DecidedAtUnix: 4102444800, Status: chaintypes.ReconciliationSubmitted}
	store.UpsertDecision(decision)

	gotDecision, ok := store.GetDecision(decision.DecisionID)
	if !ok {
		t.Fatal("expected decision to exist")
	}
	if gotDecision != decision {
		t.Fatalf("expected decision %+v, got %+v", decision, gotDecision)
	}

	auditAction := types.GovernanceAuditAction{
		ActionID:        "audit-1",
		Action:          "admin_allow_validator",
		Actor:           "bootstrap-admin-1",
		Reason:          "bootstrap policy update",
		EvidencePointer: "ipfs://evidence/audit-1",
		TimestampUnix:   4102444800,
	}
	store.PutAuditAction(auditAction)

	gotAudit, ok := store.GetAuditAction(auditAction.ActionID)
	if !ok {
		t.Fatal("expected audit action to exist")
	}
	if gotAudit != auditAction {
		t.Fatalf("expected audit action %+v, got %+v", auditAction, gotAudit)
	}

	policies := store.ListPolicies()
	if len(policies) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(policies))
	}
	if policies[0] != policy {
		t.Fatalf("expected listed policy %+v, got %+v", policy, policies[0])
	}

	decisions := store.ListDecisions()
	if len(decisions) != 1 {
		t.Fatalf("expected 1 decision, got %d", len(decisions))
	}
	if decisions[0] != decision {
		t.Fatalf("expected listed decision %+v, got %+v", decision, decisions[0])
	}

	auditActions := store.ListAuditActions()
	if len(auditActions) != 1 {
		t.Fatalf("expected 1 audit action, got %d", len(auditActions))
	}
	if auditActions[0] != auditAction {
		t.Fatalf("expected listed audit action %+v, got %+v", auditAction, auditActions[0])
	}
}

func TestKVStoreNilBackendAndInvalidUpsertsFailClosed(t *testing.T) {
	t.Parallel()

	store := NewKVStore(nil)

	validPolicy := types.GovernancePolicy{
		PolicyID:        "policy-valid",
		Title:           "Policy Valid",
		Version:         1,
		ActivatedAtUnix: 1,
		Status:          chaintypes.ReconciliationPending,
	}
	store.UpsertPolicy(validPolicy)
	if got, ok := store.GetPolicy(validPolicy.PolicyID); !ok || got != validPolicy {
		t.Fatalf("expected nil-backend store to persist valid policy, got ok=%v record=%+v", ok, got)
	}

	store.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-invalid", Version: 1, ActivatedAtUnix: 1})
	if _, ok := store.GetPolicy("policy-invalid"); ok {
		t.Fatal("expected invalid policy upsert to be ignored")
	}

	store.UpsertDecision(types.GovernanceDecision{
		DecisionID:    "decision-invalid",
		PolicyID:      validPolicy.PolicyID,
		ProposalID:    "proposal-invalid",
		Outcome:       types.DecisionOutcomeApprove,
		DecidedAtUnix: 1,
		Status:        chaintypes.ReconciliationPending,
	})
	if _, ok := store.GetDecision("decision-invalid"); ok {
		t.Fatal("expected invalid decision upsert to be ignored")
	}

	store.PutAuditAction(types.GovernanceAuditAction{
		ActionID:        "audit-invalid",
		Action:          "admin_set_policy",
		Actor:           "bootstrap-admin",
		EvidencePointer: "ipfs://evidence/audit-invalid",
		TimestampUnix:   1,
	})
	if _, ok := store.GetAuditAction("audit-invalid"); ok {
		t.Fatal("expected invalid audit action upsert to be ignored")
	}
}

func TestKVStoreListFailClosedOnMalformedEntries(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	store.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-2", Title: "Policy", Version: 2, ActivatedAtUnix: 2, Status: chaintypes.ReconciliationPending})
	store.UpsertPolicy(types.GovernancePolicy{PolicyID: "policy-1", Title: "Policy", Version: 1, ActivatedAtUnix: 1, Status: chaintypes.ReconciliationPending})
	backend.Set([]byte("policy/bad-json"), []byte("{not-valid-json"))

	store.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-2", PolicyID: "policy-2", ProposalID: "proposal-2", Outcome: types.DecisionOutcomeApprove, Decider: "c2", DecidedAtUnix: 2, Status: chaintypes.ReconciliationSubmitted})
	store.UpsertDecision(types.GovernanceDecision{DecisionID: "decision-1", PolicyID: "policy-1", ProposalID: "proposal-1", Outcome: types.DecisionOutcomeReject, Decider: "c1", DecidedAtUnix: 1, Status: chaintypes.ReconciliationSubmitted})
	backend.Set([]byte("decision/bad-json"), []byte("{not-valid-json"))

	store.PutAuditAction(types.GovernanceAuditAction{ActionID: "audit-2", Action: "admin_allow_validator", Actor: "a2", Reason: "r2", EvidencePointer: "ipfs://a2", TimestampUnix: 2})
	store.PutAuditAction(types.GovernanceAuditAction{ActionID: "audit-1", Action: "admin_disable_validator", Actor: "a1", Reason: "r1", EvidencePointer: "ipfs://a1", TimestampUnix: 1})
	backend.Set([]byte("audit_action/bad-json"), []byte("{not-valid-json"))

	policies := store.ListPolicies()
	if len(policies) != 0 {
		t.Fatalf("expected policy listing to fail closed, got %d records", len(policies))
	}
	if _, err := store.ListPoliciesWithError(); err == nil {
		t.Fatal("expected malformed policy payload to return list decode error")
	}
	if _, ok := store.GetPolicy("bad-json"); ok {
		t.Fatal("expected malformed policy payload to be rejected by GetPolicy")
	}

	decisions := store.ListDecisions()
	if len(decisions) != 0 {
		t.Fatalf("expected decision listing to fail closed, got %d records", len(decisions))
	}
	if _, err := store.ListDecisionsWithError(); err == nil {
		t.Fatal("expected malformed decision payload to return list decode error")
	}
	if _, ok := store.GetDecision("bad-json"); ok {
		t.Fatal("expected malformed decision payload to be rejected by GetDecision")
	}

	auditActions := store.ListAuditActions()
	if len(auditActions) != 0 {
		t.Fatalf("expected audit action listing to fail closed, got %d records", len(auditActions))
	}
	if _, err := store.ListAuditActionsWithError(); err == nil {
		t.Fatal("expected malformed audit payload to return list decode error")
	}
	if _, ok := store.GetAuditAction("bad-json"); ok {
		t.Fatal("expected malformed audit payload to be rejected by GetAuditAction")
	}
}

func TestKVStoreListRejectsNonCanonicalKeys(t *testing.T) {
	t.Parallel()

	policyPayload, err := json.Marshal(types.GovernancePolicy{
		PolicyID:        "policy-case",
		Title:           "Policy Case",
		Version:         1,
		ActivatedAtUnix: 1,
		Status:          chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("marshal policy payload: %v", err)
	}
	policyBackend := kvtypes.NewMapStore()
	policyBackend.Set([]byte("policy/Policy-Case"), policyPayload)
	policyStore := NewKVStore(policyBackend)
	if _, err := policyStore.ListPoliciesWithError(); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("expected non-canonical policy key error, got %v", err)
	}

	decisionPayload, err := json.Marshal(types.GovernanceDecision{
		DecisionID:    "decision-case",
		PolicyID:      "policy-case",
		ProposalID:    "proposal-case",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council",
		DecidedAtUnix: 1,
		Status:        chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("marshal decision payload: %v", err)
	}
	decisionBackend := kvtypes.NewMapStore()
	decisionBackend.Set(policyKey("policy-case"), policyPayload)
	decisionBackend.Set([]byte("decision/Decision-Case"), decisionPayload)
	decisionStore := NewKVStore(decisionBackend)
	if _, err := decisionStore.ListDecisionsWithError(); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("expected non-canonical decision key error, got %v", err)
	}

	auditPayload, err := json.Marshal(types.GovernanceAuditAction{
		ActionID:        "audit-case",
		Action:          "admin_set_policy",
		Actor:           "bootstrap-admin",
		Reason:          "case-sensitive key guard",
		EvidencePointer: "ipfs://evidence/audit-case",
		TimestampUnix:   1,
	})
	if err != nil {
		t.Fatalf("marshal audit payload: %v", err)
	}
	auditBackend := kvtypes.NewMapStore()
	auditBackend.Set([]byte("audit_action/Audit-Case"), auditPayload)
	auditStore := NewKVStore(auditBackend)
	if _, err := auditStore.ListAuditActionsWithError(); err == nil || !strings.Contains(err.Error(), "not canonical") {
		t.Fatalf("expected non-canonical audit action key error, got %v", err)
	}
}

func TestKVStoreRejectsKeyPayloadIdentityMismatch(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	policyPayload, err := json.Marshal(types.GovernancePolicy{
		PolicyID:        "policy-payload",
		Title:           "Policy Payload",
		Version:         1,
		ActivatedAtUnix: 1,
		Status:          chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("marshal policy payload: %v", err)
	}
	backend.Set(policyKey("policy-key"), policyPayload)
	if _, ok := store.GetPolicy("policy-key"); ok {
		t.Fatal("expected policy key/payload mismatch to be rejected")
	}
	if _, err := store.ListPoliciesWithError(); err == nil {
		t.Fatal("expected policy key/payload mismatch to return decode error")
	}

	decisionPayload, err := json.Marshal(types.GovernanceDecision{
		DecisionID:    "decision-payload",
		PolicyID:      "policy-1",
		ProposalID:    "proposal-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "decider-1",
		DecidedAtUnix: 1,
		Status:        chaintypes.ReconciliationSubmitted,
	})
	if err != nil {
		t.Fatalf("marshal decision payload: %v", err)
	}
	backend.Set(decisionKey("decision-key"), decisionPayload)
	if _, ok := store.GetDecision("decision-key"); ok {
		t.Fatal("expected decision key/payload mismatch to be rejected")
	}
	if _, err := store.ListDecisionsWithError(); err == nil {
		t.Fatal("expected decision key/payload mismatch to return decode error")
	}

	auditPayload, err := json.Marshal(types.GovernanceAuditAction{
		ActionID:        "audit-payload",
		Action:          "admin_set_policy",
		Actor:           "actor-1",
		Reason:          "reason-1",
		EvidencePointer: "ipfs://evidence-1",
		TimestampUnix:   1,
	})
	if err != nil {
		t.Fatalf("marshal audit payload: %v", err)
	}
	backend.Set(auditActionKey("audit-key"), auditPayload)
	if _, ok := store.GetAuditAction("audit-key"); ok {
		t.Fatal("expected audit action key/payload mismatch to be rejected")
	}
	if _, err := store.ListAuditActionsWithError(); err == nil {
		t.Fatal("expected audit action key/payload mismatch to return decode error")
	}
}

func TestKVStoreDecodersRejectEmptyAndOversizedPayloads(t *testing.T) {
	t.Parallel()

	oversized := bytes.Repeat([]byte("x"), maxKVPayloadBytes+1)
	tests := []struct {
		name   string
		decode func([]byte) error
	}{
		{
			name: "policy",
			decode: func(payload []byte) error {
				_, err := decodePolicy(payload)
				return err
			},
		},
		{
			name: "decision",
			decode: func(payload []byte) error {
				_, err := decodeDecision(payload)
				return err
			},
		},
		{
			name: "audit action",
			decode: func(payload []byte) error {
				_, err := decodeAuditAction(payload)
				return err
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name+" empty", func(t *testing.T) {
			t.Parallel()

			if err := tt.decode(nil); err == nil || !strings.Contains(err.Error(), "payload is empty") {
				t.Fatalf("expected empty payload error, got %v", err)
			}
		})
		t.Run(tt.name+" oversized", func(t *testing.T) {
			t.Parallel()

			if err := tt.decode(oversized); err == nil || !strings.Contains(err.Error(), "payload exceeds") {
				t.Fatalf("expected oversized payload error, got %v", err)
			}
		})
	}
}

func TestKVStoreFailsClosedOnDecisionMissingPolicyReference(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	payload, err := json.Marshal(types.GovernanceDecision{
		DecisionID:    "decision-orphan",
		PolicyID:      "policy-missing",
		ProposalID:    "proposal-1",
		Outcome:       types.DecisionOutcomeApprove,
		Decider:       "council-1",
		DecidedAtUnix: 1,
		Status:        chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("marshal decision payload: %v", err)
	}
	backend.Set(decisionKey("decision-orphan"), payload)

	if _, ok := store.GetDecision("decision-orphan"); ok {
		t.Fatal("expected orphaned decision to be rejected by GetDecision")
	}

	if _, err := store.ListDecisionsWithError(); err == nil {
		t.Fatal("expected ListDecisionsWithError to fail on missing policy reference")
	}

	if got := store.ListDecisions(); len(got) != 0 {
		t.Fatalf("expected fail-closed decision listing, got %d records", len(got))
	}
}
