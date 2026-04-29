package module

import (
	"errors"
	"strings"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

type queryReadErrorPenaltyStore struct {
	*keeper.InMemoryStore
	evidenceListErr error
	penaltyListErr  error
}

func newQueryReadErrorPenaltyStore() *queryReadErrorPenaltyStore {
	return &queryReadErrorPenaltyStore{InMemoryStore: keeper.NewInMemoryStore()}
}

func (s *queryReadErrorPenaltyStore) ListEvidenceWithError() ([]types.SlashEvidence, error) {
	if s.evidenceListErr != nil {
		return nil, s.evidenceListErr
	}
	return s.InMemoryStore.ListEvidence(), nil
}

func (s *queryReadErrorPenaltyStore) ListPenaltiesWithError() ([]types.PenaltyDecision, error) {
	if s.penaltyListErr != nil {
		return nil, s.penaltyListErr
	}
	return s.InMemoryStore.ListPenalties(), nil
}

func TestQueryServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewQueryServer(k)

	_, evidenceErr := server.GetEvidence(GetEvidenceRequest{EvidenceID: "evidence-nil"})
	if !errors.Is(evidenceErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for evidence query, got %v", evidenceErr)
	}

	_, penaltyErr := server.GetPenalty(GetPenaltyRequest{PenaltyID: "penalty-nil"})
	if !errors.Is(penaltyErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for penalty query, got %v", penaltyErr)
	}

	_, listEvidenceErr := server.ListEvidence(ListEvidenceRequest{})
	if !errors.Is(listEvidenceErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list evidence query, got %v", listEvidenceErr)
	}

	_, listPenaltyErr := server.ListPenalties(ListPenaltiesRequest{})
	if !errors.Is(listPenaltyErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list penalties query, got %v", listPenaltyErr)
	}
}

func TestQueryServerNotFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewQueryServer(&k)

	_, evidenceErr := server.GetEvidence(GetEvidenceRequest{EvidenceID: "evidence-missing"})
	if !errors.Is(evidenceErr, ErrEvidenceNotFound) {
		t.Fatalf("expected ErrEvidenceNotFound, got %v", evidenceErr)
	}

	_, penaltyErr := server.GetPenalty(GetPenaltyRequest{PenaltyID: "penalty-missing"})
	if !errors.Is(penaltyErr, ErrPenaltyNotFound) {
		t.Fatalf("expected ErrPenaltyNotFound, got %v", penaltyErr)
	}
}

func TestQueryServerFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	expectedEvidence := types.SlashEvidence{
		EvidenceID: "evidence-1",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-1"),
	}
	expectedPenalty := types.PenaltyDecision{
		PenaltyID:       "penalty-1",
		EvidenceID:      "evidence-1",
		SlashBasisPoint: 25,
	}
	k.UpsertEvidence(expectedEvidence)
	k.UpsertPenalty(expectedPenalty)

	server := NewQueryServer(&k)

	evidenceResp, evidenceErr := server.GetEvidence(GetEvidenceRequest{EvidenceID: "evidence-1"})
	if evidenceErr != nil {
		t.Fatalf("expected evidence query success, got %v", evidenceErr)
	}
	if evidenceResp.Evidence.EvidenceID != expectedEvidence.EvidenceID {
		t.Fatalf("unexpected evidence id: %q", evidenceResp.Evidence.EvidenceID)
	}

	penaltyResp, penaltyErr := server.GetPenalty(GetPenaltyRequest{PenaltyID: "penalty-1"})
	if penaltyErr != nil {
		t.Fatalf("expected penalty query success, got %v", penaltyErr)
	}
	if penaltyResp.Penalty.PenaltyID != expectedPenalty.PenaltyID {
		t.Fatalf("unexpected penalty id: %q", penaltyResp.Penalty.PenaltyID)
	}
}

func TestQueryServerListNonEmpty(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID: "evidence-b",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-b"),
	})
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID: "evidence-a",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-a"),
	})
	k.UpsertPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-b",
		EvidenceID:      "evidence-b",
		SlashBasisPoint: 20,
	})
	k.UpsertPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-a",
		EvidenceID:      "evidence-a",
		SlashBasisPoint: 10,
	})

	server := NewQueryServer(&k)

	evidenceResp, evidenceErr := server.ListEvidence(ListEvidenceRequest{})
	if evidenceErr != nil {
		t.Fatalf("expected list evidence success, got %v", evidenceErr)
	}
	if len(evidenceResp.Evidence) != 2 {
		t.Fatalf("expected 2 evidence records, got %d", len(evidenceResp.Evidence))
	}
	if evidenceResp.Evidence[0].EvidenceID != "evidence-a" || evidenceResp.Evidence[1].EvidenceID != "evidence-b" {
		t.Fatalf("expected sorted evidence IDs [evidence-a evidence-b], got [%s %s]", evidenceResp.Evidence[0].EvidenceID, evidenceResp.Evidence[1].EvidenceID)
	}

	penaltiesResp, penaltiesErr := server.ListPenalties(ListPenaltiesRequest{})
	if penaltiesErr != nil {
		t.Fatalf("expected list penalties success, got %v", penaltiesErr)
	}
	if len(penaltiesResp.Penalties) != 2 {
		t.Fatalf("expected 2 penalties, got %d", len(penaltiesResp.Penalties))
	}
	if penaltiesResp.Penalties[0].PenaltyID != "penalty-a" || penaltiesResp.Penalties[1].PenaltyID != "penalty-b" {
		t.Fatalf("expected sorted penalty IDs [penalty-a penalty-b], got [%s %s]", penaltiesResp.Penalties[0].PenaltyID, penaltiesResp.Penalties[1].PenaltyID)
	}
}

func TestQueryServerListEvidenceFiltersBeforeClamp(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID:      "evidence-filter-match",
		ProviderID:      "provider-filter",
		SessionID:       "sess-filter",
		ViolationType:   "invalid-settlement-proof",
		Kind:            types.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-filter-match"),
		SubmittedAtUnix: 1776643200,
	})
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID:      "evidence-filter-other-provider",
		ProviderID:      "provider-other",
		SessionID:       "sess-filter",
		ViolationType:   "invalid-settlement-proof",
		Kind:            types.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-filter-provider"),
		SubmittedAtUnix: 1776643200,
	})
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID:      "evidence-filter-outside-week",
		ProviderID:      "provider-filter",
		SessionID:       "sess-filter",
		ViolationType:   "invalid-settlement-proof",
		Kind:            types.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-filter-time"),
		SubmittedAtUnix: 1777248000,
	})

	server := NewQueryServer(&k)
	evidenceResp, evidenceErr := server.ListEvidence(ListEvidenceRequest{
		ProviderID:             "provider-filter",
		SessionID:              "sess-filter",
		ViolationType:          "INVALID-SETTLEMENT-PROOF",
		SubmittedAtOrAfterUnix: 1776643200,
		SubmittedBeforeUnix:    1777248000,
	})
	if evidenceErr != nil {
		t.Fatalf("expected list evidence success, got %v", evidenceErr)
	}
	if len(evidenceResp.Evidence) != 1 || evidenceResp.Evidence[0].EvidenceID != "evidence-filter-match" {
		t.Fatalf("filtered evidence=%+v want only evidence-filter-match", evidenceResp.Evidence)
	}
}

func TestQueryServerListEvidenceCanonicalizesProviderAndSessionFilters(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID:      "evidence-filter-canonical",
		ProviderID:      " Provider-Canonical ",
		SessionID:       " Sess-Canonical ",
		ViolationType:   "invalid-settlement-proof",
		Kind:            types.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-filter-canonical"),
		SubmittedAtUnix: 1776643200,
	})

	server := NewQueryServer(&k)
	evidenceResp, evidenceErr := server.ListEvidence(ListEvidenceRequest{
		ProviderID: "provider-canonical",
		SessionID:  "sess-canonical",
	})
	if evidenceErr != nil {
		t.Fatalf("expected list evidence success, got %v", evidenceErr)
	}
	if len(evidenceResp.Evidence) != 1 || evidenceResp.Evidence[0].EvidenceID != "evidence-filter-canonical" {
		t.Fatalf("canonicalized evidence filter=%+v want evidence-filter-canonical", evidenceResp.Evidence)
	}
}

func TestQueryServerListEvidenceIncludeFailedPresence(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID: "evidence-status-submitted",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-status-submitted"),
		Status:     "submitted",
	})
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID: "evidence-status-failed",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-status-failed"),
		Status:     "failed",
	})

	server := NewQueryServer(&k)

	defaultResp, err := server.ListEvidence(ListEvidenceRequest{})
	if err != nil {
		t.Fatalf("expected default list evidence success, got %v", err)
	}
	if len(defaultResp.Evidence) != 2 {
		t.Fatalf("expected unset include_failed to preserve failed records, got %d", len(defaultResp.Evidence))
	}

	explicitFalseResp, err := server.ListEvidence(ListEvidenceRequest{IncludeFailed: false, IncludeFailedSet: true})
	if err != nil {
		t.Fatalf("expected explicit false list evidence success, got %v", err)
	}
	if len(explicitFalseResp.Evidence) != 1 || explicitFalseResp.Evidence[0].EvidenceID != "evidence-status-submitted" {
		t.Fatalf("expected explicit false to drop failed evidence, got %+v", explicitFalseResp.Evidence)
	}
}

func TestQueryServerListFailsClosedOnReadError(t *testing.T) {
	t.Parallel()

	store := newQueryReadErrorPenaltyStore()
	store.UpsertEvidence(types.SlashEvidence{
		EvidenceID: "evidence-list-fail-closed",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-list-fail-closed"),
	})
	store.UpsertPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-list-fail-closed",
		EvidenceID:      "evidence-list-fail-closed",
		SlashBasisPoint: 10,
	})
	store.evidenceListErr = errors.New("evidence list decode failure")
	store.penaltyListErr = errors.New("penalty list decode failure")

	k := keeper.NewKeeperWithStore(store)
	server := NewQueryServer(&k)

	evidenceResp, evidenceErr := server.ListEvidence(ListEvidenceRequest{})
	if evidenceErr == nil {
		t.Fatal("expected list evidence to fail closed on read error")
	}
	if !errors.Is(evidenceErr, ErrQueryReadFailed) {
		t.Fatalf("expected ErrQueryReadFailed for evidence list failure, got %v", evidenceErr)
	}
	if !strings.Contains(evidenceErr.Error(), "list evidence") {
		t.Fatalf("expected list evidence context in error, got %v", evidenceErr)
	}
	if len(evidenceResp.Evidence) != 0 {
		t.Fatalf("expected no evidence payload on list failure, got %d records", len(evidenceResp.Evidence))
	}

	penaltiesResp, penaltiesErr := server.ListPenalties(ListPenaltiesRequest{})
	if penaltiesErr == nil {
		t.Fatal("expected list penalties to fail closed on read error")
	}
	if !errors.Is(penaltiesErr, ErrQueryReadFailed) {
		t.Fatalf("expected ErrQueryReadFailed for penalties list failure, got %v", penaltiesErr)
	}
	if !strings.Contains(penaltiesErr.Error(), "list penalties") {
		t.Fatalf("expected list penalties context in error, got %v", penaltiesErr)
	}
	if len(penaltiesResp.Penalties) != 0 {
		t.Fatalf("expected no penalty payload on list failure, got %d records", len(penaltiesResp.Penalties))
	}
}
