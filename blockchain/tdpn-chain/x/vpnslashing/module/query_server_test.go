package module

import (
	"errors"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

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
		ProofHash:  "sha256:proof-1",
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
		ProofHash:  "sha256:proof-b",
	})
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID: "evidence-a",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  "sha256:proof-a",
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
