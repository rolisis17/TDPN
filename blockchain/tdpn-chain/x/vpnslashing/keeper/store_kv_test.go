package keeper

import (
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

func TestKVStoreUpsertGetList(t *testing.T) {
	t.Parallel()

	store := NewKVStore(kvtypes.NewMapStore())

	evidence := types.SlashEvidence{
		EvidenceID: "evidence-1",
		SessionID:  "sess-1",
		ProviderID: "provider-1",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  "sha256:proof-1",
		Status:     chaintypes.ReconciliationPending,
	}
	store.UpsertEvidence(evidence)

	gotEvidence, ok := store.GetEvidence(evidence.EvidenceID)
	if !ok {
		t.Fatal("expected evidence to exist")
	}
	if gotEvidence != evidence {
		t.Fatalf("expected evidence %+v, got %+v", evidence, gotEvidence)
	}

	penalty := types.PenaltyDecision{
		PenaltyID:       "penalty-1",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 25,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertPenalty(penalty)

	gotPenalty, ok := store.GetPenalty(penalty.PenaltyID)
	if !ok {
		t.Fatal("expected penalty to exist")
	}
	if gotPenalty != penalty {
		t.Fatalf("expected penalty %+v, got %+v", penalty, gotPenalty)
	}

	evidenceList := store.ListEvidence()
	if len(evidenceList) != 1 {
		t.Fatalf("expected 1 evidence entry, got %d", len(evidenceList))
	}
	if evidenceList[0] != evidence {
		t.Fatalf("expected listed evidence %+v, got %+v", evidence, evidenceList[0])
	}

	penaltyList := store.ListPenalties()
	if len(penaltyList) != 1 {
		t.Fatalf("expected 1 penalty entry, got %d", len(penaltyList))
	}
	if penaltyList[0] != penalty {
		t.Fatalf("expected listed penalty %+v, got %+v", penalty, penaltyList[0])
	}
}
