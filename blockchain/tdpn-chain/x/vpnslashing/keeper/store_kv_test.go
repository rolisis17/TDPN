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
		ProofHash:  testSHAProof("proof-1"),
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

func TestKVStoreInvalidPayloadsAreSafeOnGetAndList(t *testing.T) {
	t.Parallel()

	rawStore := kvtypes.NewMapStore()
	store := NewKVStore(rawStore)

	rawStore.Set([]byte("evidence/evidence-bad"), []byte("{invalid-json"))
	rawStore.Set([]byte("penalty/penalty-bad"), []byte("{invalid-json"))

	if _, ok := store.GetEvidence("evidence-bad"); ok {
		t.Fatal("expected invalid evidence payload to be treated as not found")
	}
	if _, ok := store.GetPenalty("penalty-bad"); ok {
		t.Fatal("expected invalid penalty payload to be treated as not found")
	}

	goodEvidence := types.SlashEvidence{
		EvidenceID: "evidence-good",
		SessionID:  "sess-good",
		ProviderID: "provider-good",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-good"),
		Status:     chaintypes.ReconciliationSubmitted,
	}
	goodPenalty := types.PenaltyDecision{
		PenaltyID:       "penalty-good",
		EvidenceID:      goodEvidence.EvidenceID,
		SlashBasisPoint: 10,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertEvidence(goodEvidence)
	store.UpsertPenalty(goodPenalty)

	evidenceList := store.ListEvidence()
	if len(evidenceList) != 1 {
		t.Fatalf("expected only valid evidence entry to be listed, got %d", len(evidenceList))
	}
	if evidenceList[0].EvidenceID != goodEvidence.EvidenceID {
		t.Fatalf("expected listed evidence id %q, got %q", goodEvidence.EvidenceID, evidenceList[0].EvidenceID)
	}

	penaltyList := store.ListPenalties()
	if len(penaltyList) != 1 {
		t.Fatalf("expected only valid penalty entry to be listed, got %d", len(penaltyList))
	}
	if penaltyList[0].PenaltyID != goodPenalty.PenaltyID {
		t.Fatalf("expected listed penalty id %q, got %q", goodPenalty.PenaltyID, penaltyList[0].PenaltyID)
	}
}

func TestNewKVStoreNilFallbackAndPrefixIsolation(t *testing.T) {
	t.Parallel()

	store := NewKVStore(nil)

	evidence := types.SlashEvidence{
		EvidenceID: "evidence-fallback",
		ProviderID: "provider-fallback",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-fallback"),
		Status:     chaintypes.ReconciliationPending,
	}
	penalty := types.PenaltyDecision{
		PenaltyID:       "penalty-fallback",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 5,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertEvidence(evidence)
	store.UpsertPenalty(penalty)

	gotEvidence, ok := store.GetEvidence(evidence.EvidenceID)
	if !ok {
		t.Fatal("expected evidence to be readable from nil-store fallback")
	}
	if gotEvidence != evidence {
		t.Fatalf("expected fallback evidence %+v, got %+v", evidence, gotEvidence)
	}

	gotPenalty, ok := store.GetPenalty(penalty.PenaltyID)
	if !ok {
		t.Fatal("expected penalty to be readable from nil-store fallback")
	}
	if gotPenalty != penalty {
		t.Fatalf("expected fallback penalty %+v, got %+v", penalty, gotPenalty)
	}

	// Ensure prefix scans stay isolated to vpnslashing namespaces.
	rawStore := kvtypes.NewMapStore()
	rawStore.Set([]byte("other/evidence-entry"), []byte(`{"EvidenceID":"other"}`))
	rawStore.Set([]byte("other/penalty-entry"), []byte(`{"PenaltyID":"other"}`))
	prefixIsolated := NewKVStore(rawStore)

	if got := len(prefixIsolated.ListEvidence()); got != 0 {
		t.Fatalf("expected 0 evidence entries from unrelated prefix, got %d", got)
	}
	if got := len(prefixIsolated.ListPenalties()); got != 0 {
		t.Fatalf("expected 0 penalty entries from unrelated prefix, got %d", got)
	}
}
