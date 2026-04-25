package keeper

import (
	"encoding/json"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

func TestKVStoreUpsertGetList(t *testing.T) {
	t.Parallel()

	store := NewKVStore(kvtypes.NewMapStore())

	evidence := types.SlashEvidence{
		EvidenceID:    "evidence-1",
		SessionID:     "sess-1",
		ProviderID:    "provider-1",
		ViolationType: "double-sign",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-1"),
		Status:        chaintypes.ReconciliationPending,
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

func TestKVStoreRejectsKeyIDMismatchAndOrphanPenalties(t *testing.T) {
	t.Parallel()

	rawStore := kvtypes.NewMapStore()
	store := NewKVStore(rawStore)

	badEvidence := types.SlashEvidence{
		EvidenceID:    "different-evidence-id",
		SessionID:     "sess-bad",
		ProviderID:    "provider-bad",
		ViolationType: "double-sign",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-bad"),
		Status:        chaintypes.ReconciliationSubmitted,
	}
	badEvidencePayload, err := json.Marshal(badEvidence)
	if err != nil {
		t.Fatalf("marshal bad evidence: %v", err)
	}
	rawStore.Set([]byte("evidence/evidence-key"), badEvidencePayload)

	if _, ok := store.GetEvidence("evidence-key"); ok {
		t.Fatal("expected evidence key/id mismatch to be rejected")
	}
	if _, err := store.ListEvidenceWithError(); err == nil {
		t.Fatal("expected strict evidence listing to fail on key/id mismatch")
	}
	if got := len(store.ListEvidence()); got != 0 {
		t.Fatalf("expected fail-closed evidence list to return 0 records, got %d", got)
	}

	goodEvidence := types.SlashEvidence{
		EvidenceID:    "evidence-good",
		SessionID:     "sess-good",
		ProviderID:    "provider-good",
		ViolationType: "double-sign",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-good"),
		Status:        chaintypes.ReconciliationSubmitted,
	}
	store.UpsertEvidence(goodEvidence)

	mismatchPenalty := types.PenaltyDecision{
		PenaltyID:       "different-penalty-id",
		EvidenceID:      goodEvidence.EvidenceID,
		SlashBasisPoint: 10,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	mismatchPenaltyPayload, err := json.Marshal(mismatchPenalty)
	if err != nil {
		t.Fatalf("marshal mismatch penalty: %v", err)
	}
	rawStore.Set([]byte("penalty/penalty-key"), mismatchPenaltyPayload)

	orphanPenalty := types.PenaltyDecision{
		PenaltyID:       "penalty-orphan",
		EvidenceID:      "evidence-missing",
		SlashBasisPoint: 5,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	orphanPenaltyPayload, err := json.Marshal(orphanPenalty)
	if err != nil {
		t.Fatalf("marshal orphan penalty: %v", err)
	}
	rawStore.Set([]byte("penalty/penalty-orphan"), orphanPenaltyPayload)

	goodPenalty := types.PenaltyDecision{
		PenaltyID:       "penalty-good",
		EvidenceID:      goodEvidence.EvidenceID,
		SlashBasisPoint: 20,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertPenalty(goodPenalty)

	if _, ok := store.GetPenalty("penalty-key"); ok {
		t.Fatal("expected penalty key/id mismatch to be rejected")
	}
	if _, ok := store.GetPenalty("penalty-orphan"); ok {
		t.Fatal("expected orphan penalty to be rejected")
	}

	if _, err := store.ListPenaltiesWithError(); err == nil {
		t.Fatal("expected strict penalty listing to fail on malformed/orphan penalties")
	}
	penaltyList := store.ListPenalties()
	if len(penaltyList) != 0 {
		t.Fatalf("expected fail-closed penalty list to return 0 records, got %d", len(penaltyList))
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
		EvidenceID:    "evidence-good",
		SessionID:     "sess-good",
		ProviderID:    "provider-good",
		ViolationType: "double-sign",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-good"),
		Status:        chaintypes.ReconciliationSubmitted,
	}
	goodPenalty := types.PenaltyDecision{
		PenaltyID:       "penalty-good",
		EvidenceID:      goodEvidence.EvidenceID,
		SlashBasisPoint: 10,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertEvidence(goodEvidence)
	store.UpsertPenalty(goodPenalty)

	if _, err := store.ListEvidenceWithError(); err == nil {
		t.Fatal("expected strict evidence listing to fail on invalid payload")
	}
	evidenceList := store.ListEvidence()
	if len(evidenceList) != 0 {
		t.Fatalf("expected fail-closed evidence list to return 0 records, got %d", len(evidenceList))
	}

	if _, err := store.ListPenaltiesWithError(); err == nil {
		t.Fatal("expected strict penalty listing to fail on invalid payload")
	}
	penaltyList := store.ListPenalties()
	if len(penaltyList) != 0 {
		t.Fatalf("expected fail-closed penalty list to return 0 records, got %d", len(penaltyList))
	}
}

func TestNewKVStoreNilFallbackAndPrefixIsolation(t *testing.T) {
	t.Parallel()

	store := NewKVStore(nil)

	evidence := types.SlashEvidence{
		EvidenceID:    "evidence-fallback",
		SessionID:     "sess-fallback",
		ProviderID:    "provider-fallback",
		ViolationType: "double-sign",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-fallback"),
		Status:        chaintypes.ReconciliationPending,
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
