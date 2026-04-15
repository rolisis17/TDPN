package keeper

import (
	"os"
	"path/filepath"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

type trackingStore struct {
	evidence  map[string]types.SlashEvidence
	penalties map[string]types.PenaltyDecision

	upsertEvidenceCalls int
	getEvidenceCalls    int
	listEvidenceCalls   int
	upsertPenaltyCalls  int
	getPenaltyCalls     int
	listPenaltiesCalls  int
}

func newTrackingStore() *trackingStore {
	return &trackingStore{
		evidence:  make(map[string]types.SlashEvidence),
		penalties: make(map[string]types.PenaltyDecision),
	}
}

func (s *trackingStore) UpsertEvidence(record types.SlashEvidence) {
	s.upsertEvidenceCalls++
	s.evidence[record.EvidenceID] = record
}

func (s *trackingStore) GetEvidence(evidenceID string) (types.SlashEvidence, bool) {
	s.getEvidenceCalls++
	record, ok := s.evidence[evidenceID]
	return record, ok
}

func (s *trackingStore) ListEvidence() []types.SlashEvidence {
	s.listEvidenceCalls++
	out := make([]types.SlashEvidence, 0, len(s.evidence))
	for _, record := range s.evidence {
		out = append(out, record)
	}
	return out
}

func (s *trackingStore) UpsertPenalty(record types.PenaltyDecision) {
	s.upsertPenaltyCalls++
	s.penalties[record.PenaltyID] = record
}

func (s *trackingStore) GetPenalty(penaltyID string) (types.PenaltyDecision, bool) {
	s.getPenaltyCalls++
	record, ok := s.penalties[penaltyID]
	return record, ok
}

func (s *trackingStore) ListPenalties() []types.PenaltyDecision {
	s.listPenaltiesCalls++
	out := make([]types.PenaltyDecision, 0, len(s.penalties))
	for _, record := range s.penalties {
		out = append(out, record)
	}
	return out
}

func TestNewKeeperWithStoreNilFallsBackToInMemory(t *testing.T) {
	t.Parallel()

	k := NewKeeperWithStore(nil)

	record := types.SlashEvidence{
		EvidenceID: "evidence-fallback",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  "proof-fallback",
	}
	k.UpsertEvidence(record)

	got, ok := k.GetEvidence(record.EvidenceID)
	if !ok {
		t.Fatal("expected evidence to be present with nil-store fallback")
	}
	if got.EvidenceID != record.EvidenceID {
		t.Fatalf("expected evidence id %q, got %q", record.EvidenceID, got.EvidenceID)
	}
}

func TestKeeperDelegatesUpsertAndGetToCustomStore(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	evidence := types.SlashEvidence{
		EvidenceID: "evidence-1",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  "proof-1",
	}
	k.UpsertEvidence(evidence)

	if store.upsertEvidenceCalls != 1 {
		t.Fatalf("expected 1 evidence upsert call, got %d", store.upsertEvidenceCalls)
	}

	gotEvidence, ok := k.GetEvidence(evidence.EvidenceID)
	if !ok {
		t.Fatal("expected evidence from custom store")
	}
	if gotEvidence.ProofHash != evidence.ProofHash {
		t.Fatalf("expected proof hash %q, got %q", evidence.ProofHash, gotEvidence.ProofHash)
	}
	if store.getEvidenceCalls != 1 {
		t.Fatalf("expected 1 evidence get call, got %d", store.getEvidenceCalls)
	}

	penalty := types.PenaltyDecision{
		PenaltyID:       "penalty-1",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 100,
	}
	k.UpsertPenalty(penalty)

	if store.upsertPenaltyCalls != 1 {
		t.Fatalf("expected 1 penalty upsert call, got %d", store.upsertPenaltyCalls)
	}

	gotPenalty, ok := k.GetPenalty(penalty.PenaltyID)
	if !ok {
		t.Fatal("expected penalty from custom store")
	}
	if gotPenalty.SlashBasisPoint != penalty.SlashBasisPoint {
		t.Fatalf("expected slash basis point %d, got %d", penalty.SlashBasisPoint, gotPenalty.SlashBasisPoint)
	}
	if store.getPenaltyCalls != 1 {
		t.Fatalf("expected 1 penalty get call, got %d", store.getPenaltyCalls)
	}
}

func TestKeeperSubmitAndApplyUseCustomStoreWithEvidenceProgression(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	evidence, err := k.SubmitEvidence(types.SlashEvidence{
		EvidenceID: "evidence-2",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  "proof-2",
		Status:     chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("SubmitEvidence returned unexpected error: %v", err)
	}
	if evidence.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected evidence status %q, got %q", chaintypes.ReconciliationPending, evidence.Status)
	}
	if store.upsertEvidenceCalls == 0 || store.getEvidenceCalls == 0 {
		t.Fatalf("expected submit path to touch custom evidence store, got upsert=%d get=%d", store.upsertEvidenceCalls, store.getEvidenceCalls)
	}

	_, err = k.ApplyPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-2",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 1,
	})
	if err != nil {
		t.Fatalf("ApplyPenalty returned unexpected error: %v", err)
	}
	if store.upsertPenaltyCalls == 0 || store.getPenaltyCalls == 0 {
		t.Fatalf("expected apply path to touch custom penalty store, got upsert=%d get=%d", store.upsertPenaltyCalls, store.getPenaltyCalls)
	}

	updated, ok := k.GetEvidence(evidence.EvidenceID)
	if !ok {
		t.Fatal("expected evidence to exist after penalty")
	}
	if updated.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected evidence status %q after penalty, got %q", chaintypes.ReconciliationConfirmed, updated.Status)
	}
}

func TestFileStorePersistsAcrossReopen(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnslashing.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	evidence := types.SlashEvidence{
		EvidenceID:      "evidence-file-1",
		SessionID:       "session-file-1",
		ProviderID:      "provider-file-1",
		Kind:            types.EvidenceKindObjective,
		ProofHash:       "proof-file-1",
		SubmittedAtUnix: 1700000000,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	penalty := types.PenaltyDecision{
		PenaltyID:       "penalty-file-1",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 250,
		Jailed:          true,
		AppliedAtUnix:   1700000001,
		Status:          chaintypes.ReconciliationConfirmed,
	}

	store.UpsertEvidence(evidence)
	store.UpsertPenalty(penalty)

	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopening file store returned unexpected error: %v", err)
	}

	gotEvidence, ok := reopened.GetEvidence(evidence.EvidenceID)
	if !ok {
		t.Fatal("expected evidence to be loaded from file store")
	}
	if gotEvidence != evidence {
		t.Fatalf("expected reopened evidence %+v, got %+v", evidence, gotEvidence)
	}

	gotPenalty, ok := reopened.GetPenalty(penalty.PenaltyID)
	if !ok {
		t.Fatal("expected penalty to be loaded from file store")
	}
	if gotPenalty != penalty {
		t.Fatalf("expected reopened penalty %+v, got %+v", penalty, gotPenalty)
	}
}

func TestNewFileStoreInvalidPath(t *testing.T) {
	t.Parallel()

	blockerFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockerFile, []byte("blocker"), 0o644); err != nil {
		t.Fatalf("failed to seed blocker file: %v", err)
	}

	_, err := NewFileStore(filepath.Join(blockerFile, "vpnslashing.json"))
	if err == nil {
		t.Fatal("expected NewFileStore to fail when parent path is not a directory")
	}
}
