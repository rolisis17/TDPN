package keeper

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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
		EvidenceID:    "evidence-fallback",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-fallback"),
		ViolationType: "double-sign",
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
		EvidenceID:    "evidence-1",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-1"),
		ViolationType: "double-sign",
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
		EvidenceID:    "evidence-2",
		ProviderID:    "provider-2",
		SessionID:     "session-2",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-2"),
		ViolationType: "double-sign",
		Status:        chaintypes.ReconciliationPending,
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

	evidence = confirmPenaltyEvidenceForTest(t, &k, evidence.EvidenceID)
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

func TestApplyPenaltyFileStorePersistsEvidenceAdvanceAndPenaltyAtomically(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnslashing.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	k := NewKeeperWithStore(store)

	evidence, err := k.SubmitEvidence(types.SlashEvidence{
		EvidenceID:    "evidence-file-atomic-1",
		ProviderID:    "provider-file-atomic-1",
		SessionID:     "session-file-atomic-1",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-file-atomic-1"),
		ViolationType: "double-sign",
		Status:        chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
	evidence = confirmPenaltyEvidenceForTest(t, &k, evidence.EvidenceID)

	persistCalls := 0
	store.persistFailureInjector = func() error {
		persistCalls++
		return nil
	}
	defer func() {
		store.persistFailureInjector = nil
	}()

	_, err = k.ApplyPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-file-atomic-1",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 15,
	})
	if err != nil {
		t.Fatalf("apply penalty: %v", err)
	}
	if persistCalls != 1 {
		t.Fatalf("expected exactly 1 persistence call for atomic apply, got %d", persistCalls)
	}
}

func TestApplyPenaltyFileStoreAtomicPersistFailureLeavesDurableStateUnchanged(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnslashing.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("new file store: %v", err)
	}
	k := NewKeeperWithStore(store)

	evidenceID := "evidence-file-atomic-failure"
	_, err = k.SubmitEvidence(types.SlashEvidence{
		EvidenceID:    evidenceID,
		ProviderID:    "provider-file-atomic-failure",
		SessionID:     "session-file-atomic-failure",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-file-atomic-failure"),
		ViolationType: "double-sign",
		Status:        chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("seed evidence: %v", err)
	}
	confirmPenaltyEvidenceForTest(t, &k, evidenceID)

	failOnce := true
	store.persistFailureInjector = func() error {
		if failOnce {
			failOnce = false
			return errors.New("forced atomic persist failure")
		}
		return nil
	}

	penaltyID := "penalty-file-atomic-failure"
	_, err = k.ApplyPenalty(types.PenaltyDecision{
		PenaltyID:       penaltyID,
		EvidenceID:      evidenceID,
		SlashBasisPoint: 25,
	})
	if err == nil {
		t.Fatal("expected apply penalty to fail when atomic persist fails")
	}
	if !strings.Contains(err.Error(), "persist penalty") {
		t.Fatalf("expected penalty persistence failure, got %v", err)
	}
	store.persistFailureInjector = nil

	if _, ok := k.GetPenalty(penaltyID); ok {
		t.Fatal("expected no in-memory penalty after failed atomic persist")
	}

	evidenceAfter, ok := k.GetEvidence(evidenceID)
	if !ok {
		t.Fatalf("expected evidence %q to remain available", evidenceID)
	}
	if evidenceAfter.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf(
			"expected in-memory evidence status %q after failed apply, got %q",
			chaintypes.ReconciliationConfirmed,
			evidenceAfter.Status,
		)
	}

	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopen file store: %v", err)
	}

	if _, ok := reopened.GetPenalty(penaltyID); ok {
		t.Fatal("expected no durable penalty after failed atomic persist")
	}

	durableEvidence, ok := reopened.GetEvidence(evidenceID)
	if !ok {
		t.Fatalf("expected durable evidence %q to remain available", evidenceID)
	}
	if durableEvidence.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf(
			"expected durable evidence status %q after failed apply, got %q",
			chaintypes.ReconciliationConfirmed,
			durableEvidence.Status,
		)
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
		ViolationType:   "session-replay-proof",
		Kind:            types.EvidenceKindObjective,
		ProofHash:       testSHAProof("proof-file-1"),
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

func TestNewFileStoreBlankPath(t *testing.T) {
	t.Parallel()

	_, err := NewFileStore(" \t\n ")
	if err == nil {
		t.Fatal("expected NewFileStore to reject blank path")
	}
	if !strings.Contains(err.Error(), "path is required") {
		t.Fatalf("expected required path error, got %v", err)
	}
}

func TestFileStoreAtomicPenaltyEvidenceWritePersistsSnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnslashing.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	evidence := types.SlashEvidence{
		EvidenceID:    "evidence-file-atomic-direct",
		ProviderID:    "provider-file-atomic-direct",
		SessionID:     "session-file-atomic-direct",
		ViolationType: "double-sign",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-file-atomic-direct"),
		Status:        chaintypes.ReconciliationConfirmed,
	}
	penalty := types.PenaltyDecision{
		PenaltyID:       "penalty-file-atomic-direct",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 25,
		Status:          chaintypes.ReconciliationSubmitted,
	}

	if err := store.UpsertPenaltyAndEvidenceWithError(penalty, evidence); err != nil {
		t.Fatalf("atomic penalty/evidence write failed: %v", err)
	}

	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopening file store returned unexpected error: %v", err)
	}

	gotEvidence, ok := reopened.GetEvidence(evidence.EvidenceID)
	if !ok {
		t.Fatal("expected atomically written evidence to be durable")
	}
	if gotEvidence != evidence {
		t.Fatalf("expected evidence %+v, got %+v", evidence, gotEvidence)
	}

	gotPenalty, ok := reopened.GetPenalty(penalty.PenaltyID)
	if !ok {
		t.Fatal("expected atomically written penalty to be durable")
	}
	if gotPenalty != penalty {
		t.Fatalf("expected penalty %+v, got %+v", penalty, gotPenalty)
	}
}

func TestFileStoreAtomicPenaltyEvidenceWriteRollsBackNewRecordsOnFailure(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnslashing.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	evidence := types.SlashEvidence{
		EvidenceID:    "evidence-file-atomic-new-failure",
		ProviderID:    "provider-file-atomic-new-failure",
		SessionID:     "session-file-atomic-new-failure",
		ViolationType: "double-sign",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-file-atomic-new-failure"),
		Status:        chaintypes.ReconciliationConfirmed,
	}
	penalty := types.PenaltyDecision{
		PenaltyID:       "penalty-file-atomic-new-failure",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 25,
		Status:          chaintypes.ReconciliationSubmitted,
	}

	store.persistFailureInjector = func() error {
		return errors.New("forced atomic write failure")
	}
	defer func() {
		store.persistFailureInjector = nil
	}()

	err = store.UpsertPenaltyAndEvidenceWithError(penalty, evidence)
	if err == nil {
		t.Fatal("expected atomic write failure")
	}

	if _, ok := store.GetEvidence(evidence.EvidenceID); ok {
		t.Fatal("expected failed atomic write to remove new evidence from memory")
	}
	if _, ok := store.GetPenalty(penalty.PenaltyID); ok {
		t.Fatal("expected failed atomic write to remove new penalty from memory")
	}

	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopening file store returned unexpected error: %v", err)
	}
	if _, ok := reopened.GetEvidence(evidence.EvidenceID); ok {
		t.Fatal("expected failed atomic write to leave no durable evidence")
	}
	if _, ok := reopened.GetPenalty(penalty.PenaltyID); ok {
		t.Fatal("expected failed atomic write to leave no durable penalty")
	}
}

func TestFileStoreAtomicPenaltyEvidenceWriteRestoresExistingRecordsOnFailure(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnslashing.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	originalEvidence := types.SlashEvidence{
		EvidenceID:    "evidence-file-atomic-existing-failure",
		ProviderID:    "provider-file-atomic-existing-failure",
		SessionID:     "session-file-atomic-existing-failure",
		ViolationType: "double-sign",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-file-atomic-existing-failure"),
		Status:        chaintypes.ReconciliationSubmitted,
	}
	originalPenalty := types.PenaltyDecision{
		PenaltyID:       "penalty-file-atomic-existing-failure",
		EvidenceID:      originalEvidence.EvidenceID,
		SlashBasisPoint: 10,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertEvidence(originalEvidence)
	store.UpsertPenalty(originalPenalty)

	updatedEvidence := originalEvidence
	updatedEvidence.Status = chaintypes.ReconciliationConfirmed
	updatedPenalty := originalPenalty
	updatedPenalty.SlashBasisPoint = 15

	store.persistFailureInjector = func() error {
		return errors.New("forced atomic rewrite failure")
	}
	defer func() {
		store.persistFailureInjector = nil
	}()

	err = store.UpsertPenaltyAndEvidenceWithError(updatedPenalty, updatedEvidence)
	if err == nil {
		t.Fatal("expected atomic rewrite failure")
	}

	gotEvidence, ok := store.GetEvidence(originalEvidence.EvidenceID)
	if !ok {
		t.Fatal("expected original evidence to remain in memory")
	}
	if gotEvidence != originalEvidence {
		t.Fatalf("expected original evidence %+v after rollback, got %+v", originalEvidence, gotEvidence)
	}

	gotPenalty, ok := store.GetPenalty(originalPenalty.PenaltyID)
	if !ok {
		t.Fatal("expected original penalty to remain in memory")
	}
	if gotPenalty != originalPenalty {
		t.Fatalf("expected original penalty %+v after rollback, got %+v", originalPenalty, gotPenalty)
	}

	store.persistFailureInjector = nil
	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopening file store returned unexpected error: %v", err)
	}

	durableEvidence, ok := reopened.GetEvidence(originalEvidence.EvidenceID)
	if !ok {
		t.Fatal("expected original evidence to remain durable")
	}
	if durableEvidence != originalEvidence {
		t.Fatalf("expected durable evidence %+v, got %+v", originalEvidence, durableEvidence)
	}

	durablePenalty, ok := reopened.GetPenalty(originalPenalty.PenaltyID)
	if !ok {
		t.Fatal("expected original penalty to remain durable")
	}
	if durablePenalty != originalPenalty {
		t.Fatalf("expected durable penalty %+v, got %+v", originalPenalty, durablePenalty)
	}
}

func TestFileStoreListEvidenceAndPenaltiesAcrossReopen(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnslashing.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	evidenceA := types.SlashEvidence{
		EvidenceID:    "evidence-file-a",
		ProviderID:    "provider-a",
		SessionID:     "session-a",
		ViolationType: "double-sign",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-a"),
		Status:        chaintypes.ReconciliationPending,
	}
	evidenceB := types.SlashEvidence{
		EvidenceID:    "evidence-file-b",
		ProviderID:    "provider-b",
		SessionID:     "session-b",
		ViolationType: "downtime-proof",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-b"),
		Status:        chaintypes.ReconciliationSubmitted,
	}
	penaltyA := types.PenaltyDecision{
		PenaltyID:       "penalty-file-a",
		EvidenceID:      evidenceA.EvidenceID,
		SlashBasisPoint: 10,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	penaltyB := types.PenaltyDecision{
		PenaltyID:       "penalty-file-b",
		EvidenceID:      evidenceB.EvidenceID,
		SlashBasisPoint: 25,
		Status:          chaintypes.ReconciliationConfirmed,
	}

	store.UpsertEvidence(evidenceA)
	store.UpsertEvidence(evidenceB)
	store.UpsertPenalty(penaltyA)
	store.UpsertPenalty(penaltyB)

	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopening file store returned unexpected error: %v", err)
	}

	evidenceList := reopened.ListEvidence()
	if len(evidenceList) != 2 {
		t.Fatalf("expected 2 evidence entries after reopen, got %d", len(evidenceList))
	}
	evidenceByID := make(map[string]types.SlashEvidence, len(evidenceList))
	for _, record := range evidenceList {
		evidenceByID[record.EvidenceID] = record
	}
	if evidenceByID[evidenceA.EvidenceID] != evidenceA {
		t.Fatalf("expected evidence %q to round-trip through list", evidenceA.EvidenceID)
	}
	if evidenceByID[evidenceB.EvidenceID] != evidenceB {
		t.Fatalf("expected evidence %q to round-trip through list", evidenceB.EvidenceID)
	}

	penaltyList := reopened.ListPenalties()
	if len(penaltyList) != 2 {
		t.Fatalf("expected 2 penalty entries after reopen, got %d", len(penaltyList))
	}
	penaltyByID := make(map[string]types.PenaltyDecision, len(penaltyList))
	for _, record := range penaltyList {
		penaltyByID[record.PenaltyID] = record
	}
	if penaltyByID[penaltyA.PenaltyID] != penaltyA {
		t.Fatalf("expected penalty %q to round-trip through list", penaltyA.PenaltyID)
	}
	if penaltyByID[penaltyB.PenaltyID] != penaltyB {
		t.Fatalf("expected penalty %q to round-trip through list", penaltyB.PenaltyID)
	}
}

func TestNewFileStoreWhitespaceSeedInitializesEmptyState(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnslashing.json")
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		t.Fatalf("failed creating store dir: %v", err)
	}
	if err := os.WriteFile(storePath, []byte(" \n\t "), 0o644); err != nil {
		t.Fatalf("failed seeding whitespace state file: %v", err)
	}

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore with whitespace seed returned unexpected error: %v", err)
	}

	if got := len(store.ListEvidence()); got != 0 {
		t.Fatalf("expected empty evidence list for whitespace seed, got %d", got)
	}
	if got := len(store.ListPenalties()); got != 0 {
		t.Fatalf("expected empty penalty list for whitespace seed, got %d", got)
	}

	payload, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("failed reading persisted store file: %v", err)
	}
	content := string(payload)
	if !strings.Contains(content, "\"evidence\"") || !strings.Contains(content, "\"penalties\"") {
		t.Fatalf("expected initialized file to contain store keys, got: %s", content)
	}
}

func TestNewFileStoreInvalidJSON(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnslashing.json")
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		t.Fatalf("failed creating store dir: %v", err)
	}
	if err := os.WriteFile(storePath, []byte("{bad-json"), 0o644); err != nil {
		t.Fatalf("failed seeding invalid JSON file: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected NewFileStore to fail with invalid JSON state")
	}
}
