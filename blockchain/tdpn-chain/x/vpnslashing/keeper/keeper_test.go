package keeper

import (
	"fmt"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

func TestKeeperEvidenceUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetEvidence("missing"); ok {
		t.Fatal("expected missing evidence lookup to return ok=false")
	}

	initial := types.SlashEvidence{
		EvidenceID:    "evidence-1",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-1"),
		ViolationType: "  DOUBLE-SIGN ",
	}
	k.UpsertEvidence(initial)

	got, ok := k.GetEvidence(initial.EvidenceID)
	if !ok {
		t.Fatal("expected inserted evidence to be found")
	}
	if got.ProofHash != initial.ProofHash {
		t.Fatalf("expected proof hash %q, got %q", initial.ProofHash, got.ProofHash)
	}
	if got.ViolationType != "double-sign" {
		t.Fatalf("expected canonical violation type %q, got %q", "double-sign", got.ViolationType)
	}

	updated := initial
	updated.ProofHash = testSHAProof("proof-2")
	k.UpsertEvidence(updated)

	got, ok = k.GetEvidence(initial.EvidenceID)
	if !ok {
		t.Fatal("expected updated evidence to be found")
	}
	if got.ProofHash != updated.ProofHash {
		t.Fatalf("expected updated proof hash %q, got %q", updated.ProofHash, got.ProofHash)
	}
}

func TestKeeperPenaltyUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetPenalty("missing"); ok {
		t.Fatal("expected missing penalty lookup to return ok=false")
	}

	initial := types.PenaltyDecision{
		PenaltyID:       "penalty-1",
		EvidenceID:      "evidence-1",
		SlashBasisPoint: 100,
	}
	k.UpsertPenalty(initial)

	got, ok := k.GetPenalty(initial.PenaltyID)
	if !ok {
		t.Fatal("expected inserted penalty to be found")
	}
	if got.SlashBasisPoint != initial.SlashBasisPoint {
		t.Fatalf("expected slash basis point %d, got %d", initial.SlashBasisPoint, got.SlashBasisPoint)
	}

	updated := initial
	updated.SlashBasisPoint = 250
	k.UpsertPenalty(updated)

	got, ok = k.GetPenalty(initial.PenaltyID)
	if !ok {
		t.Fatal("expected updated penalty to be found")
	}
	if got.SlashBasisPoint != updated.SlashBasisPoint {
		t.Fatalf("expected updated slash basis point %d, got %d", updated.SlashBasisPoint, got.SlashBasisPoint)
	}
}

func TestKeeperListEvidenceDeterministicOrderByID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID: "evidence-c",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-c"),
	})
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID: "evidence-a",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-a"),
	})
	k.UpsertEvidence(types.SlashEvidence{
		EvidenceID: "evidence-b",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-b"),
	})

	list := k.ListEvidence()
	if len(list) != 3 {
		t.Fatalf("expected 3 evidence records, got %d", len(list))
	}

	if list[0].EvidenceID != "evidence-a" || list[1].EvidenceID != "evidence-b" || list[2].EvidenceID != "evidence-c" {
		t.Fatalf("expected sorted evidence IDs [evidence-a evidence-b evidence-c], got [%s %s %s]", list[0].EvidenceID, list[1].EvidenceID, list[2].EvidenceID)
	}
}

func TestKeeperListPenaltiesDeterministicOrderByID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-c",
		EvidenceID:      "evidence-1",
		SlashBasisPoint: 10,
	})
	k.UpsertPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-a",
		EvidenceID:      "evidence-2",
		SlashBasisPoint: 20,
	})
	k.UpsertPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-b",
		EvidenceID:      "evidence-3",
		SlashBasisPoint: 30,
	})

	list := k.ListPenalties()
	if len(list) != 3 {
		t.Fatalf("expected 3 penalty records, got %d", len(list))
	}

	if list[0].PenaltyID != "penalty-a" || list[1].PenaltyID != "penalty-b" || list[2].PenaltyID != "penalty-c" {
		t.Fatalf("expected sorted penalty IDs [penalty-a penalty-b penalty-c], got [%s %s %s]", list[0].PenaltyID, list[1].PenaltyID, list[2].PenaltyID)
	}
}

func TestSubmitEvidenceDefaultsAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	record, err := k.SubmitEvidence(types.SlashEvidence{
		EvidenceID: "evidence-submit-1",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-submit-1"),
	})
	if err != nil {
		t.Fatalf("expected submit evidence to succeed, got %v", err)
	}
	if record.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationSubmitted, record.Status)
	}

	got, ok := k.GetEvidence(record.EvidenceID)
	if !ok {
		t.Fatal("expected submitted evidence to be stored")
	}
	if got.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected stored status %q, got %q", chaintypes.ReconciliationSubmitted, got.Status)
	}
}

func TestSubmitEvidenceIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	base := types.SlashEvidence{
		EvidenceID: "evidence-submit-2",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-submit-2"),
	}

	first, err := k.SubmitEvidence(base)
	if err != nil {
		t.Fatalf("first submit failed: %v", err)
	}
	second, err := k.SubmitEvidence(base)
	if err != nil {
		t.Fatalf("replayed submit failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected replay to return identical record, first=%+v second=%+v", first, second)
	}
}

func TestSubmitEvidenceConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	base := types.SlashEvidence{
		EvidenceID: "evidence-submit-3",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-a"),
	}
	if _, err := k.SubmitEvidence(base); err != nil {
		t.Fatalf("seed evidence failed: %v", err)
	}

	conflict := base
	conflict.ProofHash = testSHAProof("proof-b")
	_, err := k.SubmitEvidence(conflict)
	if err == nil {
		t.Fatal("expected conflicting submit to fail")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestSubmitEvidenceConflictOnViolationTypeChange(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	base := types.SlashEvidence{
		EvidenceID:    "evidence-submit-violation-type-conflict",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-violation-type-a"),
		ViolationType: "double-sign",
	}
	if _, err := k.SubmitEvidence(base); err != nil {
		t.Fatalf("seed evidence failed: %v", err)
	}

	conflict := base
	conflict.ViolationType = "downtime-proof"
	_, err := k.SubmitEvidence(conflict)
	if err == nil {
		t.Fatal("expected conflicting submit to fail")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestSubmitEvidenceCanonicalizesViolationTypeAndEquivalentReplay(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	base := types.SlashEvidence{
		EvidenceID:    "evidence-submit-violation-type-canonical",
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-violation-type-canonical"),
		ViolationType: "  SESSION-REPLAY-PROOF \n",
	}

	first, err := k.SubmitEvidence(base)
	if err != nil {
		t.Fatalf("first submit failed: %v", err)
	}
	if first.ViolationType != "session-replay-proof" {
		t.Fatalf("expected canonical violation type %q, got %q", "session-replay-proof", first.ViolationType)
	}

	stored, ok := k.GetEvidence(base.EvidenceID)
	if !ok {
		t.Fatalf("expected stored evidence %q", base.EvidenceID)
	}
	if stored.ViolationType != "session-replay-proof" {
		t.Fatalf("expected stored canonical violation type %q, got %q", "session-replay-proof", stored.ViolationType)
	}

	replay := base
	replay.ViolationType = "\tsession-replay-proof  "
	second, err := k.SubmitEvidence(replay)
	if err != nil {
		t.Fatalf("equivalent replay submit failed: %v", err)
	}
	if second != first {
		t.Fatalf("expected equivalent replay to be idempotent, first=%+v second=%+v", first, second)
	}
}

func TestSubmitEvidenceInvalid(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.SubmitEvidence(types.SlashEvidence{
		Kind:      types.EvidenceKindObjective,
		ProofHash: testSHAProof("proof-invalid"),
	})
	if err == nil {
		t.Fatal("expected invalid evidence to fail")
	}
}

func TestSubmitEvidenceInvalidViolationType(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	evidenceID := "evidence-invalid-violation-type"
	_, err := k.SubmitEvidence(types.SlashEvidence{
		EvidenceID:    evidenceID,
		Kind:          types.EvidenceKindObjective,
		ProofHash:     testSHAProof("proof-invalid-violation-type"),
		ViolationType: "manual-review-only",
	})
	if err == nil {
		t.Fatal("expected invalid violation type to fail")
	}
	if !strings.Contains(err.Error(), "violation type must be one of") {
		t.Fatalf("expected violation type validation error, got %v", err)
	}
	if _, ok := k.GetEvidence(evidenceID); ok {
		t.Fatalf("expected invalid evidence %q to not be stored", evidenceID)
	}
}

func TestSubmitEvidenceInvalidProofFormat(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.SubmitEvidence(types.SlashEvidence{
		EvidenceID: "evidence-invalid-proof-format",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  "legacy-proof-format",
	})
	if err == nil {
		t.Fatal("expected invalid evidence to fail")
	}
}

func TestSubmitEvidenceInvalidProofFormats(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	invalidProofs := []string{
		"sha-256:proof",
		"object://bucket/key",
		"sha256/proof",
		"obj:/bucket/key",
		"sha256:\t ",
		"obj://   ",
	}

	for idx, proof := range invalidProofs {
		evidenceID := fmt.Sprintf("evidence-invalid-proof-%d", idx)
		_, err := k.SubmitEvidence(types.SlashEvidence{
			EvidenceID: evidenceID,
			Kind:       types.EvidenceKindObjective,
			ProofHash:  proof,
		})
		if err == nil {
			t.Fatalf("expected invalid evidence to fail for proof %q", proof)
		}
		if !strings.Contains(err.Error(), "proof hash must use objective format") {
			t.Fatalf("expected objective proof format error for proof %q, got %v", proof, err)
		}
		if _, ok := k.GetEvidence(evidenceID); ok {
			t.Fatalf("expected invalid evidence %q to not be stored", evidenceID)
		}
	}
}

func TestSubmitEvidenceReplayThenConflictOnProofHashChange(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	base := types.SlashEvidence{
		EvidenceID: "evidence-replay-conflict",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  "obj://bucket/path/replay-conflict",
	}

	first, err := k.SubmitEvidence(base)
	if err != nil {
		t.Fatalf("first submit failed: %v", err)
	}
	replay, err := k.SubmitEvidence(base)
	if err != nil {
		t.Fatalf("replay submit failed: %v", err)
	}
	if replay != first {
		t.Fatalf("expected replay to be idempotent, first=%+v replay=%+v", first, replay)
	}

	conflict := base
	conflict.ProofHash = testSHAProof("replay-conflict-updated")
	_, err = k.SubmitEvidence(conflict)
	if err == nil {
		t.Fatal("expected proof hash change conflict")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestApplyPenaltyDefaultsAndEvidenceAdvance(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	seed, err := k.SubmitEvidence(types.SlashEvidence{
		EvidenceID: "evidence-penalty-1",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-penalty-1"),
		Status:     chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("seed evidence failed: %v", err)
	}
	if seed.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected seed status pending, got %q", seed.Status)
	}

	decision, err := k.ApplyPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-apply-1",
		EvidenceID:      seed.EvidenceID,
		SlashBasisPoint: 100,
	})
	if err != nil {
		t.Fatalf("expected apply penalty to succeed, got %v", err)
	}
	if decision.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default penalty status %q, got %q", chaintypes.ReconciliationSubmitted, decision.Status)
	}

	evidenceAfter, ok := k.GetEvidence(seed.EvidenceID)
	if !ok {
		t.Fatal("expected evidence to remain available")
	}
	if evidenceAfter.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected evidence status %q after penalty, got %q", chaintypes.ReconciliationConfirmed, evidenceAfter.Status)
	}
}

func TestApplyPenaltyIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	evidence, err := k.SubmitEvidence(types.SlashEvidence{
		EvidenceID: "evidence-penalty-2",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-penalty-2"),
	})
	if err != nil {
		t.Fatalf("seed evidence failed: %v", err)
	}

	req := types.PenaltyDecision{
		PenaltyID:       "penalty-apply-2",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 55,
	}

	first, err := k.ApplyPenalty(req)
	if err != nil {
		t.Fatalf("first apply failed: %v", err)
	}
	second, err := k.ApplyPenalty(req)
	if err != nil {
		t.Fatalf("replayed apply failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected replay to return identical penalty, first=%+v second=%+v", first, second)
	}
}

func TestApplyPenaltyRejectsSecondPenaltyForSameEvidence(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	evidence, err := k.SubmitEvidence(types.SlashEvidence{
		EvidenceID: "evidence-penalty-2b",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-penalty-2b"),
	})
	if err != nil {
		t.Fatalf("seed evidence failed: %v", err)
	}

	first := types.PenaltyDecision{
		PenaltyID:       "penalty-apply-2b-a",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 60,
	}
	if _, err := k.ApplyPenalty(first); err != nil {
		t.Fatalf("first apply failed: %v", err)
	}

	second := types.PenaltyDecision{
		PenaltyID:       "penalty-apply-2b-b",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 60,
	}
	_, err = k.ApplyPenalty(second)
	if err == nil {
		t.Fatal("expected second penalty on same evidence to fail")
	}
	if !strings.Contains(err.Error(), "already has penalty") {
		t.Fatalf("expected evidence conflict error, got %v", err)
	}

	penalties := k.ListPenalties()
	if len(penalties) != 1 {
		t.Fatalf("expected only one penalty to be stored, got %d", len(penalties))
	}
	if penalties[0].PenaltyID != first.PenaltyID {
		t.Fatalf("expected stored penalty %q, got %q", first.PenaltyID, penalties[0].PenaltyID)
	}
}

func TestApplyPenaltyConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	evidence, err := k.SubmitEvidence(types.SlashEvidence{
		EvidenceID: "evidence-penalty-3",
		Kind:       types.EvidenceKindObjective,
		ProofHash:  testSHAProof("proof-penalty-3"),
	})
	if err != nil {
		t.Fatalf("seed evidence failed: %v", err)
	}

	base := types.PenaltyDecision{
		PenaltyID:       "penalty-apply-3",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 10,
	}
	if _, err := k.ApplyPenalty(base); err != nil {
		t.Fatalf("seed penalty failed: %v", err)
	}

	conflict := base
	conflict.SlashBasisPoint = 11
	_, err = k.ApplyPenalty(conflict)
	if err == nil {
		t.Fatal("expected conflicting penalty to fail")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestApplyPenaltyInvalid(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.ApplyPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-invalid-1",
		EvidenceID:      "evidence-invalid-1",
		SlashBasisPoint: 10001,
	})
	if err == nil {
		t.Fatal("expected invalid penalty to fail")
	}
}

func TestApplyPenaltyMissingEvidence(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.ApplyPenalty(types.PenaltyDecision{
		PenaltyID:       "penalty-missing-evidence",
		EvidenceID:      "does-not-exist",
		SlashBasisPoint: 100,
	})
	if err == nil {
		t.Fatal("expected missing evidence error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing evidence error, got %v", err)
	}
}
