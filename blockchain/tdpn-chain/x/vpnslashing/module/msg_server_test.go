package module

import (
	"errors"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

func TestMsgServerSubmitSlashEvidenceHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := SubmitSlashEvidenceRequest{
		Evidence: types.SlashEvidence{
			EvidenceID: "evidence-msg-1",
			Kind:       types.EvidenceKindObjective,
			ProofHash:  "sha256:proof-msg-1",
		},
	}

	resp, err := server.SubmitSlashEvidence(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first evidence submit")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first evidence submit")
	}
	if resp.Evidence.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default evidence status %q, got %q", chaintypes.ReconciliationSubmitted, resp.Evidence.Status)
	}
}

func TestMsgServerSubmitSlashEvidenceIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := SubmitSlashEvidenceRequest{
		Evidence: types.SlashEvidence{
			EvidenceID: "evidence-msg-2",
			Kind:       types.EvidenceKindObjective,
			ProofHash:  "sha256:proof-msg-2",
		},
	}
	if _, err := server.SubmitSlashEvidence(req); err != nil {
		t.Fatalf("first submit failed: %v", err)
	}

	resp, err := server.SubmitSlashEvidence(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed evidence submit")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed evidence submit")
	}
}

func TestMsgServerSubmitSlashEvidenceConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	base := SubmitSlashEvidenceRequest{
		Evidence: types.SlashEvidence{
			EvidenceID: "evidence-msg-3",
			Kind:       types.EvidenceKindObjective,
			ProofHash:  "sha256:proof-msg-3",
		},
	}
	if _, err := server.SubmitSlashEvidence(base); err != nil {
		t.Fatalf("seed submit failed: %v", err)
	}

	conflict := base
	conflict.Evidence.ProofHash = "sha256:proof-msg-3-b"
	resp, err := server.SubmitSlashEvidence(conflict)
	if err == nil {
		t.Fatal("expected evidence conflict error")
	}
	if !errors.Is(err, ErrEvidenceConflict) {
		t.Fatalf("expected ErrEvidenceConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerSubmitSlashEvidenceInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.SubmitSlashEvidence(SubmitSlashEvidenceRequest{
		Evidence: types.SlashEvidence{
			EvidenceID: "",
			Kind:       types.EvidenceKindObjective,
			ProofHash:  "sha256:proof-msg-invalid",
		},
	})
	if err == nil {
		t.Fatal("expected invalid evidence error")
	}
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("expected ErrInvalidEvidence, got %v", err)
	}
}

func TestMsgServerSubmitSlashEvidenceInvalidProofFormatPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.SubmitSlashEvidence(SubmitSlashEvidenceRequest{
		Evidence: types.SlashEvidence{
			EvidenceID: "evidence-msg-invalid-proof",
			Kind:       types.EvidenceKindObjective,
			ProofHash:  "legacy-proof",
		},
	})
	if err == nil {
		t.Fatal("expected invalid evidence error")
	}
	if !errors.Is(err, ErrInvalidEvidence) {
		t.Fatalf("expected ErrInvalidEvidence, got %v", err)
	}
}

func TestMsgServerApplyPenaltyHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.SubmitSlashEvidence(SubmitSlashEvidenceRequest{
		Evidence: types.SlashEvidence{
			EvidenceID: "evidence-msg-4",
			Kind:       types.EvidenceKindObjective,
			ProofHash:  "sha256:proof-msg-4",
		},
	}); err != nil {
		t.Fatalf("submit evidence failed: %v", err)
	}

	resp, err := server.ApplyPenalty(ApplyPenaltyRequest{
		Penalty: types.PenaltyDecision{
			PenaltyID:       "penalty-msg-4",
			EvidenceID:      "evidence-msg-4",
			SlashBasisPoint: 120,
		},
	})
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first penalty apply")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first penalty apply")
	}
	if resp.Penalty.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default penalty status %q, got %q", chaintypes.ReconciliationSubmitted, resp.Penalty.Status)
	}
}

func TestMsgServerApplyPenaltyIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.SubmitSlashEvidence(SubmitSlashEvidenceRequest{
		Evidence: types.SlashEvidence{
			EvidenceID: "evidence-msg-5",
			Kind:       types.EvidenceKindObjective,
			ProofHash:  "sha256:proof-msg-5",
		},
	}); err != nil {
		t.Fatalf("submit evidence failed: %v", err)
	}

	req := ApplyPenaltyRequest{
		Penalty: types.PenaltyDecision{
			PenaltyID:       "penalty-msg-5",
			EvidenceID:      "evidence-msg-5",
			SlashBasisPoint: 50,
		},
	}
	if _, err := server.ApplyPenalty(req); err != nil {
		t.Fatalf("first apply failed: %v", err)
	}

	resp, err := server.ApplyPenalty(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed penalty apply")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed penalty apply")
	}
}

func TestMsgServerApplyPenaltyConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.SubmitSlashEvidence(SubmitSlashEvidenceRequest{
		Evidence: types.SlashEvidence{
			EvidenceID: "evidence-msg-6",
			Kind:       types.EvidenceKindObjective,
			ProofHash:  "sha256:proof-msg-6",
		},
	}); err != nil {
		t.Fatalf("submit evidence failed: %v", err)
	}

	base := ApplyPenaltyRequest{
		Penalty: types.PenaltyDecision{
			PenaltyID:       "penalty-msg-6",
			EvidenceID:      "evidence-msg-6",
			SlashBasisPoint: 80,
		},
	}
	if _, err := server.ApplyPenalty(base); err != nil {
		t.Fatalf("first apply failed: %v", err)
	}

	conflict := base
	conflict.Penalty.SlashBasisPoint = 81
	resp, err := server.ApplyPenalty(conflict)
	if err == nil {
		t.Fatal("expected penalty conflict error")
	}
	if !errors.Is(err, ErrPenaltyConflict) {
		t.Fatalf("expected ErrPenaltyConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerApplyPenaltyInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.ApplyPenalty(ApplyPenaltyRequest{
		Penalty: types.PenaltyDecision{
			PenaltyID:       "penalty-msg-invalid",
			EvidenceID:      "evidence-msg-invalid",
			SlashBasisPoint: 10001,
		},
	})
	if err == nil {
		t.Fatal("expected invalid penalty error")
	}
	if !errors.Is(err, ErrInvalidPenalty) {
		t.Fatalf("expected ErrInvalidPenalty, got %v", err)
	}
}

func TestMsgServerApplyPenaltyMissingEvidencePropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.ApplyPenalty(ApplyPenaltyRequest{
		Penalty: types.PenaltyDecision{
			PenaltyID:       "penalty-msg-missing",
			EvidenceID:      "evidence-does-not-exist",
			SlashBasisPoint: 10,
		},
	})
	if err == nil {
		t.Fatal("expected missing evidence error")
	}
	if !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("expected ErrEvidenceNotFound, got %v", err)
	}
}

func TestMsgServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewMsgServer(k)

	_, evidenceErr := server.SubmitSlashEvidence(SubmitSlashEvidenceRequest{
		Evidence: types.SlashEvidence{
			EvidenceID: "evidence-msg-nil",
			Kind:       types.EvidenceKindObjective,
			ProofHash:  "sha256:proof-msg-nil",
		},
	})
	if !errors.Is(evidenceErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on evidence submit, got %v", evidenceErr)
	}

	_, penaltyErr := server.ApplyPenalty(ApplyPenaltyRequest{
		Penalty: types.PenaltyDecision{
			PenaltyID:       "penalty-msg-nil",
			EvidenceID:      "evidence-msg-nil",
			SlashBasisPoint: 1,
		},
	})
	if !errors.Is(penaltyErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on penalty apply, got %v", penaltyErr)
	}
}
