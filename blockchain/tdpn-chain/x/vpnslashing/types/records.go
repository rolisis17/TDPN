package types

import (
	"errors"
	"strings"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

const (
	// EvidenceKindObjective marks machine-verifiable evidence accepted in v1.
	EvidenceKindObjective = "objective"
	maxEvidenceIDLength   = 128
	maxProviderIDLength   = 128
	maxSessionIDLength    = 128
	maxViolationTypeLen   = 64
	maxProofHashLength    = 1024
	maxPenaltyIDLength    = 128
)

var objectiveViolationTypeSet = map[string]struct{}{
	"double-sign":              {},
	"downtime-proof":           {},
	"invalid-settlement-proof": {},
	"session-replay-proof":     {},
	"sponsor-overdraft-proof":  {},
}

// NormalizeViolationType canonicalizes violation type input for validation/storage.
func NormalizeViolationType(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// CanonicalObjectiveEvidenceIdentity returns a canonical identity key for
// machine-verifiable incidents so equivalent case/whitespace variants
// cannot be replayed under a different EvidenceID.
func CanonicalObjectiveEvidenceIdentity(record SlashEvidence) string {
	parts := []string{
		canonicalObjectiveIdentityToken(record.Kind),
		canonicalObjectiveIdentityToken(record.ProviderID),
		canonicalObjectiveIdentityToken(record.SessionID),
		canonicalObjectiveIdentityToken(NormalizeViolationType(record.ViolationType)),
		canonicalObjectiveIdentityToken(record.ProofHash),
	}
	return strings.Join(parts, "|")
}

func canonicalObjectiveIdentityToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// SlashEvidence represents objective evidence submitted for deterministic slashing.
type SlashEvidence struct {
	EvidenceID      string
	SessionID       string
	ProviderID      string
	ViolationType   string
	Kind            string
	ProofHash       string
	SubmittedAtUnix int64
	Status          chaintypes.ReconciliationStatus
}

// PenaltyDecision captures slash/jail intent generated from verified evidence.
type PenaltyDecision struct {
	PenaltyID       string
	EvidenceID      string
	SlashBasisPoint uint32
	Jailed          bool
	AppliedAtUnix   int64
	Status          chaintypes.ReconciliationStatus
}

func (e SlashEvidence) ValidateBasic() error {
	evidenceID := strings.TrimSpace(e.EvidenceID)
	if evidenceID == "" {
		return errors.New("evidence id is required")
	}
	if len(evidenceID) > maxEvidenceIDLength {
		return errors.New("evidence id exceeds 128 characters")
	}
	if providerID := strings.TrimSpace(e.ProviderID); providerID != "" && len(providerID) > maxProviderIDLength {
		return errors.New("provider id exceeds 128 characters")
	}
	if sessionID := strings.TrimSpace(e.SessionID); sessionID != "" && len(sessionID) > maxSessionIDLength {
		return errors.New("session id exceeds 128 characters")
	}
	if e.Kind != EvidenceKindObjective {
		return errors.New("evidence kind must be objective")
	}
	proofHash := strings.TrimSpace(e.ProofHash)
	if proofHash == "" {
		return errors.New("proof hash is required")
	}
	if len(proofHash) > maxProofHashLength {
		return errors.New("proof hash exceeds 1024 characters")
	}
	if !chaintypes.IsObjectiveEvidenceFormat(proofHash) {
		return errors.New("proof hash must use objective format (sha256:<value> or obj://<value>)")
	}
	canonicalViolationType := NormalizeViolationType(e.ViolationType)
	if canonicalViolationType == "" {
		return errors.New("violation type is required")
	}
	if len(canonicalViolationType) > maxViolationTypeLen {
		return errors.New("violation type exceeds 64 characters")
	}
	if _, ok := objectiveViolationTypeSet[canonicalViolationType]; !ok {
		return errors.New("violation type must be one of: double-sign, downtime-proof, invalid-settlement-proof, session-replay-proof, sponsor-overdraft-proof")
	}
	return nil
}

func (d PenaltyDecision) ValidateBasic() error {
	penaltyID := strings.TrimSpace(d.PenaltyID)
	if penaltyID == "" {
		return errors.New("penalty id is required")
	}
	if len(penaltyID) > maxPenaltyIDLength {
		return errors.New("penalty id exceeds 128 characters")
	}
	evidenceID := strings.TrimSpace(d.EvidenceID)
	if evidenceID == "" {
		return errors.New("evidence id is required")
	}
	if len(evidenceID) > maxEvidenceIDLength {
		return errors.New("evidence id exceeds 128 characters")
	}
	if d.SlashBasisPoint > 10000 {
		return errors.New("slash basis points cannot exceed 10000")
	}
	return nil
}
