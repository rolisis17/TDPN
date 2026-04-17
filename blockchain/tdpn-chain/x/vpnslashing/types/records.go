package types

import (
	"errors"
	"strings"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

const (
	// EvidenceKindObjective marks machine-verifiable evidence accepted in v1.
	EvidenceKindObjective = "objective"
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
	if e.EvidenceID == "" {
		return errors.New("evidence id is required")
	}
	if e.Kind != EvidenceKindObjective {
		return errors.New("evidence kind must be objective")
	}
	if e.ProofHash == "" {
		return errors.New("proof hash is required")
	}
	if !chaintypes.IsObjectiveEvidenceFormat(e.ProofHash) {
		return errors.New("proof hash must use objective format (sha256:<value> or obj://<value>)")
	}
	if canonicalViolationType := NormalizeViolationType(e.ViolationType); canonicalViolationType != "" {
		if _, ok := objectiveViolationTypeSet[canonicalViolationType]; !ok {
			return errors.New("violation type must be one of: double-sign, downtime-proof, invalid-settlement-proof, session-replay-proof, sponsor-overdraft-proof")
		}
	}
	return nil
}

func (d PenaltyDecision) ValidateBasic() error {
	if d.PenaltyID == "" {
		return errors.New("penalty id is required")
	}
	if d.EvidenceID == "" {
		return errors.New("evidence id is required")
	}
	if d.SlashBasisPoint > 10000 {
		return errors.New("slash basis points cannot exceed 10000")
	}
	return nil
}
