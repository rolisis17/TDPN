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

// SlashEvidence represents objective evidence submitted for deterministic slashing.
type SlashEvidence struct {
	EvidenceID      string
	SessionID       string
	ProviderID      string
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
	if !isObjectiveProofFormat(e.ProofHash) {
		return errors.New("proof hash must use objective format (sha256:<value> or obj://<value>)")
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

func isObjectiveProofFormat(proof string) bool {
	const (
		sha256Prefix = "sha256:"
		objectPrefix = "obj://"
	)

	if strings.HasPrefix(proof, sha256Prefix) {
		return strings.TrimSpace(strings.TrimPrefix(proof, sha256Prefix)) != ""
	}
	if strings.HasPrefix(proof, objectPrefix) {
		return strings.TrimSpace(strings.TrimPrefix(proof, objectPrefix)) != ""
	}
	return false
}
