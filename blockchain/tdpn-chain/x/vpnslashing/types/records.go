package types

import (
	"errors"
	"strings"
	"unicode"

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
	proof = strings.TrimSpace(proof)

	if strings.HasPrefix(proof, sha256Prefix) {
		hash := strings.TrimPrefix(proof, sha256Prefix)
		return isValidSHA256Hex(hash)
	}
	if strings.HasPrefix(proof, objectPrefix) {
		path := strings.TrimPrefix(proof, objectPrefix)
		if path == "" {
			return false
		}
		for _, r := range path {
			if unicode.IsSpace(r) {
				return false
			}
		}
		return true
	}
	return false
}

func isValidSHA256Hex(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, r := range hash {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}
