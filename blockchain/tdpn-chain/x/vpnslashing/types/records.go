package types

import (
	"errors"
	"net/url"
	"strings"
	"unicode"

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
	maxSlashDenomLength   = 64
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

// NormalizeEvidenceID canonicalizes evidence identifiers for storage and lookup.
func NormalizeEvidenceID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// NormalizeProviderID canonicalizes provider identifiers for storage, lookup,
// and slash-hold matching.
func NormalizeProviderID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// NormalizeSessionID canonicalizes session identifiers for storage, lookup,
// and slash-hold matching.
func NormalizeSessionID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// NormalizePenaltyID canonicalizes penalty identifiers for storage and lookup.
func NormalizePenaltyID(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// NormalizeSlashDenom canonicalizes slash currency/denom input for storage.
func NormalizeSlashDenom(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// CanonicalObjectiveEvidenceIdentity returns a canonical identity key for
// machine-verifiable incidents so equivalent case/whitespace variants
// cannot be replayed under a different EvidenceID.
func CanonicalObjectiveEvidenceIdentity(record SlashEvidence) string {
	parts := []string{
		canonicalObjectiveIdentityToken(record.Kind),
		NormalizeProviderID(record.ProviderID),
		NormalizeSessionID(record.SessionID),
		canonicalObjectiveIdentityToken(NormalizeViolationType(record.ViolationType)),
		canonicalObjectiveIdentityToken(CanonicalObjectiveEvidenceProofRef(record.ProofHash)),
	}
	return strings.Join(parts, "|")
}

// CanonicalObjectiveEvidenceProofRef unwraps bridge amount/currency metadata
// so duplicate incident detection remains keyed by the objective proof.
func CanonicalObjectiveEvidenceProofRef(value string) string {
	value = strings.TrimSpace(value)
	if unwrapped, ok := bridgeWrappedEvidenceRef(value); ok {
		return unwrapped
	}
	return value
}

func bridgeWrappedEvidenceRef(value string) (string, bool) {
	parsed, err := url.Parse(value)
	if err != nil {
		return "", false
	}
	if !strings.EqualFold(parsed.Scheme, "obj") || !strings.EqualFold(parsed.Host, "settlement-slash") {
		return "", false
	}
	evidenceRef := strings.TrimSpace(parsed.Query().Get("evidence_ref"))
	if evidenceRef == "" {
		return "", false
	}
	return evidenceRef, true
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
	SlashAmount     int64
	SlashDenom      string
	SubmittedAtUnix int64
	Status          chaintypes.ReconciliationStatus
}

// PenaltyDecision captures slash/jail intent generated from verified evidence.
// SlashBasisPoint remains valid for stake-relative slashing; SlashAmount and
// SlashDenom are required only when a concrete token-denominated slash is set.
type PenaltyDecision struct {
	PenaltyID       string
	EvidenceID      string
	SlashBasisPoint uint32
	SlashAmount     int64
	SlashDenom      string
	Jailed          bool
	AppliedAtUnix   int64
	Status          chaintypes.ReconciliationStatus
}

func (e SlashEvidence) ValidateBasic() error {
	evidenceID := NormalizeEvidenceID(e.EvidenceID)
	if evidenceID == "" {
		return errors.New("evidence id is required")
	}
	if len(evidenceID) > maxEvidenceIDLength {
		return errors.New("evidence id exceeds 128 characters")
	}
	if e.Kind != EvidenceKindObjective {
		return errors.New("evidence kind must be objective")
	}
	providerID := strings.TrimSpace(e.ProviderID)
	if providerID == "" {
		return errors.New("provider id is required")
	}
	if len(providerID) > maxProviderIDLength {
		return errors.New("provider id exceeds 128 characters")
	}
	sessionID := strings.TrimSpace(e.SessionID)
	if sessionID == "" {
		return errors.New("session id is required")
	}
	if len(sessionID) > maxSessionIDLength {
		return errors.New("session id exceeds 128 characters")
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
	hasTypedSlashValue := e.SlashAmount != 0 || strings.TrimSpace(e.SlashDenom) != ""
	if err := validateSlashValue(e.SlashAmount, e.SlashDenom, hasTypedSlashValue); err != nil {
		return err
	}
	return nil
}

func (d PenaltyDecision) ValidateBasic() error {
	penaltyID := NormalizePenaltyID(d.PenaltyID)
	if penaltyID == "" {
		return errors.New("penalty id is required")
	}
	if len(penaltyID) > maxPenaltyIDLength {
		return errors.New("penalty id exceeds 128 characters")
	}
	evidenceID := NormalizeEvidenceID(d.EvidenceID)
	if evidenceID == "" {
		return errors.New("evidence id is required")
	}
	if len(evidenceID) > maxEvidenceIDLength {
		return errors.New("evidence id exceeds 128 characters")
	}
	if d.SlashBasisPoint > 10000 {
		return errors.New("slash basis points cannot exceed 10000")
	}
	hasTypedSlashValue := d.SlashAmount != 0 || strings.TrimSpace(d.SlashDenom) != ""
	if err := validateSlashValue(d.SlashAmount, d.SlashDenom, hasTypedSlashValue); err != nil {
		return err
	}
	if d.SlashBasisPoint == 0 && d.SlashAmount == 0 && !d.Jailed {
		return errors.New("penalty decision must slash or jail")
	}
	return nil
}

func validateSlashValue(amount int64, denom string, requirePositive bool) error {
	canonicalDenom := NormalizeSlashDenom(denom)
	if amount < 0 {
		return errors.New("slash amount cannot be negative")
	}
	if requirePositive && amount == 0 {
		return errors.New("slash amount must be positive")
	}
	if (amount > 0 || requirePositive) && canonicalDenom == "" {
		return errors.New("slash denom is required")
	}
	if canonicalDenom != "" && len(canonicalDenom) > maxSlashDenomLength {
		return errors.New("slash denom exceeds 64 characters")
	}
	if canonicalDenom != "" && strings.IndexFunc(canonicalDenom, func(r rune) bool {
		return unicode.IsSpace(r) || unicode.IsControl(r)
	}) >= 0 {
		return errors.New("slash denom must be a canonical non-empty token")
	}
	return nil
}
