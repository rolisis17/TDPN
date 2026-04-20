package types

import (
	"errors"
	"strings"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

const (
	ValidatorLifecycleActive    = "active"
	ValidatorLifecycleJailed    = "jailed"
	ValidatorLifecycleSuspended = "suspended"
)

// ValidatorEligibility captures whether a validator is currently allowed to serve VPN sessions.
type ValidatorEligibility struct {
	ValidatorID     string
	OperatorAddress string
	Eligible        bool
	PolicyReason    string
	UpdatedAtUnix   int64
	Status          chaintypes.ReconciliationStatus
}

// ValidatorStatusRecord captures objective status transitions tied to chain evidence.
type ValidatorStatusRecord struct {
	StatusID         string
	ValidatorID      string
	ConsensusAddress string
	LifecycleStatus  string
	EvidenceHeight   int64
	EvidenceRef      string
	RecordedAtUnix   int64
	Status           chaintypes.ReconciliationStatus
}

func (r ValidatorEligibility) Canonicalize() ValidatorEligibility {
	r.ValidatorID = canonicalizeIdentityField(r.ValidatorID)
	r.OperatorAddress = canonicalizeIdentityField(r.OperatorAddress)
	r.PolicyReason = strings.TrimSpace(r.PolicyReason)
	r.Status = canonicalizeReconciliationStatus(r.Status)
	return r
}

func (r ValidatorStatusRecord) Canonicalize() ValidatorStatusRecord {
	r.StatusID = canonicalizeIdentityField(r.StatusID)
	r.ValidatorID = canonicalizeIdentityField(r.ValidatorID)
	r.ConsensusAddress = canonicalizeIdentityField(r.ConsensusAddress)
	r.LifecycleStatus = canonicalizeLifecycleStatus(r.LifecycleStatus)
	r.EvidenceRef = canonicalizeObjectiveEvidenceRef(r.EvidenceRef)
	r.Status = canonicalizeReconciliationStatus(r.Status)
	return r
}

func (r ValidatorEligibility) ValidateBasic() error {
	r = r.Canonicalize()

	if r.ValidatorID == "" {
		return errors.New("validator id is required")
	}
	if r.OperatorAddress == "" {
		return errors.New("operator address is required")
	}
	return nil
}

func (r ValidatorStatusRecord) ValidateBasic() error {
	r = r.Canonicalize()

	if r.StatusID == "" {
		return errors.New("status id is required")
	}
	if r.ValidatorID == "" {
		return errors.New("validator id is required")
	}
	if r.LifecycleStatus == "" {
		return errors.New("lifecycle status is required")
	}
	if !isAllowedLifecycleStatus(r.LifecycleStatus) {
		return errors.New("lifecycle status must be one of active, jailed, suspended")
	}
	if r.EvidenceHeight < 0 {
		return errors.New("evidence height cannot be negative")
	}
	if r.EvidenceRef != "" && !chaintypes.IsObjectiveEvidenceFormat(r.EvidenceRef) {
		return errors.New("evidence ref must use objective format (sha256:<value> or obj://<value>)")
	}
	return nil
}

func isAllowedLifecycleStatus(value string) bool {
	switch value {
	case ValidatorLifecycleActive, ValidatorLifecycleJailed, ValidatorLifecycleSuspended:
		return true
	default:
		return false
	}
}

func canonicalizeIdentityField(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalizeLifecycleStatus(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalizeReconciliationStatus(status chaintypes.ReconciliationStatus) chaintypes.ReconciliationStatus {
	return chaintypes.ReconciliationStatus(strings.ToLower(strings.TrimSpace(string(status))))
}

func canonicalizeObjectiveEvidenceRef(value string) string {
	if value == "" {
		return ""
	}

	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		// Preserve whitespace-only payloads so validation still rejects them.
		return value
	}

	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "sha256:"):
		hash := trimmed[len("sha256:"):]
		return "sha256:" + strings.ToLower(hash)
	case strings.HasPrefix(lower, "obj://"):
		path := trimmed[len("obj://"):]
		return "obj://" + path
	default:
		return trimmed
	}
}
