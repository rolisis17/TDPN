package types

import (
	"errors"
	"strings"
	"unicode"

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

func (r ValidatorEligibility) ValidateBasic() error {
	if r.ValidatorID == "" {
		return errors.New("validator id is required")
	}
	if r.OperatorAddress == "" {
		return errors.New("operator address is required")
	}
	return nil
}

func (r ValidatorStatusRecord) ValidateBasic() error {
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
	if r.EvidenceRef != "" && !isObjectiveEvidenceRefFormat(r.EvidenceRef) {
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

func isObjectiveEvidenceRefFormat(evidenceRef string) bool {
	const (
		sha256Prefix = "sha256:"
		objectPrefix = "obj://"
	)
	evidenceRef = strings.TrimSpace(evidenceRef)

	if strings.HasPrefix(evidenceRef, sha256Prefix) {
		hash := strings.TrimPrefix(evidenceRef, sha256Prefix)
		return isValidSHA256Hex(hash)
	}
	if strings.HasPrefix(evidenceRef, objectPrefix) {
		path := strings.TrimPrefix(evidenceRef, objectPrefix)
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
