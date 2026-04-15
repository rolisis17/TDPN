package types

import (
	"errors"

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
