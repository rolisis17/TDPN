package types

import (
	"errors"
	"strings"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

// RewardAccrual links settled usage to provider rewards.
type RewardAccrual struct {
	AccrualID      string
	SessionID      string
	ProviderID     string
	AssetDenom     string
	Amount         int64
	AccruedAtUnix  int64
	OperationState chaintypes.ReconciliationStatus
}

// DistributionRecord records payout references for accrued rewards.
type DistributionRecord struct {
	DistributionID string
	AccrualID      string
	PayoutRef      string
	DistributedAt  int64
	Status         chaintypes.ReconciliationStatus
}

// Canonicalize normalizes IDs and defaults for deterministic persistence and equality checks.
func (r RewardAccrual) Canonicalize() RewardAccrual {
	r.AccrualID = canonicalIdentifier(r.AccrualID)
	r.SessionID = canonicalIdentifier(r.SessionID)
	r.ProviderID = canonicalIdentifier(r.ProviderID)
	r.AssetDenom = canonicalIdentifier(r.AssetDenom)
	r.OperationState = canonicalStatus(r.OperationState, chaintypes.ReconciliationPending)
	return r
}

// Canonicalize normalizes IDs and defaults for deterministic persistence and equality checks.
func (r DistributionRecord) Canonicalize() DistributionRecord {
	r.DistributionID = canonicalIdentifier(r.DistributionID)
	r.AccrualID = canonicalIdentifier(r.AccrualID)
	r.Status = canonicalStatus(r.Status, chaintypes.ReconciliationSubmitted)
	return r
}

func (r RewardAccrual) ValidateBasic() error {
	r = r.Canonicalize()

	if r.AccrualID == "" {
		return errors.New("accrual id is required")
	}
	if r.ProviderID == "" {
		return errors.New("provider id is required")
	}
	if r.Amount < 0 {
		return errors.New("amount cannot be negative")
	}
	return nil
}

func (r DistributionRecord) ValidateBasic() error {
	r = r.Canonicalize()

	if r.DistributionID == "" {
		return errors.New("distribution id is required")
	}
	if r.AccrualID == "" {
		return errors.New("accrual id is required")
	}
	return nil
}

func canonicalIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalStatus(value chaintypes.ReconciliationStatus, defaultValue chaintypes.ReconciliationStatus) chaintypes.ReconciliationStatus {
	normalized := chaintypes.ReconciliationStatus(canonicalIdentifier(string(value)))
	if normalized == "" {
		return defaultValue
	}
	return normalized
}
