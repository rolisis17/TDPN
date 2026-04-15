package types

import (
	"errors"

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

func (r RewardAccrual) ValidateBasic() error {
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
	if r.DistributionID == "" {
		return errors.New("distribution id is required")
	}
	if r.AccrualID == "" {
		return errors.New("accrual id is required")
	}
	return nil
}
