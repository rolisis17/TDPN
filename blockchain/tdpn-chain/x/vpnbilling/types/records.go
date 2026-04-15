package types

import (
	"errors"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

// CreditReservation captures sponsor or user prepaid credits reserved for a session.
type CreditReservation struct {
	ReservationID string
	SponsorID     string
	SessionID     string
	AssetDenom    string
	Amount        int64
	Status        chaintypes.ReconciliationStatus
	CreatedAtUnix int64
}

// SettlementRecord finalizes billable usage for a session.
type SettlementRecord struct {
	SettlementID   string
	ReservationID  string
	SessionID      string
	BilledAmount   int64
	UsageBytes     int64
	AssetDenom     string
	SettledAtUnix  int64
	OperationState chaintypes.ReconciliationStatus
}

func (r CreditReservation) ValidateBasic() error {
	if r.ReservationID == "" {
		return errors.New("reservation id is required")
	}
	if r.SessionID == "" {
		return errors.New("session id is required")
	}
	if r.Amount <= 0 {
		return errors.New("amount must be positive")
	}
	return nil
}

func (r SettlementRecord) ValidateBasic() error {
	if r.SettlementID == "" {
		return errors.New("settlement id is required")
	}
	if r.SessionID == "" {
		return errors.New("session id is required")
	}
	if r.BilledAmount < 0 {
		return errors.New("billed amount cannot be negative")
	}
	return nil
}
