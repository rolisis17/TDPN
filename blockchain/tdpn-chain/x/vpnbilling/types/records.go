package types

import (
	"errors"
	"strings"

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

// Canonicalize trims and lower-cases id/session/sponsor/denom fields.
func (r CreditReservation) Canonicalize() CreditReservation {
	r.ReservationID = canonicalToken(r.ReservationID)
	r.SponsorID = canonicalToken(r.SponsorID)
	r.SessionID = canonicalToken(r.SessionID)
	r.AssetDenom = canonicalToken(r.AssetDenom)
	return r
}

// Canonicalize trims and lower-cases id/session/denom fields.
func (r SettlementRecord) Canonicalize() SettlementRecord {
	r.SettlementID = canonicalToken(r.SettlementID)
	r.ReservationID = canonicalToken(r.ReservationID)
	r.SessionID = canonicalToken(r.SessionID)
	r.AssetDenom = canonicalToken(r.AssetDenom)
	return r
}

func (r CreditReservation) ValidateBasic() error {
	r = r.Canonicalize()
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
	r = r.Canonicalize()
	if r.SettlementID == "" {
		return errors.New("settlement id is required")
	}
	if r.SessionID == "" {
		return errors.New("session id is required")
	}
	if r.BilledAmount <= 0 {
		return errors.New("billed amount must be positive")
	}
	return nil
}

func canonicalToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
