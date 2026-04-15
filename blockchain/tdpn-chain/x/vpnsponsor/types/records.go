package types

import (
	"errors"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

// SponsorAuthorization grants an app permission to spend sponsor credits.
type SponsorAuthorization struct {
	AuthorizationID string
	SponsorID       string
	AppID           string
	MaxCredits      int64
	ExpiresAtUnix   int64
	Status          chaintypes.ReconciliationStatus
}

// DelegatedSessionCredit links sponsor authorization to a specific user session.
type DelegatedSessionCredit struct {
	ReservationID   string
	AuthorizationID string
	SponsorID       string
	AppID           string
	EndUserID       string
	SessionID       string
	Credits         int64
	Status          chaintypes.ReconciliationStatus
}

func (a SponsorAuthorization) ValidateBasic() error {
	if a.AuthorizationID == "" {
		return errors.New("authorization id is required")
	}
	if a.SponsorID == "" {
		return errors.New("sponsor id is required")
	}
	if a.AppID == "" {
		return errors.New("app id is required")
	}
	if a.MaxCredits <= 0 {
		return errors.New("max credits must be positive")
	}
	return nil
}

func (d DelegatedSessionCredit) ValidateBasic() error {
	if d.ReservationID == "" {
		return errors.New("reservation id is required")
	}
	if d.AuthorizationID == "" {
		return errors.New("authorization id is required")
	}
	if d.SponsorID == "" {
		return errors.New("sponsor id is required")
	}
	if d.SessionID == "" {
		return errors.New("session id is required")
	}
	if d.Credits <= 0 {
		return errors.New("credits must be positive")
	}
	return nil
}
