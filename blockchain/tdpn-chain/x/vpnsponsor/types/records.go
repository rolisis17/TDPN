package types

import (
	"errors"
	"strings"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

const maxIdentityLength = 128

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

// NormalizeSponsorAuthorization canonicalizes identity fields for deterministic comparisons/storage.
func NormalizeSponsorAuthorization(record SponsorAuthorization) SponsorAuthorization {
	record.AuthorizationID = normalizeCaseInsensitiveIdentity(record.AuthorizationID)
	record.SponsorID = normalizeCaseInsensitiveIdentity(record.SponsorID)
	record.AppID = normalizeCaseInsensitiveIdentity(record.AppID)
	return record
}

// NormalizeDelegatedSessionCredit canonicalizes identity fields for deterministic comparisons/storage.
func NormalizeDelegatedSessionCredit(record DelegatedSessionCredit) DelegatedSessionCredit {
	record.ReservationID = normalizeCaseInsensitiveIdentity(record.ReservationID)
	record.AuthorizationID = normalizeCaseInsensitiveIdentity(record.AuthorizationID)
	record.SponsorID = normalizeCaseInsensitiveIdentity(record.SponsorID)
	record.AppID = normalizeCaseInsensitiveIdentity(record.AppID)
	// Session and end-user identifiers are treated as opaque (case-preserving) external values.
	record.EndUserID = normalizeCaseSensitiveIdentity(record.EndUserID)
	record.SessionID = normalizeCaseSensitiveIdentity(record.SessionID)
	return record
}

func (a SponsorAuthorization) ValidateBasic() error {
	normalized := NormalizeSponsorAuthorization(a)

	if normalized.AuthorizationID == "" {
		return errors.New("authorization id is required")
	}
	if len(normalized.AuthorizationID) > maxIdentityLength {
		return errors.New("authorization id exceeds 128 characters")
	}
	if normalized.SponsorID == "" {
		return errors.New("sponsor id is required")
	}
	if len(normalized.SponsorID) > maxIdentityLength {
		return errors.New("sponsor id exceeds 128 characters")
	}
	if normalized.AppID == "" {
		return errors.New("app id is required")
	}
	if len(normalized.AppID) > maxIdentityLength {
		return errors.New("app id exceeds 128 characters")
	}
	if a.MaxCredits <= 0 {
		return errors.New("max credits must be positive")
	}
	if a.ExpiresAtUnix < 0 {
		return errors.New("expires_at_unix cannot be negative")
	}
	return nil
}

func (d DelegatedSessionCredit) ValidateBasic() error {
	normalized := NormalizeDelegatedSessionCredit(d)

	if normalized.ReservationID == "" {
		return errors.New("reservation id is required")
	}
	if len(normalized.ReservationID) > maxIdentityLength {
		return errors.New("reservation id exceeds 128 characters")
	}
	if normalized.AuthorizationID == "" {
		return errors.New("authorization id is required")
	}
	if len(normalized.AuthorizationID) > maxIdentityLength {
		return errors.New("authorization id exceeds 128 characters")
	}
	if normalized.SponsorID == "" {
		return errors.New("sponsor id is required")
	}
	if len(normalized.SponsorID) > maxIdentityLength {
		return errors.New("sponsor id exceeds 128 characters")
	}
	if normalized.AppID != "" && len(normalized.AppID) > maxIdentityLength {
		return errors.New("app id exceeds 128 characters")
	}
	if normalized.EndUserID != "" && len(normalized.EndUserID) > maxIdentityLength {
		return errors.New("end user id exceeds 128 characters")
	}
	if normalized.SessionID == "" {
		return errors.New("session id is required")
	}
	if len(normalized.SessionID) > maxIdentityLength {
		return errors.New("session id exceeds 128 characters")
	}
	if d.Credits <= 0 {
		return errors.New("credits must be positive")
	}
	return nil
}

func normalizeCaseInsensitiveIdentity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func normalizeCaseSensitiveIdentity(value string) string {
	return strings.TrimSpace(value)
}
