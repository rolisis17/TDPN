package types

import (
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

func TestNormalizeSponsorAuthorization(t *testing.T) {
	t.Parallel()

	normalized := NormalizeSponsorAuthorization(SponsorAuthorization{
		AuthorizationID: "  Auth-1  ",
		SponsorID:       "  Sponsor-1  ",
		AppID:           "  App-1  ",
	})

	if normalized.AuthorizationID != "auth-1" {
		t.Fatalf("expected canonical authorization id %q, got %q", "auth-1", normalized.AuthorizationID)
	}
	if normalized.SponsorID != "sponsor-1" {
		t.Fatalf("expected canonical sponsor id %q, got %q", "sponsor-1", normalized.SponsorID)
	}
	if normalized.AppID != "app-1" {
		t.Fatalf("expected canonical app id %q, got %q", "app-1", normalized.AppID)
	}
}

func TestNormalizeDelegatedSessionCredit(t *testing.T) {
	t.Parallel()

	normalized := NormalizeDelegatedSessionCredit(DelegatedSessionCredit{
		ReservationID:   "  Res-1  ",
		AuthorizationID: "  Auth-1  ",
		SponsorID:       "  Sponsor-1  ",
		AppID:           "  App-1  ",
		EndUserID:       "  User-1  ",
		SessionID:       "  Sess-1  ",
	})

	if normalized.ReservationID != "res-1" {
		t.Fatalf("expected canonical reservation id %q, got %q", "res-1", normalized.ReservationID)
	}
	if normalized.AuthorizationID != "auth-1" {
		t.Fatalf("expected canonical authorization id %q, got %q", "auth-1", normalized.AuthorizationID)
	}
	if normalized.SponsorID != "sponsor-1" {
		t.Fatalf("expected canonical sponsor id %q, got %q", "sponsor-1", normalized.SponsorID)
	}
	if normalized.AppID != "app-1" {
		t.Fatalf("expected canonical app id %q, got %q", "app-1", normalized.AppID)
	}
	if normalized.EndUserID != "User-1" {
		t.Fatalf("expected trimmed end user id %q, got %q", "User-1", normalized.EndUserID)
	}
	if normalized.SessionID != "Sess-1" {
		t.Fatalf("expected trimmed session id %q, got %q", "Sess-1", normalized.SessionID)
	}
}

func TestSponsorAuthorizationValidateBasic(t *testing.T) {
	t.Parallel()

	base := SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      500,
	}

	tests := []struct {
		name    string
		record  SponsorAuthorization
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing authorization id",
			record:  SponsorAuthorization{SponsorID: base.SponsorID, AppID: base.AppID, MaxCredits: base.MaxCredits},
			wantErr: "authorization id is required",
		},
		{
			name:    "blank authorization id",
			record:  SponsorAuthorization{AuthorizationID: "   ", SponsorID: base.SponsorID, AppID: base.AppID, MaxCredits: base.MaxCredits},
			wantErr: "authorization id is required",
		},
		{
			name:    "missing sponsor id",
			record:  SponsorAuthorization{AuthorizationID: base.AuthorizationID, AppID: base.AppID, MaxCredits: base.MaxCredits},
			wantErr: "sponsor id is required",
		},
		{
			name:    "blank sponsor id",
			record:  SponsorAuthorization{AuthorizationID: base.AuthorizationID, SponsorID: "   ", AppID: base.AppID, MaxCredits: base.MaxCredits},
			wantErr: "sponsor id is required",
		},
		{
			name:    "missing app id",
			record:  SponsorAuthorization{AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, MaxCredits: base.MaxCredits},
			wantErr: "app id is required",
		},
		{
			name:    "blank app id",
			record:  SponsorAuthorization{AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, AppID: "   ", MaxCredits: base.MaxCredits},
			wantErr: "app id is required",
		},
		{
			name:    "non-positive max credits",
			record:  SponsorAuthorization{AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, AppID: base.AppID, MaxCredits: 0},
			wantErr: "max credits must be positive",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.record.ValidateBasic()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}

func TestDelegatedSessionCreditValidateBasic(t *testing.T) {
	t.Parallel()

	base := DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		SessionID:       "sess-1",
		Credits:         100,
	}

	tests := []struct {
		name    string
		record  DelegatedSessionCredit
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing reservation id",
			record:  DelegatedSessionCredit{AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, SessionID: base.SessionID, Credits: base.Credits},
			wantErr: "reservation id is required",
		},
		{
			name:    "blank reservation id",
			record:  DelegatedSessionCredit{ReservationID: "   ", AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, SessionID: base.SessionID, Credits: base.Credits},
			wantErr: "reservation id is required",
		},
		{
			name:    "missing authorization id",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, SponsorID: base.SponsorID, SessionID: base.SessionID, Credits: base.Credits},
			wantErr: "authorization id is required",
		},
		{
			name:    "blank authorization id",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, AuthorizationID: "   ", SponsorID: base.SponsorID, SessionID: base.SessionID, Credits: base.Credits},
			wantErr: "authorization id is required",
		},
		{
			name:    "missing sponsor id",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, AuthorizationID: base.AuthorizationID, SessionID: base.SessionID, Credits: base.Credits},
			wantErr: "sponsor id is required",
		},
		{
			name:    "blank sponsor id",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, AuthorizationID: base.AuthorizationID, SponsorID: "   ", SessionID: base.SessionID, Credits: base.Credits},
			wantErr: "sponsor id is required",
		},
		{
			name:    "missing session id",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, Credits: base.Credits},
			wantErr: "session id is required",
		},
		{
			name:    "blank session id",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, SessionID: "   ", Credits: base.Credits},
			wantErr: "session id is required",
		},
		{
			name:    "non-positive credits",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, SessionID: base.SessionID, Credits: 0},
			wantErr: "credits must be positive",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.record.ValidateBasic()
			if tc.wantErr == "" && err != nil {
				t.Fatalf("expected nil error, got %v", err)
			}
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error %q, got nil", tc.wantErr)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("expected error %q, got %q", tc.wantErr, err.Error())
				}
			}
		})
	}
}

func TestSponsorNormalizationRetainsLifecycleStatusFields(t *testing.T) {
	t.Parallel()

	authorization := NormalizeSponsorAuthorization(SponsorAuthorization{
		AuthorizationID: " auth-status-1 ",
		SponsorID:       " sponsor-status-1 ",
		AppID:           " app-status-1 ",
		Status:          chaintypes.ReconciliationFailed,
	})
	if authorization.Status != chaintypes.ReconciliationFailed {
		t.Fatalf("expected sponsor authorization status %q, got %q", chaintypes.ReconciliationFailed, authorization.Status)
	}

	delegation := NormalizeDelegatedSessionCredit(DelegatedSessionCredit{
		ReservationID:   " res-status-1 ",
		AuthorizationID: " auth-status-1 ",
		SponsorID:       " sponsor-status-1 ",
		AppID:           " app-status-1 ",
		EndUserID:       " user-status-1 ",
		SessionID:       " sess-status-1 ",
		Status:          chaintypes.ReconciliationConfirmed,
	})
	if delegation.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected delegated session status %q, got %q", chaintypes.ReconciliationConfirmed, delegation.Status)
	}
}
