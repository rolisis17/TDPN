package types

import "testing"

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
			name:    "missing sponsor id",
			record:  SponsorAuthorization{AuthorizationID: base.AuthorizationID, AppID: base.AppID, MaxCredits: base.MaxCredits},
			wantErr: "sponsor id is required",
		},
		{
			name:    "missing app id",
			record:  SponsorAuthorization{AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, MaxCredits: base.MaxCredits},
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
			name:    "missing authorization id",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, SponsorID: base.SponsorID, SessionID: base.SessionID, Credits: base.Credits},
			wantErr: "authorization id is required",
		},
		{
			name:    "missing sponsor id",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, AuthorizationID: base.AuthorizationID, SessionID: base.SessionID, Credits: base.Credits},
			wantErr: "sponsor id is required",
		},
		{
			name:    "missing session id",
			record:  DelegatedSessionCredit{ReservationID: base.ReservationID, AuthorizationID: base.AuthorizationID, SponsorID: base.SponsorID, Credits: base.Credits},
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
