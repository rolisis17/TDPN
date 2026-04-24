package types

import (
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

func TestCreditReservationValidateBasic(t *testing.T) {
	t.Parallel()

	base := CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		Amount:        100,
	}

	tests := []struct {
		name    string
		record  CreditReservation
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing reservation id",
			record:  CreditReservation{SessionID: base.SessionID, Amount: base.Amount},
			wantErr: "reservation id is required",
		},
		{
			name:    "whitespace reservation id becomes missing",
			record:  CreditReservation{ReservationID: "   ", SessionID: base.SessionID, Amount: base.Amount},
			wantErr: "reservation id is required",
		},
		{
			name:    "missing session id",
			record:  CreditReservation{ReservationID: base.ReservationID, Amount: base.Amount},
			wantErr: "session id is required",
		},
		{
			name:    "non-positive amount",
			record:  CreditReservation{ReservationID: base.ReservationID, SessionID: base.SessionID, Amount: 0},
			wantErr: "amount must be positive",
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

func TestSettlementRecordValidateBasic(t *testing.T) {
	t.Parallel()

	base := SettlementRecord{
		SettlementID: "set-1",
		SessionID:    "sess-1",
		AssetDenom:   "uusdc",
		BilledAmount: 55,
	}

	tests := []struct {
		name    string
		record  SettlementRecord
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing settlement id",
			record:  SettlementRecord{SessionID: base.SessionID, BilledAmount: base.BilledAmount},
			wantErr: "settlement id is required",
		},
		{
			name:    "whitespace settlement id becomes missing",
			record:  SettlementRecord{SettlementID: "  ", SessionID: base.SessionID, BilledAmount: base.BilledAmount},
			wantErr: "settlement id is required",
		},
		{
			name:    "missing session id",
			record:  SettlementRecord{SettlementID: base.SettlementID, AssetDenom: base.AssetDenom, BilledAmount: base.BilledAmount},
			wantErr: "session id is required",
		},
		{
			name:    "missing asset denom",
			record:  SettlementRecord{SettlementID: base.SettlementID, SessionID: base.SessionID, BilledAmount: base.BilledAmount},
			wantErr: "asset denom is required",
		},
		{
			name:    "whitespace asset denom",
			record:  SettlementRecord{SettlementID: base.SettlementID, SessionID: base.SessionID, AssetDenom: " \t ", BilledAmount: base.BilledAmount},
			wantErr: "asset denom is required",
		},
		{
			name:    "zero billed amount",
			record:  SettlementRecord{SettlementID: base.SettlementID, SessionID: base.SessionID, AssetDenom: base.AssetDenom, BilledAmount: 0},
			wantErr: "billed amount must be positive",
		},
		{
			name:    "negative billed amount",
			record:  SettlementRecord{SettlementID: base.SettlementID, SessionID: base.SessionID, AssetDenom: base.AssetDenom, BilledAmount: -1},
			wantErr: "billed amount must be positive",
		},
		{
			name:    "negative usage bytes",
			record:  SettlementRecord{SettlementID: base.SettlementID, SessionID: base.SessionID, AssetDenom: base.AssetDenom, BilledAmount: base.BilledAmount, UsageBytes: -1},
			wantErr: "usage bytes cannot be negative",
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

func TestCreditReservationCanonicalize(t *testing.T) {
	t.Parallel()

	record := CreditReservation{
		ReservationID: "  RES-1  ",
		SponsorID:     " Sponsor-ABC ",
		SessionID:     " Sess-1 ",
		AssetDenom:    " UUSDC ",
		Amount:        1,
	}

	got := record.Canonicalize()

	if got.ReservationID != "res-1" {
		t.Fatalf("expected reservation id %q, got %q", "res-1", got.ReservationID)
	}
	if got.SponsorID != "sponsor-abc" {
		t.Fatalf("expected sponsor id %q, got %q", "sponsor-abc", got.SponsorID)
	}
	if got.SessionID != "sess-1" {
		t.Fatalf("expected session id %q, got %q", "sess-1", got.SessionID)
	}
	if got.AssetDenom != "uusdc" {
		t.Fatalf("expected asset denom %q, got %q", "uusdc", got.AssetDenom)
	}
}

func TestSettlementRecordCanonicalize(t *testing.T) {
	t.Parallel()

	record := SettlementRecord{
		SettlementID:  " Set-1 ",
		ReservationID: " RES-1 ",
		SessionID:     " Sess-1 ",
		AssetDenom:    " UUSDC ",
		BilledAmount:  1,
	}

	got := record.Canonicalize()

	if got.SettlementID != "set-1" {
		t.Fatalf("expected settlement id %q, got %q", "set-1", got.SettlementID)
	}
	if got.ReservationID != "res-1" {
		t.Fatalf("expected reservation id %q, got %q", "res-1", got.ReservationID)
	}
	if got.SessionID != "sess-1" {
		t.Fatalf("expected session id %q, got %q", "sess-1", got.SessionID)
	}
	if got.AssetDenom != "uusdc" {
		t.Fatalf("expected asset denom %q, got %q", "uusdc", got.AssetDenom)
	}
}

func TestBillingCanonicalizeRetainsLifecycleStatusFields(t *testing.T) {
	t.Parallel()

	reservation := CreditReservation{
		ReservationID: " RES-LIFECYCLE-1 ",
		SessionID:     " SESS-LIFECYCLE-1 ",
		Amount:        1,
		Status:        " FAILED ",
	}.Canonicalize()
	if reservation.Status != " FAILED " {
		t.Fatalf("expected reservation status field to be retained verbatim, got %q", reservation.Status)
	}

	settlement := SettlementRecord{
		SettlementID:   " SET-LIFECYCLE-1 ",
		SessionID:      " SESS-LIFECYCLE-1 ",
		BilledAmount:   1,
		OperationState: chaintypes.ReconciliationConfirmed,
	}.Canonicalize()
	if settlement.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected settlement operation state %q, got %q", chaintypes.ReconciliationConfirmed, settlement.OperationState)
	}
}
