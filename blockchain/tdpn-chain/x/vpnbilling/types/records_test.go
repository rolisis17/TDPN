package types

import "testing"

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
			name:    "missing session id",
			record:  SettlementRecord{SettlementID: base.SettlementID, BilledAmount: base.BilledAmount},
			wantErr: "session id is required",
		},
		{
			name:    "negative billed amount",
			record:  SettlementRecord{SettlementID: base.SettlementID, SessionID: base.SessionID, BilledAmount: -1},
			wantErr: "billed amount cannot be negative",
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
