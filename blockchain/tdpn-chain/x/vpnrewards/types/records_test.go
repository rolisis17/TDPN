package types

import "testing"

func TestRewardAccrualValidateBasic(t *testing.T) {
	t.Parallel()

	base := RewardAccrual{
		AccrualID:  "acc-1",
		SessionID:  "sess-1",
		ProviderID: "provider-1",
		Amount:     42,
	}

	tests := []struct {
		name    string
		record  RewardAccrual
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing accrual id",
			record:  RewardAccrual{SessionID: base.SessionID, ProviderID: base.ProviderID, Amount: base.Amount},
			wantErr: "accrual id is required",
		},
		{
			name:    "missing provider id",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: base.SessionID, Amount: base.Amount},
			wantErr: "provider id is required",
		},
		{
			name:    "negative amount",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: base.SessionID, ProviderID: base.ProviderID, Amount: -1},
			wantErr: "amount cannot be negative",
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

func TestDistributionRecordValidateBasic(t *testing.T) {
	t.Parallel()

	base := DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      "acc-1",
	}

	tests := []struct {
		name    string
		record  DistributionRecord
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing distribution id",
			record:  DistributionRecord{AccrualID: base.AccrualID},
			wantErr: "distribution id is required",
		},
		{
			name:    "missing accrual id",
			record:  DistributionRecord{DistributionID: base.DistributionID},
			wantErr: "accrual id is required",
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
