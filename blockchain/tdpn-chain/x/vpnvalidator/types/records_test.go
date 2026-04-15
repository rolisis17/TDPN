package types

import "testing"

func TestValidatorEligibilityValidateBasic(t *testing.T) {
	t.Parallel()

	base := ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}

	tests := []struct {
		name    string
		record  ValidatorEligibility
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing validator id",
			record:  ValidatorEligibility{OperatorAddress: base.OperatorAddress},
			wantErr: "validator id is required",
		},
		{
			name:    "missing operator address",
			record:  ValidatorEligibility{ValidatorID: base.ValidatorID},
			wantErr: "operator address is required",
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

func TestValidatorStatusRecordValidateBasic(t *testing.T) {
	t.Parallel()

	base := ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: ValidatorLifecycleActive,
		EvidenceHeight:  10,
	}

	tests := []struct {
		name    string
		record  ValidatorStatusRecord
		wantErr string
	}{
		{name: "valid", record: base},
		{
			name:    "missing status id",
			record:  ValidatorStatusRecord{ValidatorID: base.ValidatorID, LifecycleStatus: base.LifecycleStatus, EvidenceHeight: base.EvidenceHeight},
			wantErr: "status id is required",
		},
		{
			name:    "missing validator id",
			record:  ValidatorStatusRecord{StatusID: base.StatusID, LifecycleStatus: base.LifecycleStatus, EvidenceHeight: base.EvidenceHeight},
			wantErr: "validator id is required",
		},
		{
			name:    "missing lifecycle status",
			record:  ValidatorStatusRecord{StatusID: base.StatusID, ValidatorID: base.ValidatorID, EvidenceHeight: base.EvidenceHeight},
			wantErr: "lifecycle status is required",
		},
		{
			name:    "invalid lifecycle status",
			record:  ValidatorStatusRecord{StatusID: base.StatusID, ValidatorID: base.ValidatorID, LifecycleStatus: "offline", EvidenceHeight: base.EvidenceHeight},
			wantErr: "lifecycle status must be one of active, jailed, suspended",
		},
		{
			name:    "negative evidence height",
			record:  ValidatorStatusRecord{StatusID: base.StatusID, ValidatorID: base.ValidatorID, LifecycleStatus: base.LifecycleStatus, EvidenceHeight: -1},
			wantErr: "evidence height cannot be negative",
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
