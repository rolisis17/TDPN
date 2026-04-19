package types

import (
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

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
			name:    "whitespace-only accrual id",
			record:  RewardAccrual{AccrualID: " \t ", ProviderID: base.ProviderID, Amount: base.Amount},
			wantErr: "accrual id is required",
		},
		{
			name:    "whitespace-only provider id",
			record:  RewardAccrual{AccrualID: base.AccrualID, ProviderID: " \n ", Amount: base.Amount},
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
		{
			name:    "whitespace-only distribution id",
			record:  DistributionRecord{DistributionID: "   ", AccrualID: base.AccrualID},
			wantErr: "distribution id is required",
		},
		{
			name:    "whitespace-only accrual id",
			record:  DistributionRecord{DistributionID: base.DistributionID, AccrualID: "\t"},
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

func TestRewardAccrualCanonicalize(t *testing.T) {
	t.Parallel()

	got := RewardAccrual{
		AccrualID:      "  ACC-1 ",
		SessionID:      " Sess-1\t",
		ProviderID:     " Provider-1 ",
		AssetDenom:     " UUSDC ",
		OperationState: " PENDING ",
	}.Canonicalize()

	if got.AccrualID != "acc-1" {
		t.Fatalf("expected accrual id to be canonicalized, got %q", got.AccrualID)
	}
	if got.SessionID != "sess-1" {
		t.Fatalf("expected session id to be canonicalized, got %q", got.SessionID)
	}
	if got.ProviderID != "provider-1" {
		t.Fatalf("expected provider id to be canonicalized, got %q", got.ProviderID)
	}
	if got.AssetDenom != "uusdc" {
		t.Fatalf("expected asset denom to be canonicalized, got %q", got.AssetDenom)
	}
	if got.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf("expected status to be canonicalized to pending, got %q", got.OperationState)
	}

	defaulted := RewardAccrual{
		AccrualID:  "acc-2",
		ProviderID: "provider-2",
	}.Canonicalize()
	if defaulted.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, defaulted.OperationState)
	}
}

func TestDistributionRecordCanonicalize(t *testing.T) {
	t.Parallel()

	got := DistributionRecord{
		DistributionID: " Dist-1 ",
		AccrualID:      " ACC-1 ",
		Status:         " SUBMITTED ",
	}.Canonicalize()

	if got.DistributionID != "dist-1" {
		t.Fatalf("expected distribution id to be canonicalized, got %q", got.DistributionID)
	}
	if got.AccrualID != "acc-1" {
		t.Fatalf("expected accrual id to be canonicalized, got %q", got.AccrualID)
	}
	if got.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected status to be canonicalized to submitted, got %q", got.Status)
	}

	defaulted := DistributionRecord{
		DistributionID: "dist-2",
		AccrualID:      "acc-2",
	}.Canonicalize()
	if defaulted.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationSubmitted, defaulted.Status)
	}
}

func TestRewardAccrualCanonicalizeRetainsTerminalLifecycleStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   chaintypes.ReconciliationStatus
		want chaintypes.ReconciliationStatus
	}{
		{
			name: "confirmed",
			in:   " CONFIRMED ",
			want: chaintypes.ReconciliationConfirmed,
		},
		{
			name: "failed",
			in:   " FAILED ",
			want: chaintypes.ReconciliationFailed,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := RewardAccrual{
				AccrualID:      "acc-terminal-1",
				ProviderID:     "provider-terminal-1",
				OperationState: tc.in,
			}.Canonicalize()
			if got.OperationState != tc.want {
				t.Fatalf("expected operation state %q, got %q", tc.want, got.OperationState)
			}
		})
	}
}

func TestDistributionRecordCanonicalizeRetainsTerminalLifecycleStatuses(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   chaintypes.ReconciliationStatus
		want chaintypes.ReconciliationStatus
	}{
		{
			name: "confirmed",
			in:   " CONFIRMED ",
			want: chaintypes.ReconciliationConfirmed,
		},
		{
			name: "failed",
			in:   " FAILED ",
			want: chaintypes.ReconciliationFailed,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DistributionRecord{
				DistributionID: "dist-terminal-1",
				AccrualID:      "acc-terminal-1",
				Status:         tc.in,
			}.Canonicalize()
			if got.Status != tc.want {
				t.Fatalf("expected status %q, got %q", tc.want, got.Status)
			}
		})
	}
}
