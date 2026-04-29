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
		AssetDenom: "uusdc",
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
			record:  RewardAccrual{SessionID: base.SessionID, ProviderID: base.ProviderID, AssetDenom: base.AssetDenom, Amount: base.Amount},
			wantErr: "accrual id is required",
		},
		{
			name:    "missing session id",
			record:  RewardAccrual{AccrualID: base.AccrualID, ProviderID: base.ProviderID, AssetDenom: base.AssetDenom, Amount: base.Amount},
			wantErr: "session id is required",
		},
		{
			name:    "missing provider id",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: base.SessionID, AssetDenom: base.AssetDenom, Amount: base.Amount},
			wantErr: "provider id is required",
		},
		{
			name:    "missing asset denom",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: base.SessionID, ProviderID: base.ProviderID, Amount: base.Amount},
			wantErr: "asset denom is required",
		},
		{
			name:    "whitespace-only accrual id",
			record:  RewardAccrual{AccrualID: " \t ", SessionID: base.SessionID, ProviderID: base.ProviderID, AssetDenom: base.AssetDenom, Amount: base.Amount},
			wantErr: "accrual id is required",
		},
		{
			name:    "whitespace-only session id",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: " \t ", ProviderID: base.ProviderID, AssetDenom: base.AssetDenom, Amount: base.Amount},
			wantErr: "session id is required",
		},
		{
			name:    "whitespace-only provider id",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: base.SessionID, ProviderID: " \n ", AssetDenom: base.AssetDenom, Amount: base.Amount},
			wantErr: "provider id is required",
		},
		{
			name:    "whitespace-only asset denom",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: base.SessionID, ProviderID: base.ProviderID, AssetDenom: " \n ", Amount: base.Amount},
			wantErr: "asset denom is required",
		},
		{
			name:    "zero amount",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: base.SessionID, ProviderID: base.ProviderID, AssetDenom: base.AssetDenom},
			wantErr: "amount must be positive",
		},
		{
			name:    "negative amount",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: base.SessionID, ProviderID: base.ProviderID, AssetDenom: base.AssetDenom, Amount: -1},
			wantErr: "amount must be positive",
		},
		{
			name:    "unknown operation state",
			record:  RewardAccrual{AccrualID: base.AccrualID, SessionID: base.SessionID, ProviderID: base.ProviderID, AssetDenom: base.AssetDenom, Amount: base.Amount, OperationState: "mystery"},
			wantErr: "operation state must be pending, submitted, confirmed, or failed",
		},
		{
			name: "valid weekly payout period",
			record: RewardAccrual{
				AccrualID:       base.AccrualID,
				SessionID:       base.SessionID,
				ProviderID:      base.ProviderID,
				AssetDenom:      base.AssetDenom,
				Amount:          base.Amount,
				PayoutStartUnix: 1776643200, // 2026-04-20T00:00:00Z
				PayoutEndUnix:   1777248000, // 2026-04-27T00:00:00Z
			},
		},
		{
			name: "payout start without end",
			record: RewardAccrual{
				AccrualID:       base.AccrualID,
				SessionID:       base.SessionID,
				ProviderID:      base.ProviderID,
				AssetDenom:      base.AssetDenom,
				Amount:          base.Amount,
				PayoutStartUnix: 1776643200,
			},
			wantErr: "payout start and end are required together",
		},
		{
			name: "payout start not monday",
			record: RewardAccrual{
				AccrualID:       base.AccrualID,
				SessionID:       base.SessionID,
				ProviderID:      base.ProviderID,
				AssetDenom:      base.AssetDenom,
				Amount:          base.Amount,
				PayoutStartUnix: 1776729600, // 2026-04-21T00:00:00Z
				PayoutEndUnix:   1777334400,
			},
			wantErr: "payout start must be Monday 00:00:00 UTC",
		},
		{
			name: "payout end not weekly",
			record: RewardAccrual{
				AccrualID:       base.AccrualID,
				SessionID:       base.SessionID,
				ProviderID:      base.ProviderID,
				AssetDenom:      base.AssetDenom,
				Amount:          base.Amount,
				PayoutStartUnix: 1776643200,
				PayoutEndUnix:   1777161600,
			},
			wantErr: "payout end must be exactly 7 days after payout start",
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
		PayoutRef:      "payout-1",
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
			record:  DistributionRecord{DistributionID: base.DistributionID, AccrualID: "\t", PayoutRef: base.PayoutRef},
			wantErr: "accrual id is required",
		},
		{
			name:    "missing payout ref",
			record:  DistributionRecord{DistributionID: base.DistributionID, AccrualID: base.AccrualID},
			wantErr: "payout ref is required",
		},
		{
			name:    "whitespace-only payout ref",
			record:  DistributionRecord{DistributionID: base.DistributionID, AccrualID: base.AccrualID, PayoutRef: " \n\t "},
			wantErr: "payout ref is required",
		},
		{
			name:    "unknown status",
			record:  DistributionRecord{DistributionID: base.DistributionID, AccrualID: base.AccrualID, PayoutRef: base.PayoutRef, Status: "mystery"},
			wantErr: "status must be pending, submitted, confirmed, or failed",
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

func TestRewardProofRecordValidateVerifiedBinding(t *testing.T) {
	t.Parallel()

	record := RewardProofRecord{
		ProofPath:         "traffic-proof/reward-proof-1",
		TrafficProofRef:   "obj://traffic-proof/reward-proof-1",
		TrustContract:     RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "reward-proof-1",
		ProviderSubjectID: "provider-proof-1",
		SessionID:         "session-proof-1",
		PayoutStartUnix:   1776643200,
		PayoutEndUnix:     1777248000,
		RewardMicros:      100,
		Currency:          "uusdc",
		IssuedAtUnix:      1777248001,
		Verified:          true,
		VerifierID:        "proof-verifier-1",
		VerifiedAtUnix:    1777248002,
	}
	if err := record.ValidateVerified(); err != nil {
		t.Fatalf("expected valid verified proof record, got %v", err)
	}

	mismatch := record
	mismatch.TrafficProofRef = "obj://traffic-proof/other"
	if err := mismatch.ValidateBasic(); err == nil {
		t.Fatal("expected traffic proof ref/path mismatch to fail")
	}

	unverified := record
	unverified.Verified = false
	if err := unverified.ValidateBasic(); err != nil {
		t.Fatalf("expected unverified record to be structurally storable, got %v", err)
	}
	if err := unverified.ValidateVerified(); err == nil {
		t.Fatal("expected unverified record to fail verified query validation")
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
