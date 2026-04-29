package module

import (
	"errors"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

func TestMsgServerAccrueRewardHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-1",
			SessionID:       "sess-1",
			ProviderID:      "provider-1",
			AssetDenom:      "uusdc",
			Amount:          50,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}

	resp, err := server.AccrueReward(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first accrual")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first accrual")
	}
	if resp.Accrual.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf("expected default operation state %q, got %q", chaintypes.ReconciliationPending, resp.Accrual.OperationState)
	}
}

func TestMsgServerAccrueRewardIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	req := AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-2",
			SessionID:       "sess-2",
			ProviderID:      "provider-2",
			AssetDenom:      "uusdc",
			Amount:          25,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}

	if _, err := server.AccrueReward(req); err != nil {
		t.Fatalf("first accrue failed: %v", err)
	}

	resp, err := server.AccrueReward(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed accrual")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed accrual")
	}
}

func TestMsgServerAccrueRewardInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID: "",
			SessionID: "sess-3",
			Amount:    10,
		},
	})
	if err == nil {
		t.Fatal("expected invalid accrual error")
	}
	if !errors.Is(err, ErrInvalidAccrual) {
		t.Fatalf("expected ErrInvalidAccrual, got %v", err)
	}
}

func TestMsgServerAccrueRewardConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	base := AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-4",
			SessionID:       "sess-4",
			ProviderID:      "provider-4",
			AssetDenom:      "uusdc",
			Amount:          100,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}
	if _, err := server.AccrueReward(base); err != nil {
		t.Fatalf("seed accrue failed: %v", err)
	}

	conflict := base
	conflict.Accrual.Amount = 101
	resp, err := server.AccrueReward(conflict)
	if err == nil {
		t.Fatal("expected accrual conflict error")
	}
	if !errors.Is(err, ErrAccrualConflict) {
		t.Fatalf("expected ErrAccrualConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerAccrueRewardWeeklyProviderConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-weekly-provider-msg-1",
			SessionID:       "sess-weekly-provider-msg-1",
			ProviderID:      "provider-weekly-provider-msg",
			AssetDenom:      "uusdc",
			Amount:          100,
			AccruedAtUnix:   1700000000,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}); err != nil {
		t.Fatalf("seed accrue failed: %v", err)
	}

	resp, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-weekly-provider-msg-2",
			SessionID:       "sess-weekly-provider-msg-2",
			ProviderID:      "provider-weekly-provider-msg",
			AssetDenom:      "uusdc",
			Amount:          101,
			AccruedAtUnix:   1700003600,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	})
	if err == nil {
		t.Fatal("expected weekly provider accrual conflict error")
	}
	if !errors.Is(err, ErrAccrualConflict) {
		t.Fatalf("expected ErrAccrualConflict, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false because the duplicate used a new accrual id")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on weekly provider conflict")
	}
}

func TestMsgServerDistributeRewardHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-5",
			SessionID:       "sess-5",
			ProviderID:      "provider-5",
			AssetDenom:      "uusdc",
			Amount:          75,
			OperationState:  chaintypes.ReconciliationSubmitted,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}); err != nil {
		t.Fatalf("accrue failed: %v", err)
	}

	req := DistributeRewardRequest{
		Distribution: types.DistributionRecord{
			DistributionID: "dist-5",
			AccrualID:      "acc-5",
			PayoutRef:      "payout-5",
		},
	}
	resp, err := server.DistributeReward(req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for first distribution")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for first distribution")
	}
	if resp.Distribution.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationSubmitted, resp.Distribution.Status)
	}

	accrual, ok := k.GetAccrual("acc-5")
	if !ok {
		t.Fatal("expected accrual to exist")
	}
	if accrual.OperationState != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected accrual state %q after distribution, got %q", chaintypes.ReconciliationSubmitted, accrual.OperationState)
	}
}

func TestMsgServerDistributeRewardRejectsCallerAssertedFinality(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-finality-reject",
			SessionID:       "sess-finality-reject",
			ProviderID:      "provider-finality-reject",
			AssetDenom:      "uusdc",
			Amount:          75,
			OperationState:  chaintypes.ReconciliationSubmitted,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}); err != nil {
		t.Fatalf("accrue failed: %v", err)
	}

	for _, status := range []chaintypes.ReconciliationStatus{
		chaintypes.ReconciliationConfirmed,
		chaintypes.ReconciliationFailed,
	} {
		status := status
		t.Run(string(status), func(t *testing.T) {
			resp, err := server.DistributeReward(DistributeRewardRequest{
				Distribution: types.DistributionRecord{
					DistributionID: "dist-finality-reject-" + string(status),
					AccrualID:      "acc-finality-reject",
					PayoutRef:      "payout-finality-reject-" + string(status),
					Status:         status,
				},
			})
			if err == nil {
				t.Fatal("expected caller-asserted finality to fail")
			}
			if !errors.Is(err, ErrInvalidDistribution) {
				t.Fatalf("expected ErrInvalidDistribution, got %v", err)
			}
			if !strings.Contains(err.Error(), "requires finality authority") {
				t.Fatalf("expected finality authority guidance, got %v", err)
			}
			if resp.Existed || resp.Idempotent {
				t.Fatalf("unexpected replay flags: %+v", resp)
			}
			if _, ok := k.GetDistribution("dist-finality-reject-" + string(status)); ok {
				t.Fatal("expected no distribution write on caller-asserted finality")
			}
		})
	}

	accrual, ok := k.GetAccrual("acc-finality-reject")
	if !ok {
		t.Fatal("expected accrual to remain available")
	}
	if accrual.OperationState != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected accrual state to remain submitted, got %q", accrual.OperationState)
	}
}

func TestMsgServerDistributeRewardFinalityAuthorityTransitionsExistingDistribution(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-finality-authority",
			SessionID:       "sess-finality-authority",
			ProviderID:      "provider-finality-authority",
			AssetDenom:      "uusdc",
			Amount:          75,
			OperationState:  chaintypes.ReconciliationPending,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}); err != nil {
		t.Fatalf("accrue failed: %v", err)
	}
	submitted := types.DistributionRecord{
		DistributionID: "dist-finality-authority",
		AccrualID:      "acc-finality-authority",
		PayoutRef:      "payout-finality-authority",
		DistributedAt:  1699833601,
		Status:         chaintypes.ReconciliationSubmitted,
	}
	if _, err := server.DistributeReward(DistributeRewardRequest{Distribution: submitted}); err != nil {
		t.Fatalf("submitted distribution failed: %v", err)
	}

	confirmed := submitted
	confirmed.Status = chaintypes.ReconciliationConfirmed
	if _, err := server.DistributeReward(DistributeRewardRequest{Distribution: confirmed}); err == nil {
		t.Fatal("expected finality transition without authority to fail")
	}

	resp, err := server.DistributeReward(DistributeRewardRequest{
		Distribution:           confirmed,
		AllowFinalityAuthority: true,
	})
	if err != nil {
		t.Fatalf("authorized finality transition failed: %v", err)
	}
	if !resp.Existed || resp.Idempotent {
		t.Fatalf("expected existing non-idempotent transition flags, got %+v", resp)
	}
	if resp.Distribution.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected confirmed distribution, got %q", resp.Distribution.Status)
	}
	accrual, ok := k.GetAccrual("acc-finality-authority")
	if !ok {
		t.Fatal("expected accrual after finality")
	}
	if accrual.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected confirmed accrual, got %q", accrual.OperationState)
	}

	replay, err := server.DistributeReward(DistributeRewardRequest{
		Distribution:           confirmed,
		AllowFinalityAuthority: true,
	})
	if err != nil {
		t.Fatalf("authorized finality replay failed: %v", err)
	}
	if !replay.Existed || !replay.Idempotent {
		t.Fatalf("expected existing idempotent finality replay, got %+v", replay)
	}
}

func TestMsgServerRegisterProofRequiresVerifiedTimestampedProof(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)
	proof := types.RewardProofRecord{
		ProofPath:         "traffic-proof/msg-proof-1",
		TrafficProofRef:   "obj://traffic-proof/msg-proof-1",
		TrustContract:     types.RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "rew-msg-proof-1",
		ProviderSubjectID: "provider-msg-proof-1",
		SessionID:         "sess-msg-proof-1",
		PayoutStartUnix:   1776643200,
		PayoutEndUnix:     1777248000,
		RewardMicros:      55,
		Currency:          "uusdc",
		IssuedAtUnix:      1777248001,
	}

	if _, err := server.RegisterProof(RegisterProofRequest{Proof: proof}); err == nil || !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected unverified proof to fail with ErrInvalidProof, got %v", err)
	}
	if _, found := k.GetProof(proof.ProofPath); found {
		t.Fatal("unverified proof should not be stored or squat proof path")
	}

	proof.Verified = true
	proof.VerifierID = "objective-verifier"
	if _, err := server.RegisterProof(RegisterProofRequest{Proof: proof}); err == nil || !errors.Is(err, ErrInvalidProof) {
		t.Fatalf("expected verified proof without timestamp to fail with ErrInvalidProof, got %v", err)
	}
	if _, found := k.GetProof(proof.ProofPath); found {
		t.Fatal("timestamp-missing proof should not be stored or squat proof path")
	}

	proof.VerifiedAtUnix = 1777248002
	resp, err := server.RegisterProof(RegisterProofRequest{Proof: proof})
	if err != nil {
		t.Fatalf("expected timestamped verified proof to register, got %v", err)
	}
	if resp.Existed || resp.Idempotent {
		t.Fatalf("first proof registration existed=%v idempotent=%v want false/false", resp.Existed, resp.Idempotent)
	}
	if got, found := k.GetProof(proof.ProofPath); !found || got.VerifierID != "objective-verifier" || got.VerifiedAtUnix != proof.VerifiedAtUnix {
		t.Fatalf("stored proof mismatch found=%v proof=%+v", found, got)
	}
}

func TestMsgServerDistributeRewardIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-6",
			SessionID:       "sess-6",
			ProviderID:      "provider-6",
			AssetDenom:      "uusdc",
			Amount:          80,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}); err != nil {
		t.Fatalf("accrue failed: %v", err)
	}

	req := DistributeRewardRequest{
		Distribution: types.DistributionRecord{
			DistributionID: "dist-6",
			AccrualID:      "acc-6",
			PayoutRef:      "payout-6",
		},
	}
	if _, err := server.DistributeReward(req); err != nil {
		t.Fatalf("first distribute failed: %v", err)
	}

	resp, err := server.DistributeReward(req)
	if err != nil {
		t.Fatalf("expected idempotent replay to succeed, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true for replayed distribution")
	}
	if !resp.Idempotent {
		t.Fatal("expected idempotent=true for replayed distribution")
	}
}

func TestMsgServerDistributeRewardInvalidPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.DistributeReward(DistributeRewardRequest{
		Distribution: types.DistributionRecord{
			DistributionID: "",
			AccrualID:      "acc-7",
		},
	})
	if err == nil {
		t.Fatal("expected invalid distribution error")
	}
	if !errors.Is(err, ErrInvalidDistribution) {
		t.Fatalf("expected ErrInvalidDistribution, got %v", err)
	}
}

func TestMsgServerDistributeRewardMissingPayoutRefPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-missing-payout-msg",
			SessionID:       "sess-missing-payout-msg",
			ProviderID:      "provider-missing-payout-msg",
			AssetDenom:      "uusdc",
			Amount:          25,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}); err != nil {
		t.Fatalf("accrue failed: %v", err)
	}

	resp, err := server.DistributeReward(DistributeRewardRequest{
		Distribution: types.DistributionRecord{
			DistributionID: "dist-missing-payout-msg",
			AccrualID:      "acc-missing-payout-msg",
			PayoutRef:      " \t ",
		},
	})
	if err == nil {
		t.Fatal("expected invalid distribution error")
	}
	if !errors.Is(err, ErrInvalidDistribution) {
		t.Fatalf("expected ErrInvalidDistribution, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false for missing payout ref rejection")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false for missing payout ref rejection")
	}
}

func TestMsgServerDistributeRewardConflictPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:       "acc-8",
			SessionID:       "sess-8",
			ProviderID:      "provider-8",
			AssetDenom:      "uusdc",
			Amount:          45,
			PayoutStartUnix: 1699833600,
			PayoutEndUnix:   1699833600 + 7*24*60*60,
		},
	}); err != nil {
		t.Fatalf("accrue failed: %v", err)
	}

	req := DistributeRewardRequest{
		Distribution: types.DistributionRecord{
			DistributionID: "dist-8",
			AccrualID:      "acc-8",
			PayoutRef:      "payout-8",
		},
	}
	if _, err := server.DistributeReward(req); err != nil {
		t.Fatalf("first distribute failed: %v", err)
	}

	conflict := req
	conflict.Distribution.PayoutRef = "payout-8b"
	resp, err := server.DistributeReward(conflict)
	if err == nil {
		t.Fatal("expected distribution conflict error")
	}
	if !errors.Is(err, ErrDistributionConflict) {
		t.Fatalf("expected ErrDistributionConflict, got %v", err)
	}
	if !resp.Existed {
		t.Fatal("expected existed=true on conflict")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on conflict")
	}
}

func TestMsgServerDistributeRewardMissingAccrualPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	_, err := server.DistributeReward(DistributeRewardRequest{
		Distribution: types.DistributionRecord{
			DistributionID: "dist-9",
			AccrualID:      "missing",
			PayoutRef:      "payout-9",
		},
	})
	if err == nil {
		t.Fatal("expected accrual not found error")
	}
	if !errors.Is(err, ErrAccrualNotFound) {
		t.Fatalf("expected ErrAccrualNotFound, got %v", err)
	}
}

func TestMsgServerDistributeRewardFailsClosedWhenAccrualHasNoProviderSubject(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	k.UpsertAccrual(types.RewardAccrual{
		AccrualID:  "acc-no-provider-subject",
		SessionID:  "sess-no-provider-subject",
		AssetDenom: "uusdc",
		Amount:     10,
	})

	resp, err := server.DistributeReward(DistributeRewardRequest{
		Distribution: types.DistributionRecord{
			DistributionID: "dist-no-provider-subject",
			AccrualID:      "acc-no-provider-subject",
			PayoutRef:      "payout-no-provider-subject",
		},
	})
	if err == nil {
		t.Fatal("expected fail-closed unauthorized distribution error")
	}
	if !errors.Is(err, ErrUnauthorizedDistribution) {
		t.Fatalf("expected ErrUnauthorizedDistribution, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false on unauthorized distribution")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on unauthorized distribution")
	}
	if _, ok := k.GetDistribution("dist-no-provider-subject"); ok {
		t.Fatal("expected no distribution write on unauthorized distribution")
	}
}

func TestMsgServerDistributeRewardFailsClosedWhenAccrualOperationStateFailed(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	k.UpsertAccrual(types.RewardAccrual{
		AccrualID:      "acc-failed-state",
		SessionID:      "sess-failed-state",
		ProviderID:     "provider-failed-state",
		AssetDenom:     "uusdc",
		Amount:         10,
		OperationState: chaintypes.ReconciliationFailed,
	})

	resp, err := server.DistributeReward(DistributeRewardRequest{
		Distribution: types.DistributionRecord{
			DistributionID: "dist-failed-state",
			AccrualID:      "acc-failed-state",
			PayoutRef:      "payout-failed-state",
		},
	})
	if err == nil {
		t.Fatal("expected fail-closed invalid distribution error for failed accrual state")
	}
	if !errors.Is(err, ErrInvalidDistribution) {
		t.Fatalf("expected ErrInvalidDistribution, got %v", err)
	}
	if resp.Existed {
		t.Fatal("expected existed=false on failed accrual state rejection")
	}
	if resp.Idempotent {
		t.Fatal("expected idempotent=false on failed accrual state rejection")
	}
	if _, ok := k.GetDistribution("dist-failed-state"); ok {
		t.Fatal("expected no distribution write when accrual state is failed")
	}
}

func TestMsgServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewMsgServer(k)

	_, accrueErr := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:  "acc-nil",
			SessionID:  "sess-nil",
			ProviderID: "provider-nil",
			Amount:     1,
		},
	})
	if !errors.Is(accrueErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on accrue, got %v", accrueErr)
	}

	_, distErr := server.DistributeReward(DistributeRewardRequest{
		Distribution: types.DistributionRecord{
			DistributionID: "dist-nil",
			AccrualID:      "acc-nil",
		},
	})
	if !errors.Is(distErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper on distribute, got %v", distErr)
	}
}
