package module

import (
	"errors"
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
			AccrualID:  "acc-1",
			SessionID:  "sess-1",
			ProviderID: "provider-1",
			AssetDenom: "uusdc",
			Amount:     50,
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
			AccrualID:  "acc-2",
			SessionID:  "sess-2",
			ProviderID: "provider-2",
			Amount:     25,
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
			AccrualID:  "acc-4",
			SessionID:  "sess-4",
			ProviderID: "provider-4",
			Amount:     100,
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

func TestMsgServerDistributeRewardHappyPath(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:      "acc-5",
			SessionID:      "sess-5",
			ProviderID:     "provider-5",
			Amount:         75,
			OperationState: chaintypes.ReconciliationSubmitted,
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
	if accrual.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected accrual state %q after distribution, got %q", chaintypes.ReconciliationConfirmed, accrual.OperationState)
	}
}

func TestMsgServerDistributeRewardIdempotentReplay(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewMsgServer(&k)

	if _, err := server.AccrueReward(AccrueRewardRequest{
		Accrual: types.RewardAccrual{
			AccrualID:  "acc-6",
			SessionID:  "sess-6",
			ProviderID: "provider-6",
			Amount:     80,
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
			AccrualID:  "acc-missing-payout-msg",
			SessionID:  "sess-missing-payout-msg",
			ProviderID: "provider-missing-payout-msg",
			Amount:     25,
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
			AccrualID:  "acc-8",
			SessionID:  "sess-8",
			ProviderID: "provider-8",
			Amount:     45,
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
