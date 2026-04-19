package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	governancemodule "github.com/tdpn/tdpn-chain/x/vpngovernance/module"
	governancetypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
	rewardsmodule "github.com/tdpn/tdpn-chain/x/vpnrewards/module"
	rewardstypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
	slashingmodule "github.com/tdpn/tdpn-chain/x/vpnslashing/module"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

func TestRewardsMsgServer_RecordDistribution_PassesThroughInvalidDistributionError(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.RewardsMsgServer()

	_, err := server.RecordDistribution(context.Background(), RewardsRecordDistributionRequest{
		Record: rewardstypes.DistributionRecord{
			AccrualID: "acc-1",
		},
	})
	if err == nil {
		t.Fatal("expected invalid distribution error")
	}
	if !errors.Is(err, rewardsmodule.ErrInvalidDistribution) {
		t.Fatalf("expected errors.Is(err, ErrInvalidDistribution), got %v", err)
	}
	if errors.Is(err, errRewardsKeeperNotWired) {
		t.Fatalf("expected passthrough error, got keeper wiring error: %v", err)
	}
	if !strings.Contains(err.Error(), "distribution id is required") {
		t.Fatalf("expected validation message in error, got %v", err)
	}
}

func TestSlashingMsgServer_ApplyPenalty_PassesThroughInvalidPenaltyError(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SlashingMsgServer()

	_, err := server.ApplyPenalty(context.Background(), SlashingApplyPenaltyRequest{
		Record: slashingtypes.PenaltyDecision{
			EvidenceID:      "evidence-1",
			SlashBasisPoint: 100,
		},
	})
	if err == nil {
		t.Fatal("expected invalid penalty error")
	}
	if !errors.Is(err, slashingmodule.ErrInvalidPenalty) {
		t.Fatalf("expected errors.Is(err, ErrInvalidPenalty), got %v", err)
	}
	if errors.Is(err, errSlashingKeeperNotWired) {
		t.Fatalf("expected passthrough error, got keeper wiring error: %v", err)
	}
	if !strings.Contains(err.Error(), "penalty id is required") {
		t.Fatalf("expected validation message in error, got %v", err)
	}
}

func TestGovernanceMsgServer_RecordAuditAction_PassesThroughInvalidAuditActionError(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.GovernanceMsgServer()

	_, err := server.RecordAuditAction(context.Background(), GovernanceRecordAuditActionRequest{
		Record: governancetypes.GovernanceAuditAction{
			Action:          "policy.override",
			Actor:           "bootstrap-multisig",
			Reason:          "rollback",
			EvidencePointer: "obj://audit/action-1",
			TimestampUnix:   1735689800,
		},
	})
	if err == nil {
		t.Fatal("expected invalid audit action error")
	}
	if !errors.Is(err, governancemodule.ErrInvalidAuditAction) {
		t.Fatalf("expected errors.Is(err, ErrInvalidAuditAction), got %v", err)
	}
	if errors.Is(err, errGovernanceKeeperNotWired) {
		t.Fatalf("expected passthrough error, got keeper wiring error: %v", err)
	}
	if !strings.Contains(err.Error(), "action id is required") {
		t.Fatalf("expected validation message in error, got %v", err)
	}
}
