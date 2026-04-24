package app

import (
	"context"
	"errors"

	rewardsmodule "github.com/tdpn/tdpn-chain/x/vpnrewards/module"
	rewardstypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

var (
	errRewardsKeeperNotWired = errors.New("vpnrewards keeper is not wired")
)

// RewardsMsgServer exposes phase-1 vpnrewards operations through the scaffold.
type RewardsMsgServer interface {
	CreateAccrual(context.Context, RewardsCreateAccrualRequest) (RewardsCreateAccrualResponse, error)
	RecordDistribution(context.Context, RewardsRecordDistributionRequest) (RewardsRecordDistributionResponse, error)
}

type RewardsCreateAccrualRequest struct {
	Record rewardstypes.RewardAccrual
}

type RewardsCreateAccrualResponse struct {
	Accrual rewardstypes.RewardAccrual
	Replay  bool
}

type RewardsRecordDistributionRequest struct {
	Record rewardstypes.DistributionRecord
}

type RewardsRecordDistributionResponse struct {
	Distribution rewardstypes.DistributionRecord
	Replay       bool
}

type rewardsMsgServer struct {
	msgServer rewardsmodule.MsgServer
}

func (m rewardsMsgServer) CreateAccrual(ctx context.Context, req RewardsCreateAccrualRequest) (RewardsCreateAccrualResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return RewardsCreateAccrualResponse{}, err
		}
	}

	resp, err := m.msgServer.AccrueReward(rewardsmodule.AccrueRewardRequest{Accrual: req.Record})
	if err != nil {
		if errors.Is(err, rewardsmodule.ErrNilKeeper) {
			return RewardsCreateAccrualResponse{}, errRewardsKeeperNotWired
		}
		return RewardsCreateAccrualResponse{}, err
	}
	return RewardsCreateAccrualResponse{
		Accrual: resp.Accrual,
		Replay:  resp.Idempotent,
	}, nil
}

func (m rewardsMsgServer) RecordDistribution(ctx context.Context, req RewardsRecordDistributionRequest) (RewardsRecordDistributionResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return RewardsRecordDistributionResponse{}, err
		}
	}

	resp, err := m.msgServer.DistributeReward(rewardsmodule.DistributeRewardRequest{Distribution: req.Record})
	if err != nil {
		if errors.Is(err, rewardsmodule.ErrNilKeeper) {
			return RewardsRecordDistributionResponse{}, errRewardsKeeperNotWired
		}
		return RewardsRecordDistributionResponse{}, err
	}
	return RewardsRecordDistributionResponse{
		Distribution: resp.Distribution,
		Replay:       resp.Idempotent,
	}, nil
}
