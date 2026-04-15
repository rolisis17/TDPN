package app

import (
	"context"
	"errors"

	rewardsmodule "github.com/tdpn/tdpn-chain/x/vpnrewards/module"
	rewardstypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

// RewardsQueryServer exposes phase-1 vpnrewards query operations through the scaffold.
type RewardsQueryServer interface {
	GetAccrual(context.Context, RewardsGetAccrualRequest) (RewardsGetAccrualResponse, error)
	GetDistribution(context.Context, RewardsGetDistributionRequest) (RewardsGetDistributionResponse, error)
	ListAccruals(context.Context, RewardsListAccrualsRequest) (RewardsListAccrualsResponse, error)
	ListDistributions(context.Context, RewardsListDistributionsRequest) (RewardsListDistributionsResponse, error)
}

type RewardsGetAccrualRequest struct {
	AccrualID string
}

type RewardsGetAccrualResponse struct {
	Accrual rewardstypes.RewardAccrual
	Found   bool
}

type RewardsGetDistributionRequest struct {
	DistributionID string
}

type RewardsGetDistributionResponse struct {
	Distribution rewardstypes.DistributionRecord
	Found        bool
}

type RewardsListAccrualsRequest struct{}

type RewardsListAccrualsResponse struct {
	Accruals []rewardstypes.RewardAccrual
}

type RewardsListDistributionsRequest struct{}

type RewardsListDistributionsResponse struct {
	Distributions []rewardstypes.DistributionRecord
}

type rewardsQueryServer struct {
	queryServer rewardsmodule.QueryServer
}

func (m rewardsQueryServer) GetAccrual(_ context.Context, req RewardsGetAccrualRequest) (RewardsGetAccrualResponse, error) {
	resp, err := m.queryServer.GetAccrual(rewardsmodule.GetAccrualRequest{AccrualID: req.AccrualID})
	if err != nil {
		if errors.Is(err, rewardsmodule.ErrNilKeeper) {
			return RewardsGetAccrualResponse{}, errRewardsKeeperNotWired
		}
		if errors.Is(err, rewardsmodule.ErrAccrualNotFound) {
			return RewardsGetAccrualResponse{Found: false}, nil
		}
		return RewardsGetAccrualResponse{}, err
	}
	return RewardsGetAccrualResponse{
		Accrual: resp.Accrual,
		Found:   true,
	}, nil
}

func (m rewardsQueryServer) GetDistribution(_ context.Context, req RewardsGetDistributionRequest) (RewardsGetDistributionResponse, error) {
	resp, err := m.queryServer.GetDistribution(rewardsmodule.GetDistributionRequest{DistributionID: req.DistributionID})
	if err != nil {
		if errors.Is(err, rewardsmodule.ErrNilKeeper) {
			return RewardsGetDistributionResponse{}, errRewardsKeeperNotWired
		}
		if errors.Is(err, rewardsmodule.ErrDistributionNotFound) {
			return RewardsGetDistributionResponse{Found: false}, nil
		}
		return RewardsGetDistributionResponse{}, err
	}
	return RewardsGetDistributionResponse{
		Distribution: resp.Distribution,
		Found:        true,
	}, nil
}

func (m rewardsQueryServer) ListAccruals(_ context.Context, _ RewardsListAccrualsRequest) (RewardsListAccrualsResponse, error) {
	resp, err := m.queryServer.ListAccruals(rewardsmodule.ListAccrualsRequest{})
	if err != nil {
		if errors.Is(err, rewardsmodule.ErrNilKeeper) {
			return RewardsListAccrualsResponse{}, errRewardsKeeperNotWired
		}
		return RewardsListAccrualsResponse{}, err
	}
	return RewardsListAccrualsResponse{
		Accruals: resp.Accruals,
	}, nil
}

func (m rewardsQueryServer) ListDistributions(_ context.Context, _ RewardsListDistributionsRequest) (RewardsListDistributionsResponse, error) {
	resp, err := m.queryServer.ListDistributions(rewardsmodule.ListDistributionsRequest{})
	if err != nil {
		if errors.Is(err, rewardsmodule.ErrNilKeeper) {
			return RewardsListDistributionsResponse{}, errRewardsKeeperNotWired
		}
		return RewardsListDistributionsResponse{}, err
	}
	return RewardsListDistributionsResponse{
		Distributions: resp.Distributions,
	}, nil
}
