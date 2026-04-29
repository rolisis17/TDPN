package app

import (
	"context"
	"errors"

	rewardsmodule "github.com/tdpn/tdpn-chain/x/vpnrewards/module"
	rewardstypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

var (
	errRewardsKeeperNotWired       = errors.New("vpnrewards keeper is not wired")
	errRewardsFinalityUnauthorized = errors.New("vpnrewards finality authority is not permitted by context")
)

type rewardsFinalityAuthorityContextKey struct{}

// WithRewardsFinalityAuthority marks an already-authenticated bridge context as
// allowed to request reward finality transitions through the app facade.
func WithRewardsFinalityAuthority(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, rewardsFinalityAuthorityContextKey{}, true)
}

// RewardsMsgServer exposes phase-1 vpnrewards operations through the scaffold.
type RewardsMsgServer interface {
	CreateAccrual(context.Context, RewardsCreateAccrualRequest) (RewardsCreateAccrualResponse, error)
	RecordDistribution(context.Context, RewardsRecordDistributionRequest) (RewardsRecordDistributionResponse, error)
	RegisterProof(context.Context, RewardsRegisterProofRequest) (RewardsRegisterProofResponse, error)
}

type RewardsCreateAccrualRequest struct {
	Record rewardstypes.RewardAccrual
}

type RewardsCreateAccrualResponse struct {
	Accrual rewardstypes.RewardAccrual
	Replay  bool
}

type RewardsRecordDistributionRequest struct {
	Record                 rewardstypes.DistributionRecord
	AllowFinalityAuthority bool
}

type RewardsRecordDistributionResponse struct {
	Distribution rewardstypes.DistributionRecord
	Replay       bool
}

type RewardsRegisterProofRequest struct {
	Record rewardstypes.RewardProofRecord
}

type RewardsRegisterProofResponse struct {
	Proof  rewardstypes.RewardProofRecord
	Replay bool
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
	allowFinalityAuthority := req.AllowFinalityAuthority && rewardsFinalityAuthorityFromContext(ctx)
	if req.AllowFinalityAuthority && !allowFinalityAuthority {
		return RewardsRecordDistributionResponse{}, errRewardsFinalityUnauthorized
	}

	resp, err := m.msgServer.DistributeReward(rewardsmodule.DistributeRewardRequest{
		Distribution:           req.Record,
		AllowFinalityAuthority: allowFinalityAuthority,
	})
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

func rewardsFinalityAuthorityFromContext(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	allowed, _ := ctx.Value(rewardsFinalityAuthorityContextKey{}).(bool)
	return allowed
}

func (m rewardsMsgServer) RegisterProof(ctx context.Context, req RewardsRegisterProofRequest) (RewardsRegisterProofResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return RewardsRegisterProofResponse{}, err
		}
	}

	resp, err := m.msgServer.RegisterProof(rewardsmodule.RegisterProofRequest{Proof: req.Record})
	if err != nil {
		if errors.Is(err, rewardsmodule.ErrNilKeeper) {
			return RewardsRegisterProofResponse{}, errRewardsKeeperNotWired
		}
		return RewardsRegisterProofResponse{}, err
	}
	return RewardsRegisterProofResponse{
		Proof:  resp.Proof,
		Replay: resp.Idempotent,
	}, nil
}
