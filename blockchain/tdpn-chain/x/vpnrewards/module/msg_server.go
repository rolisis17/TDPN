package module

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

var (
	ErrNilKeeper            = errors.New("vpnrewards: keeper is nil")
	ErrInvalidAccrual       = errors.New("vpnrewards: invalid accrual")
	ErrInvalidDistribution  = errors.New("vpnrewards: invalid distribution")
	ErrAccrualConflict      = errors.New("vpnrewards: accrual conflict")
	ErrDistributionConflict = errors.New("vpnrewards: distribution conflict")
	ErrAccrualNotFound      = errors.New("vpnrewards: accrual not found")
)

// AccrueRewardRequest captures an intent to persist a reward accrual.
type AccrueRewardRequest struct {
	Accrual types.RewardAccrual
}

// AccrueRewardResponse returns the persisted accrual plus idempotency flags.
type AccrueRewardResponse struct {
	Accrual    types.RewardAccrual
	Existed    bool
	Idempotent bool
}

// DistributeRewardRequest captures an intent to persist reward distribution.
type DistributeRewardRequest struct {
	Distribution types.DistributionRecord
}

// DistributeRewardResponse returns the persisted distribution plus idempotency flags.
type DistributeRewardResponse struct {
	Distribution types.DistributionRecord
	Existed      bool
	Idempotent   bool
}

// MsgServer exposes a lightweight Cosmos-style message surface for vpnrewards.
type MsgServer struct {
	keeper *keeper.Keeper
}

func NewMsgServer(k *keeper.Keeper) MsgServer {
	return MsgServer{keeper: k}
}

func (s MsgServer) AccrueReward(req AccrueRewardRequest) (AccrueRewardResponse, error) {
	if s.keeper == nil {
		return AccrueRewardResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Accrual.AccrualID != "" {
		_, existed = s.keeper.GetAccrual(req.Accrual.AccrualID)
	}

	record, err := s.keeper.CreateAccrual(req.Accrual)
	resp := AccrueRewardResponse{
		Accrual:    record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrAccrualConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidAccrual, err)
	}
	return resp, nil
}

func (s MsgServer) DistributeReward(req DistributeRewardRequest) (DistributeRewardResponse, error) {
	if s.keeper == nil {
		return DistributeRewardResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Distribution.DistributionID != "" {
		_, existed = s.keeper.GetDistribution(req.Distribution.DistributionID)
	}

	record, err := s.keeper.RecordDistribution(req.Distribution)
	resp := DistributeRewardResponse{
		Distribution: record,
		Existed:      existed,
		Idempotent:   existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return resp, fmt.Errorf("%w: %v", ErrAccrualNotFound, err)
		}
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrDistributionConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidDistribution, err)
	}
	return resp, nil
}
