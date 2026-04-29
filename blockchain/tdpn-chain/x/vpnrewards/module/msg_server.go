package module

import (
	"errors"
	"fmt"
	"strings"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

var (
	ErrNilKeeper                = errors.New("vpnrewards: keeper is nil")
	ErrInvalidAccrual           = errors.New("vpnrewards: invalid accrual")
	ErrInvalidDistribution      = errors.New("vpnrewards: invalid distribution")
	ErrInvalidProof             = errors.New("vpnrewards: invalid proof")
	ErrAccrualConflict          = errors.New("vpnrewards: accrual conflict")
	ErrDistributionConflict     = errors.New("vpnrewards: distribution conflict")
	ErrProofConflict            = errors.New("vpnrewards: proof conflict")
	ErrAccrualNotFound          = errors.New("vpnrewards: accrual not found")
	ErrUnauthorizedDistribution = errors.New("vpnrewards: unauthorized distribution")
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
	Distribution           types.DistributionRecord
	AllowFinalityAuthority bool
}

// DistributeRewardResponse returns the persisted distribution plus idempotency flags.
type DistributeRewardResponse struct {
	Distribution types.DistributionRecord
	Existed      bool
	Idempotent   bool
}

// RegisterProofRequest captures an intent to persist a verified reward proof.
type RegisterProofRequest struct {
	Proof types.RewardProofRecord
}

// RegisterProofResponse returns the persisted proof plus idempotency flags.
type RegisterProofResponse struct {
	Proof      types.RewardProofRecord
	Existed    bool
	Idempotent bool
}

// MsgServer exposes a lightweight Cosmos-style message surface for vpnrewards.
type MsgServer struct {
	keeper *keeper.Keeper
}

const weeklyPayoutEpochSeconds int64 = 7 * 24 * 60 * 60
const weeklyPayoutMondayOffsetSeconds int64 = 3 * 24 * 60 * 60

func NewMsgServer(k *keeper.Keeper) MsgServer {
	return MsgServer{keeper: k}
}

func (s MsgServer) AccrueReward(req AccrueRewardRequest) (AccrueRewardResponse, error) {
	if s.keeper == nil {
		return AccrueRewardResponse{}, ErrNilKeeper
	}
	accrual := req.Accrual
	fillAccrualWeeklyPayoutPeriod(&accrual)
	if accrual.PayoutStartUnix <= 0 || accrual.PayoutEndUnix <= 0 {
		return AccrueRewardResponse{}, fmt.Errorf("%w: payout start and end are required for chain reward accrual", ErrInvalidAccrual)
	}

	existed := false
	if accrual.AccrualID != "" {
		_, existed = s.keeper.GetAccrual(accrual.AccrualID)
	}

	record, err := s.keeper.CreateAccrual(accrual)
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

func (s MsgServer) RegisterProof(req RegisterProofRequest) (RegisterProofResponse, error) {
	if s.keeper == nil {
		return RegisterProofResponse{}, ErrNilKeeper
	}
	proof := req.Proof
	fillProofWeeklyPayoutPeriod(&proof)
	if proof.PayoutStartUnix <= 0 || proof.PayoutEndUnix <= 0 {
		return RegisterProofResponse{}, fmt.Errorf("%w: payout start and end are required for chain reward proof", ErrInvalidProof)
	}
	if err := proof.ValidateVerified(); err != nil {
		return RegisterProofResponse{}, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}

	existed := false
	if proof.ProofPath != "" {
		_, existed = s.keeper.GetProof(proof.ProofPath)
	}
	err := s.keeper.UpsertProofWithError(proof)
	record, found := s.keeper.GetProof(proof.ProofPath)
	if !found {
		record = proof.Canonicalize()
	}
	resp := RegisterProofResponse{
		Proof:      record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrProofConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}
	return resp, nil
}

func fillAccrualWeeklyPayoutPeriod(record *types.RewardAccrual) {
	if record == nil || record.PayoutStartUnix > 0 || record.PayoutEndUnix > 0 {
		return
	}
	start, end, ok := weeklyPayoutPeriodForUnix(record.AccruedAtUnix)
	if !ok {
		return
	}
	record.PayoutStartUnix = start
	record.PayoutEndUnix = end
}

func fillProofWeeklyPayoutPeriod(record *types.RewardProofRecord) {
	if record == nil || record.PayoutStartUnix > 0 || record.PayoutEndUnix > 0 {
		return
	}
	start, end, ok := weeklyPayoutPeriodForUnix(record.IssuedAtUnix)
	if !ok {
		return
	}
	record.PayoutStartUnix = start
	record.PayoutEndUnix = end
}

func weeklyPayoutPeriodForUnix(unixSeconds int64) (int64, int64, bool) {
	if unixSeconds <= 0 {
		return 0, 0, false
	}
	epoch := (unixSeconds + weeklyPayoutMondayOffsetSeconds) / weeklyPayoutEpochSeconds
	start := epoch*weeklyPayoutEpochSeconds - weeklyPayoutMondayOffsetSeconds
	return start, start + weeklyPayoutEpochSeconds, true
}

func (s MsgServer) DistributeReward(req DistributeRewardRequest) (DistributeRewardResponse, error) {
	if s.keeper == nil {
		return DistributeRewardResponse{}, ErrNilKeeper
	}
	distribution := req.Distribution.Canonicalize()
	if err := distribution.ValidateBasic(); err != nil {
		return DistributeRewardResponse{}, fmt.Errorf("%w: %v", ErrInvalidDistribution, err)
	}

	existed := false
	var existingDistribution types.DistributionRecord
	if distribution.DistributionID != "" {
		existingDistribution, existed = s.keeper.GetDistribution(distribution.DistributionID)
	}
	if !req.AllowFinalityAuthority && (distribution.Status == chaintypes.ReconciliationConfirmed || distribution.Status == chaintypes.ReconciliationFailed) {
		return DistributeRewardResponse{
				Distribution: distribution,
				Existed:      existed,
				Idempotent:   false,
			}, fmt.Errorf(
				"%w: distribution status %q requires finality authority",
				ErrInvalidDistribution,
				distribution.Status,
			)
	}
	if strings.TrimSpace(distribution.AccrualID) != "" {
		accrual, ok := s.keeper.GetAccrual(distribution.AccrualID)
		if !ok {
			return DistributeRewardResponse{
				Distribution: distribution,
				Existed:      existed,
				Idempotent:   false,
			}, fmt.Errorf("%w: accrual_id=%s", ErrAccrualNotFound, distribution.AccrualID)
		}
		if strings.TrimSpace(accrual.ProviderID) == "" {
			return DistributeRewardResponse{
				Distribution: distribution,
				Existed:      existed,
				Idempotent:   false,
			}, fmt.Errorf("%w: accrual_id=%s has no provider subject", ErrUnauthorizedDistribution, distribution.AccrualID)
		}
		if !existed && accrual.OperationState == chaintypes.ReconciliationFailed {
			return DistributeRewardResponse{
					Distribution: distribution,
					Existed:      existed,
					Idempotent:   false,
				}, fmt.Errorf(
					"%w: accrual_id=%s has operation_state=%s",
					ErrInvalidDistribution,
					accrual.AccrualID,
					accrual.OperationState,
				)
		}
	}

	var record types.DistributionRecord
	var err error
	if req.AllowFinalityAuthority {
		record, err = s.keeper.RecordDistributionWithFinalityAuthority(distribution)
	} else {
		record, err = s.keeper.RecordDistribution(distribution)
	}
	idempotent := false
	if err == nil && existed {
		idempotent = moduleDistributionRecordsEqual(existingDistribution, record)
	}
	resp := DistributeRewardResponse{
		Distribution: record,
		Existed:      existed,
		Idempotent:   idempotent,
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

func moduleDistributionRecordsEqual(a, b types.DistributionRecord) bool {
	a = a.Canonicalize()
	b = b.Canonicalize()
	return a.DistributionID == b.DistributionID &&
		a.AccrualID == b.AccrualID &&
		a.PayoutRef == b.PayoutRef &&
		a.DistributedAt == b.DistributedAt &&
		a.Status == b.Status
}
