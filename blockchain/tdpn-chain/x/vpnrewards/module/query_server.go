package module

import (
	"errors"
	"fmt"

	"github.com/tdpn/tdpn-chain/x/vpnrewards/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

var (
	ErrDistributionNotFound = errors.New("vpnrewards: distribution not found")
	ErrProofNotFound        = errors.New("vpnrewards: proof not found")
)

const maxQueryListResults = 1000

// GetAccrualRequest requests a reward accrual by accrual ID.
type GetAccrualRequest struct {
	AccrualID string
}

// GetAccrualResponse contains an accrual lookup result.
type GetAccrualResponse struct {
	Accrual types.RewardAccrual
}

// GetDistributionRequest requests a distribution by distribution ID.
type GetDistributionRequest struct {
	DistributionID string
}

// GetDistributionResponse contains a distribution lookup result.
type GetDistributionResponse struct {
	Distribution types.DistributionRecord
}

// GetProofRequest requests a verified reward proof by proof path.
type GetProofRequest struct {
	ProofPath string
}

// GetProofResponse contains a reward proof lookup result.
type GetProofResponse struct {
	Proof types.RewardProofRecord
}

// ListAccrualsRequest requests all accruals.
type ListAccrualsRequest struct{}

// ListAccrualsResponse contains accrual list results.
type ListAccrualsResponse struct {
	Accruals []types.RewardAccrual
}

// ListDistributionsRequest requests all distributions.
type ListDistributionsRequest struct{}

// ListDistributionsResponse contains distribution list results.
type ListDistributionsResponse struct {
	Distributions []types.DistributionRecord
}

// QueryServer exposes a lightweight Cosmos-style query surface for vpnrewards.
type QueryServer struct {
	keeper *keeper.Keeper
}

func NewQueryServer(k *keeper.Keeper) QueryServer {
	return QueryServer{keeper: k}
}

func (s QueryServer) GetAccrual(req GetAccrualRequest) (GetAccrualResponse, error) {
	if s.keeper == nil {
		return GetAccrualResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetAccrual(req.AccrualID)
	if !ok {
		return GetAccrualResponse{}, fmt.Errorf("%w: accrual_id=%s", ErrAccrualNotFound, req.AccrualID)
	}
	return GetAccrualResponse{Accrual: record}, nil
}

func (s QueryServer) GetDistribution(req GetDistributionRequest) (GetDistributionResponse, error) {
	if s.keeper == nil {
		return GetDistributionResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetDistribution(req.DistributionID)
	if !ok {
		return GetDistributionResponse{}, fmt.Errorf("%w: distribution_id=%s", ErrDistributionNotFound, req.DistributionID)
	}
	return GetDistributionResponse{Distribution: record}, nil
}

func (s QueryServer) GetProof(req GetProofRequest) (GetProofResponse, error) {
	if s.keeper == nil {
		return GetProofResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetVerifiedProof(req.ProofPath)
	if !ok {
		return GetProofResponse{}, fmt.Errorf("%w: proof_path=%s", ErrProofNotFound, req.ProofPath)
	}
	return GetProofResponse{Proof: record}, nil
}

func (s QueryServer) ListAccruals(_ ListAccrualsRequest) (ListAccrualsResponse, error) {
	if s.keeper == nil {
		return ListAccrualsResponse{}, ErrNilKeeper
	}

	records, err := s.keeper.ListAccrualsWithError()
	if err != nil {
		return ListAccrualsResponse{}, err
	}
	return ListAccrualsResponse{Accruals: clampAccruals(records)}, nil
}

func (s QueryServer) ListDistributions(_ ListDistributionsRequest) (ListDistributionsResponse, error) {
	if s.keeper == nil {
		return ListDistributionsResponse{}, ErrNilKeeper
	}

	records, err := s.keeper.ListDistributionsWithError()
	if err != nil {
		return ListDistributionsResponse{}, err
	}
	return ListDistributionsResponse{Distributions: clampDistributions(records)}, nil
}

func clampAccruals(records []types.RewardAccrual) []types.RewardAccrual {
	if len(records) <= maxQueryListResults {
		return records
	}
	return records[:maxQueryListResults]
}

func clampDistributions(records []types.DistributionRecord) []types.DistributionRecord {
	if len(records) <= maxQueryListResults {
		return records
	}
	return records[:maxQueryListResults]
}
