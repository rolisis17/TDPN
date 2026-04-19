package module

import (
	"errors"
	"fmt"

	"github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

var (
	ErrPenaltyNotFound = errors.New("vpnslashing: penalty not found")
)

const maxQueryListResults = 1000

// GetEvidenceRequest requests slash evidence by evidence ID.
type GetEvidenceRequest struct {
	EvidenceID string
}

// GetEvidenceResponse contains an evidence lookup result.
type GetEvidenceResponse struct {
	Evidence types.SlashEvidence
}

// GetPenaltyRequest requests a penalty by penalty ID.
type GetPenaltyRequest struct {
	PenaltyID string
}

// GetPenaltyResponse contains a penalty lookup result.
type GetPenaltyResponse struct {
	Penalty types.PenaltyDecision
}

// ListEvidenceRequest requests all evidence records.
type ListEvidenceRequest struct{}

// ListEvidenceResponse contains evidence records ordered by evidence_id.
type ListEvidenceResponse struct {
	Evidence []types.SlashEvidence
}

// ListPenaltiesRequest requests all penalty records.
type ListPenaltiesRequest struct{}

// ListPenaltiesResponse contains penalty records ordered by penalty_id.
type ListPenaltiesResponse struct {
	Penalties []types.PenaltyDecision
}

// QueryServer exposes a lightweight Cosmos-style query surface for vpnslashing.
type QueryServer struct {
	keeper *keeper.Keeper
}

func NewQueryServer(k *keeper.Keeper) QueryServer {
	return QueryServer{keeper: k}
}

func (s QueryServer) GetEvidence(req GetEvidenceRequest) (GetEvidenceResponse, error) {
	if s.keeper == nil {
		return GetEvidenceResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetEvidence(req.EvidenceID)
	if !ok {
		return GetEvidenceResponse{}, fmt.Errorf("%w: evidence_id=%s", ErrEvidenceNotFound, req.EvidenceID)
	}
	return GetEvidenceResponse{Evidence: record}, nil
}

func (s QueryServer) GetPenalty(req GetPenaltyRequest) (GetPenaltyResponse, error) {
	if s.keeper == nil {
		return GetPenaltyResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetPenalty(req.PenaltyID)
	if !ok {
		return GetPenaltyResponse{}, fmt.Errorf("%w: penalty_id=%s", ErrPenaltyNotFound, req.PenaltyID)
	}
	return GetPenaltyResponse{Penalty: record}, nil
}

func (s QueryServer) ListEvidence(req ListEvidenceRequest) (ListEvidenceResponse, error) {
	_ = req
	if s.keeper == nil {
		return ListEvidenceResponse{}, ErrNilKeeper
	}

	records := s.keeper.ListEvidence()
	return ListEvidenceResponse{Evidence: clampEvidence(records)}, nil
}

func (s QueryServer) ListPenalties(req ListPenaltiesRequest) (ListPenaltiesResponse, error) {
	_ = req
	if s.keeper == nil {
		return ListPenaltiesResponse{}, ErrNilKeeper
	}

	records := s.keeper.ListPenalties()
	return ListPenaltiesResponse{Penalties: clampPenalties(records)}, nil
}

func clampEvidence(records []types.SlashEvidence) []types.SlashEvidence {
	if len(records) <= maxQueryListResults {
		return records
	}
	return records[:maxQueryListResults]
}

func clampPenalties(records []types.PenaltyDecision) []types.PenaltyDecision {
	if len(records) <= maxQueryListResults {
		return records
	}
	return records[:maxQueryListResults]
}
