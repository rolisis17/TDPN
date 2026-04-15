package app

import (
	"context"
	"errors"

	slashingmodule "github.com/tdpn/tdpn-chain/x/vpnslashing/module"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

// SlashingQueryServer exposes phase-1 vpnslashing query operations through the scaffold.
type SlashingQueryServer interface {
	GetEvidence(context.Context, SlashingGetEvidenceRequest) (SlashingGetEvidenceResponse, error)
	GetPenalty(context.Context, SlashingGetPenaltyRequest) (SlashingGetPenaltyResponse, error)
	ListEvidence(context.Context, SlashingListEvidenceRequest) (SlashingListEvidenceResponse, error)
	ListPenalties(context.Context, SlashingListPenaltiesRequest) (SlashingListPenaltiesResponse, error)
}

type SlashingGetEvidenceRequest struct {
	EvidenceID string
}

type SlashingGetEvidenceResponse struct {
	Evidence slashingtypes.SlashEvidence
	Found    bool
}

type SlashingGetPenaltyRequest struct {
	PenaltyID string
}

type SlashingGetPenaltyResponse struct {
	Penalty slashingtypes.PenaltyDecision
	Found   bool
}

type SlashingListEvidenceRequest struct{}

type SlashingListEvidenceResponse struct {
	Evidence []slashingtypes.SlashEvidence
}

type SlashingListPenaltiesRequest struct{}

type SlashingListPenaltiesResponse struct {
	Penalties []slashingtypes.PenaltyDecision
}

type slashingQueryServer struct {
	queryServer slashingmodule.QueryServer
}

func (m slashingQueryServer) GetEvidence(_ context.Context, req SlashingGetEvidenceRequest) (SlashingGetEvidenceResponse, error) {
	resp, err := m.queryServer.GetEvidence(slashingmodule.GetEvidenceRequest{EvidenceID: req.EvidenceID})
	if err != nil {
		if errors.Is(err, slashingmodule.ErrNilKeeper) {
			return SlashingGetEvidenceResponse{}, errSlashingKeeperNotWired
		}
		if errors.Is(err, slashingmodule.ErrEvidenceNotFound) {
			return SlashingGetEvidenceResponse{Found: false}, nil
		}
		return SlashingGetEvidenceResponse{}, err
	}
	return SlashingGetEvidenceResponse{
		Evidence: resp.Evidence,
		Found:    true,
	}, nil
}

func (m slashingQueryServer) GetPenalty(_ context.Context, req SlashingGetPenaltyRequest) (SlashingGetPenaltyResponse, error) {
	resp, err := m.queryServer.GetPenalty(slashingmodule.GetPenaltyRequest{PenaltyID: req.PenaltyID})
	if err != nil {
		if errors.Is(err, slashingmodule.ErrNilKeeper) {
			return SlashingGetPenaltyResponse{}, errSlashingKeeperNotWired
		}
		if errors.Is(err, slashingmodule.ErrPenaltyNotFound) {
			return SlashingGetPenaltyResponse{Found: false}, nil
		}
		return SlashingGetPenaltyResponse{}, err
	}
	return SlashingGetPenaltyResponse{
		Penalty: resp.Penalty,
		Found:   true,
	}, nil
}

func (m slashingQueryServer) ListEvidence(_ context.Context, _ SlashingListEvidenceRequest) (SlashingListEvidenceResponse, error) {
	resp, err := m.queryServer.ListEvidence(slashingmodule.ListEvidenceRequest{})
	if err != nil {
		if errors.Is(err, slashingmodule.ErrNilKeeper) {
			return SlashingListEvidenceResponse{}, errSlashingKeeperNotWired
		}
		return SlashingListEvidenceResponse{}, err
	}
	return SlashingListEvidenceResponse{
		Evidence: resp.Evidence,
	}, nil
}

func (m slashingQueryServer) ListPenalties(_ context.Context, _ SlashingListPenaltiesRequest) (SlashingListPenaltiesResponse, error) {
	resp, err := m.queryServer.ListPenalties(slashingmodule.ListPenaltiesRequest{})
	if err != nil {
		if errors.Is(err, slashingmodule.ErrNilKeeper) {
			return SlashingListPenaltiesResponse{}, errSlashingKeeperNotWired
		}
		return SlashingListPenaltiesResponse{}, err
	}
	return SlashingListPenaltiesResponse{
		Penalties: resp.Penalties,
	}, nil
}
