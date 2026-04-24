package app

import (
	"context"
	"errors"

	slashingmodule "github.com/tdpn/tdpn-chain/x/vpnslashing/module"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

var (
	errSlashingKeeperNotWired = errors.New("vpnslashing keeper is not wired")
)

// SlashingMsgServer exposes phase-1 vpnslashing operations through the scaffold.
type SlashingMsgServer interface {
	SubmitEvidence(context.Context, SlashingSubmitEvidenceRequest) (SlashingSubmitEvidenceResponse, error)
	ApplyPenalty(context.Context, SlashingApplyPenaltyRequest) (SlashingApplyPenaltyResponse, error)
}

type SlashingSubmitEvidenceRequest struct {
	Record slashingtypes.SlashEvidence
}

type SlashingSubmitEvidenceResponse struct {
	Evidence slashingtypes.SlashEvidence
	Replay   bool
}

type SlashingApplyPenaltyRequest struct {
	Record slashingtypes.PenaltyDecision
}

type SlashingApplyPenaltyResponse struct {
	Penalty slashingtypes.PenaltyDecision
	Replay  bool
}

type slashingMsgServer struct {
	msgServer slashingmodule.MsgServer
}

func (m slashingMsgServer) SubmitEvidence(ctx context.Context, req SlashingSubmitEvidenceRequest) (SlashingSubmitEvidenceResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return SlashingSubmitEvidenceResponse{}, err
		}
	}

	resp, err := m.msgServer.SubmitSlashEvidence(slashingmodule.SubmitSlashEvidenceRequest{Evidence: req.Record})
	if err != nil {
		if errors.Is(err, slashingmodule.ErrNilKeeper) {
			return SlashingSubmitEvidenceResponse{}, errSlashingKeeperNotWired
		}
		return SlashingSubmitEvidenceResponse{}, err
	}
	return SlashingSubmitEvidenceResponse{
		Evidence: resp.Evidence,
		Replay:   resp.Idempotent,
	}, nil
}

func (m slashingMsgServer) ApplyPenalty(ctx context.Context, req SlashingApplyPenaltyRequest) (SlashingApplyPenaltyResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return SlashingApplyPenaltyResponse{}, err
		}
	}

	resp, err := m.msgServer.ApplyPenalty(slashingmodule.ApplyPenaltyRequest{Penalty: req.Record})
	if err != nil {
		if errors.Is(err, slashingmodule.ErrNilKeeper) {
			return SlashingApplyPenaltyResponse{}, errSlashingKeeperNotWired
		}
		return SlashingApplyPenaltyResponse{}, err
	}
	return SlashingApplyPenaltyResponse{
		Penalty: resp.Penalty,
		Replay:  resp.Idempotent,
	}, nil
}
