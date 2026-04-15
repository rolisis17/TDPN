package module

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

var (
	ErrNilKeeper        = errors.New("vpnslashing: keeper is nil")
	ErrInvalidEvidence  = errors.New("vpnslashing: invalid evidence")
	ErrEvidenceConflict = errors.New("vpnslashing: evidence conflict")
	ErrInvalidPenalty   = errors.New("vpnslashing: invalid penalty")
	ErrPenaltyConflict  = errors.New("vpnslashing: penalty conflict")
	ErrEvidenceNotFound = errors.New("vpnslashing: evidence not found")
)

// SubmitSlashEvidenceRequest captures objective evidence input for deterministic slashing.
type SubmitSlashEvidenceRequest struct {
	Evidence types.SlashEvidence
}

// SubmitSlashEvidenceResponse returns the persisted evidence plus idempotency flags.
type SubmitSlashEvidenceResponse struct {
	Evidence   types.SlashEvidence
	Existed    bool
	Idempotent bool
}

// ApplyPenaltyRequest captures an intent to apply deterministic slash/jail penalties.
type ApplyPenaltyRequest struct {
	Penalty types.PenaltyDecision
}

// ApplyPenaltyResponse returns the persisted penalty plus idempotency flags.
type ApplyPenaltyResponse struct {
	Penalty    types.PenaltyDecision
	Existed    bool
	Idempotent bool
}

// MsgServer exposes a lightweight Cosmos-style message surface for vpnslashing.
type MsgServer struct {
	keeper *keeper.Keeper
}

func NewMsgServer(k *keeper.Keeper) MsgServer {
	return MsgServer{keeper: k}
}

func (s MsgServer) SubmitSlashEvidence(req SubmitSlashEvidenceRequest) (SubmitSlashEvidenceResponse, error) {
	if s.keeper == nil {
		return SubmitSlashEvidenceResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Evidence.EvidenceID != "" {
		_, existed = s.keeper.GetEvidence(req.Evidence.EvidenceID)
	}

	record, err := s.keeper.SubmitEvidence(req.Evidence)
	resp := SubmitSlashEvidenceResponse{
		Evidence:   record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrEvidenceConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidEvidence, err)
	}
	return resp, nil
}

func (s MsgServer) ApplyPenalty(req ApplyPenaltyRequest) (ApplyPenaltyResponse, error) {
	if s.keeper == nil {
		return ApplyPenaltyResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Penalty.PenaltyID != "" {
		_, existed = s.keeper.GetPenalty(req.Penalty.PenaltyID)
	}

	record, err := s.keeper.ApplyPenalty(req.Penalty)
	resp := ApplyPenaltyResponse{
		Penalty:    record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrPenaltyConflict, err)
		}
		if strings.Contains(err.Error(), "not found") {
			return resp, fmt.Errorf("%w: %v", ErrEvidenceNotFound, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidPenalty, err)
	}
	return resp, nil
}
