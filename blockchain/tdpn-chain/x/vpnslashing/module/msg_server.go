package module

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tdpn/tdpn-chain/x/vpnslashing/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnslashing/types"
)

var (
	ErrNilKeeper           = errors.New("vpnslashing: keeper is nil")
	ErrInvalidEvidence     = errors.New("vpnslashing: invalid evidence")
	ErrEvidenceConflict    = errors.New("vpnslashing: evidence conflict")
	ErrInvalidPenalty      = errors.New("vpnslashing: invalid penalty")
	ErrPenaltyConflict     = errors.New("vpnslashing: penalty conflict")
	ErrPenaltyStoreRead    = errors.New("vpnslashing: penalty store read failed")
	ErrEvidenceNotFound    = errors.New("vpnslashing: evidence not found")
	ErrUnauthorizedPenalty = errors.New("vpnslashing: unauthorized penalty")
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
		if strings.Contains(err.Error(), "conflicting fields") ||
			strings.Contains(err.Error(), "duplicates already-recorded evidence") {
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

	if err := req.Penalty.ValidateBasic(); err != nil {
		return ApplyPenaltyResponse{}, fmt.Errorf("%w: %v", ErrInvalidPenalty, err)
	}
	normalizedEvidenceID := types.NormalizeEvidenceID(req.Penalty.EvidenceID)
	normalizedPenaltyID := types.NormalizePenaltyID(req.Penalty.PenaltyID)
	if normalizedEvidenceID != "" {
		evidence, ok := s.keeper.GetEvidence(normalizedEvidenceID)
		if !ok {
			return ApplyPenaltyResponse{
				Penalty:    req.Penalty,
				Existed:    false,
				Idempotent: false,
			}, fmt.Errorf("%w: evidence_id=%s", ErrEvidenceNotFound, normalizedEvidenceID)
		}
		if strings.TrimSpace(evidence.ProviderID) == "" {
			return ApplyPenaltyResponse{
				Penalty:    req.Penalty,
				Existed:    false,
				Idempotent: false,
			}, fmt.Errorf("%w: evidence_id=%s has no provider subject", ErrUnauthorizedPenalty, normalizedEvidenceID)
		}
	}

	existed := false
	if normalizedPenaltyID != "" {
		_, existed = s.keeper.GetPenalty(normalizedPenaltyID)
	}

	evidencePenaltyExists, samePenaltyID, evidencePenaltyConflict, err := s.penaltyForEvidence(normalizedEvidenceID, normalizedPenaltyID)
	if err != nil {
		return ApplyPenaltyResponse{
			Penalty:    req.Penalty,
			Existed:    false,
			Idempotent: false,
		}, fmt.Errorf("%w: %v", ErrPenaltyStoreRead, err)
	}
	if evidencePenaltyConflict || (evidencePenaltyExists && !samePenaltyID) {
		return ApplyPenaltyResponse{
			Penalty:    req.Penalty,
			Existed:    true,
			Idempotent: false,
		}, fmt.Errorf("%w: evidence %q already has a penalty", ErrPenaltyConflict, normalizedEvidenceID)
	}

	record, err := s.keeper.ApplyPenalty(req.Penalty)
	resp := ApplyPenaltyResponse{
		Penalty:    record,
		Existed:    existed || evidencePenaltyExists,
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

func (s MsgServer) penaltyForEvidence(evidenceID string, penaltyID string) (bool, bool, bool, error) {
	evidenceID = types.NormalizeEvidenceID(evidenceID)
	penaltyID = types.NormalizePenaltyID(penaltyID)
	if s.keeper == nil || evidenceID == "" {
		return false, false, false, nil
	}

	penalties, err := s.keeper.ListPenaltiesWithError()
	if err != nil {
		return false, false, false, fmt.Errorf("list penalties: %w", err)
	}

	found := false
	samePenaltyID := false
	for _, penalty := range penalties {
		if types.NormalizeEvidenceID(penalty.EvidenceID) != evidenceID {
			continue
		}
		found = true
		if types.NormalizePenaltyID(penalty.PenaltyID) == penaltyID {
			samePenaltyID = true
		}
	}

	return found, samePenaltyID, found && !samePenaltyID, nil
}
