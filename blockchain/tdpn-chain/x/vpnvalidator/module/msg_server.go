package module

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

var (
	ErrNilKeeper           = errors.New("vpnvalidator: keeper is nil")
	ErrInvalidEligibility  = errors.New("vpnvalidator: invalid validator eligibility")
	ErrEligibilityConflict = errors.New("vpnvalidator: validator eligibility conflict")
	ErrInvalidStatusRecord = errors.New("vpnvalidator: invalid validator status record")
	ErrStatusConflict      = errors.New("vpnvalidator: validator status conflict")
	ErrEligibilityNotFound = errors.New("vpnvalidator: validator eligibility not found")
)

// SetValidatorEligibilityRequest captures an intent to create or replay validator eligibility.
type SetValidatorEligibilityRequest struct {
	Eligibility types.ValidatorEligibility
}

// SetValidatorEligibilityResponse returns persisted eligibility plus replay hints.
type SetValidatorEligibilityResponse struct {
	Eligibility types.ValidatorEligibility
	Existed     bool
	Idempotent  bool
}

// RecordValidatorStatusRequest captures an intent to create or replay validator status transitions.
type RecordValidatorStatusRequest struct {
	Record types.ValidatorStatusRecord
}

// RecordValidatorStatusResponse returns persisted status plus replay hints.
type RecordValidatorStatusResponse struct {
	Record     types.ValidatorStatusRecord
	Existed    bool
	Idempotent bool
}

// MsgServer exposes a lightweight Cosmos-style message surface for vpnvalidator.
type MsgServer struct {
	keeper *keeper.Keeper
}

func NewMsgServer(k *keeper.Keeper) MsgServer {
	return MsgServer{keeper: k}
}

func (s MsgServer) SetValidatorEligibility(req SetValidatorEligibilityRequest) (SetValidatorEligibilityResponse, error) {
	if s.keeper == nil {
		return SetValidatorEligibilityResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Eligibility.ValidatorID != "" {
		_, existed = s.keeper.GetEligibility(req.Eligibility.ValidatorID)
	}

	record, err := s.keeper.CreateEligibility(req.Eligibility)
	resp := SetValidatorEligibilityResponse{
		Eligibility: record,
		Existed:     existed,
		Idempotent:  existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrEligibilityConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidEligibility, err)
	}

	return resp, nil
}

func (s MsgServer) RecordValidatorStatus(req RecordValidatorStatusRequest) (RecordValidatorStatusResponse, error) {
	if s.keeper == nil {
		return RecordValidatorStatusResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Record.StatusID != "" {
		_, existed = s.keeper.GetStatusRecord(req.Record.StatusID)
	}

	if strings.TrimSpace(req.Record.ValidatorID) != "" {
		if _, ok := s.keeper.GetEligibility(req.Record.ValidatorID); !ok {
			return RecordValidatorStatusResponse{
				Record:  req.Record,
				Existed: existed,
			}, fmt.Errorf("%w: validator_id=%s", ErrEligibilityNotFound, req.Record.ValidatorID)
		}
	}

	record, err := s.keeper.CreateStatusRecord(req.Record)
	resp := RecordValidatorStatusResponse{
		Record:     record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrStatusConflict, err)
		}
		if strings.Contains(err.Error(), "not found") {
			return resp, fmt.Errorf("%w: %v", ErrEligibilityNotFound, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidStatusRecord, err)
	}

	return resp, nil
}
