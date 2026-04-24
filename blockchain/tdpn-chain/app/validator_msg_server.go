package app

import (
	"context"
	"errors"

	validatormodule "github.com/tdpn/tdpn-chain/x/vpnvalidator/module"
	validatortypes "github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

// ValidatorMsgServer exposes vpnvalidator message operations through the scaffold.
type ValidatorMsgServer interface {
	SetEligibility(context.Context, ValidatorSetEligibilityRequest) (ValidatorSetEligibilityResponse, error)
	RecordStatus(context.Context, ValidatorRecordStatusRequest) (ValidatorRecordStatusResponse, error)
}

type ValidatorSetEligibilityRequest struct {
	Record validatortypes.ValidatorEligibility
}

type ValidatorSetEligibilityResponse struct {
	Eligibility validatortypes.ValidatorEligibility
	Replay      bool
}

type ValidatorRecordStatusRequest struct {
	Record validatortypes.ValidatorStatusRecord
}

type ValidatorRecordStatusResponse struct {
	Status validatortypes.ValidatorStatusRecord
	Replay bool
}

type validatorMsgServer struct {
	msgServer validatormodule.MsgServer
}

func (m validatorMsgServer) SetEligibility(ctx context.Context, req ValidatorSetEligibilityRequest) (ValidatorSetEligibilityResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return ValidatorSetEligibilityResponse{}, err
		}
	}

	resp, err := m.msgServer.SetValidatorEligibility(validatormodule.SetValidatorEligibilityRequest{Eligibility: req.Record})
	if err != nil {
		if errors.Is(err, validatormodule.ErrNilKeeper) {
			return ValidatorSetEligibilityResponse{}, errValidatorKeeperNotWired
		}
		return ValidatorSetEligibilityResponse{}, err
	}

	return ValidatorSetEligibilityResponse{
		Eligibility: resp.Eligibility,
		Replay:      resp.Idempotent,
	}, nil
}

func (m validatorMsgServer) RecordStatus(ctx context.Context, req ValidatorRecordStatusRequest) (ValidatorRecordStatusResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return ValidatorRecordStatusResponse{}, err
		}
	}

	resp, err := m.msgServer.RecordValidatorStatus(validatormodule.RecordValidatorStatusRequest{Record: req.Record})
	if err != nil {
		if errors.Is(err, validatormodule.ErrNilKeeper) {
			return ValidatorRecordStatusResponse{}, errValidatorKeeperNotWired
		}
		return ValidatorRecordStatusResponse{}, err
	}

	return ValidatorRecordStatusResponse{
		Status: resp.Record,
		Replay: resp.Idempotent,
	}, nil
}
