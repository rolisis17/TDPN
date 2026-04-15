package app

import (
	"context"
	"errors"

	validatormodule "github.com/tdpn/tdpn-chain/x/vpnvalidator/module"
	validatortypes "github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

var (
	errValidatorKeeperNotWired = errors.New("vpnvalidator keeper is not wired")
)

// ValidatorQueryServer exposes vpnvalidator query operations through the scaffold.
type ValidatorQueryServer interface {
	GetEligibility(context.Context, ValidatorGetEligibilityRequest) (ValidatorGetEligibilityResponse, error)
	GetStatusRecord(context.Context, ValidatorGetStatusRecordRequest) (ValidatorGetStatusRecordResponse, error)
	ListEligibilities(context.Context, ValidatorListEligibilitiesRequest) (ValidatorListEligibilitiesResponse, error)
	ListStatusRecords(context.Context, ValidatorListStatusRecordsRequest) (ValidatorListStatusRecordsResponse, error)
}

type ValidatorGetEligibilityRequest struct {
	ValidatorID string
}

type ValidatorGetEligibilityResponse struct {
	Eligibility validatortypes.ValidatorEligibility
	Found       bool
}

type ValidatorGetStatusRecordRequest struct {
	StatusID string
}

type ValidatorGetStatusRecordResponse struct {
	Record validatortypes.ValidatorStatusRecord
	Found  bool
}

type ValidatorListEligibilitiesRequest struct{}

type ValidatorListEligibilitiesResponse struct {
	Eligibilities []validatortypes.ValidatorEligibility
}

type ValidatorListStatusRecordsRequest struct{}

type ValidatorListStatusRecordsResponse struct {
	Records []validatortypes.ValidatorStatusRecord
}

type validatorQueryServer struct {
	queryServer validatormodule.QueryServer
}

func (m validatorQueryServer) GetEligibility(_ context.Context, req ValidatorGetEligibilityRequest) (ValidatorGetEligibilityResponse, error) {
	resp, err := m.queryServer.GetValidatorEligibility(validatormodule.GetValidatorEligibilityRequest{ValidatorID: req.ValidatorID})
	if err != nil {
		if errors.Is(err, validatormodule.ErrNilKeeper) {
			return ValidatorGetEligibilityResponse{}, errValidatorKeeperNotWired
		}
		if errors.Is(err, validatormodule.ErrEligibilityNotFound) {
			return ValidatorGetEligibilityResponse{Found: false}, nil
		}
		return ValidatorGetEligibilityResponse{}, err
	}
	return ValidatorGetEligibilityResponse{
		Eligibility: resp.Eligibility,
		Found:       true,
	}, nil
}

func (m validatorQueryServer) GetStatusRecord(_ context.Context, req ValidatorGetStatusRecordRequest) (ValidatorGetStatusRecordResponse, error) {
	resp, err := m.queryServer.GetValidatorStatusRecord(validatormodule.GetValidatorStatusRecordRequest{StatusID: req.StatusID})
	if err != nil {
		if errors.Is(err, validatormodule.ErrNilKeeper) {
			return ValidatorGetStatusRecordResponse{}, errValidatorKeeperNotWired
		}
		if errors.Is(err, validatormodule.ErrStatusNotFound) {
			return ValidatorGetStatusRecordResponse{Found: false}, nil
		}
		return ValidatorGetStatusRecordResponse{}, err
	}
	return ValidatorGetStatusRecordResponse{
		Record: resp.Record,
		Found:  true,
	}, nil
}

func (m validatorQueryServer) ListEligibilities(_ context.Context, _ ValidatorListEligibilitiesRequest) (ValidatorListEligibilitiesResponse, error) {
	resp, err := m.queryServer.ListValidatorEligibilities(validatormodule.ListValidatorEligibilitiesRequest{})
	if err != nil {
		if errors.Is(err, validatormodule.ErrNilKeeper) {
			return ValidatorListEligibilitiesResponse{}, errValidatorKeeperNotWired
		}
		return ValidatorListEligibilitiesResponse{}, err
	}
	return ValidatorListEligibilitiesResponse{
		Eligibilities: resp.Eligibilities,
	}, nil
}

func (m validatorQueryServer) ListStatusRecords(_ context.Context, _ ValidatorListStatusRecordsRequest) (ValidatorListStatusRecordsResponse, error) {
	resp, err := m.queryServer.ListValidatorStatusRecords(validatormodule.ListValidatorStatusRecordsRequest{})
	if err != nil {
		if errors.Is(err, validatormodule.ErrNilKeeper) {
			return ValidatorListStatusRecordsResponse{}, errValidatorKeeperNotWired
		}
		return ValidatorListStatusRecordsResponse{}, err
	}
	return ValidatorListStatusRecordsResponse{
		Records: resp.Records,
	}, nil
}
