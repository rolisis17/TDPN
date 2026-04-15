package module

import (
	"errors"
	"fmt"

	"github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

var (
	ErrStatusNotFound = errors.New("vpnvalidator: validator status record not found")
)

// GetValidatorEligibilityRequest requests eligibility by validator id.
type GetValidatorEligibilityRequest struct {
	ValidatorID string
}

// GetValidatorEligibilityResponse contains eligibility lookup result.
type GetValidatorEligibilityResponse struct {
	Eligibility types.ValidatorEligibility
}

// GetValidatorStatusRecordRequest requests status by status id.
type GetValidatorStatusRecordRequest struct {
	StatusID string
}

// GetValidatorStatusRecordResponse contains status lookup result.
type GetValidatorStatusRecordResponse struct {
	Record types.ValidatorStatusRecord
}

// ListValidatorEligibilitiesRequest requests the full eligibility read-model.
type ListValidatorEligibilitiesRequest struct{}

// ListValidatorEligibilitiesResponse contains all eligibilities sorted by ValidatorID.
type ListValidatorEligibilitiesResponse struct {
	Eligibilities []types.ValidatorEligibility
}

// ListValidatorStatusRecordsRequest requests the full status read-model.
type ListValidatorStatusRecordsRequest struct{}

// ListValidatorStatusRecordsResponse contains all statuses sorted by StatusID.
type ListValidatorStatusRecordsResponse struct {
	Records []types.ValidatorStatusRecord
}

// PreviewEpochSelectionRequest requests deterministic validator-set preview for an epoch.
type PreviewEpochSelectionRequest struct {
	Policy     types.EpochSelectionPolicy
	Candidates []types.EpochValidatorCandidate
}

// PreviewEpochSelectionResponse contains deterministic stable/rotating seat selection preview.
type PreviewEpochSelectionResponse struct {
	Result types.EpochSelectionResult
}

// QueryServer exposes a lightweight Cosmos-style query surface for vpnvalidator.
type QueryServer struct {
	keeper *keeper.Keeper
}

func NewQueryServer(k *keeper.Keeper) QueryServer {
	return QueryServer{keeper: k}
}

func (s QueryServer) GetValidatorEligibility(req GetValidatorEligibilityRequest) (GetValidatorEligibilityResponse, error) {
	if s.keeper == nil {
		return GetValidatorEligibilityResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetEligibility(req.ValidatorID)
	if !ok {
		return GetValidatorEligibilityResponse{}, fmt.Errorf("%w: validator_id=%s", ErrEligibilityNotFound, req.ValidatorID)
	}
	return GetValidatorEligibilityResponse{Eligibility: record}, nil
}

func (s QueryServer) GetValidatorStatusRecord(req GetValidatorStatusRecordRequest) (GetValidatorStatusRecordResponse, error) {
	if s.keeper == nil {
		return GetValidatorStatusRecordResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetStatusRecord(req.StatusID)
	if !ok {
		return GetValidatorStatusRecordResponse{}, fmt.Errorf("%w: status_id=%s", ErrStatusNotFound, req.StatusID)
	}
	return GetValidatorStatusRecordResponse{Record: record}, nil
}

func (s QueryServer) ListValidatorEligibilities(_ ListValidatorEligibilitiesRequest) (ListValidatorEligibilitiesResponse, error) {
	if s.keeper == nil {
		return ListValidatorEligibilitiesResponse{}, ErrNilKeeper
	}

	return ListValidatorEligibilitiesResponse{
		Eligibilities: s.keeper.ListEligibilities(),
	}, nil
}

func (s QueryServer) ListValidatorStatusRecords(_ ListValidatorStatusRecordsRequest) (ListValidatorStatusRecordsResponse, error) {
	if s.keeper == nil {
		return ListValidatorStatusRecordsResponse{}, ErrNilKeeper
	}

	return ListValidatorStatusRecordsResponse{
		Records: s.keeper.ListStatusRecords(),
	}, nil
}

func (s QueryServer) PreviewEpochSelection(req PreviewEpochSelectionRequest) (PreviewEpochSelectionResponse, error) {
	if s.keeper == nil {
		return PreviewEpochSelectionResponse{}, ErrNilKeeper
	}

	result, err := s.keeper.SelectEpochValidators(req.Policy, req.Candidates)
	if err != nil {
		return PreviewEpochSelectionResponse{}, err
	}

	return PreviewEpochSelectionResponse{
		Result: result,
	}, nil
}
