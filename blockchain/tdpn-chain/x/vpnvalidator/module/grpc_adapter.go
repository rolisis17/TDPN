package module

import (
	"context"
	"errors"
	"fmt"

	validatorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnvalidator/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
	validatortypes "github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

var _ validatorpb.MsgServer = (*GRPCMsgServerAdapter)(nil)
var _ validatorpb.QueryServer = (*GRPCQueryServerAdapter)(nil)

const (
	maxInt = int64(^uint(0) >> 1)
	minInt = -maxInt - 1
)

// GRPCMsgServerAdapter adapts module MsgServer to protobuf gRPC MsgServer.
type GRPCMsgServerAdapter struct {
	validatorpb.UnimplementedMsgServer
	server MsgServer
}

func NewGRPCMsgServerAdapter(k *keeper.Keeper) *GRPCMsgServerAdapter {
	return &GRPCMsgServerAdapter{
		server: NewMsgServer(k),
	}
}

func (a *GRPCMsgServerAdapter) SetValidatorEligibility(_ context.Context, req *validatorpb.MsgSetValidatorEligibilityRequest) (*validatorpb.MsgSetValidatorEligibilityResponse, error) {
	resp, err := a.server.SetValidatorEligibility(SetValidatorEligibilityRequest{
		Eligibility: fromProtoEligibility(req.GetEligibility()),
	})
	if err != nil {
		return nil, err
	}

	return &validatorpb.MsgSetValidatorEligibilityResponse{
		Eligibility: toProtoEligibility(resp.Eligibility),
	}, nil
}

func (a *GRPCMsgServerAdapter) RecordValidatorStatus(_ context.Context, req *validatorpb.MsgRecordValidatorStatusRequest) (*validatorpb.MsgRecordValidatorStatusResponse, error) {
	resp, err := a.server.RecordValidatorStatus(RecordValidatorStatusRequest{
		Record: fromProtoStatusRecord(req.GetRecord()),
	})
	if err != nil {
		return nil, err
	}

	return &validatorpb.MsgRecordValidatorStatusResponse{
		Record: toProtoStatusRecord(resp.Record),
	}, nil
}

// GRPCQueryServerAdapter adapts module QueryServer to protobuf gRPC QueryServer.
type GRPCQueryServerAdapter struct {
	validatorpb.UnimplementedQueryServer
	server QueryServer
}

func NewGRPCQueryServerAdapter(k *keeper.Keeper) *GRPCQueryServerAdapter {
	return &GRPCQueryServerAdapter{
		server: NewQueryServer(k),
	}
}

func (a *GRPCQueryServerAdapter) ValidatorEligibility(_ context.Context, req *validatorpb.QueryValidatorEligibilityRequest) (*validatorpb.QueryValidatorEligibilityResponse, error) {
	resp, err := a.server.GetValidatorEligibility(GetValidatorEligibilityRequest{
		ValidatorID: req.GetValidatorId(),
	})
	if err != nil {
		if errors.Is(err, ErrEligibilityNotFound) {
			return &validatorpb.QueryValidatorEligibilityResponse{Found: false}, nil
		}
		return nil, err
	}

	return &validatorpb.QueryValidatorEligibilityResponse{
		Eligibility: toProtoEligibility(resp.Eligibility),
		Found:       true,
	}, nil
}

func (a *GRPCQueryServerAdapter) ValidatorStatusRecord(_ context.Context, req *validatorpb.QueryValidatorStatusRecordRequest) (*validatorpb.QueryValidatorStatusRecordResponse, error) {
	resp, err := a.server.GetValidatorStatusRecord(GetValidatorStatusRecordRequest{
		StatusID: req.GetStatusId(),
	})
	if err != nil {
		if errors.Is(err, ErrStatusNotFound) {
			return &validatorpb.QueryValidatorStatusRecordResponse{Found: false}, nil
		}
		return nil, err
	}

	return &validatorpb.QueryValidatorStatusRecordResponse{
		Record: toProtoStatusRecord(resp.Record),
		Found:  true,
	}, nil
}

func (a *GRPCQueryServerAdapter) ListValidatorEligibilities(_ context.Context, _ *validatorpb.QueryListValidatorEligibilitiesRequest) (*validatorpb.QueryListValidatorEligibilitiesResponse, error) {
	resp, err := a.server.ListValidatorEligibilities(ListValidatorEligibilitiesRequest{})
	if err != nil {
		return nil, err
	}

	records := make([]*validatorpb.ValidatorEligibility, 0, len(resp.Eligibilities))
	for _, eligibility := range resp.Eligibilities {
		records = append(records, toProtoEligibility(eligibility))
	}
	return &validatorpb.QueryListValidatorEligibilitiesResponse{
		Eligibilities: records,
	}, nil
}

func (a *GRPCQueryServerAdapter) ListValidatorStatusRecords(_ context.Context, _ *validatorpb.QueryListValidatorStatusRecordsRequest) (*validatorpb.QueryListValidatorStatusRecordsResponse, error) {
	resp, err := a.server.ListValidatorStatusRecords(ListValidatorStatusRecordsRequest{})
	if err != nil {
		return nil, err
	}

	records := make([]*validatorpb.ValidatorStatusRecord, 0, len(resp.Records))
	for _, statusRecord := range resp.Records {
		records = append(records, toProtoStatusRecord(statusRecord))
	}
	return &validatorpb.QueryListValidatorStatusRecordsResponse{
		Records: records,
	}, nil
}

func (a *GRPCQueryServerAdapter) PreviewEpochSelection(_ context.Context, req *validatorpb.QueryPreviewEpochSelectionRequest) (*validatorpb.QueryPreviewEpochSelectionResponse, error) {
	policy, err := fromProtoEpochSelectionPolicy(req.GetPolicy())
	if err != nil {
		return nil, err
	}

	resp, err := a.server.PreviewEpochSelection(PreviewEpochSelectionRequest{
		Policy:     policy,
		Candidates: fromProtoEpochValidatorCandidates(req.GetCandidates()),
	})
	if err != nil {
		return nil, err
	}

	return &validatorpb.QueryPreviewEpochSelectionResponse{
		Result: toProtoEpochSelectionResult(resp.Result),
	}, nil
}

func fromProtoEligibility(pb *validatorpb.ValidatorEligibility) validatortypes.ValidatorEligibility {
	if pb == nil {
		return validatortypes.ValidatorEligibility{}
	}

	return validatortypes.ValidatorEligibility{
		ValidatorID:     pb.GetValidatorId(),
		OperatorAddress: pb.GetOperatorAddress(),
		Eligible:        pb.GetEligible(),
		PolicyReason:    pb.GetPolicyReason(),
		UpdatedAtUnix:   pb.GetUpdatedAtUnix(),
		Status:          statusFromProto(pb.GetStatus()),
	}
}

func toProtoEligibility(record validatortypes.ValidatorEligibility) *validatorpb.ValidatorEligibility {
	return &validatorpb.ValidatorEligibility{
		ValidatorId:     record.ValidatorID,
		OperatorAddress: record.OperatorAddress,
		Eligible:        record.Eligible,
		PolicyReason:    record.PolicyReason,
		UpdatedAtUnix:   record.UpdatedAtUnix,
		Status:          statusToProto(record.Status),
	}
}

func fromProtoStatusRecord(pb *validatorpb.ValidatorStatusRecord) validatortypes.ValidatorStatusRecord {
	if pb == nil {
		return validatortypes.ValidatorStatusRecord{}
	}

	return validatortypes.ValidatorStatusRecord{
		StatusID:         pb.GetStatusId(),
		ValidatorID:      pb.GetValidatorId(),
		ConsensusAddress: pb.GetConsensusAddress(),
		LifecycleStatus:  pb.GetLifecycleStatus(),
		EvidenceHeight:   pb.GetEvidenceHeight(),
		EvidenceRef:      pb.GetEvidenceRef(),
		RecordedAtUnix:   pb.GetRecordedAtUnix(),
		Status:           statusFromProto(pb.GetStatus()),
	}
}

func toProtoStatusRecord(record validatortypes.ValidatorStatusRecord) *validatorpb.ValidatorStatusRecord {
	return &validatorpb.ValidatorStatusRecord{
		StatusId:         record.StatusID,
		ValidatorId:      record.ValidatorID,
		ConsensusAddress: record.ConsensusAddress,
		LifecycleStatus:  record.LifecycleStatus,
		EvidenceHeight:   record.EvidenceHeight,
		EvidenceRef:      record.EvidenceRef,
		RecordedAtUnix:   record.RecordedAtUnix,
		Status:           statusToProto(record.Status),
	}
}

func fromProtoEpochSelectionPolicy(pb *validatorpb.EpochSelectionPolicy) (validatortypes.EpochSelectionPolicy, error) {
	if pb == nil {
		return validatortypes.EpochSelectionPolicy{}, nil
	}

	stableSeatCount, err := protoInt64ToInt(pb.GetStableSeatCount(), "stable_seat_count")
	if err != nil {
		return validatortypes.EpochSelectionPolicy{}, err
	}
	rotatingSeatCount, err := protoInt64ToInt(pb.GetRotatingSeatCount(), "rotating_seat_count")
	if err != nil {
		return validatortypes.EpochSelectionPolicy{}, err
	}
	maxSeatsPerOperator, err := protoInt64ToInt(pb.GetMaxSeatsPerOperator(), "max_seats_per_operator")
	if err != nil {
		return validatortypes.EpochSelectionPolicy{}, err
	}
	maxSeatsPerASN, err := protoInt64ToInt(pb.GetMaxSeatsPerAsn(), "max_seats_per_asn")
	if err != nil {
		return validatortypes.EpochSelectionPolicy{}, err
	}
	maxSeatsPerRegion, err := protoInt64ToInt(pb.GetMaxSeatsPerRegion(), "max_seats_per_region")
	if err != nil {
		return validatortypes.EpochSelectionPolicy{}, err
	}

	return validatortypes.EpochSelectionPolicy{
		Epoch:               pb.GetEpoch(),
		StableSeatCount:     stableSeatCount,
		RotatingSeatCount:   rotatingSeatCount,
		MinStake:            pb.GetMinStake(),
		MinStakeAgeEpochs:   pb.GetMinStakeAgeEpochs(),
		MinHealthScore:      pb.GetMinHealthScore(),
		MinResourceHeadroom: pb.GetMinResourceHeadroom(),
		WarmupEpochs:        pb.GetWarmupEpochs(),
		CooldownEpochs:      pb.GetCooldownEpochs(),
		MaxSeatsPerOperator: maxSeatsPerOperator,
		MaxSeatsPerASN:      maxSeatsPerASN,
		MaxSeatsPerRegion:   maxSeatsPerRegion,
	}, nil
}

func fromProtoEpochValidatorCandidates(candidates []*validatorpb.EpochValidatorCandidate) []validatortypes.EpochValidatorCandidate {
	if len(candidates) == 0 {
		return nil
	}

	converted := make([]validatortypes.EpochValidatorCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		converted = append(converted, fromProtoEpochValidatorCandidate(candidate))
	}
	return converted
}

func fromProtoEpochValidatorCandidate(pb *validatorpb.EpochValidatorCandidate) validatortypes.EpochValidatorCandidate {
	if pb == nil {
		return validatortypes.EpochValidatorCandidate{}
	}

	return validatortypes.EpochValidatorCandidate{
		ValidatorID:                 pb.GetValidatorId(),
		OperatorID:                  pb.GetOperatorId(),
		ASN:                         pb.GetAsn(),
		Region:                      pb.GetRegion(),
		Stake:                       pb.GetStake(),
		StakeAgeEpochs:              pb.GetStakeAgeEpochs(),
		HealthScore:                 pb.GetHealthScore(),
		ResourceHeadroom:            pb.GetResourceHeadroom(),
		HasActiveSanction:           pb.GetHasActiveSanction(),
		HasUnresolvedCriticalIssues: pb.GetHasUnresolvedCriticalIssues(),
		ConsecutiveEligibleEpochs:   pb.GetConsecutiveEligibleEpochs(),
		LastRemovedEpoch:            pb.GetLastRemovedEpoch(),
		Score:                       pb.GetScore(),
		StableSeatPreferred:         pb.GetStableSeatPreferred(),
	}
}

func toProtoEpochSelectionResult(result validatortypes.EpochSelectionResult) *validatorpb.EpochSelectionResult {
	stable := make([]*validatorpb.EpochValidatorCandidate, 0, len(result.StableSeats))
	for _, candidate := range result.StableSeats {
		stable = append(stable, toProtoEpochValidatorCandidate(candidate))
	}

	rotating := make([]*validatorpb.EpochValidatorCandidate, 0, len(result.RotatingSeats))
	for _, candidate := range result.RotatingSeats {
		rotating = append(rotating, toProtoEpochValidatorCandidate(candidate))
	}

	return &validatorpb.EpochSelectionResult{
		StableSeats:   stable,
		RotatingSeats: rotating,
	}
}

func toProtoEpochValidatorCandidate(candidate validatortypes.EpochValidatorCandidate) *validatorpb.EpochValidatorCandidate {
	return &validatorpb.EpochValidatorCandidate{
		ValidatorId:                 candidate.ValidatorID,
		OperatorId:                  candidate.OperatorID,
		Asn:                         candidate.ASN,
		Region:                      candidate.Region,
		Stake:                       candidate.Stake,
		StakeAgeEpochs:              candidate.StakeAgeEpochs,
		HealthScore:                 candidate.HealthScore,
		ResourceHeadroom:            candidate.ResourceHeadroom,
		HasActiveSanction:           candidate.HasActiveSanction,
		HasUnresolvedCriticalIssues: candidate.HasUnresolvedCriticalIssues,
		ConsecutiveEligibleEpochs:   candidate.ConsecutiveEligibleEpochs,
		LastRemovedEpoch:            candidate.LastRemovedEpoch,
		Score:                       candidate.Score,
		StableSeatPreferred:         candidate.StableSeatPreferred,
	}
}

func protoInt64ToInt(value int64, fieldName string) (int, error) {
	if value > maxInt || value < minInt {
		return 0, fmt.Errorf("vpnvalidator: %s=%d out of int range", fieldName, value)
	}
	return int(value), nil
}

func statusFromProto(status validatorpb.ReconciliationStatus) chaintypes.ReconciliationStatus {
	switch status {
	case validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING:
		return chaintypes.ReconciliationPending
	case validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED:
		return chaintypes.ReconciliationSubmitted
	case validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED:
		return chaintypes.ReconciliationConfirmed
	case validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED:
		return chaintypes.ReconciliationFailed
	default:
		return ""
	}
}

func statusToProto(status chaintypes.ReconciliationStatus) validatorpb.ReconciliationStatus {
	switch status {
	case chaintypes.ReconciliationPending:
		return validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING
	case chaintypes.ReconciliationSubmitted:
		return validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED
	case chaintypes.ReconciliationConfirmed:
		return validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED
	case chaintypes.ReconciliationFailed:
		return validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED
	default:
		return validatorpb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED
	}
}
