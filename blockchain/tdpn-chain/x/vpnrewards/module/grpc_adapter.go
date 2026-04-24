package module

import (
	"context"
	"errors"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnrewards/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	modtypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

// GRPCMsgAdapter adapts module MsgServer to generated gRPC MsgServer.
type GRPCMsgAdapter struct {
	pb.UnimplementedMsgServer
	msg MsgServer
}

// GRPCQueryAdapter adapts module QueryServer to generated gRPC QueryServer.
type GRPCQueryAdapter struct {
	pb.UnimplementedQueryServer
	query QueryServer
}

var (
	_ pb.MsgServer   = (*GRPCMsgAdapter)(nil)
	_ pb.QueryServer = (*GRPCQueryAdapter)(nil)
)

func NewGRPCMsgAdapter(msg MsgServer) GRPCMsgAdapter {
	return GRPCMsgAdapter{msg: msg}
}

func NewGRPCQueryAdapter(query QueryServer) GRPCQueryAdapter {
	return GRPCQueryAdapter{query: query}
}

func (a GRPCMsgAdapter) RecordAccrual(ctx context.Context, req *pb.MsgRecordAccrualRequest) (*pb.MsgRecordAccrualResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var accrual *pb.RewardAccrual
	if req != nil {
		accrual = req.GetAccrual()
	}

	resp, err := a.msg.AccrueReward(AccrueRewardRequest{
		Accrual: protoAccrualToModule(accrual),
	})
	if err != nil {
		return nil, err
	}

	return &pb.MsgRecordAccrualResponse{
		Accrual: moduleAccrualToProto(resp.Accrual),
	}, nil
}

func (a GRPCMsgAdapter) RecordDistribution(ctx context.Context, req *pb.MsgRecordDistributionRequest) (*pb.MsgRecordDistributionResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var distribution *pb.DistributionRecord
	if req != nil {
		distribution = req.GetDistribution()
	}

	resp, err := a.msg.DistributeReward(DistributeRewardRequest{
		Distribution: protoDistributionToModule(distribution),
	})
	if err != nil {
		return nil, err
	}

	return &pb.MsgRecordDistributionResponse{
		Distribution: moduleDistributionToProto(resp.Distribution),
	}, nil
}

func (a GRPCQueryAdapter) RewardAccrual(ctx context.Context, req *pb.QueryRewardAccrualRequest) (*pb.QueryRewardAccrualResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	accrualID := ""
	if req != nil {
		accrualID = req.GetAccrualId()
	}

	resp, err := a.query.GetAccrual(GetAccrualRequest{AccrualID: accrualID})
	if err != nil {
		if errors.Is(err, ErrAccrualNotFound) {
			return &pb.QueryRewardAccrualResponse{Found: false}, nil
		}
		return nil, err
	}

	return &pb.QueryRewardAccrualResponse{
		Accrual: moduleAccrualToProto(resp.Accrual),
		Found:   true,
	}, nil
}

func (a GRPCQueryAdapter) DistributionRecord(ctx context.Context, req *pb.QueryDistributionRecordRequest) (*pb.QueryDistributionRecordResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	distributionID := ""
	if req != nil {
		distributionID = req.GetDistributionId()
	}

	resp, err := a.query.GetDistribution(GetDistributionRequest{DistributionID: distributionID})
	if err != nil {
		if errors.Is(err, ErrDistributionNotFound) {
			return &pb.QueryDistributionRecordResponse{Found: false}, nil
		}
		return nil, err
	}

	return &pb.QueryDistributionRecordResponse{
		Distribution: moduleDistributionToProto(resp.Distribution),
		Found:        true,
	}, nil
}

func (a GRPCQueryAdapter) ListRewardAccruals(ctx context.Context, _ *pb.QueryListRewardAccrualsRequest) (*pb.QueryListRewardAccrualsResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resp, err := a.query.ListAccruals(ListAccrualsRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]*pb.RewardAccrual, 0, len(resp.Accruals))
	for _, record := range resp.Accruals {
		out = append(out, moduleAccrualToProto(record))
	}

	return &pb.QueryListRewardAccrualsResponse{
		Accruals: out,
	}, nil
}

func (a GRPCQueryAdapter) ListDistributionRecords(ctx context.Context, _ *pb.QueryListDistributionRecordsRequest) (*pb.QueryListDistributionRecordsResponse, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resp, err := a.query.ListDistributions(ListDistributionsRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]*pb.DistributionRecord, 0, len(resp.Distributions))
	for _, record := range resp.Distributions {
		out = append(out, moduleDistributionToProto(record))
	}

	return &pb.QueryListDistributionRecordsResponse{
		Distributions: out,
	}, nil
}

func moduleAccrualToProto(record modtypes.RewardAccrual) *pb.RewardAccrual {
	return &pb.RewardAccrual{
		AccrualId:      record.AccrualID,
		SessionId:      record.SessionID,
		ProviderId:     record.ProviderID,
		AssetDenom:     record.AssetDenom,
		Amount:         record.Amount,
		AccruedAtUnix:  record.AccruedAtUnix,
		OperationState: moduleStatusToProto(record.OperationState),
	}
}

func protoAccrualToModule(record *pb.RewardAccrual) modtypes.RewardAccrual {
	if record == nil {
		return modtypes.RewardAccrual{}
	}

	return modtypes.RewardAccrual{
		AccrualID:     record.GetAccrualId(),
		SessionID:     record.GetSessionId(),
		ProviderID:    record.GetProviderId(),
		AssetDenom:    record.GetAssetDenom(),
		Amount:        record.GetAmount(),
		AccruedAtUnix: record.GetAccruedAtUnix(),
		// OperationState is server-owned lifecycle metadata and must not be client-injectable.
		OperationState: "",
	}
}

func moduleDistributionToProto(record modtypes.DistributionRecord) *pb.DistributionRecord {
	return &pb.DistributionRecord{
		DistributionId: record.DistributionID,
		AccrualId:      record.AccrualID,
		PayoutRef:      record.PayoutRef,
		DistributedAt:  record.DistributedAt,
		Status:         moduleStatusToProto(record.Status),
	}
}

func protoDistributionToModule(record *pb.DistributionRecord) modtypes.DistributionRecord {
	if record == nil {
		return modtypes.DistributionRecord{}
	}

	return modtypes.DistributionRecord{
		DistributionID: record.GetDistributionId(),
		AccrualID:      record.GetAccrualId(),
		PayoutRef:      record.GetPayoutRef(),
		DistributedAt:  record.GetDistributedAt(),
		// Status is server-owned lifecycle metadata and must not be client-injectable.
		Status: "",
	}
}

func moduleStatusToProto(status chaintypes.ReconciliationStatus) pb.ReconciliationStatus {
	switch status {
	case chaintypes.ReconciliationPending:
		return pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING
	case chaintypes.ReconciliationSubmitted:
		return pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED
	case chaintypes.ReconciliationConfirmed:
		return pb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED
	case chaintypes.ReconciliationFailed:
		return pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED
	default:
		return pb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED
	}
}

func protoStatusToModule(status pb.ReconciliationStatus) chaintypes.ReconciliationStatus {
	switch status {
	case pb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING:
		return chaintypes.ReconciliationPending
	case pb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED:
		return chaintypes.ReconciliationSubmitted
	case pb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED:
		return chaintypes.ReconciliationConfirmed
	case pb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED:
		return chaintypes.ReconciliationFailed
	default:
		return ""
	}
}
