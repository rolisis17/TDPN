package module

import (
	"context"
	"errors"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/keeper"
	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

var _ pb.MsgServer = (*ProtoMsgServerAdapter)(nil)
var _ pb.QueryServer = (*ProtoQueryServerAdapter)(nil)

// ProtoMsgServerAdapter bridges generated protobuf MsgServer RPCs to module MsgServer logic.
type ProtoMsgServerAdapter struct {
	pb.UnimplementedMsgServer
	msg MsgServer
}

// NewProtoMsgServerAdapter creates a protobuf MsgServer adapter.
func NewProtoMsgServerAdapter(k *keeper.Keeper) *ProtoMsgServerAdapter {
	return &ProtoMsgServerAdapter{
		msg: NewMsgServer(k),
	}
}

func (a *ProtoMsgServerAdapter) ReserveCredits(_ context.Context, req *pb.MsgReserveCreditsRequest) (*pb.MsgReserveCreditsResponse, error) {
	record := billingtypes.CreditReservation{}
	if req != nil && req.GetReservation() != nil {
		record = fromProtoCreditReservation(req.GetReservation())
	}

	resp, err := a.msg.ReserveCredits(ReserveCreditsRequest{Reservation: record})
	out := &pb.MsgReserveCreditsResponse{
		Reservation:      toProtoCreditReservation(resp.Reservation),
		IdempotentReplay: resp.Idempotent,
		Conflict:         errors.Is(err, ErrReservationConflict),
	}
	if err != nil {
		return out, err
	}
	return out, nil
}

func (a *ProtoMsgServerAdapter) FinalizeUsage(_ context.Context, req *pb.MsgFinalizeUsageRequest) (*pb.MsgFinalizeUsageResponse, error) {
	record := billingtypes.SettlementRecord{}
	if req != nil && req.GetSettlement() != nil {
		record = fromProtoSettlementRecord(req.GetSettlement())
	}

	resp, err := a.msg.FinalizeUsage(FinalizeUsageRequest{Settlement: record})
	out := &pb.MsgFinalizeUsageResponse{
		Settlement:       toProtoSettlementRecord(resp.Settlement),
		IdempotentReplay: resp.Idempotent,
		Conflict:         errors.Is(err, ErrSettlementConflict),
	}
	if err != nil {
		return out, err
	}
	return out, nil
}

// ProtoQueryServerAdapter bridges generated protobuf QueryServer RPCs to module QueryServer logic.
type ProtoQueryServerAdapter struct {
	pb.UnimplementedQueryServer
	query QueryServer
}

// NewProtoQueryServerAdapter creates a protobuf QueryServer adapter.
func NewProtoQueryServerAdapter(k *keeper.Keeper) *ProtoQueryServerAdapter {
	return &ProtoQueryServerAdapter{
		query: NewQueryServer(k),
	}
}

func (a *ProtoQueryServerAdapter) CreditReservation(_ context.Context, req *pb.QueryCreditReservationRequest) (*pb.QueryCreditReservationResponse, error) {
	reservationID := ""
	if req != nil {
		reservationID = req.GetReservationId()
	}

	resp, err := a.query.GetReservation(GetReservationRequest{ReservationID: reservationID})
	if err != nil {
		if errors.Is(err, ErrReservationNotFound) {
			return &pb.QueryCreditReservationResponse{Found: false}, nil
		}
		return nil, err
	}

	return &pb.QueryCreditReservationResponse{
		Reservation: toProtoCreditReservation(resp.Reservation),
		Found:       true,
	}, nil
}

func (a *ProtoQueryServerAdapter) SettlementRecord(_ context.Context, req *pb.QuerySettlementRecordRequest) (*pb.QuerySettlementRecordResponse, error) {
	settlementID := ""
	if req != nil {
		settlementID = req.GetSettlementId()
	}

	resp, err := a.query.GetSettlement(GetSettlementRequest{SettlementID: settlementID})
	if err != nil {
		if errors.Is(err, ErrSettlementNotFound) {
			return &pb.QuerySettlementRecordResponse{Found: false}, nil
		}
		return nil, err
	}

	return &pb.QuerySettlementRecordResponse{
		Settlement: toProtoSettlementRecord(resp.Settlement),
		Found:      true,
	}, nil
}

func (a *ProtoQueryServerAdapter) ListCreditReservations(_ context.Context, _ *pb.QueryListCreditReservationsRequest) (*pb.QueryListCreditReservationsResponse, error) {
	resp, err := a.query.ListReservations(ListReservationsRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]*pb.CreditReservation, 0, len(resp.Reservations))
	for _, record := range resp.Reservations {
		out = append(out, toProtoCreditReservation(record))
	}
	return &pb.QueryListCreditReservationsResponse{Reservations: out}, nil
}

func (a *ProtoQueryServerAdapter) ListSettlementRecords(_ context.Context, _ *pb.QueryListSettlementRecordsRequest) (*pb.QueryListSettlementRecordsResponse, error) {
	resp, err := a.query.ListSettlements(ListSettlementsRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]*pb.SettlementRecord, 0, len(resp.Settlements))
	for _, record := range resp.Settlements {
		out = append(out, toProtoSettlementRecord(record))
	}
	return &pb.QueryListSettlementRecordsResponse{Settlements: out}, nil
}

func fromProtoCreditReservation(in *pb.CreditReservation) billingtypes.CreditReservation {
	if in == nil {
		return billingtypes.CreditReservation{}
	}
	return billingtypes.CreditReservation{
		ReservationID: in.GetReservationId(),
		SponsorID:     in.GetSponsorId(),
		SessionID:     in.GetSessionId(),
		AssetDenom:    in.GetAssetDenom(),
		Amount:        in.GetAmount(),
		// Server owns reconciliation lifecycle transitions for writes.
		Status:        "",
		CreatedAtUnix: in.GetCreatedAtUnix(),
	}
}

func toProtoCreditReservation(in billingtypes.CreditReservation) *pb.CreditReservation {
	return &pb.CreditReservation{
		ReservationId: in.ReservationID,
		SponsorId:     in.SponsorID,
		SessionId:     in.SessionID,
		AssetDenom:    in.AssetDenom,
		Amount:        in.Amount,
		Status:        toProtoStatus(in.Status),
		CreatedAtUnix: in.CreatedAtUnix,
	}
}

func fromProtoSettlementRecord(in *pb.SettlementRecord) billingtypes.SettlementRecord {
	if in == nil {
		return billingtypes.SettlementRecord{}
	}
	return billingtypes.SettlementRecord{
		SettlementID:  in.GetSettlementId(),
		ReservationID: in.GetReservationId(),
		SessionID:     in.GetSessionId(),
		BilledAmount:  in.GetBilledAmount(),
		UsageBytes:    in.GetUsageBytes(),
		AssetDenom:    in.GetAssetDenom(),
		SettledAtUnix: in.GetSettledAtUnix(),
		// Server owns reconciliation lifecycle transitions for writes.
		OperationState: "",
	}
}

func toProtoSettlementRecord(in billingtypes.SettlementRecord) *pb.SettlementRecord {
	return &pb.SettlementRecord{
		SettlementId:   in.SettlementID,
		ReservationId:  in.ReservationID,
		SessionId:      in.SessionID,
		BilledAmount:   in.BilledAmount,
		UsageBytes:     in.UsageBytes,
		AssetDenom:     in.AssetDenom,
		SettledAtUnix:  in.SettledAtUnix,
		OperationState: toProtoStatus(in.OperationState),
	}
}

func fromProtoStatus(in pb.ReconciliationStatus) chaintypes.ReconciliationStatus {
	switch in {
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

func toProtoStatus(in chaintypes.ReconciliationStatus) pb.ReconciliationStatus {
	switch in {
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
