package module

import (
	"context"
	"errors"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnslashing/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	modtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
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

func (a GRPCMsgAdapter) SubmitEvidence(_ context.Context, req *pb.MsgSubmitEvidenceRequest) (*pb.MsgSubmitEvidenceResponse, error) {
	var evidence *pb.SlashEvidence
	if req != nil {
		evidence = req.GetEvidence()
	}

	resp, err := a.msg.SubmitSlashEvidence(SubmitSlashEvidenceRequest{
		Evidence: protoEvidenceToModule(evidence),
	})
	if err != nil {
		return nil, err
	}

	return &pb.MsgSubmitEvidenceResponse{
		Evidence: moduleEvidenceToProto(resp.Evidence),
	}, nil
}

func (a GRPCMsgAdapter) RecordPenalty(_ context.Context, req *pb.MsgRecordPenaltyRequest) (*pb.MsgRecordPenaltyResponse, error) {
	var penalty *pb.PenaltyDecision
	if req != nil {
		penalty = req.GetPenalty()
	}

	resp, err := a.msg.ApplyPenalty(ApplyPenaltyRequest{
		Penalty: protoPenaltyToModule(penalty),
	})
	if err != nil {
		return nil, err
	}

	return &pb.MsgRecordPenaltyResponse{
		Penalty: modulePenaltyToProto(resp.Penalty),
	}, nil
}

func (a GRPCQueryAdapter) SlashEvidence(_ context.Context, req *pb.QuerySlashEvidenceRequest) (*pb.QuerySlashEvidenceResponse, error) {
	evidenceID := ""
	if req != nil {
		evidenceID = req.GetEvidenceId()
	}

	resp, err := a.query.GetEvidence(GetEvidenceRequest{EvidenceID: evidenceID})
	if err != nil {
		if errors.Is(err, ErrEvidenceNotFound) {
			return &pb.QuerySlashEvidenceResponse{Found: false}, nil
		}
		return nil, err
	}

	return &pb.QuerySlashEvidenceResponse{
		Evidence: moduleEvidenceToProto(resp.Evidence),
		Found:    true,
	}, nil
}

func (a GRPCQueryAdapter) PenaltyDecision(_ context.Context, req *pb.QueryPenaltyDecisionRequest) (*pb.QueryPenaltyDecisionResponse, error) {
	penaltyID := ""
	if req != nil {
		penaltyID = req.GetPenaltyId()
	}

	resp, err := a.query.GetPenalty(GetPenaltyRequest{PenaltyID: penaltyID})
	if err != nil {
		if errors.Is(err, ErrPenaltyNotFound) {
			return &pb.QueryPenaltyDecisionResponse{Found: false}, nil
		}
		return nil, err
	}

	return &pb.QueryPenaltyDecisionResponse{
		Penalty: modulePenaltyToProto(resp.Penalty),
		Found:   true,
	}, nil
}

func (a GRPCQueryAdapter) ListSlashEvidence(_ context.Context, _ *pb.QueryListSlashEvidenceRequest) (*pb.QueryListSlashEvidenceResponse, error) {
	resp, err := a.query.ListEvidence(ListEvidenceRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]*pb.SlashEvidence, 0, len(resp.Evidence))
	for _, record := range resp.Evidence {
		out = append(out, moduleEvidenceToProto(record))
	}

	return &pb.QueryListSlashEvidenceResponse{Evidence: out}, nil
}

func (a GRPCQueryAdapter) ListPenaltyDecisions(_ context.Context, _ *pb.QueryListPenaltyDecisionsRequest) (*pb.QueryListPenaltyDecisionsResponse, error) {
	resp, err := a.query.ListPenalties(ListPenaltiesRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]*pb.PenaltyDecision, 0, len(resp.Penalties))
	for _, record := range resp.Penalties {
		out = append(out, modulePenaltyToProto(record))
	}

	return &pb.QueryListPenaltyDecisionsResponse{Penalties: out}, nil
}

func moduleEvidenceToProto(record modtypes.SlashEvidence) *pb.SlashEvidence {
	return &pb.SlashEvidence{
		EvidenceId:      record.EvidenceID,
		SessionId:       record.SessionID,
		ProviderId:      record.ProviderID,
		ViolationType:   record.ViolationType,
		Kind:            record.Kind,
		ProofHash:       record.ProofHash,
		SubmittedAtUnix: record.SubmittedAtUnix,
	}
}

func protoEvidenceToModule(record *pb.SlashEvidence) modtypes.SlashEvidence {
	if record == nil {
		return modtypes.SlashEvidence{}
	}

	return modtypes.SlashEvidence{
		EvidenceID:      record.GetEvidenceId(),
		SessionID:       record.GetSessionId(),
		ProviderID:      record.GetProviderId(),
		ViolationType:   record.GetViolationType(),
		Kind:            record.GetKind(),
		ProofHash:       record.GetProofHash(),
		SubmittedAtUnix: record.GetSubmittedAtUnix(),
	}
}

func modulePenaltyToProto(record modtypes.PenaltyDecision) *pb.PenaltyDecision {
	return &pb.PenaltyDecision{
		PenaltyId:       record.PenaltyID,
		EvidenceId:      record.EvidenceID,
		SlashBasisPoint: record.SlashBasisPoint,
		Jailed:          record.Jailed,
		AppliedAtUnix:   record.AppliedAtUnix,
		Status:          moduleStatusToProto(record.Status),
	}
}

func protoPenaltyToModule(record *pb.PenaltyDecision) modtypes.PenaltyDecision {
	if record == nil {
		return modtypes.PenaltyDecision{}
	}

	return modtypes.PenaltyDecision{
		PenaltyID:       record.GetPenaltyId(),
		EvidenceID:      record.GetEvidenceId(),
		SlashBasisPoint: record.GetSlashBasisPoint(),
		Jailed:          record.GetJailed(),
		AppliedAtUnix:   record.GetAppliedAtUnix(),
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
