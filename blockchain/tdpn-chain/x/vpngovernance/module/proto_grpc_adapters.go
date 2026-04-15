package module

import (
	"context"
	"errors"

	pb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpngovernance/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	governtypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

var _ pb.MsgServer = (*ProtoMsgServerAdapter)(nil)
var _ pb.QueryServer = (*ProtoQueryServerAdapter)(nil)

// ProtoMsgServerAdapter bridges protobuf MsgServer RPCs to module MsgServer logic.
type ProtoMsgServerAdapter struct {
	pb.UnimplementedMsgServer
	msg MsgServer
}

// NewProtoMsgServerAdapter creates a protobuf MsgServer adapter.
func NewProtoMsgServerAdapter(k *keeper.Keeper) *ProtoMsgServerAdapter {
	return &ProtoMsgServerAdapter{msg: NewMsgServer(k)}
}

func (a *ProtoMsgServerAdapter) CreatePolicy(_ context.Context, req *pb.MsgCreatePolicyRequest) (*pb.MsgCreatePolicyResponse, error) {
	record := governtypes.GovernancePolicy{}
	if req != nil && req.GetPolicy() != nil {
		record = fromProtoPolicy(req.GetPolicy())
	}

	resp, err := a.msg.CreatePolicy(CreatePolicyRequest{Policy: record})
	out := &pb.MsgCreatePolicyResponse{
		Policy:           toProtoPolicy(resp.Policy),
		IdempotentReplay: resp.Idempotent,
		Conflict:         errors.Is(err, ErrPolicyConflict),
	}
	if err != nil {
		return out, err
	}
	return out, nil
}

func (a *ProtoMsgServerAdapter) RecordDecision(_ context.Context, req *pb.MsgRecordDecisionRequest) (*pb.MsgRecordDecisionResponse, error) {
	record := governtypes.GovernanceDecision{}
	if req != nil && req.GetDecision() != nil {
		record = fromProtoDecision(req.GetDecision())
	}

	resp, err := a.msg.RecordDecision(RecordDecisionRequest{Decision: record})
	out := &pb.MsgRecordDecisionResponse{
		Decision:         toProtoDecision(resp.Decision),
		IdempotentReplay: resp.Idempotent,
		Conflict:         errors.Is(err, ErrDecisionConflict),
	}
	if err != nil {
		return out, err
	}
	return out, nil
}

// ProtoQueryServerAdapter bridges protobuf QueryServer RPCs to module QueryServer logic.
type ProtoQueryServerAdapter struct {
	pb.UnimplementedQueryServer
	query QueryServer
}

// NewProtoQueryServerAdapter creates a protobuf QueryServer adapter.
func NewProtoQueryServerAdapter(k *keeper.Keeper) *ProtoQueryServerAdapter {
	return &ProtoQueryServerAdapter{query: NewQueryServer(k)}
}

func (a *ProtoQueryServerAdapter) GovernancePolicy(_ context.Context, req *pb.QueryGovernancePolicyRequest) (*pb.QueryGovernancePolicyResponse, error) {
	policyID := ""
	if req != nil {
		policyID = req.GetPolicyId()
	}

	resp, err := a.query.GetPolicy(GetPolicyRequest{PolicyID: policyID})
	if err != nil {
		if errors.Is(err, ErrPolicyNotFound) {
			return &pb.QueryGovernancePolicyResponse{Found: false}, nil
		}
		return nil, err
	}

	return &pb.QueryGovernancePolicyResponse{Policy: toProtoPolicy(resp.Policy), Found: true}, nil
}

func (a *ProtoQueryServerAdapter) GovernanceDecision(_ context.Context, req *pb.QueryGovernanceDecisionRequest) (*pb.QueryGovernanceDecisionResponse, error) {
	decisionID := ""
	if req != nil {
		decisionID = req.GetDecisionId()
	}

	resp, err := a.query.GetDecision(GetDecisionRequest{DecisionID: decisionID})
	if err != nil {
		if errors.Is(err, errDecisionNotFound) {
			return &pb.QueryGovernanceDecisionResponse{Found: false}, nil
		}
		return nil, err
	}

	return &pb.QueryGovernanceDecisionResponse{Decision: toProtoDecision(resp.Decision), Found: true}, nil
}

func (a *ProtoQueryServerAdapter) ListGovernancePolicies(_ context.Context, _ *pb.QueryListGovernancePoliciesRequest) (*pb.QueryListGovernancePoliciesResponse, error) {
	resp, err := a.query.ListPolicies(ListPoliciesRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]*pb.GovernancePolicy, 0, len(resp.Policies))
	for _, record := range resp.Policies {
		out = append(out, toProtoPolicy(record))
	}
	return &pb.QueryListGovernancePoliciesResponse{Policies: out}, nil
}

func (a *ProtoQueryServerAdapter) ListGovernanceDecisions(_ context.Context, _ *pb.QueryListGovernanceDecisionsRequest) (*pb.QueryListGovernanceDecisionsResponse, error) {
	resp, err := a.query.ListDecisions(ListDecisionsRequest{})
	if err != nil {
		return nil, err
	}

	out := make([]*pb.GovernanceDecision, 0, len(resp.Decisions))
	for _, record := range resp.Decisions {
		out = append(out, toProtoDecision(record))
	}
	return &pb.QueryListGovernanceDecisionsResponse{Decisions: out}, nil
}

func fromProtoPolicy(in *pb.GovernancePolicy) governtypes.GovernancePolicy {
	if in == nil {
		return governtypes.GovernancePolicy{}
	}
	return governtypes.GovernancePolicy{
		PolicyID:        in.GetPolicyId(),
		Title:           in.GetTitle(),
		Description:     in.GetDescription(),
		Version:         in.GetVersion(),
		ActivatedAtUnix: in.GetActivatedAtUnix(),
		Status:          fromProtoStatus(in.GetStatus()),
	}
}

func toProtoPolicy(in governtypes.GovernancePolicy) *pb.GovernancePolicy {
	return &pb.GovernancePolicy{
		PolicyId:        in.PolicyID,
		Title:           in.Title,
		Description:     in.Description,
		Version:         in.Version,
		ActivatedAtUnix: in.ActivatedAtUnix,
		Status:          toProtoStatus(in.Status),
	}
}

func fromProtoDecision(in *pb.GovernanceDecision) governtypes.GovernanceDecision {
	if in == nil {
		return governtypes.GovernanceDecision{}
	}
	return governtypes.GovernanceDecision{
		DecisionID:    in.GetDecisionId(),
		PolicyID:      in.GetPolicyId(),
		ProposalID:    in.GetProposalId(),
		Outcome:       in.GetOutcome(),
		Decider:       in.GetDecider(),
		Reason:        in.GetReason(),
		DecidedAtUnix: in.GetDecidedAtUnix(),
		Status:        fromProtoStatus(in.GetStatus()),
	}
}

func toProtoDecision(in governtypes.GovernanceDecision) *pb.GovernanceDecision {
	return &pb.GovernanceDecision{
		DecisionId:    in.DecisionID,
		PolicyId:      in.PolicyID,
		ProposalId:    in.ProposalID,
		Outcome:       in.Outcome,
		Decider:       in.Decider,
		Reason:        in.Reason,
		DecidedAtUnix: in.DecidedAtUnix,
		Status:        toProtoStatus(in.Status),
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
