package app

import (
	"context"
	"errors"

	governancemodule "github.com/tdpn/tdpn-chain/x/vpngovernance/module"
	governancetypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

// GovernanceMsgServer exposes vpngovernance message operations through the scaffold.
type GovernanceMsgServer interface {
	CreatePolicy(context.Context, GovernanceCreatePolicyRequest) (GovernanceCreatePolicyResponse, error)
	RecordDecision(context.Context, GovernanceRecordDecisionRequest) (GovernanceRecordDecisionResponse, error)
	RecordAuditAction(context.Context, GovernanceRecordAuditActionRequest) (GovernanceRecordAuditActionResponse, error)
}

type GovernanceCreatePolicyRequest struct {
	Record governancetypes.GovernancePolicy
}

type GovernanceCreatePolicyResponse struct {
	Policy governancetypes.GovernancePolicy
	Replay bool
}

type GovernanceRecordDecisionRequest struct {
	Record governancetypes.GovernanceDecision
}

type GovernanceRecordDecisionResponse struct {
	Decision governancetypes.GovernanceDecision
	Replay   bool
}

type GovernanceRecordAuditActionRequest struct {
	Record governancetypes.GovernanceAuditAction
}

type GovernanceRecordAuditActionResponse struct {
	Action governancetypes.GovernanceAuditAction
	Replay bool
}

type governanceMsgServer struct {
	msgServer governancemodule.MsgServer
}

func (m governanceMsgServer) CreatePolicy(ctx context.Context, req GovernanceCreatePolicyRequest) (GovernanceCreatePolicyResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return GovernanceCreatePolicyResponse{}, err
		}
	}

	resp, err := m.msgServer.CreatePolicy(governancemodule.CreatePolicyRequest{Policy: req.Record})
	if err != nil {
		if errors.Is(err, governancemodule.ErrNilKeeper) {
			return GovernanceCreatePolicyResponse{}, errGovernanceKeeperNotWired
		}
		return GovernanceCreatePolicyResponse{}, err
	}

	return GovernanceCreatePolicyResponse{
		Policy: resp.Policy,
		Replay: resp.Idempotent,
	}, nil
}

func (m governanceMsgServer) RecordDecision(ctx context.Context, req GovernanceRecordDecisionRequest) (GovernanceRecordDecisionResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return GovernanceRecordDecisionResponse{}, err
		}
	}

	resp, err := m.msgServer.RecordDecision(governancemodule.RecordDecisionRequest{Decision: req.Record})
	if err != nil {
		if errors.Is(err, governancemodule.ErrNilKeeper) {
			return GovernanceRecordDecisionResponse{}, errGovernanceKeeperNotWired
		}
		return GovernanceRecordDecisionResponse{}, err
	}

	return GovernanceRecordDecisionResponse{
		Decision: resp.Decision,
		Replay:   resp.Idempotent,
	}, nil
}

func (m governanceMsgServer) RecordAuditAction(ctx context.Context, req GovernanceRecordAuditActionRequest) (GovernanceRecordAuditActionResponse, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return GovernanceRecordAuditActionResponse{}, err
		}
	}

	resp, err := m.msgServer.RecordAuditAction(governancemodule.RecordAuditActionRequest{Action: req.Record})
	if err != nil {
		if errors.Is(err, governancemodule.ErrNilKeeper) {
			return GovernanceRecordAuditActionResponse{}, errGovernanceKeeperNotWired
		}
		return GovernanceRecordAuditActionResponse{}, err
	}

	return GovernanceRecordAuditActionResponse{
		Action: resp.Action,
		Replay: resp.Idempotent,
	}, nil
}
