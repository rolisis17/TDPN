package app

import (
	"context"
	"errors"

	governancemodule "github.com/tdpn/tdpn-chain/x/vpngovernance/module"
	governancetypes "github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

var (
	errGovernanceKeeperNotWired = errors.New("vpngovernance keeper is not wired")
)

// GovernanceQueryServer exposes vpngovernance query operations through the scaffold.
type GovernanceQueryServer interface {
	GetPolicy(context.Context, GovernanceGetPolicyRequest) (GovernanceGetPolicyResponse, error)
	GetDecision(context.Context, GovernanceGetDecisionRequest) (GovernanceGetDecisionResponse, error)
	GetAuditAction(context.Context, GovernanceGetAuditActionRequest) (GovernanceGetAuditActionResponse, error)
	ListPolicies(context.Context, GovernanceListPoliciesRequest) (GovernanceListPoliciesResponse, error)
	ListDecisions(context.Context, GovernanceListDecisionsRequest) (GovernanceListDecisionsResponse, error)
	ListAuditActions(context.Context, GovernanceListAuditActionsRequest) (GovernanceListAuditActionsResponse, error)
}

type GovernanceGetPolicyRequest struct {
	PolicyID string
}

type GovernanceGetPolicyResponse struct {
	Policy governancetypes.GovernancePolicy
	Found  bool
}

type GovernanceGetDecisionRequest struct {
	DecisionID string
}

type GovernanceGetDecisionResponse struct {
	Decision governancetypes.GovernanceDecision
	Found    bool
}

type GovernanceGetAuditActionRequest struct {
	ActionID string
}

type GovernanceGetAuditActionResponse struct {
	Action governancetypes.GovernanceAuditAction
	Found  bool
}

type GovernanceListPoliciesRequest struct{}

type GovernanceListPoliciesResponse struct {
	Policies []governancetypes.GovernancePolicy
}

type GovernanceListDecisionsRequest struct{}

type GovernanceListDecisionsResponse struct {
	Decisions []governancetypes.GovernanceDecision
}

type GovernanceListAuditActionsRequest struct{}

type GovernanceListAuditActionsResponse struct {
	Actions []governancetypes.GovernanceAuditAction
}

type governanceQueryServer struct {
	queryServer governancemodule.QueryServer
}

func (m governanceQueryServer) GetPolicy(_ context.Context, req GovernanceGetPolicyRequest) (GovernanceGetPolicyResponse, error) {
	resp, err := m.queryServer.GetPolicy(governancemodule.GetPolicyRequest{PolicyID: req.PolicyID})
	if err != nil {
		if errors.Is(err, governancemodule.ErrNilKeeper) {
			return GovernanceGetPolicyResponse{}, errGovernanceKeeperNotWired
		}
		if errors.Is(err, governancemodule.ErrPolicyNotFound) {
			return GovernanceGetPolicyResponse{Found: false}, nil
		}
		return GovernanceGetPolicyResponse{}, err
	}
	return GovernanceGetPolicyResponse{
		Policy: resp.Policy,
		Found:  true,
	}, nil
}

func (m governanceQueryServer) GetDecision(_ context.Context, req GovernanceGetDecisionRequest) (GovernanceGetDecisionResponse, error) {
	resp, err := m.queryServer.GetDecision(governancemodule.GetDecisionRequest{DecisionID: req.DecisionID})
	if err != nil {
		if errors.Is(err, governancemodule.ErrNilKeeper) {
			return GovernanceGetDecisionResponse{}, errGovernanceKeeperNotWired
		}
		if errors.Is(err, governancemodule.ErrDecisionNotFound) {
			return GovernanceGetDecisionResponse{Found: false}, nil
		}
		return GovernanceGetDecisionResponse{}, err
	}
	return GovernanceGetDecisionResponse{
		Decision: resp.Decision,
		Found:    true,
	}, nil
}

func (m governanceQueryServer) GetAuditAction(_ context.Context, req GovernanceGetAuditActionRequest) (GovernanceGetAuditActionResponse, error) {
	resp, err := m.queryServer.GetAuditAction(governancemodule.GetAuditActionRequest{ActionID: req.ActionID})
	if err != nil {
		if errors.Is(err, governancemodule.ErrNilKeeper) {
			return GovernanceGetAuditActionResponse{}, errGovernanceKeeperNotWired
		}
		if errors.Is(err, governancemodule.ErrAuditActionNotFound) {
			return GovernanceGetAuditActionResponse{Found: false}, nil
		}
		return GovernanceGetAuditActionResponse{}, err
	}
	return GovernanceGetAuditActionResponse{
		Action: resp.Action,
		Found:  true,
	}, nil
}

func (m governanceQueryServer) ListPolicies(_ context.Context, _ GovernanceListPoliciesRequest) (GovernanceListPoliciesResponse, error) {
	resp, err := m.queryServer.ListPolicies(governancemodule.ListPoliciesRequest{})
	if err != nil {
		if errors.Is(err, governancemodule.ErrNilKeeper) {
			return GovernanceListPoliciesResponse{}, errGovernanceKeeperNotWired
		}
		return GovernanceListPoliciesResponse{}, err
	}
	return GovernanceListPoliciesResponse{
		Policies: resp.Policies,
	}, nil
}

func (m governanceQueryServer) ListDecisions(_ context.Context, _ GovernanceListDecisionsRequest) (GovernanceListDecisionsResponse, error) {
	resp, err := m.queryServer.ListDecisions(governancemodule.ListDecisionsRequest{})
	if err != nil {
		if errors.Is(err, governancemodule.ErrNilKeeper) {
			return GovernanceListDecisionsResponse{}, errGovernanceKeeperNotWired
		}
		return GovernanceListDecisionsResponse{}, err
	}
	return GovernanceListDecisionsResponse{
		Decisions: resp.Decisions,
	}, nil
}

func (m governanceQueryServer) ListAuditActions(_ context.Context, _ GovernanceListAuditActionsRequest) (GovernanceListAuditActionsResponse, error) {
	resp, err := m.queryServer.ListAuditActions(governancemodule.ListAuditActionsRequest{})
	if err != nil {
		if errors.Is(err, governancemodule.ErrNilKeeper) {
			return GovernanceListAuditActionsResponse{}, errGovernanceKeeperNotWired
		}
		return GovernanceListAuditActionsResponse{}, err
	}
	return GovernanceListAuditActionsResponse{
		Actions: resp.Actions,
	}, nil
}
