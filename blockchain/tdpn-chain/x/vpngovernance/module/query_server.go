package module

import (
	"errors"

	"github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

var (
	ErrDecisionNotFound    = errors.New("vpngovernance: decision not found")
	ErrAuditActionNotFound = errors.New("vpngovernance: audit action not found")
)

const maxQueryListResults = 1000

// GetPolicyRequest requests governance policy by policy ID.
type GetPolicyRequest struct {
	PolicyID string
}

// GetPolicyResponse contains a policy lookup result.
type GetPolicyResponse struct {
	Policy types.GovernancePolicy
}

// GetDecisionRequest requests governance decision by decision ID.
type GetDecisionRequest struct {
	DecisionID string
}

// GetDecisionResponse contains a decision lookup result.
type GetDecisionResponse struct {
	Decision types.GovernanceDecision
}

// GetAuditActionRequest requests governance audit action by action ID.
type GetAuditActionRequest struct {
	ActionID string
}

// GetAuditActionResponse contains an audit action lookup result.
type GetAuditActionResponse struct {
	Action types.GovernanceAuditAction
}

// ListPoliciesRequest requests full policy read-model.
type ListPoliciesRequest struct{}

// ListPoliciesResponse contains all policies sorted by PolicyID.
type ListPoliciesResponse struct {
	Policies []types.GovernancePolicy
}

// ListDecisionsRequest requests full decision read-model.
type ListDecisionsRequest struct{}

// ListDecisionsResponse contains all decisions sorted by DecisionID.
type ListDecisionsResponse struct {
	Decisions []types.GovernanceDecision
}

// ListAuditActionsRequest requests full governance audit-action read-model.
type ListAuditActionsRequest struct{}

// ListAuditActionsResponse contains all audit actions sorted by ActionID.
type ListAuditActionsResponse struct {
	Actions []types.GovernanceAuditAction
}

// QueryServer exposes a lightweight Cosmos-style query surface for vpngovernance.
type QueryServer struct {
	keeper *keeper.Keeper
}

func NewQueryServer(k *keeper.Keeper) QueryServer {
	return QueryServer{keeper: k}
}

func (s QueryServer) GetPolicy(req GetPolicyRequest) (GetPolicyResponse, error) {
	if s.keeper == nil {
		return GetPolicyResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetPolicy(req.PolicyID)
	if !ok {
		if err := s.ensurePoliciesReadable(); err != nil {
			return GetPolicyResponse{}, err
		}
		return GetPolicyResponse{}, ErrPolicyNotFound
	}
	return GetPolicyResponse{Policy: record}, nil
}

func (s QueryServer) GetDecision(req GetDecisionRequest) (GetDecisionResponse, error) {
	if s.keeper == nil {
		return GetDecisionResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetDecision(req.DecisionID)
	if !ok {
		if err := s.ensureDecisionsReadable(); err != nil {
			return GetDecisionResponse{}, err
		}
		return GetDecisionResponse{}, ErrDecisionNotFound
	}
	return GetDecisionResponse{Decision: record}, nil
}

func (s QueryServer) GetAuditAction(req GetAuditActionRequest) (GetAuditActionResponse, error) {
	if s.keeper == nil {
		return GetAuditActionResponse{}, ErrNilKeeper
	}

	record, ok := s.keeper.GetAuditAction(req.ActionID)
	if !ok {
		if err := s.ensureAuditActionsReadable(); err != nil {
			return GetAuditActionResponse{}, err
		}
		return GetAuditActionResponse{}, ErrAuditActionNotFound
	}
	return GetAuditActionResponse{Action: record}, nil
}

func (s QueryServer) ListPolicies(_ ListPoliciesRequest) (ListPoliciesResponse, error) {
	if s.keeper == nil {
		return ListPoliciesResponse{}, ErrNilKeeper
	}

	records, err := s.keeper.ListPoliciesWithError()
	if err != nil {
		return ListPoliciesResponse{}, err
	}
	return ListPoliciesResponse{Policies: clampPolicies(records)}, nil
}

func (s QueryServer) ListDecisions(_ ListDecisionsRequest) (ListDecisionsResponse, error) {
	if s.keeper == nil {
		return ListDecisionsResponse{}, ErrNilKeeper
	}

	records, err := s.keeper.ListDecisionsWithError()
	if err != nil {
		return ListDecisionsResponse{}, err
	}
	return ListDecisionsResponse{Decisions: clampDecisions(records)}, nil
}

func (s QueryServer) ListAuditActions(_ ListAuditActionsRequest) (ListAuditActionsResponse, error) {
	if s.keeper == nil {
		return ListAuditActionsResponse{}, ErrNilKeeper
	}

	records, err := s.keeper.ListAuditActionsWithError()
	if err != nil {
		return ListAuditActionsResponse{}, err
	}
	return ListAuditActionsResponse{Actions: clampAuditActions(records)}, nil
}

func clampPolicies(records []types.GovernancePolicy) []types.GovernancePolicy {
	if len(records) <= maxQueryListResults {
		return records
	}
	return records[:maxQueryListResults]
}

func clampDecisions(records []types.GovernanceDecision) []types.GovernanceDecision {
	if len(records) <= maxQueryListResults {
		return records
	}
	return records[:maxQueryListResults]
}

func clampAuditActions(records []types.GovernanceAuditAction) []types.GovernanceAuditAction {
	if len(records) <= maxQueryListResults {
		return records
	}
	return records[:maxQueryListResults]
}

func (s QueryServer) ensurePoliciesReadable() error {
	_, err := s.keeper.ListPoliciesWithError()
	return err
}

func (s QueryServer) ensureDecisionsReadable() error {
	_, err := s.keeper.ListDecisionsWithError()
	return err
}

func (s QueryServer) ensureAuditActionsReadable() error {
	_, err := s.keeper.ListAuditActionsWithError()
	return err
}
