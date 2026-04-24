package module

import (
	"errors"
	"fmt"
	"strings"

	"github.com/tdpn/tdpn-chain/x/vpngovernance/keeper"
	"github.com/tdpn/tdpn-chain/x/vpngovernance/types"
)

var (
	ErrNilKeeper           = errors.New("vpngovernance: keeper is nil")
	ErrInvalidPolicy       = errors.New("vpngovernance: invalid policy")
	ErrInvalidDecision     = errors.New("vpngovernance: invalid decision")
	ErrInvalidAuditAction  = errors.New("vpngovernance: invalid audit action")
	ErrPolicyConflict      = errors.New("vpngovernance: policy conflict")
	ErrDecisionConflict    = errors.New("vpngovernance: decision conflict")
	ErrAuditActionConflict = errors.New("vpngovernance: audit action conflict")
	ErrPolicyNotFound      = errors.New("vpngovernance: policy not found")
)

// CreatePolicyRequest captures an intent to create or replay governance policy.
type CreatePolicyRequest struct {
	Policy types.GovernancePolicy
}

// CreatePolicyResponse returns persisted policy plus replay hints.
type CreatePolicyResponse struct {
	Policy     types.GovernancePolicy
	Existed    bool
	Idempotent bool
}

// RecordDecisionRequest captures an intent to create or replay governance decision.
type RecordDecisionRequest struct {
	Decision types.GovernanceDecision
}

// RecordDecisionResponse returns persisted decision plus replay hints.
type RecordDecisionResponse struct {
	Decision   types.GovernanceDecision
	Existed    bool
	Idempotent bool
}

// RecordAuditActionRequest captures an intent to create or replay governance audit action.
type RecordAuditActionRequest struct {
	Action types.GovernanceAuditAction
}

// RecordAuditActionResponse returns persisted audit action plus replay hints.
type RecordAuditActionResponse struct {
	Action     types.GovernanceAuditAction
	Existed    bool
	Idempotent bool
}

// MsgServer exposes a lightweight Cosmos-style message surface for vpngovernance.
type MsgServer struct {
	keeper *keeper.Keeper
}

func NewMsgServer(k *keeper.Keeper) MsgServer {
	return MsgServer{keeper: k}
}

func (s MsgServer) CreatePolicy(req CreatePolicyRequest) (CreatePolicyResponse, error) {
	if s.keeper == nil {
		return CreatePolicyResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Policy.PolicyID != "" {
		_, existed = s.keeper.GetPolicy(req.Policy.PolicyID)
	}

	record, err := s.keeper.CreatePolicy(req.Policy)
	resp := CreatePolicyResponse{
		Policy:     record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrPolicyConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidPolicy, err)
	}
	return resp, nil
}

func (s MsgServer) RecordDecision(req RecordDecisionRequest) (RecordDecisionResponse, error) {
	if s.keeper == nil {
		return RecordDecisionResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Decision.DecisionID != "" {
		_, existed = s.keeper.GetDecision(req.Decision.DecisionID)
	}

	if strings.TrimSpace(req.Decision.PolicyID) != "" {
		if _, ok := s.keeper.GetPolicy(req.Decision.PolicyID); !ok {
			return RecordDecisionResponse{
				Decision: req.Decision,
				Existed:  existed,
			}, fmt.Errorf("%w: policy_id=%s", ErrPolicyNotFound, req.Decision.PolicyID)
		}
	}

	record, err := s.keeper.RecordDecision(req.Decision)
	resp := RecordDecisionResponse{
		Decision:   record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrDecisionConflict, err)
		}
		if isPolicyReferenceNotFoundError(err) {
			return resp, fmt.Errorf("%w: %v", ErrPolicyNotFound, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidDecision, err)
	}
	return resp, nil
}

func isPolicyReferenceNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "policy \"") && strings.Contains(message, "\" not found")
}

func (s MsgServer) RecordAuditAction(req RecordAuditActionRequest) (RecordAuditActionResponse, error) {
	if s.keeper == nil {
		return RecordAuditActionResponse{}, ErrNilKeeper
	}

	existed := false
	if req.Action.ActionID != "" {
		_, existed = s.keeper.GetAuditAction(req.Action.ActionID)
	}

	record, err := s.keeper.RecordAuditAction(req.Action)
	resp := RecordAuditActionResponse{
		Action:     record,
		Existed:    existed,
		Idempotent: existed && err == nil,
	}
	if err != nil {
		if strings.Contains(err.Error(), "conflicting fields") {
			return resp, fmt.Errorf("%w: %v", ErrAuditActionConflict, err)
		}
		return resp, fmt.Errorf("%w: %v", ErrInvalidAuditAction, err)
	}

	return resp, nil
}
