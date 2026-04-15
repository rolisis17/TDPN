package types

import (
	"errors"
	"strings"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

const (
	DecisionOutcomeApprove = "approve"
	DecisionOutcomeReject  = "reject"
	DecisionOutcomeAbstain = "abstain"
)

// GovernancePolicy captures chain governance rules active for a policy scope.
type GovernancePolicy struct {
	PolicyID        string
	Title           string
	Description     string
	Version         uint64
	ActivatedAtUnix int64
	Status          chaintypes.ReconciliationStatus
}

// GovernanceDecision captures a proposal outcome bound to a governance policy.
type GovernanceDecision struct {
	DecisionID    string
	PolicyID      string
	ProposalID    string
	Outcome       string
	Decider       string
	Reason        string
	DecidedAtUnix int64
	Status        chaintypes.ReconciliationStatus
}

// GovernanceAuditAction captures append-only bootstrap governance admin actions.
type GovernanceAuditAction struct {
	ActionID        string
	Action          string
	Actor           string
	Reason          string
	EvidencePointer string
	TimestampUnix   int64
}

func (p GovernancePolicy) ValidateBasic() error {
	if strings.TrimSpace(p.PolicyID) == "" {
		return errors.New("policy id is required")
	}
	if strings.TrimSpace(p.Title) == "" {
		return errors.New("policy title is required")
	}
	if p.Version == 0 {
		return errors.New("policy version must be positive")
	}
	if p.ActivatedAtUnix < 0 {
		return errors.New("activated_at_unix cannot be negative")
	}
	return nil
}

func (d GovernanceDecision) ValidateBasic() error {
	if strings.TrimSpace(d.DecisionID) == "" {
		return errors.New("decision id is required")
	}
	if strings.TrimSpace(d.PolicyID) == "" {
		return errors.New("policy id is required")
	}
	if strings.TrimSpace(d.ProposalID) == "" {
		return errors.New("proposal id is required")
	}
	if strings.TrimSpace(d.Decider) == "" {
		return errors.New("decider is required")
	}
	if d.DecidedAtUnix <= 0 {
		return errors.New("decided_at_unix must be positive")
	}
	if !isValidDecisionOutcome(d.Outcome) {
		return errors.New("decision outcome must be approve, reject, or abstain")
	}
	return nil
}

func (a GovernanceAuditAction) ValidateBasic() error {
	if strings.TrimSpace(a.ActionID) == "" {
		return errors.New("action id is required")
	}
	if strings.TrimSpace(a.Action) == "" {
		return errors.New("action is required")
	}
	if strings.TrimSpace(a.Actor) == "" {
		return errors.New("actor is required")
	}
	if strings.TrimSpace(a.Reason) == "" {
		return errors.New("reason is required")
	}
	if strings.TrimSpace(a.EvidencePointer) == "" {
		return errors.New("evidence pointer is required")
	}
	if a.TimestampUnix <= 0 {
		return errors.New("timestamp_unix must be positive")
	}
	return nil
}

func isValidDecisionOutcome(outcome string) bool {
	switch strings.ToLower(strings.TrimSpace(outcome)) {
	case DecisionOutcomeApprove, DecisionOutcomeReject, DecisionOutcomeAbstain:
		return true
	default:
		return false
	}
}
