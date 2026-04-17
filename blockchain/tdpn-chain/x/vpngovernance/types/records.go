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

// Canonicalize normalizes identity and enum-like fields while preserving free-text fields.
func (p GovernancePolicy) Canonicalize() GovernancePolicy {
	p.PolicyID = canonicalIdentifier(p.PolicyID)
	p.Status = canonicalStatus(p.Status)
	return p
}

// Canonicalize normalizes identity and enum-like fields while preserving free-text fields.
func (d GovernanceDecision) Canonicalize() GovernanceDecision {
	d.DecisionID = canonicalIdentifier(d.DecisionID)
	d.PolicyID = canonicalIdentifier(d.PolicyID)
	d.ProposalID = canonicalIdentifier(d.ProposalID)
	d.Outcome = canonicalEnum(d.Outcome)
	d.Decider = canonicalIdentifier(d.Decider)
	d.Status = canonicalStatus(d.Status)
	return d
}

// Canonicalize normalizes identity and enum-like fields while preserving free-text fields.
func (a GovernanceAuditAction) Canonicalize() GovernanceAuditAction {
	a.ActionID = canonicalIdentifier(a.ActionID)
	a.Action = canonicalEnum(a.Action)
	a.Actor = canonicalIdentifier(a.Actor)
	a.EvidencePointer = strings.TrimSpace(a.EvidencePointer)
	return a
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

func canonicalIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalEnum(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalStatus(value chaintypes.ReconciliationStatus) chaintypes.ReconciliationStatus {
	return chaintypes.ReconciliationStatus(canonicalEnum(string(value)))
}
