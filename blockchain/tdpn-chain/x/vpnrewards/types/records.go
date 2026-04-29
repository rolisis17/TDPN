package types

import (
	"errors"
	"strings"
	"time"

	chaintypes "github.com/tdpn/tdpn-chain/types"
)

// RewardAccrual links settled usage to provider rewards.
type RewardAccrual struct {
	AccrualID       string
	SessionID       string
	ProviderID      string
	AssetDenom      string
	Amount          int64
	AccruedAtUnix   int64
	PayoutStartUnix int64
	PayoutEndUnix   int64
	OperationState  chaintypes.ReconciliationStatus
}

// DistributionRecord records payout references for accrued rewards.
type DistributionRecord struct {
	DistributionID string
	AccrualID      string
	PayoutRef      string
	DistributedAt  int64
	Status         chaintypes.ReconciliationStatus
}

const RewardProofTrustContractObjectiveTrafficV1 = "settlement.reward.objective-traffic.v1"

// RewardProofRecord binds an objective traffic proof to the exact reward material
// it authorizes. The bridge exposes these records as a read-only proof registry.
type RewardProofRecord struct {
	ProofPath         string
	TrafficProofRef   string
	TrustContract     string
	RewardID          string
	ProviderSubjectID string
	SessionID         string
	PayoutStartUnix   int64
	PayoutEndUnix     int64
	RewardMicros      int64
	Currency          string
	IssuedAtUnix      int64
	Verified          bool
	VerifierID        string
	VerifiedAtUnix    int64
}

// Canonicalize normalizes IDs and defaults for deterministic persistence and equality checks.
func (r RewardAccrual) Canonicalize() RewardAccrual {
	r.AccrualID = canonicalIdentifier(r.AccrualID)
	r.SessionID = canonicalIdentifier(r.SessionID)
	r.ProviderID = canonicalIdentifier(r.ProviderID)
	r.AssetDenom = canonicalIdentifier(r.AssetDenom)
	r.OperationState = canonicalStatus(r.OperationState, chaintypes.ReconciliationPending)
	return r
}

// Canonicalize normalizes IDs and defaults for deterministic persistence and equality checks.
func (r DistributionRecord) Canonicalize() DistributionRecord {
	r.DistributionID = canonicalIdentifier(r.DistributionID)
	r.AccrualID = canonicalIdentifier(r.AccrualID)
	r.Status = canonicalStatus(r.Status, chaintypes.ReconciliationSubmitted)
	return r
}

// Canonicalize normalizes whitespace and defaults without changing proof-object identity.
func (r RewardProofRecord) Canonicalize() RewardProofRecord {
	r.ProofPath = canonicalProofPath(r.ProofPath)
	r.TrafficProofRef = strings.TrimSpace(r.TrafficProofRef)
	r.TrustContract = strings.TrimSpace(r.TrustContract)
	if r.TrustContract == "" {
		r.TrustContract = RewardProofTrustContractObjectiveTrafficV1
	}
	r.RewardID = strings.TrimSpace(r.RewardID)
	r.ProviderSubjectID = strings.TrimSpace(r.ProviderSubjectID)
	r.SessionID = strings.TrimSpace(r.SessionID)
	r.Currency = strings.TrimSpace(r.Currency)
	r.VerifierID = strings.TrimSpace(r.VerifierID)
	return r
}

func (r RewardAccrual) ValidateBasic() error {
	r = r.Canonicalize()

	if r.AccrualID == "" {
		return errors.New("accrual id is required")
	}
	if r.SessionID == "" {
		return errors.New("session id is required")
	}
	if r.ProviderID == "" {
		return errors.New("provider id is required")
	}
	if r.AssetDenom == "" {
		return errors.New("asset denom is required")
	}
	if r.Amount <= 0 {
		return errors.New("amount must be positive")
	}
	if !isKnownReconciliationStatus(r.OperationState) {
		return errors.New("operation state must be pending, submitted, confirmed, or failed")
	}
	if err := validateWeeklyPayoutPeriod(r.PayoutStartUnix, r.PayoutEndUnix); err != nil {
		return err
	}
	return nil
}

func (r DistributionRecord) ValidateBasic() error {
	r = r.Canonicalize()

	if r.DistributionID == "" {
		return errors.New("distribution id is required")
	}
	if r.AccrualID == "" {
		return errors.New("accrual id is required")
	}
	if strings.TrimSpace(r.PayoutRef) == "" {
		return errors.New("payout ref is required")
	}
	if !isKnownReconciliationStatus(r.Status) {
		return errors.New("status must be pending, submitted, confirmed, or failed")
	}
	return nil
}

func (r RewardProofRecord) ValidateBasic() error {
	r = r.Canonicalize()

	if r.ProofPath == "" {
		return errors.New("proof path is required")
	}
	if strings.ContainsAny(r.ProofPath, " \t\r\n") {
		return errors.New("proof path must not contain whitespace")
	}
	if r.TrafficProofRef == "" {
		return errors.New("traffic proof ref is required")
	}
	proofPath, ok := ProofPathFromTrafficProofRef(r.TrafficProofRef)
	if !ok {
		return errors.New("traffic proof ref must be canonical obj:// proof reference")
	}
	if proofPath != r.ProofPath {
		return errors.New("traffic proof ref does not match proof path")
	}
	if r.TrustContract != RewardProofTrustContractObjectiveTrafficV1 {
		return errors.New("unsupported reward proof trust contract")
	}
	if r.RewardID == "" {
		return errors.New("reward id is required")
	}
	if r.ProviderSubjectID == "" {
		return errors.New("provider subject id is required")
	}
	if r.SessionID == "" {
		return errors.New("session id is required")
	}
	if r.Currency == "" {
		return errors.New("currency is required")
	}
	if r.RewardMicros <= 0 {
		return errors.New("reward micros must be positive")
	}
	if err := validateWeeklyPayoutPeriod(r.PayoutStartUnix, r.PayoutEndUnix); err != nil {
		return err
	}
	if r.IssuedAtUnix <= 0 {
		return errors.New("issued at unix is required")
	}
	if r.Verified && r.VerifierID == "" {
		return errors.New("verifier id is required for verified proof")
	}
	return nil
}

func (r RewardProofRecord) ValidateVerified() error {
	r = r.Canonicalize()
	if err := r.ValidateBasic(); err != nil {
		return err
	}
	if !r.Verified {
		return errors.New("reward proof is not verified")
	}
	if r.VerifierID == "" {
		return errors.New("verifier id is required")
	}
	if r.VerifiedAtUnix <= 0 {
		return errors.New("verified at unix is required")
	}
	return nil
}

func canonicalIdentifier(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func canonicalProofPath(value string) string {
	return strings.TrimSpace(value)
}

func ProofPathFromTrafficProofRef(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "obj://") {
		return "", false
	}
	path := canonicalProofPath(strings.TrimPrefix(ref, "obj://"))
	if path == "" || strings.ContainsAny(path, " \t\r\n") {
		return "", false
	}
	return path, true
}

func canonicalStatus(value chaintypes.ReconciliationStatus, defaultValue chaintypes.ReconciliationStatus) chaintypes.ReconciliationStatus {
	normalized := chaintypes.ReconciliationStatus(canonicalIdentifier(string(value)))
	if normalized == "" {
		return defaultValue
	}
	return normalized
}

func isKnownReconciliationStatus(status chaintypes.ReconciliationStatus) bool {
	switch status {
	case chaintypes.ReconciliationPending,
		chaintypes.ReconciliationSubmitted,
		chaintypes.ReconciliationConfirmed,
		chaintypes.ReconciliationFailed:
		return true
	default:
		return false
	}
}

func validateWeeklyPayoutPeriod(startUnix int64, endUnix int64) error {
	if startUnix == 0 && endUnix == 0 {
		return nil
	}
	if startUnix == 0 || endUnix == 0 {
		return errors.New("payout start and end are required together")
	}
	start := time.Unix(startUnix, 0).UTC()
	end := time.Unix(endUnix, 0).UTC()
	if start.Weekday() != time.Monday ||
		start.Hour() != 0 ||
		start.Minute() != 0 ||
		start.Second() != 0 ||
		start.Nanosecond() != 0 {
		return errors.New("payout start must be Monday 00:00:00 UTC")
	}
	if !end.Equal(start.AddDate(0, 0, 7)) {
		return errors.New("payout end must be exactly 7 days after payout start")
	}
	return nil
}
