package settlement

import (
	"context"
	"time"
)

type OperationStatus string

const (
	OperationStatusPending   OperationStatus = "pending"
	OperationStatusSubmitted OperationStatus = "submitted"
	OperationStatusConfirmed OperationStatus = "confirmed"
	OperationStatusFailed    OperationStatus = "failed"
)

type UsageRecord struct {
	SessionID    string
	SubjectID    string
	EntryRelayID string
	ExitRelayID  string
	BytesIngress int64
	BytesEgress  int64
	RecordedAt   time.Time
}

type PriceQuote struct {
	SubjectID         string
	PricePerMiBMicros int64
	Currency          string
	QuotedAt          time.Time
	ExpiresAt         time.Time
}

type FundReservation struct {
	ReservationID    string
	SessionID        string
	SubjectID        string
	AmountMicros     int64
	Currency         string
	CreatedAt        time.Time
	IdempotentReplay bool
	Status           OperationStatus
}

type SessionSettlement struct {
	SettlementID               string
	ReservationID              string
	SessionID                  string
	SubjectID                  string
	ChargedMicros              int64
	Currency                   string
	SettledAt                  time.Time
	IdempotentReplay           bool
	AdapterSubmitted           bool
	AdapterReferenceID         string
	AdapterDeferred            bool
	ShadowAdapterSubmitted     bool
	ShadowAdapterReferenceID   string
	ShadowAdapterLastError     string
	ShadowAdapterLastAttemptAt time.Time
	ShadowAdapterStatus        OperationStatus
	Status                     OperationStatus
}

type RewardIssue struct {
	RewardID                   string
	ProviderSubjectID          string
	SessionID                  string
	SettlementReferenceID      string
	TrafficProofRef            string
	TrafficProofVerified       bool
	TrafficProofVerifierID     string
	TrafficProofVerifiedAt     time.Time
	TrafficProofTrustContract  RewardProofTrustContract
	PayoutPeriodStart          time.Time
	PayoutPeriodEnd            time.Time
	RewardMicros               int64
	Currency                   string
	IssuedAt                   time.Time
	IdempotentReplay           bool
	AdapterSubmitted           bool
	AdapterReferenceID         string
	AdapterDeferred            bool
	ShadowAdapterSubmitted     bool
	ShadowAdapterReferenceID   string
	ShadowAdapterLastError     string
	ShadowAdapterLastAttemptAt time.Time
	ShadowAdapterStatus        OperationStatus
	Status                     OperationStatus
}

type SponsorCreditReservation struct {
	ReservationID              string
	SponsorID                  string
	SubjectID                  string
	SessionID                  string
	AmountMicros               int64
	Currency                   string
	CreatedAt                  time.Time
	ExpiresAt                  time.Time
	ConsumedAt                 time.Time
	IdempotentReplay           bool
	AdapterSubmitted           bool
	AdapterReferenceID         string
	AdapterDeferred            bool
	ShadowAdapterSubmitted     bool
	ShadowAdapterReferenceID   string
	ShadowAdapterLastError     string
	ShadowAdapterLastAttemptAt time.Time
	ShadowAdapterStatus        OperationStatus
	Status                     OperationStatus
}

type PaymentProof struct {
	ReservationID string
	SponsorID     string
	SubjectID     string
	SessionID     string
}

type PaymentAuthorization struct {
	ReservationID    string
	SponsorID        string
	SubjectID        string
	SessionID        string
	AuthorizedMicros int64
	Currency         string
	AuthorizedAt     time.Time
	IdempotentReplay bool
	Status           OperationStatus
}

type SlashEvidence struct {
	EvidenceID                 string
	SubjectID                  string
	SessionID                  string
	ViolationType              string
	EvidenceRef                string
	SlashMicros                int64
	Currency                   string
	ObservedAt                 time.Time
	IdempotentReplay           bool
	AdapterSubmitted           bool
	AdapterReferenceID         string
	AdapterDeferred            bool
	ShadowAdapterSubmitted     bool
	ShadowAdapterReferenceID   string
	ShadowAdapterLastError     string
	ShadowAdapterLastAttemptAt time.Time
	ShadowAdapterStatus        OperationStatus
	Status                     OperationStatus
}

type SlashEvidenceFilter struct {
	SubjectID           string
	SessionID           string
	ViolationType       string
	ObservedAtOrAfter   time.Time
	ObservedBefore      time.Time
	IncludeFailed       bool
	IncludeFailedSet    bool
	IncludeZeroObserved bool
}

type RewardProofTrustContract string

const (
	// RewardProofTrustContractObjectiveTrafficV1 requires the verifier to bind
	// the referenced objective traffic proof to the reward's payout material.
	RewardProofTrustContractObjectiveTrafficV1 RewardProofTrustContract = "settlement.reward.objective-traffic.v1"
)

type RewardProofVerificationRequest struct {
	TrustContract     RewardProofTrustContract
	TrafficProofRef   string
	RewardID          string
	ProviderSubjectID string
	SessionID         string
	PayoutPeriodStart time.Time
	PayoutPeriodEnd   time.Time
	RewardMicros      int64
	Currency          string
	IssuedAt          time.Time
}

type RewardProofVerification struct {
	Verified   bool
	VerifierID string
	VerifiedAt time.Time
}

type RewardProofRecord struct {
	ProofPath         string
	TrafficProofRef   string
	TrustContract     RewardProofTrustContract
	RewardID          string
	ProviderSubjectID string
	SessionID         string
	PayoutPeriodStart time.Time
	PayoutPeriodEnd   time.Time
	RewardMicros      int64
	Currency          string
	IssuedAt          time.Time
	Verified          bool
	VerifierID        string
	VerifiedAt        time.Time
}

type RewardProofRegistrar interface {
	RegisterRewardProof(ctx context.Context, proof RewardProofRecord) error
}

// RewardProofVerifier verifies traffic proof object references before they can
// stand in for a finalized settlement reference on chain-backed reward payouts.
type RewardProofVerifier interface {
	VerifyRewardProof(ctx context.Context, request RewardProofVerificationRequest) (RewardProofVerification, error)
}

type ReconcileReport struct {
	GeneratedAt               time.Time
	OpenReservations          int
	UsageSessions             int
	SettledSessions           int
	IssuedRewards             int
	SponsorReservations       int
	SponsorAuthorizations     int
	SubmittedSlashEvidence    int
	TotalChargedMicros        int64
	TotalRewardedMicros       int64
	TotalSponsoredMicros      int64
	TotalSlashedMicros        int64
	PendingAdapterOperations  int
	ShadowAdapterConfigured   bool
	ShadowAttemptedOperations int
	ShadowSubmittedOperations int
	ShadowFailedOperations    int
	PendingOperations         int
	SubmittedOperations       int
	ConfirmedOperations       int
	FailedOperations          int
}

type Service interface {
	RecordUsage(ctx context.Context, usage UsageRecord) error
	QuotePrice(ctx context.Context, subjectID string, currency string) (PriceQuote, error)
	ReserveFunds(ctx context.Context, reservation FundReservation) (FundReservation, error)
	ReserveSponsorCredits(ctx context.Context, reservation SponsorCreditReservation) (SponsorCreditReservation, error)
	GetSponsorReservation(ctx context.Context, reservationID string) (SponsorCreditReservation, error)
	AuthorizePayment(ctx context.Context, proof PaymentProof) (PaymentAuthorization, error)
	SettleSession(ctx context.Context, sessionID string) (SessionSettlement, error)
	IssueReward(ctx context.Context, reward RewardIssue) (RewardIssue, error)
	SubmitSlashEvidence(ctx context.Context, evidence SlashEvidence) (SlashEvidence, error)
	Reconcile(ctx context.Context) (ReconcileReport, error)
}

type ChainAdapter interface {
	SubmitSessionSettlement(ctx context.Context, settlement SessionSettlement) (referenceID string, err error)
	SubmitRewardIssue(ctx context.Context, reward RewardIssue) (referenceID string, err error)
	SubmitSponsorReservation(ctx context.Context, reservation SponsorCreditReservation) (referenceID string, err error)
	SubmitSlashEvidence(ctx context.Context, evidence SlashEvidence) (referenceID string, err error)
	Health(ctx context.Context) error
}

type ChainRewardProofRegistrar interface {
	SubmitRewardProof(ctx context.Context, proof RewardProofRecord) (referenceID string, err error)
}

// ChainBillingReservationSubmitter is an optional adapter capability for
// submitting normal client fund reservations before session settlement.
type ChainBillingReservationSubmitter interface {
	SubmitFundReservation(ctx context.Context, reservation FundReservation) (referenceID string, err error)
}

// ChainRewardProofRequirement marks adapters whose reward write surface rejects
// rewards without an objective traffic proof or finalized settlement reference.
type ChainRewardProofRequirement interface {
	RequiresRewardProofReference() bool
}

// ChainSlashEvidenceLister is an optional adapter capability for querying
// chain-wide slashing evidence before reward payout finalization.
type ChainSlashEvidenceLister interface {
	ListSlashEvidence(ctx context.Context, filter SlashEvidenceFilter) ([]SlashEvidence, error)
}

// ChainConfirmationQuerier is a legacy optional adapter capability for
// by-ID existence checks. Existence alone is not sufficient finality for
// submitted -> confirmed reconciliation promotion.
type ChainConfirmationQuerier interface {
	HasSessionSettlement(ctx context.Context, settlementID string) (bool, error)
	HasRewardIssue(ctx context.Context, rewardID string) (bool, error)
	HasSponsorReservation(ctx context.Context, reservationID string) (bool, error)
	HasSlashEvidence(ctx context.Context, evidenceID string) (bool, error)
}

// ChainConfirmationStatusQuerier is an optional adapter capability used by
// reconcile flows to promote submitted records only after chain state reports
// the record as confirmed/finalized.
type ChainConfirmationStatusQuerier interface {
	SessionSettlementStatus(ctx context.Context, settlementID string) (OperationStatus, bool, error)
	RewardIssueStatus(ctx context.Context, rewardID string) (OperationStatus, bool, error)
	SponsorReservationStatus(ctx context.Context, reservationID string) (OperationStatus, bool, error)
	SlashEvidenceStatus(ctx context.Context, evidenceID string) (OperationStatus, bool, error)
}

// SessionSettlementQuerier returns the material chain settlement record for
// reconciliation paths that must bind confirmation to the local session.
type SessionSettlementQuerier interface {
	SessionSettlement(ctx context.Context, settlementID string) (SessionSettlement, bool, error)
}

// RewardIssueQuerier returns the material chain reward record for finality
// checks that must bind confirmation to the local reward intent.
type RewardIssueQuerier interface {
	RewardIssue(ctx context.Context, rewardID string) (RewardIssue, bool, error)
}

// SlashEvidenceQuerier returns the material chain slash record for finality
// checks that must bind confirmation to the local slash evidence intent.
type SlashEvidenceQuerier interface {
	SlashEvidence(ctx context.Context, evidenceID string) (SlashEvidence, bool, error)
}

// ChainFundReservationStatusQuerier is an optional adapter capability for
// checking normal client fund reservation finality before those reservations
// are treated as spendable in chain-backed flows.
type ChainFundReservationStatusQuerier interface {
	FundReservationStatus(ctx context.Context, reservationID string) (OperationStatus, bool, error)
}

// FundReservationQuerier returns the material fund reservation record for
// callers that must bind a confirmed reservation to the signed-in subject.
type FundReservationQuerier interface {
	FundReservation(ctx context.Context, reservationID string) (FundReservation, bool, error)
}

// ChainReservationConfirmationStatusQuerier groups the reservation finality
// checks needed by callers that must fail closed until both client-funded and
// sponsor-funded reservations are finalized on chain.
type ChainReservationConfirmationStatusQuerier interface {
	ChainFundReservationStatusQuerier
	SponsorReservationStatus(ctx context.Context, reservationID string) (OperationStatus, bool, error)
}

// ChainDeferredReporter is an optional chain-adapter extension for surfacing
// adapter-internal deferred backlog (for async submission failures after enqueue).
type ChainDeferredReporter interface {
	DeferredOperationCount() int
}
