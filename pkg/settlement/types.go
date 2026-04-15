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
	ReservationID string
	SessionID     string
	SubjectID     string
	AmountMicros  int64
	Currency      string
	CreatedAt     time.Time
}

type SessionSettlement struct {
	SettlementID       string
	SessionID          string
	SubjectID          string
	ChargedMicros      int64
	Currency           string
	SettledAt          time.Time
	IdempotentReplay   bool
	AdapterSubmitted   bool
	AdapterReferenceID string
	AdapterDeferred    bool
	Status             OperationStatus
}

type RewardIssue struct {
	RewardID           string
	ProviderSubjectID  string
	SessionID          string
	RewardMicros       int64
	Currency           string
	IssuedAt           time.Time
	IdempotentReplay   bool
	AdapterSubmitted   bool
	AdapterReferenceID string
	AdapterDeferred    bool
	Status             OperationStatus
}

type SponsorCreditReservation struct {
	ReservationID      string
	SponsorID          string
	SubjectID          string
	SessionID          string
	AmountMicros       int64
	Currency           string
	CreatedAt          time.Time
	ExpiresAt          time.Time
	ConsumedAt         time.Time
	IdempotentReplay   bool
	AdapterSubmitted   bool
	AdapterReferenceID string
	AdapterDeferred    bool
	Status             OperationStatus
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
	EvidenceID         string
	SubjectID          string
	SessionID          string
	ViolationType      string
	EvidenceRef        string
	SlashMicros        int64
	Currency           string
	ObservedAt         time.Time
	IdempotentReplay   bool
	AdapterSubmitted   bool
	AdapterReferenceID string
	AdapterDeferred    bool
	Status             OperationStatus
}

type ReconcileReport struct {
	GeneratedAt              time.Time
	OpenReservations         int
	UsageSessions            int
	SettledSessions          int
	IssuedRewards            int
	SponsorReservations      int
	SponsorAuthorizations    int
	SubmittedSlashEvidence   int
	TotalChargedMicros       int64
	TotalRewardedMicros      int64
	TotalSponsoredMicros     int64
	TotalSlashedMicros       int64
	PendingAdapterOperations int
	PendingOperations        int
	SubmittedOperations      int
	ConfirmedOperations      int
	FailedOperations         int
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
