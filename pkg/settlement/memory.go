package settlement

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultPricePerMiBMicros    = int64(1000)
	defaultCurrency             = "TDPNC"
	defaultSponsorReservationTT = 5 * time.Minute
)

type currencyRate struct {
	Numerator   int64
	Denominator int64
}

var supportedObjectiveViolationTypes = map[string]struct{}{
	"double-sign":              {},
	"downtime-proof":           {},
	"invalid-settlement-proof": {},
	"session-replay-proof":     {},
	"sponsor-overdraft-proof":  {},
}

type deferredOperationType string

const (
	deferredOperationSettlement         deferredOperationType = "settlement"
	deferredOperationReward             deferredOperationType = "reward"
	deferredOperationSponsorReservation deferredOperationType = "sponsor_reservation"
	deferredOperationSlashEvidence      deferredOperationType = "slash_evidence"
)

type deferredAdapterOperation struct {
	Type           deferredOperationType
	RecordKey      string
	IdempotencyKey string
	DeferredAt     time.Time
	LastAttemptAt  time.Time
	Attempts       int
	LastError      string
}

type shadowSubmissionResult struct {
	Attempted   bool
	Submitted   bool
	Status      OperationStatus
	ReferenceID string
	LastError   string
	AttemptedAt time.Time
}

type MemoryService struct {
	mu sync.Mutex

	usageBySession             map[string][]UsageRecord
	reservationsBySession      map[string]FundReservation
	settledBySession           map[string]SessionSettlement
	rewardsByID                map[string]RewardIssue
	sponsorReservationsByID    map[string]SponsorCreditReservation
	paymentAuthByReservationID map[string]PaymentAuthorization
	slashEvidenceByID          map[string]SlashEvidence
	deferredAdapterOps         map[string]deferredAdapterOperation

	pricePerMiBMicros int64
	currency          string
	currencyRates     map[string]currencyRate
	adapter           ChainAdapter
	shadowAdapter     ChainAdapter

	pendingAdapterOps int
}

type MemoryOption func(*MemoryService)

func WithChainAdapter(adapter ChainAdapter) MemoryOption {
	return func(s *MemoryService) {
		s.adapter = adapter
	}
}

// WithShadowChainAdapter enables best-effort shadow submissions that mirror
// primary adapter writes without changing primary fail-soft semantics.
func WithShadowChainAdapter(adapter ChainAdapter) MemoryOption {
	return func(s *MemoryService) {
		s.shadowAdapter = adapter
	}
}

func WithPricePerMiBMicros(v int64) MemoryOption {
	return func(s *MemoryService) {
		if v > 0 {
			s.pricePerMiBMicros = v
		}
	}
}

func WithCurrency(currency string) MemoryOption {
	return func(s *MemoryService) {
		currency = normalizeCurrencyCode(currency)
		if currency != "" {
			s.currency = currency
		}
	}
}

func WithCurrencyRate(currency string, numerator int64, denominator int64) MemoryOption {
	return func(s *MemoryService) {
		currency = normalizeCurrencyCode(currency)
		if currency == "" || numerator <= 0 || denominator <= 0 {
			return
		}
		if s.currencyRates == nil {
			s.currencyRates = map[string]currencyRate{}
		}
		s.currencyRates[currency] = currencyRate{
			Numerator:   numerator,
			Denominator: denominator,
		}
	}
}

func NewMemoryService(opts ...MemoryOption) *MemoryService {
	s := &MemoryService{
		usageBySession:             map[string][]UsageRecord{},
		reservationsBySession:      map[string]FundReservation{},
		settledBySession:           map[string]SessionSettlement{},
		rewardsByID:                map[string]RewardIssue{},
		sponsorReservationsByID:    map[string]SponsorCreditReservation{},
		paymentAuthByReservationID: map[string]PaymentAuthorization{},
		slashEvidenceByID:          map[string]SlashEvidence{},
		deferredAdapterOps:         map[string]deferredAdapterOperation{},
		pricePerMiBMicros:          defaultPricePerMiBMicros,
		currency:                   defaultCurrency,
		currencyRates: map[string]currencyRate{
			defaultCurrency: {Numerator: 1, Denominator: 1},
		},
	}
	for _, opt := range opts {
		opt(s)
	}
	s.currency = normalizeCurrencyCode(s.currency)
	if s.currency == "" {
		s.currency = defaultCurrency
	}
	if s.currencyRates == nil {
		s.currencyRates = map[string]currencyRate{}
	}
	if _, ok := s.currencyRates[s.currency]; !ok {
		s.currencyRates[s.currency] = currencyRate{Numerator: 1, Denominator: 1}
	}
	return s
}

func (s *MemoryService) RecordUsage(_ context.Context, usage UsageRecord) error {
	usage.SessionID = strings.TrimSpace(usage.SessionID)
	usage.SubjectID = strings.TrimSpace(usage.SubjectID)
	if usage.SessionID == "" || usage.SubjectID == "" {
		return fmt.Errorf("record usage requires session_id and subject_id")
	}
	if usage.BytesIngress < 0 || usage.BytesEgress < 0 {
		return fmt.Errorf("record usage requires non-negative byte counters")
	}
	if usage.RecordedAt.IsZero() {
		usage.RecordedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.usageBySession[usage.SessionID] = append(s.usageBySession[usage.SessionID], usage)
	return nil
}

func (s *MemoryService) QuotePrice(_ context.Context, subjectID string, currency string) (PriceQuote, error) {
	subjectID = strings.TrimSpace(subjectID)
	if subjectID == "" {
		return PriceQuote{}, fmt.Errorf("quote price requires subject_id")
	}
	currency = normalizeCurrencyCode(currency)
	now := time.Now().UTC()
	s.mu.Lock()
	price := s.pricePerMiBMicros
	if currency == "" {
		currency = s.currency
	}
	convertedPrice, err := s.convertFromBaseMicrosLocked(price, currency)
	s.mu.Unlock()
	if err != nil {
		return PriceQuote{}, err
	}
	return PriceQuote{
		SubjectID:         subjectID,
		PricePerMiBMicros: convertedPrice,
		Currency:          currency,
		QuotedAt:          now,
		ExpiresAt:         now.Add(2 * time.Minute),
	}, nil
}

func (s *MemoryService) ReserveFunds(_ context.Context, reservation FundReservation) (FundReservation, error) {
	reservation.SessionID = strings.TrimSpace(reservation.SessionID)
	reservation.SubjectID = strings.TrimSpace(reservation.SubjectID)
	reservation.Currency = normalizeCurrencyCode(reservation.Currency)
	if reservation.SessionID == "" || reservation.SubjectID == "" {
		return FundReservation{}, fmt.Errorf("reserve funds requires session_id and subject_id")
	}
	if reservation.AmountMicros <= 0 {
		return FundReservation{}, fmt.Errorf("reserve funds requires amount_micros > 0")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.reservationsBySession[reservation.SessionID]; ok {
		return existing, nil
	}
	if reservation.Currency == "" {
		reservation.Currency = s.currency
	}
	if err := s.ensureSupportedCurrencyLocked(reservation.Currency); err != nil {
		return FundReservation{}, err
	}
	if reservation.CreatedAt.IsZero() {
		reservation.CreatedAt = time.Now().UTC()
	}
	if reservation.ReservationID == "" {
		reservation.ReservationID = "res-" + reservation.SessionID
	}
	s.reservationsBySession[reservation.SessionID] = reservation
	return reservation, nil
}

func (s *MemoryService) ReserveSponsorCredits(ctx context.Context, reservation SponsorCreditReservation) (SponsorCreditReservation, error) {
	reservation.ReservationID = strings.TrimSpace(reservation.ReservationID)
	reservation.SponsorID = strings.TrimSpace(reservation.SponsorID)
	reservation.SubjectID = strings.TrimSpace(reservation.SubjectID)
	reservation.SessionID = strings.TrimSpace(reservation.SessionID)
	reservation.Currency = normalizeCurrencyCode(reservation.Currency)
	if reservation.ReservationID == "" || reservation.SponsorID == "" || reservation.SubjectID == "" {
		return SponsorCreditReservation{}, fmt.Errorf("reserve sponsor credits requires reservation_id, sponsor_id, and subject_id")
	}
	if reservation.AmountMicros <= 0 {
		return SponsorCreditReservation{}, fmt.Errorf("reserve sponsor credits requires amount_micros > 0")
	}

	s.mu.Lock()
	if existing, ok := s.sponsorReservationsByID[reservation.ReservationID]; ok {
		existing.IdempotentReplay = true
		s.mu.Unlock()
		return existing, nil
	}
	currency := s.currency
	currencyRates := s.currencyRates
	s.mu.Unlock()

	if reservation.Currency == "" {
		reservation.Currency = currency
	}
	if _, ok := currencyRates[reservation.Currency]; !ok {
		return SponsorCreditReservation{}, fmt.Errorf("unsupported settlement currency: %s", reservation.Currency)
	}
	if reservation.CreatedAt.IsZero() {
		reservation.CreatedAt = time.Now().UTC()
	}
	if reservation.ExpiresAt.IsZero() {
		reservation.ExpiresAt = reservation.CreatedAt.Add(defaultSponsorReservationTT)
	}
	reservation.Status = OperationStatusConfirmed

	s.submitSponsorReservationAdapter(ctx, &reservation)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.sponsorReservationsByID[reservation.ReservationID] = reservation
	return reservation, nil
}

func (s *MemoryService) GetSponsorReservation(_ context.Context, reservationID string) (SponsorCreditReservation, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return SponsorCreditReservation{}, fmt.Errorf("reservation_id required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	reservation, ok := s.sponsorReservationsByID[reservationID]
	if !ok {
		return SponsorCreditReservation{}, fmt.Errorf("reservation not found: %s", reservationID)
	}
	return reservation, nil
}

func (s *MemoryService) AuthorizePayment(_ context.Context, proof PaymentProof) (PaymentAuthorization, error) {
	proof.ReservationID = strings.TrimSpace(proof.ReservationID)
	proof.SponsorID = strings.TrimSpace(proof.SponsorID)
	proof.SubjectID = strings.TrimSpace(proof.SubjectID)
	proof.SessionID = strings.TrimSpace(proof.SessionID)
	if proof.ReservationID == "" {
		return PaymentAuthorization{}, fmt.Errorf("authorize payment requires reservation_id")
	}

	now := time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.paymentAuthByReservationID[proof.ReservationID]; ok {
		existing.IdempotentReplay = true
		return existing, nil
	}
	reservation, ok := s.sponsorReservationsByID[proof.ReservationID]
	if !ok {
		return PaymentAuthorization{}, fmt.Errorf("reservation not found: %s", proof.ReservationID)
	}
	if !reservation.ExpiresAt.IsZero() && now.After(reservation.ExpiresAt) {
		return PaymentAuthorization{}, fmt.Errorf("reservation expired: %s", proof.ReservationID)
	}
	if !reservation.ConsumedAt.IsZero() {
		return PaymentAuthorization{}, fmt.Errorf("reservation already consumed: %s", proof.ReservationID)
	}
	if proof.SponsorID != "" && proof.SponsorID != reservation.SponsorID {
		return PaymentAuthorization{}, fmt.Errorf("reservation sponsor mismatch")
	}
	if proof.SubjectID != "" && proof.SubjectID != reservation.SubjectID {
		return PaymentAuthorization{}, fmt.Errorf("reservation subject mismatch")
	}
	if proof.SessionID != "" && reservation.SessionID != "" && proof.SessionID != reservation.SessionID {
		return PaymentAuthorization{}, fmt.Errorf("reservation session mismatch")
	}

	auth := PaymentAuthorization{
		ReservationID:    reservation.ReservationID,
		SponsorID:        reservation.SponsorID,
		SubjectID:        reservation.SubjectID,
		SessionID:        reservation.SessionID,
		AuthorizedMicros: reservation.AmountMicros,
		Currency:         reservation.Currency,
		AuthorizedAt:     now,
		Status:           OperationStatusConfirmed,
	}

	reservation.ConsumedAt = now
	reservation.Status = OperationStatusConfirmed
	s.sponsorReservationsByID[reservation.ReservationID] = reservation
	s.paymentAuthByReservationID[reservation.ReservationID] = auth
	return auth, nil
}

func (s *MemoryService) SettleSession(ctx context.Context, sessionID string) (SessionSettlement, error) {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return SessionSettlement{}, fmt.Errorf("settle session requires session_id")
	}

	s.mu.Lock()
	if existing, ok := s.settledBySession[sessionID]; ok {
		existing.IdempotentReplay = true
		s.mu.Unlock()
		return existing, nil
	}
	records := append([]UsageRecord(nil), s.usageBySession[sessionID]...)
	reservation, hasReservation := s.reservationsBySession[sessionID]
	price := s.pricePerMiBMicros
	currency := normalizeCurrencyCode(reservation.Currency)
	if currency == "" {
		currency = s.currency
	}
	rate, hasRate := s.currencyRates[currency]
	s.mu.Unlock()

	if len(records) == 0 {
		return SessionSettlement{}, fmt.Errorf("settle session requires recorded usage for session %s", sessionID)
	}
	if !hasReservation {
		return SessionSettlement{}, fmt.Errorf("settle session requires reservation for session %s", sessionID)
	}

	subjectID := reservation.SubjectID
	totalBytes := int64(0)
	for _, rec := range records {
		totalBytes += rec.BytesIngress + rec.BytesEgress
	}
	chargeBase := priceMicrosForBytes(totalBytes, price)
	if !hasRate {
		return SessionSettlement{}, fmt.Errorf("unsupported settlement currency: %s", currency)
	}
	charge, err := convertMicrosByRate(chargeBase, rate)
	if err != nil {
		return SessionSettlement{}, err
	}
	if charge > reservation.AmountMicros {
		return SessionSettlement{}, fmt.Errorf("reserved funds insufficient for settlement session=%s reserved=%d required=%d",
			sessionID, reservation.AmountMicros, charge)
	}

	settlement := SessionSettlement{
		SettlementID:  "set-" + sessionID,
		SessionID:     sessionID,
		SubjectID:     subjectID,
		ChargedMicros: charge,
		Currency:      currency,
		SettledAt:     time.Now().UTC(),
		Status:        OperationStatusConfirmed,
	}

	s.submitSettlementAdapter(ctx, &settlement)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.settledBySession[sessionID] = settlement
	delete(s.reservationsBySession, sessionID)
	return settlement, nil
}

func (s *MemoryService) IssueReward(ctx context.Context, reward RewardIssue) (RewardIssue, error) {
	reward.RewardID = strings.TrimSpace(reward.RewardID)
	reward.ProviderSubjectID = strings.TrimSpace(reward.ProviderSubjectID)
	reward.SessionID = strings.TrimSpace(reward.SessionID)
	reward.Currency = normalizeCurrencyCode(reward.Currency)
	if reward.RewardID == "" || reward.ProviderSubjectID == "" || reward.SessionID == "" {
		return RewardIssue{}, fmt.Errorf("issue reward requires reward_id, provider_subject_id, and session_id")
	}
	if reward.RewardMicros <= 0 {
		return RewardIssue{}, fmt.Errorf("issue reward requires reward_micros > 0")
	}
	s.mu.Lock()
	if existing, ok := s.rewardsByID[reward.RewardID]; ok {
		existing.IdempotentReplay = true
		s.mu.Unlock()
		return existing, nil
	}
	currency := s.currency
	s.mu.Unlock()

	if reward.Currency == "" {
		reward.Currency = currency
	}
	if _, ok := s.currencyRates[reward.Currency]; !ok {
		return RewardIssue{}, fmt.Errorf("unsupported settlement currency: %s", reward.Currency)
	}
	if reward.IssuedAt.IsZero() {
		reward.IssuedAt = time.Now().UTC()
	}
	reward.Status = OperationStatusConfirmed

	s.submitRewardAdapter(ctx, &reward)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.rewardsByID[reward.RewardID] = reward
	return reward, nil
}

func (s *MemoryService) SubmitSlashEvidence(ctx context.Context, evidence SlashEvidence) (SlashEvidence, error) {
	evidence.EvidenceID = strings.TrimSpace(evidence.EvidenceID)
	evidence.SubjectID = strings.TrimSpace(evidence.SubjectID)
	evidence.SessionID = strings.TrimSpace(evidence.SessionID)
	evidence.ViolationType = strings.TrimSpace(evidence.ViolationType)
	evidence.EvidenceRef = strings.TrimSpace(evidence.EvidenceRef)
	evidence.Currency = normalizeCurrencyCode(evidence.Currency)
	if evidence.EvidenceID == "" || evidence.SubjectID == "" || evidence.ViolationType == "" {
		return SlashEvidence{}, fmt.Errorf("submit slash evidence requires evidence_id, subject_id, and violation_type")
	}
	if evidence.SlashMicros < 0 {
		return SlashEvidence{}, fmt.Errorf("submit slash evidence requires slash_micros >= 0")
	}
	if !isObjectiveViolationType(evidence.ViolationType) {
		return SlashEvidence{}, fmt.Errorf("submit slash evidence requires objective violation_type")
	}
	if !isObjectiveEvidenceRef(evidence.EvidenceRef) {
		return SlashEvidence{}, fmt.Errorf("submit slash evidence requires objective evidence_ref (obj://... or sha256:...)")
	}

	s.mu.Lock()
	if existing, ok := s.slashEvidenceByID[evidence.EvidenceID]; ok {
		existing.IdempotentReplay = true
		s.mu.Unlock()
		return existing, nil
	}
	currency := s.currency
	s.mu.Unlock()

	if evidence.Currency == "" {
		evidence.Currency = currency
	}
	if _, ok := s.currencyRates[evidence.Currency]; !ok {
		return SlashEvidence{}, fmt.Errorf("unsupported settlement currency: %s", evidence.Currency)
	}
	if evidence.ObservedAt.IsZero() {
		evidence.ObservedAt = time.Now().UTC()
	}
	evidence.Status = OperationStatusConfirmed

	s.submitSlashEvidenceAdapter(ctx, &evidence)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.slashEvidenceByID[evidence.EvidenceID] = evidence
	return evidence, nil
}

func (s *MemoryService) Reconcile(ctx context.Context) (ReconcileReport, error) {
	s.replayDeferredAdapterOperations(ctx)
	s.confirmSubmittedAdapterOperations(ctx)

	adapterDeferredCount := 0
	if reporter, ok := s.currentAdapter().(ChainDeferredReporter); ok && reporter != nil {
		adapterDeferredCount = reporter.DeferredOperationCount()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	report := ReconcileReport{
		GeneratedAt:              time.Now().UTC(),
		OpenReservations:         len(s.reservationsBySession),
		UsageSessions:            len(s.usageBySession),
		SettledSessions:          len(s.settledBySession),
		IssuedRewards:            len(s.rewardsByID),
		SponsorReservations:      len(s.sponsorReservationsByID),
		SponsorAuthorizations:    len(s.paymentAuthByReservationID),
		SubmittedSlashEvidence:   len(s.slashEvidenceByID),
		PendingAdapterOperations: len(s.deferredAdapterOps) + adapterDeferredCount,
		ShadowAdapterConfigured:  s.shadowAdapter != nil,
	}

	countStatus := func(status OperationStatus) {
		switch status {
		case OperationStatusPending:
			report.PendingOperations++
		case OperationStatusSubmitted:
			report.SubmittedOperations++
		case OperationStatusConfirmed:
			report.ConfirmedOperations++
		case OperationStatusFailed:
			report.FailedOperations++
		}
	}
	countShadowStatus := func(status OperationStatus, attemptedAt time.Time) {
		if attemptedAt.IsZero() {
			return
		}
		report.ShadowAttemptedOperations++
		switch status {
		case OperationStatusSubmitted, OperationStatusConfirmed:
			report.ShadowSubmittedOperations++
		case OperationStatusFailed:
			report.ShadowFailedOperations++
		}
	}

	for _, settlement := range s.settledBySession {
		report.TotalChargedMicros += settlement.ChargedMicros
		countStatus(settlement.Status)
		countShadowStatus(settlement.ShadowAdapterStatus, settlement.ShadowAdapterLastAttemptAt)
	}
	for _, reward := range s.rewardsByID {
		report.TotalRewardedMicros += reward.RewardMicros
		countStatus(reward.Status)
		countShadowStatus(reward.ShadowAdapterStatus, reward.ShadowAdapterLastAttemptAt)
	}
	for _, reservation := range s.sponsorReservationsByID {
		countStatus(reservation.Status)
		countShadowStatus(reservation.ShadowAdapterStatus, reservation.ShadowAdapterLastAttemptAt)
	}
	for _, auth := range s.paymentAuthByReservationID {
		report.TotalSponsoredMicros += auth.AuthorizedMicros
		countStatus(auth.Status)
	}
	for _, evidence := range s.slashEvidenceByID {
		report.TotalSlashedMicros += evidence.SlashMicros
		countStatus(evidence.Status)
		countShadowStatus(evidence.ShadowAdapterStatus, evidence.ShadowAdapterLastAttemptAt)
	}

	return report, nil
}

func (s *MemoryService) submitSettlementAdapter(ctx context.Context, settlement *SessionSettlement) {
	adapter := s.currentAdapter()
	if adapter == nil {
		return
	}
	idempotencyKey := cosmosID("settlement", settlement.SettlementID, settlement.SessionID)
	shadowSubmit := func(ctx context.Context, adapter ChainAdapter) (string, error) {
		return adapter.SubmitSessionSettlement(ctx, *settlement)
	}
	op := deferredAdapterOperation{
		Type:           deferredOperationSettlement,
		RecordKey:      settlement.SessionID,
		IdempotencyKey: idempotencyKey,
	}

	ref, err := adapter.SubmitSessionSettlement(ctx, *settlement)
	shadowResult := s.submitShadowSubmission(ctx, idempotencyKey, shadowSubmit)
	if err != nil {
		settlement.AdapterDeferred = true
		settlement.AdapterSubmitted = false
		settlement.AdapterReferenceID = idempotencyKey
		settlement.Status = OperationStatusPending
		applyShadowResultToSettlement(settlement, shadowResult)
		s.mu.Lock()
		s.upsertDeferredOperationLocked(op, err)
		s.mu.Unlock()
		return
	}
	if strings.TrimSpace(ref) == "" {
		ref = idempotencyKey
	}
	settlement.AdapterSubmitted = true
	settlement.AdapterDeferred = false
	settlement.AdapterReferenceID = ref
	settlement.Status = OperationStatusSubmitted
	applyShadowResultToSettlement(settlement, shadowResult)

	s.mu.Lock()
	s.clearDeferredOperationLocked(idempotencyKey)
	s.mu.Unlock()
}

func (s *MemoryService) submitRewardAdapter(ctx context.Context, reward *RewardIssue) {
	adapter := s.currentAdapter()
	if adapter == nil {
		return
	}
	idempotencyKey := cosmosID("reward", reward.RewardID, reward.SessionID)
	shadowSubmit := func(ctx context.Context, adapter ChainAdapter) (string, error) {
		return adapter.SubmitRewardIssue(ctx, *reward)
	}
	op := deferredAdapterOperation{
		Type:           deferredOperationReward,
		RecordKey:      reward.RewardID,
		IdempotencyKey: idempotencyKey,
	}
	ref, err := adapter.SubmitRewardIssue(ctx, *reward)
	shadowResult := s.submitShadowSubmission(ctx, idempotencyKey, shadowSubmit)
	if err != nil {
		reward.AdapterDeferred = true
		reward.AdapterSubmitted = false
		reward.AdapterReferenceID = idempotencyKey
		reward.Status = OperationStatusPending
		applyShadowResultToReward(reward, shadowResult)
		s.mu.Lock()
		s.upsertDeferredOperationLocked(op, err)
		s.mu.Unlock()
		return
	}
	if strings.TrimSpace(ref) == "" {
		ref = idempotencyKey
	}
	reward.AdapterSubmitted = true
	reward.AdapterDeferred = false
	reward.AdapterReferenceID = ref
	reward.Status = OperationStatusSubmitted
	applyShadowResultToReward(reward, shadowResult)

	s.mu.Lock()
	s.clearDeferredOperationLocked(idempotencyKey)
	s.mu.Unlock()
}

func (s *MemoryService) submitSponsorReservationAdapter(ctx context.Context, reservation *SponsorCreditReservation) {
	adapter := s.currentAdapter()
	if adapter == nil {
		return
	}
	idempotencyKey := cosmosID("sponsor-reservation", reservation.ReservationID, reservation.SessionID)
	shadowSubmit := func(ctx context.Context, adapter ChainAdapter) (string, error) {
		return adapter.SubmitSponsorReservation(ctx, *reservation)
	}
	op := deferredAdapterOperation{
		Type:           deferredOperationSponsorReservation,
		RecordKey:      reservation.ReservationID,
		IdempotencyKey: idempotencyKey,
	}
	ref, err := adapter.SubmitSponsorReservation(ctx, *reservation)
	shadowResult := s.submitShadowSubmission(ctx, idempotencyKey, shadowSubmit)
	if err != nil {
		reservation.AdapterDeferred = true
		reservation.AdapterSubmitted = false
		reservation.AdapterReferenceID = idempotencyKey
		reservation.Status = OperationStatusPending
		applyShadowResultToSponsorReservation(reservation, shadowResult)
		s.mu.Lock()
		s.upsertDeferredOperationLocked(op, err)
		s.mu.Unlock()
		return
	}
	if strings.TrimSpace(ref) == "" {
		ref = idempotencyKey
	}
	reservation.AdapterSubmitted = true
	reservation.AdapterDeferred = false
	reservation.AdapterReferenceID = ref
	reservation.Status = OperationStatusSubmitted
	applyShadowResultToSponsorReservation(reservation, shadowResult)

	s.mu.Lock()
	s.clearDeferredOperationLocked(idempotencyKey)
	s.mu.Unlock()
}

func (s *MemoryService) submitSlashEvidenceAdapter(ctx context.Context, evidence *SlashEvidence) {
	adapter := s.currentAdapter()
	if adapter == nil {
		return
	}
	idempotencyKey := cosmosID("slash", evidence.EvidenceID, evidence.SubjectID)
	shadowSubmit := func(ctx context.Context, adapter ChainAdapter) (string, error) {
		return adapter.SubmitSlashEvidence(ctx, *evidence)
	}
	op := deferredAdapterOperation{
		Type:           deferredOperationSlashEvidence,
		RecordKey:      evidence.EvidenceID,
		IdempotencyKey: idempotencyKey,
	}
	ref, err := adapter.SubmitSlashEvidence(ctx, *evidence)
	shadowResult := s.submitShadowSubmission(ctx, idempotencyKey, shadowSubmit)
	if err != nil {
		evidence.AdapterDeferred = true
		evidence.AdapterSubmitted = false
		evidence.AdapterReferenceID = idempotencyKey
		evidence.Status = OperationStatusPending
		applyShadowResultToSlashEvidence(evidence, shadowResult)
		s.mu.Lock()
		s.upsertDeferredOperationLocked(op, err)
		s.mu.Unlock()
		return
	}
	if strings.TrimSpace(ref) == "" {
		ref = idempotencyKey
	}
	evidence.AdapterSubmitted = true
	evidence.AdapterDeferred = false
	evidence.AdapterReferenceID = ref
	evidence.Status = OperationStatusSubmitted
	applyShadowResultToSlashEvidence(evidence, shadowResult)

	s.mu.Lock()
	s.clearDeferredOperationLocked(idempotencyKey)
	s.mu.Unlock()
}

func (s *MemoryService) currentAdapter() ChainAdapter {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.adapter
}

func (s *MemoryService) currentShadowAdapter() ChainAdapter {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.shadowAdapter
}

func (s *MemoryService) submitShadowSubmission(
	ctx context.Context,
	idempotencyKey string,
	submitFn func(context.Context, ChainAdapter) (string, error),
) shadowSubmissionResult {
	shadowAdapter := s.currentShadowAdapter()
	if shadowAdapter == nil || submitFn == nil {
		return shadowSubmissionResult{}
	}
	return submitShadowWithAdapter(ctx, shadowAdapter, idempotencyKey, submitFn)
}

func submitShadowWithAdapter(
	ctx context.Context,
	adapter ChainAdapter,
	idempotencyKey string,
	submitFn func(context.Context, ChainAdapter) (string, error),
) shadowSubmissionResult {
	attemptedAt := time.Now().UTC()
	ref, err := submitFn(ctx, adapter)
	if err != nil {
		return shadowSubmissionResult{
			Attempted:   true,
			Submitted:   false,
			Status:      OperationStatusFailed,
			ReferenceID: idempotencyKey,
			LastError:   err.Error(),
			AttemptedAt: attemptedAt,
		}
	}
	if strings.TrimSpace(ref) == "" {
		ref = idempotencyKey
	}
	return shadowSubmissionResult{
		Attempted:   true,
		Submitted:   true,
		Status:      OperationStatusSubmitted,
		ReferenceID: ref,
		AttemptedAt: attemptedAt,
	}
}

func applyShadowResultToSettlement(settlement *SessionSettlement, shadow shadowSubmissionResult) {
	if settlement == nil || !shadow.Attempted {
		return
	}
	settlement.ShadowAdapterSubmitted = shadow.Submitted
	settlement.ShadowAdapterReferenceID = shadow.ReferenceID
	settlement.ShadowAdapterLastError = shadow.LastError
	settlement.ShadowAdapterLastAttemptAt = shadow.AttemptedAt
	settlement.ShadowAdapterStatus = shadow.Status
}

func applyShadowResultToReward(reward *RewardIssue, shadow shadowSubmissionResult) {
	if reward == nil || !shadow.Attempted {
		return
	}
	reward.ShadowAdapterSubmitted = shadow.Submitted
	reward.ShadowAdapterReferenceID = shadow.ReferenceID
	reward.ShadowAdapterLastError = shadow.LastError
	reward.ShadowAdapterLastAttemptAt = shadow.AttemptedAt
	reward.ShadowAdapterStatus = shadow.Status
}

func applyShadowResultToSponsorReservation(reservation *SponsorCreditReservation, shadow shadowSubmissionResult) {
	if reservation == nil || !shadow.Attempted {
		return
	}
	reservation.ShadowAdapterSubmitted = shadow.Submitted
	reservation.ShadowAdapterReferenceID = shadow.ReferenceID
	reservation.ShadowAdapterLastError = shadow.LastError
	reservation.ShadowAdapterLastAttemptAt = shadow.AttemptedAt
	reservation.ShadowAdapterStatus = shadow.Status
}

func applyShadowResultToSlashEvidence(evidence *SlashEvidence, shadow shadowSubmissionResult) {
	if evidence == nil || !shadow.Attempted {
		return
	}
	evidence.ShadowAdapterSubmitted = shadow.Submitted
	evidence.ShadowAdapterReferenceID = shadow.ReferenceID
	evidence.ShadowAdapterLastError = shadow.LastError
	evidence.ShadowAdapterLastAttemptAt = shadow.AttemptedAt
	evidence.ShadowAdapterStatus = shadow.Status
}

func (s *MemoryService) upsertDeferredOperationLocked(op deferredAdapterOperation, submitErr error) {
	existing, hasExisting := s.deferredAdapterOps[op.IdempotencyKey]
	now := time.Now().UTC()
	if hasExisting {
		op.DeferredAt = existing.DeferredAt
		op.Attempts = existing.Attempts
	}
	if op.DeferredAt.IsZero() {
		op.DeferredAt = now
	}
	op.LastAttemptAt = now
	op.Attempts++
	if submitErr != nil {
		op.LastError = submitErr.Error()
	}
	s.deferredAdapterOps[op.IdempotencyKey] = op
	s.pendingAdapterOps = len(s.deferredAdapterOps)
}

func (s *MemoryService) applyShadowDeferredOperationLocked(op deferredAdapterOperation, shadow shadowSubmissionResult) {
	if !shadow.Attempted {
		return
	}
	switch op.Type {
	case deferredOperationSettlement:
		settlement, ok := s.settledBySession[op.RecordKey]
		if !ok {
			return
		}
		applyShadowResultToSettlement(&settlement, shadow)
		s.settledBySession[op.RecordKey] = settlement
	case deferredOperationReward:
		reward, ok := s.rewardsByID[op.RecordKey]
		if !ok {
			return
		}
		applyShadowResultToReward(&reward, shadow)
		s.rewardsByID[op.RecordKey] = reward
	case deferredOperationSponsorReservation:
		reservation, ok := s.sponsorReservationsByID[op.RecordKey]
		if !ok {
			return
		}
		applyShadowResultToSponsorReservation(&reservation, shadow)
		s.sponsorReservationsByID[op.RecordKey] = reservation
	case deferredOperationSlashEvidence:
		evidence, ok := s.slashEvidenceByID[op.RecordKey]
		if !ok {
			return
		}
		applyShadowResultToSlashEvidence(&evidence, shadow)
		s.slashEvidenceByID[op.RecordKey] = evidence
	}
}

func (s *MemoryService) clearDeferredOperationLocked(idempotencyKey string) {
	delete(s.deferredAdapterOps, idempotencyKey)
	s.pendingAdapterOps = len(s.deferredAdapterOps)
}

func (s *MemoryService) snapshotDeferredOperations() []deferredAdapterOperation {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]deferredAdapterOperation, 0, len(s.deferredAdapterOps))
	for _, op := range s.deferredAdapterOps {
		out = append(out, op)
	}
	return out
}

func (s *MemoryService) replayDeferredAdapterOperations(ctx context.Context) {
	adapter := s.currentAdapter()
	if adapter == nil {
		return
	}
	shadowAdapter := s.currentShadowAdapter()
	ops := s.snapshotDeferredOperations()
	if len(ops) == 0 {
		return
	}
	sort.Slice(ops, func(i, j int) bool {
		if ops[i].DeferredAt.Equal(ops[j].DeferredAt) {
			return ops[i].IdempotencyKey < ops[j].IdempotencyKey
		}
		return ops[i].DeferredAt.Before(ops[j].DeferredAt)
	})
	for _, op := range ops {
		s.replayDeferredAdapterOperation(ctx, adapter, shadowAdapter, op)
	}
}

func (s *MemoryService) replayDeferredAdapterOperation(ctx context.Context, adapter ChainAdapter, shadowAdapter ChainAdapter, op deferredAdapterOperation) {
	var (
		ref         string
		err         error
		shadowFn    func(context.Context, ChainAdapter) (string, error)
		shadowState shadowSubmissionResult
	)

	switch op.Type {
	case deferredOperationSettlement:
		s.mu.Lock()
		settlement, ok := s.settledBySession[op.RecordKey]
		s.mu.Unlock()
		if !ok {
			return
		}
		shadowFn = func(ctx context.Context, adapter ChainAdapter) (string, error) {
			return adapter.SubmitSessionSettlement(ctx, settlement)
		}
		ref, err = adapter.SubmitSessionSettlement(ctx, settlement)
	case deferredOperationReward:
		s.mu.Lock()
		reward, ok := s.rewardsByID[op.RecordKey]
		s.mu.Unlock()
		if !ok {
			return
		}
		shadowFn = func(ctx context.Context, adapter ChainAdapter) (string, error) {
			return adapter.SubmitRewardIssue(ctx, reward)
		}
		ref, err = adapter.SubmitRewardIssue(ctx, reward)
	case deferredOperationSponsorReservation:
		s.mu.Lock()
		reservation, ok := s.sponsorReservationsByID[op.RecordKey]
		s.mu.Unlock()
		if !ok {
			return
		}
		shadowFn = func(ctx context.Context, adapter ChainAdapter) (string, error) {
			return adapter.SubmitSponsorReservation(ctx, reservation)
		}
		ref, err = adapter.SubmitSponsorReservation(ctx, reservation)
	case deferredOperationSlashEvidence:
		s.mu.Lock()
		evidence, ok := s.slashEvidenceByID[op.RecordKey]
		s.mu.Unlock()
		if !ok {
			return
		}
		shadowFn = func(ctx context.Context, adapter ChainAdapter) (string, error) {
			return adapter.SubmitSlashEvidence(ctx, evidence)
		}
		ref, err = adapter.SubmitSlashEvidence(ctx, evidence)
	default:
		return
	}
	if shadowAdapter != nil && shadowFn != nil {
		shadowState = submitShadowWithAdapter(ctx, shadowAdapter, op.IdempotencyKey, shadowFn)
	}

	if err != nil {
		s.mu.Lock()
		s.applyShadowDeferredOperationLocked(op, shadowState)
		s.applyDeferredOperationStatusLocked(op, OperationStatusFailed, "")
		s.upsertDeferredOperationLocked(op, err)
		s.mu.Unlock()
		return
	}
	if strings.TrimSpace(ref) == "" {
		ref = op.IdempotencyKey
	}
	s.mu.Lock()
	s.applyShadowDeferredOperationLocked(op, shadowState)
	s.applyDeferredOperationStatusLocked(op, OperationStatusSubmitted, ref)
	s.clearDeferredOperationLocked(op.IdempotencyKey)
	s.mu.Unlock()
}

func (s *MemoryService) confirmSubmittedAdapterOperations(ctx context.Context) {
	adapter := s.currentAdapter()
	if adapter == nil {
		return
	}
	confirmer, ok := adapter.(ChainConfirmationQuerier)
	if !ok {
		return
	}

	type settlementSnapshot struct {
		SessionID    string
		SettlementID string
	}
	type rewardSnapshot struct {
		RewardID string
	}
	type sponsorSnapshot struct {
		ReservationID string
	}
	type slashSnapshot struct {
		EvidenceID string
	}

	s.mu.Lock()
	settlements := make([]settlementSnapshot, 0)
	for sessionID, settlement := range s.settledBySession {
		if settlement.Status == OperationStatusSubmitted && strings.TrimSpace(settlement.SettlementID) != "" {
			settlements = append(settlements, settlementSnapshot{
				SessionID:    sessionID,
				SettlementID: settlement.SettlementID,
			})
		}
	}
	rewards := make([]rewardSnapshot, 0)
	for rewardID, reward := range s.rewardsByID {
		if reward.Status == OperationStatusSubmitted {
			rewards = append(rewards, rewardSnapshot{RewardID: rewardID})
		}
	}
	sponsorReservations := make([]sponsorSnapshot, 0)
	for reservationID, reservation := range s.sponsorReservationsByID {
		if reservation.Status == OperationStatusSubmitted {
			sponsorReservations = append(sponsorReservations, sponsorSnapshot{ReservationID: reservationID})
		}
	}
	slashEvidence := make([]slashSnapshot, 0)
	for evidenceID, evidence := range s.slashEvidenceByID {
		if evidence.Status == OperationStatusSubmitted {
			slashEvidence = append(slashEvidence, slashSnapshot{EvidenceID: evidenceID})
		}
	}
	s.mu.Unlock()

	for _, snapshot := range settlements {
		exists, err := confirmer.HasSessionSettlement(ctx, snapshot.SettlementID)
		if err != nil || !exists {
			continue
		}
		s.mu.Lock()
		settlement, ok := s.settledBySession[snapshot.SessionID]
		if ok && settlement.Status == OperationStatusSubmitted {
			settlement.Status = OperationStatusConfirmed
			settlement.AdapterDeferred = false
			settlement.AdapterSubmitted = true
			s.settledBySession[snapshot.SessionID] = settlement
		}
		s.mu.Unlock()
	}
	for _, snapshot := range rewards {
		exists, err := confirmer.HasRewardIssue(ctx, snapshot.RewardID)
		if err != nil || !exists {
			continue
		}
		s.mu.Lock()
		reward, ok := s.rewardsByID[snapshot.RewardID]
		if ok && reward.Status == OperationStatusSubmitted {
			reward.Status = OperationStatusConfirmed
			reward.AdapterDeferred = false
			reward.AdapterSubmitted = true
			s.rewardsByID[snapshot.RewardID] = reward
		}
		s.mu.Unlock()
	}
	for _, snapshot := range sponsorReservations {
		exists, err := confirmer.HasSponsorReservation(ctx, snapshot.ReservationID)
		if err != nil || !exists {
			continue
		}
		s.mu.Lock()
		reservation, ok := s.sponsorReservationsByID[snapshot.ReservationID]
		if ok && reservation.Status == OperationStatusSubmitted {
			reservation.Status = OperationStatusConfirmed
			reservation.AdapterDeferred = false
			reservation.AdapterSubmitted = true
			s.sponsorReservationsByID[snapshot.ReservationID] = reservation
		}
		s.mu.Unlock()
	}
	for _, snapshot := range slashEvidence {
		exists, err := confirmer.HasSlashEvidence(ctx, snapshot.EvidenceID)
		if err != nil || !exists {
			continue
		}
		s.mu.Lock()
		evidence, ok := s.slashEvidenceByID[snapshot.EvidenceID]
		if ok && evidence.Status == OperationStatusSubmitted {
			evidence.Status = OperationStatusConfirmed
			evidence.AdapterDeferred = false
			evidence.AdapterSubmitted = true
			s.slashEvidenceByID[snapshot.EvidenceID] = evidence
		}
		s.mu.Unlock()
	}
}

func (s *MemoryService) applyDeferredOperationStatusLocked(op deferredAdapterOperation, status OperationStatus, referenceID string) {
	isSubmitted := status == OperationStatusSubmitted
	isDeferred := !isSubmitted
	switch op.Type {
	case deferredOperationSettlement:
		settlement, ok := s.settledBySession[op.RecordKey]
		if !ok {
			return
		}
		settlement.Status = status
		settlement.AdapterDeferred = isDeferred
		settlement.AdapterSubmitted = isSubmitted
		if referenceID != "" {
			settlement.AdapterReferenceID = referenceID
		}
		s.settledBySession[op.RecordKey] = settlement
	case deferredOperationReward:
		reward, ok := s.rewardsByID[op.RecordKey]
		if !ok {
			return
		}
		reward.Status = status
		reward.AdapterDeferred = isDeferred
		reward.AdapterSubmitted = isSubmitted
		if referenceID != "" {
			reward.AdapterReferenceID = referenceID
		}
		s.rewardsByID[op.RecordKey] = reward
	case deferredOperationSponsorReservation:
		reservation, ok := s.sponsorReservationsByID[op.RecordKey]
		if !ok {
			return
		}
		reservation.Status = status
		reservation.AdapterDeferred = isDeferred
		reservation.AdapterSubmitted = isSubmitted
		if referenceID != "" {
			reservation.AdapterReferenceID = referenceID
		}
		s.sponsorReservationsByID[op.RecordKey] = reservation
	case deferredOperationSlashEvidence:
		evidence, ok := s.slashEvidenceByID[op.RecordKey]
		if !ok {
			return
		}
		evidence.Status = status
		evidence.AdapterDeferred = isDeferred
		evidence.AdapterSubmitted = isSubmitted
		if referenceID != "" {
			evidence.AdapterReferenceID = referenceID
		}
		s.slashEvidenceByID[op.RecordKey] = evidence
	}
}

func priceMicrosForBytes(bytes int64, pricePerMiBMicros int64) int64 {
	if bytes <= 0 {
		return 0
	}
	const mebibyte = int64(1024 * 1024)
	return (bytes * pricePerMiBMicros) / mebibyte
}

func normalizeCurrencyCode(raw string) string {
	return strings.ToUpper(strings.TrimSpace(raw))
}

func (s *MemoryService) ensureSupportedCurrencyLocked(currency string) error {
	if _, ok := s.currencyRates[currency]; ok {
		return nil
	}
	return fmt.Errorf("unsupported settlement currency: %s", currency)
}

func (s *MemoryService) convertFromBaseMicrosLocked(amount int64, currency string) (int64, error) {
	rate, ok := s.currencyRates[currency]
	if !ok {
		return 0, fmt.Errorf("unsupported settlement currency: %s", currency)
	}
	return convertMicrosByRate(amount, rate)
}

func convertMicrosByRate(amount int64, rate currencyRate) (int64, error) {
	if amount < 0 {
		return 0, fmt.Errorf("amount must be >= 0")
	}
	if rate.Numerator <= 0 || rate.Denominator <= 0 {
		return 0, fmt.Errorf("invalid currency rate")
	}
	if amount == 0 {
		return 0, nil
	}
	if amount > math.MaxInt64/rate.Numerator {
		return 0, fmt.Errorf("currency conversion overflow")
	}
	converted := (amount * rate.Numerator) / rate.Denominator
	if converted < 0 {
		return 0, fmt.Errorf("currency conversion overflow")
	}
	return converted, nil
}

func isObjectiveViolationType(violationType string) bool {
	_, ok := supportedObjectiveViolationTypes[strings.ToLower(strings.TrimSpace(violationType))]
	return ok
}

func isObjectiveEvidenceRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	return strings.HasPrefix(ref, "obj://") || strings.HasPrefix(ref, "sha256:")
}

func (s *MemoryService) dumpSettledSessionIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.settledBySession))
	for id := range s.settledBySession {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
