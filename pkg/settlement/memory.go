package settlement

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	urlpkg "net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	defaultPricePerMiBMicros    = int64(1000)
	defaultCurrency             = "TDPNC"
	defaultSponsorReservationTT = 5 * time.Minute
	weeklyRewardPayoutPeriod    = 7 * 24 * time.Hour
)

type currencyRate struct {
	Numerator   int64
	Denominator int64
}

var (
	supportedObjectiveViolationTypes = map[string]struct{}{
		"double-sign":              {},
		"downtime-proof":           {},
		"invalid-settlement-proof": {},
		"session-replay-proof":     {},
		"sponsor-overdraft-proof":  {},
	}
	errChainAdapterNotConfigured = errors.New("chain adapter not configured")
)

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

type rewardPayoutKey struct {
	ProviderSubjectID string
	PeriodStart       string
	PeriodEnd         string
}

type settlementInFlight struct {
	done       chan struct{}
	settlement SessionSettlement
	err        error
}

type fundReservationInFlight struct {
	done        chan struct{}
	reservation FundReservation
	err         error
}

func (op *settlementInFlight) wait(ctx context.Context) (SessionSettlement, error) {
	select {
	case <-op.done:
		if op.err != nil {
			return SessionSettlement{}, op.err
		}
		settlement := op.settlement
		settlement.IdempotentReplay = true
		return settlement, nil
	case <-ctx.Done():
		return SessionSettlement{}, ctx.Err()
	}
}

func (op *fundReservationInFlight) wait(ctx context.Context) (FundReservation, error) {
	select {
	case <-op.done:
		if op.err != nil {
			return FundReservation{}, op.err
		}
		reservation := op.reservation
		reservation.IdempotentReplay = true
		return reservation, nil
	case <-ctx.Done():
		return FundReservation{}, ctx.Err()
	}
}

type MemoryService struct {
	mu sync.Mutex

	usageBySession                  map[string][]UsageRecord
	reservationsBySession           map[string]FundReservation
	reservationSessionByID          map[string]string
	settlementReservationsBySession map[string]FundReservation
	reservationsInFlight            map[string]*fundReservationInFlight
	settledBySession                map[string]SessionSettlement
	settlementsInFlight             map[string]*settlementInFlight
	rewardsByID                     map[string]RewardIssue
	weeklyRewardPayoutByKey         map[rewardPayoutKey]string
	sponsorReservationsByID         map[string]SponsorCreditReservation
	paymentAuthByReservationID      map[string]PaymentAuthorization
	slashEvidenceByID               map[string]SlashEvidence
	deferredAdapterOps              map[string]deferredAdapterOperation

	pricePerMiBMicros   int64
	currency            string
	currencyRates       map[string]currencyRate
	adapter             ChainAdapter
	shadowAdapter       ChainAdapter
	rewardProofVerifier RewardProofVerifier
	blockchainMode      bool

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

func WithRewardProofVerifier(verifier RewardProofVerifier) MemoryOption {
	return func(s *MemoryService) {
		s.rewardProofVerifier = verifier
	}
}

// WithBlockchainMode enables chain-backed settlement semantics. In this mode,
// missing primary adapter writes fail closed as deferred/pending operations.
func WithBlockchainMode(enabled bool) MemoryOption {
	return func(s *MemoryService) {
		s.blockchainMode = enabled
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
		usageBySession:                  map[string][]UsageRecord{},
		reservationsBySession:           map[string]FundReservation{},
		reservationSessionByID:          map[string]string{},
		settlementReservationsBySession: map[string]FundReservation{},
		reservationsInFlight:            map[string]*fundReservationInFlight{},
		settledBySession:                map[string]SessionSettlement{},
		settlementsInFlight:             map[string]*settlementInFlight{},
		rewardsByID:                     map[string]RewardIssue{},
		weeklyRewardPayoutByKey:         map[rewardPayoutKey]string{},
		sponsorReservationsByID:         map[string]SponsorCreditReservation{},
		paymentAuthByReservationID:      map[string]PaymentAuthorization{},
		slashEvidenceByID:               map[string]SlashEvidence{},
		deferredAdapterOps:              map[string]deferredAdapterOperation{},
		pricePerMiBMicros:               defaultPricePerMiBMicros,
		currency:                        defaultCurrency,
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
	if err := s.ensureSessionSubjectConsistencyLocked(usage.SessionID, usage.SubjectID); err != nil {
		return err
	}
	if _, settled := s.settledBySession[usage.SessionID]; settled {
		return sessionAlreadySettledError(usage.SessionID)
	}
	if _, settling := s.settlementsInFlight[usage.SessionID]; settling {
		return fmt.Errorf("session settlement in progress for session %s", usage.SessionID)
	}
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

func (s *MemoryService) ReserveFunds(ctx context.Context, reservation FundReservation) (FundReservation, error) {
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
	if err := s.ensureSessionSubjectConsistencyLocked(reservation.SessionID, reservation.SubjectID); err != nil {
		s.mu.Unlock()
		return FundReservation{}, err
	}
	if _, settled := s.settledBySession[reservation.SessionID]; settled {
		s.mu.Unlock()
		return FundReservation{}, sessionAlreadySettledError(reservation.SessionID)
	}
	if reservation.Currency == "" {
		reservation.Currency = s.currency
	}
	if err := s.ensureSupportedCurrencyLocked(reservation.Currency); err != nil {
		s.mu.Unlock()
		return FundReservation{}, err
	}
	reservation.ReservationID = strings.TrimSpace(reservation.ReservationID)
	if reservation.ReservationID == "" {
		reservation.ReservationID = "res-" + reservation.SessionID
	}
	if existing, ok := s.reservationsBySession[reservation.SessionID]; ok {
		if !fundReservationMaterialMatches(existing, reservation) {
			s.mu.Unlock()
			return FundReservation{}, idempotencyConflictError("fund reservation", reservation.SessionID)
		}
		if s.reservationSessionByID == nil {
			s.reservationSessionByID = map[string]string{}
		}
		s.reservationSessionByID[reservation.ReservationID] = reservation.SessionID
		existing.IdempotentReplay = true
		s.mu.Unlock()
		return existing, nil
	}
	if reservation.CreatedAt.IsZero() {
		reservation.CreatedAt = time.Now().UTC()
	}
	if s.reservationsInFlight == nil {
		s.reservationsInFlight = map[string]*fundReservationInFlight{}
	}
	if s.reservationSessionByID == nil {
		s.reservationSessionByID = map[string]string{}
	}
	if ownerSessionID, ok := s.reservationSessionByID[reservation.ReservationID]; ok && ownerSessionID != reservation.SessionID {
		s.mu.Unlock()
		return FundReservation{}, idempotencyConflictError("fund reservation", reservation.ReservationID)
	}
	if op, ok := s.reservationsInFlight[reservation.SessionID]; ok {
		if !fundReservationMaterialMatches(op.reservation, reservation) {
			s.mu.Unlock()
			return FundReservation{}, idempotencyConflictError("fund reservation", reservation.SessionID)
		}
		s.mu.Unlock()
		return op.wait(ctx)
	}
	op := &fundReservationInFlight{done: make(chan struct{}), reservation: reservation}
	s.reservationsInFlight[reservation.SessionID] = op
	s.reservationSessionByID[reservation.ReservationID] = reservation.SessionID
	blockchainMode := s.blockchainMode
	adapter := s.adapter
	s.mu.Unlock()

	finish := func(result FundReservation, err error) (FundReservation, error) {
		s.mu.Lock()
		if err == nil {
			if existing, ok := s.reservationsBySession[reservation.SessionID]; ok {
				result = existing
				result.IdempotentReplay = true
			} else if _, settled := s.settledBySession[reservation.SessionID]; settled {
				err = sessionAlreadySettledError(reservation.SessionID)
			} else {
				s.reservationsBySession[reservation.SessionID] = result
			}
		}
		delete(s.reservationsInFlight, reservation.SessionID)
		if err != nil {
			if ownerSessionID, ok := s.reservationSessionByID[reservation.ReservationID]; ok && ownerSessionID == reservation.SessionID {
				delete(s.reservationSessionByID, reservation.ReservationID)
			}
		}
		op.reservation = result
		op.err = err
		close(op.done)
		s.mu.Unlock()
		return result, err
	}

	submittedToChain, err := submitFundReservationAdapter(ctx, blockchainMode, adapter, reservation)
	if err != nil {
		return finish(FundReservation{}, err)
	}
	if submittedToChain {
		reservation.Status = OperationStatusSubmitted
	} else if reservation.Status == "" {
		reservation.Status = OperationStatusConfirmed
	}

	return finish(reservation, nil)
}

// FundReservationStatus exposes a bounded one-hop chain status view for callers
// that receive MemoryService as the production settlement wrapper.
func (s *MemoryService) FundReservationStatus(ctx context.Context, reservationID string) (OperationStatus, bool, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return "", false, fmt.Errorf("reservation id required")
	}

	adapter := s.currentAdapter()
	if querier, ok := adapter.(ChainFundReservationStatusQuerier); ok && querier != nil {
		status, found, err := querier.FundReservationStatus(ctx, reservationID)
		if err != nil || !found || status == "" {
			return status, found, err
		}
		s.mu.Lock()
		if sessionID, ok := s.reservationSessionByID[reservationID]; ok {
			if reservation, ok := s.reservationsBySession[sessionID]; ok {
				reservation.Status = status
				s.reservationsBySession[sessionID] = reservation
			}
		}
		s.mu.Unlock()
		return status, found, nil
	}

	if s.blockchainModeEnabled() {
		return "", false, fmt.Errorf("fund reservation chain status querier not configured")
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	sessionID, ok := s.reservationSessionByID[reservationID]
	if !ok {
		return "", false, nil
	}
	reservation, ok := s.reservationsBySession[sessionID]
	if !ok {
		return "", false, nil
	}
	return reservation.Status, true, nil
}

func (s *MemoryService) FundReservation(ctx context.Context, reservationID string) (FundReservation, bool, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return FundReservation{}, false, fmt.Errorf("reservation id required")
	}

	adapter := s.currentAdapter()
	if querier, ok := adapter.(FundReservationQuerier); ok && querier != nil {
		reservation, found, err := querier.FundReservation(ctx, reservationID)
		if err != nil || !found {
			return reservation, found, err
		}
		s.mu.Lock()
		if s.reservationSessionByID == nil {
			s.reservationSessionByID = map[string]string{}
		}
		if s.reservationsBySession == nil {
			s.reservationsBySession = map[string]FundReservation{}
		}
		if sessionID := strings.TrimSpace(reservation.SessionID); sessionID != "" {
			s.reservationSessionByID[reservationID] = sessionID
			if existing, ok := s.reservationsBySession[sessionID]; !ok || strings.TrimSpace(existing.ReservationID) == reservationID {
				s.reservationsBySession[sessionID] = reservation
			}
		}
		s.mu.Unlock()
		return reservation, true, nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	sessionID, ok := s.reservationSessionByID[reservationID]
	if !ok {
		return FundReservation{}, false, nil
	}
	reservation, ok := s.reservationsBySession[sessionID]
	if !ok {
		return FundReservation{}, false, nil
	}
	return reservation, true, nil
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
	currency := s.currency
	currencyRates := s.currencyRates
	if reservation.Currency == "" {
		reservation.Currency = currency
	}
	if existing, ok := s.sponsorReservationsByID[reservation.ReservationID]; ok {
		if reservation.CreatedAt.IsZero() {
			reservation.CreatedAt = existing.CreatedAt
		}
		if reservation.ExpiresAt.IsZero() {
			reservation.ExpiresAt = existing.ExpiresAt
		}
		if !sponsorReservationMaterialEqual(existing, reservation) {
			s.mu.Unlock()
			return SponsorCreditReservation{}, idempotencyConflictError("sponsor reservation", reservation.ReservationID)
		}
		existing.IdempotentReplay = true
		s.mu.Unlock()
		return existing, nil
	}
	if reservation.SessionID != "" {
		if err := s.ensureSessionSubjectConsistencyLocked(reservation.SessionID, reservation.SubjectID); err != nil {
			s.mu.Unlock()
			return SponsorCreditReservation{}, err
		}
	}
	if _, ok := currencyRates[reservation.Currency]; !ok {
		s.mu.Unlock()
		return SponsorCreditReservation{}, fmt.Errorf("unsupported settlement currency: %s", reservation.Currency)
	}
	if reservation.CreatedAt.IsZero() {
		reservation.CreatedAt = time.Now().UTC()
	}
	if reservation.ExpiresAt.IsZero() {
		reservation.ExpiresAt = reservation.CreatedAt.Add(defaultSponsorReservationTT)
	}
	reservation.Status = OperationStatusPending
	s.sponsorReservationsByID[reservation.ReservationID] = reservation
	s.mu.Unlock()

	reservation.Status = OperationStatusConfirmed

	s.submitSponsorReservationAdapter(ctx, &reservation)

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.sponsorReservationsByID[reservation.ReservationID]; ok && existing.Status == OperationStatusPending && sponsorReservationMaterialEqual(existing, reservation) {
		s.sponsorReservationsByID[reservation.ReservationID] = reservation
	}
	return reservation, nil
}

func (s *MemoryService) GetSponsorReservation(ctx context.Context, reservationID string) (SponsorCreditReservation, error) {
	reservationID = strings.TrimSpace(reservationID)
	if reservationID == "" {
		return SponsorCreditReservation{}, fmt.Errorf("reservation_id required")
	}
	s.mu.Lock()
	reservation, ok := s.sponsorReservationsByID[reservationID]
	s.mu.Unlock()
	if ok {
		return reservation, nil
	}
	if reservation, found, err := s.sponsorReservationFromAdapter(ctx, reservationID); err != nil || found {
		if err != nil {
			return SponsorCreditReservation{}, err
		}
		return reservation, nil
	}
	if s.blockchainModeEnabled() {
		return SponsorCreditReservation{}, fmt.Errorf("sponsor reservation not found on chain: %s", reservationID)
	}
	return SponsorCreditReservation{}, fmt.Errorf("reservation not found: %s", reservationID)
}

func (s *MemoryService) AuthorizePayment(ctx context.Context, proof PaymentProof) (PaymentAuthorization, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	proof.Source = strings.TrimSpace(proof.Source)
	proof.ReservationID = strings.TrimSpace(proof.ReservationID)
	proof.SponsorID = strings.TrimSpace(proof.SponsorID)
	proof.SubjectID = strings.TrimSpace(proof.SubjectID)
	proof.SessionID = strings.TrimSpace(proof.SessionID)
	if proof.Source == "" {
		proof.Source = PaymentProofSourceSponsor
	}
	if proof.ReservationID == "" {
		return PaymentAuthorization{}, fmt.Errorf("authorize payment requires reservation_id")
	}
	if proof.SubjectID == "" {
		return PaymentAuthorization{}, fmt.Errorf("authorize payment requires subject_id")
	}
	switch proof.Source {
	case PaymentProofSourceSponsor:
		return s.authorizeSponsorPayment(ctx, proof)
	case PaymentProofSourceWalletFund:
		return s.authorizeWalletFundPayment(ctx, proof)
	default:
		return PaymentAuthorization{}, fmt.Errorf("unsupported payment proof source: %s", proof.Source)
	}
}

func paymentAuthorizationMapKey(source, reservationID string) string {
	source = strings.TrimSpace(source)
	reservationID = strings.TrimSpace(reservationID)
	if source == "" {
		source = PaymentProofSourceSponsor
	}
	return fmt.Sprintf(
		"v2:%s:%s",
		base64.RawURLEncoding.EncodeToString([]byte(source)),
		base64.RawURLEncoding.EncodeToString([]byte(reservationID)),
	)
}

func validatePaymentAuthorizationReplay(proof PaymentProof, existing PaymentAuthorization) error {
	if existing.Source != "" && proof.Source != existing.Source {
		return fmt.Errorf("reservation source mismatch")
	}
	if proof.SponsorID != existing.SponsorID {
		return fmt.Errorf("reservation sponsor mismatch")
	}
	if proof.SubjectID != existing.SubjectID {
		return fmt.Errorf("reservation subject mismatch")
	}
	if existing.SessionID != "" {
		if proof.SessionID == "" {
			return fmt.Errorf("authorize payment requires session_id")
		}
		if proof.SessionID != existing.SessionID {
			return fmt.Errorf("reservation session mismatch")
		}
	} else if proof.SessionID != "" {
		return fmt.Errorf("reservation session mismatch")
	}
	return nil
}

func (s *MemoryService) authorizeSponsorPayment(ctx context.Context, proof PaymentProof) (PaymentAuthorization, error) {
	if proof.SponsorID == "" {
		return PaymentAuthorization{}, fmt.Errorf("authorize payment requires sponsor_id")
	}

	now := time.Now().UTC()
	authKey := paymentAuthorizationMapKey(proof.Source, proof.ReservationID)
	s.mu.Lock()
	if existing, ok := s.paymentAuthByReservationID[authKey]; ok {
		if err := validatePaymentAuthorizationReplay(proof, existing); err != nil {
			s.mu.Unlock()
			return PaymentAuthorization{}, err
		}
		existing.IdempotentReplay = true
		s.mu.Unlock()
		return existing, nil
	}
	reservation, ok := s.sponsorReservationsByID[proof.ReservationID]
	blockchainMode := s.blockchainMode
	s.mu.Unlock()
	if blockchainMode {
		chainReservation, err := s.confirmedSponsorReservationForPayment(ctx, reservation, ok, proof.ReservationID)
		if err != nil {
			return PaymentAuthorization{}, err
		}
		reservation = chainReservation
		ok = true
	}
	if !ok {
		return PaymentAuthorization{}, fmt.Errorf("reservation not found: %s", proof.ReservationID)
	}
	var materialErr error
	reservation, materialErr = validateSponsorPaymentReservationMaterial(reservation, proof.ReservationID)
	if materialErr != nil {
		return PaymentAuthorization{}, materialErr
	}
	if !reservation.ExpiresAt.IsZero() && now.After(reservation.ExpiresAt) {
		return PaymentAuthorization{}, fmt.Errorf("reservation expired: %s", proof.ReservationID)
	}
	if !reservation.ConsumedAt.IsZero() {
		return PaymentAuthorization{}, fmt.Errorf("reservation already consumed: %s", proof.ReservationID)
	}
	if proof.SponsorID != reservation.SponsorID {
		return PaymentAuthorization{}, fmt.Errorf("reservation sponsor mismatch")
	}
	if proof.SubjectID != reservation.SubjectID {
		return PaymentAuthorization{}, fmt.Errorf("reservation subject mismatch")
	}
	if reservation.SessionID != "" {
		if proof.SessionID == "" {
			return PaymentAuthorization{}, fmt.Errorf("authorize payment requires session_id")
		}
		if proof.SessionID != reservation.SessionID {
			return PaymentAuthorization{}, fmt.Errorf("reservation session mismatch")
		}
	} else if proof.SessionID != "" {
		return PaymentAuthorization{}, fmt.Errorf("reservation session mismatch")
	}
	if blockchainMode {
		if reservation.Status == OperationStatusPending {
			return PaymentAuthorization{}, fmt.Errorf("reservation pending chain submission: %s", proof.ReservationID)
		}
		if reservation.Status != OperationStatusConfirmed {
			return PaymentAuthorization{}, fmt.Errorf("reservation not chain-finalized: %s", proof.ReservationID)
		}
	}

	auth := PaymentAuthorization{
		Source:           PaymentProofSourceSponsor,
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sponsorReservationsByID == nil {
		s.sponsorReservationsByID = map[string]SponsorCreditReservation{}
	}
	if s.paymentAuthByReservationID == nil {
		s.paymentAuthByReservationID = map[string]PaymentAuthorization{}
	}
	if existing, ok := s.paymentAuthByReservationID[authKey]; ok {
		if err := validatePaymentAuthorizationReplay(proof, existing); err != nil {
			return PaymentAuthorization{}, err
		}
		existing.IdempotentReplay = true
		return existing, nil
	}
	s.sponsorReservationsByID[reservation.ReservationID] = reservation
	s.paymentAuthByReservationID[authKey] = auth
	return auth, nil
}

func (s *MemoryService) authorizeWalletFundPayment(ctx context.Context, proof PaymentProof) (PaymentAuthorization, error) {
	if proof.SponsorID != "" {
		return PaymentAuthorization{}, fmt.Errorf("wallet fund payment proof must not include sponsor_id")
	}
	if proof.SessionID == "" {
		return PaymentAuthorization{}, fmt.Errorf("authorize payment requires session_id")
	}

	now := time.Now().UTC()
	authKey := paymentAuthorizationMapKey(proof.Source, proof.ReservationID)
	s.mu.Lock()
	if existing, ok := s.paymentAuthByReservationID[authKey]; ok {
		if err := validatePaymentAuthorizationReplay(proof, existing); err != nil {
			s.mu.Unlock()
			return PaymentAuthorization{}, err
		}
		existing.IdempotentReplay = true
		s.mu.Unlock()
		return existing, nil
	}
	blockchainMode := s.blockchainMode
	adapter := s.adapter
	s.mu.Unlock()

	var reservation FundReservation
	var found bool
	var err error
	if blockchainMode {
		querier, ok := adapter.(FundReservationQuerier)
		if !ok || querier == nil {
			return PaymentAuthorization{}, fmt.Errorf("wallet fund payment proof requires chain fund reservation material query for reservation %s", proof.ReservationID)
		}
		reservation, found, err = querier.FundReservation(ctx, proof.ReservationID)
		if err != nil {
			return PaymentAuthorization{}, fmt.Errorf("wallet fund reservation material check failed for %s: %w", proof.ReservationID, err)
		}
	} else {
		reservation, found, err = s.FundReservation(ctx, proof.ReservationID)
		if err != nil {
			return PaymentAuthorization{}, err
		}
	}
	if !found {
		return PaymentAuthorization{}, fmt.Errorf("fund reservation not found: %s", proof.ReservationID)
	}

	reservation.ReservationID = strings.TrimSpace(reservation.ReservationID)
	reservation.SessionID = strings.TrimSpace(reservation.SessionID)
	reservation.SubjectID = strings.TrimSpace(reservation.SubjectID)
	reservation.Currency = normalizeCurrencyCode(reservation.Currency)
	if reservation.ReservationID == "" {
		reservation.ReservationID = proof.ReservationID
	}
	if reservation.ReservationID != proof.ReservationID {
		return PaymentAuthorization{}, fmt.Errorf("fund reservation id mismatch")
	}
	if reservation.SubjectID == "" {
		return PaymentAuthorization{}, fmt.Errorf("fund reservation missing subject_id")
	}
	if reservation.SessionID == "" {
		return PaymentAuthorization{}, fmt.Errorf("fund reservation missing session_id")
	}
	if reservation.AmountMicros <= 0 {
		return PaymentAuthorization{}, fmt.Errorf("fund reservation amount invalid")
	}
	if reservation.Currency == "" {
		return PaymentAuthorization{}, fmt.Errorf("fund reservation missing currency")
	}
	if proof.SubjectID != reservation.SubjectID {
		return PaymentAuthorization{}, fmt.Errorf("reservation subject mismatch")
	}
	if proof.SessionID != reservation.SessionID {
		return PaymentAuthorization{}, fmt.Errorf("reservation session mismatch")
	}
	if reservation.Status == "" && !blockchainMode {
		reservation.Status = OperationStatusConfirmed
	}
	if reservation.Status == OperationStatusPending || reservation.Status == OperationStatusSubmitted {
		return PaymentAuthorization{}, fmt.Errorf("reservation pending chain submission: %s", proof.ReservationID)
	}
	if reservation.Status != OperationStatusConfirmed {
		return PaymentAuthorization{}, fmt.Errorf("reservation not chain-finalized: %s", proof.ReservationID)
	}

	auth := PaymentAuthorization{
		Source:           PaymentProofSourceWalletFund,
		ReservationID:    reservation.ReservationID,
		SubjectID:        reservation.SubjectID,
		SessionID:        reservation.SessionID,
		AuthorizedMicros: reservation.AmountMicros,
		Currency:         reservation.Currency,
		AuthorizedAt:     now,
		Status:           OperationStatusConfirmed,
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.paymentAuthByReservationID == nil {
		s.paymentAuthByReservationID = map[string]PaymentAuthorization{}
	}
	if existing, ok := s.paymentAuthByReservationID[authKey]; ok {
		if err := validatePaymentAuthorizationReplay(proof, existing); err != nil {
			return PaymentAuthorization{}, err
		}
		existing.IdempotentReplay = true
		return existing, nil
	}
	if s.reservationSessionByID == nil {
		s.reservationSessionByID = map[string]string{}
	}
	if s.reservationsBySession == nil {
		s.reservationsBySession = map[string]FundReservation{}
	}
	s.reservationSessionByID[reservation.ReservationID] = reservation.SessionID
	s.reservationsBySession[reservation.SessionID] = reservation
	s.paymentAuthByReservationID[authKey] = auth
	return auth, nil
}

func (s *MemoryService) sponsorReservationFromAdapter(ctx context.Context, reservationID string) (SponsorCreditReservation, bool, error) {
	reservation, found, err := s.querySponsorReservationFromAdapter(ctx, reservationID)
	if err != nil || !found {
		return reservation, found, err
	}
	s.mu.Lock()
	if s.sponsorReservationsByID == nil {
		s.sponsorReservationsByID = map[string]SponsorCreditReservation{}
	}
	s.sponsorReservationsByID[reservationID] = reservation
	s.mu.Unlock()
	return reservation, true, nil
}

func (s *MemoryService) querySponsorReservationFromAdapter(ctx context.Context, reservationID string) (SponsorCreditReservation, bool, error) {
	adapter := s.currentAdapter()
	querier, ok := adapter.(SponsorReservationQuerier)
	if !ok || querier == nil {
		if s.blockchainModeEnabled() {
			return SponsorCreditReservation{}, false, fmt.Errorf("sponsor reservation chain material querier not configured")
		}
		return SponsorCreditReservation{}, false, nil
	}
	reservation, found, err := querier.SponsorReservation(ctx, reservationID)
	if err != nil || !found {
		return reservation, found, err
	}
	reservation, err = validateSponsorPaymentReservationMaterial(reservation, reservationID)
	if err != nil {
		return SponsorCreditReservation{}, false, err
	}
	return reservation, true, nil
}

func (s *MemoryService) confirmedSponsorReservationForPayment(ctx context.Context, local SponsorCreditReservation, localFound bool, reservationID string) (SponsorCreditReservation, error) {
	chainReservation, found, err := s.querySponsorReservationFromAdapter(ctx, reservationID)
	if err != nil {
		return SponsorCreditReservation{}, fmt.Errorf("reservation chain material query failed: %w", err)
	}
	if !found {
		return SponsorCreditReservation{}, fmt.Errorf("reservation not found on chain: %s", reservationID)
	}
	if chainReservation.Status != OperationStatusConfirmed {
		return SponsorCreditReservation{}, fmt.Errorf("reservation not chain-finalized: %s", reservationID)
	}
	if chainReservation.ExpiresAt.IsZero() {
		return SponsorCreditReservation{}, fmt.Errorf("reservation chain material missing expires_at: %s", reservationID)
	}
	if !chainReservation.ConsumedAt.IsZero() {
		return SponsorCreditReservation{}, fmt.Errorf("reservation already consumed on chain: %s", reservationID)
	}
	if localFound && !sponsorReservationChainMaterialEqual(local, chainReservation) {
		return SponsorCreditReservation{}, fmt.Errorf("reservation chain material mismatch for %s", reservationID)
	}
	return chainReservation, nil
}

func validateSponsorPaymentReservationMaterial(reservation SponsorCreditReservation, requestedReservationID string) (SponsorCreditReservation, error) {
	requestedReservationID = strings.TrimSpace(requestedReservationID)
	reservation.ReservationID = strings.TrimSpace(reservation.ReservationID)
	reservation.SponsorID = strings.TrimSpace(reservation.SponsorID)
	reservation.SubjectID = strings.TrimSpace(reservation.SubjectID)
	reservation.SessionID = strings.TrimSpace(reservation.SessionID)
	reservation.Currency = normalizeCurrencyCode(reservation.Currency)
	if requestedReservationID == "" {
		return SponsorCreditReservation{}, fmt.Errorf("reservation_id required")
	}
	if reservation.ReservationID == "" {
		reservation.ReservationID = requestedReservationID
	}
	if reservation.ReservationID != requestedReservationID {
		return SponsorCreditReservation{}, fmt.Errorf("reservation chain material id mismatch: requested=%s got=%s", requestedReservationID, reservation.ReservationID)
	}
	if reservation.SponsorID == "" || reservation.SubjectID == "" {
		return SponsorCreditReservation{}, fmt.Errorf("reservation chain material missing sponsor_id or subject_id: %s", requestedReservationID)
	}
	if reservation.AmountMicros <= 0 {
		return SponsorCreditReservation{}, fmt.Errorf("reservation chain material requires amount_micros > 0: %s", requestedReservationID)
	}
	if reservation.Currency == "" {
		return SponsorCreditReservation{}, fmt.Errorf("reservation chain material missing currency: %s", requestedReservationID)
	}
	return reservation, nil
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
	if op, ok := s.reservationsInFlight[sessionID]; ok {
		s.mu.Unlock()
		if _, err := op.wait(ctx); err != nil {
			return SessionSettlement{}, err
		}
		return s.SettleSession(ctx, sessionID)
	}
	if s.settlementsInFlight == nil {
		s.settlementsInFlight = map[string]*settlementInFlight{}
	}
	if op, ok := s.settlementsInFlight[sessionID]; ok {
		s.mu.Unlock()
		return op.wait(ctx)
	}
	op := &settlementInFlight{done: make(chan struct{})}
	s.settlementsInFlight[sessionID] = op
	records := append([]UsageRecord(nil), s.usageBySession[sessionID]...)
	reservation, hasReservation := s.reservationsBySession[sessionID]
	price := s.pricePerMiBMicros
	currency := normalizeCurrencyCode(reservation.Currency)
	if currency == "" {
		currency = s.currency
	}
	rate, hasRate := s.currencyRates[currency]
	blockchainMode := s.blockchainMode
	s.mu.Unlock()
	finish := func(settlement SessionSettlement, err error) (SessionSettlement, error) {
		s.mu.Lock()
		if err == nil {
			if existing, ok := s.settledBySession[sessionID]; ok {
				settlement = existing
				settlement.IdempotentReplay = true
			} else {
				if s.settlementReservationsBySession == nil {
					s.settlementReservationsBySession = map[string]FundReservation{}
				}
				s.settlementReservationsBySession[sessionID] = reservation
				s.settledBySession[sessionID] = settlement
				delete(s.reservationsBySession, sessionID)
			}
		}
		delete(s.settlementsInFlight, sessionID)
		op.settlement = settlement
		op.err = err
		close(op.done)
		s.mu.Unlock()
		return settlement, err
	}

	if len(records) == 0 {
		return finish(SessionSettlement{}, fmt.Errorf("settle session requires recorded usage for session %s", sessionID))
	}
	if !hasReservation {
		return finish(SessionSettlement{}, fmt.Errorf("settle session requires reservation for session %s", sessionID))
	}

	subjectID := strings.TrimSpace(reservation.SubjectID)
	if subjectID == "" {
		return finish(SessionSettlement{}, fmt.Errorf("settle session requires reservation subject for session %s", sessionID))
	}
	if err := ensureUsageRecordsSubject(sessionID, subjectID, records); err != nil {
		return finish(SessionSettlement{}, err)
	}
	if blockchainMode {
		confirmedReservation, err := s.confirmedFundReservationForSettlement(ctx, reservation)
		if err != nil {
			return finish(SessionSettlement{}, err)
		}
		reservation = confirmedReservation
	}
	totalBytes := int64(0)
	for _, rec := range records {
		recordBytes, err := checkedAddInt64(rec.BytesIngress, rec.BytesEgress)
		if err != nil {
			return finish(SessionSettlement{}, fmt.Errorf("usage byte counters overflow for session %s", sessionID))
		}
		totalBytes, err = checkedAddInt64(totalBytes, recordBytes)
		if err != nil {
			return finish(SessionSettlement{}, fmt.Errorf("usage byte counters overflow for session %s", sessionID))
		}
	}
	chargeBase, err := priceMicrosForBytes(totalBytes, price)
	if err != nil {
		return finish(SessionSettlement{}, err)
	}
	if !hasRate {
		return finish(SessionSettlement{}, fmt.Errorf("unsupported settlement currency: %s", currency))
	}
	charge, err := convertMicrosByRate(chargeBase, rate)
	if err != nil {
		return finish(SessionSettlement{}, err)
	}
	if charge > reservation.AmountMicros {
		return finish(SessionSettlement{}, fmt.Errorf("reserved funds insufficient for settlement session=%s reserved=%d required=%d",
			sessionID, reservation.AmountMicros, charge))
	}

	settlement := SessionSettlement{
		SettlementID:  "set-" + sessionID,
		ReservationID: reservation.ReservationID,
		SessionID:     sessionID,
		SubjectID:     subjectID,
		ChargedMicros: charge,
		Currency:      currency,
		SettledAt:     time.Now().UTC(),
		Status:        OperationStatusConfirmed,
	}

	s.submitSettlementAdapter(ctx, &settlement)
	if blockchainMode && settlement.AdapterDeferred {
		s.mu.Lock()
		s.clearDeferredOperationLocked(cosmosID("settlement", settlement.SettlementID, settlement.SessionID))
		s.mu.Unlock()
		return finish(SessionSettlement{}, fmt.Errorf("settle session chain settlement submit deferred for session %s: %s", sessionID, settlement.AdapterReferenceID))
	}

	return finish(settlement, nil)
}

func (s *MemoryService) IssueReward(ctx context.Context, reward RewardIssue) (RewardIssue, error) {
	reward.RewardID = strings.TrimSpace(reward.RewardID)
	reward.ProviderSubjectID = strings.TrimSpace(reward.ProviderSubjectID)
	reward.SessionID = strings.TrimSpace(reward.SessionID)
	reward.SettlementReferenceID = strings.TrimSpace(reward.SettlementReferenceID)
	reward.TrafficProofRef = canonicalObjectiveEvidenceRef(reward.TrafficProofRef)
	reward.TrafficProofVerified = false
	reward.TrafficProofVerifierID = ""
	reward.TrafficProofVerifiedAt = time.Time{}
	reward.TrafficProofTrustContract = ""
	reward.Currency = normalizeCurrencyCode(reward.Currency)
	if reward.RewardID == "" || reward.ProviderSubjectID == "" || reward.SessionID == "" {
		return RewardIssue{}, fmt.Errorf("issue reward requires reward_id, provider_subject_id, and session_id")
	}
	if reward.RewardMicros <= 0 {
		return RewardIssue{}, fmt.Errorf("issue reward requires reward_micros > 0")
	}
	hasPayoutPeriod, err := normalizeRewardPayoutPeriod(&reward)
	if err != nil {
		return RewardIssue{}, err
	}
	if reward.TrafficProofRef != "" && !isObjectiveEvidenceRef(reward.TrafficProofRef) {
		return RewardIssue{}, fmt.Errorf("issue reward requires objective traffic_proof_ref (obj://... or sha256:...)")
	}
	issuedAtProvided := !reward.IssuedAt.IsZero()

	proofVerified := false
	slashHoldChecked := false
	for {
		s.mu.Lock()
		if reward.Currency == "" {
			reward.Currency = s.currency
		}
		if err := s.ensureSupportedCurrencyLocked(reward.Currency); err != nil {
			s.mu.Unlock()
			return RewardIssue{}, err
		}
		if reward.IssuedAt.IsZero() {
			reward.IssuedAt = time.Now().UTC()
		}
		reward.IssuedAt = reward.IssuedAt.UTC().Truncate(time.Second)
		if reward.SettlementReferenceID == "" && reward.TrafficProofRef == "" {
			if settlement, ok := s.settledBySession[reward.SessionID]; ok {
				if !s.blockchainMode || settlement.Status == OperationStatusConfirmed {
					reward.SettlementReferenceID = rewardSettlementReference(settlement)
				}
			}
		}
		chainRewardSubmissionConfigured := s.blockchainMode || adapterRequiresRewardProofReference(s.adapter) || adapterRequiresRewardProofReference(s.shadowAdapter)
		if err := s.validateRewardProofTrustLocked(chainRewardSubmissionConfigured, reward); err != nil {
			s.mu.Unlock()
			return RewardIssue{}, err
		}
		if existing, ok := s.rewardsByID[reward.RewardID]; ok {
			if !issuedAtProvided {
				reward.IssuedAt = existing.IssuedAt
			}
			if !rewardIssueMaterialEqual(existing, reward) {
				s.mu.Unlock()
				return RewardIssue{}, idempotencyConflictError("reward issue", reward.RewardID)
			}
			existing.IdempotentReplay = true
			s.mu.Unlock()
			return existing, nil
		}
		if chainRewardSubmissionConfigured && reward.TrafficProofRef != "" && !proofVerified {
			verifier := s.rewardProofVerifierLocked()
			s.mu.Unlock()
			verification, err := verifyRewardTrafficProof(ctx, verifier, reward)
			if err != nil {
				return RewardIssue{}, err
			}
			applyRewardProofVerification(&reward, verification)
			proofVerified = true
			continue
		}
		if chainRewardSubmissionConfigured && !hasPayoutPeriod {
			s.mu.Unlock()
			return RewardIssue{}, fmt.Errorf("issue reward requires weekly payout period for chain-backed reward issuance")
		}
		if hasPayoutPeriod && !slashHoldChecked {
			s.mu.Unlock()
			if err := s.ensureNoRewardSlashHold(ctx, reward); err != nil {
				return RewardIssue{}, err
			}
			slashHoldChecked = true
			continue
		}

		reward.Status = OperationStatusPending
		var payoutKey rewardPayoutKey
		if hasPayoutPeriod {
			payoutKey = rewardWeeklyPayoutKey(reward)
			if existingRewardID, ok := s.weeklyRewardPayoutByKey[payoutKey]; ok && existingRewardID != reward.RewardID {
				s.mu.Unlock()
				return RewardIssue{}, fmt.Errorf("reward payout already issued for provider %s period %s to %s: %s",
					reward.ProviderSubjectID,
					reward.PayoutPeriodStart.Format(time.RFC3339),
					reward.PayoutPeriodEnd.Format(time.RFC3339),
					existingRewardID,
				)
			}
			s.weeklyRewardPayoutByKey[payoutKey] = reward.RewardID
		}
		s.rewardsByID[reward.RewardID] = reward
		s.mu.Unlock()
		break
	}

	reward.Status = OperationStatusConfirmed

	s.submitRewardAdapter(ctx, &reward)

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.rewardsByID[reward.RewardID]; ok && existing.Status == OperationStatusPending && rewardIssueMaterialEqual(existing, reward) {
		s.rewardsByID[reward.RewardID] = reward
	}
	return reward, nil
}

func (s *MemoryService) ensureNoRewardSlashHold(ctx context.Context, reward RewardIssue) error {
	if reward.ProviderSubjectID == "" || reward.PayoutPeriodStart.IsZero() || reward.PayoutPeriodEnd.IsZero() {
		return nil
	}
	adapter := s.currentAdapter()
	if adapter == nil {
		records := s.listLocalSlashEvidence(SlashEvidenceFilter{
			SubjectID:         reward.ProviderSubjectID,
			ObservedAtOrAfter: reward.PayoutPeriodStart,
			ObservedBefore:    reward.PayoutPeriodEnd,
		})
		return ensureNoRewardSlashHoldFromRecords(reward, records)
	}
	records, err := s.ListSlashEvidence(ctx, SlashEvidenceFilter{
		SubjectID:         reward.ProviderSubjectID,
		ObservedAtOrAfter: reward.PayoutPeriodStart,
		ObservedBefore:    reward.PayoutPeriodEnd,
	})
	if err != nil {
		return fmt.Errorf("issue reward slash evidence hold check failed: %w", err)
	}
	return ensureNoRewardSlashHoldFromRecords(reward, records)
}

func ensureNoRewardSlashHoldFromRecords(reward RewardIssue, records []SlashEvidence) error {
	for _, evidence := range records {
		if evidence.Status == OperationStatusFailed {
			continue
		}
		evidenceID := strings.TrimSpace(evidence.EvidenceID)
		if evidenceID == "" {
			evidenceID = strings.TrimSpace(evidence.EvidenceRef)
		}
		return fmt.Errorf("issue reward blocked by slash evidence for provider %s in payout period %s to %s: %s",
			reward.ProviderSubjectID,
			reward.PayoutPeriodStart.Format(time.RFC3339),
			reward.PayoutPeriodEnd.Format(time.RFC3339),
			evidenceID,
		)
	}
	return nil
}

func (s *MemoryService) RegisterRewardProof(ctx context.Context, proof RewardProofRecord) error {
	proof.ProofPath = strings.TrimSpace(proof.ProofPath)
	proof.TrafficProofRef = canonicalObjectiveEvidenceRef(proof.TrafficProofRef)
	proof.RewardID = strings.TrimSpace(proof.RewardID)
	proof.ProviderSubjectID = strings.TrimSpace(proof.ProviderSubjectID)
	proof.SessionID = strings.TrimSpace(proof.SessionID)
	proof.Currency = normalizeCurrencyCode(proof.Currency)
	proof.VerifierID = strings.TrimSpace(proof.VerifierID)
	if proof.TrustContract == "" {
		proof.TrustContract = RewardProofTrustContractObjectiveTrafficV1
	}
	if proof.ProofPath == "" || proof.TrafficProofRef == "" || proof.RewardID == "" || proof.ProviderSubjectID == "" || proof.SessionID == "" {
		return fmt.Errorf("register reward proof requires proof_path, traffic_proof_ref, reward_id, provider_subject_id, and session_id")
	}
	if !strings.HasPrefix(proof.TrafficProofRef, "obj://") || strings.TrimPrefix(proof.TrafficProofRef, "obj://") != proof.ProofPath {
		return fmt.Errorf("register reward proof requires matching obj:// traffic_proof_ref")
	}
	if proof.TrustContract != RewardProofTrustContractObjectiveTrafficV1 {
		return fmt.Errorf("register reward proof unsupported trust contract: %s", proof.TrustContract)
	}
	if proof.RewardMicros <= 0 {
		return fmt.Errorf("register reward proof requires reward_micros > 0")
	}
	if proof.Currency == "" {
		return fmt.Errorf("register reward proof requires currency")
	}
	if proof.IssuedAt.IsZero() {
		return fmt.Errorf("register reward proof requires issued_at")
	}
	proof.IssuedAt = proof.IssuedAt.UTC().Truncate(time.Second)
	if !proof.VerifiedAt.IsZero() {
		proof.VerifiedAt = proof.VerifiedAt.UTC().Truncate(time.Second)
	}
	if !proof.Verified {
		return fmt.Errorf("register reward proof requires verified proof")
	}
	if proof.VerifierID == "" {
		return fmt.Errorf("register reward proof requires verifier_id")
	}
	s.mu.Lock()
	adapter, _ := s.adapter.(ChainRewardProofRegistrar)
	shadowAdapter, _ := s.shadowAdapter.(ChainRewardProofRegistrar)
	s.mu.Unlock()
	if adapter == nil && shadowAdapter == nil {
		return nil
	}
	if adapter != nil {
		if _, err := adapter.SubmitRewardProof(ctx, proof); err != nil {
			return err
		}
	}
	if shadowAdapter != nil {
		_, _ = shadowAdapter.SubmitRewardProof(ctx, proof)
	}
	return nil
}

func (s *MemoryService) SubmitSlashEvidence(ctx context.Context, evidence SlashEvidence) (SlashEvidence, error) {
	evidence.EvidenceID = strings.TrimSpace(evidence.EvidenceID)
	evidence.SubjectID = strings.TrimSpace(evidence.SubjectID)
	evidence.SessionID = strings.TrimSpace(evidence.SessionID)
	evidence.ViolationType = strings.TrimSpace(evidence.ViolationType)
	evidence.EvidenceRef = canonicalObjectiveEvidenceRef(evidence.EvidenceRef)
	evidence.Currency = normalizeCurrencyCode(evidence.Currency)
	if evidence.EvidenceID == "" || evidence.SubjectID == "" || evidence.SessionID == "" || evidence.ViolationType == "" {
		return SlashEvidence{}, fmt.Errorf("submit slash evidence requires evidence_id, subject_id, session_id, and violation_type")
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
	currency := s.currency
	if evidence.SlashMicros > 0 && evidence.Currency == "" {
		evidence.Currency = currency
	}
	if evidence.SlashMicros == 0 && evidence.Currency != "" {
		s.mu.Unlock()
		return SlashEvidence{}, fmt.Errorf("submit slash evidence requires slash_micros > 0 when currency is provided")
	}
	if existing, ok := s.slashEvidenceByID[evidence.EvidenceID]; ok {
		if evidence.ObservedAt.IsZero() {
			evidence.ObservedAt = existing.ObservedAt
		}
		if !slashEvidenceMaterialEqual(existing, evidence) {
			s.mu.Unlock()
			return SlashEvidence{}, idempotencyConflictError("slash evidence", evidence.EvidenceID)
		}
		existing.IdempotentReplay = true
		s.mu.Unlock()
		return existing, nil
	}
	incidentKey := slashEvidenceIncidentKey(evidence)
	if incidentKey != "" {
		for _, existing := range s.slashEvidenceByID {
			if slashEvidenceIncidentKey(existing) == incidentKey {
				s.mu.Unlock()
				return SlashEvidence{}, fmt.Errorf("slash evidence incident conflict for id %s: duplicate incident already recorded as %s", evidence.EvidenceID, existing.EvidenceID)
			}
		}
	}
	if evidence.Currency != "" {
		if _, ok := s.currencyRates[evidence.Currency]; !ok {
			s.mu.Unlock()
			return SlashEvidence{}, fmt.Errorf("unsupported settlement currency: %s", evidence.Currency)
		}
	}
	if evidence.ObservedAt.IsZero() {
		evidence.ObservedAt = time.Now().UTC()
	}
	evidence.Status = OperationStatusPending
	s.slashEvidenceByID[evidence.EvidenceID] = evidence
	s.mu.Unlock()

	evidence.Status = OperationStatusConfirmed

	s.submitSlashEvidenceAdapter(ctx, &evidence)

	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.slashEvidenceByID[evidence.EvidenceID]; ok && existing.Status == OperationStatusPending && slashEvidenceMaterialEqual(existing, evidence) {
		s.slashEvidenceByID[evidence.EvidenceID] = evidence
	}
	return evidence, nil
}

func (s *MemoryService) ListSlashEvidence(ctx context.Context, filter SlashEvidenceFilter) ([]SlashEvidence, error) {
	local := s.listLocalSlashEvidence(filter)
	adapter := s.currentAdapter()
	if adapter == nil {
		if s.blockchainModeEnabled() {
			return nil, fmt.Errorf("list slash evidence requires chain adapter in blockchain mode: %w", errChainAdapterNotConfigured)
		}
		return local, nil
	}
	lister, ok := adapter.(ChainSlashEvidenceLister)
	if !ok || lister == nil {
		if s.blockchainModeEnabled() {
			return nil, fmt.Errorf("list slash evidence requires chain slash evidence lister in blockchain mode")
		}
		return local, nil
	}
	chainEvidence, err := lister.ListSlashEvidence(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("list chain slash evidence: %w", err)
	}
	return mergeSlashEvidence(local, filterSlashEvidence(chainEvidence, filter)), nil
}

func (s *MemoryService) listLocalSlashEvidence(filter SlashEvidenceFilter) []SlashEvidence {
	subjectID := strings.TrimSpace(filter.SubjectID)
	sessionID := strings.TrimSpace(filter.SessionID)
	violationType := strings.TrimSpace(filter.ViolationType)
	start := filter.ObservedAtOrAfter.UTC()
	end := filter.ObservedBefore.UTC()

	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]SlashEvidence, 0, len(s.slashEvidenceByID))
	for _, evidence := range s.slashEvidenceByID {
		if !slashEvidenceMatchesFilter(evidence, subjectID, sessionID, violationType, start, end, filter.IncludeFailed, filter.IncludeFailedSet, filter.IncludeZeroObserved) {
			continue
		}
		out = append(out, evidence)
	}
	return sortSlashEvidence(out)
}

func filterSlashEvidence(records []SlashEvidence, filter SlashEvidenceFilter) []SlashEvidence {
	subjectID := strings.TrimSpace(filter.SubjectID)
	sessionID := strings.TrimSpace(filter.SessionID)
	violationType := strings.TrimSpace(filter.ViolationType)
	start := filter.ObservedAtOrAfter.UTC()
	end := filter.ObservedBefore.UTC()

	out := make([]SlashEvidence, 0, len(records))
	for _, evidence := range records {
		if slashEvidenceMatchesFilter(evidence, subjectID, sessionID, violationType, start, end, filter.IncludeFailed, filter.IncludeFailedSet, filter.IncludeZeroObserved) {
			out = append(out, evidence)
		}
	}
	return sortSlashEvidence(out)
}

func slashEvidenceMatchesFilter(evidence SlashEvidence, subjectID string, sessionID string, violationType string, start time.Time, end time.Time, includeFailed bool, includeFailedSet bool, includeZeroObserved bool) bool {
	if subjectID != "" && strings.TrimSpace(evidence.SubjectID) != subjectID {
		return false
	}
	if sessionID != "" && strings.TrimSpace(evidence.SessionID) != sessionID {
		return false
	}
	if violationType != "" && strings.TrimSpace(evidence.ViolationType) != violationType {
		return false
	}
	if includeFailedSet && !includeFailed && evidence.Status == OperationStatusFailed {
		return false
	}
	observedAt := evidence.ObservedAt.UTC()
	if observedAt.IsZero() {
		return includeZeroObserved
	}
	if !start.IsZero() && observedAt.Before(start) {
		return false
	}
	if !end.IsZero() && !observedAt.Before(end) {
		return false
	}
	return true
}

func mergeSlashEvidence(local []SlashEvidence, chain []SlashEvidence) []SlashEvidence {
	merged := make([]SlashEvidence, 0, len(local)+len(chain))
	seen := map[string]struct{}{}
	appendRecord := func(evidence SlashEvidence) {
		key := strings.TrimSpace(evidence.EvidenceID)
		if key == "" {
			key = slashEvidenceIncidentKey(evidence)
		}
		if key != "" {
			if _, ok := seen[key]; ok {
				return
			}
			seen[key] = struct{}{}
		}
		merged = append(merged, evidence)
	}
	for _, evidence := range local {
		appendRecord(evidence)
	}
	for _, evidence := range chain {
		appendRecord(evidence)
	}
	return sortSlashEvidence(merged)
}

func sortSlashEvidence(out []SlashEvidence) []SlashEvidence {
	sort.Slice(out, func(i, j int) bool {
		if out[i].ObservedAt.Equal(out[j].ObservedAt) {
			return out[i].EvidenceID < out[j].EvidenceID
		}
		return out[i].ObservedAt.Before(out[j].ObservedAt)
	})
	return out
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

func fundReservationMaterialMatches(existing FundReservation, incoming FundReservation) bool {
	return strings.TrimSpace(existing.SubjectID) == strings.TrimSpace(incoming.SubjectID) &&
		strings.TrimSpace(existing.ReservationID) == strings.TrimSpace(incoming.ReservationID) &&
		existing.AmountMicros == incoming.AmountMicros &&
		normalizeCurrencyCode(existing.Currency) == normalizeCurrencyCode(incoming.Currency)
}

func submitFundReservationAdapter(ctx context.Context, blockchainMode bool, adapter ChainAdapter, reservation FundReservation) (bool, error) {
	if !blockchainMode {
		return false, nil
	}
	if adapter == nil {
		return false, fmt.Errorf("reserve funds requires chain billing reservation submitter: %w", errChainAdapterNotConfigured)
	}
	submitter, ok := adapter.(ChainBillingReservationSubmitter)
	if !ok || submitter == nil {
		return false, fmt.Errorf("reserve funds requires chain billing reservation submitter: %w", errChainAdapterNotConfigured)
	}
	submission := reservation
	if adapterTrustedBridgeFinalityEnabled(adapter) {
		submission.Status = OperationStatusConfirmed
	} else {
		submission.Status = OperationStatusSubmitted
	}
	if _, err := submitter.SubmitFundReservation(ctx, submission); err != nil {
		return false, fmt.Errorf("reserve funds chain reservation submit failed: %w", err)
	}
	return true, nil
}

func (s *MemoryService) confirmedFundReservationForSettlement(ctx context.Context, reservation FundReservation) (FundReservation, error) {
	reservationID := strings.TrimSpace(reservation.ReservationID)
	if reservationID == "" {
		return FundReservation{}, fmt.Errorf("settle session requires reservation id for session %s", reservation.SessionID)
	}
	if !s.blockchainModeEnabled() && reservation.Status == OperationStatusConfirmed {
		return reservation, nil
	}

	adapter := s.currentAdapter()
	if s.blockchainModeEnabled() {
		querier, ok := adapter.(FundReservationQuerier)
		if !ok || querier == nil {
			return FundReservation{}, fmt.Errorf("settle session requires chain fund reservation material query for reservation %s", reservationID)
		}
		chainReservation, found, err := querier.FundReservation(ctx, reservationID)
		if err != nil {
			return FundReservation{}, fmt.Errorf("settle session fund reservation material check failed for %s: %w", reservationID, err)
		}
		if !found {
			return FundReservation{}, fmt.Errorf("settle session requires chain-finalized fund reservation %s; current status=%s", reservationID, reservation.Status)
		}
		if chainReservation.Status != OperationStatusConfirmed {
			return FundReservation{}, fmt.Errorf("settle session requires chain-finalized fund reservation %s; current status=%s", reservationID, chainReservation.Status)
		}
		if !fundReservationChainMaterialEqual(reservation, chainReservation) {
			return FundReservation{}, fmt.Errorf("settle session fund reservation material mismatch for %s", reservationID)
		}
		reservation.Status = OperationStatusConfirmed
		s.mu.Lock()
		if existing, ok := s.reservationsBySession[reservation.SessionID]; ok && strings.TrimSpace(existing.ReservationID) == reservationID {
			existing.Status = OperationStatusConfirmed
			reservation = existing
			s.reservationsBySession[reservation.SessionID] = existing
		}
		s.mu.Unlock()
		return reservation, nil
	}

	if querier, ok := adapter.(ChainFundReservationStatusQuerier); ok && querier != nil {
		status, found, err := querier.FundReservationStatus(ctx, reservationID)
		if err != nil {
			return FundReservation{}, fmt.Errorf("settle session fund reservation finality check failed for %s: %w", reservationID, err)
		}
		if found && status != "" {
			reservation.Status = status
			s.mu.Lock()
			if existing, ok := s.reservationsBySession[reservation.SessionID]; ok && strings.TrimSpace(existing.ReservationID) == reservationID {
				existing.Status = status
				reservation = existing
				s.reservationsBySession[reservation.SessionID] = existing
			}
			s.mu.Unlock()
		}
	}
	if reservation.Status != OperationStatusConfirmed {
		return FundReservation{}, fmt.Errorf("settle session requires chain-finalized fund reservation %s; current status=%s", reservationID, reservation.Status)
	}
	return reservation, nil
}

func adapterRequiresRewardProofReference(adapter ChainAdapter) bool {
	if adapter == nil {
		return false
	}
	requirement, ok := adapter.(ChainRewardProofRequirement)
	return ok && requirement.RequiresRewardProofReference()
}

func adapterTrustedBridgeFinalityEnabled(adapter ChainAdapter) bool {
	if adapter == nil {
		return false
	}
	reporter, ok := adapter.(interface {
		TrustedBridgeFinalityEnabled() bool
	})
	return ok && reporter.TrustedBridgeFinalityEnabled()
}

func (s *MemoryService) rewardProofVerifierLocked() RewardProofVerifier {
	if s.rewardProofVerifier != nil {
		return s.rewardProofVerifier
	}
	verifier, ok := s.adapter.(RewardProofVerifier)
	if !ok {
		return nil
	}
	return verifier
}

func (s *MemoryService) validateRewardProofTrustLocked(chainRewardSubmissionConfigured bool, reward RewardIssue) error {
	if !chainRewardSubmissionConfigured {
		return nil
	}
	hasSettlementReference := reward.SettlementReferenceID != ""
	if hasSettlementReference {
		settlement, ok := s.settledBySession[reward.SessionID]
		if !ok {
			return fmt.Errorf("issue reward settlement reference not found for session: %s", reward.SessionID)
		}
		if rewardSettlementReference(settlement) != reward.SettlementReferenceID {
			return fmt.Errorf("issue reward settlement reference mismatch for session: %s", reward.SessionID)
		}
		if settlement.Status != OperationStatusConfirmed {
			return fmt.Errorf("issue reward requires chain-finalized settlement reference: %s", reward.SettlementReferenceID)
		}
	}
	if reward.TrafficProofRef == "" {
		return fmt.Errorf("issue reward requires verified traffic_proof_ref (obj://...) for chain-backed reward issuance")
	}
	if !isStrongRewardTrafficProofRef(reward.TrafficProofRef) {
		return fmt.Errorf("issue reward requires verified traffic_proof_ref (obj://...) for chain-backed reward issuance")
	}
	return nil
}

func verifyRewardTrafficProof(ctx context.Context, verifier RewardProofVerifier, reward RewardIssue) (RewardProofVerification, error) {
	if verifier == nil {
		return RewardProofVerification{}, fmt.Errorf("issue reward requires reward proof verifier for traffic_proof_ref: %s", reward.TrafficProofRef)
	}
	verification, err := verifier.VerifyRewardProof(ctx, rewardProofVerificationRequest(reward))
	if err != nil {
		return RewardProofVerification{}, fmt.Errorf("verify reward traffic proof: %w", err)
	}
	verification.VerifierID = strings.TrimSpace(verification.VerifierID)
	if !verification.Verified {
		return RewardProofVerification{}, fmt.Errorf("issue reward traffic proof not verified: %s", reward.TrafficProofRef)
	}
	if verification.VerifierID == "" {
		return RewardProofVerification{}, fmt.Errorf("issue reward traffic proof verifier id required")
	}
	if verification.VerifiedAt.IsZero() {
		verification.VerifiedAt = time.Now().UTC()
	} else {
		verification.VerifiedAt = verification.VerifiedAt.UTC().Round(0)
	}
	return verification, nil
}

func rewardProofVerificationRequest(reward RewardIssue) RewardProofVerificationRequest {
	return RewardProofVerificationRequest{
		TrustContract:     RewardProofTrustContractObjectiveTrafficV1,
		TrafficProofRef:   reward.TrafficProofRef,
		RewardID:          reward.RewardID,
		ProviderSubjectID: reward.ProviderSubjectID,
		SessionID:         reward.SessionID,
		PayoutPeriodStart: reward.PayoutPeriodStart,
		PayoutPeriodEnd:   reward.PayoutPeriodEnd,
		RewardMicros:      reward.RewardMicros,
		Currency:          reward.Currency,
		IssuedAt:          reward.IssuedAt,
	}
}

func applyRewardProofVerification(reward *RewardIssue, verification RewardProofVerification) {
	if reward == nil {
		return
	}
	reward.TrafficProofVerified = true
	reward.TrafficProofVerifierID = verification.VerifierID
	reward.TrafficProofVerifiedAt = verification.VerifiedAt
	reward.TrafficProofTrustContract = RewardProofTrustContractObjectiveTrafficV1
}

func rewardTrafficProofVerified(reward RewardIssue) bool {
	return reward.TrafficProofVerified &&
		reward.TrafficProofTrustContract == RewardProofTrustContractObjectiveTrafficV1 &&
		strings.TrimSpace(reward.TrafficProofVerifierID) != "" &&
		!reward.TrafficProofVerifiedAt.IsZero()
}

func (s *MemoryService) submitSettlementAdapter(ctx context.Context, settlement *SessionSettlement) {
	submission := *settlement
	if adapterTrustedBridgeFinalityEnabled(s.currentAdapter()) {
		submission.Status = OperationStatusConfirmed
	} else {
		submission.Status = OperationStatusSubmitted
	}
	idempotencyKey := cosmosID("settlement", settlement.SettlementID, settlement.SessionID)
	shadowSubmit := func(ctx context.Context, adapter ChainAdapter) (string, error) {
		return adapter.SubmitSessionSettlement(ctx, submission)
	}
	op := deferredAdapterOperation{
		Type:           deferredOperationSettlement,
		RecordKey:      settlement.SessionID,
		IdempotencyKey: idempotencyKey,
	}
	adapter := s.currentAdapter()
	if adapter == nil {
		if !s.blockchainModeEnabled() {
			return
		}
		shadowResult := s.submitShadowSubmission(ctx, idempotencyKey, shadowSubmit)
		settlement.AdapterDeferred = true
		settlement.AdapterSubmitted = false
		settlement.AdapterReferenceID = idempotencyKey
		settlement.Status = OperationStatusPending
		applyShadowResultToSettlement(settlement, shadowResult)
		s.mu.Lock()
		s.upsertDeferredOperationLocked(op, errChainAdapterNotConfigured)
		s.mu.Unlock()
		return
	}

	ref, err := adapter.SubmitSessionSettlement(ctx, submission)
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
	submission := *reward
	if adapterTrustedBridgeFinalityEnabled(s.currentAdapter()) {
		submission.Status = OperationStatusConfirmed
	} else {
		submission.Status = OperationStatusSubmitted
	}
	idempotencyKey := cosmosID("reward", reward.RewardID, reward.SessionID)
	shadowSubmit := func(ctx context.Context, adapter ChainAdapter) (string, error) {
		return adapter.SubmitRewardIssue(ctx, submission)
	}
	op := deferredAdapterOperation{
		Type:           deferredOperationReward,
		RecordKey:      reward.RewardID,
		IdempotencyKey: idempotencyKey,
	}
	adapter := s.currentAdapter()
	if adapter == nil {
		if !s.blockchainModeEnabled() {
			return
		}
		shadowResult := s.submitShadowSubmission(ctx, idempotencyKey, shadowSubmit)
		reward.AdapterDeferred = true
		reward.AdapterSubmitted = false
		reward.AdapterReferenceID = idempotencyKey
		reward.Status = OperationStatusPending
		applyShadowResultToReward(reward, shadowResult)
		s.mu.Lock()
		s.upsertDeferredOperationLocked(op, errChainAdapterNotConfigured)
		s.mu.Unlock()
		return
	}
	ref, err := adapter.SubmitRewardIssue(ctx, submission)
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
	submission := *reservation
	submission.Status = OperationStatusPending
	idempotencyKey := cosmosID("sponsor-reservation", reservation.ReservationID, reservation.SessionID)
	shadowSubmit := func(ctx context.Context, adapter ChainAdapter) (string, error) {
		return adapter.SubmitSponsorReservation(ctx, submission)
	}
	op := deferredAdapterOperation{
		Type:           deferredOperationSponsorReservation,
		RecordKey:      reservation.ReservationID,
		IdempotencyKey: idempotencyKey,
	}
	adapter := s.currentAdapter()
	if adapter == nil {
		if !s.blockchainModeEnabled() {
			return
		}
		shadowResult := s.submitShadowSubmission(ctx, idempotencyKey, shadowSubmit)
		reservation.AdapterDeferred = true
		reservation.AdapterSubmitted = false
		reservation.AdapterReferenceID = idempotencyKey
		reservation.Status = OperationStatusPending
		applyShadowResultToSponsorReservation(reservation, shadowResult)
		s.mu.Lock()
		s.upsertDeferredOperationLocked(op, errChainAdapterNotConfigured)
		s.mu.Unlock()
		return
	}
	ref, err := adapter.SubmitSponsorReservation(ctx, submission)
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
	submission := *evidence
	submission.Status = OperationStatusSubmitted
	idempotencyKey := cosmosID("slash", evidence.EvidenceID, evidence.SubjectID)
	shadowSubmit := func(ctx context.Context, adapter ChainAdapter) (string, error) {
		return adapter.SubmitSlashEvidence(ctx, submission)
	}
	op := deferredAdapterOperation{
		Type:           deferredOperationSlashEvidence,
		RecordKey:      evidence.EvidenceID,
		IdempotencyKey: idempotencyKey,
	}
	adapter := s.currentAdapter()
	if adapter == nil {
		if !s.blockchainModeEnabled() {
			return
		}
		shadowResult := s.submitShadowSubmission(ctx, idempotencyKey, shadowSubmit)
		evidence.AdapterDeferred = true
		evidence.AdapterSubmitted = false
		evidence.AdapterReferenceID = idempotencyKey
		evidence.Status = OperationStatusPending
		applyShadowResultToSlashEvidence(evidence, shadowResult)
		s.mu.Lock()
		s.upsertDeferredOperationLocked(op, errChainAdapterNotConfigured)
		s.mu.Unlock()
		return
	}
	ref, err := adapter.SubmitSlashEvidence(ctx, submission)
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

func (s *MemoryService) blockchainModeEnabled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.blockchainMode
}

// ChainBacked reports whether this settlement wrapper is enforcing chain-backed
// semantics with a primary chain adapter configured.
func (s *MemoryService) ChainBacked() bool {
	return s.blockchainModeEnabled() && s.currentAdapter() != nil
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
		submission := settlement
		submission.Status = OperationStatusSubmitted
		shadowFn = func(ctx context.Context, adapter ChainAdapter) (string, error) {
			return adapter.SubmitSessionSettlement(ctx, submission)
		}
		ref, err = adapter.SubmitSessionSettlement(ctx, submission)
	case deferredOperationReward:
		s.mu.Lock()
		reward, ok := s.rewardsByID[op.RecordKey]
		s.mu.Unlock()
		if !ok {
			return
		}
		verifiedReward, ready := s.rewardReadyForFinalization(ctx, reward)
		if !ready {
			err = fmt.Errorf("deferred reward replay requires verified traffic proof before adapter submission: %s", reward.RewardID)
			break
		}
		s.mu.Lock()
		if current, ok := s.rewardsByID[op.RecordKey]; ok && rewardIssueMaterialEqual(current, verifiedReward) {
			current.TrafficProofVerified = verifiedReward.TrafficProofVerified
			current.TrafficProofVerifierID = verifiedReward.TrafficProofVerifierID
			current.TrafficProofVerifiedAt = verifiedReward.TrafficProofVerifiedAt
			current.TrafficProofTrustContract = verifiedReward.TrafficProofTrustContract
			s.rewardsByID[op.RecordKey] = current
			reward = current
		} else {
			reward = verifiedReward
		}
		s.mu.Unlock()
		submission := reward
		submission.Status = OperationStatusSubmitted
		shadowFn = func(ctx context.Context, adapter ChainAdapter) (string, error) {
			return adapter.SubmitRewardIssue(ctx, submission)
		}
		ref, err = adapter.SubmitRewardIssue(ctx, submission)
	case deferredOperationSponsorReservation:
		s.mu.Lock()
		reservation, ok := s.sponsorReservationsByID[op.RecordKey]
		s.mu.Unlock()
		if !ok {
			return
		}
		submission := reservation
		submission.Status = OperationStatusPending
		shadowFn = func(ctx context.Context, adapter ChainAdapter) (string, error) {
			return adapter.SubmitSponsorReservation(ctx, submission)
		}
		ref, err = adapter.SubmitSponsorReservation(ctx, submission)
	case deferredOperationSlashEvidence:
		s.mu.Lock()
		evidence, ok := s.slashEvidenceByID[op.RecordKey]
		s.mu.Unlock()
		if !ok {
			return
		}
		submission := evidence
		submission.Status = OperationStatusSubmitted
		shadowFn = func(ctx context.Context, adapter ChainAdapter) (string, error) {
			return adapter.SubmitSlashEvidence(ctx, submission)
		}
		ref, err = adapter.SubmitSlashEvidence(ctx, submission)
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
	_, ok := adapter.(ChainConfirmationStatusQuerier)
	if !ok {
		return
	}

	type settlementSnapshot struct {
		Settlement  SessionSettlement
		Reservation FundReservation
	}
	type rewardSnapshot struct {
		RewardID string
		Reward   RewardIssue
	}
	type sponsorSnapshot struct {
		ReservationID string
		Reservation   SponsorCreditReservation
	}
	type slashSnapshot struct {
		EvidenceID string
		Evidence   SlashEvidence
	}

	s.mu.Lock()
	settlements := make([]settlementSnapshot, 0)
	for sessionID, settlement := range s.settledBySession {
		if settlement.Status == OperationStatusSubmitted && strings.TrimSpace(settlement.SettlementID) != "" {
			if strings.TrimSpace(settlement.SessionID) == "" {
				settlement.SessionID = sessionID
			}
			reservation := s.settlementReservationsBySession[settlement.SessionID]
			if strings.TrimSpace(reservation.ReservationID) == "" {
				reservation = s.reservationsBySession[settlement.SessionID]
			}
			settlements = append(settlements, settlementSnapshot{
				Settlement:  settlement,
				Reservation: reservation,
			})
		}
	}
	rewards := make([]rewardSnapshot, 0)
	for rewardID, reward := range s.rewardsByID {
		if reward.Status == OperationStatusSubmitted {
			rewards = append(rewards, rewardSnapshot{RewardID: rewardID, Reward: reward})
		}
	}
	sponsorReservations := make([]sponsorSnapshot, 0)
	for reservationID, reservation := range s.sponsorReservationsByID {
		if reservation.Status == OperationStatusSubmitted {
			sponsorReservations = append(sponsorReservations, sponsorSnapshot{ReservationID: reservationID, Reservation: reservation})
		}
	}
	slashEvidence := make([]slashSnapshot, 0)
	for evidenceID, evidence := range s.slashEvidenceByID {
		if evidence.Status == OperationStatusSubmitted {
			slashEvidence = append(slashEvidence, slashSnapshot{EvidenceID: evidenceID, Evidence: evidence})
		}
	}
	s.mu.Unlock()

	settlementQuerier, settlementQueryAvailable := adapter.(SessionSettlementQuerier)
	rewardQuerier, rewardQueryAvailable := adapter.(RewardIssueQuerier)
	sponsorQuerier, sponsorQueryAvailable := adapter.(SponsorReservationQuerier)
	slashQuerier, slashQueryAvailable := adapter.(SlashEvidenceQuerier)
	for _, snapshot := range settlements {
		if !settlementQueryAvailable {
			continue
		}
		chainSettlement, found, err := settlementQuerier.SessionSettlement(ctx, snapshot.Settlement.SettlementID)
		if err != nil ||
			!found ||
			chainSettlement.Status != OperationStatusConfirmed {
			continue
		}
		chainSettlement = enrichSessionSettlementChainMaterial(snapshot.Settlement, snapshot.Reservation, chainSettlement)
		if !sessionSettlementChainMaterialEqual(snapshot.Settlement, chainSettlement) {
			continue
		}
		s.mu.Lock()
		settlement, ok := s.settledBySession[snapshot.Settlement.SessionID]
		if ok && settlement.Status == OperationStatusSubmitted {
			settlement.Status = OperationStatusConfirmed
			settlement.AdapterDeferred = false
			settlement.AdapterSubmitted = true
			s.settledBySession[snapshot.Settlement.SessionID] = settlement
		}
		s.mu.Unlock()
	}
	for _, snapshot := range rewards {
		if !rewardQueryAvailable {
			continue
		}
		chainReward, found, err := rewardQuerier.RewardIssue(ctx, snapshot.RewardID)
		if err != nil ||
			!found ||
			chainReward.Status != OperationStatusConfirmed ||
			!rewardIssueChainMaterialEqual(snapshot.Reward, chainReward) {
			continue
		}
		finalReward, ok := s.rewardReadyForFinalization(ctx, snapshot.Reward)
		if !ok {
			continue
		}
		if !rewardIssueChainMaterialEqual(finalReward, chainReward) {
			continue
		}
		s.mu.Lock()
		reward, ok := s.rewardsByID[snapshot.RewardID]
		if ok && reward.Status == OperationStatusSubmitted && rewardIssueMaterialEqual(reward, finalReward) {
			reward.TrafficProofVerified = finalReward.TrafficProofVerified
			reward.TrafficProofVerifierID = finalReward.TrafficProofVerifierID
			reward.TrafficProofVerifiedAt = finalReward.TrafficProofVerifiedAt
			reward.TrafficProofTrustContract = finalReward.TrafficProofTrustContract
			reward.Status = OperationStatusConfirmed
			reward.AdapterDeferred = false
			reward.AdapterSubmitted = true
			s.rewardsByID[snapshot.RewardID] = reward
		}
		s.mu.Unlock()
	}
	for _, snapshot := range sponsorReservations {
		if !sponsorQueryAvailable {
			continue
		}
		chainReservation, found, err := sponsorQuerier.SponsorReservation(ctx, snapshot.ReservationID)
		if err != nil ||
			!found ||
			chainReservation.Status != OperationStatusConfirmed ||
			!chainReservation.ConsumedAt.IsZero() ||
			!sponsorReservationChainMaterialEqual(snapshot.Reservation, chainReservation) {
			continue
		}
		s.mu.Lock()
		reservation, ok := s.sponsorReservationsByID[snapshot.ReservationID]
		if ok && reservation.Status == OperationStatusSubmitted && sponsorReservationChainMaterialEqual(reservation, chainReservation) {
			reservation.Status = OperationStatusConfirmed
			reservation.AdapterDeferred = false
			reservation.AdapterSubmitted = true
			s.sponsorReservationsByID[snapshot.ReservationID] = reservation
		}
		s.mu.Unlock()
	}
	for _, snapshot := range slashEvidence {
		if !slashQueryAvailable {
			continue
		}
		chainEvidence, found, err := slashQuerier.SlashEvidence(ctx, snapshot.EvidenceID)
		if err != nil ||
			!found ||
			chainEvidence.Status != OperationStatusConfirmed ||
			!slashEvidenceChainMaterialEqual(snapshot.Evidence, chainEvidence) {
			continue
		}
		s.mu.Lock()
		evidence, ok := s.slashEvidenceByID[snapshot.EvidenceID]
		if ok && evidence.Status == OperationStatusSubmitted && slashEvidenceChainMaterialEqual(evidence, chainEvidence) {
			evidence.Status = OperationStatusConfirmed
			evidence.AdapterDeferred = false
			evidence.AdapterSubmitted = true
			s.slashEvidenceByID[snapshot.EvidenceID] = evidence
		}
		s.mu.Unlock()
	}
}

func (s *MemoryService) rewardReadyForFinalization(ctx context.Context, reward RewardIssue) (RewardIssue, bool) {
	reward.SettlementReferenceID = strings.TrimSpace(reward.SettlementReferenceID)
	reward.TrafficProofRef = canonicalObjectiveEvidenceRef(reward.TrafficProofRef)

	s.mu.Lock()
	chainRewardSubmissionConfigured := s.blockchainMode || adapterRequiresRewardProofReference(s.adapter) || adapterRequiresRewardProofReference(s.shadowAdapter)
	if !chainRewardSubmissionConfigured {
		s.mu.Unlock()
		return reward, true
	}
	settlementReferenceValid := true
	if reward.SettlementReferenceID != "" {
		settlement, ok := s.settledBySession[reward.SessionID]
		settlementReferenceValid = ok &&
			rewardSettlementReference(settlement) == reward.SettlementReferenceID &&
			settlement.Status == OperationStatusConfirmed
	}
	verifier := s.rewardProofVerifierLocked()
	s.mu.Unlock()

	if !settlementReferenceValid {
		return reward, false
	}
	if !isStrongRewardTrafficProofRef(reward.TrafficProofRef) {
		return reward, false
	}
	if rewardTrafficProofVerified(reward) {
		return reward, true
	}
	verification, err := verifyRewardTrafficProof(ctx, verifier, reward)
	if err != nil {
		return reward, false
	}
	applyRewardProofVerification(&reward, verification)
	return reward, true
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

func priceMicrosForBytes(bytes int64, pricePerMiBMicros int64) (int64, error) {
	if bytes <= 0 || pricePerMiBMicros <= 0 {
		return 0, nil
	}
	const mebibyte = int64(1024 * 1024)

	wholeMiB := bytes / mebibyte
	remainderBytes := bytes % mebibyte

	wholeCharge, err := checkedMulInt64(wholeMiB, pricePerMiBMicros)
	if err != nil {
		return 0, fmt.Errorf("settlement charge overflow")
	}
	remainderProduct, err := checkedMulInt64(remainderBytes, pricePerMiBMicros)
	if err != nil {
		return 0, fmt.Errorf("settlement charge overflow")
	}
	remainderCharge := remainderProduct / mebibyte

	charge, err := checkedAddInt64(wholeCharge, remainderCharge)
	if err != nil {
		return 0, fmt.Errorf("settlement charge overflow")
	}
	return charge, nil
}

func checkedAddInt64(a int64, b int64) (int64, error) {
	if b > 0 && a > math.MaxInt64-b {
		return 0, fmt.Errorf("int64 overflow")
	}
	if b < 0 && a < math.MinInt64-b {
		return 0, fmt.Errorf("int64 overflow")
	}
	return a + b, nil
}

func checkedMulInt64(a int64, b int64) (int64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if (a == -1 && b == math.MinInt64) || (b == -1 && a == math.MinInt64) {
		return 0, fmt.Errorf("int64 overflow")
	}
	product := a * b
	if product/a != b {
		return 0, fmt.Errorf("int64 overflow")
	}
	return product, nil
}

func (s *MemoryService) ensureSessionSubjectConsistencyLocked(sessionID string, subjectID string) error {
	if inFlight, ok := s.reservationsInFlight[sessionID]; ok {
		if strings.TrimSpace(inFlight.reservation.SubjectID) != subjectID {
			return sessionSubjectMismatchError(sessionID)
		}
	}
	if reservation, ok := s.reservationsBySession[sessionID]; ok {
		if strings.TrimSpace(reservation.SubjectID) != subjectID {
			return sessionSubjectMismatchError(sessionID)
		}
	}
	if settlement, ok := s.settledBySession[sessionID]; ok {
		if strings.TrimSpace(settlement.SubjectID) != subjectID {
			return sessionSubjectMismatchError(sessionID)
		}
	}
	return ensureUsageRecordsSubject(sessionID, subjectID, s.usageBySession[sessionID])
}

func normalizeRewardPayoutPeriod(reward *RewardIssue) (bool, error) {
	if reward == nil {
		return false, nil
	}
	hasStart := !reward.PayoutPeriodStart.IsZero()
	hasEnd := !reward.PayoutPeriodEnd.IsZero()
	if !hasStart && !hasEnd {
		return false, nil
	}

	start := reward.PayoutPeriodStart.UTC().Round(0)
	end := reward.PayoutPeriodEnd.UTC().Round(0)
	if hasStart && !hasEnd {
		end = start.Add(weeklyRewardPayoutPeriod)
	}
	if !hasStart && hasEnd {
		start = end.Add(-weeklyRewardPayoutPeriod)
	}
	if !start.Before(end) {
		return false, fmt.Errorf("issue reward requires payout period start before end")
	}
	if end.Sub(start) != weeklyRewardPayoutPeriod {
		return false, fmt.Errorf("issue reward requires weekly payout period duration")
	}
	if !isWeeklyPayoutPeriodStart(start) {
		return false, fmt.Errorf("issue reward requires payout period to start at Monday 00:00 UTC")
	}

	reward.PayoutPeriodStart = start
	reward.PayoutPeriodEnd = end
	return true, nil
}

func isWeeklyPayoutPeriodStart(t time.Time) bool {
	t = t.UTC()
	return t.Weekday() == time.Monday &&
		t.Hour() == 0 &&
		t.Minute() == 0 &&
		t.Second() == 0 &&
		t.Nanosecond() == 0
}

func rewardWeeklyPayoutKey(reward RewardIssue) rewardPayoutKey {
	return rewardPayoutKey{
		ProviderSubjectID: reward.ProviderSubjectID,
		PeriodStart:       reward.PayoutPeriodStart.UTC().Format(time.RFC3339),
		PeriodEnd:         reward.PayoutPeriodEnd.UTC().Format(time.RFC3339),
	}
}

func rewardSettlementReference(settlement SessionSettlement) string {
	if ref := strings.TrimSpace(settlement.SettlementID); ref != "" {
		return ref
	}
	if ref := strings.TrimSpace(settlement.AdapterReferenceID); ref != "" {
		return ref
	}
	return strings.TrimSpace(settlement.ReservationID)
}

func ensureUsageRecordsSubject(sessionID string, subjectID string, records []UsageRecord) error {
	for _, record := range records {
		if strings.TrimSpace(record.SubjectID) != subjectID {
			return sessionSubjectMismatchError(sessionID)
		}
	}
	return nil
}

func sessionSubjectMismatchError(sessionID string) error {
	return fmt.Errorf("session subject mismatch for session %s", sessionID)
}

func sessionAlreadySettledError(sessionID string) error {
	return fmt.Errorf("session already settled for session %s", sessionID)
}

func idempotencyConflictError(recordType string, id string) error {
	return fmt.Errorf("%s idempotency conflict for id %s", recordType, id)
}

func sessionSettlementChainMaterialEqual(a SessionSettlement, b SessionSettlement) bool {
	return strings.TrimSpace(a.SettlementID) == strings.TrimSpace(b.SettlementID) &&
		strings.TrimSpace(a.ReservationID) == strings.TrimSpace(b.ReservationID) &&
		strings.TrimSpace(a.SessionID) == strings.TrimSpace(b.SessionID) &&
		strings.TrimSpace(a.SubjectID) == strings.TrimSpace(b.SubjectID) &&
		a.ChargedMicros == b.ChargedMicros &&
		strings.EqualFold(strings.TrimSpace(a.Currency), strings.TrimSpace(b.Currency)) &&
		chainTimeUnixSecondEqual(a.SettledAt, b.SettledAt)
}

func enrichSessionSettlementChainMaterial(local SessionSettlement, reservation FundReservation, chain SessionSettlement) SessionSettlement {
	if strings.TrimSpace(chain.SubjectID) == "" &&
		strings.TrimSpace(reservation.ReservationID) != "" &&
		strings.TrimSpace(local.ReservationID) == strings.TrimSpace(reservation.ReservationID) {
		chain.SubjectID = strings.TrimSpace(reservation.SubjectID)
	}
	return chain
}

func fundReservationChainMaterialEqual(a FundReservation, b FundReservation) bool {
	return strings.TrimSpace(a.ReservationID) == strings.TrimSpace(b.ReservationID) &&
		strings.TrimSpace(a.SessionID) == strings.TrimSpace(b.SessionID) &&
		strings.TrimSpace(a.SubjectID) == strings.TrimSpace(b.SubjectID) &&
		a.AmountMicros == b.AmountMicros &&
		strings.EqualFold(strings.TrimSpace(a.Currency), strings.TrimSpace(b.Currency))
}

func chainTimeUnixSecondEqual(local time.Time, chain time.Time) bool {
	if local.IsZero() {
		return true
	}
	if chain.IsZero() {
		return false
	}
	return local.UTC().Unix() == chain.UTC().Unix()
}

func rewardIssueChainMaterialEqual(a RewardIssue, b RewardIssue) bool {
	return strings.TrimSpace(a.RewardID) == strings.TrimSpace(b.RewardID) &&
		strings.TrimSpace(a.ProviderSubjectID) == strings.TrimSpace(b.ProviderSubjectID) &&
		strings.TrimSpace(a.SessionID) == strings.TrimSpace(b.SessionID) &&
		strings.TrimSpace(a.SettlementReferenceID) == strings.TrimSpace(b.SettlementReferenceID) &&
		canonicalObjectiveEvidenceRef(a.TrafficProofRef) == canonicalObjectiveEvidenceRef(b.TrafficProofRef) &&
		chainTimeUnixSecondEqual(a.PayoutPeriodStart, b.PayoutPeriodStart) &&
		chainTimeUnixSecondEqual(a.PayoutPeriodEnd, b.PayoutPeriodEnd) &&
		a.RewardMicros == b.RewardMicros &&
		strings.EqualFold(strings.TrimSpace(a.Currency), strings.TrimSpace(b.Currency)) &&
		chainTimeUnixSecondEqual(a.IssuedAt, b.IssuedAt)
}

func rewardIssueMaterialEqual(a RewardIssue, b RewardIssue) bool {
	return a.RewardID == b.RewardID &&
		a.ProviderSubjectID == b.ProviderSubjectID &&
		a.SessionID == b.SessionID &&
		a.SettlementReferenceID == b.SettlementReferenceID &&
		a.TrafficProofRef == b.TrafficProofRef &&
		a.PayoutPeriodStart.Equal(b.PayoutPeriodStart) &&
		a.PayoutPeriodEnd.Equal(b.PayoutPeriodEnd) &&
		a.RewardMicros == b.RewardMicros &&
		a.Currency == b.Currency &&
		a.IssuedAt.Equal(b.IssuedAt)
}

func sponsorReservationMaterialEqual(a SponsorCreditReservation, b SponsorCreditReservation) bool {
	return a.ReservationID == b.ReservationID &&
		a.SponsorID == b.SponsorID &&
		a.SubjectID == b.SubjectID &&
		a.SessionID == b.SessionID &&
		a.AmountMicros == b.AmountMicros &&
		a.Currency == b.Currency &&
		a.CreatedAt.Equal(b.CreatedAt) &&
		a.ExpiresAt.Equal(b.ExpiresAt)
}

func sponsorReservationChainMaterialEqual(a SponsorCreditReservation, b SponsorCreditReservation) bool {
	return strings.TrimSpace(a.ReservationID) == strings.TrimSpace(b.ReservationID) &&
		strings.TrimSpace(a.SponsorID) == strings.TrimSpace(b.SponsorID) &&
		strings.TrimSpace(a.SubjectID) == strings.TrimSpace(b.SubjectID) &&
		strings.TrimSpace(a.SessionID) == strings.TrimSpace(b.SessionID) &&
		a.AmountMicros == b.AmountMicros &&
		strings.EqualFold(strings.TrimSpace(a.Currency), strings.TrimSpace(b.Currency)) &&
		chainTimeUnixSecondEqual(a.CreatedAt, b.CreatedAt) &&
		chainTimeUnixSecondEqual(a.ExpiresAt, b.ExpiresAt) &&
		chainOptionalTimeUnixSecondEqual(a.ConsumedAt, b.ConsumedAt)
}

func chainOptionalTimeUnixSecondEqual(a time.Time, b time.Time) bool {
	if a.IsZero() || b.IsZero() {
		return a.IsZero() && b.IsZero()
	}
	return a.UTC().Unix() == b.UTC().Unix()
}

func slashEvidenceMaterialEqual(a SlashEvidence, b SlashEvidence) bool {
	return a.EvidenceID == b.EvidenceID &&
		a.SubjectID == b.SubjectID &&
		a.SessionID == b.SessionID &&
		strings.EqualFold(a.ViolationType, b.ViolationType) &&
		a.EvidenceRef == b.EvidenceRef &&
		a.SlashMicros == b.SlashMicros &&
		a.Currency == b.Currency &&
		a.ObservedAt.Equal(b.ObservedAt)
}

func slashEvidenceChainMaterialEqual(a SlashEvidence, b SlashEvidence) bool {
	return strings.TrimSpace(a.EvidenceID) == strings.TrimSpace(b.EvidenceID) &&
		strings.TrimSpace(a.SubjectID) == strings.TrimSpace(b.SubjectID) &&
		strings.TrimSpace(a.SessionID) == strings.TrimSpace(b.SessionID) &&
		strings.EqualFold(strings.TrimSpace(a.ViolationType), strings.TrimSpace(b.ViolationType)) &&
		canonicalObjectiveEvidenceRef(a.EvidenceRef) == canonicalObjectiveEvidenceRef(unwrapBridgeSlashEvidenceRef(b.EvidenceRef)) &&
		a.SlashMicros == b.SlashMicros &&
		strings.EqualFold(strings.TrimSpace(a.Currency), strings.TrimSpace(b.Currency)) &&
		chainTimeUnixSecondEqual(a.ObservedAt, b.ObservedAt)
}

func unwrapBridgeSlashEvidenceRef(raw string) string {
	raw = strings.TrimSpace(raw)
	if !strings.HasPrefix(raw, "obj://settlement-slash/") {
		return raw
	}
	parsed, err := urlpkg.Parse(raw)
	if err != nil {
		return raw
	}
	evidenceRef := strings.TrimSpace(parsed.Query().Get("evidence_ref"))
	if evidenceRef == "" {
		return raw
	}
	return evidenceRef
}

func slashEvidenceIncidentKey(e SlashEvidence) string {
	subjectID := strings.TrimSpace(e.SubjectID)
	sessionID := strings.TrimSpace(e.SessionID)
	violationType := strings.ToLower(strings.TrimSpace(e.ViolationType))
	evidenceRef := canonicalObjectiveEvidenceRef(e.EvidenceRef)
	if subjectID == "" || violationType == "" || evidenceRef == "" {
		return ""
	}
	return strings.Join([]string{subjectID, sessionID, violationType, evidenceRef}, "\x00")
}

func canonicalObjectiveEvidenceRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "sha256:") {
		sum := strings.TrimPrefix(ref, "sha256:")
		if len(sum) == 64 {
			return "sha256:" + strings.ToLower(sum)
		}
	}
	return ref
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
	if strings.HasPrefix(ref, "obj://") {
		path := strings.TrimSpace(strings.TrimPrefix(ref, "obj://"))
		if path == "" {
			return false
		}
		if strings.ContainsAny(path, " \t\r\n") {
			return false
		}
		return true
	}
	if !strings.HasPrefix(ref, "sha256:") {
		return false
	}
	sum := strings.TrimPrefix(ref, "sha256:")
	if len(sum) != 64 {
		return false
	}
	for _, ch := range sum {
		switch {
		case ch >= '0' && ch <= '9':
		case ch >= 'a' && ch <= 'f':
		case ch >= 'A' && ch <= 'F':
		default:
			return false
		}
	}
	return true
}

func isStrongRewardTrafficProofRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if !strings.HasPrefix(ref, "obj://") {
		return false
	}
	path := strings.TrimSpace(strings.TrimPrefix(ref, "obj://"))
	return path != "" && !strings.ContainsAny(path, " \t\r\n")
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
