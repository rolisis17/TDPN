package settlement

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeAdapter struct {
	fail bool
}

func (f fakeAdapter) SubmitSessionSettlement(_ context.Context, _ SessionSettlement) (string, error) {
	if f.fail {
		return "", errFakeAdapter
	}
	return "chain-set-1", nil
}

func (f fakeAdapter) SubmitRewardIssue(_ context.Context, _ RewardIssue) (string, error) {
	if f.fail {
		return "", errFakeAdapter
	}
	return "chain-rew-1", nil
}

func (f fakeAdapter) SubmitSponsorReservation(_ context.Context, _ SponsorCreditReservation) (string, error) {
	if f.fail {
		return "", errFakeAdapter
	}
	return "chain-sponsor-res-1", nil
}

func (f fakeAdapter) SubmitSlashEvidence(_ context.Context, _ SlashEvidence) (string, error) {
	if f.fail {
		return "", errFakeAdapter
	}
	return "chain-slash-1", nil
}

func (f fakeAdapter) Health(_ context.Context) error {
	if f.fail {
		return errFakeAdapter
	}
	return nil
}

var errFakeAdapter = &fakeErr{"adapter-fail"}

type fakeErr struct {
	msg string
}

func (e *fakeErr) Error() string {
	return e.msg
}

type switchableAdapter struct {
	mu                 sync.Mutex
	fail               bool
	sessionSubmitCalls int
}

func (a *switchableAdapter) setFail(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = v
}

func (a *switchableAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	a.mu.Lock()
	a.sessionSubmitCalls++
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-set-" + settlement.SessionID, nil
}

func (a *switchableAdapter) SubmitRewardIssue(_ context.Context, _ RewardIssue) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-rew-ok", nil
}

func (a *switchableAdapter) SubmitSponsorReservation(_ context.Context, _ SponsorCreditReservation) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-sponsor-res-ok", nil
}

func (a *switchableAdapter) SubmitSlashEvidence(_ context.Context, _ SlashEvidence) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-slash-ok", nil
}

func (a *switchableAdapter) Health(_ context.Context) error {
	return nil
}

func (a *switchableAdapter) settlementCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionSubmitCalls
}

type confirmingAdapter struct{}

func (a confirmingAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	return "chain-set-" + settlement.SessionID, nil
}

func (a confirmingAdapter) SubmitRewardIssue(_ context.Context, reward RewardIssue) (string, error) {
	return "chain-rew-" + reward.RewardID, nil
}

func (a confirmingAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	return "chain-sponsor-" + reservation.ReservationID, nil
}

func (a confirmingAdapter) SubmitSlashEvidence(_ context.Context, evidence SlashEvidence) (string, error) {
	return "chain-slash-" + evidence.EvidenceID, nil
}

func (a confirmingAdapter) Health(_ context.Context) error { return nil }

func (a confirmingAdapter) HasSessionSettlement(_ context.Context, settlementID string) (bool, error) {
	return settlementID != "", nil
}

func (a confirmingAdapter) HasRewardIssue(_ context.Context, rewardID string) (bool, error) {
	return rewardID != "", nil
}

func (a confirmingAdapter) HasSponsorReservation(_ context.Context, reservationID string) (bool, error) {
	return reservationID != "", nil
}

func (a confirmingAdapter) HasSlashEvidence(_ context.Context, evidenceID string) (bool, error) {
	return evidenceID != "", nil
}

func setupDeferredSettlement(t *testing.T, s *MemoryService, sessionID string) {
	t.Helper()
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    "client-" + sessionID,
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	err = s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-" + sessionID,
		BytesIngress: 1024 * 1024,
		RecordedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if !settlement.AdapterDeferred {
		t.Fatalf("expected deferred settlement for session %s", sessionID)
	}
}

func TestMemoryServiceSettleIdempotent(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1024 * 1024))
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-1",
		SubjectID:    "client-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	err = s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-1",
		SubjectID:    "client-1",
		BytesIngress: 1024 * 1024,
		BytesEgress:  0,
		RecordedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlementA, err := s.SettleSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("SettleSession first: %v", err)
	}
	settlementB, err := s.SettleSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("SettleSession second: %v", err)
	}
	if settlementA.SettlementID != settlementB.SettlementID {
		t.Fatalf("expected same settlement id, got %s vs %s", settlementA.SettlementID, settlementB.SettlementID)
	}
	if !settlementB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on second settle")
	}
}

func TestMemoryServiceAdapterDeferredOnFailure(t *testing.T) {
	s := NewMemoryService(WithChainAdapter(fakeAdapter{fail: true}))
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-2",
		SubjectID:    "client-2",
		AmountMicros: 10_000,
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-2",
		SubjectID:    "client-2",
		BytesIngress: 1024,
		BytesEgress:  1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-2")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if !settlement.AdapterDeferred {
		t.Fatalf("expected adapter deferred settlement on adapter failure")
	}
	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-1",
		ProviderSubjectID: "provider-1",
		SessionID:         "sess-2",
		RewardMicros:      50,
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if !reward.AdapterDeferred {
		t.Fatalf("expected adapter deferred reward on adapter failure")
	}
	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-1",
		SponsorID:     "sponsor-1",
		SubjectID:     "client-2",
		SessionID:     "sess-2",
		AmountMicros:  100,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if !reservation.AdapterDeferred {
		t.Fatalf("expected adapter deferred sponsor reservation on adapter failure")
	}
	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-1",
		SubjectID:     "provider-1",
		SessionID:     "sess-2",
		ViolationType: "double-sign",
		EvidenceRef:   "obj://validator/double-sign/sess-2",
		SlashMicros:   7,
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if !evidence.AdapterDeferred {
		t.Fatalf("expected adapter deferred slash evidence on adapter failure")
	}
	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 4 {
		t.Fatalf("expected pending adapter operations 4, got %d", report.PendingAdapterOperations)
	}
	if len(s.deferredAdapterOps) != 4 {
		t.Fatalf("expected deferred backlog entries 4, got %d", len(s.deferredAdapterOps))
	}
}

func TestMemoryServiceReconcileReplaySuccessClearsBacklog(t *testing.T) {
	adapter := &switchableAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-1")
	ctx := context.Background()

	before, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile before recovery: %v", err)
	}
	if before.PendingAdapterOperations != 1 {
		t.Fatalf("expected 1 deferred operation before recovery, got %d", before.PendingAdapterOperations)
	}

	adapter.setFail(false)
	after, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile after recovery: %v", err)
	}
	if after.PendingAdapterOperations != 0 {
		t.Fatalf("expected deferred backlog to clear after replay, got %d pending", after.PendingAdapterOperations)
	}

	s.mu.Lock()
	settlement := s.settledBySession["sess-replay-1"]
	s.mu.Unlock()
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected settlement status submitted after replay, got %s", settlement.Status)
	}
	if !settlement.AdapterSubmitted || settlement.AdapterDeferred {
		t.Fatalf("expected settlement adapter state submitted=true deferred=false after replay")
	}
}

func TestMemoryServiceReconcileReplayIsIdempotentAcrossRepeatedCalls(t *testing.T) {
	adapter := &switchableAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-2")
	ctx := context.Background()

	adapter.setFail(false)
	first, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile first: %v", err)
	}
	second, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile second: %v", err)
	}
	if first.PendingAdapterOperations != 0 || second.PendingAdapterOperations != 0 {
		t.Fatalf("expected no pending operations after successful replay, got first=%d second=%d",
			first.PendingAdapterOperations, second.PendingAdapterOperations)
	}
	if gotCalls := adapter.settlementCalls(); gotCalls != 2 {
		t.Fatalf("expected exactly two settlement submissions (initial fail + single replay), got %d", gotCalls)
	}
}

func TestMemoryServiceReconcileMarksSubmittedAsConfirmedWhenQueryable(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(confirmingAdapter{}),
	)
	ctx := context.Background()

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-confirm-1",
		SubjectID:    "client-confirm-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-confirm-1",
		SubjectID:    "client-confirm-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if _, err := s.SettleSession(ctx, "sess-confirm-1"); err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if _, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-confirm-1",
		ProviderSubjectID: "provider-confirm-1",
		SessionID:         "sess-confirm-1",
		RewardMicros:      25,
		Currency:          "TDPNC",
	}); err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if _, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-confirm-1",
		SponsorID:     "sponsor-confirm-1",
		SubjectID:     "client-confirm-1",
		SessionID:     "sess-confirm-1",
		AmountMicros:  100,
		Currency:      "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-confirm-1",
		SubjectID:     "provider-confirm-1",
		SessionID:     "sess-confirm-1",
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:abcd1234",
		SlashMicros:   11,
		Currency:      "TDPNC",
	}); err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}

	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations < 4 {
		t.Fatalf("expected at least four confirmed operations, got %d", report.ConfirmedOperations)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if got := s.settledBySession["sess-confirm-1"].Status; got != OperationStatusConfirmed {
		t.Fatalf("expected settlement confirmed, got %s", got)
	}
	if got := s.rewardsByID["rew-confirm-1"].Status; got != OperationStatusConfirmed {
		t.Fatalf("expected reward confirmed, got %s", got)
	}
	if got := s.sponsorReservationsByID["sres-confirm-1"].Status; got != OperationStatusConfirmed {
		t.Fatalf("expected sponsor reservation confirmed, got %s", got)
	}
	if got := s.slashEvidenceByID["ev-confirm-1"].Status; got != OperationStatusConfirmed {
		t.Fatalf("expected slash evidence confirmed, got %s", got)
	}
}

func TestMemoryServiceSponsorFlowAuthorizeIdempotent(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-2",
		SponsorID:     "sponsor-2",
		SubjectID:     "client-22",
		SessionID:     "sess-22",
		AmountMicros:  333,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	authA, err := s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-2",
		SponsorID:     "sponsor-2",
		SubjectID:     "client-22",
		SessionID:     "sess-22",
	})
	if err != nil {
		t.Fatalf("AuthorizePayment first: %v", err)
	}
	authB, err := s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-2",
		SponsorID:     "sponsor-2",
		SubjectID:     "client-22",
		SessionID:     "sess-22",
	})
	if err != nil {
		t.Fatalf("AuthorizePayment second: %v", err)
	}
	if authA.ReservationID != authB.ReservationID {
		t.Fatalf("expected same reservation id on idempotent auth, got %s vs %s", authA.ReservationID, authB.ReservationID)
	}
	if !authB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on second authorize")
	}
}

func TestMemoryServiceQuotePriceCurrencyConversion(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1000),
		WithCurrency("USDC"),
		WithCurrencyRate("TDPN", 2, 1),
	)
	ctx := context.Background()
	quote, err := s.QuotePrice(ctx, "client-1", "TDPN")
	if err != nil {
		t.Fatalf("QuotePrice: %v", err)
	}
	if quote.Currency != "TDPN" {
		t.Fatalf("expected TDPN quote currency, got %s", quote.Currency)
	}
	if quote.PricePerMiBMicros != 2000 {
		t.Fatalf("expected converted quote price 2000, got %d", quote.PricePerMiBMicros)
	}
}

func TestMemoryServiceSettleSessionCurrencyConversion(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1_000_000),
		WithCurrency("USDC"),
		WithCurrencyRate("TDPN", 2, 1),
	)
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-conv-1",
		SubjectID:    "client-conv-1",
		AmountMicros: 2100000,
		Currency:     "TDPN",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-conv-1",
		SubjectID:    "client-conv-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-conv-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Currency != "TDPN" {
		t.Fatalf("expected settlement currency TDPN, got %s", settlement.Currency)
	}
	if settlement.ChargedMicros != 2_000_000 {
		t.Fatalf("expected converted charge 2000000, got %d", settlement.ChargedMicros)
	}
}

func TestMemoryServiceDualAssetSessionEntitlementEquivalence(t *testing.T) {
	const (
		pricePerMiBMicros = int64(1_000_000) // 1.0 unit per MiB in base settlement currency.
		usageBytes        = int64(2 * 1024 * 1024)
	)

	s := NewMemoryService(
		WithPricePerMiBMicros(pricePerMiBMicros),
		WithCurrency("USDC"),
		WithCurrencyRate("TDPN", 2, 1), // 1 USDC micro == 2 TDPN micros.
	)
	ctx := context.Background()

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-eq-usdc-ok",
		SubjectID:    "client-eq-usdc-ok",
		AmountMicros: 2_000_000,
		Currency:     "USDC",
	}); err != nil {
		t.Fatalf("ReserveFunds usdc success case: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-eq-usdc-ok",
		SubjectID:    "client-eq-usdc-ok",
		BytesIngress: usageBytes,
	}); err != nil {
		t.Fatalf("RecordUsage usdc success case: %v", err)
	}
	usdcSettlement, err := s.SettleSession(ctx, "sess-eq-usdc-ok")
	if err != nil {
		t.Fatalf("SettleSession usdc success case: %v", err)
	}

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-eq-tdpn-ok",
		SubjectID:    "client-eq-tdpn-ok",
		AmountMicros: 4_000_000,
		Currency:     "TDPN",
	}); err != nil {
		t.Fatalf("ReserveFunds tdpn success case: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-eq-tdpn-ok",
		SubjectID:    "client-eq-tdpn-ok",
		BytesIngress: usageBytes,
	}); err != nil {
		t.Fatalf("RecordUsage tdpn success case: %v", err)
	}
	tdpnSettlement, err := s.SettleSession(ctx, "sess-eq-tdpn-ok")
	if err != nil {
		t.Fatalf("SettleSession tdpn success case: %v", err)
	}

	if usdcSettlement.ChargedMicros != 2_000_000 {
		t.Fatalf("expected USDC charged micros 2000000, got %d", usdcSettlement.ChargedMicros)
	}
	if tdpnSettlement.ChargedMicros != 4_000_000 {
		t.Fatalf("expected TDPN charged micros 4000000, got %d", tdpnSettlement.ChargedMicros)
	}

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-eq-usdc-fail",
		SubjectID:    "client-eq-usdc-fail",
		AmountMicros: 1_999_999,
		Currency:     "USDC",
	}); err != nil {
		t.Fatalf("ReserveFunds usdc insufficient case: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-eq-usdc-fail",
		SubjectID:    "client-eq-usdc-fail",
		BytesIngress: usageBytes,
	}); err != nil {
		t.Fatalf("RecordUsage usdc insufficient case: %v", err)
	}
	if _, err := s.SettleSession(ctx, "sess-eq-usdc-fail"); err == nil {
		t.Fatalf("expected USDC insufficient reservation to fail")
	}

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-eq-tdpn-fail",
		SubjectID:    "client-eq-tdpn-fail",
		AmountMicros: 3_999_999,
		Currency:     "TDPN",
	}); err != nil {
		t.Fatalf("ReserveFunds tdpn insufficient case: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-eq-tdpn-fail",
		SubjectID:    "client-eq-tdpn-fail",
		BytesIngress: usageBytes,
	}); err != nil {
		t.Fatalf("RecordUsage tdpn insufficient case: %v", err)
	}
	if _, err := s.SettleSession(ctx, "sess-eq-tdpn-fail"); err == nil {
		t.Fatalf("expected TDPN insufficient reservation to fail")
	}
}

func TestMemoryServiceSubmitSlashEvidenceRequiresObjectiveSchema(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-bad-1",
		SubjectID:     "provider-1",
		ViolationType: "manual-review-only",
		EvidenceRef:   "obj://evidence/manual",
		SlashMicros:   1,
	}); err == nil {
		t.Fatalf("expected non-objective violation type to fail")
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-bad-2",
		SubjectID:     "provider-1",
		ViolationType: "double-sign",
		EvidenceRef:   "manual-note://not-verifiable",
		SlashMicros:   1,
	}); err == nil {
		t.Fatalf("expected non-objective evidence ref to fail")
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-good-1",
		SubjectID:     "provider-1",
		ViolationType: "double-sign",
		EvidenceRef:   "obj://validator/double-sign/block-12",
		SlashMicros:   1,
	}); err != nil {
		t.Fatalf("expected objective slash evidence to pass: %v", err)
	}
}
