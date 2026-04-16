package settlement

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
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

func testSHA256Ref(seed string) string {
	const alphabet = "0123456789abcdef"
	if seed == "" {
		seed = "seed"
	}
	out := make([]byte, 64)
	for i := 0; i < len(out); i++ {
		out[i] = alphabet[int(seed[i%len(seed)])%len(alphabet)]
	}
	return "sha256:" + string(out)
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

type replayConfirmingAdapter struct {
	mu                 sync.Mutex
	fail               bool
	sessionSubmitCalls int
}

func (a *replayConfirmingAdapter) setFail(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = v
}

func (a *replayConfirmingAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	a.mu.Lock()
	a.sessionSubmitCalls++
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-set-" + settlement.SessionID, nil
}

func (a *replayConfirmingAdapter) SubmitRewardIssue(_ context.Context, _ RewardIssue) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-rew-ok", nil
}

func (a *replayConfirmingAdapter) SubmitSponsorReservation(_ context.Context, _ SponsorCreditReservation) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-sponsor-res-ok", nil
}

func (a *replayConfirmingAdapter) SubmitSlashEvidence(_ context.Context, _ SlashEvidence) (string, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-slash-ok", nil
}

func (a *replayConfirmingAdapter) Health(_ context.Context) error { return nil }

func (a *replayConfirmingAdapter) HasSessionSettlement(_ context.Context, settlementID string) (bool, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	return !fail && settlementID != "", nil
}

func (a *replayConfirmingAdapter) HasRewardIssue(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a *replayConfirmingAdapter) HasSponsorReservation(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a *replayConfirmingAdapter) HasSlashEvidence(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a *replayConfirmingAdapter) settlementCalls() int {
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

type notFoundConfirmingAdapter struct{ confirmingAdapter }

func (a notFoundConfirmingAdapter) HasSessionSettlement(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a notFoundConfirmingAdapter) HasRewardIssue(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a notFoundConfirmingAdapter) HasSponsorReservation(_ context.Context, _ string) (bool, error) {
	return false, nil
}

func (a notFoundConfirmingAdapter) HasSlashEvidence(_ context.Context, _ string) (bool, error) {
	return false, nil
}

type errorConfirmingAdapter struct{ confirmingAdapter }

func (a errorConfirmingAdapter) HasSessionSettlement(_ context.Context, _ string) (bool, error) {
	return false, errFakeAdapter
}

func (a errorConfirmingAdapter) HasRewardIssue(_ context.Context, _ string) (bool, error) {
	return false, errFakeAdapter
}

func (a errorConfirmingAdapter) HasSponsorReservation(_ context.Context, _ string) (bool, error) {
	return false, errFakeAdapter
}

func (a errorConfirmingAdapter) HasSlashEvidence(_ context.Context, _ string) (bool, error) {
	return false, errFakeAdapter
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

func setupSettledSessionForShadowTests(t *testing.T, s *MemoryService, sessionID string) SessionSettlement {
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
	return settlement
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

func TestMemoryServiceShadowAdapterSuccessRecordsOutcome(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(fakeAdapter{}),
		WithShadowChainAdapter(fakeAdapter{}),
	)
	settlement := setupSettledSessionForShadowTests(t, s, "sess-shadow-success-1")
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected primary settlement status submitted, got %s", settlement.Status)
	}
	if !settlement.ShadowAdapterSubmitted {
		t.Fatalf("expected shadow adapter submission marker")
	}
	if settlement.ShadowAdapterStatus != OperationStatusSubmitted {
		t.Fatalf("expected shadow adapter status submitted, got %s", settlement.ShadowAdapterStatus)
	}
	if settlement.ShadowAdapterLastAttemptAt.IsZero() {
		t.Fatalf("expected shadow adapter attempt timestamp")
	}
	if settlement.ShadowAdapterReferenceID == "" {
		t.Fatalf("expected shadow adapter reference id")
	}
	if settlement.ShadowAdapterLastError != "" {
		t.Fatalf("expected empty shadow adapter error, got %q", settlement.ShadowAdapterLastError)
	}
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !report.ShadowAdapterConfigured {
		t.Fatalf("expected shadow adapter configured marker")
	}
	if report.ShadowAttemptedOperations != 1 || report.ShadowSubmittedOperations != 1 || report.ShadowFailedOperations != 0 {
		t.Fatalf("unexpected shadow report counts attempted=%d submitted=%d failed=%d",
			report.ShadowAttemptedOperations, report.ShadowSubmittedOperations, report.ShadowFailedOperations)
	}
}

func TestMemoryServiceShadowAdapterFailureDoesNotAffectPrimaryPath(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(fakeAdapter{}),
		WithShadowChainAdapter(fakeAdapter{fail: true}),
	)
	settlement := setupSettledSessionForShadowTests(t, s, "sess-shadow-fail-1")
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected primary settlement status submitted, got %s", settlement.Status)
	}
	if settlement.AdapterDeferred {
		t.Fatalf("expected primary adapter not deferred when primary succeeds")
	}
	if settlement.ShadowAdapterSubmitted {
		t.Fatalf("expected shadow adapter submission to be marked failed")
	}
	if settlement.ShadowAdapterStatus != OperationStatusFailed {
		t.Fatalf("expected shadow adapter status failed, got %s", settlement.ShadowAdapterStatus)
	}
	if settlement.ShadowAdapterLastAttemptAt.IsZero() {
		t.Fatalf("expected shadow adapter attempt timestamp")
	}
	if settlement.ShadowAdapterLastError == "" {
		t.Fatalf("expected shadow adapter error")
	}
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected no primary deferred backlog, got %d", report.PendingAdapterOperations)
	}
	if report.ShadowAttemptedOperations != 1 || report.ShadowSubmittedOperations != 0 || report.ShadowFailedOperations != 1 {
		t.Fatalf("unexpected shadow report counts attempted=%d submitted=%d failed=%d",
			report.ShadowAttemptedOperations, report.ShadowSubmittedOperations, report.ShadowFailedOperations)
	}
}

func TestMemoryServiceShadowAdapterNotConfiguredLeavesShadowMetadataEmpty(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(fakeAdapter{}),
	)
	settlement := setupSettledSessionForShadowTests(t, s, "sess-shadow-none-1")
	if settlement.ShadowAdapterSubmitted {
		t.Fatalf("expected no shadow submission marker when shadow adapter is not configured")
	}
	if !settlement.ShadowAdapterLastAttemptAt.IsZero() {
		t.Fatalf("expected zero shadow adapter attempt timestamp")
	}
	if settlement.ShadowAdapterReferenceID != "" {
		t.Fatalf("expected empty shadow adapter reference id when unconfigured")
	}
	if settlement.ShadowAdapterStatus != "" {
		t.Fatalf("expected empty shadow adapter status when unconfigured, got %s", settlement.ShadowAdapterStatus)
	}
	if settlement.ShadowAdapterLastError != "" {
		t.Fatalf("expected empty shadow adapter error when unconfigured")
	}
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ShadowAdapterConfigured {
		t.Fatalf("expected shadow adapter configured marker false")
	}
	if report.ShadowAttemptedOperations != 0 || report.ShadowSubmittedOperations != 0 || report.ShadowFailedOperations != 0 {
		t.Fatalf("expected empty shadow report counts attempted=%d submitted=%d failed=%d",
			report.ShadowAttemptedOperations, report.ShadowSubmittedOperations, report.ShadowFailedOperations)
	}
}

func TestMemoryServicePrimaryFailureStillDefersWhenShadowSucceeds(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(fakeAdapter{fail: true}),
		WithShadowChainAdapter(fakeAdapter{}),
	)
	settlement := setupSettledSessionForShadowTests(t, s, "sess-shadow-primary-fail-1")
	if settlement.Status != OperationStatusPending {
		t.Fatalf("expected primary settlement pending when primary adapter fails, got %s", settlement.Status)
	}
	if !settlement.AdapterDeferred || settlement.AdapterSubmitted {
		t.Fatalf("expected primary deferred marker when primary adapter fails")
	}
	if !settlement.ShadowAdapterSubmitted || settlement.ShadowAdapterStatus != OperationStatusSubmitted {
		t.Fatalf("expected successful shadow submission despite primary failure")
	}
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 1 {
		t.Fatalf("expected primary deferred backlog to remain 1, got %d", report.PendingAdapterOperations)
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

func TestMemoryServiceReconcileReplayFailureMarksFailedAndRetainsBacklog(t *testing.T) {
	adapter := &switchableAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-fail-1")
	ctx := context.Background()

	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile with persistent adapter failure: %v", err)
	}
	if report.PendingAdapterOperations != 1 {
		t.Fatalf("expected deferred backlog to remain 1 after failed replay, got %d", report.PendingAdapterOperations)
	}
	if report.FailedOperations < 1 {
		t.Fatalf("expected at least one failed operation after failed replay, got %d", report.FailedOperations)
	}

	s.mu.Lock()
	settlement := s.settledBySession["sess-replay-fail-1"]
	deferredOp, hasDeferredOp := s.deferredAdapterOps["settlement:set-sess-replay-fail-1"]
	s.mu.Unlock()

	if settlement.Status != OperationStatusFailed {
		t.Fatalf("expected settlement status failed after failed replay, got %s", settlement.Status)
	}
	if !settlement.AdapterDeferred || settlement.AdapterSubmitted {
		t.Fatalf("expected settlement adapter state deferred=true submitted=false after failed replay")
	}
	if !hasDeferredOp {
		t.Fatalf("expected deferred operation to remain after failed replay")
	}
	if deferredOp.Attempts < 2 {
		t.Fatalf("expected deferred operation attempts >= 2 (initial submit + replay), got %d", deferredOp.Attempts)
	}
	if gotCalls := adapter.settlementCalls(); gotCalls != 2 {
		t.Fatalf("expected exactly two settlement submissions (initial fail + replay fail), got %d", gotCalls)
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

func TestMemoryServiceReconcileReplayPromotesToConfirmedWhenQuerierAvailable(t *testing.T) {
	adapter := &replayConfirmingAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-confirm-1")
	ctx := context.Background()

	adapter.setFail(false)
	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected deferred backlog cleared after replay, got %d", report.PendingAdapterOperations)
	}
	if report.ConfirmedOperations < 1 {
		t.Fatalf("expected at least one confirmed operation after replay+query, got %d", report.ConfirmedOperations)
	}

	s.mu.Lock()
	settlement := s.settledBySession["sess-replay-confirm-1"]
	s.mu.Unlock()
	if settlement.Status != OperationStatusConfirmed {
		t.Fatalf("expected settlement confirmed after replay+query, got %s", settlement.Status)
	}
	if !settlement.AdapterSubmitted || settlement.AdapterDeferred {
		t.Fatalf("expected adapter state submitted=true deferred=false after replay+query")
	}
	if gotCalls := adapter.settlementCalls(); gotCalls != 2 {
		t.Fatalf("expected exactly two settlement submissions (initial fail + single replay), got %d", gotCalls)
	}
}

func TestMemoryServiceCosmosAdapterAsyncFailureAfterEnqueueReplaysAndConfirms(t *testing.T) {
	var failWrites atomic.Bool
	failWrites.Store(true)

	var submittedMu sync.Mutex
	submittedSettlementByID := map[string]struct{}{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/x/vpnbilling/settlements":
			var settlement SessionSettlement
			if err := json.NewDecoder(r.Body).Decode(&settlement); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if failWrites.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			submittedMu.Lock()
			submittedSettlementByID[settlement.SettlementID] = struct{}{}
			submittedMu.Unlock()
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/x/vpnbilling/settlements/"):
			settlementID := strings.TrimPrefix(r.URL.Path, "/x/vpnbilling/settlements/")
			submittedMu.Lock()
			_, ok := submittedSettlementByID[settlementID]
			submittedMu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	adapter, err := NewCosmosAdapter(CosmosAdapterConfig{
		Endpoint:    srv.URL,
		QueueSize:   8,
		MaxRetries:  0,
		BaseBackoff: 10 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("NewCosmosAdapter: %v", err)
	}
	defer adapter.Close()

	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	ctx := context.Background()

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-cosmos-adapter-replay-1",
		SubjectID:    "client-cosmos-adapter-replay-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-cosmos-adapter-replay-1",
		SubjectID:    "client-cosmos-adapter-replay-1",
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-cosmos-adapter-replay-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected fail-soft settlement submit status submitted, got %s", settlement.Status)
	}
	if settlement.AdapterDeferred {
		t.Fatalf("expected fail-soft async adapter path to avoid immediate deferred state")
	}

	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 1
	}, "adapter deferred backlog after async failure")
	reportWithDeferred, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile with async adapter deferred backlog: %v", err)
	}
	if reportWithDeferred.PendingAdapterOperations < 1 {
		t.Fatalf("expected reconcile report pending adapter operations >= 1 while adapter backlog exists, got %d", reportWithDeferred.PendingAdapterOperations)
	}

	failWrites.Store(false)
	waitForCondition(t, 2*time.Second, func() bool {
		return adapter.deferredOperationCount() == 0
	}, "adapter deferred backlog replay clear")

	waitForCondition(t, 3*time.Second, func() bool {
		_, err := s.Reconcile(ctx)
		if err != nil {
			return false
		}
		s.mu.Lock()
		current := s.settledBySession["sess-cosmos-adapter-replay-1"]
		s.mu.Unlock()
		return current.Status == OperationStatusConfirmed && current.AdapterSubmitted && !current.AdapterDeferred
	}, "memory reconcile confirmation after async replay")
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
		EvidenceRef:   testSHA256Ref("ev-confirm-1"),
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

func setupSubmittedConfirmationRecords(t *testing.T, s *MemoryService, suffix string) (string, string, string, string) {
	t.Helper()
	ctx := context.Background()

	sessionID := "sess-confirm-" + suffix
	subjectID := "client-confirm-" + suffix
	rewardID := "rew-confirm-" + suffix
	sponsorReservationID := "sres-confirm-" + suffix
	evidenceID := "ev-confirm-" + suffix

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	}); err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected settlement submitted before reconcile confirmation checks, got %s", settlement.Status)
	}

	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          rewardID,
		ProviderSubjectID: "provider-" + suffix,
		SessionID:         sessionID,
		RewardMicros:      25,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if reward.Status != OperationStatusSubmitted {
		t.Fatalf("expected reward submitted before reconcile confirmation checks, got %s", reward.Status)
	}

	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: sponsorReservationID,
		SponsorID:     "sponsor-" + suffix,
		SubjectID:     subjectID,
		SessionID:     sessionID,
		AmountMicros:  100,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != OperationStatusSubmitted {
		t.Fatalf("expected sponsor reservation submitted before reconcile confirmation checks, got %s", reservation.Status)
	}

	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    evidenceID,
		SubjectID:     "provider-" + suffix,
		SessionID:     sessionID,
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref(suffix),
		SlashMicros:   11,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if evidence.Status != OperationStatusSubmitted {
		t.Fatalf("expected slash evidence submitted before reconcile confirmation checks, got %s", evidence.Status)
	}

	return sessionID, rewardID, sponsorReservationID, evidenceID
}

func assertSubmittedConfirmationRecords(t *testing.T, s *MemoryService, sessionID string, rewardID string, sponsorReservationID string, evidenceID string) {
	t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()

	settlement := s.settledBySession[sessionID]
	if settlement.Status != OperationStatusSubmitted {
		t.Fatalf("expected settlement to remain submitted, got %s", settlement.Status)
	}
	if !settlement.AdapterSubmitted || settlement.AdapterDeferred {
		t.Fatalf("expected settlement adapter state submitted=true deferred=false")
	}

	reward := s.rewardsByID[rewardID]
	if reward.Status != OperationStatusSubmitted {
		t.Fatalf("expected reward to remain submitted, got %s", reward.Status)
	}
	if !reward.AdapterSubmitted || reward.AdapterDeferred {
		t.Fatalf("expected reward adapter state submitted=true deferred=false")
	}

	reservation := s.sponsorReservationsByID[sponsorReservationID]
	if reservation.Status != OperationStatusSubmitted {
		t.Fatalf("expected sponsor reservation to remain submitted, got %s", reservation.Status)
	}
	if !reservation.AdapterSubmitted || reservation.AdapterDeferred {
		t.Fatalf("expected sponsor reservation adapter state submitted=true deferred=false")
	}

	evidence := s.slashEvidenceByID[evidenceID]
	if evidence.Status != OperationStatusSubmitted {
		t.Fatalf("expected slash evidence to remain submitted, got %s", evidence.Status)
	}
	if !evidence.AdapterSubmitted || evidence.AdapterDeferred {
		t.Fatalf("expected slash evidence adapter state submitted=true deferred=false")
	}
}

func TestMemoryServiceReconcileKeepsSubmittedWhenConfirmationNotFound(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(notFoundConfirmingAdapter{}),
	)
	sessionID, rewardID, sponsorReservationID, evidenceID := setupSubmittedConfirmationRecords(t, s, "not-found-1")

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 0 {
		t.Fatalf("expected no confirmed operations when lookups return not found, got %d", report.ConfirmedOperations)
	}
	if report.SubmittedOperations < 4 {
		t.Fatalf("expected at least four submitted operations, got %d", report.SubmittedOperations)
	}

	assertSubmittedConfirmationRecords(t, s, sessionID, rewardID, sponsorReservationID, evidenceID)
}

func TestMemoryServiceReconcileKeepsSubmittedWhenConfirmationLookupErrors(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(errorConfirmingAdapter{}),
	)
	sessionID, rewardID, sponsorReservationID, evidenceID := setupSubmittedConfirmationRecords(t, s, "lookup-error-1")

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.ConfirmedOperations != 0 {
		t.Fatalf("expected no confirmed operations when lookups return errors, got %d", report.ConfirmedOperations)
	}
	if report.SubmittedOperations < 4 {
		t.Fatalf("expected at least four submitted operations, got %d", report.SubmittedOperations)
	}

	assertSubmittedConfirmationRecords(t, s, sessionID, rewardID, sponsorReservationID, evidenceID)
}

func TestMemoryServiceGetSponsorReservationReturnsStoredReservationByID(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()

	stored, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-get-1",
		SponsorID:     "sponsor-get-1",
		SubjectID:     "client-get-1",
		SessionID:     "sess-get-1",
		AmountMicros:  777,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	got, err := s.GetSponsorReservation(ctx, "sres-get-1")
	if err != nil {
		t.Fatalf("GetSponsorReservation: %v", err)
	}
	if got.ReservationID != stored.ReservationID {
		t.Fatalf("expected reservation id %s, got %s", stored.ReservationID, got.ReservationID)
	}
	if got.SponsorID != stored.SponsorID {
		t.Fatalf("expected sponsor id %s, got %s", stored.SponsorID, got.SponsorID)
	}
	if got.SubjectID != stored.SubjectID {
		t.Fatalf("expected subject id %s, got %s", stored.SubjectID, got.SubjectID)
	}
	if got.SessionID != stored.SessionID {
		t.Fatalf("expected session id %s, got %s", stored.SessionID, got.SessionID)
	}
	if got.AmountMicros != stored.AmountMicros {
		t.Fatalf("expected amount_micros %d, got %d", stored.AmountMicros, got.AmountMicros)
	}
	if got.Currency != stored.Currency {
		t.Fatalf("expected currency %s, got %s", stored.Currency, got.Currency)
	}
	if got.Status != stored.Status {
		t.Fatalf("expected status %s, got %s", stored.Status, got.Status)
	}
	if got.CreatedAt.IsZero() {
		t.Fatalf("expected created_at to be set")
	}
	if got.ExpiresAt.IsZero() {
		t.Fatalf("expected expires_at to be set")
	}
}

func TestMemoryServiceGetSponsorReservationNotFoundReturnsErrorContract(t *testing.T) {
	s := NewMemoryService()

	_, err := s.GetSponsorReservation(context.Background(), "sres-missing-1")
	if err == nil {
		t.Fatalf("expected unknown reservation lookup to fail")
	}
	if err.Error() != "reservation not found: sres-missing-1" {
		t.Fatalf("unexpected error for unknown reservation lookup: %v", err)
	}
}

func TestMemoryServiceGetSponsorReservationStatusPersistsAfterConsumeAndSessionSettle(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	sessionID := "sess-sponsor-status-1"

	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-status-1",
		SponsorID:     "sponsor-status-1",
		SubjectID:     "client-status-1",
		SessionID:     sessionID,
		AmountMicros:  1500,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	beforeConsume, err := s.GetSponsorReservation(ctx, "sres-status-1")
	if err != nil {
		t.Fatalf("GetSponsorReservation before consume: %v", err)
	}
	if beforeConsume.Status != OperationStatusConfirmed {
		t.Fatalf("expected pre-consume status confirmed, got %s", beforeConsume.Status)
	}
	if !beforeConsume.ConsumedAt.IsZero() {
		t.Fatalf("expected pre-consume consumed_at to be zero")
	}

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-status-1",
		SponsorID:     "sponsor-status-1",
		SubjectID:     "client-status-1",
		SessionID:     sessionID,
	})
	if err != nil {
		t.Fatalf("AuthorizePayment: %v", err)
	}

	afterConsume, err := s.GetSponsorReservation(ctx, "sres-status-1")
	if err != nil {
		t.Fatalf("GetSponsorReservation after consume: %v", err)
	}
	if afterConsume.Status != OperationStatusConfirmed {
		t.Fatalf("expected post-consume status confirmed, got %s", afterConsume.Status)
	}
	if afterConsume.ConsumedAt.IsZero() {
		t.Fatalf("expected post-consume consumed_at to be set")
	}

	_, err = s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    "client-status-1",
		AmountMicros: 10_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-status-1",
		BytesIngress: 1024 * 1024,
		RecordedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	if _, err := s.SettleSession(ctx, sessionID); err != nil {
		t.Fatalf("SettleSession: %v", err)
	}

	afterSettle, err := s.GetSponsorReservation(ctx, "sres-status-1")
	if err != nil {
		t.Fatalf("GetSponsorReservation after settle: %v", err)
	}
	if afterSettle.Status != afterConsume.Status {
		t.Fatalf("expected sponsor status to persist after settle; got %s want %s", afterSettle.Status, afterConsume.Status)
	}
	if !afterSettle.ConsumedAt.Equal(afterConsume.ConsumedAt) {
		t.Fatalf("expected consumed_at to persist after settle")
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

func TestMemoryServiceAuthorizePaymentRequiresReservationID(t *testing.T) {
	s := NewMemoryService()
	_, err := s.AuthorizePayment(context.Background(), PaymentProof{
		ReservationID: "   ",
		SponsorID:     "sponsor-1",
		SubjectID:     "client-1",
		SessionID:     "sess-1",
	})
	if err == nil {
		t.Fatalf("expected missing reservation_id to fail")
	}
	if err.Error() != "authorize payment requires reservation_id" {
		t.Fatalf("unexpected error for missing reservation_id: %v", err)
	}
}

func TestMemoryServiceAuthorizePaymentReservationNotFound(t *testing.T) {
	s := NewMemoryService()
	_, err := s.AuthorizePayment(context.Background(), PaymentProof{
		ReservationID: "sres-missing-1",
		SponsorID:     "sponsor-missing-1",
		SubjectID:     "client-missing-1",
		SessionID:     "sess-missing-1",
	})
	if err == nil {
		t.Fatalf("expected unknown reservation to fail")
	}
	if err.Error() != "reservation not found: sres-missing-1" {
		t.Fatalf("unexpected error for unknown reservation: %v", err)
	}
}

func TestMemoryServiceAuthorizePaymentRejectsProofFieldMismatches(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-mismatch-1",
		SponsorID:     "sponsor-good-1",
		SubjectID:     "client-good-1",
		SessionID:     "sess-good-1",
		AmountMicros:  700,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	testCases := []struct {
		name    string
		proof   PaymentProof
		wantErr string
	}{
		{
			name: "sponsor mismatch",
			proof: PaymentProof{
				ReservationID: "sres-mismatch-1",
				SponsorID:     "sponsor-bad-1",
				SubjectID:     "client-good-1",
				SessionID:     "sess-good-1",
			},
			wantErr: "reservation sponsor mismatch",
		},
		{
			name: "subject mismatch",
			proof: PaymentProof{
				ReservationID: "sres-mismatch-1",
				SponsorID:     "sponsor-good-1",
				SubjectID:     "client-bad-1",
				SessionID:     "sess-good-1",
			},
			wantErr: "reservation subject mismatch",
		},
		{
			name: "session mismatch",
			proof: PaymentProof{
				ReservationID: "sres-mismatch-1",
				SponsorID:     "sponsor-good-1",
				SubjectID:     "client-good-1",
				SessionID:     "sess-bad-1",
			},
			wantErr: "reservation session mismatch",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.AuthorizePayment(ctx, tc.proof)
			if err == nil {
				t.Fatalf("expected authorize mismatch to fail")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("unexpected authorize mismatch error: got %v want %s", err, tc.wantErr)
			}
		})
	}
}

func TestMemoryServiceAuthorizePaymentRejectsExpiredReservation(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	createdAt := time.Now().UTC().Add(-15 * time.Minute)
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-expired-1",
		SponsorID:     "sponsor-expired-1",
		SubjectID:     "client-expired-1",
		SessionID:     "sess-expired-1",
		AmountMicros:  500,
		CreatedAt:     createdAt,
		ExpiresAt:     createdAt.Add(1 * time.Minute),
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-expired-1",
		SponsorID:     "sponsor-expired-1",
		SubjectID:     "client-expired-1",
		SessionID:     "sess-expired-1",
	})
	if err == nil {
		t.Fatalf("expected expired reservation to fail authorization")
	}
	if err.Error() != "reservation expired: sres-expired-1" {
		t.Fatalf("unexpected error for expired reservation: %v", err)
	}
}

func TestMemoryServiceAuthorizePaymentRejectsConsumedReservationWithoutPriorAuthRecord(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-consumed-1",
		SponsorID:     "sponsor-consumed-1",
		SubjectID:     "client-consumed-1",
		SessionID:     "sess-consumed-1",
		AmountMicros:  444,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	s.mu.Lock()
	reservation := s.sponsorReservationsByID["sres-consumed-1"]
	reservation.ConsumedAt = time.Now().UTC().Add(-time.Minute)
	s.sponsorReservationsByID["sres-consumed-1"] = reservation
	delete(s.paymentAuthByReservationID, "sres-consumed-1")
	s.mu.Unlock()

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-consumed-1",
		SponsorID:     "sponsor-consumed-1",
		SubjectID:     "client-consumed-1",
		SessionID:     "sess-consumed-1",
	})
	if err == nil {
		t.Fatalf("expected consumed reservation to fail authorization")
	}
	if err.Error() != "reservation already consumed: sres-consumed-1" {
		t.Fatalf("unexpected error for consumed reservation: %v", err)
	}
}

func TestMemoryServiceAuthorizePaymentDuplicateProofReplayPreservesIdempotency(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-replay-1",
		SponsorID:     "sponsor-replay-1",
		SubjectID:     "client-replay-1",
		SessionID:     "sess-replay-1",
		AmountMicros:  333,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	authA, err := s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-replay-1",
		SponsorID:     "sponsor-replay-1",
		SubjectID:     "client-replay-1",
		SessionID:     "sess-replay-1",
	})
	if err != nil {
		t.Fatalf("AuthorizePayment first: %v", err)
	}

	authB, err := s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-replay-1",
		SponsorID:     "sponsor-other",
		SubjectID:     "client-other",
		SessionID:     "sess-other",
	})
	if err != nil {
		t.Fatalf("AuthorizePayment duplicate replay: %v", err)
	}
	if !authB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on duplicate proof")
	}
	if authA.ReservationID != authB.ReservationID || authA.SponsorID != authB.SponsorID || authA.SubjectID != authB.SubjectID || authA.SessionID != authB.SessionID {
		t.Fatalf("expected replay authorization to return original authorization identity")
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
		EvidenceID:    "ev-bad-3",
		SubjectID:     "provider-1",
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:abcd1234",
		SlashMicros:   1,
	}); err == nil {
		t.Fatalf("expected short sha256 evidence ref to fail")
	}
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-bad-4",
		SubjectID:     "provider-1",
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
		SlashMicros:   1,
	}); err == nil {
		t.Fatalf("expected non-hex sha256 evidence ref to fail")
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
	if _, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-good-2",
		SubjectID:     "provider-1",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("ev-good-2"),
		SlashMicros:   1,
	}); err != nil {
		t.Fatalf("expected sha256 objective slash evidence to pass: %v", err)
	}
}
