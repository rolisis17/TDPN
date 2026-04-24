package settlement

import (
	"context"
	"encoding/json"
	"math"
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

type statusCapturingReplayAdapter struct {
	mu                 sync.Mutex
	failFirst          bool
	settlementStatuses []OperationStatus
}

func (a *statusCapturingReplayAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	a.mu.Lock()
	a.settlementStatuses = append(a.settlementStatuses, settlement.Status)
	call := len(a.settlementStatuses)
	fail := a.failFirst && call == 1
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-set-" + settlement.SessionID, nil
}

func (a *statusCapturingReplayAdapter) SubmitRewardIssue(_ context.Context, _ RewardIssue) (string, error) {
	return "chain-rew-ok", nil
}

func (a *statusCapturingReplayAdapter) SubmitSponsorReservation(_ context.Context, _ SponsorCreditReservation) (string, error) {
	return "chain-sponsor-res-ok", nil
}

func (a *statusCapturingReplayAdapter) SubmitSlashEvidence(_ context.Context, _ SlashEvidence) (string, error) {
	return "chain-slash-ok", nil
}

func (a *statusCapturingReplayAdapter) Health(_ context.Context) error {
	return nil
}

func (a *statusCapturingReplayAdapter) settlementStatusesSnapshot() []OperationStatus {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]OperationStatus(nil), a.settlementStatuses...)
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

type multiOperationReplayAdapter struct {
	mu                 sync.Mutex
	fail               bool
	sessionSubmitCalls int
	rewardSubmitCalls  int
	sponsorSubmitCalls int
	slashEvidenceCalls int
}

func (a *multiOperationReplayAdapter) setFail(v bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.fail = v
}

func (a *multiOperationReplayAdapter) SubmitSessionSettlement(_ context.Context, settlement SessionSettlement) (string, error) {
	a.mu.Lock()
	a.sessionSubmitCalls++
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-set-" + settlement.SessionID, nil
}

func (a *multiOperationReplayAdapter) SubmitRewardIssue(_ context.Context, reward RewardIssue) (string, error) {
	a.mu.Lock()
	a.rewardSubmitCalls++
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-rew-" + reward.RewardID, nil
}

func (a *multiOperationReplayAdapter) SubmitSponsorReservation(_ context.Context, reservation SponsorCreditReservation) (string, error) {
	a.mu.Lock()
	a.sponsorSubmitCalls++
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-sponsor-res-" + reservation.ReservationID, nil
}

func (a *multiOperationReplayAdapter) SubmitSlashEvidence(_ context.Context, evidence SlashEvidence) (string, error) {
	a.mu.Lock()
	a.slashEvidenceCalls++
	fail := a.fail
	a.mu.Unlock()
	if fail {
		return "", errFakeAdapter
	}
	return "chain-slash-" + evidence.EvidenceID, nil
}

func (a *multiOperationReplayAdapter) Health(_ context.Context) error { return nil }

func (a *multiOperationReplayAdapter) HasSessionSettlement(_ context.Context, settlementID string) (bool, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	return !fail && settlementID != "", nil
}

func (a *multiOperationReplayAdapter) HasRewardIssue(_ context.Context, rewardID string) (bool, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	return !fail && strings.TrimSpace(rewardID) != "", nil
}

func (a *multiOperationReplayAdapter) HasSponsorReservation(_ context.Context, reservationID string) (bool, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	return !fail && strings.TrimSpace(reservationID) != "", nil
}

func (a *multiOperationReplayAdapter) HasSlashEvidence(_ context.Context, evidenceID string) (bool, error) {
	a.mu.Lock()
	fail := a.fail
	a.mu.Unlock()
	return !fail && strings.TrimSpace(evidenceID) != "", nil
}

func (a *multiOperationReplayAdapter) settlementCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sessionSubmitCalls
}

func (a *multiOperationReplayAdapter) rewardCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.rewardSubmitCalls
}

func (a *multiOperationReplayAdapter) sponsorCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sponsorSubmitCalls
}

func (a *multiOperationReplayAdapter) slashCalls() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.slashEvidenceCalls
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

func setupDeferredNonSettlementOperations(t *testing.T, s *MemoryService, suffix string) (string, string, string, string, string) {
	t.Helper()
	ctx := context.Background()

	sessionID := "sess-replay-" + suffix
	rewardID := "rew-replay-" + suffix
	reservationID := "sres-replay-" + suffix
	evidenceID := "ev-replay-" + suffix
	slashSubjectID := "provider-" + suffix

	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          rewardID,
		ProviderSubjectID: "provider-" + suffix,
		SessionID:         sessionID,
		RewardMicros:      33,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if !reward.AdapterDeferred {
		t.Fatalf("expected deferred reward for %s", rewardID)
	}

	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: reservationID,
		SponsorID:     "sponsor-" + suffix,
		SubjectID:     "client-" + suffix,
		SessionID:     sessionID,
		AmountMicros:  150,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if !reservation.AdapterDeferred {
		t.Fatalf("expected deferred sponsor reservation for %s", reservationID)
	}

	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    evidenceID,
		SubjectID:     slashSubjectID,
		SessionID:     sessionID,
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("replay-" + suffix),
		SlashMicros:   9,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if !evidence.AdapterDeferred {
		t.Fatalf("expected deferred slash evidence for %s", evidenceID)
	}

	return sessionID, rewardID, reservationID, evidenceID, slashSubjectID
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

func TestMemoryServiceSessionSubjectConsistencyRejectsMismatches(t *testing.T) {
	ctx := context.Background()

	t.Run("record usage rejects mismatch with existing reservation subject", func(t *testing.T) {
		s := NewMemoryService()
		const (
			sessionID        = "sess-subject-mismatch-record-1"
			reservationSubj  = "client-subject-good-1"
			recordUsageSubj  = "client-subject-bad-1"
			reservationFunds = int64(10_000)
		)

		if _, err := s.ReserveFunds(ctx, FundReservation{
			SessionID:    sessionID,
			SubjectID:    reservationSubj,
			AmountMicros: reservationFunds,
			Currency:     "TDPNC",
		}); err != nil {
			t.Fatalf("ReserveFunds: %v", err)
		}
		err := s.RecordUsage(ctx, UsageRecord{
			SessionID:    sessionID,
			SubjectID:    recordUsageSubj,
			BytesIngress: 1024,
		})
		if err == nil {
			t.Fatalf("expected mismatched usage subject to fail")
		}
		if !strings.Contains(err.Error(), "session subject mismatch for session "+sessionID) {
			t.Fatalf("unexpected mismatch error: %v", err)
		}
	})

	t.Run("reserve funds rejects mismatch with existing usage subject", func(t *testing.T) {
		s := NewMemoryService()
		const (
			sessionID       = "sess-subject-mismatch-reservation-1"
			usageSubject    = "client-subject-good-2"
			reserveSubject  = "client-subject-bad-2"
			reservationFund = int64(20_000)
		)

		if err := s.RecordUsage(ctx, UsageRecord{
			SessionID:    sessionID,
			SubjectID:    usageSubject,
			BytesIngress: 1024,
		}); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}
		_, err := s.ReserveFunds(ctx, FundReservation{
			SessionID:    sessionID,
			SubjectID:    reserveSubject,
			AmountMicros: reservationFund,
			Currency:     "TDPNC",
		})
		if err == nil {
			t.Fatalf("expected mismatched reservation subject to fail")
		}
		if !strings.Contains(err.Error(), "session subject mismatch for session "+sessionID) {
			t.Fatalf("unexpected mismatch error: %v", err)
		}
	})

	t.Run("reserve sponsor credits rejects mismatch with existing usage subject", func(t *testing.T) {
		s := NewMemoryService()
		const (
			sessionID                = "sess-subject-mismatch-sponsor-reservation-1"
			usageSubject             = "client-subject-good-2a"
			sponsorProofSubj         = "client-subject-bad-2a"
			sponsorReserveID         = "sres-subject-mismatch-sponsor-reservation-1"
			sponsorReservationAmount = int64(20_000)
		)

		if err := s.RecordUsage(ctx, UsageRecord{
			SessionID:    sessionID,
			SubjectID:    usageSubject,
			BytesIngress: 1024,
		}); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}
		_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
			ReservationID: sponsorReserveID,
			SponsorID:     "sponsor-subject-mismatch-2a",
			SubjectID:     sponsorProofSubj,
			SessionID:     sessionID,
			AmountMicros:  sponsorReservationAmount,
			Currency:      "TDPNC",
		})
		if err == nil {
			t.Fatalf("expected mismatched sponsor reservation subject to fail")
		}
		if !strings.Contains(err.Error(), "session subject mismatch for session "+sessionID) {
			t.Fatalf("unexpected mismatch error: %v", err)
		}

		s.mu.Lock()
		_, ok := s.sponsorReservationsByID[sponsorReserveID]
		s.mu.Unlock()
		if ok {
			t.Fatalf("expected mismatched sponsor reservation to not be stored")
		}
	})

	t.Run("settle session rejects mixed usage subjects fail closed", func(t *testing.T) {
		s := NewMemoryService(WithPricePerMiBMicros(1024 * 1024))
		const (
			sessionID      = "sess-subject-mismatch-settle-1"
			sessionSubject = "client-subject-good-3"
		)

		if _, err := s.ReserveFunds(ctx, FundReservation{
			SessionID:    sessionID,
			SubjectID:    sessionSubject,
			AmountMicros: 3_000_000,
			Currency:     "TDPNC",
		}); err != nil {
			t.Fatalf("ReserveFunds: %v", err)
		}
		if err := s.RecordUsage(ctx, UsageRecord{
			SessionID:    sessionID,
			SubjectID:    sessionSubject,
			BytesIngress: 1024 * 1024,
		}); err != nil {
			t.Fatalf("RecordUsage: %v", err)
		}

		s.mu.Lock()
		s.usageBySession[sessionID] = append(s.usageBySession[sessionID], UsageRecord{
			SessionID:    sessionID,
			SubjectID:    "client-subject-bad-3",
			BytesIngress: 1024,
		})
		s.mu.Unlock()

		_, err := s.SettleSession(ctx, sessionID)
		if err == nil {
			t.Fatalf("expected mixed subject usage to fail settlement")
		}
		if !strings.Contains(err.Error(), "session subject mismatch for session "+sessionID) {
			t.Fatalf("unexpected settle mismatch error: %v", err)
		}
	})
}

func TestMemoryServiceSessionSubjectConsistencyValidLifecycle(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1_000_000))
	ctx := context.Background()
	const (
		sessionID = "sess-subject-consistent-valid-1"
		subjectID = "client-subject-consistent-valid-1"
	)

	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		BytesIngress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage first: %v", err)
	}

	reservationA, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 3_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds first: %v", err)
	}
	reservationB, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 9_999_999,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds second: %v", err)
	}
	if reservationA.ReservationID != reservationB.ReservationID {
		t.Fatalf("expected idempotent reservation replay for consistent subject")
	}

	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:   sessionID,
		SubjectID:   subjectID,
		BytesEgress: 1024 * 1024,
	}); err != nil {
		t.Fatalf("RecordUsage second: %v", err)
	}

	settlement, err := s.SettleSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.SubjectID != subjectID {
		t.Fatalf("expected settlement subject %s, got %s", subjectID, settlement.SubjectID)
	}
	if settlement.ChargedMicros != 2_000_000 {
		t.Fatalf("expected charged micros 2000000, got %d", settlement.ChargedMicros)
	}
}

func TestMemoryServiceSessionSubjectConsistencyRejectsUsageAndReserveFundsAfterSettlement(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1_000_000))
	ctx := context.Background()
	const (
		sessionID = "sess-settled-write-reject-1"
		subjectID = "client-settled-write-reject-1"
	)

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
	if _, err := s.SettleSession(ctx, sessionID); err != nil {
		t.Fatalf("SettleSession: %v", err)
	}

	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		BytesIngress: 1024,
	}); err == nil {
		t.Fatalf("expected RecordUsage on settled session to fail closed")
	} else if !strings.Contains(err.Error(), "session already settled for session "+sessionID) {
		t.Fatalf("unexpected RecordUsage error: %v", err)
	}

	if _, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    subjectID,
		AmountMicros: 10_000,
		Currency:     "TDPNC",
	}); err == nil {
		t.Fatalf("expected ReserveFunds on settled session to fail closed")
	} else if !strings.Contains(err.Error(), "session already settled for session "+sessionID) {
		t.Fatalf("unexpected ReserveFunds error: %v", err)
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

func TestMemoryServiceBlockchainModeWithoutAdapterFailsClosed(t *testing.T) {
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithBlockchainMode(true),
	)
	ctx := context.Background()

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-blockchain-no-adapter-1",
		SubjectID:    "client-blockchain-no-adapter-1",
		AmountMicros: 10_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-blockchain-no-adapter-1",
		SubjectID:    "client-blockchain-no-adapter-1",
		BytesIngress: 1024,
		BytesEgress:  1024,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-blockchain-no-adapter-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Status != OperationStatusPending {
		t.Fatalf("expected pending settlement status when blockchain mode has no adapter, got %s", settlement.Status)
	}
	if !settlement.AdapterDeferred || settlement.AdapterSubmitted {
		t.Fatalf("expected settlement adapter state deferred=true submitted=false when adapter is missing")
	}
	settlementRef := cosmosID("settlement", settlement.SettlementID, settlement.SessionID)
	if settlement.AdapterReferenceID != settlementRef {
		t.Fatalf("expected settlement adapter reference id %s, got %s", settlementRef, settlement.AdapterReferenceID)
	}

	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-blockchain-no-adapter-1",
		ProviderSubjectID: "provider-blockchain-no-adapter-1",
		SessionID:         "sess-blockchain-no-adapter-1",
		RewardMicros:      50,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if reward.Status != OperationStatusPending || !reward.AdapterDeferred || reward.AdapterSubmitted {
		t.Fatalf("expected reward pending+deferred when blockchain mode has no adapter")
	}
	rewardRef := cosmosID("reward", reward.RewardID, reward.SessionID)
	if reward.AdapterReferenceID != rewardRef {
		t.Fatalf("expected reward adapter reference id %s, got %s", rewardRef, reward.AdapterReferenceID)
	}

	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-blockchain-no-adapter-1",
		SponsorID:     "sponsor-blockchain-no-adapter-1",
		SubjectID:     "client-blockchain-no-adapter-1",
		SessionID:     "sess-blockchain-no-adapter-1",
		AmountMicros:  100,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != OperationStatusPending || !reservation.AdapterDeferred || reservation.AdapterSubmitted {
		t.Fatalf("expected sponsor reservation pending+deferred when blockchain mode has no adapter")
	}
	reservationRef := cosmosID("sponsor-reservation", reservation.ReservationID, reservation.SessionID)
	if reservation.AdapterReferenceID != reservationRef {
		t.Fatalf("expected reservation adapter reference id %s, got %s", reservationRef, reservation.AdapterReferenceID)
	}
	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: reservation.ReservationID,
		SponsorID:     reservation.SponsorID,
		SubjectID:     reservation.SubjectID,
		SessionID:     reservation.SessionID,
	})
	if err == nil {
		t.Fatalf("expected authorize payment to fail for pending deferred reservation in blockchain mode")
	}
	if err.Error() != "reservation pending chain submission: sres-blockchain-no-adapter-1" {
		t.Fatalf("unexpected authorize payment error for pending deferred reservation: %v", err)
	}

	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-blockchain-no-adapter-1",
		SubjectID:     "provider-blockchain-no-adapter-1",
		SessionID:     "sess-blockchain-no-adapter-1",
		ViolationType: "double-sign",
		EvidenceRef:   "obj://validator/double-sign/sess-blockchain-no-adapter-1",
		SlashMicros:   7,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if evidence.Status != OperationStatusPending || !evidence.AdapterDeferred || evidence.AdapterSubmitted {
		t.Fatalf("expected slash evidence pending+deferred when blockchain mode has no adapter")
	}
	evidenceRef := cosmosID("slash", evidence.EvidenceID, evidence.SubjectID)
	if evidence.AdapterReferenceID != evidenceRef {
		t.Fatalf("expected slash evidence adapter reference id %s, got %s", evidenceRef, evidence.AdapterReferenceID)
	}

	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 4 {
		t.Fatalf("expected pending adapter operations 4 when adapter is missing in blockchain mode, got %d", report.PendingAdapterOperations)
	}
	if report.PendingOperations != 4 {
		t.Fatalf("expected pending operations 4 when adapter is missing in blockchain mode, got %d", report.PendingOperations)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	storedReservation := s.sponsorReservationsByID["sres-blockchain-no-adapter-1"]
	if storedReservation.Status != OperationStatusPending || !storedReservation.AdapterDeferred || storedReservation.AdapterSubmitted {
		t.Fatalf("expected pending deferred sponsor reservation to remain unchanged after failed authorize")
	}
	if !storedReservation.ConsumedAt.IsZero() {
		t.Fatalf("expected pending deferred sponsor reservation to remain unconsumed after failed authorize")
	}
	if _, ok := s.paymentAuthByReservationID["sres-blockchain-no-adapter-1"]; ok {
		t.Fatalf("expected no payment authorization record for pending deferred sponsor reservation")
	}
	if len(s.deferredAdapterOps) != 4 {
		t.Fatalf("expected deferred backlog entries 4, got %d", len(s.deferredAdapterOps))
	}
	for _, idempotencyKey := range []string{settlementRef, rewardRef, reservationRef, evidenceRef} {
		op, ok := s.deferredAdapterOps[idempotencyKey]
		if !ok {
			t.Fatalf("expected deferred operation for %s", idempotencyKey)
		}
		if op.LastError != errChainAdapterNotConfigured.Error() {
			t.Fatalf("expected deferred operation error %q for %s, got %q", errChainAdapterNotConfigured.Error(), idempotencyKey, op.LastError)
		}
	}
}

func TestMemoryServiceAuthorizePaymentRequiresFinalizedStateInBlockchainMode(t *testing.T) {
	s := NewMemoryService(WithBlockchainMode(true))
	ctx := context.Background()

	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-deferred-states-1",
		SponsorID:     "sponsor-deferred-states-1",
		SubjectID:     "client-deferred-states-1",
		SessionID:     "sess-deferred-states-1",
		AmountMicros:  100,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != OperationStatusPending || !reservation.AdapterDeferred || reservation.AdapterSubmitted {
		t.Fatalf("expected initial blockchain-mode reservation to be pending+deferred")
	}

	proof := PaymentProof{
		ReservationID: reservation.ReservationID,
		SponsorID:     reservation.SponsorID,
		SubjectID:     reservation.SubjectID,
		SessionID:     reservation.SessionID,
	}

	testCases := []struct {
		name             string
		status           OperationStatus
		adapterDeferred  bool
		adapterSubmitted bool
		wantErr          string
	}{
		{
			name:             "pending deferred",
			status:           OperationStatusPending,
			adapterDeferred:  true,
			adapterSubmitted: false,
			wantErr:          "reservation pending chain submission: sres-deferred-states-1",
		},
		{
			name:             "failed deferred",
			status:           OperationStatusFailed,
			adapterDeferred:  true,
			adapterSubmitted: false,
			wantErr:          "reservation not chain-finalized: sres-deferred-states-1",
		},
		{
			name:             "submitted deferred",
			status:           OperationStatusSubmitted,
			adapterDeferred:  true,
			adapterSubmitted: true,
			wantErr:          "reservation not chain-finalized: sres-deferred-states-1",
		},
		{
			name:             "submitted non-deferred",
			status:           OperationStatusSubmitted,
			adapterDeferred:  false,
			adapterSubmitted: true,
			wantErr:          "reservation not chain-finalized: sres-deferred-states-1",
		},
		{
			name:             "confirmed deferred",
			status:           OperationStatusConfirmed,
			adapterDeferred:  true,
			adapterSubmitted: true,
			wantErr:          "",
		},
		{
			name:             "confirmed non-deferred",
			status:           OperationStatusConfirmed,
			adapterDeferred:  false,
			adapterSubmitted: true,
			wantErr:          "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			s.mu.Lock()
			stored := s.sponsorReservationsByID[reservation.ReservationID]
			stored.Status = tc.status
			stored.AdapterDeferred = tc.adapterDeferred
			stored.AdapterSubmitted = tc.adapterSubmitted
			stored.ConsumedAt = time.Time{}
			s.sponsorReservationsByID[reservation.ReservationID] = stored
			delete(s.paymentAuthByReservationID, reservation.ReservationID)
			s.mu.Unlock()

			auth, err := s.AuthorizePayment(ctx, proof)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected authorize to fail for status %s", tc.status)
				}
				if err.Error() != tc.wantErr {
					t.Fatalf("unexpected authorize error for status %s: got %v want %s", tc.status, err, tc.wantErr)
				}
				s.mu.Lock()
				after := s.sponsorReservationsByID[reservation.ReservationID]
				_, hasAuth := s.paymentAuthByReservationID[reservation.ReservationID]
				s.mu.Unlock()
				if !after.ConsumedAt.IsZero() {
					t.Fatalf("expected reservation to remain unconsumed after failed authorize for status %s", tc.status)
				}
				if hasAuth {
					t.Fatalf("expected no payment authorization record after failed authorize for status %s", tc.status)
				}
				return
			}

			if err != nil {
				t.Fatalf("expected authorize to succeed for status %s, got %v", tc.status, err)
			}
			if auth.Status != OperationStatusConfirmed {
				t.Fatalf("expected confirmed authorization status for status %s, got %s", tc.status, auth.Status)
			}
			s.mu.Lock()
			after := s.sponsorReservationsByID[reservation.ReservationID]
			_, hasAuth := s.paymentAuthByReservationID[reservation.ReservationID]
			s.mu.Unlock()
			if after.ConsumedAt.IsZero() {
				t.Fatalf("expected reservation to be consumed after successful authorize for status %s", tc.status)
			}
			if !hasAuth {
				t.Fatalf("expected payment authorization record after successful authorize for status %s", tc.status)
			}
		})
	}
}

func TestMemoryServiceDefaultMemoryModeWithoutAdapterStaysConfirmed(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(1024 * 1024))
	ctx := context.Background()
	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    "sess-memory-no-adapter-1",
		SubjectID:    "client-memory-no-adapter-1",
		AmountMicros: 2_000_000,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	err = s.RecordUsage(ctx, UsageRecord{
		SessionID:    "sess-memory-no-adapter-1",
		SubjectID:    "client-memory-no-adapter-1",
		BytesIngress: 1024 * 1024,
		RecordedAt:   time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}
	settlement, err := s.SettleSession(ctx, "sess-memory-no-adapter-1")
	if err != nil {
		t.Fatalf("SettleSession: %v", err)
	}
	if settlement.Status != OperationStatusConfirmed {
		t.Fatalf("expected confirmed settlement status in default memory mode, got %s", settlement.Status)
	}
	if settlement.AdapterDeferred || settlement.AdapterSubmitted {
		t.Fatalf("expected settlement adapter state deferred=false submitted=false in default memory mode")
	}
	if settlement.AdapterReferenceID != "" {
		t.Fatalf("expected empty settlement adapter reference id in default memory mode, got %s", settlement.AdapterReferenceID)
	}
	reward, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-memory-no-adapter-1",
		ProviderSubjectID: "provider-memory-no-adapter-1",
		SessionID:         "sess-memory-no-adapter-1",
		RewardMicros:      55,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward: %v", err)
	}
	if reward.Status != OperationStatusConfirmed || reward.AdapterDeferred || reward.AdapterSubmitted {
		t.Fatalf("expected reward to remain confirmed and non-deferred in default memory mode")
	}
	if reward.AdapterReferenceID != "" {
		t.Fatalf("expected empty reward adapter reference id in default memory mode, got %s", reward.AdapterReferenceID)
	}
	reservation, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-memory-no-adapter-1",
		SponsorID:     "sponsor-memory-no-adapter-1",
		SubjectID:     "client-memory-no-adapter-1",
		SessionID:     "sess-memory-no-adapter-1",
		AmountMicros:  300,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != OperationStatusConfirmed || reservation.AdapterDeferred || reservation.AdapterSubmitted {
		t.Fatalf("expected sponsor reservation to remain confirmed and non-deferred in default memory mode")
	}
	if reservation.AdapterReferenceID != "" {
		t.Fatalf("expected empty sponsor reservation adapter reference id in default memory mode, got %s", reservation.AdapterReferenceID)
	}
	auth, err := s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: reservation.ReservationID,
		SponsorID:     reservation.SponsorID,
		SubjectID:     reservation.SubjectID,
		SessionID:     reservation.SessionID,
	})
	if err != nil {
		t.Fatalf("AuthorizePayment: %v", err)
	}
	if auth.Status != OperationStatusConfirmed {
		t.Fatalf("expected payment authorization confirmed in default memory mode, got %s", auth.Status)
	}
	storedReservation, err := s.GetSponsorReservation(ctx, reservation.ReservationID)
	if err != nil {
		t.Fatalf("GetSponsorReservation: %v", err)
	}
	if storedReservation.Status != OperationStatusConfirmed {
		t.Fatalf("expected consumed sponsor reservation to remain confirmed in default memory mode, got %s", storedReservation.Status)
	}
	if storedReservation.ConsumedAt.IsZero() {
		t.Fatalf("expected consumed sponsor reservation timestamp to be set in default memory mode")
	}
	evidence, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-memory-no-adapter-1",
		SubjectID:     "provider-memory-no-adapter-1",
		SessionID:     "sess-memory-no-adapter-1",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("ev-memory-no-adapter-1"),
		SlashMicros:   9,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence: %v", err)
	}
	if evidence.Status != OperationStatusConfirmed || evidence.AdapterDeferred || evidence.AdapterSubmitted {
		t.Fatalf("expected slash evidence to remain confirmed and non-deferred in default memory mode")
	}
	if evidence.AdapterReferenceID != "" {
		t.Fatalf("expected empty slash evidence adapter reference id in default memory mode, got %s", evidence.AdapterReferenceID)
	}
	report, err := s.Reconcile(ctx)
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected no deferred adapter operations in default memory mode, got %d", report.PendingAdapterOperations)
	}
	if report.PendingOperations != 0 {
		t.Fatalf("expected no pending operations in default memory mode, got %d", report.PendingOperations)
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

func TestMemoryServiceDeferredReplayUsesNormalizedSubmissionStatus(t *testing.T) {
	adapter := &statusCapturingReplayAdapter{failFirst: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	setupDeferredSettlement(t, s, "sess-replay-status-normalization-1")

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected deferred backlog to clear after replay, got %d", report.PendingAdapterOperations)
	}

	statuses := adapter.settlementStatusesSnapshot()
	if len(statuses) != 2 {
		t.Fatalf("expected exactly two settlement submissions (initial fail + replay), got %d", len(statuses))
	}
	for idx, status := range statuses {
		if status != OperationStatusSubmitted {
			t.Fatalf("expected settlement submission call %d to use status %q, got %q", idx+1, OperationStatusSubmitted, status)
		}
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

func TestMemoryServiceReconcileReplayFailureRetainsBacklogAcrossNonSettlementOperations(t *testing.T) {
	adapter := &multiOperationReplayAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	sessionID, rewardID, reservationID, evidenceID, slashSubjectID := setupDeferredNonSettlementOperations(t, s, "non-set-fail-1")

	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile with persistent adapter failure: %v", err)
	}
	if report.PendingAdapterOperations != 3 {
		t.Fatalf("expected deferred backlog 3 after failed replay, got %d", report.PendingAdapterOperations)
	}
	if report.FailedOperations < 3 {
		t.Fatalf("expected at least three failed operations after failed replay, got %d", report.FailedOperations)
	}

	s.mu.Lock()
	reward := s.rewardsByID[rewardID]
	reservation := s.sponsorReservationsByID[reservationID]
	evidence := s.slashEvidenceByID[evidenceID]
	rewardOp, hasRewardOp := s.deferredAdapterOps[cosmosID("reward", rewardID, sessionID)]
	reservationOp, hasReservationOp := s.deferredAdapterOps[cosmosID("sponsor-reservation", reservationID, sessionID)]
	evidenceOp, hasEvidenceOp := s.deferredAdapterOps[cosmosID("slash", evidenceID, slashSubjectID)]
	s.mu.Unlock()

	if reward.Status != OperationStatusFailed || !reward.AdapterDeferred || reward.AdapterSubmitted {
		t.Fatalf("expected reward to retain failed+deferred state after failed replay")
	}
	if reservation.Status != OperationStatusFailed || !reservation.AdapterDeferred || reservation.AdapterSubmitted {
		t.Fatalf("expected sponsor reservation to retain failed+deferred state after failed replay")
	}
	if evidence.Status != OperationStatusFailed || !evidence.AdapterDeferred || evidence.AdapterSubmitted {
		t.Fatalf("expected slash evidence to retain failed+deferred state after failed replay")
	}
	if !hasRewardOp || !hasReservationOp || !hasEvidenceOp {
		t.Fatalf("expected deferred operations to be retained for reward/sponsor/slash after failed replay")
	}
	if rewardOp.Attempts < 2 || reservationOp.Attempts < 2 || evidenceOp.Attempts < 2 {
		t.Fatalf("expected deferred attempts >=2 for reward/sponsor/slash, got reward=%d sponsor=%d slash=%d",
			rewardOp.Attempts, reservationOp.Attempts, evidenceOp.Attempts)
	}
	if adapter.rewardCalls() != 2 || adapter.sponsorCalls() != 2 || adapter.slashCalls() != 2 {
		t.Fatalf("expected exactly two submissions per non-settlement op (initial fail + replay fail), got reward=%d sponsor=%d slash=%d",
			adapter.rewardCalls(), adapter.sponsorCalls(), adapter.slashCalls())
	}
}

func TestMemoryServiceReconcileReplayRecoveryConfirmsAcrossNonSettlementOperations(t *testing.T) {
	adapter := &multiOperationReplayAdapter{fail: true}
	s := NewMemoryService(
		WithPricePerMiBMicros(1024*1024),
		WithChainAdapter(adapter),
	)
	sessionID, rewardID, reservationID, evidenceID, slashSubjectID := setupDeferredNonSettlementOperations(t, s, "non-set-recover-1")

	adapter.setFail(false)
	report, err := s.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile after adapter recovery: %v", err)
	}
	if report.PendingAdapterOperations != 0 {
		t.Fatalf("expected deferred backlog cleared after replay recovery, got %d", report.PendingAdapterOperations)
	}
	if report.ConfirmedOperations < 3 {
		t.Fatalf("expected at least three confirmed operations after replay recovery, got %d", report.ConfirmedOperations)
	}

	s.mu.Lock()
	reward := s.rewardsByID[rewardID]
	reservation := s.sponsorReservationsByID[reservationID]
	evidence := s.slashEvidenceByID[evidenceID]
	_, hasRewardOp := s.deferredAdapterOps[cosmosID("reward", rewardID, sessionID)]
	_, hasReservationOp := s.deferredAdapterOps[cosmosID("sponsor-reservation", reservationID, sessionID)]
	_, hasEvidenceOp := s.deferredAdapterOps[cosmosID("slash", evidenceID, slashSubjectID)]
	s.mu.Unlock()

	if reward.Status != OperationStatusConfirmed || !reward.AdapterSubmitted || reward.AdapterDeferred {
		t.Fatalf("expected reward to be confirmed with submitted adapter state after replay recovery")
	}
	if reservation.Status != OperationStatusConfirmed || !reservation.AdapterSubmitted || reservation.AdapterDeferred {
		t.Fatalf("expected sponsor reservation to be confirmed with submitted adapter state after replay recovery")
	}
	if evidence.Status != OperationStatusConfirmed || !evidence.AdapterSubmitted || evidence.AdapterDeferred {
		t.Fatalf("expected slash evidence to be confirmed with submitted adapter state after replay recovery")
	}
	if hasRewardOp || hasReservationOp || hasEvidenceOp {
		t.Fatalf("expected replay recovery to clear deferred operations for reward/sponsor/slash")
	}

	if adapter.rewardCalls() != 2 || adapter.sponsorCalls() != 2 || adapter.slashCalls() != 2 {
		t.Fatalf("expected exactly two submissions per non-settlement op (initial fail + single replay), got reward=%d sponsor=%d slash=%d",
			adapter.rewardCalls(), adapter.sponsorCalls(), adapter.slashCalls())
	}

	if _, err := s.Reconcile(context.Background()); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}
	if adapter.rewardCalls() != 2 || adapter.sponsorCalls() != 2 || adapter.slashCalls() != 2 {
		t.Fatalf("expected replay to be idempotent after backlog clears, got reward=%d sponsor=%d slash=%d",
			adapter.rewardCalls(), adapter.sponsorCalls(), adapter.slashCalls())
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

func TestMemoryServiceNonSettlementWritesAreIdempotentByRecordID(t *testing.T) {
	adapter := &multiOperationReplayAdapter{}
	s := NewMemoryService(WithChainAdapter(adapter))
	ctx := context.Background()

	rewardA, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-idem-1",
		ProviderSubjectID: "provider-idem-1",
		SessionID:         "sess-idem-1",
		RewardMicros:      55,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward first: %v", err)
	}
	rewardB, err := s.IssueReward(ctx, RewardIssue{
		RewardID:          "rew-idem-1",
		ProviderSubjectID: "provider-idem-override",
		SessionID:         "sess-idem-override",
		RewardMicros:      99,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("IssueReward second: %v", err)
	}
	if !rewardB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on duplicate reward write")
	}
	if rewardA.RewardID != rewardB.RewardID || rewardA.ProviderSubjectID != rewardB.ProviderSubjectID || rewardA.SessionID != rewardB.SessionID {
		t.Fatalf("expected duplicate reward write to return original record identity")
	}

	reservationA, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-idem-1",
		SponsorID:     "sponsor-idem-1",
		SubjectID:     "client-idem-1",
		SessionID:     "sess-idem-1",
		AmountMicros:  300,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits first: %v", err)
	}
	reservationB, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-idem-1",
		SponsorID:     "sponsor-idem-override",
		SubjectID:     "client-idem-override",
		SessionID:     "sess-idem-override",
		AmountMicros:  999,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits second: %v", err)
	}
	if !reservationB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on duplicate sponsor reservation")
	}
	if reservationA.ReservationID != reservationB.ReservationID || reservationA.SponsorID != reservationB.SponsorID || reservationA.SubjectID != reservationB.SubjectID {
		t.Fatalf("expected duplicate sponsor reservation write to return original record identity")
	}

	evidenceA, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-idem-1",
		SubjectID:     "provider-idem-1",
		SessionID:     "sess-idem-1",
		ViolationType: "double-sign",
		EvidenceRef:   testSHA256Ref("slash-idem-a"),
		SlashMicros:   17,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence first: %v", err)
	}
	evidenceB, err := s.SubmitSlashEvidence(ctx, SlashEvidence{
		EvidenceID:    "ev-idem-1",
		SubjectID:     "provider-idem-override",
		SessionID:     "sess-idem-override",
		ViolationType: "sponsor-overdraft-proof",
		EvidenceRef:   testSHA256Ref("slash-idem-b"),
		SlashMicros:   123,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("SubmitSlashEvidence second: %v", err)
	}
	if !evidenceB.IdempotentReplay {
		t.Fatalf("expected idempotent replay marker on duplicate slash evidence write")
	}
	if evidenceA.EvidenceID != evidenceB.EvidenceID || evidenceA.SubjectID != evidenceB.SubjectID || evidenceA.EvidenceRef != evidenceB.EvidenceRef {
		t.Fatalf("expected duplicate slash evidence write to return original proof identity")
	}

	if adapter.rewardCalls() != 1 || adapter.sponsorCalls() != 1 || adapter.slashCalls() != 1 {
		t.Fatalf("expected duplicate writes not to resubmit adapter operations, got reward=%d sponsor=%d slash=%d",
			adapter.rewardCalls(), adapter.sponsorCalls(), adapter.slashCalls())
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

func TestMemoryServiceAuthorizePaymentRequiresSponsorAndSubject(t *testing.T) {
	s := NewMemoryService()
	tests := []struct {
		name    string
		proof   PaymentProof
		wantErr string
	}{
		{
			name: "missing sponsor_id",
			proof: PaymentProof{
				ReservationID: "sres-binding-missing-sponsor",
				SponsorID:     "   ",
				SubjectID:     "client-1",
				SessionID:     "sess-1",
			},
			wantErr: "authorize payment requires sponsor_id",
		},
		{
			name: "missing subject_id",
			proof: PaymentProof{
				ReservationID: "sres-binding-missing-subject",
				SponsorID:     "sponsor-1",
				SubjectID:     " ",
				SessionID:     "sess-1",
			},
			wantErr: "authorize payment requires subject_id",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.AuthorizePayment(context.Background(), tc.proof)
			if err == nil {
				t.Fatalf("expected missing binding field to fail")
			}
			if err.Error() != tc.wantErr {
				t.Fatalf("unexpected error for missing binding field: got %v want %s", err, tc.wantErr)
			}
		})
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
		{
			name: "missing session when reservation requires it",
			proof: PaymentProof{
				ReservationID: "sres-mismatch-1",
				SponsorID:     "sponsor-good-1",
				SubjectID:     "client-good-1",
				SessionID:     "   ",
			},
			wantErr: "authorize payment requires session_id",
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

func TestMemoryServiceAuthorizePaymentRejectsUnexpectedSessionBinding(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	_, err := s.ReserveSponsorCredits(ctx, SponsorCreditReservation{
		ReservationID: "sres-empty-session-1",
		SponsorID:     "sponsor-empty-session-1",
		SubjectID:     "client-empty-session-1",
		AmountMicros:  300,
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-empty-session-1",
		SponsorID:     "sponsor-empty-session-1",
		SubjectID:     "client-empty-session-1",
		SessionID:     "sess-should-not-be-set",
	})
	if err == nil {
		t.Fatalf("expected session mismatch when reservation has no session")
	}
	if err.Error() != "reservation session mismatch" {
		t.Fatalf("unexpected error for unexpected session binding: %v", err)
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

func TestMemoryServiceAuthorizePaymentDuplicateProofReplayRejectsMismatchedProof(t *testing.T) {
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

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-replay-1",
		SponsorID:     "sponsor-replay-1",
		SubjectID:     "client-replay-1",
		SessionID:     "sess-replay-1",
	})
	if err != nil {
		t.Fatalf("AuthorizePayment first: %v", err)
	}

	_, err = s.AuthorizePayment(ctx, PaymentProof{
		ReservationID: "sres-replay-1",
		SponsorID:     "sponsor-other",
		SubjectID:     "client-other",
		SessionID:     "sess-other",
	})
	if err == nil {
		t.Fatalf("expected mismatched duplicate proof replay to fail")
	}
	if err.Error() != "reservation sponsor mismatch" {
		t.Fatalf("unexpected error for mismatched duplicate replay: %v", err)
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

func TestMemoryServiceSettleSessionRejectsUsageByteOverflow(t *testing.T) {
	s := NewMemoryService()
	ctx := context.Background()
	const sessionID = "sess-overflow-bytes-1"

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    "client-overflow-bytes-1",
		AmountMicros: math.MaxInt64,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-overflow-bytes-1",
		BytesIngress: math.MaxInt64,
		BytesEgress:  1,
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}

	_, err = s.SettleSession(ctx, sessionID)
	if err == nil {
		t.Fatalf("expected usage byte overflow to fail settle")
	}
	if !strings.Contains(err.Error(), "usage byte counters overflow") {
		t.Fatalf("unexpected usage byte overflow error: %v", err)
	}
}

func TestMemoryServiceSettleSessionRejectsChargeOverflow(t *testing.T) {
	s := NewMemoryService(WithPricePerMiBMicros(math.MaxInt64))
	ctx := context.Background()
	const sessionID = "sess-overflow-charge-1"

	_, err := s.ReserveFunds(ctx, FundReservation{
		SessionID:    sessionID,
		SubjectID:    "client-overflow-charge-1",
		AmountMicros: math.MaxInt64,
		Currency:     "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if err := s.RecordUsage(ctx, UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-overflow-charge-1",
		BytesIngress: 2 * 1024 * 1024, // 2 MiB
	}); err != nil {
		t.Fatalf("RecordUsage: %v", err)
	}

	_, err = s.SettleSession(ctx, sessionID)
	if err == nil {
		t.Fatalf("expected settlement charge overflow to fail settle")
	}
	if !strings.Contains(err.Error(), "settlement charge overflow") {
		t.Fatalf("unexpected settlement charge overflow error: %v", err)
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
