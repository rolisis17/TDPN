package issuer

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"privacynode/pkg/settlement"
)

type issuerSettlementReconcileStub struct {
	report settlement.ReconcileReport
	err    error
	calls  int
}

func (s *issuerSettlementReconcileStub) RecordUsage(_ context.Context, _ settlement.UsageRecord) error {
	return nil
}

func (s *issuerSettlementReconcileStub) QuotePrice(_ context.Context, subjectID string, currency string) (settlement.PriceQuote, error) {
	return settlement.PriceQuote{SubjectID: subjectID, Currency: currency}, nil
}

func (s *issuerSettlementReconcileStub) ReserveFunds(_ context.Context, reservation settlement.FundReservation) (settlement.FundReservation, error) {
	return reservation, nil
}

func (s *issuerSettlementReconcileStub) ReserveSponsorCredits(_ context.Context, reservation settlement.SponsorCreditReservation) (settlement.SponsorCreditReservation, error) {
	return reservation, nil
}

func (s *issuerSettlementReconcileStub) GetSponsorReservation(_ context.Context, reservationID string) (settlement.SponsorCreditReservation, error) {
	return settlement.SponsorCreditReservation{ReservationID: reservationID}, nil
}

func (s *issuerSettlementReconcileStub) AuthorizePayment(_ context.Context, proof settlement.PaymentProof) (settlement.PaymentAuthorization, error) {
	return settlement.PaymentAuthorization{ReservationID: proof.ReservationID}, nil
}

func (s *issuerSettlementReconcileStub) SettleSession(_ context.Context, sessionID string) (settlement.SessionSettlement, error) {
	return settlement.SessionSettlement{SessionID: sessionID}, nil
}

func (s *issuerSettlementReconcileStub) IssueReward(_ context.Context, reward settlement.RewardIssue) (settlement.RewardIssue, error) {
	return reward, nil
}

func (s *issuerSettlementReconcileStub) SubmitSlashEvidence(_ context.Context, evidence settlement.SlashEvidence) (settlement.SlashEvidence, error) {
	return evidence, nil
}

func (s *issuerSettlementReconcileStub) Reconcile(_ context.Context) (settlement.ReconcileReport, error) {
	s.calls++
	if s.err != nil {
		return settlement.ReconcileReport{}, s.err
	}
	return s.report, nil
}

func captureIssuerLogs(t *testing.T, fn func()) string {
	t.Helper()
	prevWriter := log.Writer()
	prevFlags := log.Flags()
	prevPrefix := log.Prefix()
	var buf bytes.Buffer
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	defer func() {
		log.SetOutput(prevWriter)
		log.SetFlags(prevFlags)
		log.SetPrefix(prevPrefix)
	}()
	fn()
	return buf.String()
}

func TestNewReadsSettlementReconcileIntervalFromEnv(t *testing.T) {
	t.Setenv("ISSUER_SETTLEMENT_RECONCILE_SEC", "42")
	svc := New()
	if svc.settlementReconcileSec != 42 {
		t.Fatalf("expected settlement reconcile interval 42, got %d", svc.settlementReconcileSec)
	}
}

func TestNewAllowsDisablingSettlementReconcileInterval(t *testing.T) {
	t.Setenv("ISSUER_SETTLEMENT_RECONCILE_SEC", "0")
	svc := New()
	if svc.settlementReconcileSec != 0 {
		t.Fatalf("expected settlement reconcile interval 0, got %d", svc.settlementReconcileSec)
	}
}

func TestReconcileSettlementLogsWarningOnError(t *testing.T) {
	stub := &issuerSettlementReconcileStub{err: errors.New("adapter unavailable")}
	svc := &Service{settlement: stub}

	out := captureIssuerLogs(t, func() {
		svc.reconcileSettlement(context.Background())
	})

	if stub.calls != 1 {
		t.Fatalf("expected reconcile call count 1, got %d", stub.calls)
	}
	if !strings.Contains(out, "issuer settlement reconcile warning: adapter unavailable") {
		t.Fatalf("expected reconcile warning log, got %q", out)
	}
}

func TestReconcileSettlementLogsBacklogSummary(t *testing.T) {
	stub := &issuerSettlementReconcileStub{
		report: settlement.ReconcileReport{
			PendingAdapterOperations: 3,
			PendingOperations:        2,
			FailedOperations:         1,
			SubmittedOperations:      9,
			ConfirmedOperations:      5,
		},
	}
	svc := &Service{settlement: stub}

	out := captureIssuerLogs(t, func() {
		svc.reconcileSettlement(context.Background())
	})

	if stub.calls != 1 {
		t.Fatalf("expected reconcile call count 1, got %d", stub.calls)
	}
	if !strings.Contains(out, "issuer settlement reconcile backlog") {
		t.Fatalf("expected backlog summary log, got %q", out)
	}
	if !strings.Contains(out, "pending_adapter=3") || !strings.Contains(out, "pending=2") || !strings.Contains(out, "failed=1") {
		t.Fatalf("expected backlog counters in log, got %q", out)
	}
}

func TestReconcileSettlementSkipsNoBacklogNoError(t *testing.T) {
	stub := &issuerSettlementReconcileStub{
		report: settlement.ReconcileReport{
			PendingAdapterOperations: 0,
			PendingOperations:        0,
			FailedOperations:         0,
		},
	}
	svc := &Service{settlement: stub}

	out := captureIssuerLogs(t, func() {
		svc.reconcileSettlement(context.Background())
	})

	if stub.calls != 1 {
		t.Fatalf("expected reconcile call count 1, got %d", stub.calls)
	}
	if strings.TrimSpace(out) != "" {
		t.Fatalf("expected no reconcile logs for clean report, got %q", out)
	}
}
