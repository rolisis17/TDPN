package exit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/policy"
	"privacynode/pkg/proto"
	"privacynode/pkg/relay"
	"privacynode/pkg/settlement"
	"privacynode/pkg/wg"
)

type settlementServiceStub struct {
	reserveFundsFn           func(context.Context, settlement.FundReservation) (settlement.FundReservation, error)
	recordUsageFn            func(context.Context, settlement.UsageRecord) error
	settleSessionFn          func(context.Context, string) (settlement.SessionSettlement, error)
	issueRewardFn            func(context.Context, settlement.RewardIssue) (settlement.RewardIssue, error)
	reconcileFn              func(context.Context) (settlement.ReconcileReport, error)
	reserveFundsCalls        int
	recordUsageCalls         int
	settleSessionCalls       int
	issueRewardCalls         int
	reconcileCalls           int
	submitSlashEvidenceCalls int
}

func (s *settlementServiceStub) RecordUsage(ctx context.Context, usage settlement.UsageRecord) error {
	s.recordUsageCalls++
	if s.recordUsageFn != nil {
		return s.recordUsageFn(ctx, usage)
	}
	return nil
}

func (s *settlementServiceStub) QuotePrice(_ context.Context, subjectID string, currency string) (settlement.PriceQuote, error) {
	return settlement.PriceQuote{
		SubjectID: subjectID,
		Currency:  currency,
	}, nil
}

func (s *settlementServiceStub) ReserveFunds(ctx context.Context, reservation settlement.FundReservation) (settlement.FundReservation, error) {
	s.reserveFundsCalls++
	if s.reserveFundsFn != nil {
		return s.reserveFundsFn(ctx, reservation)
	}
	return reservation, nil
}

func (s *settlementServiceStub) ReserveSponsorCredits(_ context.Context, reservation settlement.SponsorCreditReservation) (settlement.SponsorCreditReservation, error) {
	return reservation, nil
}

func (s *settlementServiceStub) GetSponsorReservation(_ context.Context, reservationID string) (settlement.SponsorCreditReservation, error) {
	return settlement.SponsorCreditReservation{}, errors.New("not found: " + reservationID)
}

func (s *settlementServiceStub) AuthorizePayment(_ context.Context, proof settlement.PaymentProof) (settlement.PaymentAuthorization, error) {
	return settlement.PaymentAuthorization{
		ReservationID: proof.ReservationID,
	}, nil
}

func (s *settlementServiceStub) SettleSession(ctx context.Context, sessionID string) (settlement.SessionSettlement, error) {
	s.settleSessionCalls++
	if s.settleSessionFn != nil {
		return s.settleSessionFn(ctx, sessionID)
	}
	return settlement.SessionSettlement{
		SessionID:     sessionID,
		ChargedMicros: 1,
		Currency:      "USD",
	}, nil
}

func (s *settlementServiceStub) IssueReward(ctx context.Context, reward settlement.RewardIssue) (settlement.RewardIssue, error) {
	s.issueRewardCalls++
	if s.issueRewardFn != nil {
		return s.issueRewardFn(ctx, reward)
	}
	return reward, nil
}

func (s *settlementServiceStub) SubmitSlashEvidence(_ context.Context, evidence settlement.SlashEvidence) (settlement.SlashEvidence, error) {
	s.submitSlashEvidenceCalls++
	return evidence, nil
}

func (s *settlementServiceStub) Reconcile(ctx context.Context) (settlement.ReconcileReport, error) {
	s.reconcileCalls++
	if s.reconcileFn != nil {
		return s.reconcileFn(ctx)
	}
	return settlement.ReconcileReport{}, nil
}

type failingSettlementChainAdapter struct {
	submitSessionSettlementCalls int
	submitRewardIssueCalls       int
}

func (a *failingSettlementChainAdapter) SubmitSessionSettlement(_ context.Context, _ settlement.SessionSettlement) (string, error) {
	a.submitSessionSettlementCalls++
	return "", errors.New("chain unavailable")
}

func (a *failingSettlementChainAdapter) SubmitRewardIssue(_ context.Context, _ settlement.RewardIssue) (string, error) {
	a.submitRewardIssueCalls++
	return "", errors.New("chain unavailable")
}

func (a *failingSettlementChainAdapter) SubmitSponsorReservation(_ context.Context, _ settlement.SponsorCreditReservation) (string, error) {
	return "", errors.New("chain unavailable")
}

func (a *failingSettlementChainAdapter) SubmitSlashEvidence(_ context.Context, _ settlement.SlashEvidence) (string, error) {
	return "", errors.New("chain unavailable")
}

func (a *failingSettlementChainAdapter) Health(_ context.Context) error {
	return errors.New("chain unavailable")
}

func TestHandlePathCloseFinalizeWarningDoesNotFailSessionClose(t *testing.T) {
	stub := &settlementServiceStub{
		settleSessionFn: func(_ context.Context, sessionID string) (settlement.SessionSettlement, error) {
			return settlement.SessionSettlement{}, errors.New("adapter unavailable for " + sessionID)
		},
	}
	now := time.Now()
	s := &Service{
		settlement: stub,
		sessions: map[string]sessionInfo{
			"sid-close-finalize-warning": {
				claims:       crypto.CapabilityClaims{Subject: "client-1", ExpiryUnix: now.Add(2 * time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				ingressBytes: 512,
				egressBytes:  1024,
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sid-close-finalize-warning"}`))
	rr := httptest.NewRecorder()
	s.handlePathClose(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected close HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathCloseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode close response: %v", err)
	}
	if !resp.Closed {
		t.Fatalf("expected session close success despite settlement finalize warning: %+v", resp)
	}
	if _, exists := s.sessions["sid-close-finalize-warning"]; exists {
		t.Fatalf("expected closed session removed from session map")
	}
	if stub.recordUsageCalls != 1 {
		t.Fatalf("expected one usage record attempt, got %d", stub.recordUsageCalls)
	}
	if stub.settleSessionCalls != 1 {
		t.Fatalf("expected one settle attempt, got %d", stub.settleSessionCalls)
	}
	if stub.issueRewardCalls != 0 {
		t.Fatalf("expected no reward issue attempt after settle warning, got %d", stub.issueRewardCalls)
	}
}

func TestSettlementReserveAndFinalizeWarningsDoNotBlockSessionClose(t *testing.T) {
	stub := &settlementServiceStub{
		reserveFundsFn: func(_ context.Context, reservation settlement.FundReservation) (settlement.FundReservation, error) {
			return reservation, errors.New("reserve deferred")
		},
		recordUsageFn: func(_ context.Context, _ settlement.UsageRecord) error {
			return errors.New("usage deferred")
		},
	}
	now := time.Now()
	s := &Service{
		settlement:     stub,
		sessionReserve: 200000,
		sessions: map[string]sessionInfo{
			"sid-close-reserve-warning": {
				claims:       crypto.CapabilityClaims{Subject: "client-2", ExpiryUnix: now.Add(2 * time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				ingressBytes: 2048,
				egressBytes:  1024,
			},
		},
	}

	s.reserveSettlementForSession(context.Background(), "sid-close-reserve-warning", "client-2")
	if stub.reserveFundsCalls != 1 {
		t.Fatalf("expected reserve attempted once, got %d", stub.reserveFundsCalls)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sid-close-reserve-warning"}`))
	rr := httptest.NewRecorder()
	s.handlePathClose(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected close HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathCloseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode close response: %v", err)
	}
	if !resp.Closed {
		t.Fatalf("expected close success despite reserve/finalize warnings: %+v", resp)
	}
	if _, exists := s.sessions["sid-close-reserve-warning"]; exists {
		t.Fatalf("expected closed session removed from session map")
	}
	if stub.recordUsageCalls != 1 {
		t.Fatalf("expected one usage record attempt on close, got %d", stub.recordUsageCalls)
	}
	if stub.settleSessionCalls != 0 {
		t.Fatalf("expected no settle attempt when usage recording fails, got %d", stub.settleSessionCalls)
	}
}

func TestHandlePathCloseDeferredChainAdapterDoesNotBlockSessionClose(t *testing.T) {
	adapter := &failingSettlementChainAdapter{}
	memSettlement := settlement.NewMemoryService(
		settlement.WithPricePerMiBMicros(100000),
		settlement.WithChainAdapter(adapter),
	)
	now := time.Now()
	s := &Service{
		addr:           "127.0.0.1:51820",
		settlement:     memSettlement,
		sessionReserve: 500000,
		sessions: map[string]sessionInfo{
			"sid-close-deferred-chain": {
				claims:       crypto.CapabilityClaims{Subject: "client-3", ExpiryUnix: now.Add(2 * time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				ingressBytes: 400000,
				egressBytes:  200000,
			},
		},
	}

	s.reserveSettlementForSession(context.Background(), "sid-close-deferred-chain", "client-3")

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sid-close-deferred-chain"}`))
	rr := httptest.NewRecorder()
	s.handlePathClose(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected close HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathCloseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode close response: %v", err)
	}
	if !resp.Closed {
		t.Fatalf("expected close success when chain adapter defers writes: %+v", resp)
	}
	if _, exists := s.sessions["sid-close-deferred-chain"]; exists {
		t.Fatalf("expected closed session removed from session map")
	}
	if adapter.submitSessionSettlementCalls < 1 {
		t.Fatalf("expected chain settlement submit attempted")
	}

	report, err := memSettlement.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile report: %v", err)
	}
	if report.PendingAdapterOperations < 1 {
		t.Fatalf("expected pending adapter operations after chain failure, got %d", report.PendingAdapterOperations)
	}
	if report.FailedOperations < 1 {
		t.Fatalf("expected failed settlement operations after replayed chain failure, got %d", report.FailedOperations)
	}
}

func TestReconcileSettlementCallsService(t *testing.T) {
	stub := &settlementServiceStub{
		reconcileFn: func(_ context.Context) (settlement.ReconcileReport, error) {
			return settlement.ReconcileReport{PendingAdapterOperations: 1}, nil
		},
	}
	s := &Service{settlement: stub}
	s.reconcileSettlement(context.Background())

	if stub.reconcileCalls != 1 {
		t.Fatalf("expected one reconcile call, got %d", stub.reconcileCalls)
	}
}

func TestReconcileSettlementToleratesError(t *testing.T) {
	stub := &settlementServiceStub{
		reconcileFn: func(_ context.Context) (settlement.ReconcileReport, error) {
			return settlement.ReconcileReport{}, errors.New("temporary reconcile outage")
		},
	}
	s := &Service{settlement: stub}
	s.reconcileSettlement(context.Background())

	if stub.reconcileCalls != 1 {
		t.Fatalf("expected one reconcile call, got %d", stub.reconcileCalls)
	}
}

func TestHandleSettlementStatusReturnsReport(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	stub := &settlementServiceStub{
		reconcileFn: func(_ context.Context) (settlement.ReconcileReport, error) {
			return settlement.ReconcileReport{
				GeneratedAt:              now,
				PendingAdapterOperations: 4,
				PendingOperations:        7,
				SubmittedOperations:      3,
				ConfirmedOperations:      2,
				FailedOperations:         1,
			}, nil
		},
	}
	s := &Service{settlement: stub}

	req := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	rr := httptest.NewRecorder()
	s.handleSettlementStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp settlementStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode settlement status response: %v", err)
	}
	if !resp.Enabled {
		t.Fatalf("expected settlement status endpoint enabled")
	}
	if resp.Stale {
		t.Fatalf("expected fresh reconcile report")
	}
	if resp.CheckedAt.IsZero() {
		t.Fatalf("expected checked_at timestamp")
	}
	if !resp.ReportGeneratedAt.Equal(now) {
		t.Fatalf("expected report_generated_at %s, got %s", now, resp.ReportGeneratedAt)
	}
	if resp.PendingAdapterOperations != 4 || resp.PendingOperations != 7 || resp.SubmittedOperations != 3 || resp.ConfirmedOperations != 2 || resp.FailedOperations != 1 {
		t.Fatalf("unexpected reconcile counters: %+v", resp)
	}
	if resp.LastError != "" {
		t.Fatalf("expected no error on success, got %q", resp.LastError)
	}
	if stub.reconcileCalls != 1 {
		t.Fatalf("expected one reconcile call, got %d", stub.reconcileCalls)
	}
}

func TestHandleSettlementStatusSurfacesLifecycleCountersWithConfirmedProgress(t *testing.T) {
	now := time.Unix(1700000200, 0).UTC()
	stub := &settlementServiceStub{
		reconcileFn: func(_ context.Context) (settlement.ReconcileReport, error) {
			return settlement.ReconcileReport{
				GeneratedAt:         now,
				PendingOperations:   0,
				SubmittedOperations: 4,
				ConfirmedOperations: 6,
				FailedOperations:    0,
			}, nil
		},
	}
	s := &Service{settlement: stub}

	req := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	rr := httptest.NewRecorder()
	s.handleSettlementStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp settlementStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode settlement status response: %v", err)
	}
	if !resp.Enabled || resp.Stale {
		t.Fatalf("expected enabled fresh settlement status, got enabled=%t stale=%t", resp.Enabled, resp.Stale)
	}
	if !resp.ReportGeneratedAt.Equal(now) {
		t.Fatalf("expected report_generated_at %s, got %s", now, resp.ReportGeneratedAt)
	}
	if resp.PendingOperations != 0 || resp.SubmittedOperations != 4 || resp.ConfirmedOperations != 6 || resp.FailedOperations != 0 {
		t.Fatalf("unexpected lifecycle counters: %+v", resp)
	}
	if stub.reconcileCalls != 1 {
		t.Fatalf("expected one reconcile call, got %d", stub.reconcileCalls)
	}
}

func TestHandleSettlementStatusReconcileErrorIsFailSoft(t *testing.T) {
	stub := &settlementServiceStub{
		reconcileFn: func(_ context.Context) (settlement.ReconcileReport, error) {
			return settlement.ReconcileReport{}, errors.New("temporary reconcile outage")
		},
	}
	s := &Service{settlement: stub}
	s.settlementStatus.lastReport = settlement.ReconcileReport{
		GeneratedAt:              time.Unix(1700000100, 0).UTC(),
		PendingAdapterOperations: 5,
		PendingOperations:        6,
		SubmittedOperations:      2,
		ConfirmedOperations:      1,
		FailedOperations:         3,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	rr := httptest.NewRecorder()
	s.handleSettlementStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status HTTP 200 on reconcile error, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp settlementStatusResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode settlement status response: %v", err)
	}
	if !resp.Enabled {
		t.Fatalf("expected settlement status endpoint enabled")
	}
	if !resp.Stale {
		t.Fatalf("expected stale response on reconcile error")
	}
	if !strings.Contains(resp.LastError, "temporary reconcile outage") {
		t.Fatalf("expected reconcile error in response, got %q", resp.LastError)
	}
	if resp.PendingAdapterOperations != 5 || resp.PendingOperations != 6 || resp.SubmittedOperations != 2 || resp.ConfirmedOperations != 1 || resp.FailedOperations != 3 {
		t.Fatalf("expected cached counters in fail-soft response, got %+v", resp)
	}
	if stub.reconcileCalls != 1 {
		t.Fatalf("expected one reconcile call, got %d", stub.reconcileCalls)
	}
}

type settlementAdapterRequest struct {
	path string
	auth string
	body []byte
}

func collectSettlementAdapterRequests(t *testing.T, ch <-chan settlementAdapterRequest, count int) []settlementAdapterRequest {
	t.Helper()
	out := make([]settlementAdapterRequest, 0, count)
	timeout := time.After(2 * time.Second)
	for len(out) < count {
		select {
		case req := <-ch:
			out = append(out, req)
		case <-timeout:
			t.Fatalf("timed out waiting for %d adapter requests; got %d", count, len(out))
		}
	}
	return out
}

func hasSettlementAdapterRequest(requests []settlementAdapterRequest, path string, auth string) bool {
	for _, req := range requests {
		if req.path == path && req.auth == auth {
			return true
		}
	}
	return false
}

func runSettlementForAdapterEnvTest(t *testing.T, svc settlement.Service, sessionID string) {
	t.Helper()
	ctx := context.Background()
	if _, err := svc.ReserveFunds(ctx, settlement.FundReservation{
		SessionID:    sessionID,
		SubjectID:    "subject-env-test",
		AmountMicros: 200000,
	}); err != nil {
		t.Fatalf("reserve funds: %v", err)
	}
	if err := svc.RecordUsage(ctx, settlement.UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "subject-env-test",
		BytesIngress: 4096,
		BytesEgress:  2048,
		RecordedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("record usage: %v", err)
	}
	if _, err := svc.SettleSession(ctx, sessionID); err != nil {
		t.Fatalf("settle session: %v", err)
	}
}

func TestSettlementServiceFromEnvCurrencyNativeDualQuoteBehavior(t *testing.T) {
	t.Setenv("SETTLEMENT_PRICE_PER_MIB_MICROS", "2000000")
	t.Setenv("SETTLEMENT_CURRENCY", "USDC")
	t.Setenv("SETTLEMENT_NATIVE_CURRENCY", "TDPN")
	t.Setenv("SETTLEMENT_NATIVE_RATE_NUMERATOR", "3")
	t.Setenv("SETTLEMENT_NATIVE_RATE_DENOMINATOR", "2")
	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "")

	svc := newSettlementServiceFromEnv()
	ctx := context.Background()

	baseQuote, err := svc.QuotePrice(ctx, "subject-currency-base", "")
	if err != nil {
		t.Fatalf("quote base currency: %v", err)
	}
	if baseQuote.Currency != "USDC" {
		t.Fatalf("expected base quote currency USDC, got %s", baseQuote.Currency)
	}
	if baseQuote.PricePerMiBMicros != 2000000 {
		t.Fatalf("expected base quote 2000000 micros, got %d", baseQuote.PricePerMiBMicros)
	}

	nativeQuote, err := svc.QuotePrice(ctx, "subject-currency-native", "TDPN")
	if err != nil {
		t.Fatalf("quote native currency: %v", err)
	}
	if nativeQuote.Currency != "TDPN" {
		t.Fatalf("expected native quote currency TDPN, got %s", nativeQuote.Currency)
	}
	if nativeQuote.PricePerMiBMicros != 3000000 {
		t.Fatalf("expected native quote 3000000 micros with 3/2 conversion, got %d", nativeQuote.PricePerMiBMicros)
	}
}

func TestSettlementServiceFromEnvDualNativeCurrencySettlementCoherence(t *testing.T) {
	t.Setenv("SETTLEMENT_PRICE_PER_MIB_MICROS", "2000000")
	t.Setenv("SETTLEMENT_CURRENCY", "USDC")
	t.Setenv("SETTLEMENT_NATIVE_CURRENCY", "TDPN")
	t.Setenv("SETTLEMENT_NATIVE_RATE_NUMERATOR", "3")
	t.Setenv("SETTLEMENT_NATIVE_RATE_DENOMINATOR", "2")
	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "")

	svc := newSettlementServiceFromEnv()
	ctx := context.Background()
	sessionID := "sess-dual-native-coherent"

	nativeQuote, err := svc.QuotePrice(ctx, "subject-dual-native", "TDPN")
	if err != nil {
		t.Fatalf("quote native currency: %v", err)
	}

	if _, err := svc.ReserveFunds(ctx, settlement.FundReservation{
		SessionID:    sessionID,
		SubjectID:    "subject-dual-native",
		AmountMicros: 3500000,
		Currency:     "TDPN",
	}); err != nil {
		t.Fatalf("reserve funds in native currency: %v", err)
	}

	if err := svc.RecordUsage(ctx, settlement.UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "subject-dual-native",
		BytesIngress: 1048576,
		BytesEgress:  0,
		RecordedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("record usage: %v", err)
	}

	settled, err := svc.SettleSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("settle session: %v", err)
	}
	if settled.Currency != "TDPN" {
		t.Fatalf("expected settlement in TDPN, got %s", settled.Currency)
	}
	if settled.ChargedMicros != nativeQuote.PricePerMiBMicros {
		t.Fatalf("expected charged micros %d to match native quote, got %d", nativeQuote.PricePerMiBMicros, settled.ChargedMicros)
	}
	if settled.ChargedMicros != 3000000 {
		t.Fatalf("expected deterministic converted charge 3000000, got %d", settled.ChargedMicros)
	}
}

func TestNewSettlementServiceFromEnvCosmosDefaultHTTPSubmitMode(t *testing.T) {
	seenCh := make(chan settlementAdapterRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenCh <- settlementAdapterRequest{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", srv.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "api-http-1")
	t.Setenv("COSMOS_SETTLEMENT_QUEUE_SIZE", "8")
	t.Setenv("COSMOS_SETTLEMENT_MAX_RETRIES", "1")
	t.Setenv("COSMOS_SETTLEMENT_BASE_BACKOFF_MS", "5")
	t.Setenv("COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS", "500")
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_BROADCAST_PATH", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "")

	svc := newSettlementServiceFromEnv()
	runSettlementForAdapterEnvTest(t, svc, "sess-http-default")

	select {
	case got := <-seenCh:
		if got.path != "/x/vpnbilling/settlements" {
			t.Fatalf("expected default HTTP submit path, got %q", got.path)
		}
		if got.auth != "Bearer api-http-1" {
			t.Fatalf("expected bearer auth preserved, got %q", got.auth)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for HTTP-mode settlement submit")
	}
}

func TestNewSettlementServiceFromEnvCosmosSignedTxModeUsesConfiguredFields(t *testing.T) {
	seenCh := make(chan settlementAdapterRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenCh <- settlementAdapterRequest{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", srv.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "api-signed-1")
	t.Setenv("COSMOS_SETTLEMENT_QUEUE_SIZE", "8")
	t.Setenv("COSMOS_SETTLEMENT_MAX_RETRIES", "1")
	t.Setenv("COSMOS_SETTLEMENT_BASE_BACKOFF_MS", "5")
	t.Setenv("COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS", "500")
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", settlement.CosmosSubmitModeSignedTx)
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_BROADCAST_PATH", "/custom/tx/broadcast")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID", "tdpn-env-1")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "signer-env-1")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "")
	secretFile := filepath.Join(t.TempDir(), "exit_signed_tx_secret.txt")
	if err := os.WriteFile(secretFile, []byte(" signed-secret \n"), 0o600); err != nil {
		t.Fatalf("write signed-tx secret file: %v", err)
	}
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE", secretFile)
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID", "exit-kms-key-1")

	svc := newSettlementServiceFromEnv()
	runSettlementForAdapterEnvTest(t, svc, "sess-signed-env")

	select {
	case got := <-seenCh:
		if got.path != "/custom/tx/broadcast" {
			t.Fatalf("expected signed-tx broadcast path override, got %q", got.path)
		}
		if got.auth != "Bearer api-signed-1" {
			t.Fatalf("expected bearer auth preserved in signed-tx mode, got %q", got.auth)
		}
		var req struct {
			Tx struct {
				ChainID     string `json:"chain_id"`
				KeyID       string `json:"key_id"`
				Signer      string `json:"signer"`
				MessageType string `json:"message_type"`
				Signature   string `json:"signature"`
			} `json:"tx"`
		}
		if err := json.Unmarshal(got.body, &req); err != nil {
			t.Fatalf("decode signed-tx broadcast request: %v", err)
		}
		if req.Tx.ChainID != "tdpn-env-1" {
			t.Fatalf("expected signed-tx chain id from env, got %q", req.Tx.ChainID)
		}
		if req.Tx.KeyID != "exit-kms-key-1" {
			t.Fatalf("expected signed-tx key id from env, got %q", req.Tx.KeyID)
		}
		if req.Tx.Signer != "signer-env-1" {
			t.Fatalf("expected signed-tx signer from env, got %q", req.Tx.Signer)
		}
		if req.Tx.MessageType != "/x/vpnbilling/settlements" {
			t.Fatalf("expected settlement message type in signed-tx request, got %q", req.Tx.MessageType)
		}
		if req.Tx.Signature == "" {
			t.Fatalf("expected non-empty signed-tx signature")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for signed-tx settlement submit")
	}
}

func TestNewSettlementServiceFromEnvCosmosSignedTxMissingRequiredFieldsFallsBack(t *testing.T) {
	seenCh := make(chan settlementAdapterRequest, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		seenCh <- settlementAdapterRequest{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", srv.URL)
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", settlement.CosmosSubmitModeSignedTx)
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_BROADCAST_PATH", "/custom/tx/broadcast")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID", "tdpn-env-1")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "signed-secret")

	svc := newSettlementServiceFromEnv()
	runSettlementForAdapterEnvTest(t, svc, "sess-signed-fallback")

	select {
	case got := <-seenCh:
		t.Fatalf("expected memory-only fallback when signed-tx required fields are missing, got request path=%s", got.path)
	case <-time.After(800 * time.Millisecond):
	}

	report, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile fallback service: %v", err)
	}
	if report.PendingAdapterOperations != 0 || report.FailedOperations != 0 {
		t.Fatalf("expected no adapter operations after fallback, got pending=%d failed=%d", report.PendingAdapterOperations, report.FailedOperations)
	}
}

func TestNewSettlementServiceFromEnvCosmosShadowAdapterMirrorsSubmissions(t *testing.T) {
	primarySeenCh := make(chan settlementAdapterRequest, 4)
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		primarySeenCh <- settlementAdapterRequest{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer primarySrv.Close()

	shadowSeenCh := make(chan settlementAdapterRequest, 4)
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		shadowSeenCh <- settlementAdapterRequest{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowSrv.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", primarySrv.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "api-primary-1")
	t.Setenv("COSMOS_SETTLEMENT_QUEUE_SIZE", "8")
	t.Setenv("COSMOS_SETTLEMENT_MAX_RETRIES", "1")
	t.Setenv("COSMOS_SETTLEMENT_BASE_BACKOFF_MS", "5")
	t.Setenv("COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS", "500")
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_BROADCAST_PATH", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID", "")

	t.Setenv("COSMOS_SETTLEMENT_SHADOW_ENDPOINT", shadowSrv.URL)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_API_KEY", "api-shadow-1")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_QUEUE_SIZE", "8")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_MAX_RETRIES", "1")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_BASE_BACKOFF_MS", "5")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_HTTP_TIMEOUT_MS", "500")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SUBMIT_MODE", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_BROADCAST_PATH", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_CHAIN_ID", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET_FILE", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_KEY_ID", "")

	svc := newSettlementServiceFromEnv()
	ctx := context.Background()
	sessionID := "sess-shadow-mirror"
	if _, err := svc.ReserveFunds(ctx, settlement.FundReservation{
		SessionID:    sessionID,
		SubjectID:    "subject-shadow-mirror",
		AmountMicros: 200000,
	}); err != nil {
		t.Fatalf("reserve funds: %v", err)
	}
	if err := svc.RecordUsage(ctx, settlement.UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "subject-shadow-mirror",
		BytesIngress: 4096,
		BytesEgress:  2048,
		RecordedAt:   time.Now().UTC(),
	}); err != nil {
		t.Fatalf("record usage: %v", err)
	}
	sessionSettlement, err := svc.SettleSession(ctx, sessionID)
	if err != nil {
		t.Fatalf("settle session: %v", err)
	}
	if !sessionSettlement.AdapterSubmitted || sessionSettlement.AdapterDeferred {
		t.Fatalf("expected primary adapter submission to remain canonical, got submitted=%t deferred=%t",
			sessionSettlement.AdapterSubmitted, sessionSettlement.AdapterDeferred)
	}
	if !sessionSettlement.ShadowAdapterSubmitted {
		t.Fatalf("expected shadow adapter submission marker on settlement")
	}
	if sessionSettlement.ShadowAdapterStatus != settlement.OperationStatusSubmitted {
		t.Fatalf("expected shadow settlement status submitted, got %s", sessionSettlement.ShadowAdapterStatus)
	}

	reward, err := svc.IssueReward(ctx, settlement.RewardIssue{
		RewardID:          "rew-shadow-mirror-1",
		ProviderSubjectID: "provider-shadow-mirror-1",
		SessionID:         sessionID,
		RewardMicros:      100,
		Currency:          "TDPNC",
	})
	if err != nil {
		t.Fatalf("issue reward: %v", err)
	}
	if !reward.ShadowAdapterSubmitted {
		t.Fatalf("expected shadow adapter submission marker on reward")
	}

	primaryRequests := collectSettlementAdapterRequests(t, primarySeenCh, 2)
	shadowRequests := collectSettlementAdapterRequests(t, shadowSeenCh, 2)

	if !hasSettlementAdapterRequest(primaryRequests, "/x/vpnbilling/settlements", "Bearer api-primary-1") {
		t.Fatalf("expected primary settlement submission with primary auth, got %+v", primaryRequests)
	}
	if !hasSettlementAdapterRequest(primaryRequests, "/x/vpnrewards/issues", "Bearer api-primary-1") {
		t.Fatalf("expected primary reward submission with primary auth, got %+v", primaryRequests)
	}
	if !hasSettlementAdapterRequest(shadowRequests, "/x/vpnbilling/settlements", "Bearer api-shadow-1") {
		t.Fatalf("expected shadow settlement submission with shadow auth, got %+v", shadowRequests)
	}
	if !hasSettlementAdapterRequest(shadowRequests, "/x/vpnrewards/issues", "Bearer api-shadow-1") {
		t.Fatalf("expected shadow reward submission with shadow auth, got %+v", shadowRequests)
	}

	report, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if !report.ShadowAdapterConfigured {
		t.Fatalf("expected shadow adapter configured in reconcile report")
	}
	if report.ShadowAttemptedOperations < 2 || report.ShadowSubmittedOperations < 2 || report.ShadowFailedOperations != 0 {
		t.Fatalf("unexpected shadow report counts attempted=%d submitted=%d failed=%d",
			report.ShadowAttemptedOperations, report.ShadowSubmittedOperations, report.ShadowFailedOperations)
	}
}

func TestNewSettlementServiceFromEnvCosmosShadowAdapterInitFailureDoesNotBlockPrimary(t *testing.T) {
	primarySeenCh := make(chan settlementAdapterRequest, 2)
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		primarySeenCh <- settlementAdapterRequest{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer primarySrv.Close()

	shadowSeenCh := make(chan settlementAdapterRequest, 1)
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		shadowSeenCh <- settlementAdapterRequest{
			path: r.URL.Path,
			auth: r.Header.Get("Authorization"),
			body: body,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowSrv.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", primarySrv.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "api-primary-only")
	t.Setenv("COSMOS_SETTLEMENT_QUEUE_SIZE", "8")
	t.Setenv("COSMOS_SETTLEMENT_MAX_RETRIES", "1")
	t.Setenv("COSMOS_SETTLEMENT_BASE_BACKOFF_MS", "5")
	t.Setenv("COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS", "500")
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_BROADCAST_PATH", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_CHAIN_ID", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE", "")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_KEY_ID", "")

	// Force shadow adapter init failure (signed-tx mode requires signer).
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_ENDPOINT", shadowSrv.URL)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SUBMIT_MODE", settlement.CosmosSubmitModeSignedTx)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET", "shadow-secret")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET_FILE", "")

	svc := newSettlementServiceFromEnv()
	runSettlementForAdapterEnvTest(t, svc, "sess-shadow-init-fallback")

	select {
	case got := <-primarySeenCh:
		if got.path != "/x/vpnbilling/settlements" {
			t.Fatalf("expected primary settlement path, got %q", got.path)
		}
		if got.auth != "Bearer api-primary-only" {
			t.Fatalf("expected primary auth header, got %q", got.auth)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for primary settlement submit")
	}

	select {
	case got := <-shadowSeenCh:
		t.Fatalf("expected no shadow requests when shadow adapter init fails, got path=%s", got.path)
	case <-time.After(800 * time.Millisecond):
	}

	report, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if report.ShadowAdapterConfigured {
		t.Fatalf("expected shadow adapter to remain disabled after init failure")
	}
	if report.ShadowAttemptedOperations != 0 || report.ShadowSubmittedOperations != 0 || report.ShadowFailedOperations != 0 {
		t.Fatalf("expected no shadow operation accounting, got attempted=%d submitted=%d failed=%d",
			report.ShadowAttemptedOperations, report.ShadowSubmittedOperations, report.ShadowFailedOperations)
	}
}

func TestAuthorizePacketReplayDenied(t *testing.T) {
	s := &Service{enforcer: policy.NewEnforcer(), sessions: map[string]sessionInfo{}}
	s.sessions["s1"] = sessionInfo{
		claims: crypto.CapabilityClaims{
			Tier:       1,
			ExpiryUnix: time.Now().Add(5 * time.Minute).Unix(),
		},
		seenNonces: map[uint64]struct{}{},
	}

	pkt := proto.InnerPacket{DestinationPort: 443, Nonce: 42, Payload: "x"}
	if _, err := s.authorizePacket("s1", pkt, time.Now()); err != nil {
		t.Fatalf("first packet should pass: %v", err)
	}
	if _, err := s.authorizePacket("s1", pkt, time.Now()); err == nil {
		t.Fatalf("expected replay to be denied")
	}
}

func TestAuthorizePacketExpiredDenied(t *testing.T) {
	s := &Service{enforcer: policy.NewEnforcer(), sessions: map[string]sessionInfo{}}
	s.sessions["s1"] = sessionInfo{
		claims: crypto.CapabilityClaims{
			Tier:       1,
			ExpiryUnix: time.Now().Add(-time.Minute).Unix(),
		},
		seenNonces: map[uint64]struct{}{},
	}

	pkt := proto.InnerPacket{DestinationPort: 443, Nonce: 1, Payload: "x"}
	if _, err := s.authorizePacket("s1", pkt, time.Now()); err == nil {
		t.Fatalf("expected expired session to be denied")
	}
}

func TestValidatePathOpenClaims(t *testing.T) {
	now := time.Now().Unix()
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	popPubB64 := crypto.EncodeEd25519PublicKey(popPub)
	good := crypto.CapabilityClaims{
		Audience:   "exit",
		TokenType:  crypto.TokenTypeClientAccess,
		CNFEd25519: popPubB64,
		Subject:    "client-a",
		Tier:       2,
		ExpiryUnix: now + 60,
		TokenID:    "jti-1",
	}
	if err := validatePathOpenClaims(good, now); err != nil {
		t.Fatalf("expected valid claims, got err=%v", err)
	}

	cases := []struct {
		name   string
		claims crypto.CapabilityClaims
	}{
		{
			name: "bad audience",
			claims: crypto.CapabilityClaims{
				Audience:   "entry",
				TokenType:  crypto.TokenTypeClientAccess,
				CNFEd25519: popPubB64,
				Subject:    "client-a",
				Tier:       1,
				ExpiryUnix: now + 60,
				TokenID:    "jti-1",
			},
		},
		{
			name: "bad token type",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				TokenType:  crypto.TokenTypeProviderRole,
				CNFEd25519: popPubB64,
				Subject:    "client-a",
				Tier:       1,
				ExpiryUnix: now + 60,
				TokenID:    "jti-1",
			},
		},
		{
			name: "missing token proof key",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				TokenType:  crypto.TokenTypeClientAccess,
				Subject:    "client-a",
				Tier:       1,
				ExpiryUnix: now + 60,
				TokenID:    "jti-1",
			},
		},
		{
			name: "bad tier",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				TokenType:  crypto.TokenTypeClientAccess,
				CNFEd25519: popPubB64,
				Subject:    "client-a",
				Tier:       0,
				ExpiryUnix: now + 60,
				TokenID:    "jti-1",
			},
		},
		{
			name: "missing token id",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				TokenType:  crypto.TokenTypeClientAccess,
				CNFEd25519: popPubB64,
				Subject:    "client-a",
				Tier:       1,
				ExpiryUnix: now + 60,
			},
		},
		{
			name: "expired",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				TokenType:  crypto.TokenTypeClientAccess,
				CNFEd25519: popPubB64,
				Subject:    "client-a",
				Tier:       1,
				ExpiryUnix: now - 1,
				TokenID:    "jti-1",
			},
		},
		{
			name: "tier2 missing subject",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				TokenType:  crypto.TokenTypeClientAccess,
				CNFEd25519: popPubB64,
				Tier:       2,
				ExpiryUnix: now + 60,
				TokenID:    "jti-1",
			},
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := validatePathOpenClaims(tc.claims, now); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestVerifyPathOpenTokenProof(t *testing.T) {
	popPub, popPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	claims := crypto.CapabilityClaims{
		CNFEd25519: crypto.EncodeEd25519PublicKey(popPub),
	}
	req := proto.PathOpenRequest{
		ExitID:          "exit-local-1",
		MiddleRelayID:   "middle-local-1",
		Token:           "tok-1",
		TokenProofNonce: "nonce-1",
		ClientInnerPub:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Transport:       "policy-json",
		RequestedMTU:    1280,
		RequestedRegion: "local",
	}
	req.TokenProof, err = crypto.SignPathOpenProof(popPriv, crypto.PathOpenProofInput{
		Token:           req.Token,
		ExitID:          req.ExitID,
		MiddleRelayID:   req.MiddleRelayID,
		TokenProofNonce: req.TokenProofNonce,
		ClientInnerPub:  req.ClientInnerPub,
		Transport:       req.Transport,
		RequestedMTU:    req.RequestedMTU,
		RequestedRegion: req.RequestedRegion,
	})
	if err != nil {
		t.Fatalf("sign proof: %v", err)
	}
	if err := verifyPathOpenTokenProof(req, claims); err != nil {
		t.Fatalf("expected token proof verification success, got %v", err)
	}

	req.MiddleRelayID = "middle-other"
	if err := verifyPathOpenTokenProof(req, claims); err == nil {
		t.Fatalf("expected token proof verification failure for mutated request")
	}
}

func TestCheckAndRememberProofNonceDisabled(t *testing.T) {
	s := &Service{tokenProofReplayGuard: false}
	claims := crypto.CapabilityClaims{TokenID: "jti-1", ExpiryUnix: time.Now().Add(time.Minute).Unix()}
	req := proto.PathOpenRequest{}
	if err := s.checkAndRememberProofNonce(claims, req, time.Now().Unix()); err != nil {
		t.Fatalf("expected disabled guard to allow request, got %v", err)
	}
}

func TestCheckAndRememberProofNonceReplay(t *testing.T) {
	now := time.Now().Unix()
	s := &Service{
		tokenProofReplayGuard: true,
		proofNonceSeen:        make(map[string]map[string]int64),
	}
	claims := crypto.CapabilityClaims{TokenID: "jti-1", ExpiryUnix: now + 60}
	req := proto.PathOpenRequest{TokenProofNonce: "nonce-1"}
	if err := s.checkAndRememberProofNonce(claims, req, now); err != nil {
		t.Fatalf("first nonce should pass: %v", err)
	}
	if err := s.checkAndRememberProofNonce(claims, req, now); err == nil {
		t.Fatalf("expected nonce replay rejection")
	}
	req2 := proto.PathOpenRequest{TokenProofNonce: "nonce-2"}
	if err := s.checkAndRememberProofNonce(claims, req2, now); err != nil {
		t.Fatalf("second nonce should pass: %v", err)
	}
}

func TestApplyRevocationFeedSigned(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	feed := proto.RevocationListResponse{
		Issuer:      "issuer-local",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{{JTI: "jti-1", Until: now + 120}},
	}
	feed.Signature = mustSignFeed(t, feed, priv)

	s := &Service{
		issuerPub:  pub,
		revokedJTI: map[string]int64{},
	}
	if err := s.applyRevocationFeed(feed, now); err != nil {
		t.Fatalf("expected signed feed to apply: %v", err)
	}
	if !s.isRevoked(issuerKeyID(pub), "jti-1", now) {
		t.Fatalf("expected jti-1 to be revoked")
	}
}

func TestApplyRevocationFeedRejectsBadSignature(t *testing.T) {
	_, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pub2, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen2: %v", err)
	}
	now := time.Now().Unix()
	feed := proto.RevocationListResponse{
		Issuer:      "issuer-local",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{{JTI: "jti-2", Until: now + 120}},
	}
	feed.Signature = mustSignFeed(t, feed, priv)

	s := &Service{
		issuerPub:  pub2,
		revokedJTI: map[string]int64{},
	}
	if err := s.applyRevocationFeed(feed, now); err == nil {
		t.Fatalf("expected bad signature to be rejected")
	}
}

func TestVerifyTokenAcceptsAnyTrustedIssuer(t *testing.T) {
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	claimsA := crypto.CapabilityClaims{
		Issuer:     "issuer-a",
		Audience:   "exit",
		Tier:       1,
		ExpiryUnix: time.Now().Add(time.Minute).Unix(),
		TokenID:    "jti-a",
	}
	claimsB := crypto.CapabilityClaims{
		Issuer:     "issuer-b",
		Audience:   "exit",
		Tier:       1,
		ExpiryUnix: time.Now().Add(time.Minute).Unix(),
		TokenID:    "jti-b",
	}
	tokenA, err := crypto.SignClaims(claimsA, privA)
	if err != nil {
		t.Fatalf("signA: %v", err)
	}
	tokenB, err := crypto.SignClaims(claimsB, privB)
	if err != nil {
		t.Fatalf("signB: %v", err)
	}
	s := &Service{
		issuerPubs: map[string]ed25519.PublicKey{
			issuerKeyID(pubA): pubA,
			issuerKeyID(pubB): pubB,
		},
	}
	if out, keyID, err := s.verifyToken(tokenA); err != nil {
		t.Fatalf("verify tokenA: %v", err)
	} else {
		if out.TokenID != "jti-a" || keyID != issuerKeyID(pubA) {
			t.Fatalf("unexpected tokenA verify result token=%s key=%s", out.TokenID, keyID)
		}
	}
	if out, keyID, err := s.verifyToken(tokenB); err != nil {
		t.Fatalf("verify tokenB: %v", err)
	} else {
		if out.TokenID != "jti-b" || keyID != issuerKeyID(pubB) {
			t.Fatalf("unexpected tokenB verify result token=%s key=%s", out.TokenID, keyID)
		}
	}
}

func TestVerifyTokenRejectsIssuerMismatchWhenMapped(t *testing.T) {
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	claims := crypto.CapabilityClaims{
		Issuer:     "issuer-spoofed",
		Audience:   "exit",
		Tier:       1,
		ExpiryUnix: time.Now().Add(time.Minute).Unix(),
		TokenID:    "jti-spoof",
	}
	token, err := crypto.SignClaims(claims, privA)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	keyID := issuerKeyID(pubA)
	s := &Service{
		issuerPubs:      map[string]ed25519.PublicKey{keyID: pubA},
		issuerKeyIssuer: map[string]string{keyID: "issuer-a"},
	}
	if _, _, err := s.verifyToken(token); err == nil {
		t.Fatalf("expected issuer mismatch rejection")
	}
}

func TestRevocationScopedByIssuerKey(t *testing.T) {
	pubA, privA, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenA: %v", err)
	}
	pubB, privB, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygenB: %v", err)
	}
	now := time.Now().Unix()
	feedA := proto.RevocationListResponse{
		Issuer:      "issuer-a",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{{JTI: "shared-jti", Until: now + 120}},
	}
	feedA.Signature = mustSignFeed(t, feedA, privA)
	feedB := proto.RevocationListResponse{
		Issuer:      "issuer-b",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{},
	}
	feedB.Signature = mustSignFeed(t, feedB, privB)

	s := &Service{
		issuerPubs: map[string]ed25519.PublicKey{
			issuerKeyID(pubA): pubA,
			issuerKeyID(pubB): pubB,
		},
		revokedJTI: map[string]int64{},
	}
	if err := s.applyRevocationFeed(feedA, now); err != nil {
		t.Fatalf("apply feedA: %v", err)
	}
	if err := s.applyRevocationFeed(feedB, now); err != nil {
		t.Fatalf("apply feedB: %v", err)
	}
	if !s.isRevoked(issuerKeyID(pubA), "shared-jti", now) {
		t.Fatalf("expected issuer A token revoked")
	}
	if s.isRevoked(issuerKeyID(pubB), "shared-jti", now) {
		t.Fatalf("did not expect issuer B token revoked")
	}
}

func mustSignFeed(t *testing.T, feed proto.RevocationListResponse, priv ed25519.PrivateKey) string {
	t.Helper()
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload))
}

func TestNewCommandBackendDisablesOpaqueEchoByDefault(t *testing.T) {
	t.Setenv("WG_BACKEND", "command")
	t.Setenv("EXIT_OPAQUE_ECHO", "")
	t.Setenv("EXIT_LIVE_WG_MODE", "0")

	s := New()
	if s.opaqueEcho {
		t.Fatalf("expected opaque echo disabled by default in command backend")
	}
}

func TestNewCommandBackendAllowsOpaqueEchoOverride(t *testing.T) {
	t.Setenv("WG_BACKEND", "command")
	t.Setenv("EXIT_OPAQUE_ECHO", "1")

	s := New()
	if !s.opaqueEcho {
		t.Fatalf("expected opaque echo enabled when explicitly overridden")
	}
}

func TestValidateRuntimeConfigLiveModeRequiresSink(t *testing.T) {
	s := &Service{
		dataMode:         "opaque",
		wgBackend:        "command",
		wgPrivateKey:     "/tmp/wg-exit.key",
		liveWGMode:       true,
		opaqueEcho:       false,
		opaqueSinkAddr:   "",
		opaqueSourceAddr: "127.0.0.1:53010",
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected live mode validation error without EXIT_OPAQUE_SINK_ADDR")
	}
}

func TestValidateRuntimeConfigLiveModeRequiresSource(t *testing.T) {
	s := &Service{
		dataMode:         "opaque",
		wgBackend:        "command",
		wgPrivateKey:     "/tmp/wg-exit.key",
		liveWGMode:       true,
		opaqueEcho:       false,
		opaqueSinkAddr:   "127.0.0.1:53011",
		opaqueSourceAddr: "",
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected live mode validation error without EXIT_OPAQUE_SOURCE_ADDR")
	}
}

func TestValidateRuntimeConfigCommandModeRequiresOpaque(t *testing.T) {
	s := &Service{
		dataMode:     "json",
		wgBackend:    "command",
		wgPrivateKey: "/tmp/wg-exit.key",
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected command backend validation error for non-opaque data mode")
	}
}

func TestValidateRuntimeConfigCommandModeRejectsPortConflict(t *testing.T) {
	s := &Service{
		dataMode:     "opaque",
		dataAddr:     "127.0.0.1:51831",
		wgBackend:    "command",
		wgPrivateKey: "/tmp/wg-exit.key",
		wgListenPort: 51831,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected port conflict validation error")
	}
	if !strings.Contains(err.Error(), "conflicts") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigKernelProxyRequiresCommandBackend(t *testing.T) {
	s := &Service{
		dataMode:       "opaque",
		dataAddr:       "127.0.0.1:51821",
		wgBackend:      "noop",
		wgKernelProxy:  true,
		wgListenPort:   51831,
		wgPrivateKey:   "",
		opaqueSinkAddr: "",
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected kernel proxy validation error")
	}
	if !strings.Contains(err.Error(), "WG_BACKEND=command") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigWGOnlyRequiresStartupSyncTimeout(t *testing.T) {
	s := &Service{
		wgOnlyMode:         true,
		dataMode:           "opaque",
		dataAddr:           "127.0.0.1:51821",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg-exit.key",
		wgKernelProxy:      true,
		wgListenPort:       51831,
		liveWGMode:         true,
		opaqueEcho:         false,
		opaqueSinkAddr:     "127.0.0.1:53011",
		opaqueSourceAddr:   "127.0.0.1:53012",
		startupSyncTimeout: 0,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected wg-only validation failure")
	}
	if !strings.Contains(err.Error(), "WG_ONLY_MODE requires EXIT_STARTUP_SYNC_TIMEOUT_SEC>0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigWGOnlyAcceptsValidConfig(t *testing.T) {
	s := &Service{
		wgOnlyMode:         true,
		dataMode:           "opaque",
		dataAddr:           "127.0.0.1:51821",
		wgBackend:          "command",
		wgPrivateKey:       "/tmp/wg-exit.key",
		wgKernelProxy:      true,
		wgListenPort:       51831,
		liveWGMode:         true,
		opaqueEcho:         false,
		opaqueSinkAddr:     "127.0.0.1:53011",
		opaqueSourceAddr:   "127.0.0.1:53012",
		startupSyncTimeout: 8 * time.Second,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected wg-only config valid, got %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRequiresLiveKernelReplayGuard(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		dataMode:              "opaque",
		dataAddr:              "127.0.0.1:51821",
		wgBackend:             "command",
		wgPrivateKey:          "/tmp/wg-exit.key",
		wgKernelProxy:         true,
		wgListenPort:          51831,
		liveWGMode:            true,
		opaqueEcho:            false,
		opaqueSinkAddr:        "127.0.0.1:53011",
		opaqueSourceAddr:      "127.0.0.1:53012",
		tokenProofReplayGuard: true,
		peerRebindAfter:       0,
		startupSyncTimeout:    8 * time.Second,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected strict config to validate, got %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsNoReplayGuard(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		dataMode:              "opaque",
		dataAddr:              "127.0.0.1:51821",
		wgBackend:             "command",
		wgPrivateKey:          "/tmp/wg-exit.key",
		wgKernelProxy:         true,
		wgListenPort:          51831,
		liveWGMode:            true,
		opaqueEcho:            false,
		opaqueSinkAddr:        "127.0.0.1:53011",
		opaqueSourceAddr:      "127.0.0.1:53012",
		tokenProofReplayGuard: false,
		peerRebindAfter:       0,
		startupSyncTimeout:    8 * time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "EXIT_TOKEN_PROOF_REPLAY_GUARD") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsPeerRebind(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		dataMode:              "opaque",
		dataAddr:              "127.0.0.1:51821",
		wgBackend:             "command",
		wgPrivateKey:          "/tmp/wg-exit.key",
		wgKernelProxy:         true,
		wgListenPort:          51831,
		liveWGMode:            true,
		opaqueEcho:            false,
		opaqueSinkAddr:        "127.0.0.1:53011",
		opaqueSourceAddr:      "127.0.0.1:53012",
		tokenProofReplayGuard: true,
		peerRebindAfter:       5 * time.Second,
		startupSyncTimeout:    8 * time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "EXIT_PEER_REBIND_SEC=0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMissingStartupSyncTimeout(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		dataMode:              "opaque",
		dataAddr:              "127.0.0.1:51821",
		wgBackend:             "command",
		wgPrivateKey:          "/tmp/wg-exit.key",
		wgKernelProxy:         true,
		wgListenPort:          51831,
		liveWGMode:            true,
		opaqueEcho:            false,
		opaqueSinkAddr:        "127.0.0.1:53011",
		opaqueSourceAddr:      "127.0.0.1:53012",
		tokenProofReplayGuard: true,
		peerRebindAfter:       0,
		startupSyncTimeout:    0,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "EXIT_STARTUP_SYNC_TIMEOUT_SEC>0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMultiIssuerWithoutSourceQuorum(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		dataMode:              "opaque",
		dataAddr:              "127.0.0.1:51821",
		wgBackend:             "command",
		wgPrivateKey:          "/tmp/wg-exit.key",
		wgKernelProxy:         true,
		wgListenPort:          51831,
		liveWGMode:            true,
		opaqueEcho:            false,
		opaqueSinkAddr:        "127.0.0.1:53011",
		opaqueSourceAddr:      "127.0.0.1:53012",
		tokenProofReplayGuard: true,
		peerRebindAfter:       0,
		startupSyncTimeout:    8 * time.Second,
		issuerURLs:            []string{"http://127.0.0.1:8082", "http://127.0.0.1:8086"},
		issuerMinSources:      1,
		issuerMinOperators:    2,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "EXIT_ISSUER_MIN_SOURCES>=2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMultiIssuerWithoutOperatorQuorum(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		dataMode:              "opaque",
		dataAddr:              "127.0.0.1:51821",
		wgBackend:             "command",
		wgPrivateKey:          "/tmp/wg-exit.key",
		wgKernelProxy:         true,
		wgListenPort:          51831,
		liveWGMode:            true,
		opaqueEcho:            false,
		opaqueSinkAddr:        "127.0.0.1:53011",
		opaqueSourceAddr:      "127.0.0.1:53012",
		tokenProofReplayGuard: true,
		peerRebindAfter:       0,
		startupSyncTimeout:    8 * time.Second,
		issuerURLs:            []string{"http://127.0.0.1:8082", "http://127.0.0.1:8086"},
		issuerMinSources:      2,
		issuerMinOperators:    1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "EXIT_ISSUER_MIN_OPERATORS>=2") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMultiIssuerWithoutIdentityRequirement(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		dataMode:              "opaque",
		dataAddr:              "127.0.0.1:51821",
		wgBackend:             "command",
		wgPrivateKey:          "/tmp/wg-exit.key",
		wgKernelProxy:         true,
		wgListenPort:          51831,
		liveWGMode:            true,
		opaqueEcho:            false,
		opaqueSinkAddr:        "127.0.0.1:53011",
		opaqueSourceAddr:      "127.0.0.1:53012",
		tokenProofReplayGuard: true,
		peerRebindAfter:       0,
		startupSyncTimeout:    8 * time.Second,
		issuerURLs:            []string{"http://127.0.0.1:8082", "http://127.0.0.1:8086"},
		issuerMinSources:      2,
		issuerMinOperators:    2,
		issuerRequireID:       false,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "EXIT_ISSUER_REQUIRE_ID=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsNegativeCleanupInterval(t *testing.T) {
	s := &Service{
		sessionCleanupSec: -1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected cleanup interval validation error")
	}
	if !strings.Contains(err.Error(), "EXIT_SESSION_CLEANUP_SEC") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsNegativeSettlementReconcileInterval(t *testing.T) {
	s := &Service{
		settlementReconcileSec: -1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected settlement reconcile interval validation error")
	}
	if !strings.Contains(err.Error(), "EXIT_SETTLEMENT_RECONCILE_SEC") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsInvalidWGPubKeyInNoopMode(t *testing.T) {
	s := &Service{
		dataMode:  "json",
		wgBackend: "noop",
		wgPubKey:  "not-a-wg-pubkey",
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected invalid wg pubkey validation error")
	}
	if !strings.Contains(err.Error(), "EXIT_WG_PUBKEY") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDefaultWGPubKeyIsValid(t *testing.T) {
	t.Setenv("EXIT_WG_PUBKEY", "")
	t.Setenv("WG_BACKEND", "noop")
	s := New()
	if !wg.IsValidPublicKey(s.wgPubKey) {
		t.Fatalf("expected default exit wg pubkey to be valid, got %q", s.wgPubKey)
	}
}

func TestNewSettlementReconcileIntervalDefaultsEnabled(t *testing.T) {
	t.Setenv("EXIT_SETTLEMENT_RECONCILE_SEC", "")
	s := New()
	if s.settlementReconcileSec <= 0 {
		t.Fatalf("expected settlement reconcile enabled by default, got %d", s.settlementReconcileSec)
	}
}

func TestNewSettlementReconcileIntervalOverride(t *testing.T) {
	t.Setenv("EXIT_SETTLEMENT_RECONCILE_SEC", "7")
	s := New()
	if s.settlementReconcileSec != 7 {
		t.Fatalf("expected settlement reconcile interval override 7, got %d", s.settlementReconcileSec)
	}
}

func TestNewSettlementReconcileIntervalCanDisable(t *testing.T) {
	t.Setenv("EXIT_SETTLEMENT_RECONCILE_SEC", "0")
	s := New()
	if s.settlementReconcileSec != 0 {
		t.Fatalf("expected settlement reconcile disabled by override, got %d", s.settlementReconcileSec)
	}
}

func TestNewCommandBackendKeepsUnsetWGPubKeyForDerivation(t *testing.T) {
	t.Setenv("EXIT_WG_PUBKEY", "")
	t.Setenv("WG_BACKEND", "command")
	s := New()
	if strings.TrimSpace(s.wgPubKey) != "" {
		t.Fatalf("expected empty EXIT_WG_PUBKEY in command mode for runtime derivation, got %q", s.wgPubKey)
	}
}

func TestValidateRuntimeConfigRejectsNegativeStartupSyncTimeout(t *testing.T) {
	s := &Service{
		startupSyncTimeout: -1 * time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected startup sync timeout validation error")
	}
	if !strings.Contains(err.Error(), "EXIT_STARTUP_SYNC_TIMEOUT_SEC") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewBetaStrictDefaultStartupSyncTimeout(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "1")
	t.Setenv("EXIT_BETA_STRICT", "0")
	t.Setenv("EXIT_STARTUP_SYNC_TIMEOUT_SEC", "")

	s := New()
	if s.startupSyncTimeout != 30*time.Second {
		t.Fatalf("expected strict default startup sync timeout 30s, got %s", s.startupSyncTimeout)
	}
}

func TestNewCommandBackendDefaultStartupSyncTimeout(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("EXIT_BETA_STRICT", "0")
	t.Setenv("WG_BACKEND", "command")
	t.Setenv("EXIT_STARTUP_SYNC_TIMEOUT_SEC", "")

	s := New()
	if s.startupSyncTimeout != 8*time.Second {
		t.Fatalf("expected command default startup sync timeout 8s, got %s", s.startupSyncTimeout)
	}
}

func TestNewWGOnlyDefaultStartupSyncTimeout(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("EXIT_BETA_STRICT", "0")
	t.Setenv("WG_BACKEND", "noop")
	t.Setenv("WG_ONLY_MODE", "1")
	t.Setenv("EXIT_STARTUP_SYNC_TIMEOUT_SEC", "")

	s := New()
	if s.startupSyncTimeout != 8*time.Second {
		t.Fatalf("expected wg-only default startup sync timeout 8s, got %s", s.startupSyncTimeout)
	}
}

func TestNewProdStrictEnablesWGOnly(t *testing.T) {
	t.Setenv("PROD_STRICT_MODE", "1")
	t.Setenv("EXIT_PROD_STRICT", "0")

	s := New()
	if !s.wgOnlyMode {
		t.Fatalf("expected prod strict mode to enable wg-only mode")
	}
}

func TestNewStartupSyncTimeoutOverride(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("EXIT_BETA_STRICT", "0")
	t.Setenv("WG_BACKEND", "command")
	t.Setenv("EXIT_STARTUP_SYNC_TIMEOUT_SEC", "7")

	s := New()
	if s.startupSyncTimeout != 7*time.Second {
		t.Fatalf("expected startup sync timeout override 7s, got %s", s.startupSyncTimeout)
	}
}

func TestEnsureStartupIssuerSyncTimeout(t *testing.T) {
	s := &Service{
		issuerURLs:         []string{"http://127.0.0.1:1"},
		revocationsURLs:    []string{"http://127.0.0.1:1/v1/revocations"},
		httpClient:         &http.Client{Timeout: 60 * time.Millisecond},
		startupSyncTimeout: 250 * time.Millisecond,
		issuerPubs:         map[string]ed25519.PublicKey{},
		revokedJTI:         map[string]int64{},
		minTokenEpoch:      map[string]int64{},
		revocationVersion:  map[string]int64{},
	}
	err := s.ensureStartupIssuerSync(context.Background())
	if err == nil {
		t.Fatalf("expected startup sync timeout error")
	}
	if !strings.Contains(err.Error(), "timeout") {
		t.Fatalf("expected timeout error, got %v", err)
	}
}

func TestEnsureStartupIssuerSyncSuccess(t *testing.T) {
	pub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pubkeys":
			_ = json.NewEncoder(w).Encode(proto.IssuerPubKeysResponse{
				PubKeys: []string{pubB64},
				Issuer:  "issuer-local",
			})
		case "/v1/revocations":
			_ = json.NewEncoder(w).Encode(proto.RevocationListResponse{
				Issuer:      "issuer-local",
				GeneratedAt: time.Now().Unix(),
				ExpiresAt:   time.Now().Add(time.Minute).Unix(),
				Revocations: []proto.Revocation{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	s := &Service{
		issuerURLs:         []string{srv.URL},
		revocationsURLs:    []string{srv.URL + "/v1/revocations"},
		httpClient:         srv.Client(),
		startupSyncTimeout: time.Second,
		issuerPubs:         map[string]ed25519.PublicKey{},
		issuerKeyIssuer:    map[string]string{},
		revokedJTI:         map[string]int64{},
		minTokenEpoch:      map[string]int64{},
		revocationVersion:  map[string]int64{},
	}
	if err := s.ensureStartupIssuerSync(context.Background()); err != nil {
		t.Fatalf("expected startup sync success, got %v", err)
	}
	if len(s.issuerPubs) == 0 {
		t.Fatalf("expected issuer keys loaded after startup sync")
	}
}

func newIssuerPubKeyServer(t *testing.T, issuerID string) *httptest.Server {
	t.Helper()
	pub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB64 := base64.RawURLEncoding.EncodeToString(pub)
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pubkeys":
			_ = json.NewEncoder(w).Encode(proto.IssuerPubKeysResponse{
				PubKeys: []string{pubB64},
				Issuer:  issuerID,
			})
		case "/v1/revocations":
			_ = json.NewEncoder(w).Encode(proto.RevocationListResponse{
				Issuer:      issuerID,
				GeneratedAt: time.Now().Unix(),
				ExpiresAt:   time.Now().Add(time.Minute).Unix(),
				Revocations: []proto.Revocation{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestRefreshIssuerKeysRequiresSourceQuorum(t *testing.T) {
	srv := newIssuerPubKeyServer(t, "issuer-a")
	defer srv.Close()

	s := &Service{
		issuerURLs:         []string{srv.URL, "http://127.0.0.1:1"},
		issuerMinSources:   2,
		issuerMinOperators: 1,
		httpClient:         &http.Client{Timeout: 80 * time.Millisecond},
		issuerPubs:         map[string]ed25519.PublicKey{},
		issuerKeyIssuer:    map[string]string{},
		minTokenEpoch:      map[string]int64{},
	}
	err := s.refreshIssuerKeys(context.Background())
	if err == nil {
		t.Fatalf("expected source quorum failure")
	}
	if !strings.Contains(err.Error(), "issuer source quorum not met") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRefreshIssuerKeysRequiresOperatorQuorum(t *testing.T) {
	srvA := newIssuerPubKeyServer(t, "issuer-same")
	defer srvA.Close()
	srvB := newIssuerPubKeyServer(t, "issuer-same")
	defer srvB.Close()

	s := &Service{
		issuerURLs:         []string{srvA.URL, srvB.URL},
		issuerMinSources:   2,
		issuerMinOperators: 2,
		httpClient:         &http.Client{Timeout: 100 * time.Millisecond},
		issuerPubs:         map[string]ed25519.PublicKey{},
		issuerKeyIssuer:    map[string]string{},
		minTokenEpoch:      map[string]int64{},
	}
	err := s.refreshIssuerKeys(context.Background())
	if err == nil {
		t.Fatalf("expected operator quorum failure")
	}
	if !strings.Contains(err.Error(), "issuer operator quorum not met") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRefreshIssuerKeysWithSourceAndOperatorQuorum(t *testing.T) {
	srvA := newIssuerPubKeyServer(t, "issuer-a")
	defer srvA.Close()
	srvB := newIssuerPubKeyServer(t, "issuer-b")
	defer srvB.Close()

	s := &Service{
		issuerURLs:         []string{srvA.URL, srvB.URL},
		issuerMinSources:   2,
		issuerMinOperators: 2,
		httpClient:         &http.Client{Timeout: 100 * time.Millisecond},
		issuerPubs:         map[string]ed25519.PublicKey{},
		issuerKeyIssuer:    map[string]string{},
		minTokenEpoch:      map[string]int64{},
	}
	if err := s.refreshIssuerKeys(context.Background()); err != nil {
		t.Fatalf("expected issuer key refresh success, got %v", err)
	}
	if len(s.issuerPubs) == 0 {
		t.Fatalf("expected issuer keys populated")
	}
}

func TestRefreshIssuerKeysRequiresIssuerIdentityWhenConfigured(t *testing.T) {
	srv := newIssuerPubKeyServer(t, "")
	defer srv.Close()

	s := &Service{
		issuerURLs:         []string{srv.URL},
		issuerMinSources:   1,
		issuerMinOperators: 1,
		issuerRequireID:    true,
		httpClient:         &http.Client{Timeout: 100 * time.Millisecond},
		issuerPubs:         map[string]ed25519.PublicKey{},
		issuerKeyIssuer:    map[string]string{},
		minTokenEpoch:      map[string]int64{},
	}
	err := s.refreshIssuerKeys(context.Background())
	if err == nil {
		t.Fatalf("expected issuer identity validation failure")
	}
	if !strings.Contains(err.Error(), "issuer identity missing for source") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestEnsureCommandWGPubKeyDerivesWhenUnset(t *testing.T) {
	original := deriveWGPublicKeyFromPrivateFile
	defer func() { deriveWGPublicKeyFromPrivateFile = original }()

	validPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	called := 0
	deriveWGPublicKeyFromPrivateFile = func(_ context.Context, privateKeyPath string) (string, error) {
		called++
		if privateKeyPath != "/tmp/wg-exit.key" {
			t.Fatalf("unexpected private key path: %s", privateKeyPath)
		}
		return validPub, nil
	}

	s := &Service{
		wgBackend:    "command",
		wgPrivateKey: "/tmp/wg-exit.key",
		wgPubKey:     "",
	}
	if err := s.ensureCommandWGPubKey(context.Background()); err != nil {
		t.Fatalf("ensure command wg pubkey: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected one derive call, got %d", called)
	}
	if s.wgPubKey != validPub {
		t.Fatalf("expected derived pubkey, got %q", s.wgPubKey)
	}
}

func TestEnsureCommandWGPubKeySkipsDeriveWhenAlreadyValid(t *testing.T) {
	original := deriveWGPublicKeyFromPrivateFile
	defer func() { deriveWGPublicKeyFromPrivateFile = original }()

	called := 0
	validPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	deriveWGPublicKeyFromPrivateFile = func(context.Context, string) (string, error) {
		called++
		return validPub, nil
	}

	s := &Service{
		wgBackend: "command",
		wgPubKey:  validPub,
	}
	if err := s.ensureCommandWGPubKey(context.Background()); err != nil {
		t.Fatalf("ensure command wg pubkey: %v", err)
	}
	if called != 1 {
		t.Fatalf("expected derive call for consistency check, got %d", called)
	}
}

func TestEnsureCommandWGPubKeyRejectsMismatch(t *testing.T) {
	original := deriveWGPublicKeyFromPrivateFile
	defer func() { deriveWGPublicKeyFromPrivateFile = original }()

	configuredPub := base64.StdEncoding.EncodeToString(make([]byte, 32))
	derivedPubBytes := make([]byte, 32)
	derivedPubBytes[0] = 1
	derivedPub := base64.StdEncoding.EncodeToString(derivedPubBytes)

	deriveWGPublicKeyFromPrivateFile = func(context.Context, string) (string, error) {
		return derivedPub, nil
	}

	s := &Service{
		wgBackend: "command",
		wgPubKey:  configuredPub,
	}
	if err := s.ensureCommandWGPubKey(context.Background()); err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestEnsureCommandWGPubKeyReturnsDeriveError(t *testing.T) {
	original := deriveWGPublicKeyFromPrivateFile
	defer func() { deriveWGPublicKeyFromPrivateFile = original }()

	deriveWGPublicKeyFromPrivateFile = func(context.Context, string) (string, error) {
		return "", os.ErrInvalid
	}

	s := &Service{
		wgBackend:    "command",
		wgPrivateKey: "/tmp/wg-exit.key",
	}
	if err := s.ensureCommandWGPubKey(context.Background()); err == nil {
		t.Fatalf("expected derive error")
	}
}

func TestApplyRevocationFeedSetsMinTokenEpoch(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	feed := proto.RevocationListResponse{
		Issuer:        "issuer-epoch",
		KeyEpoch:      7,
		MinTokenEpoch: 6,
		Version:       2,
		GeneratedAt:   now,
		ExpiresAt:     now + 30,
	}
	feed.Signature = mustSignFeed(t, feed, priv)
	s := &Service{
		issuerPubs:        map[string]ed25519.PublicKey{issuerKeyID(pub): pub},
		revokedJTI:        map[string]int64{},
		minTokenEpoch:     map[string]int64{},
		revocationVersion: map[string]int64{},
	}
	if err := s.applyRevocationFeed(feed, now); err != nil {
		t.Fatalf("apply feed: %v", err)
	}
	if got := s.minTokenEpoch["issuer-epoch"]; got != 6 {
		t.Fatalf("expected min epoch 6, got %d", got)
	}
	if got := s.revocationVersion["issuer-epoch"]; got != 2 {
		t.Fatalf("expected revocation version 2, got %d", got)
	}
}

func TestParseOpaqueDownlinkPacketFramed(t *testing.T) {
	s := &Service{sessions: map[string]sessionInfo{}}
	frame := relay.BuildDatagram("sid-1", []byte("hello-downlink"))
	sid, payload, ok := s.parseOpaqueDownlinkPacket(frame, time.Now())
	if !ok {
		t.Fatalf("expected framed downlink parse success")
	}
	if sid != "sid-1" || string(payload) != "hello-downlink" {
		t.Fatalf("unexpected parsed result sid=%s payload=%q", sid, string(payload))
	}
}

func TestParseOpaqueDownlinkPacketSingleSessionFallback(t *testing.T) {
	now := time.Now()
	s := &Service{
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				peerAddr:     "127.0.0.1:51820",
				sessionKeyID: "k1",
			},
		},
	}
	sid, payload, ok := s.parseOpaqueDownlinkPacket([]byte("raw-from-kernel"), now)
	if !ok {
		t.Fatalf("expected fallback parse success")
	}
	if sid != "sid-1" || string(payload) != "raw-from-kernel" {
		t.Fatalf("unexpected fallback result sid=%s payload=%q", sid, string(payload))
	}
}

func TestParseOpaqueDownlinkPacketLiveModeRequiresFraming(t *testing.T) {
	now := time.Now()
	s := &Service{
		liveWGMode: true,
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				peerAddr:     "127.0.0.1:51820",
				sessionKeyID: "k1",
			},
		},
	}
	if sid, payload, ok := s.parseOpaqueDownlinkPacket([]byte("raw-from-kernel"), now); ok {
		t.Fatalf("expected live mode raw downlink drop, got sid=%s payload_len=%d", sid, len(payload))
	}
}

func TestParseOpaqueDownlinkPacketLiveModeRequiresPlausibleWireGuard(t *testing.T) {
	now := time.Now()
	s := &Service{
		liveWGMode: true,
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				peerAddr:     "127.0.0.1:51820",
				sessionKeyID: "k1",
			},
		},
	}
	shortWG := []byte{4, 0, 0, 0, 1}
	if sid, payload, ok := s.parseOpaqueDownlinkPacket(relay.BuildDatagram("sid-1", shortWG), now); ok {
		t.Fatalf("expected short wireguard-like payload rejected, got sid=%s payload_len=%d", sid, len(payload))
	}
	validWG := make([]byte, 32)
	validWG[0] = 4
	sid, payload, ok := s.parseOpaqueDownlinkPacket(relay.BuildDatagram("sid-1", validWG), now)
	if !ok {
		t.Fatalf("expected plausible wireguard payload accepted")
	}
	if sid != "sid-1" || len(payload) != len(validWG) {
		t.Fatalf("unexpected parsed live payload sid=%s payload_len=%d", sid, len(payload))
	}
}

func TestWGKernelProxyRoundTrip(t *testing.T) {
	exitDataConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen exit data: %v", err)
	}
	defer exitDataConn.Close()

	clientPeerConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen client peer: %v", err)
	}
	defer clientPeerConn.Close()

	wgEmulatorConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen wg emulator: %v", err)
	}
	defer wgEmulatorConn.Close()

	now := time.Now()
	s := &Service{
		wgKernelProxy:     true,
		wgListenPort:      wgEmulatorConn.LocalAddr().(*net.UDPAddr).Port,
		wgKernelTargetUDP: wgEmulatorConn.LocalAddr().(*net.UDPAddr),
		udpConn:           exitDataConn,
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				peerAddr:     clientPeerConn.LocalAddr().String(),
				peerLastSeen: now.Unix(),
			},
		},
		wgSessionProxies: make(map[string]*net.UDPConn),
	}
	defer s.closeAllWGKernelSessionProxies()

	uplink := make([]byte, 32)
	uplink[0] = 4
	uplink[4] = 0x42
	wgReply := append([]byte("wg-down-"), uplink...)

	wgReadErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 2048)
		_ = wgEmulatorConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := wgEmulatorConn.ReadFromUDP(buf)
		if err != nil {
			wgReadErr <- err
			return
		}
		if string(buf[:n]) != string(uplink) {
			wgReadErr <- errors.New("wg emulator uplink mismatch")
			return
		}
		_, err = wgEmulatorConn.WriteToUDP(wgReply, src)
		wgReadErr <- err
	}()

	if err := s.forwardOpaqueToWGKernel("sid-1", uplink); err != nil {
		t.Fatalf("forwardOpaqueToWGKernel failed: %v", err)
	}
	if err := <-wgReadErr; err != nil {
		t.Fatalf("wg emulator flow failed: %v", err)
	}

	buf := make([]byte, 4096)
	_ = clientPeerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := clientPeerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read client peer frame: %v", err)
	}
	sessionID, payload, err := relay.ParseDatagram(buf[:n])
	if err != nil {
		t.Fatalf("parse downlink frame: %v", err)
	}
	if sessionID != "sid-1" {
		t.Fatalf("unexpected session id: %s", sessionID)
	}
	nonce, raw, err := relay.ParseOpaquePayload(payload)
	if err != nil {
		t.Fatalf("parse opaque downlink payload: %v", err)
	}
	if nonce == 0 {
		t.Fatalf("expected non-zero downlink nonce")
	}
	if string(raw) != string(wgReply) {
		t.Fatalf("unexpected downlink payload got=%x want=%x", raw, wgReply)
	}
}

func TestForwardOpaqueToWGKernelEnforcesProxySessionLimit(t *testing.T) {
	wgEmulatorConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen wg emulator: %v", err)
	}
	defer wgEmulatorConn.Close()

	s := &Service{
		wgKernelProxy:     true,
		wgKernelProxyMax:  1,
		wgKernelTargetUDP: wgEmulatorConn.LocalAddr().(*net.UDPAddr),
		wgSessionProxies:  make(map[string]*net.UDPConn),
		wgProxyLastSeen:   make(map[string]int64),
	}
	defer s.closeAllWGKernelSessionProxies()

	if err := s.forwardOpaqueToWGKernel("sid-1", []byte{1, 2, 3}); err != nil {
		t.Fatalf("expected first session proxy creation to succeed: %v", err)
	}
	err = s.forwardOpaqueToWGKernel("sid-2", []byte{4, 5, 6})
	if err == nil {
		t.Fatalf("expected proxy session limit error")
	}
	if !errors.Is(err, errWGProxySessionLimit) {
		t.Fatalf("expected session limit error, got: %v", err)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.metrics.WGProxyLimitDrops != 1 {
		t.Fatalf("expected one wg proxy limit drop, got %d", s.metrics.WGProxyLimitDrops)
	}
	if s.metrics.ActiveWGProxySessions != 1 {
		t.Fatalf("expected one active wg proxy session, got %d", s.metrics.ActiveWGProxySessions)
	}
}

func TestCleanupExpiredSessionsClosesIdleWGProxySessions(t *testing.T) {
	now := time.Now()
	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}

	s := &Service{
		wgKernelProxy:     true,
		wgKernelProxyIdle: 2 * time.Second,
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				lastActivity: now.Add(-10 * time.Second),
			},
		},
		wgSessionProxies: map[string]*net.UDPConn{
			"sid-1": proxyConn,
		},
		wgProxyLastSeen: map[string]int64{
			"sid-1": now.Add(-10 * time.Second).Unix(),
		},
		proofNonceSeen: make(map[string]map[string]int64),
	}
	s.cleanupExpiredSessions(now)

	s.mu.RLock()
	_, stillOpen := s.wgSessionProxies["sid-1"]
	closed := s.metrics.WGProxyClosed
	idleClosed := s.metrics.WGProxyIdleClosed
	active := s.metrics.ActiveWGProxySessions
	s.mu.RUnlock()
	if stillOpen {
		t.Fatalf("expected idle wg proxy session removed")
	}
	if closed != 1 || idleClosed != 1 {
		t.Fatalf("expected one idle proxy close, got closed=%d idle_closed=%d", closed, idleClosed)
	}
	if active != 0 {
		t.Fatalf("expected zero active wg proxy sessions, got %d", active)
	}
	if _, err := proxyConn.WriteToUDP([]byte("x"), proxyConn.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatalf("expected closed proxy connection write to fail")
	}
}

func TestAllowSessionPeerRejectsMismatchByDefault(t *testing.T) {
	now := time.Now()
	s := &Service{
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				peerAddr:     "127.0.0.1:51820",
				peerLastSeen: now.Unix(),
			},
		},
	}
	allowed, rebound, current := s.allowSessionPeer("sid-1", "127.0.0.1:51899", now.Add(time.Second))
	if allowed {
		t.Fatalf("expected mismatch source rejected without rebind window")
	}
	if rebound {
		t.Fatalf("did not expect rebound flag")
	}
	if current != "127.0.0.1:51820" {
		t.Fatalf("expected current peer reported, got %s", current)
	}
}

func TestAllowSessionPeerAllowsRebindAfterThreshold(t *testing.T) {
	now := time.Now()
	s := &Service{
		peerRebindAfter: 10 * time.Second,
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				peerAddr:     "127.0.0.1:51820",
				peerLastSeen: now.Unix(),
			},
		},
	}
	allowedEarly, reboundEarly, _ := s.allowSessionPeer("sid-1", "127.0.0.1:51899", now.Add(5*time.Second))
	if allowedEarly || reboundEarly {
		t.Fatalf("expected early rebind rejection before threshold")
	}
	allowedLate, reboundLate, current := s.allowSessionPeer("sid-1", "127.0.0.1:51899", now.Add(11*time.Second))
	if !allowedLate || !reboundLate {
		t.Fatalf("expected rebind allowed after threshold")
	}
	if current != "127.0.0.1:51820" {
		t.Fatalf("expected previous peer retained before commit, got %s", current)
	}
}

func TestBindSessionPeerCommitsRebind(t *testing.T) {
	now := time.Now()
	s := &Service{
		peerRebindAfter: 10 * time.Second,
		sessions: map[string]sessionInfo{
			"sid-1": {
				claims:       crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				peerAddr:     "127.0.0.1:51820",
				peerLastSeen: now.Unix(),
			},
		},
	}
	allowed, rebound, previous := s.bindSessionPeer("sid-1", "127.0.0.1:51899", now.Add(12*time.Second))
	if !allowed || !rebound {
		t.Fatalf("expected bindSessionPeer to commit rebind")
	}
	if previous != "127.0.0.1:51820" {
		t.Fatalf("expected previous peer reported, got %s", previous)
	}
	got := s.sessions["sid-1"]
	if got.peerAddr != "127.0.0.1:51899" {
		t.Fatalf("expected peer address rebound, got %s", got.peerAddr)
	}
	if got.peerLastSeen != now.Add(12*time.Second).Unix() {
		t.Fatalf("expected peer last seen updated, got %d", got.peerLastSeen)
	}
}

func TestRecordSourceMismatchDropUpdatesMetrics(t *testing.T) {
	s := &Service{}
	s.recordSourceMismatchDrop(12)
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.metrics.DroppedSourceMismatch != 1 {
		t.Fatalf("expected mismatch counter incremented")
	}
	if s.metrics.DroppedPackets != 1 || s.metrics.DroppedBytes != 12 {
		t.Fatalf("expected drop counters updated, got packets=%d bytes=%d", s.metrics.DroppedPackets, s.metrics.DroppedBytes)
	}
}

func TestApplyRevocationFeedRejectsVersionRollback(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	base := proto.RevocationListResponse{
		Issuer:      "issuer-epoch",
		Version:     5,
		GeneratedAt: now,
		ExpiresAt:   now + 30,
	}
	base.Signature = mustSignFeed(t, base, priv)
	s := &Service{
		issuerPubs:        map[string]ed25519.PublicKey{issuerKeyID(pub): pub},
		revokedJTI:        map[string]int64{},
		revocationVersion: map[string]int64{},
		minTokenEpoch:     map[string]int64{},
	}
	if err := s.applyRevocationFeed(base, now); err != nil {
		t.Fatalf("apply base feed: %v", err)
	}
	stale := proto.RevocationListResponse{
		Issuer:      "issuer-epoch",
		Version:     4,
		GeneratedAt: now,
		ExpiresAt:   now + 30,
	}
	stale.Signature = mustSignFeed(t, stale, priv)
	if err := s.applyRevocationFeed(stale, now); err == nil {
		t.Fatalf("expected rollback version rejection")
	}
}

func TestAcceptsTokenKeyEpoch(t *testing.T) {
	s := &Service{
		minTokenEpoch:   map[string]int64{"issuer-a": 4},
		issuerKeyIssuer: map[string]string{"kid-a": "issuer-a"},
	}
	if !s.acceptsTokenKeyEpoch(crypto.CapabilityClaims{Issuer: "issuer-a", KeyEpoch: 4}, "kid-a") {
		t.Fatalf("expected token at epoch threshold accepted")
	}
	if s.acceptsTokenKeyEpoch(crypto.CapabilityClaims{Issuer: "issuer-a", KeyEpoch: 3}, "kid-a") {
		t.Fatalf("expected stale key epoch token rejected")
	}
	if !s.acceptsTokenKeyEpoch(crypto.CapabilityClaims{Issuer: "issuer-b", KeyEpoch: 1}, "kid-b") {
		t.Fatalf("expected untracked issuer epoch accepted")
	}
}

func TestFlushAccountingSnapshotWritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "acct.json")
	s := &Service{
		accountingFile: path,
		sessions: map[string]sessionInfo{
			"s1": {},
		},
		metrics: exitMetrics{
			AcceptedPackets: 10,
			DroppedPackets:  2,
		},
	}
	if err := s.flushAccountingSnapshot(time.Unix(1700000000, 0)); err != nil {
		t.Fatalf("flush accounting: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read accounting file: %v", err)
	}
	text := string(b)
	if !strings.Contains(text, "\"accepted_packets\": 10") {
		t.Fatalf("expected accepted packet metric in accounting output: %s", text)
	}
	if !strings.Contains(text, "\"active_sessions\": 1") {
		t.Fatalf("expected active session count in accounting output: %s", text)
	}
}

func TestBuildEgressSetupCommandsContainsHardeningRules(t *testing.T) {
	cmds := buildEgressSetupCommands("CHAINX", "10.90.0.0/24", "eth9")
	joined := strings.Join(cmds, "\n")
	if !strings.Contains(joined, "sysctl -w net.ipv4.ip_forward=1") {
		t.Fatalf("expected ip_forward setup command")
	}
	if !strings.Contains(joined, "iptables -t nat -A CHAINX -s 10.90.0.0/24 -o eth9 -j MASQUERADE") {
		t.Fatalf("expected dedicated nat chain masquerade command")
	}
	if !strings.Contains(joined, "conntrack --ctstate ESTABLISHED,RELATED") {
		t.Fatalf("expected established conntrack forward rule")
	}
}
