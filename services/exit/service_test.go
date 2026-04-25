package exit

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/policy"
	"privacynode/pkg/proto"
	"privacynode/pkg/relay"
	"privacynode/pkg/settlement"
	"privacynode/pkg/wg"

	"github.com/alicebob/miniredis/v2"
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

type sequentialWGManager struct {
	removeSessionErrs  []error
	removeSessionCalls int
	removedSessionCfgs []wg.SessionConfig
}

func (m *sequentialWGManager) ConfigureSession(_ context.Context, _ wg.SessionConfig) error {
	return nil
}

func (m *sequentialWGManager) RemoveSession(_ context.Context, cfg wg.SessionConfig) error {
	m.removeSessionCalls++
	m.removedSessionCfgs = append(m.removedSessionCfgs, cfg)
	if len(m.removeSessionErrs) == 0 {
		return nil
	}
	err := m.removeSessionErrs[0]
	m.removeSessionErrs = m.removeSessionErrs[1:]
	return err
}

type blockingWGManager struct {
	started           chan struct{}
	release           chan struct{}
	removeSessionErrs []error

	mu sync.Mutex

	removeSessionCalls int
	removedSessionCfgs []wg.SessionConfig
}

func (m *blockingWGManager) ConfigureSession(_ context.Context, _ wg.SessionConfig) error {
	return nil
}

func (m *blockingWGManager) RemoveSession(_ context.Context, cfg wg.SessionConfig) error {
	var err error
	m.mu.Lock()
	m.removeSessionCalls++
	m.removedSessionCfgs = append(m.removedSessionCfgs, cfg)
	started := m.started
	release := m.release
	if len(m.removeSessionErrs) > 0 {
		err = m.removeSessionErrs[0]
		m.removeSessionErrs = m.removeSessionErrs[1:]
	}
	m.mu.Unlock()

	if started != nil {
		started <- struct{}{}
	}
	if release != nil {
		<-release
	}
	return err
}

func (m *blockingWGManager) RemoveSessionCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.removeSessionCalls
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
				sessionKeyID: "sk-close-finalize-warning",
				ingressBytes: 512,
				egressBytes:  1024,
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sid-close-finalize-warning","session_key_id":"sk-close-finalize-warning"}`))
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
				sessionKeyID: "sk-close-reserve-warning",
				ingressBytes: 2048,
				egressBytes:  1024,
			},
		},
	}

	s.reserveSettlementForSession(context.Background(), "sid-close-reserve-warning", "client-2")
	if stub.reserveFundsCalls != 1 {
		t.Fatalf("expected reserve attempted once, got %d", stub.reserveFundsCalls)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sid-close-reserve-warning","session_key_id":"sk-close-reserve-warning"}`))
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

func TestHandlePathCloseRejectsSessionKeyMismatch(t *testing.T) {
	now := time.Now()
	s := &Service{
		sessions: map[string]sessionInfo{
			"sid-close-key-mismatch": {
				claims:       crypto.CapabilityClaims{Subject: "client-4", ExpiryUnix: now.Add(2 * time.Minute).Unix()},
				seenNonces:   map[uint64]struct{}{},
				sessionKeyID: "sk-close-key-correct",
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sid-close-key-mismatch","session_key_id":"sk-close-key-wrong"}`))
	rr := httptest.NewRecorder()
	s.handlePathClose(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected close HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathCloseResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode close response: %v", err)
	}
	if resp.Closed {
		t.Fatalf("expected close rejection for mismatched session key id: %+v", resp)
	}
	if resp.Reason != "session-key-id-mismatch" {
		t.Fatalf("reason=%q want=session-key-id-mismatch", resp.Reason)
	}
	if _, exists := s.sessions["sid-close-key-mismatch"]; !exists {
		t.Fatalf("expected session to remain when session key id mismatches")
	}
}

func TestHandlePathCloseWGTeardownFailureKeepsSessionForRetry(t *testing.T) {
	now := time.Now()
	wgManager := &sequentialWGManager{
		removeSessionErrs: []error{errors.New("wg remove temporarily failed"), nil},
	}
	settlementStub := &settlementServiceStub{}
	s := &Service{
		wgInterface: "wg-exit0",
		wgManager:   wgManager,
		settlement:  settlementStub,
		sessions: map[string]sessionInfo{
			"sid-close-wg-retry": {
				claims:        crypto.CapabilityClaims{Subject: "client-5", ExpiryUnix: now.Add(2 * time.Minute).Unix()},
				seenNonces:    map[uint64]struct{}{},
				transport:     "wireguard-udp",
				sessionKeyID:  "sk-close-wg-retry",
				clientPubKey:  "client-wg-pubkey",
				clientInnerIP: "10.90.0.2/32",
			},
		},
	}

	reqBody := `{"session_id":"sid-close-wg-retry","session_key_id":"sk-close-wg-retry"}`

	firstReq := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(reqBody))
	firstRR := httptest.NewRecorder()
	s.handlePathClose(firstRR, firstReq)

	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected first close HTTP 200, got %d body=%s", firstRR.Code, firstRR.Body.String())
	}
	var firstResp proto.PathCloseResponse
	if err := json.Unmarshal(firstRR.Body.Bytes(), &firstResp); err != nil {
		t.Fatalf("decode first close response: %v", err)
	}
	if firstResp.Closed {
		t.Fatalf("expected first close to fail when wg teardown fails: %+v", firstResp)
	}
	if firstResp.Reason != "wg remove failed" {
		t.Fatalf("first close reason=%q want=wg remove failed", firstResp.Reason)
	}
	if _, exists := s.sessions["sid-close-wg-retry"]; !exists {
		t.Fatalf("expected session retained after wg teardown failure")
	}
	if settlementStub.recordUsageCalls != 0 || settlementStub.settleSessionCalls != 0 {
		t.Fatalf("expected no settlement finalization after failed close, got record=%d settle=%d",
			settlementStub.recordUsageCalls, settlementStub.settleSessionCalls)
	}
	if wgManager.removeSessionCalls != 1 {
		t.Fatalf("expected one wg remove attempt, got %d", wgManager.removeSessionCalls)
	}

	secondReq := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(reqBody))
	secondRR := httptest.NewRecorder()
	s.handlePathClose(secondRR, secondReq)

	if secondRR.Code != http.StatusOK {
		t.Fatalf("expected retry close HTTP 200, got %d body=%s", secondRR.Code, secondRR.Body.String())
	}
	var secondResp proto.PathCloseResponse
	if err := json.Unmarshal(secondRR.Body.Bytes(), &secondResp); err != nil {
		t.Fatalf("decode retry close response: %v", err)
	}
	if !secondResp.Closed {
		t.Fatalf("expected retry close success after wg teardown recovery: %+v", secondResp)
	}
	if _, exists := s.sessions["sid-close-wg-retry"]; exists {
		t.Fatalf("expected session removed after successful retry close")
	}
	if wgManager.removeSessionCalls != 2 {
		t.Fatalf("expected two wg remove attempts across retries, got %d", wgManager.removeSessionCalls)
	}
	if settlementStub.recordUsageCalls != 1 || settlementStub.settleSessionCalls != 1 {
		t.Fatalf("expected settlement finalized exactly once after successful close, got record=%d settle=%d",
			settlementStub.recordUsageCalls, settlementStub.settleSessionCalls)
	}

	thirdReq := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(reqBody))
	thirdRR := httptest.NewRecorder()
	s.handlePathClose(thirdRR, thirdReq)

	if thirdRR.Code != http.StatusOK {
		t.Fatalf("expected repeated close HTTP 200, got %d body=%s", thirdRR.Code, thirdRR.Body.String())
	}
	var thirdResp proto.PathCloseResponse
	if err := json.Unmarshal(thirdRR.Body.Bytes(), &thirdResp); err != nil {
		t.Fatalf("decode repeated close response: %v", err)
	}
	if !thirdResp.Closed {
		t.Fatalf("expected repeated close after success to be idempotent success: %+v", thirdResp)
	}
	if wgManager.removeSessionCalls != 2 {
		t.Fatalf("expected no additional wg remove on repeated close, got %d calls", wgManager.removeSessionCalls)
	}
	if settlementStub.recordUsageCalls != 1 || settlementStub.settleSessionCalls != 1 {
		t.Fatalf("expected settlement totals unchanged on repeated close, got record=%d settle=%d",
			settlementStub.recordUsageCalls, settlementStub.settleSessionCalls)
	}
}

func TestHandlePathCloseConcurrentCloseRequestsAreIdempotent(t *testing.T) {
	now := time.Now()
	wgManager := &blockingWGManager{
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	settlementStub := &settlementServiceStub{}
	s := &Service{
		wgInterface: "wg-exit0",
		wgManager:   wgManager,
		settlement:  settlementStub,
		sessions: map[string]sessionInfo{
			"sid-close-race": {
				claims:        crypto.CapabilityClaims{Subject: "client-race", ExpiryUnix: now.Add(2 * time.Minute).Unix()},
				seenNonces:    map[uint64]struct{}{},
				transport:     "wireguard-udp",
				sessionKeyID:  "sk-close-race",
				clientPubKey:  "client-wg-pubkey",
				clientInnerIP: "10.90.0.2/32",
				ingressBytes:  4096,
				egressBytes:   2048,
			},
		},
	}

	reqBody := `{"session_id":"sid-close-race","session_key_id":"sk-close-race"}`
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(reqBody))
	firstRR := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(reqBody))
	secondRR := httptest.NewRecorder()

	var callWG sync.WaitGroup
	callWG.Add(2)
	go func() {
		defer callWG.Done()
		s.handlePathClose(firstRR, firstReq)
	}()
	go func() {
		defer callWG.Done()
		s.handlePathClose(secondRR, secondReq)
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-wgManager.started:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for concurrent wg remove calls")
		}
	}
	close(wgManager.release)
	callWG.Wait()

	for idx, rr := range []*httptest.ResponseRecorder{firstRR, secondRR} {
		if rr.Code != http.StatusOK {
			t.Fatalf("expected close HTTP 200 for call %d, got %d body=%s", idx+1, rr.Code, rr.Body.String())
		}
		var resp proto.PathCloseResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode close response %d: %v", idx+1, err)
		}
		if !resp.Closed {
			t.Fatalf("expected close call %d to succeed idempotently, got %+v", idx+1, resp)
		}
	}
	if _, exists := s.sessions["sid-close-race"]; exists {
		t.Fatalf("expected session removed after concurrent close calls")
	}
	if wgManager.RemoveSessionCalls() != 2 {
		t.Fatalf("expected two overlapping wg remove attempts, got %d", wgManager.RemoveSessionCalls())
	}
	if settlementStub.recordUsageCalls != 1 || settlementStub.settleSessionCalls != 1 {
		t.Fatalf("expected settlement finalized exactly once across concurrent closes, got record=%d settle=%d",
			settlementStub.recordUsageCalls, settlementStub.settleSessionCalls)
	}
}

func TestHandlePathCloseConcurrentCloseStaysIdempotentWhenSecondWGRemoveErrors(t *testing.T) {
	now := time.Now()
	wgManager := &blockingWGManager{
		started:           make(chan struct{}, 2),
		release:           make(chan struct{}),
		removeSessionErrs: []error{nil, errors.New("already removed")},
	}
	settlementStub := &settlementServiceStub{}
	s := &Service{
		wgInterface: "wg-exit0",
		wgManager:   wgManager,
		settlement:  settlementStub,
		sessions: map[string]sessionInfo{
			"sid-close-race-err": {
				claims:        crypto.CapabilityClaims{Subject: "client-race-err", ExpiryUnix: now.Add(2 * time.Minute).Unix()},
				seenNonces:    map[uint64]struct{}{},
				transport:     "wireguard-udp",
				sessionKeyID:  "sk-close-race-err",
				clientPubKey:  "client-wg-pubkey-race-err",
				clientInnerIP: "10.90.0.3/32",
				ingressBytes:  1024,
				egressBytes:   512,
			},
		},
	}

	reqBody := `{"session_id":"sid-close-race-err","session_key_id":"sk-close-race-err"}`
	firstReq := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(reqBody))
	firstRR := httptest.NewRecorder()
	secondReq := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(reqBody))
	secondRR := httptest.NewRecorder()

	var callWG sync.WaitGroup
	callWG.Add(2)
	go func() {
		defer callWG.Done()
		s.handlePathClose(firstRR, firstReq)
	}()
	go func() {
		defer callWG.Done()
		s.handlePathClose(secondRR, secondReq)
	}()

	for i := 0; i < 2; i++ {
		select {
		case <-wgManager.started:
		case <-time.After(2 * time.Second):
			t.Fatalf("timed out waiting for concurrent wg remove calls")
		}
	}
	close(wgManager.release)
	callWG.Wait()

	for idx, rr := range []*httptest.ResponseRecorder{firstRR, secondRR} {
		if rr.Code != http.StatusOK {
			t.Fatalf("expected close HTTP 200 for call %d, got %d body=%s", idx+1, rr.Code, rr.Body.String())
		}
		var resp proto.PathCloseResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode close response %d: %v", idx+1, err)
		}
		if !resp.Closed {
			t.Fatalf("expected close call %d to remain idempotent success, got %+v", idx+1, resp)
		}
	}
	if _, exists := s.sessions["sid-close-race-err"]; exists {
		t.Fatalf("expected session removed after concurrent close calls")
	}
	if wgManager.RemoveSessionCalls() != 2 {
		t.Fatalf("expected two overlapping wg remove attempts, got %d", wgManager.RemoveSessionCalls())
	}
	if settlementStub.recordUsageCalls != 1 || settlementStub.settleSessionCalls != 1 {
		t.Fatalf("expected settlement finalized exactly once across concurrent closes, got record=%d settle=%d",
			settlementStub.recordUsageCalls, settlementStub.settleSessionCalls)
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
				sessionKeyID: "sk-close-deferred-chain",
				ingressBytes: 400000,
				egressBytes:  200000,
			},
		},
	}

	s.reserveSettlementForSession(context.Background(), "sid-close-deferred-chain", "client-3")

	req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(`{"session_id":"sid-close-deferred-chain","session_key_id":"sk-close-deferred-chain"}`))
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

func TestHandlePathOpenRejectsMalformedJSONBodies(t *testing.T) {
	oversizedSessionID := strings.Repeat("a", int(pathControlJSONBodyMaxBytes)+1024)
	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: `{"session_id":"sid-open","token":"tok-open","unexpected":true}`,
		},
		{
			name: "trailing json",
			body: `{"session_id":"sid-open","token":"tok-open"}{"trailing":true}`,
		},
		{
			name: "oversized body",
			body: `{"session_id":"` + oversizedSessionID + `","token":"tok-open"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{}
			req := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(tc.body))
			rr := httptest.NewRecorder()

			s.handlePathOpen(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected HTTP 400 for malformed path open body, got %d body=%s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "invalid json") {
				t.Fatalf("expected invalid json error body, got %q", rr.Body.String())
			}
		})
	}
}

func signedPathOpenRequestBody(t *testing.T, req proto.PathOpenRequest, claims crypto.CapabilityClaims, issuerPriv ed25519.PrivateKey, popPriv ed25519.PrivateKey) []byte {
	t.Helper()

	token, err := crypto.SignClaims(claims, issuerPriv)
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	req.Token = token

	tokenProof, err := crypto.SignPathOpenProof(popPriv, crypto.PathOpenProofInput{
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
		t.Fatalf("sign path-open proof: %v", err)
	}
	req.TokenProof = tokenProof

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal path-open request: %v", err)
	}
	return body
}

func TestHandlePathOpenRejectsExitIdentityMismatchInEnforceMode(t *testing.T) {
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	popPub, popPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}

	req := proto.PathOpenRequest{
		ExitID:          "exit-remote-2",
		MiddleRelayID:   "middle-local-1",
		TokenProofNonce: "nonce-open-exit-id-mismatch",
		ClientInnerPub:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Transport:       "wireguard-udp",
		RequestedMTU:    1280,
		RequestedRegion: "local",
		SessionID:       "sid-open-exit-id-mismatch",
	}
	claims := crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "exit",
		TokenType:  crypto.TokenTypeClientAccess,
		CNFEd25519: crypto.EncodeEd25519PublicKey(popPub),
		Tier:       1,
		ExpiryUnix: time.Now().Add(2 * time.Minute).Unix(),
		TokenID:    "jti-open-exit-id-mismatch",
		ExitScope:  []string{req.ExitID},
	}
	body := signedPathOpenRequestBody(t, req, claims, issuerPriv, popPriv)

	s := &Service{
		dataMode:      "json",
		betaStrict:    true,
		exitRelayID:   "exit-local-1",
		issuerPubs:    map[string]ed25519.PublicKey{issuerKeyID(issuerPub): issuerPub},
		issuerPub:     issuerPub,
		sessions:      map[string]sessionInfo{},
		enforcer:      policy.NewEnforcer(),
		revokedJTI:    map[string]int64{},
		minTokenEpoch: map[string]int64{},
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, httpReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathOpenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Accepted {
		t.Fatalf("expected rejection for mismatched exit identity, got %+v", resp)
	}
	if resp.Reason != "exit identity mismatch" {
		t.Fatalf("reason=%q want=exit identity mismatch", resp.Reason)
	}
	if _, exists := s.sessions[req.SessionID]; exists {
		t.Fatalf("expected rejected path-open to avoid creating session")
	}
}

func TestHandlePathOpenRejectsWhenStrictBindingExitRelayIDUnset(t *testing.T) {
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	popPub, popPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}

	req := proto.PathOpenRequest{
		ExitID:          "exit-local-1",
		MiddleRelayID:   "middle-local-1",
		TokenProofNonce: "nonce-open-exit-id-unset",
		ClientInnerPub:  crypto.EncodeEd25519PublicKey(popPub),
		Transport:       "policy-json",
		RequestedMTU:    1280,
		RequestedRegion: "local",
		SessionID:       "sid-open-exit-id-unset",
	}
	claims := crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "exit",
		TokenType:  crypto.TokenTypeClientAccess,
		CNFEd25519: crypto.EncodeEd25519PublicKey(popPub),
		Tier:       1,
		ExpiryUnix: time.Now().Add(2 * time.Minute).Unix(),
		TokenID:    "jti-open-exit-id-unset",
		ExitScope:  []string{req.ExitID},
	}
	body := signedPathOpenRequestBody(t, req, claims, issuerPriv, popPriv)

	s := &Service{
		dataMode:      "json",
		betaStrict:    true,
		exitRelayID:   " ",
		issuerPubs:    map[string]ed25519.PublicKey{issuerKeyID(issuerPub): issuerPub},
		issuerPub:     issuerPub,
		sessions:      map[string]sessionInfo{},
		enforcer:      policy.NewEnforcer(),
		revokedJTI:    map[string]int64{},
		minTokenEpoch: map[string]int64{},
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, httpReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathOpenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Accepted {
		t.Fatalf("expected rejection when strict identity binding has no EXIT_RELAY_ID, got %+v", resp)
	}
	if resp.Reason != "exit identity mismatch" {
		t.Fatalf("reason=%q want=exit identity mismatch", resp.Reason)
	}
	if _, exists := s.sessions[req.SessionID]; exists {
		t.Fatalf("expected rejected path-open to avoid creating session")
	}
}

func TestHandlePathOpenAcceptsMatchingExitIdentityInEnforceMode(t *testing.T) {
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	popPub, popPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}

	req := proto.PathOpenRequest{
		ExitID:          "exit-local-1",
		MiddleRelayID:   "middle-local-1",
		TokenProofNonce: "nonce-open-exit-id-match",
		ClientInnerPub:  crypto.EncodeEd25519PublicKey(popPub),
		Transport:       "policy-json",
		RequestedMTU:    1280,
		RequestedRegion: "local",
		SessionID:       "sid-open-exit-id-match",
	}
	claims := crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "exit",
		TokenType:  crypto.TokenTypeClientAccess,
		CNFEd25519: crypto.EncodeEd25519PublicKey(popPub),
		Tier:       1,
		ExpiryUnix: time.Now().Add(2 * time.Minute).Unix(),
		TokenID:    "jti-open-exit-id-match",
		ExitScope:  []string{"exit-alt-1", req.ExitID},
	}
	body := signedPathOpenRequestBody(t, req, claims, issuerPriv, popPriv)

	s := &Service{
		dataMode:      "json",
		betaStrict:    true,
		exitRelayID:   req.ExitID,
		issuerPubs:    map[string]ed25519.PublicKey{issuerKeyID(issuerPub): issuerPub},
		issuerPub:     issuerPub,
		sessions:      map[string]sessionInfo{},
		enforcer:      policy.NewEnforcer(),
		revokedJTI:    map[string]int64{},
		minTokenEpoch: map[string]int64{},
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, httpReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathOpenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Accepted {
		t.Fatalf("expected successful path-open when exit identity matches, got %+v", resp)
	}
	if resp.SessionKeyID == "" {
		t.Fatalf("expected session key id on success")
	}
	if resp.Transport != "policy-json" {
		t.Fatalf("transport=%q want=policy-json", resp.Transport)
	}
	if _, exists := s.sessions[req.SessionID]; !exists {
		t.Fatalf("expected accepted path-open to create session")
	}
}

func TestHandlePathOpenRejectsExitIdentityMismatchWhenExitRelayConfigured(t *testing.T) {
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	popPub, popPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}

	req := proto.PathOpenRequest{
		ExitID:          "exit-remote-2",
		MiddleRelayID:   "middle-local-1",
		TokenProofNonce: "nonce-open-exit-id-mismatch-configured",
		ClientInnerPub:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Transport:       "wireguard-udp",
		RequestedMTU:    1280,
		RequestedRegion: "local",
		SessionID:       "sid-open-exit-id-mismatch-configured",
	}
	claims := crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "exit",
		TokenType:  crypto.TokenTypeClientAccess,
		CNFEd25519: crypto.EncodeEd25519PublicKey(popPub),
		Tier:       1,
		ExpiryUnix: time.Now().Add(2 * time.Minute).Unix(),
		TokenID:    "jti-open-exit-id-mismatch-configured",
		ExitScope:  []string{req.ExitID},
	}
	body := signedPathOpenRequestBody(t, req, claims, issuerPriv, popPriv)

	s := &Service{
		dataMode:      "json",
		exitRelayID:   "exit-local-1",
		issuerPubs:    map[string]ed25519.PublicKey{issuerKeyID(issuerPub): issuerPub},
		issuerPub:     issuerPub,
		sessions:      map[string]sessionInfo{},
		enforcer:      policy.NewEnforcer(),
		revokedJTI:    map[string]int64{},
		minTokenEpoch: map[string]int64{},
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, httpReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathOpenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Accepted {
		t.Fatalf("expected rejection for mismatched exit identity when EXIT_RELAY_ID is configured, got %+v", resp)
	}
	if resp.Reason != "exit identity mismatch" {
		t.Fatalf("reason=%q want=exit identity mismatch", resp.Reason)
	}
	if _, exists := s.sessions[req.SessionID]; exists {
		t.Fatalf("expected rejected path-open to avoid creating session")
	}
}

func TestHandlePathOpenAcceptsMatchingExitIdentityWhenExitRelayConfigured(t *testing.T) {
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	popPub, popPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}

	req := proto.PathOpenRequest{
		ExitID:          "exit-local-1",
		MiddleRelayID:   "middle-local-1",
		TokenProofNonce: "nonce-open-exit-id-match-configured",
		ClientInnerPub:  crypto.EncodeEd25519PublicKey(popPub),
		Transport:       "policy-json",
		RequestedMTU:    1280,
		RequestedRegion: "local",
		SessionID:       "sid-open-exit-id-match-configured",
	}
	claims := crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "exit",
		TokenType:  crypto.TokenTypeClientAccess,
		CNFEd25519: crypto.EncodeEd25519PublicKey(popPub),
		Tier:       1,
		ExpiryUnix: time.Now().Add(2 * time.Minute).Unix(),
		TokenID:    "jti-open-exit-id-match-configured",
		ExitScope:  []string{"exit-alt-1", req.ExitID},
	}
	body := signedPathOpenRequestBody(t, req, claims, issuerPriv, popPriv)

	s := &Service{
		dataMode:      "json",
		exitRelayID:   req.ExitID,
		issuerPubs:    map[string]ed25519.PublicKey{issuerKeyID(issuerPub): issuerPub},
		issuerPub:     issuerPub,
		sessions:      map[string]sessionInfo{},
		enforcer:      policy.NewEnforcer(),
		revokedJTI:    map[string]int64{},
		minTokenEpoch: map[string]int64{},
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, httpReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathOpenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Accepted {
		t.Fatalf("expected successful path-open when exit identity matches configured EXIT_RELAY_ID, got %+v", resp)
	}
	if resp.SessionKeyID == "" {
		t.Fatalf("expected session key id on success")
	}
	if resp.Transport != "policy-json" {
		t.Fatalf("transport=%q want=policy-json", resp.Transport)
	}
	if _, exists := s.sessions[req.SessionID]; !exists {
		t.Fatalf("expected accepted path-open to create session")
	}
}

func TestHandlePathOpenRejectsOpaqueModeWhenPortPolicyClaimsPresent(t *testing.T) {
	tests := []struct {
		name       string
		allowPorts []int
		denyPorts  []int
	}{
		{
			name:       "allow ports",
			allowPorts: []int{443},
		},
		{
			name:      "deny ports",
			denyPorts: []int{25},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
			if err != nil {
				t.Fatalf("issuer keygen: %v", err)
			}
			popPub, popPriv, err := crypto.GenerateEd25519Keypair()
			if err != nil {
				t.Fatalf("pop keygen: %v", err)
			}

			req := proto.PathOpenRequest{
				ExitID:          "exit-local-1",
				MiddleRelayID:   "middle-local-1",
				TokenProofNonce: "nonce-open-opaque-port-policy-reject",
				ClientInnerPub:  crypto.EncodeEd25519PublicKey(popPub),
				Transport:       "wireguard-udp",
				RequestedMTU:    1280,
				RequestedRegion: "local",
				SessionID:       "sid-open-opaque-port-policy-reject",
			}
			claims := crypto.CapabilityClaims{
				Issuer:     "issuer-local",
				Audience:   "exit",
				TokenType:  crypto.TokenTypeClientAccess,
				CNFEd25519: crypto.EncodeEd25519PublicKey(popPub),
				Tier:       1,
				ExpiryUnix: time.Now().Add(2 * time.Minute).Unix(),
				TokenID:    "jti-open-opaque-port-policy-reject",
				ExitScope:  []string{req.ExitID},
				AllowPorts: tc.allowPorts,
				DenyPorts:  tc.denyPorts,
			}
			body := signedPathOpenRequestBody(t, req, claims, issuerPriv, popPriv)

			s := &Service{
				dataMode:      "opaque",
				exitRelayID:   req.ExitID,
				issuerPubs:    map[string]ed25519.PublicKey{issuerKeyID(issuerPub): issuerPub},
				issuerPub:     issuerPub,
				sessions:      map[string]sessionInfo{},
				enforcer:      policy.NewEnforcer(),
				revokedJTI:    map[string]int64{},
				minTokenEpoch: map[string]int64{},
				wgManager:     wg.NewNoopManager(),
			}
			httpReq := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(string(body)))
			rr := httptest.NewRecorder()
			s.handlePathOpen(rr, httpReq)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
			}
			var resp proto.PathOpenResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode response: %v", err)
			}
			if resp.Accepted {
				t.Fatalf("expected opaque mode rejection when port policy claims are present, got %+v", resp)
			}
			if resp.Reason != "opaque mode cannot enforce port policy" {
				t.Fatalf("reason=%q want=opaque mode cannot enforce port policy", resp.Reason)
			}
			if _, exists := s.sessions[req.SessionID]; exists {
				t.Fatalf("expected rejected path-open to avoid creating session")
			}
		})
	}
}

func TestHandlePathOpenAcceptsOpaqueModeWhenPortPolicyClaimsAbsent(t *testing.T) {
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	popPub, popPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}

	req := proto.PathOpenRequest{
		ExitID:          "exit-local-1",
		MiddleRelayID:   "middle-local-1",
		TokenProofNonce: "nonce-open-opaque-port-policy-allow",
		ClientInnerPub:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		Transport:       "wireguard-udp",
		RequestedMTU:    1280,
		RequestedRegion: "local",
		SessionID:       "sid-open-opaque-port-policy-allow",
	}
	claims := crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "exit",
		TokenType:  crypto.TokenTypeClientAccess,
		CNFEd25519: crypto.EncodeEd25519PublicKey(popPub),
		Tier:       1,
		ExpiryUnix: time.Now().Add(2 * time.Minute).Unix(),
		TokenID:    "jti-open-opaque-port-policy-allow",
		ExitScope:  []string{req.ExitID},
	}
	body := signedPathOpenRequestBody(t, req, claims, issuerPriv, popPriv)

	s := &Service{
		dataMode:      "opaque",
		exitRelayID:   req.ExitID,
		issuerPubs:    map[string]ed25519.PublicKey{issuerKeyID(issuerPub): issuerPub},
		issuerPub:     issuerPub,
		sessions:      map[string]sessionInfo{},
		enforcer:      policy.NewEnforcer(),
		revokedJTI:    map[string]int64{},
		minTokenEpoch: map[string]int64{},
		wgManager:     wg.NewNoopManager(),
	}
	httpReq := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, httpReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathOpenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Accepted {
		t.Fatalf("expected opaque mode success when no port policy claims are present, got %+v", resp)
	}
	if resp.Transport != "wireguard-udp" {
		t.Fatalf("transport=%q want=wireguard-udp", resp.Transport)
	}
	if _, exists := s.sessions[req.SessionID]; !exists {
		t.Fatalf("expected accepted path-open to create session")
	}
}

func TestHandlePathOpenRejectsDuplicateSessionID(t *testing.T) {
	issuerPub, issuerPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("issuer keygen: %v", err)
	}
	popPub, popPriv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen: %v", err)
	}

	req := proto.PathOpenRequest{
		ExitID:          "exit-local-1",
		MiddleRelayID:   "middle-local-1",
		TokenProofNonce: "nonce-open-duplicate-session",
		ClientInnerPub:  crypto.EncodeEd25519PublicKey(popPub),
		Transport:       "policy-json",
		RequestedMTU:    1280,
		RequestedRegion: "local",
		SessionID:       "sid-open-duplicate-session",
	}
	claims := crypto.CapabilityClaims{
		Issuer:     "issuer-local",
		Audience:   "exit",
		TokenType:  crypto.TokenTypeClientAccess,
		CNFEd25519: crypto.EncodeEd25519PublicKey(popPub),
		Tier:       1,
		ExpiryUnix: time.Now().Add(2 * time.Minute).Unix(),
		TokenID:    "jti-open-duplicate-session",
		ExitScope:  []string{req.ExitID},
	}
	body := signedPathOpenRequestBody(t, req, claims, issuerPriv, popPriv)

	existing := sessionInfo{
		claims:       crypto.CapabilityClaims{Subject: "existing", ExpiryUnix: time.Now().Add(time.Minute).Unix()},
		seenNonces:   map[uint64]struct{}{},
		transport:    "policy-json",
		sessionKeyID: "existing-session-key",
	}
	s := &Service{
		dataMode:      "json",
		exitRelayID:   req.ExitID,
		issuerPubs:    map[string]ed25519.PublicKey{issuerKeyID(issuerPub): issuerPub},
		issuerPub:     issuerPub,
		sessions:      map[string]sessionInfo{req.SessionID: existing},
		enforcer:      policy.NewEnforcer(),
		revokedJTI:    map[string]int64{},
		minTokenEpoch: map[string]int64{},
	}

	httpReq := httptest.NewRequest(http.MethodPost, "/v1/path/open", strings.NewReader(string(body)))
	rr := httptest.NewRecorder()
	s.handlePathOpen(rr, httpReq)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected HTTP 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.PathOpenResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Accepted {
		t.Fatalf("expected duplicate session id rejection, got %+v", resp)
	}
	if resp.Reason != "session already exists" {
		t.Fatalf("reason=%q want=session already exists", resp.Reason)
	}
	got, exists := s.sessions[req.SessionID]
	if !exists {
		t.Fatalf("expected pre-existing session retained")
	}
	if got.sessionKeyID != existing.sessionKeyID {
		t.Fatalf("expected existing session unchanged, got key=%q", got.sessionKeyID)
	}
}

func TestSessionCapacityReachedLockedRejectsOnlyNewSessionsAtCapacity(t *testing.T) {
	s := &Service{
		maxActiveSessions: 1,
		sessions: map[string]sessionInfo{
			"sid-existing": {},
		},
	}
	if !s.sessionCapacityReachedLocked("sid-new") {
		t.Fatalf("expected capacity reached for new session id")
	}
	if s.sessionCapacityReachedLocked("sid-existing") {
		t.Fatalf("expected existing session id to bypass capacity rejection")
	}
}

func TestEffectiveMaxActiveSessionsDefaults(t *testing.T) {
	s := &Service{}
	if got := s.effectiveMaxActiveSessions(); got != defaultMaxActiveSessions {
		t.Fatalf("effectiveMaxActiveSessions()=%d want=%d", got, defaultMaxActiveSessions)
	}
}

func TestHandlePathCloseRejectsMalformedJSONBodies(t *testing.T) {
	oversizedSessionID := strings.Repeat("a", int(pathControlJSONBodyMaxBytes)+1024)
	cases := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: `{"session_id":"sid-close","unexpected":true}`,
		},
		{
			name: "trailing json",
			body: `{"session_id":"sid-close"}{"trailing":true}`,
		},
		{
			name: "oversized body",
			body: `{"session_id":"` + oversizedSessionID + `"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &Service{}
			req := httptest.NewRequest(http.MethodPost, "/v1/path/close", strings.NewReader(tc.body))
			rr := httptest.NewRecorder()

			s.handlePathClose(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected HTTP 400 for malformed path close body, got %d body=%s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "invalid json") {
				t.Fatalf("expected invalid json error body, got %q", rr.Body.String())
			}
		})
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
				GeneratedAt:               now,
				PendingAdapterOperations:  4,
				ShadowAdapterConfigured:   true,
				ShadowAttemptedOperations: 9,
				ShadowSubmittedOperations: 8,
				ShadowFailedOperations:    1,
				PendingOperations:         7,
				SubmittedOperations:       3,
				ConfirmedOperations:       2,
				FailedOperations:          1,
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
	if !resp.ShadowAdapterConfigured {
		t.Fatalf("expected shadow adapter configured in status response")
	}
	if resp.ShadowAttemptedOperations != 9 || resp.ShadowSubmittedOperations != 8 || resp.ShadowFailedOperations != 1 {
		t.Fatalf("unexpected shadow counters: attempted=%d submitted=%d failed=%d",
			resp.ShadowAttemptedOperations, resp.ShadowSubmittedOperations, resp.ShadowFailedOperations)
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
		GeneratedAt:               time.Unix(1700000100, 0).UTC(),
		PendingAdapterOperations:  5,
		ShadowAdapterConfigured:   true,
		ShadowAttemptedOperations: 4,
		ShadowSubmittedOperations: 3,
		ShadowFailedOperations:    1,
		PendingOperations:         6,
		SubmittedOperations:       2,
		ConfirmedOperations:       1,
		FailedOperations:          3,
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
	if !resp.ShadowAdapterConfigured {
		t.Fatalf("expected cached shadow adapter configured flag in fail-soft response")
	}
	if resp.ShadowAttemptedOperations != 4 || resp.ShadowSubmittedOperations != 3 || resp.ShadowFailedOperations != 1 {
		t.Fatalf("expected cached shadow counters in fail-soft response, got attempted=%d submitted=%d failed=%d",
			resp.ShadowAttemptedOperations, resp.ShadowSubmittedOperations, resp.ShadowFailedOperations)
	}
	if resp.PendingAdapterOperations != 5 || resp.PendingOperations != 6 || resp.SubmittedOperations != 2 || resp.ConfirmedOperations != 1 || resp.FailedOperations != 3 {
		t.Fatalf("expected cached counters in fail-soft response, got %+v", resp)
	}
	if stub.reconcileCalls != 1 {
		t.Fatalf("expected one reconcile call, got %d", stub.reconcileCalls)
	}
}

func TestHandleSettlementStatusStaleClearsAfterRecovery(t *testing.T) {
	recoveredAt := time.Unix(1700000300, 0).UTC()
	call := 0
	stub := &settlementServiceStub{
		reconcileFn: func(_ context.Context) (settlement.ReconcileReport, error) {
			call++
			if call == 1 {
				return settlement.ReconcileReport{}, errors.New("temporary reconcile outage")
			}
			return settlement.ReconcileReport{
				GeneratedAt:               recoveredAt,
				PendingAdapterOperations:  1,
				ShadowAdapterConfigured:   true,
				ShadowAttemptedOperations: 5,
				ShadowSubmittedOperations: 4,
				ShadowFailedOperations:    1,
				PendingOperations:         0,
				SubmittedOperations:       4,
				ConfirmedOperations:       3,
				FailedOperations:          0,
			}, nil
		},
	}
	s := &Service{settlement: stub}
	s.settlementStatus.lastReport = settlement.ReconcileReport{
		GeneratedAt:              time.Unix(1700000200, 0).UTC(),
		PendingAdapterOperations: 9,
		PendingOperations:        9,
		FailedOperations:         2,
	}

	firstReq := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	firstRR := httptest.NewRecorder()
	s.handleSettlementStatus(firstRR, firstReq)
	if firstRR.Code != http.StatusOK {
		t.Fatalf("expected status HTTP 200 for degraded response, got %d body=%s", firstRR.Code, firstRR.Body.String())
	}
	var degraded settlementStatusResponse
	if err := json.Unmarshal(firstRR.Body.Bytes(), &degraded); err != nil {
		t.Fatalf("decode degraded settlement status response: %v", err)
	}
	if !degraded.Stale {
		t.Fatalf("expected stale response while reconcile is failing")
	}
	if !strings.Contains(degraded.LastError, "temporary reconcile outage") {
		t.Fatalf("expected reconcile error in degraded response, got %q", degraded.LastError)
	}

	secondReq := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	secondRR := httptest.NewRecorder()
	s.handleSettlementStatus(secondRR, secondReq)
	if secondRR.Code != http.StatusOK {
		t.Fatalf("expected status HTTP 200 for recovered response, got %d body=%s", secondRR.Code, secondRR.Body.String())
	}
	var recovered settlementStatusResponse
	if err := json.Unmarshal(secondRR.Body.Bytes(), &recovered); err != nil {
		t.Fatalf("decode recovered settlement status response: %v", err)
	}
	if recovered.Stale {
		t.Fatalf("expected stale=false after recovery")
	}
	if recovered.LastError != "" {
		t.Fatalf("expected last_error cleared after recovery, got %q", recovered.LastError)
	}
	if !recovered.ReportGeneratedAt.Equal(recoveredAt) {
		t.Fatalf("expected recovered report_generated_at %s, got %s", recoveredAt, recovered.ReportGeneratedAt)
	}
	if recovered.PendingAdapterOperations != 1 || recovered.PendingOperations != 0 || recovered.SubmittedOperations != 4 || recovered.ConfirmedOperations != 3 || recovered.FailedOperations != 0 {
		t.Fatalf("unexpected recovered counters: %+v", recovered)
	}
	if stub.reconcileCalls != 2 {
		t.Fatalf("expected two reconcile calls across degrade->recover, got %d", stub.reconcileCalls)
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

func assertPanicContains(t *testing.T, want string, fn func()) {
	t.Helper()
	defer func() {
		got := recover()
		if got == nil {
			t.Fatalf("expected panic containing %q", want)
		}
		if want != "" && !strings.Contains(fmt.Sprint(got), want) {
			t.Fatalf("expected panic containing %q, got %v", want, got)
		}
	}()
	fn()
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
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET", "signed-secret")
	t.Setenv("COSMOS_SETTLEMENT_SIGNED_TX_SECRET_FILE", "")
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

func TestNewSettlementServiceFromEnvCosmosSignedTxMissingRequiredFieldsPanicsByDefault(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	assertPanicContains(t, "refusing startup", func() {
		_ = newSettlementServiceFromEnv()
	})
}

func TestNewSettlementServiceFromEnvCosmosSignedTxMissingRequiredFieldsFallsBackWithDangerousOverride(t *testing.T) {
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
	t.Setenv(allowDangerousCosmosAdapterFallback, "1")

	svc := newSettlementServiceFromEnv()
	runSettlementForAdapterEnvTest(t, svc, "sess-signed-fallback-dangerous")

	select {
	case got := <-seenCh:
		t.Fatalf("expected no cosmos request in dangerous memory-only fallback mode, got path=%s", got.path)
	case <-time.After(800 * time.Millisecond):
	}

	report, err := svc.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile fallback service: %v", err)
	}
	if report.PendingAdapterOperations != 0 || report.FailedOperations != 0 {
		t.Fatalf("expected no adapter operations after dangerous fallback, got pending=%d failed=%d", report.PendingAdapterOperations, report.FailedOperations)
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

func TestNewSettlementServiceFromEnvCosmosShadowAdapterSignedTxModeUsesConfiguredFields(t *testing.T) {
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

	shadowSeenCh := make(chan settlementAdapterRequest, 2)
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
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "api-primary-http")
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
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_API_KEY", "api-shadow-signed")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_QUEUE_SIZE", "8")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_MAX_RETRIES", "1")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_BASE_BACKOFF_MS", "5")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_HTTP_TIMEOUT_MS", "500")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SUBMIT_MODE", settlement.CosmosSubmitModeSignedTx)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_BROADCAST_PATH", "/shadow/custom/tx")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_CHAIN_ID", "tdpn-shadow-1")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SIGNER", "shadow-signer-1")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET", "shadow-secret")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET_FILE", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_KEY_ID", "shadow-kms-key-1")

	svc := newSettlementServiceFromEnv()
	ctx := context.Background()
	sessionID := "sess-shadow-signedtx"
	if _, err := svc.ReserveFunds(ctx, settlement.FundReservation{
		SessionID:    sessionID,
		SubjectID:    "subject-shadow-signedtx",
		AmountMicros: 200000,
	}); err != nil {
		t.Fatalf("reserve funds: %v", err)
	}
	if err := svc.RecordUsage(ctx, settlement.UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "subject-shadow-signedtx",
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
		t.Fatalf("expected primary adapter to remain canonical, got submitted=%t deferred=%t",
			sessionSettlement.AdapterSubmitted, sessionSettlement.AdapterDeferred)
	}
	if !sessionSettlement.ShadowAdapterSubmitted {
		t.Fatalf("expected shadow adapter submission marker on settlement")
	}
	if sessionSettlement.ShadowAdapterStatus != settlement.OperationStatusSubmitted {
		t.Fatalf("expected shadow settlement status submitted, got %s", sessionSettlement.ShadowAdapterStatus)
	}

	primaryRequests := collectSettlementAdapterRequests(t, primarySeenCh, 1)
	shadowRequests := collectSettlementAdapterRequests(t, shadowSeenCh, 1)

	primaryReq := primaryRequests[0]
	if primaryReq.path != "/x/vpnbilling/settlements" {
		t.Fatalf("expected canonical primary HTTP path, got %q", primaryReq.path)
	}
	if primaryReq.auth != "Bearer api-primary-http" {
		t.Fatalf("expected primary bearer auth, got %q", primaryReq.auth)
	}
	var primaryBody map[string]any
	if err := json.Unmarshal(primaryReq.body, &primaryBody); err != nil {
		t.Fatalf("decode primary settlement payload: %v", err)
	}
	if _, ok := primaryBody["tx"]; ok {
		t.Fatalf("expected primary payload to stay canonical HTTP shape, got signed-tx envelope")
	}
	if gotSessionID, _ := primaryBody["SessionID"].(string); gotSessionID != sessionID {
		t.Fatalf("expected primary payload SessionID %q, got %q", sessionID, gotSessionID)
	}

	shadowReq := shadowRequests[0]
	if shadowReq.path != "/shadow/custom/tx" {
		t.Fatalf("expected shadow signed-tx broadcast path override, got %q", shadowReq.path)
	}
	if shadowReq.auth != "Bearer api-shadow-signed" {
		t.Fatalf("expected shadow bearer auth in signed-tx mode, got %q", shadowReq.auth)
	}
	var signedReq struct {
		Mode string `json:"mode"`
		Tx   struct {
			ChainID        string          `json:"chain_id"`
			KeyID          string          `json:"key_id"`
			Signer         string          `json:"signer"`
			MessageType    string          `json:"message_type"`
			Message        json.RawMessage `json:"message"`
			IdempotencyKey string          `json:"idempotency_key"`
			Signature      string          `json:"signature"`
		} `json:"tx"`
	}
	if err := json.Unmarshal(shadowReq.body, &signedReq); err != nil {
		t.Fatalf("decode shadow signed-tx broadcast request: %v", err)
	}
	if signedReq.Mode != "BROADCAST_MODE_SYNC" {
		t.Fatalf("expected signed-tx broadcast mode BROADCAST_MODE_SYNC, got %q", signedReq.Mode)
	}
	if signedReq.Tx.ChainID != "tdpn-shadow-1" {
		t.Fatalf("expected shadow chain id from env, got %q", signedReq.Tx.ChainID)
	}
	if signedReq.Tx.KeyID != "shadow-kms-key-1" {
		t.Fatalf("expected shadow key id from env, got %q", signedReq.Tx.KeyID)
	}
	if signedReq.Tx.Signer != "shadow-signer-1" {
		t.Fatalf("expected shadow signer from env, got %q", signedReq.Tx.Signer)
	}
	if signedReq.Tx.MessageType != "/x/vpnbilling/settlements" {
		t.Fatalf("expected settlement message type in shadow signed-tx request, got %q", signedReq.Tx.MessageType)
	}
	if signedReq.Tx.IdempotencyKey == "" {
		t.Fatalf("expected non-empty shadow idempotency key")
	}
	if signedReq.Tx.Signature == "" {
		t.Fatalf("expected non-empty shadow signed-tx signature")
	}
	var signedMessage map[string]any
	if err := json.Unmarshal(signedReq.Tx.Message, &signedMessage); err != nil {
		t.Fatalf("decode shadow signed-tx message payload: %v", err)
	}
	if gotSessionID, _ := signedMessage["SessionID"].(string); gotSessionID != sessionID {
		t.Fatalf("expected shadow signed-tx message SessionID %q, got %q", sessionID, gotSessionID)
	}
}

func TestNewSettlementServiceFromEnvCosmosShadowAdapterInitFailurePanicsByDefault(t *testing.T) {
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primarySrv.Close()

	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer shadowSrv.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", primarySrv.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "api-primary-only")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_ENDPOINT", shadowSrv.URL)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SUBMIT_MODE", settlement.CosmosSubmitModeSignedTx)
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SIGNER", "")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET", "shadow-secret")
	t.Setenv("COSMOS_SETTLEMENT_SHADOW_SIGNED_TX_SECRET_FILE", "")

	assertPanicContains(t, "refusing startup", func() {
		_ = newSettlementServiceFromEnv()
	})
}

func TestNewSettlementServiceFromEnvCosmosShadowAdapterInitFailureWithDangerousOverrideDoesNotBlockPrimary(t *testing.T) {
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
	t.Setenv(allowDangerousCosmosAdapterFallback, "1")

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
		ExitScope:  []string{"exit-a"},
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
			name: "missing exit scope",
			claims: crypto.CapabilityClaims{
				Audience:   "exit",
				TokenType:  crypto.TokenTypeClientAccess,
				CNFEd25519: popPubB64,
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

func TestCheckAndRememberProofNoncePerTokenCap(t *testing.T) {
	now := time.Now().Unix()
	s := &Service{
		tokenProofReplayGuard: true,
		proofNonceSeen:        make(map[string]map[string]int64),
	}
	claims := crypto.CapabilityClaims{TokenID: "jti-cap-1", ExpiryUnix: now + 3600}

	total := tokenProofReplayMaxNoncesPerToken
	for i := 0; i < total; i++ {
		req := proto.PathOpenRequest{TokenProofNonce: fmt.Sprintf("nonce-%d", i)}
		if err := s.checkAndRememberProofNonce(claims, req, now); err != nil {
			t.Fatalf("nonce %d should pass: %v", i, err)
		}
	}
	if err := s.checkAndRememberProofNonce(claims, proto.PathOpenRequest{TokenProofNonce: "nonce-overflow"}, now); err == nil {
		t.Fatalf("expected per-token replay cache saturation")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := s.proofNonceSeen[claims.TokenID]
	if got := len(seen); got != tokenProofReplayMaxNoncesPerToken {
		t.Fatalf("expected %d nonces retained, got %d", tokenProofReplayMaxNoncesPerToken, got)
	}
	if _, ok := seen[fmt.Sprintf("nonce-%d", total-1)]; !ok {
		t.Fatalf("expected newest nonce retained")
	}
	if _, ok := seen["nonce-overflow"]; ok {
		t.Fatalf("did not expect overflow nonce retained")
	}
}

func TestCheckAndRememberProofNonceTokenIDCap(t *testing.T) {
	now := time.Now().Unix()
	s := &Service{
		tokenProofReplayGuard: true,
		proofNonceSeen:        make(map[string]map[string]int64),
	}

	total := tokenProofReplayMaxTokenIDs
	for i := 0; i < total; i++ {
		tokenID := fmt.Sprintf("jti-bucket-%05d", i)
		claims := crypto.CapabilityClaims{TokenID: tokenID, ExpiryUnix: now + int64(3600+i)}
		req := proto.PathOpenRequest{TokenProofNonce: "nonce-1"}
		if err := s.checkAndRememberProofNonce(claims, req, now); err != nil {
			t.Fatalf("token %s should pass: %v", tokenID, err)
		}
	}
	overflowTokenID := fmt.Sprintf("jti-bucket-%05d", total)
	if err := s.checkAndRememberProofNonce(
		crypto.CapabilityClaims{TokenID: overflowTokenID, ExpiryUnix: now + 7200},
		proto.PathOpenRequest{TokenProofNonce: "nonce-1"},
		now,
	); err == nil {
		t.Fatalf("expected token replay bucket saturation")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()
	if got := len(s.proofNonceSeen); got != tokenProofReplayMaxTokenIDs {
		t.Fatalf("expected %d token buckets retained, got %d", tokenProofReplayMaxTokenIDs, got)
	}
	newestTokenID := fmt.Sprintf("jti-bucket-%05d", total-1)
	if _, ok := s.proofNonceSeen[newestTokenID]; !ok {
		t.Fatalf("expected newest token bucket %q retained", newestTokenID)
	}
	if _, ok := s.proofNonceSeen[overflowTokenID]; ok {
		t.Fatalf("did not expect overflow token bucket retained")
	}
}

func TestCheckAndRememberProofNoncePersistsAcrossReload(t *testing.T) {
	now := time.Now().Unix()
	storePath := filepath.Join(t.TempDir(), "exit_replay_store.json")
	claims := crypto.CapabilityClaims{
		TokenID:    "jti-persist-1",
		ExpiryUnix: now + 3600,
	}
	req := proto.PathOpenRequest{TokenProofNonce: "nonce-1"}

	s := &Service{
		tokenProofReplayGuard:     true,
		tokenProofReplayStoreFile: storePath,
		proofNonceSeen:            make(map[string]map[string]int64),
	}
	if err := s.checkAndRememberProofNonce(claims, req, now); err != nil {
		t.Fatalf("first nonce should pass: %v", err)
	}

	loaded := &Service{
		tokenProofReplayGuard:     true,
		tokenProofReplayStoreFile: storePath,
	}
	if err := loaded.loadTokenProofReplayStore(now + 1); err != nil {
		t.Fatalf("load replay store: %v", err)
	}
	if err := loaded.checkAndRememberProofNonce(claims, req, now+1); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected replay rejection after reload, got %v", err)
	}
}

func TestLoadTokenProofReplayStorePrunesExpiredEntries(t *testing.T) {
	now := time.Now().Unix()
	storePath := filepath.Join(t.TempDir(), "exit_replay_store.json")
	expiredClaims := crypto.CapabilityClaims{
		TokenID:    "jti-persist-2",
		ExpiryUnix: now - 10,
	}
	freshClaims := crypto.CapabilityClaims{
		TokenID:    "jti-persist-2",
		ExpiryUnix: now + 3600,
	}

	seed := &Service{
		tokenProofReplayGuard:     true,
		tokenProofReplayStoreFile: storePath,
		proofNonceSeen:            make(map[string]map[string]int64),
	}
	if err := seed.checkAndRememberProofNonce(expiredClaims, proto.PathOpenRequest{TokenProofNonce: "nonce-old"}, now-20); err != nil {
		t.Fatalf("seed old nonce: %v", err)
	}
	if err := seed.checkAndRememberProofNonce(freshClaims, proto.PathOpenRequest{TokenProofNonce: "nonce-new"}, now); err != nil {
		t.Fatalf("seed new nonce: %v", err)
	}

	loaded := &Service{
		tokenProofReplayGuard:     true,
		tokenProofReplayStoreFile: storePath,
	}
	if err := loaded.loadTokenProofReplayStore(now); err != nil {
		t.Fatalf("load replay store: %v", err)
	}
	bucket := loaded.proofNonceSeen[freshClaims.TokenID]
	if got := len(bucket); got != 1 {
		t.Fatalf("expected one non-expired nonce after load, got %d", got)
	}
	if _, ok := bucket["nonce-new"]; !ok {
		t.Fatalf("expected non-expired nonce retained")
	}
	if _, ok := bucket["nonce-old"]; ok {
		t.Fatalf("did not expect expired nonce retained")
	}
}

func TestNewReadsTokenProofReplaySharedFileModeConfig(t *testing.T) {
	t.Setenv("EXIT_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE", "1")
	t.Setenv("EXIT_TOKEN_PROOF_REPLAY_LOCK_TIMEOUT_SEC", "9")

	s := New()
	if !s.tokenProofReplaySharedFileMode {
		t.Fatalf("expected EXIT_TOKEN_PROOF_REPLAY_SHARED_FILE_MODE to enable shared replay mode")
	}
	if got := s.effectiveTokenProofReplayLockTimeout(); got != 9*time.Second {
		t.Fatalf("effective replay lock timeout=%s want=%s", got, 9*time.Second)
	}
}

func TestNewReadsTokenProofReplayRedisConfig(t *testing.T) {
	t.Setenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_ADDR", "127.0.0.1:6380")
	t.Setenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_PASSWORD", "secret")
	t.Setenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_DB", "4")
	t.Setenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_TLS", "1")
	t.Setenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_PREFIX", "gpm:test:replay")
	t.Setenv("EXIT_TOKEN_PROOF_REPLAY_REDIS_DIAL_TIMEOUT_SEC", "7")

	s := New()
	if !s.tokenProofReplayRedisEnabled() {
		t.Fatalf("expected redis replay mode to be enabled")
	}
	if got := s.tokenProofReplayRedisAddr; got != "127.0.0.1:6380" {
		t.Fatalf("redis addr=%q want=%q", got, "127.0.0.1:6380")
	}
	if got := s.tokenProofReplayRedisPassword; got != "secret" {
		t.Fatalf("redis password=%q want=%q", got, "secret")
	}
	if got := s.tokenProofReplayRedisDB; got != 4 {
		t.Fatalf("redis db=%d want=%d", got, 4)
	}
	if !s.tokenProofReplayRedisTLS {
		t.Fatalf("expected redis tls enabled from env")
	}
	if got := s.effectiveTokenProofReplayRedisPrefix(); got != "gpm:test:replay" {
		t.Fatalf("redis prefix=%q want=%q", got, "gpm:test:replay")
	}
	if got := s.effectiveTokenProofReplayRedisDialTimeout(); got != 7*time.Second {
		t.Fatalf("redis dial timeout=%s want=%s", got, 7*time.Second)
	}
	if got := s.tokenProofReplayMode(); got != "redis" {
		t.Fatalf("replay mode=%q want=%q", got, "redis")
	}
}

func TestCheckAndRememberProofNonceSharedModeRejectsCrossInstanceReplay(t *testing.T) {
	now := time.Now().Unix()
	storePath := filepath.Join(t.TempDir(), "exit_replay_store_shared.json")
	claims := crypto.CapabilityClaims{
		TokenID:    "jti-shared-1",
		ExpiryUnix: now + 3600,
	}
	req := proto.PathOpenRequest{TokenProofNonce: "nonce-shared-1"}

	first := &Service{
		tokenProofReplayGuard:          true,
		tokenProofReplaySharedFileMode: true,
		tokenProofReplayLockTimeout:    time.Second,
		tokenProofReplayStoreFile:      storePath,
	}
	second := &Service{
		tokenProofReplayGuard:          true,
		tokenProofReplaySharedFileMode: true,
		tokenProofReplayLockTimeout:    time.Second,
		tokenProofReplayStoreFile:      storePath,
	}

	if err := first.checkAndRememberProofNonce(claims, req, now); err != nil {
		t.Fatalf("first shared replay nonce should pass: %v", err)
	}
	if err := second.checkAndRememberProofNonce(claims, req, now+1); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected shared replay rejection in second instance, got %v", err)
	}

	second.mu.RLock()
	defer second.mu.RUnlock()
	if seen := second.proofNonceSeen[claims.TokenID]; seen == nil {
		t.Fatalf("expected second instance memory cache refreshed from shared replay store")
	} else if _, ok := seen[req.TokenProofNonce]; !ok {
		t.Fatalf("expected shared nonce reflected in refreshed in-memory cache")
	}
}

func TestCheckAndRememberProofNonceSharedModeLockTimeout(t *testing.T) {
	now := time.Now().Unix()
	storePath := filepath.Join(t.TempDir(), "exit_replay_store_shared.json")
	lockPath := storePath + ".lock"
	if err := os.WriteFile(lockPath, []byte("held"), 0o600); err != nil {
		t.Fatalf("seed lock file: %v", err)
	}

	s := &Service{
		tokenProofReplayGuard:          true,
		tokenProofReplaySharedFileMode: true,
		tokenProofReplayLockTimeout:    100 * time.Millisecond,
		tokenProofReplayStoreFile:      storePath,
	}
	claims := crypto.CapabilityClaims{
		TokenID:    "jti-shared-lock-timeout",
		ExpiryUnix: now + 60,
	}
	req := proto.PathOpenRequest{TokenProofNonce: "nonce-shared-timeout"}
	err := s.checkAndRememberProofNonce(claims, req, now)
	if err == nil {
		t.Fatalf("expected lock timeout error in shared replay mode")
	}
	if !strings.Contains(err.Error(), "token proof replay lock failed") {
		t.Fatalf("expected lock failure context, got %v", err)
	}
	if !strings.Contains(err.Error(), "timeout acquiring replay store lock") {
		t.Fatalf("expected timeout lock error detail, got %v", err)
	}
}

func TestCheckAndRememberProofNonceRedisModeRejectsCrossInstanceReplay(t *testing.T) {
	now := time.Now().Unix()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	defer mr.Close()

	claims := crypto.CapabilityClaims{
		TokenID:    "jti-redis-1",
		ExpiryUnix: now + 3600,
	}
	req := proto.PathOpenRequest{TokenProofNonce: "nonce-redis-1"}

	first := &Service{
		tokenProofReplayGuard:            true,
		tokenProofReplayRedisAddr:        mr.Addr(),
		tokenProofReplayRedisPrefix:      "gpm:test:exit:replay",
		tokenProofReplayRedisDialTimeout: time.Second,
	}
	second := &Service{
		tokenProofReplayGuard:            true,
		tokenProofReplayRedisAddr:        mr.Addr(),
		tokenProofReplayRedisPrefix:      "gpm:test:exit:replay",
		tokenProofReplayRedisDialTimeout: time.Second,
	}

	if err := first.checkAndRememberProofNonce(claims, req, now); err != nil {
		t.Fatalf("first redis replay nonce should pass: %v", err)
	}
	if err := second.checkAndRememberProofNonce(claims, req, now+1); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected redis replay rejection in second instance, got %v", err)
	}
}

func TestCheckAndRememberProofNonceRedisModeFailureFailsClosed(t *testing.T) {
	now := time.Now().Unix()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("start miniredis: %v", err)
	}
	claims := crypto.CapabilityClaims{
		TokenID:    "jti-redis-fail-1",
		ExpiryUnix: now + 3600,
	}
	s := &Service{
		tokenProofReplayGuard:            true,
		tokenProofReplayRedisAddr:        mr.Addr(),
		tokenProofReplayRedisPrefix:      "gpm:test:exit:replay",
		tokenProofReplayRedisDialTimeout: time.Second,
	}
	if err := s.checkAndRememberProofNonce(claims, proto.PathOpenRequest{TokenProofNonce: "nonce-1"}, now); err != nil {
		t.Fatalf("seed redis nonce: %v", err)
	}
	mr.Close()

	err = s.checkAndRememberProofNonce(claims, proto.PathOpenRequest{TokenProofNonce: "nonce-2"}, now+1)
	if err == nil {
		t.Fatalf("expected redis failure to fail closed")
	}
	if !strings.Contains(err.Error(), "token proof replay redis failed") {
		t.Fatalf("expected redis failure context, got %v", err)
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

func TestApplyRevocationFeedRejectsUnsignedFeed(t *testing.T) {
	pub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	feed := proto.RevocationListResponse{
		Issuer:      "issuer-local",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{{JTI: "jti-unsigned", Until: now + 120}},
	}
	s := &Service{
		issuerPub:  pub,
		revokedJTI: map[string]int64{},
	}
	err = s.applyRevocationFeed(feed, now)
	if err == nil {
		t.Fatalf("expected unsigned feed rejection")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Fatalf("expected signature-related error, got %v", err)
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

func TestVerifyTokenThrottlesRefreshOnRepeatedInvalidTokens(t *testing.T) {
	pub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	fetchCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pubkeys" {
			http.NotFound(w, r)
			return
		}
		fetchCount++
		_ = json.NewEncoder(w).Encode(proto.IssuerPubKeysResponse{
			Issuer:  "issuer-local",
			PubKeys: []string{base64.RawURLEncoding.EncodeToString(pub)},
		})
	}))
	defer server.Close()

	s := &Service{
		issuerURLs:               []string{server.URL},
		httpClient:               server.Client(),
		issuerPubs:               map[string]ed25519.PublicKey{issuerKeyID(pub): pub},
		issuerKeyIssuer:          map[string]string{},
		verifyRefreshMinInterval: time.Hour,
	}
	if _, _, err := s.verifyToken("invalid-token-1"); err == nil {
		t.Fatalf("expected invalid token verification failure")
	}
	if _, _, err := s.verifyToken("invalid-token-2"); err == nil {
		t.Fatalf("expected repeated invalid token verification failure")
	}
	if fetchCount != 0 {
		t.Fatalf("expected malformed tokens to skip issuer refresh fetches, got %d", fetchCount)
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
	signature, err := signFeed(feed, priv)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return signature
}

func signFeed(feed proto.RevocationListResponse, priv ed25519.PrivateKey) (string, error) {
	unsigned := feed
	unsigned.Signature = ""
	payload, err := json.Marshal(unsigned)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload)), nil
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

func TestValidateRuntimeConfigRejectsMalformedStrictModeEnv(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "definitely")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected malformed strict-mode env to fail closed")
	}
	if !strings.Contains(err.Error(), "BETA_STRICT_MODE/EXIT_BETA_STRICT invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsEmptyStrictModeEnv(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", " ")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected empty strict-mode env to fail closed")
	}
	if !strings.Contains(err.Error(), "BETA_STRICT_MODE/EXIT_BETA_STRICT invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsMalformedProdStrictModeEnv(t *testing.T) {
	t.Setenv("PROD_STRICT_MODE", "invalid")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected malformed prod strict-mode env to fail closed")
	}
	if !strings.Contains(err.Error(), "PROD_STRICT_MODE/EXIT_PROD_STRICT invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsStrictModeWithEmptyExitRelayID(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "1")
	t.Setenv("EXIT_RELAY_ID", " ")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode with empty EXIT_RELAY_ID to fail closed")
	}
	if !strings.Contains(err.Error(), "EXIT_RELAY_ID") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigAllowsNonStrictModeWithEmptyExitRelayID(t *testing.T) {
	s := &Service{
		dataMode:     "opaque",
		wgBackend:    "command",
		wgPrivateKey: "/tmp/wg-exit.key",
		exitRelayID:  " ",
		betaStrict:   false,
		prodStrict:   false,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected non-strict mode with empty EXIT_RELAY_ID to validate, got %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRequiresLiveKernelReplayGuard(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		exitRelayID:           "exit-local-1",
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
		exitRelayID:           "exit-local-1",
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

func TestValidateRuntimeConfigBetaStrictRejectsDangerousOutboundPrivateDNS(t *testing.T) {
	t.Setenv(allowDangerousOutboundPrivateDNS, "1")

	s := &Service{
		betaStrict:            true,
		exitRelayID:           "exit-local-1",
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
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	expected := "BETA_STRICT_MODE forbids " + allowDangerousOutboundPrivateDNS
	if err.Error() != expected {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsDangerousIssuerKeysetReplacement(t *testing.T) {
	t.Setenv(allowDangerousIssuerKeysetReplacement, "1")

	s := &Service{
		betaStrict:            true,
		exitRelayID:           "exit-local-1",
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
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	expected := "BETA_STRICT_MODE forbids " + allowDangerousIssuerKeysetReplacement
	if err.Error() != expected {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsDangerousCosmosFallback(t *testing.T) {
	t.Setenv(allowDangerousCosmosAdapterFallback, "1")

	s := &Service{
		betaStrict:            true,
		exitRelayID:           "exit-local-1",
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
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	expected := "BETA_STRICT_MODE forbids " + allowDangerousCosmosAdapterFallback
	if err.Error() != expected {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsPeerRebind(t *testing.T) {
	s := &Service{
		betaStrict:            true,
		exitRelayID:           "exit-local-1",
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
		exitRelayID:           "exit-local-1",
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
		exitRelayID:           "exit-local-1",
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
		exitRelayID:           "exit-local-1",
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
		exitRelayID:           "exit-local-1",
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
		issuerMinKeyVotes:     2,
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

func TestValidateRuntimeConfigProdStrictRejectsInsecureSkipVerify(t *testing.T) {
	t.Setenv("MTLS_ENABLE", "1")
	t.Setenv("MTLS_INSECURE_SKIP_VERIFY", "1")

	s := &Service{
		prodStrict:            true,
		betaStrict:            true,
		exitRelayID:           "exit-local-1",
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
		issuerURLs:            []string{"https://issuer-a.example", "https://issuer-b.example"},
		issuerMinSources:      2,
		issuerMinOperators:    2,
		issuerMinKeyVotes:     2,
		issuerRequireID:       true,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict mode validation failure")
	}
	if !strings.Contains(err.Error(), "MTLS_INSECURE_SKIP_VERIFY") {
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

func TestDecodeBoundedJSONResponseRejectsOversizedBody(t *testing.T) {
	body := strings.NewReader(`{"value":"` + strings.Repeat("a", int(remoteResponseMaxBodyBytes)+1024) + `"}`)
	var out map[string]string
	if err := decodeBoundedJSONResponse(body, &out, remoteResponseMaxBodyBytes); err == nil {
		t.Fatalf("expected oversized response rejection")
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

func TestNewBetaStrictConflictPreservesStrictMode(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("EXIT_BETA_STRICT", "1")

	s := New()
	if !s.betaStrict {
		t.Fatalf("expected strict mode enabled when strict env vars conflict")
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

func TestNewProdStrictConflictPreservesStrictMode(t *testing.T) {
	t.Setenv("PROD_STRICT_MODE", "0")
	t.Setenv("EXIT_PROD_STRICT", "1")

	s := New()
	if !s.prodStrict {
		t.Fatalf("expected prod strict mode enabled when strict env vars conflict")
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
	pub, priv, err := crypto.GenerateEd25519Keypair()
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
			feed := proto.RevocationListResponse{
				Issuer:      "issuer-local",
				GeneratedAt: time.Now().Unix(),
				ExpiresAt:   time.Now().Add(time.Minute).Unix(),
				Revocations: []proto.Revocation{},
			}
			signature, err := signFeed(feed, priv)
			if err != nil {
				http.Error(w, "sign revocation feed", http.StatusInternalServerError)
				return
			}
			feed.Signature = signature
			_ = json.NewEncoder(w).Encode(feed)
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
	pub, priv, err := crypto.GenerateEd25519Keypair()
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
			feed := proto.RevocationListResponse{
				Issuer:      issuerID,
				GeneratedAt: time.Now().Unix(),
				ExpiresAt:   time.Now().Add(time.Minute).Unix(),
				Revocations: []proto.Revocation{},
			}
			signature, err := signFeed(feed, priv)
			if err != nil {
				http.Error(w, "sign revocation feed", http.StatusInternalServerError)
				return
			}
			feed.Signature = signature
			_ = json.NewEncoder(w).Encode(feed)
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

func TestRefreshIssuerKeysRequiresIssuerIdentityForOperatorQuorum(t *testing.T) {
	srvMissing := newIssuerPubKeyServer(t, "")
	defer srvMissing.Close()
	srvKnown := newIssuerPubKeyServer(t, "issuer-known")
	defer srvKnown.Close()

	s := &Service{
		issuerURLs:         []string{srvMissing.URL, srvKnown.URL},
		issuerMinSources:   1,
		issuerMinOperators: 2,
		httpClient:         &http.Client{Timeout: 100 * time.Millisecond},
		issuerPubs:         map[string]ed25519.PublicKey{},
		issuerKeyIssuer:    map[string]string{},
		minTokenEpoch:      map[string]int64{},
	}
	err := s.refreshIssuerKeys(context.Background())
	if err == nil {
		t.Fatalf("expected operator quorum failure when source lacks issuer identity")
	}
	if !strings.Contains(err.Error(), "issuer operator quorum not met") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRefreshIssuerKeysSingleOperatorQuorumAllowsMissingIssuerIdentity(t *testing.T) {
	srv := newIssuerPubKeyServer(t, "")
	defer srv.Close()

	s := &Service{
		issuerURLs:         []string{srv.URL},
		issuerMinSources:   1,
		issuerMinOperators: 1,
		httpClient:         &http.Client{Timeout: 100 * time.Millisecond},
		issuerPubs:         map[string]ed25519.PublicKey{},
		issuerKeyIssuer:    map[string]string{},
		minTokenEpoch:      map[string]int64{},
	}
	if err := s.refreshIssuerKeys(context.Background()); err != nil {
		t.Fatalf("expected refresh success with single-operator quorum, got %v", err)
	}
	if len(s.issuerPubs) == 0 {
		t.Fatalf("expected issuer keys populated")
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

func TestRefreshIssuerKeysRejectsConflictingIssuerIdentityForSameKey(t *testing.T) {
	existingPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("existing keygen: %v", err)
	}
	sharedPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("shared keygen: %v", err)
	}
	sharedPubB64 := base64.RawURLEncoding.EncodeToString(sharedPub)

	newPubKeyServer := func(issuerID string) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/pubkeys" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(proto.IssuerPubKeysResponse{
				PubKeys: []string{sharedPubB64},
				Issuer:  issuerID,
			})
		}))
	}

	srvA := newPubKeyServer("issuer-a")
	defer srvA.Close()
	srvB := newPubKeyServer("issuer-b")
	defer srvB.Close()

	existingKeyID := issuerKeyID(existingPub)
	s := &Service{
		issuerURLs:         []string{srvA.URL, srvB.URL},
		issuerMinSources:   2,
		issuerMinOperators: 2,
		httpClient:         &http.Client{Timeout: 100 * time.Millisecond},
		issuerPubs:         map[string]ed25519.PublicKey{existingKeyID: existingPub},
		issuerKeyIssuer:    map[string]string{},
		minTokenEpoch:      map[string]int64{},
	}
	err = s.refreshIssuerKeys(context.Background())
	if err == nil {
		t.Fatalf("expected issuer identity conflict to be rejected")
	}
	if !strings.Contains(err.Error(), "issuer identity conflict for key") {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(s.issuerPubs) != 1 {
		t.Fatalf("expected existing issuer keyset unchanged on conflict, got %d keys", len(s.issuerPubs))
	}
	if _, ok := s.issuerPubs[existingKeyID]; !ok {
		t.Fatalf("expected existing trusted key retained after conflict")
	}
}

func TestRefreshIssuerKeysRejectsDisjointKeysetByDefault(t *testing.T) {
	existingPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("existing keygen: %v", err)
	}
	newPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("new keygen: %v", err)
	}
	newPubB64 := base64.RawURLEncoding.EncodeToString(newPub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pubkeys" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(proto.IssuerPubKeysResponse{
			PubKeys: []string{newPubB64},
			Issuer:  "issuer-rotation",
		})
	}))
	defer srv.Close()

	s := &Service{
		issuerURLs:         []string{srv.URL},
		issuerMinSources:   1,
		issuerMinOperators: 1,
		httpClient:         srv.Client(),
		issuerPubs: map[string]ed25519.PublicKey{
			issuerKeyID(existingPub): existingPub,
		},
		issuerKeyIssuer: map[string]string{},
		minTokenEpoch:   map[string]int64{},
	}
	err = s.refreshIssuerKeys(context.Background())
	if err == nil {
		t.Fatalf("expected disjoint keyset to be rejected")
	}
	if !strings.Contains(err.Error(), "continuity check failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRefreshIssuerKeysAllowsDisjointKeysetWithDangerousOverride(t *testing.T) {
	t.Setenv("EXIT_ALLOW_DANGEROUS_ISSUER_KEYSET_REPLACEMENT", "1")

	existingPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("existing keygen: %v", err)
	}
	newPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("new keygen: %v", err)
	}
	newPubB64 := base64.RawURLEncoding.EncodeToString(newPub)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/pubkeys" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(proto.IssuerPubKeysResponse{
			PubKeys: []string{newPubB64},
			Issuer:  "issuer-rotation",
		})
	}))
	defer srv.Close()

	s := &Service{
		issuerURLs:         []string{srv.URL},
		issuerMinSources:   1,
		issuerMinOperators: 1,
		httpClient:         srv.Client(),
		issuerPubs: map[string]ed25519.PublicKey{
			issuerKeyID(existingPub): existingPub,
		},
		issuerKeyIssuer: map[string]string{},
		minTokenEpoch:   map[string]int64{},
	}
	if err := s.refreshIssuerKeys(context.Background()); err != nil {
		t.Fatalf("expected dangerous override to allow disjoint rotation, got %v", err)
	}
	if _, ok := s.issuerPubs[issuerKeyID(newPub)]; !ok {
		t.Fatalf("expected refreshed keyset to include new key")
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

func TestApplyRevocationFeedRejectsSignerIssuerMismatch(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	feed := proto.RevocationListResponse{
		Issuer:      "issuer-spoofed",
		GeneratedAt: now,
		ExpiresAt:   now + 30,
		Revocations: []proto.Revocation{{JTI: "jti-spoof", Until: now + 120}},
	}
	feed.Signature = mustSignFeed(t, feed, priv)
	keyID := issuerKeyID(pub)

	s := &Service{
		issuerPubs:        map[string]ed25519.PublicKey{keyID: pub},
		issuerKeyIssuer:   map[string]string{keyID: "issuer-real"},
		revokedJTI:        map[string]int64{},
		minTokenEpoch:     map[string]int64{},
		revocationVersion: map[string]int64{},
	}
	if err := s.applyRevocationFeed(feed, now); err == nil {
		t.Fatalf("expected signer/issuer mismatch rejection")
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

func TestCleanupExpiredSessionsRemovesWGSessionAndFinalizesSettlement(t *testing.T) {
	now := time.Now()
	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}

	wgManager := &sequentialWGManager{}
	settlementStub := &settlementServiceStub{}
	s := &Service{
		wgInterface: "wg-exit0",
		wgManager:   wgManager,
		settlement:  settlementStub,
		sessions: map[string]sessionInfo{
			"sid-expired-wg-cleanup": {
				claims:        crypto.CapabilityClaims{Subject: "client-expired", ExpiryUnix: now.Add(-time.Second).Unix()},
				seenNonces:    map[uint64]struct{}{},
				transport:     "wireguard-udp",
				sessionKeyID:  "sk-expired-wg-cleanup",
				clientPubKey:  "client-wg-pubkey-expired",
				clientInnerIP: "10.90.0.9/32",
				ingressBytes:  1024,
				egressBytes:   2048,
			},
		},
		wgSessionProxies: map[string]*net.UDPConn{
			"sid-expired-wg-cleanup": proxyConn,
		},
		wgProxyLastSeen: map[string]int64{
			"sid-expired-wg-cleanup": now.Add(-10 * time.Second).Unix(),
		},
		proofNonceSeen: make(map[string]map[string]int64),
	}

	s.cleanupExpiredSessions(now)

	if _, exists := s.sessions["sid-expired-wg-cleanup"]; exists {
		t.Fatalf("expected expired session removed from session map")
	}
	if _, exists := s.wgSessionProxies["sid-expired-wg-cleanup"]; exists {
		t.Fatalf("expected expired session proxy removed")
	}
	if wgManager.removeSessionCalls != 1 {
		t.Fatalf("expected one wg remove call for expired session, got %d", wgManager.removeSessionCalls)
	}
	if len(wgManager.removedSessionCfgs) != 1 {
		t.Fatalf("expected one wg remove config, got %d", len(wgManager.removedSessionCfgs))
	}
	cfg := wgManager.removedSessionCfgs[0]
	if cfg.SessionID != "sid-expired-wg-cleanup" {
		t.Fatalf("expected wg remove for sid-expired-wg-cleanup, got %s", cfg.SessionID)
	}
	if cfg.SessionKeyID != "sk-expired-wg-cleanup" {
		t.Fatalf("expected wg remove session key sk-expired-wg-cleanup, got %s", cfg.SessionKeyID)
	}
	if settlementStub.recordUsageCalls != 1 || settlementStub.settleSessionCalls != 1 {
		t.Fatalf("expected settlement finalized once for expired cleanup, got record=%d settle=%d",
			settlementStub.recordUsageCalls, settlementStub.settleSessionCalls)
	}
	if _, err := proxyConn.WriteToUDP([]byte("x"), proxyConn.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatalf("expected expired session proxy connection closed")
	}
}

func TestAllowSessionPeerExpiredSessionTriggersTeardown(t *testing.T) {
	now := time.Now()
	proxyConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}

	wgManager := &sequentialWGManager{}
	settlementStub := &settlementServiceStub{}
	s := &Service{
		wgInterface: "wg-exit0",
		wgManager:   wgManager,
		settlement:  settlementStub,
		sessions: map[string]sessionInfo{
			"sid-allow-expired": {
				claims:        crypto.CapabilityClaims{Subject: "client-allow-expired", ExpiryUnix: now.Add(-time.Second).Unix()},
				seenNonces:    map[uint64]struct{}{},
				transport:     "wireguard-udp",
				sessionKeyID:  "sk-allow-expired",
				clientPubKey:  "client-wg-pubkey-allow-expired",
				clientInnerIP: "10.90.0.12/32",
				peerAddr:      "127.0.0.1:51820",
				ingressBytes:  256,
				egressBytes:   128,
			},
		},
		wgSessionProxies: map[string]*net.UDPConn{
			"sid-allow-expired": proxyConn,
		},
	}

	allowed, rebound, current := s.allowSessionPeer("sid-allow-expired", "127.0.0.1:51999", now)
	if allowed || rebound {
		t.Fatalf("expected expired session source check to reject packet")
	}
	if current != "127.0.0.1:51820" {
		t.Fatalf("expected current peer reported before teardown, got %s", current)
	}
	if _, exists := s.sessions["sid-allow-expired"]; exists {
		t.Fatalf("expected expired session removed by allowSessionPeer teardown")
	}
	if _, exists := s.wgSessionProxies["sid-allow-expired"]; exists {
		t.Fatalf("expected expired session proxy removed by allowSessionPeer teardown")
	}
	if wgManager.removeSessionCalls != 1 {
		t.Fatalf("expected one wg remove call for expired allowSessionPeer teardown, got %d", wgManager.removeSessionCalls)
	}
	if settlementStub.recordUsageCalls != 1 || settlementStub.settleSessionCalls != 1 {
		t.Fatalf("expected settlement finalized once for expired allowSessionPeer teardown, got record=%d settle=%d",
			settlementStub.recordUsageCalls, settlementStub.settleSessionCalls)
	}
	if _, err := proxyConn.WriteToUDP([]byte("x"), proxyConn.LocalAddr().(*net.UDPAddr)); err == nil {
		t.Fatalf("expected expired allowSessionPeer proxy connection closed")
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

func TestAuthorizeNonceCapacityEvictsIncrementally(t *testing.T) {
	now := time.Now()
	seen := make(map[uint64]struct{}, 8192)
	for i := uint64(1); i <= 8192; i++ {
		seen[i] = struct{}{}
	}
	s := &Service{
		sessions: map[string]sessionInfo{
			"sid-capacity": {
				claims:     crypto.CapabilityClaims{ExpiryUnix: now.Add(time.Minute).Unix()},
				seenNonces: seen,
			},
		},
	}
	if _, err := s.authorizeNonce("sid-capacity", 9001, now); err != nil {
		t.Fatalf("authorizeNonce failed: %v", err)
	}
	got := s.sessions["sid-capacity"]
	if len(got.seenNonces) <= 1 {
		t.Fatalf("expected incremental eviction preserving nonce history, got %d entries", len(got.seenNonces))
	}
	if _, ok := got.seenNonces[9001]; !ok {
		t.Fatalf("expected newly authorized nonce to be tracked")
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

func TestApplyRevocationFeedRejectsSameVersionConflict(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	base := proto.RevocationListResponse{
		Issuer:      "issuer-conflict",
		Version:     7,
		GeneratedAt: now,
		ExpiresAt:   now + 60,
		Revocations: []proto.Revocation{{JTI: "jti-conflict", Until: now + 300}},
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

	conflict := proto.RevocationListResponse{
		Issuer:      "issuer-conflict",
		Version:     7,
		GeneratedAt: now + 1,
		ExpiresAt:   now + 60,
		Revocations: []proto.Revocation{{JTI: "jti-conflict", Until: now + 120}},
	}
	conflict.Signature = mustSignFeed(t, conflict, priv)

	err = s.applyRevocationFeed(conflict, now)
	if err == nil {
		t.Fatalf("expected same-version conflict rejection")
	}
	if !strings.Contains(err.Error(), "revocation feed conflict detected") || !strings.Contains(err.Error(), "shortened_active=1") {
		t.Fatalf("expected explicit conflict diagnostics, got %v", err)
	}
	if !s.isRevoked(issuerKeyID(pub), "jti-conflict", now+200) {
		t.Fatalf("expected original revocation preserved after conflict")
	}
}

func TestApplyRevocationFeedStaleSourceOverwriteAttemptFailsClosed(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	base := proto.RevocationListResponse{
		Issuer:      "issuer-stale",
		Version:     11,
		GeneratedAt: now,
		ExpiresAt:   now + 60,
		Revocations: []proto.Revocation{{JTI: "jti-stale", Until: now + 300}},
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
		Issuer:      "issuer-stale",
		Version:     10,
		GeneratedAt: now + 1,
		ExpiresAt:   now + 60,
		Revocations: []proto.Revocation{},
	}
	stale.Signature = mustSignFeed(t, stale, priv)

	err = s.applyRevocationFeed(stale, now)
	if err == nil {
		t.Fatalf("expected stale-source overwrite rejection")
	}
	if !strings.Contains(err.Error(), "version rollback detected") ||
		!strings.Contains(err.Error(), "incoming_version=10") ||
		!strings.Contains(err.Error(), "current_version=11") {
		t.Fatalf("expected explicit rollback diagnostics, got %v", err)
	}
	if got := s.revocationVersion["issuer-stale"]; got != 11 {
		t.Fatalf("expected revocation version to remain 11, got %d", got)
	}
	if !s.isRevoked(issuerKeyID(pub), "jti-stale", now+200) {
		t.Fatalf("expected stale overwrite attempt not to un-revoke trusted token")
	}
}

func TestApplyRevocationFeedPartialSameVersionCannotUnrevoke(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now().Unix()
	base := proto.RevocationListResponse{
		Issuer:      "issuer-partial",
		Version:     15,
		GeneratedAt: now,
		ExpiresAt:   now + 60,
		Revocations: []proto.Revocation{
			{JTI: "jti-a", Until: now + 300},
			{JTI: "jti-b", Until: now + 300},
		},
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

	partial := proto.RevocationListResponse{
		Issuer:      "issuer-partial",
		Version:     15,
		GeneratedAt: now + 1,
		ExpiresAt:   now + 60,
		Revocations: []proto.Revocation{
			{JTI: "jti-a", Until: now + 300},
		},
	}
	partial.Signature = mustSignFeed(t, partial, priv)

	err = s.applyRevocationFeed(partial, now)
	if err == nil {
		t.Fatalf("expected partial same-version feed rejection")
	}
	if !strings.Contains(err.Error(), "revocation feed conflict detected") || !strings.Contains(err.Error(), "missing_active=1") {
		t.Fatalf("expected explicit partial-feed conflict diagnostics, got %v", err)
	}
	if !s.isRevoked(issuerKeyID(pub), "jti-a", now+200) {
		t.Fatalf("expected jti-a to remain revoked")
	}
	if !s.isRevoked(issuerKeyID(pub), "jti-b", now+200) {
		t.Fatalf("expected jti-b to remain revoked after partial update attempt")
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

func TestSanitizeEgressCommandInputsRejectsMaliciousValues(t *testing.T) {
	tests := []struct {
		name  string
		chain string
		cidr  string
		iface string
	}{
		{
			name:  "chain injection",
			chain: "PRIVNODE_EGRESS; touch /tmp/pwned",
			cidr:  "10.90.0.0/24",
			iface: "eth0",
		},
		{
			name:  "iface injection",
			chain: "PRIVNODE_EGRESS",
			cidr:  "10.90.0.0/24",
			iface: "eth0; id",
		},
		{
			name:  "cidr injection",
			chain: "PRIVNODE_EGRESS",
			cidr:  "10.90.0.0/24; iptables -F",
			iface: "eth0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := sanitizeEgressCommandInputs(tc.chain, tc.cidr, tc.iface)
			if err == nil {
				t.Fatalf("expected input rejection for %q", tc.name)
			}
		})
	}
}

func TestSanitizeEgressCommandInputsAcceptsValidValues(t *testing.T) {
	chain, cidr, iface, err := sanitizeEgressCommandInputs(" CHAIN_X-1 ", "10.90.0.0/24", "eth0.100@uplink")
	if err != nil {
		t.Fatalf("expected valid egress command inputs: %v", err)
	}
	if chain != "CHAIN_X-1" {
		t.Fatalf("expected trimmed chain value, got %q", chain)
	}
	if cidr != "10.90.0.0/24" {
		t.Fatalf("expected cidr preserved, got %q", cidr)
	}
	if iface != "eth0.100@uplink" {
		t.Fatalf("expected iface preserved, got %q", iface)
	}
}

func TestConfigureEgressRejectsInvalidCommandInputs(t *testing.T) {
	s := &Service{
		egressBackend: "command",
		egressChain:   "PRIVNODE_EGRESS",
		egressCIDR:    "10.90.0.0/24",
		egressIface:   "eth0; rm -rf /",
	}
	err := s.configureEgress(context.Background())
	if err == nil {
		t.Fatalf("expected configureEgress rejection for invalid egress interface")
	}
	if s.egressConfigured {
		t.Fatalf("expected egressConfigured to remain false on validation failure")
	}
}

func TestTeardownEgressRejectsInvalidCommandInputs(t *testing.T) {
	s := &Service{
		egressBackend:    "command",
		egressConfigured: true,
		egressChain:      "PRIVNODE_EGRESS; whoami",
		egressCIDR:       "10.90.0.0/24",
		egressIface:      "eth0",
	}
	err := s.teardownEgress(context.Background())
	if err == nil {
		t.Fatalf("expected teardownEgress rejection for invalid egress chain")
	}
	if !s.egressConfigured {
		t.Fatalf("expected egressConfigured unchanged when teardown validation fails")
	}
}

func TestNewSettlementServiceFromEnvWiresBlockchainModeForCosmosAdapter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", srv.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "exit-mode-test")
	t.Setenv("COSMOS_SETTLEMENT_MAX_RETRIES", "0")
	t.Setenv("COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS", "500")

	svc := newSettlementServiceFromEnv()
	ctx := context.Background()

	const reservationID = "res-exit-blockchain-on"
	const sessionID = "sess-exit-blockchain-on"
	reservation, err := svc.ReserveSponsorCredits(ctx, settlement.SponsorCreditReservation{
		ReservationID: reservationID,
		SponsorID:     "sponsor-a",
		SubjectID:     "subject-a",
		SessionID:     sessionID,
		AmountMicros:  1000,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != settlement.OperationStatusSubmitted {
		t.Fatalf("expected submitted reservation when cosmos adapter is configured, got %s", reservation.Status)
	}

	_, err = svc.AuthorizePayment(ctx, settlement.PaymentProof{
		ReservationID: reservationID,
		SponsorID:     "sponsor-a",
		SubjectID:     "subject-a",
		SessionID:     sessionID,
	})
	if err == nil {
		t.Fatalf("expected AuthorizePayment to fail until chain finality in blockchain mode")
	}
	if !strings.Contains(err.Error(), "chain") {
		t.Fatalf("expected chain finality error, got %v", err)
	}
}

func TestNewSettlementServiceFromEnvKeepsMemoryModeWhenChainAdapterDisabled(t *testing.T) {
	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", "")

	svc := newSettlementServiceFromEnv()
	ctx := context.Background()

	const reservationID = "res-exit-memory-on"
	const sessionID = "sess-exit-memory-on"
	reservation, err := svc.ReserveSponsorCredits(ctx, settlement.SponsorCreditReservation{
		ReservationID: reservationID,
		SponsorID:     "sponsor-a",
		SubjectID:     "subject-a",
		SessionID:     sessionID,
		AmountMicros:  1000,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != settlement.OperationStatusConfirmed {
		t.Fatalf("expected confirmed reservation in default memory mode, got %s", reservation.Status)
	}

	auth, err := svc.AuthorizePayment(ctx, settlement.PaymentProof{
		ReservationID: reservationID,
		SponsorID:     "sponsor-a",
		SubjectID:     "subject-a",
		SessionID:     sessionID,
	})
	if err != nil {
		t.Fatalf("AuthorizePayment: %v", err)
	}
	if auth.ReservationID != reservationID {
		t.Fatalf("expected authorization for reservation %s, got %s", reservationID, auth.ReservationID)
	}
}
