package issuer

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/settlement"
)

func TestHandleSettlementStatusRequiresAdmin(t *testing.T) {
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      settlement.NewMemoryService(),
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	rr := httptest.NewRecorder()

	s.handleSettlementStatus(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized without admin token, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleSettlementStatusReturnsBacklogCounters(t *testing.T) {
	now := time.Unix(1713200000, 0).UTC()
	stub := &issuerSettlementReconcileStub{
		report: settlement.ReconcileReport{
			GeneratedAt:               now,
			PendingAdapterOperations:  3,
			ShadowAdapterConfigured:   true,
			ShadowAttemptedOperations: 6,
			ShadowSubmittedOperations: 5,
			ShadowFailedOperations:    1,
			PendingOperations:         2,
			SubmittedOperations:       8,
			ConfirmedOperations:       5,
			FailedOperations:          1,
		},
	}
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      stub,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleSettlementStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Enabled                   bool   `json:"enabled"`
		Stale                     bool   `json:"stale"`
		Status                    string `json:"status"`
		CheckedAt                 int64  `json:"checked_at"`
		LastError                 string `json:"last_error"`
		GeneratedAt               int64  `json:"generated_at"`
		PendingAdapterOperations  int    `json:"pending_adapter_operations"`
		ShadowAdapterConfigured   bool   `json:"shadow_adapter_configured"`
		ShadowAttemptedOperations int    `json:"shadow_attempted_operations"`
		ShadowSubmittedOperations int    `json:"shadow_submitted_operations"`
		ShadowFailedOperations    int    `json:"shadow_failed_operations"`
		PendingOperations         int    `json:"pending_operations"`
		SubmittedOperations       int    `json:"submitted_operations"`
		ConfirmedOperations       int    `json:"confirmed_operations"`
		FailedOperations          int    `json:"failed_operations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "backlog" {
		t.Fatalf("expected status backlog, got %q", resp.Status)
	}
	if !resp.Enabled {
		t.Fatalf("expected settlement status endpoint enabled")
	}
	if resp.Stale {
		t.Fatalf("expected fresh reconcile report")
	}
	if resp.CheckedAt <= 0 {
		t.Fatalf("expected checked_at timestamp, got %d", resp.CheckedAt)
	}
	if resp.LastError != "" {
		t.Fatalf("expected no last_error on success, got %q", resp.LastError)
	}
	if resp.GeneratedAt != now.Unix() {
		t.Fatalf("expected generated_at %d, got %d", now.Unix(), resp.GeneratedAt)
	}
	if resp.PendingAdapterOperations != 3 || !resp.ShadowAdapterConfigured || resp.ShadowAttemptedOperations != 6 || resp.ShadowSubmittedOperations != 5 || resp.ShadowFailedOperations != 1 {
		t.Fatalf("unexpected shadow counters: %+v", resp)
	}
	if resp.PendingOperations != 2 || resp.SubmittedOperations != 8 || resp.ConfirmedOperations != 5 || resp.FailedOperations != 1 {
		t.Fatalf("unexpected counters: %+v", resp)
	}
	if stub.calls != 1 {
		t.Fatalf("expected reconcile call count 1, got %d", stub.calls)
	}
}

func TestHandleSettlementStatusReconcileErrorIsFailSoftWithCachedReport(t *testing.T) {
	stub := &issuerSettlementReconcileStub{err: errors.New("adapter unavailable")}
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      stub,
		settlementStatus: settlementStatusSnapshot{
			lastReport: settlement.ReconcileReport{
				GeneratedAt:               time.Unix(1713201111, 0).UTC(),
				PendingAdapterOperations:  5,
				ShadowAdapterConfigured:   true,
				ShadowAttemptedOperations: 4,
				ShadowSubmittedOperations: 3,
				ShadowFailedOperations:    1,
				PendingOperations:         6,
				SubmittedOperations:       2,
				ConfirmedOperations:       1,
				FailedOperations:          3,
			},
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleSettlementStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 on fail-soft reconcile error, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Enabled                   bool   `json:"enabled"`
		Stale                     bool   `json:"stale"`
		Status                    string `json:"status"`
		LastError                 string `json:"last_error"`
		PendingAdapterOperations  int    `json:"pending_adapter_operations"`
		ShadowAdapterConfigured   bool   `json:"shadow_adapter_configured"`
		ShadowAttemptedOperations int    `json:"shadow_attempted_operations"`
		ShadowSubmittedOperations int    `json:"shadow_submitted_operations"`
		ShadowFailedOperations    int    `json:"shadow_failed_operations"`
		PendingOperations         int    `json:"pending_operations"`
		SubmittedOperations       int    `json:"submitted_operations"`
		ConfirmedOperations       int    `json:"confirmed_operations"`
		FailedOperations          int    `json:"failed_operations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Enabled {
		t.Fatalf("expected settlement status endpoint enabled")
	}
	if !resp.Stale {
		t.Fatalf("expected stale response on reconcile error")
	}
	if resp.Status != "backlog" {
		t.Fatalf("expected backlog status from cached backlog report, got %q", resp.Status)
	}
	if !strings.Contains(resp.LastError, "adapter unavailable") {
		t.Fatalf("expected reconcile error detail in last_error, got %q", resp.LastError)
	}
	if resp.PendingAdapterOperations != 5 || resp.PendingOperations != 6 || resp.SubmittedOperations != 2 || resp.ConfirmedOperations != 1 || resp.FailedOperations != 3 {
		t.Fatalf("expected cached counters in fail-soft response, got %+v", resp)
	}
	if !resp.ShadowAdapterConfigured || resp.ShadowAttemptedOperations != 4 || resp.ShadowSubmittedOperations != 3 || resp.ShadowFailedOperations != 1 {
		t.Fatalf("expected cached shadow counters in fail-soft response, got %+v", resp)
	}
	if stub.calls != 1 {
		t.Fatalf("expected reconcile call count 1, got %d", stub.calls)
	}
}

func TestHandleSettlementStatusReconcileErrorWithoutCachedReportIsDegraded(t *testing.T) {
	stub := &issuerSettlementReconcileStub{err: errors.New("adapter unavailable")}
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      stub,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleSettlementStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200 on fail-soft reconcile error, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Enabled   bool   `json:"enabled"`
		Stale     bool   `json:"stale"`
		Status    string `json:"status"`
		LastError string `json:"last_error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Enabled {
		t.Fatalf("expected settlement status endpoint enabled")
	}
	if !resp.Stale {
		t.Fatalf("expected stale response on reconcile error")
	}
	if resp.Status != "degraded" {
		t.Fatalf("expected degraded status without cached report, got %q", resp.Status)
	}
	if !strings.Contains(resp.LastError, "adapter unavailable") {
		t.Fatalf("expected reconcile error detail in last_error, got %q", resp.LastError)
	}
	if stub.calls != 1 {
		t.Fatalf("expected reconcile call count 1, got %d", stub.calls)
	}
}

func TestHandleSettlementStatusStaleClearsAfterRecovery(t *testing.T) {
	backlogAt := time.Unix(1713202222, 0).UTC()
	recoveredAt := time.Unix(1713203333, 0).UTC()
	stub := &issuerSettlementReconcileStub{
		err: errors.New("adapter unavailable"),
	}
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      stub,
		settlementStatus: settlementStatusSnapshot{
			lastReport: settlement.ReconcileReport{
				GeneratedAt:              backlogAt,
				PendingAdapterOperations: 2,
				PendingOperations:        1,
				SubmittedOperations:      1,
			},
		},
	}

	req1 := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	req1.Header.Set("X-Admin-Token", "admin-secret-token")
	rr1 := httptest.NewRecorder()
	s.handleSettlementStatus(rr1, req1)

	if rr1.Code != http.StatusOK {
		t.Fatalf("expected status 200 on fail-soft reconcile error, got %d body=%s", rr1.Code, rr1.Body.String())
	}
	var outageResp struct {
		Stale     bool   `json:"stale"`
		Status    string `json:"status"`
		LastError string `json:"last_error"`
	}
	if err := json.Unmarshal(rr1.Body.Bytes(), &outageResp); err != nil {
		t.Fatalf("decode outage response: %v", err)
	}
	if !outageResp.Stale {
		t.Fatalf("expected stale=true during fail-soft outage response")
	}
	if outageResp.Status != "backlog" {
		t.Fatalf("expected backlog status while fail-soft uses cached backlog report, got %q", outageResp.Status)
	}
	if !strings.Contains(outageResp.LastError, "adapter unavailable") {
		t.Fatalf("expected fail-soft outage last_error detail, got %q", outageResp.LastError)
	}

	stub.err = nil
	stub.report = settlement.ReconcileReport{
		GeneratedAt: recoveredAt,
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	req2.Header.Set("X-Admin-Token", "admin-secret-token")
	rr2 := httptest.NewRecorder()
	s.handleSettlementStatus(rr2, req2)

	if rr2.Code != http.StatusOK {
		t.Fatalf("expected status 200 after reconcile recovery, got %d body=%s", rr2.Code, rr2.Body.String())
	}
	var recoveryResp struct {
		Stale       bool   `json:"stale"`
		Status      string `json:"status"`
		LastError   string `json:"last_error"`
		GeneratedAt int64  `json:"generated_at"`
	}
	if err := json.Unmarshal(rr2.Body.Bytes(), &recoveryResp); err != nil {
		t.Fatalf("decode recovery response: %v", err)
	}
	if recoveryResp.Stale {
		t.Fatalf("expected stale=false once reconcile recovers")
	}
	if recoveryResp.Status != "ok" {
		t.Fatalf("expected ok status after recovery, got %q", recoveryResp.Status)
	}
	if recoveryResp.LastError != "" {
		t.Fatalf("expected last_error cleared after recovery, got %q", recoveryResp.LastError)
	}
	if recoveryResp.GeneratedAt != recoveredAt.Unix() {
		t.Fatalf("expected generated_at=%d after recovery, got %d", recoveredAt.Unix(), recoveryResp.GeneratedAt)
	}
	if stub.calls != 2 {
		t.Fatalf("expected reconcile call count 2, got %d", stub.calls)
	}
}
