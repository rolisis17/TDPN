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
		Status                    string `json:"status"`
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

func TestHandleSettlementStatusReturnsDeterministicDegradedError(t *testing.T) {
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

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "degraded" {
		t.Fatalf("expected degraded status, got %q", resp.Status)
	}
	if !strings.EqualFold(resp.Error, "reconcile failed") {
		t.Fatalf("expected deterministic reconcile error message, got %q", resp.Error)
	}
	if stub.calls != 1 {
		t.Fatalf("expected reconcile call count 1, got %d", stub.calls)
	}
}
