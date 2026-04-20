package issuer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/proto"
)

func newAdminAuditRevokeTestService(t *testing.T) *Service {
	t.Helper()
	baseDir := t.TempDir()
	return &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		tokenTTL:        2 * time.Minute,
		revocations:     make(map[string]int64),
		revocationsFile: filepath.Join(baseDir, "issuer_revocations.json"),
		audit:           make([]proto.AuditEvent, 0, 16),
		auditFile:       filepath.Join(baseDir, "issuer_audit.json"),
		auditMax:        100,
	}
}

func TestHandleGetAuditMethodNotAllowed(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/audit", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleGetAudit(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleGetAuditNotFoundSubjectReturnsEmptyList(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)
	s.audit = append(s.audit,
		proto.AuditEvent{ID: 1, Action: "subject-upsert", Subject: "alice"},
		proto.AuditEvent{ID: 2, Action: "subject-promote", Subject: "bob"},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit?subject=charlie", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleGetAudit(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", got)
	}
	var out []proto.AuditEvent
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out) != 0 {
		t.Fatalf("expected empty list for unknown subject, got %+v", out)
	}
}

func TestHandleGetAuditSuccessSubjectFilterAndLimit(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)
	s.audit = append(s.audit,
		proto.AuditEvent{ID: 1, Action: "subject-upsert", Subject: "alice", Reason: "seed"},
		proto.AuditEvent{ID: 2, Action: "subject-promote", Subject: "bob", Reason: "seed"},
		proto.AuditEvent{ID: 3, Action: "subject-dispute-apply", Subject: "alice", Reason: "case-open"},
		proto.AuditEvent{ID: 4, Action: "subject-appeal-open", Subject: "alice", Reason: "appeal"},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit?subject=alice&limit=2", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleGetAudit(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out []proto.AuditEvent
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out) != 2 {
		t.Fatalf("expected 2 events after filtering/limit, got %d payload=%+v", len(out), out)
	}
	if out[0].Action != "subject-appeal-open" || out[0].Subject != "alice" {
		t.Fatalf("unexpected first event: %+v", out[0])
	}
	if out[1].Action != "subject-dispute-apply" || out[1].Subject != "alice" {
		t.Fatalf("unexpected second event: %+v", out[1])
	}
}

func TestHandleGetAuditCapsExcessiveLimit(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)
	for i := 0; i < adminAuditQueryLimitMax+20; i++ {
		s.audit = append(s.audit, proto.AuditEvent{
			ID:      int64(i + 1),
			Action:  "subject-upsert",
			Subject: "alice",
		})
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/admin/audit?limit=999999", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleGetAudit(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out []proto.AuditEvent
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out) != adminAuditQueryLimitMax {
		t.Fatalf("events len=%d want=%d", len(out), adminAuditQueryLimitMax)
	}
	if out[0].ID != int64(adminAuditQueryLimitMax+20) {
		t.Fatalf("first event id=%d want=%d", out[0].ID, adminAuditQueryLimitMax+20)
	}
}

func TestHandleRevokeTokenMethodNotAllowed(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/admin/revoke-token", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleRevokeToken(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleRevokeTokenInvalidJSON(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/revoke-token", bytes.NewBufferString("{"))
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleRevokeToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleRevokeTokenRejectsMalformedJSONShapes(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)

	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: `{"jti":"token-abc","until":123,"unexpected":"value"}`,
		},
		{
			name: "trailing json",
			body: `{"jti":"token-abc","until":123} {"jti":"token-def"}`,
		},
		{
			name: "oversized body",
			body: `{"jti":"` + strings.Repeat("a", 9*1024) + `"}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/admin/revoke-token", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("X-Admin-Token", "admin-secret-token")
			rr := httptest.NewRecorder()

			s.handleRevokeToken(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected status %d, got %d body=%s", http.StatusBadRequest, rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "invalid json") {
				t.Fatalf("expected invalid json error, got body=%s", rr.Body.String())
			}
		})
	}
}

func TestHandleRevokeTokenMissingJTI(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)
	payload, err := json.Marshal(proto.RevokeTokenRequest{Until: 123})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/revoke-token", bytes.NewReader(payload))
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleRevokeToken(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleRevokeTokenSuccess(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)
	until := time.Now().Add(5 * time.Minute).Unix()
	payload, err := json.Marshal(proto.RevokeTokenRequest{JTI: "token-abc", Until: until})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/revoke-token", bytes.NewReader(payload))
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleRevokeToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected content-type application/json, got %q", got)
	}
	var out proto.Revocation
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.JTI != "token-abc" || out.Until != until {
		t.Fatalf("unexpected response payload: %+v", out)
	}
	if got := s.revocations["token-abc"]; got != until {
		t.Fatalf("expected revocations map updated with until=%d, got %d", until, got)
	}
	if s.revocationVersion != 1 {
		t.Fatalf("expected revocationVersion incremented to 1, got %d", s.revocationVersion)
	}
	if len(s.audit) == 0 {
		t.Fatalf("expected audit event to be recorded")
	}
	last := s.audit[len(s.audit)-1]
	if last.Action != "token-revoke" || last.Subject != "token-abc" || last.Reason != "admin-revocation" {
		t.Fatalf("unexpected audit event: %+v", last)
	}
	if int64(last.Value) != until {
		t.Fatalf("expected audit value to include revoke-until=%d, got %f", until, last.Value)
	}
}

func TestHandleRevokeTokenSuccessDefaultUntilForUnknownToken(t *testing.T) {
	s := newAdminAuditRevokeTestService(t)
	before := time.Now().Unix()
	payload, err := json.Marshal(proto.RevokeTokenRequest{JTI: "token-new"})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/revoke-token", bytes.NewReader(payload))
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleRevokeToken(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.Revocation
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.JTI != "token-new" {
		t.Fatalf("expected jti token-new, got %q", out.JTI)
	}
	if out.Until <= before {
		t.Fatalf("expected default until after request time, got %d (before=%d)", out.Until, before)
	}
	maxExpected := before + int64((s.tokenTTL+5*time.Second)/time.Second)
	if out.Until > maxExpected {
		t.Fatalf("expected default until near tokenTTL window, got %d maxExpected=%d", out.Until, maxExpected)
	}
	if got := s.revocations["token-new"]; got != out.Until {
		t.Fatalf("expected unknown token to be revocable, map until=%d response until=%d", got, out.Until)
	}
}
