package issuer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"privacynode/pkg/proto"
	"privacynode/pkg/settlement"
)

func TestHandleSubmitSlashEvidenceRequiresAdmin(t *testing.T) {
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      settlement.NewMemoryService(),
	}

	body, _ := json.Marshal(proto.SubmitSlashEvidenceRequest{
		EvidenceID:    "ev-1",
		Subject:       "provider-1",
		ViolationType: "double-sign",
		EvidenceRef:   "obj://validator/double-sign/block-12",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/slash/evidence", bytes.NewReader(body))
	rr := httptest.NewRecorder()

	s.handleSubmitSlashEvidence(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized without admin token, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestHandleSubmitSlashEvidenceAcceptsObjectiveEvidence(t *testing.T) {
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      settlement.NewMemoryService(),
		auditFile:       filepath.Join(t.TempDir(), "issuer_audit.json"),
	}

	body, _ := json.Marshal(proto.SubmitSlashEvidenceRequest{
		EvidenceID:    "ev-2",
		Subject:       "provider-2",
		SessionID:     "sess-2",
		ViolationType: "double-sign",
		EvidenceRef:   "obj://validator/double-sign/block-13",
		SlashMicros:   1200,
		Currency:      "TDPNC",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/slash/evidence", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleSubmitSlashEvidence(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp proto.SubmitSlashEvidenceResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Accepted {
		t.Fatalf("expected accepted slash evidence response")
	}
	if resp.EvidenceID != "ev-2" || resp.Subject != "provider-2" {
		t.Fatalf("unexpected response payload: %+v", resp)
	}
	if resp.Status == "" {
		t.Fatalf("expected non-empty operation status")
	}
	if len(s.audit) == 0 || s.audit[len(s.audit)-1].Action != "subject-slash-evidence-submit" {
		t.Fatalf("expected slash-evidence audit event to be recorded")
	}
}

func TestHandleSubmitSlashEvidenceRejectsNonObjectiveViolation(t *testing.T) {
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      settlement.NewMemoryService(),
	}

	body, _ := json.Marshal(proto.SubmitSlashEvidenceRequest{
		EvidenceID:    "ev-3",
		Subject:       "provider-3",
		ViolationType: "manual-review-only",
		EvidenceRef:   "obj://validator/manual/block-14",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/slash/evidence", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()

	s.handleSubmitSlashEvidence(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "objective violation_type") {
		t.Fatalf("expected objective violation_type error, got %q", rr.Body.String())
	}
}

