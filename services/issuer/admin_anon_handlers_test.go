package issuer

import (
	"bytes"
	stded25519 "crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func newAnonAdminHandlerTestService(t *testing.T) *Service {
	t.Helper()

	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	dir := t.TempDir()
	return &Service{
		adminToken:          "test-admin-token",
		adminAllowToken:     true,
		issuerID:            "issuer-local",
		pubKey:              pub,
		privKey:             priv,
		anonRevocations:     map[string]int64{},
		anonRevocationsFile: filepath.Join(dir, "anon_revocations.json"),
		anonDisputes:        map[string]anonymousCredentialDispute{},
		auditFile:           filepath.Join(dir, "audit.json"),
	}
}

func TestHandleIssueAnonymousCredential(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		s := newAnonAdminHandlerTestService(t)
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/anon-credential/issue", nil)
		req.Header.Set("X-Admin-Token", "test-admin-token")
		rr := httptest.NewRecorder()

		s.handleIssueAnonymousCredential(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		s := newAnonAdminHandlerTestService(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/anon-credential/issue", strings.NewReader("{"))
		req.Header.Set("X-Admin-Token", "test-admin-token")
		rr := httptest.NewRecorder()

		s.handleIssueAnonymousCredential(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("success with defaults and signed credential payload", func(t *testing.T) {
		s := newAnonAdminHandlerTestService(t)
		reqBody, err := json.Marshal(proto.IssueAnonymousCredentialRequest{
			Tier: 0,
		})
		if err != nil {
			t.Fatalf("marshal issue request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/anon-credential/issue", bytes.NewReader(reqBody))
		req.Header.Set("X-Admin-Token", "test-admin-token")
		rr := httptest.NewRecorder()
		now := time.Now().Unix()

		s.handleIssueAnonymousCredential(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		var out proto.IssueAnonymousCredentialResponse
		if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
			t.Fatalf("decode issue response: %v", err)
		}
		if strings.TrimSpace(out.Credential) == "" {
			t.Fatalf("expected credential in response")
		}
		if out.ExpiresAt <= now {
			t.Fatalf("expected future expires_at, got %d now=%d", out.ExpiresAt, now)
		}
		claims, payload, sig, err := parseAnonymousCredential(out.Credential)
		if err != nil {
			t.Fatalf("parse credential: %v", err)
		}
		if !stded25519.Verify(s.pubKey, payload, sig) {
			t.Fatalf("expected credential signature verification to pass")
		}
		if claims.Issuer != "issuer-local" {
			t.Fatalf("expected issuer issuer-local, got %q", claims.Issuer)
		}
		if strings.TrimSpace(claims.CredentialID) == "" {
			t.Fatalf("expected generated credential id in claims")
		}
		if claims.Tier != 1 {
			t.Fatalf("expected tier clamped to 1 when omitted/zero, got %d", claims.Tier)
		}
		if claims.ExpiryUnix != out.ExpiresAt {
			t.Fatalf("expected claim expiry %d to match response expires_at %d", claims.ExpiryUnix, out.ExpiresAt)
		}
	})
}

func TestHandleRevokeAnonymousCredential(t *testing.T) {
	t.Run("method not allowed", func(t *testing.T) {
		s := newAnonAdminHandlerTestService(t)
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/anon-credential/revoke", nil)
		req.Header.Set("X-Admin-Token", "test-admin-token")
		rr := httptest.NewRecorder()

		s.handleRevokeAnonymousCredential(rr, req)

		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		s := newAnonAdminHandlerTestService(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/anon-credential/revoke", strings.NewReader("{"))
		req.Header.Set("X-Admin-Token", "test-admin-token")
		rr := httptest.NewRecorder()

		s.handleRevokeAnonymousCredential(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing required credential_id", func(t *testing.T) {
		s := newAnonAdminHandlerTestService(t)
		reqBody, err := json.Marshal(proto.RevokeAnonymousCredentialRequest{
			CredentialID: "   ",
			Reason:       "missing id",
		})
		if err != nil {
			t.Fatalf("marshal revoke request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/anon-credential/revoke", bytes.NewReader(reqBody))
		req.Header.Set("X-Admin-Token", "test-admin-token")
		rr := httptest.NewRecorder()

		s.handleRevokeAnonymousCredential(rr, req)

		if rr.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("unknown credential revoke succeeds and persists", func(t *testing.T) {
		s := newAnonAdminHandlerTestService(t)
		until := time.Now().Add(2 * time.Hour).Unix()
		reqBody, err := json.Marshal(proto.RevokeAnonymousCredentialRequest{
			CredentialID: "cred-unknown-1",
			Until:        until,
			Reason:       "manual revoke",
		})
		if err != nil {
			t.Fatalf("marshal revoke request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/anon-credential/revoke", bytes.NewReader(reqBody))
		req.Header.Set("X-Admin-Token", "test-admin-token")
		rr := httptest.NewRecorder()

		s.handleRevokeAnonymousCredential(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		var out map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
			t.Fatalf("decode revoke response: %v", err)
		}
		if gotID, _ := out["credential_id"].(string); gotID != "cred-unknown-1" {
			t.Fatalf("expected credential_id cred-unknown-1, got %v", out["credential_id"])
		}
		gotUntil, ok := out["until"].(float64)
		if !ok {
			t.Fatalf("expected numeric until in response, got %T", out["until"])
		}
		if int64(gotUntil) != until {
			t.Fatalf("expected until %d, got %d", until, int64(gotUntil))
		}
		if stored, ok := s.anonRevocations["cred-unknown-1"]; !ok || stored != until {
			t.Fatalf("expected anon revocation map to contain credential until=%d, got ok=%v value=%d", until, ok, stored)
		}
		if !s.isAnonCredentialRevoked("cred-unknown-1", time.Now().Unix()) {
			t.Fatalf("expected newly revoked credential to be active in revocation map")
		}
	})

	t.Run("already revoked credential can be revoked again with updated until", func(t *testing.T) {
		s := newAnonAdminHandlerTestService(t)
		credID := "cred-revoked-1"
		firstUntil := time.Now().Add(1 * time.Hour).Unix()
		secondUntil := time.Now().Add(3 * time.Hour).Unix()
		s.anonRevocations[credID] = firstUntil

		reqBody, err := json.Marshal(proto.RevokeAnonymousCredentialRequest{
			CredentialID: credID,
			Until:        secondUntil,
			Reason:       "extend revoke",
		})
		if err != nil {
			t.Fatalf("marshal revoke request: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/anon-credential/revoke", bytes.NewReader(reqBody))
		req.Header.Set("X-Admin-Token", "test-admin-token")
		rr := httptest.NewRecorder()

		s.handleRevokeAnonymousCredential(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		var out map[string]interface{}
		if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
			t.Fatalf("decode revoke response: %v", err)
		}
		if gotID, _ := out["credential_id"].(string); gotID != credID {
			t.Fatalf("expected credential_id %s, got %v", credID, out["credential_id"])
		}
		gotUntil, ok := out["until"].(float64)
		if !ok {
			t.Fatalf("expected numeric until in response, got %T", out["until"])
		}
		if int64(gotUntil) != secondUntil {
			t.Fatalf("expected until %d, got %d", secondUntil, int64(gotUntil))
		}
		if stored := s.anonRevocations[credID]; stored != secondUntil {
			t.Fatalf("expected stored revoke until=%d, got %d", secondUntil, stored)
		}
		if !s.isAnonCredentialRevoked(credID, time.Now().Unix()) {
			t.Fatalf("expected credential to remain revoked after update")
		}
	})
}
