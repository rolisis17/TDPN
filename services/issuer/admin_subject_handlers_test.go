package issuer

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"privacynode/pkg/proto"
)

const adminSubjectHandlersTestToken = "super-secret-admin-token"

func newAdminSubjectHandlersTestService(t *testing.T) *Service {
	t.Helper()
	tmp := t.TempDir()
	return &Service{
		adminToken:         adminSubjectHandlersTestToken,
		adminAllowToken:    true,
		adminAllowTokenSet: true,
		subjects:           map[string]proto.SubjectProfile{},
		subjectsFile:       filepath.Join(tmp, "subjects.json"),
		auditFile:          filepath.Join(tmp, "audit.json"),
	}
}

func adminSubjectHandlersTestRequest(method string, target string, body string) *http.Request {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("X-Admin-Token", adminSubjectHandlersTestToken)
	return req
}

func decodeAdminSubjectProfile(t *testing.T, rr *httptest.ResponseRecorder) proto.SubjectProfile {
	t.Helper()
	var got proto.SubjectProfile
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode response json: %v body=%q", err, rr.Body.String())
	}
	return got
}

func TestHandleUpsertSubject(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/upsert", strings.NewReader(`{"subject":"sub-1","tier":1}`))
		rr := httptest.NewRecorder()
		s.handleUpsertSubject(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodGet, "/v1/admin/subject/upsert", "")
		rr := httptest.NewRecorder()
		s.handleUpsertSubject(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bad_json", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/upsert", "{")
		rr := httptest.NewRecorder()
		s.handleUpsertSubject(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid json") {
			t.Fatalf("expected 400 invalid json, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid_subject_or_tier", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/upsert", `{"subject":"","tier":0}`)
		rr := httptest.NewRecorder()
		s.handleUpsertSubject(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid subject or tier") {
			t.Fatalf("expected 400 invalid subject or tier, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(
			http.MethodPost,
			"/v1/admin/subject/upsert",
			`{"subject":"sub-1","kind":"client","tier":2,"reputation":0.4,"bond":25,"stake":5}`,
		)
		rr := httptest.NewRecorder()
		s.handleUpsertSubject(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		got := decodeAdminSubjectProfile(t, rr)
		if got.Subject != "sub-1" || got.Kind != proto.SubjectKindClient || got.Tier != 2 {
			t.Fatalf("unexpected profile: %+v", got)
		}
	})
}

func TestHandlePromoteSubject(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/promote", strings.NewReader(`{"subject":"sub-1","tier":2}`))
		rr := httptest.NewRecorder()
		s.handlePromoteSubject(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodGet, "/v1/admin/subject/promote", "")
		rr := httptest.NewRecorder()
		s.handlePromoteSubject(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bad_json", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/promote", "{")
		rr := httptest.NewRecorder()
		s.handlePromoteSubject(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid json") {
			t.Fatalf("expected 400 invalid json, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("invalid_subject_or_tier", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/promote", `{"subject":"","tier":4}`)
		rr := httptest.NewRecorder()
		s.handlePromoteSubject(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid subject or tier") {
			t.Fatalf("expected 400 invalid subject or tier, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		s.subjects["sub-1"] = proto.SubjectProfile{
			Subject: "sub-1",
			Kind:    proto.SubjectKindRelayExit,
			Tier:    1,
		}
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/promote", `{"subject":"sub-1","tier":3,"reason":"strong uptime"}`)
		rr := httptest.NewRecorder()
		s.handlePromoteSubject(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		got := decodeAdminSubjectProfile(t, rr)
		if got.Subject != "sub-1" || got.Tier != 3 {
			t.Fatalf("unexpected profile: %+v", got)
		}
	})
}

func TestHandleApplyReputation(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/reputation/apply", strings.NewReader(`{"subject":"sub-1","delta":0.1}`))
		rr := httptest.NewRecorder()
		s.handleApplyReputation(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodGet, "/v1/admin/subject/reputation/apply", "")
		rr := httptest.NewRecorder()
		s.handleApplyReputation(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bad_json", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/reputation/apply", "{")
		rr := httptest.NewRecorder()
		s.handleApplyReputation(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid json") {
			t.Fatalf("expected 400 invalid json, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing_subject", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/reputation/apply", `{"subject":" ","delta":0.2}`)
		rr := httptest.NewRecorder()
		s.handleApplyReputation(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "missing subject") {
			t.Fatalf("expected 400 missing subject, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		s.subjects["sub-1"] = proto.SubjectProfile{
			Subject:    "sub-1",
			Kind:       proto.SubjectKindClient,
			Tier:       1,
			Reputation: 0.5,
		}
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/reputation/apply", `{"subject":"sub-1","delta":0.4,"reason":"good behavior"}`)
		rr := httptest.NewRecorder()
		s.handleApplyReputation(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		got := decodeAdminSubjectProfile(t, rr)
		if got.Subject != "sub-1" || got.Tier != 2 {
			t.Fatalf("unexpected profile: %+v", got)
		}
		if math.Abs(got.Reputation-0.9) > 1e-9 {
			t.Fatalf("expected reputation 0.9, got %.12f", got.Reputation)
		}
	})
}

func TestHandleApplyBond(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/bond/apply", strings.NewReader(`{"subject":"sub-1","delta":10}`))
		rr := httptest.NewRecorder()
		s.handleApplyBond(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodGet, "/v1/admin/subject/bond/apply", "")
		rr := httptest.NewRecorder()
		s.handleApplyBond(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bad_json", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/bond/apply", "{")
		rr := httptest.NewRecorder()
		s.handleApplyBond(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid json") {
			t.Fatalf("expected 400 invalid json, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing_subject", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/bond/apply", `{"subject":" ","delta":20}`)
		rr := httptest.NewRecorder()
		s.handleApplyBond(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "missing subject") {
			t.Fatalf("expected 400 missing subject, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		s.subjects["sub-1"] = proto.SubjectProfile{
			Subject:    "sub-1",
			Kind:       proto.SubjectKindRelayExit,
			Tier:       1,
			Reputation: 0.6,
			Bond:       50,
		}
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/bond/apply", `{"subject":"sub-1","delta":60,"reason":"top-up"}`)
		rr := httptest.NewRecorder()
		s.handleApplyBond(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		got := decodeAdminSubjectProfile(t, rr)
		if got.Subject != "sub-1" || got.Tier != 2 {
			t.Fatalf("unexpected profile: %+v", got)
		}
		if math.Abs(got.Bond-110) > 1e-9 {
			t.Fatalf("expected bond 110, got %.12f", got.Bond)
		}
	})
}

func TestHandleRecomputeTier(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/recompute-tier", strings.NewReader(`{"subject":"sub-1"}`))
		rr := httptest.NewRecorder()
		s.handleRecomputeTier(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodGet, "/v1/admin/subject/recompute-tier", "")
		rr := httptest.NewRecorder()
		s.handleRecomputeTier(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("bad_json", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/recompute-tier", "{")
		rr := httptest.NewRecorder()
		s.handleRecomputeTier(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "invalid json") {
			t.Fatalf("expected 400 invalid json, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing_subject", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/recompute-tier", `{"subject":" "}`)
		rr := httptest.NewRecorder()
		s.handleRecomputeTier(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "missing subject") {
			t.Fatalf("expected 400 missing subject, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("not_found", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/recompute-tier", `{"subject":"unknown-subject"}`)
		rr := httptest.NewRecorder()
		s.handleRecomputeTier(rr, req)
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "not found") {
			t.Fatalf("expected 404 not found, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		s.subjects["sub-1"] = proto.SubjectProfile{
			Subject:    "sub-1",
			Kind:       proto.SubjectKindRelayExit,
			Tier:       1,
			Reputation: 0.95,
			Bond:       600,
		}
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject/recompute-tier", `{"subject":"sub-1","reason":"periodic recompute"}`)
		rr := httptest.NewRecorder()
		s.handleRecomputeTier(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		got := decodeAdminSubjectProfile(t, rr)
		if got.Subject != "sub-1" || got.Tier != 3 {
			t.Fatalf("unexpected profile: %+v", got)
		}
	})
}

func TestHandleGetSubject(t *testing.T) {
	t.Run("unauthorized", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := httptest.NewRequest(http.MethodGet, "/v1/admin/subject?subject=sub-1", nil)
		rr := httptest.NewRecorder()
		s.handleGetSubject(rr, req)
		if rr.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("method_not_allowed", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodPost, "/v1/admin/subject?subject=sub-1", "")
		rr := httptest.NewRecorder()
		s.handleGetSubject(rr, req)
		if rr.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected 405, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("missing_subject", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodGet, "/v1/admin/subject", "")
		rr := httptest.NewRecorder()
		s.handleGetSubject(rr, req)
		if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "missing subject") {
			t.Fatalf("expected 400 missing subject, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("not_found", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		req := adminSubjectHandlersTestRequest(http.MethodGet, "/v1/admin/subject?subject=missing", "")
		rr := httptest.NewRecorder()
		s.handleGetSubject(rr, req)
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "not found") {
			t.Fatalf("expected 404 not found, got %d body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("success", func(t *testing.T) {
		s := newAdminSubjectHandlersTestService(t)
		s.subjects["sub-1"] = proto.SubjectProfile{
			Subject:    "sub-1",
			Kind:       proto.SubjectKindClient,
			Tier:       2,
			Reputation: 0.85,
			Bond:       120,
		}
		req := adminSubjectHandlersTestRequest(http.MethodGet, "/v1/admin/subject?subject=sub-1", "")
		rr := httptest.NewRecorder()
		s.handleGetSubject(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d body=%s", rr.Code, rr.Body.String())
		}
		got := decodeAdminSubjectProfile(t, rr)
		if got.Subject != "sub-1" || got.Tier != 2 || got.Kind != proto.SubjectKindClient {
			t.Fatalf("unexpected profile: %+v", got)
		}
	})
}
