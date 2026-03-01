package issuer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"privacynode/pkg/proto"
)

func TestHandleApplyStake(t *testing.T) {
	s := &Service{
		adminToken:   "admin-token",
		subjects:     map[string]proto.SubjectProfile{"client-a": {Subject: "client-a", Kind: proto.SubjectKindClient, Tier: 1, Reputation: 0.9, Stake: 40}},
		subjectsFile: filepath.Join(t.TempDir(), "subjects.json"),
	}
	reqBody, err := json.Marshal(proto.ApplyStakeRequest{
		Subject: "client-a",
		Delta:   70,
		Reason:  "beta stake top-up",
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/stake/apply", bytes.NewReader(reqBody))
	req.Header.Set("X-Admin-Token", "admin-token")
	rr := httptest.NewRecorder()
	s.handleApplyStake(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var out proto.SubjectProfile
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.Stake < 109.9 || out.Stake > 110.1 {
		t.Fatalf("expected stake updated to 110, got %f", out.Stake)
	}
	if out.Tier != 2 {
		t.Fatalf("expected tier upgraded to 2 via stake threshold, got %d", out.Tier)
	}
}
