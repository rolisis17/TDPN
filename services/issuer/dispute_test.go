package issuer

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
)

func TestHandleApplyDisputeCapsTierAndTrustSignal(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	dir := t.TempDir()
	s := &Service{
		adminToken:        "test-admin",
		pubKey:            pub,
		privKey:           priv,
		subjects:          map[string]proto.SubjectProfile{},
		subjectsFile:      filepath.Join(dir, "subjects.json"),
		audit:             make([]proto.AuditEvent, 0, 8),
		auditFile:         filepath.Join(dir, "audit.json"),
		auditMax:          100,
		disputeDefaultTTL: time.Hour,
		trustFeedTTL:      30 * time.Second,
		trustConfidence:   0.9,
		trustBondMax:      500,
	}
	s.subjects["exit-a"] = proto.SubjectProfile{
		Subject:    "exit-a",
		Kind:       proto.SubjectKindRelayExit,
		Tier:       3,
		Reputation: 0.97,
		Bond:       600,
	}

	body, _ := json.Marshal(proto.ApplyDisputeRequest{
		Subject:           "exit-a",
		TierCap:           1,
		Until:             time.Now().Add(2 * time.Hour).Unix(),
		ReputationPenalty: 0.2,
		CaseID:            "case-dispute-100",
		EvidenceRef:       "evidence://packet-capture-100",
		Reason:            "abuse-signal",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/dispute", bytes.NewReader(body))
	req.Header.Set("X-Admin-Token", "test-admin")
	rr := httptest.NewRecorder()
	s.handleApplyDispute(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var out proto.SubjectProfile
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("decode subject profile: %v", err)
	}
	if out.Tier != 1 {
		t.Fatalf("expected disputed subject tier 1, got %d", out.Tier)
	}
	if out.TierCap != 1 {
		t.Fatalf("expected tier cap 1, got %d", out.TierCap)
	}
	if out.DisputeUntil <= time.Now().Unix() {
		t.Fatalf("expected active dispute window")
	}
	if out.Reputation > 0.78 || out.Reputation < 0.76 {
		t.Fatalf("expected penalty-adjusted reputation around 0.77, got %f", out.Reputation)
	}
	if out.DisputeCase != "case-dispute-100" || out.DisputeRef != "evidence://packet-capture-100" {
		t.Fatalf("expected dispute metadata persisted, got case=%q ref=%q", out.DisputeCase, out.DisputeRef)
	}
	if got := s.effectiveTierFor("exit-a", 3); got != 1 {
		t.Fatalf("expected effective tier capped at 1, got %d", got)
	}

	feed, err := s.buildRelayTrustFeed(time.Now())
	if err != nil {
		t.Fatalf("buildRelayTrustFeed: %v", err)
	}
	if len(feed.Attestations) != 1 {
		t.Fatalf("expected one attestation, got %d", len(feed.Attestations))
	}
	att := feed.Attestations[0]
	if att.AbusePenalty <= 0.6 {
		t.Fatalf("expected elevated abuse penalty from dispute, got %f", att.AbusePenalty)
	}
	if att.Confidence >= 0.9 {
		t.Fatalf("expected lowered confidence under dispute, got %f", att.Confidence)
	}
	if att.DisputeCase != "case-dispute-100" || att.DisputeRef != "evidence://packet-capture-100" {
		t.Fatalf("expected dispute metadata in trust feed, got case=%q ref=%q", att.DisputeCase, att.DisputeRef)
	}
}

func TestHandleClearDisputeRestoresEligibility(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	dir := t.TempDir()
	s := &Service{
		adminToken:        "test-admin",
		pubKey:            pub,
		privKey:           priv,
		subjects:          map[string]proto.SubjectProfile{},
		subjectsFile:      filepath.Join(dir, "subjects.json"),
		audit:             make([]proto.AuditEvent, 0, 8),
		auditFile:         filepath.Join(dir, "audit.json"),
		auditMax:          100,
		disputeDefaultTTL: time.Hour,
	}
	s.subjects["exit-a"] = proto.SubjectProfile{
		Subject:    "exit-a",
		Kind:       proto.SubjectKindClient,
		Tier:       3,
		Reputation: 0.97,
		Bond:       600,
	}

	applyBody, _ := json.Marshal(proto.ApplyDisputeRequest{
		Subject: "exit-a",
		TierCap: 1,
		Until:   time.Now().Add(time.Hour).Unix(),
	})
	applyReq := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/dispute", bytes.NewReader(applyBody))
	applyReq.Header.Set("X-Admin-Token", "test-admin")
	applyRR := httptest.NewRecorder()
	s.handleApplyDispute(applyRR, applyReq)
	if applyRR.Code != http.StatusOK {
		t.Fatalf("apply dispute expected 200, got %d", applyRR.Code)
	}
	if got := s.effectiveTierFor("exit-a", 3); got != 1 {
		t.Fatalf("expected capped tier before clear, got %d", got)
	}

	clearBody, _ := json.Marshal(proto.ClearDisputeRequest{
		Subject: "exit-a",
		Reason:  "resolved",
	})
	clearReq := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/dispute/clear", bytes.NewReader(clearBody))
	clearReq.Header.Set("X-Admin-Token", "test-admin")
	clearRR := httptest.NewRecorder()
	s.handleClearDispute(clearRR, clearReq)
	if clearRR.Code != http.StatusOK {
		t.Fatalf("clear dispute expected 200, got %d", clearRR.Code)
	}
	var out proto.SubjectProfile
	if err := json.NewDecoder(clearRR.Body).Decode(&out); err != nil {
		t.Fatalf("decode clear response: %v", err)
	}
	if out.TierCap != 0 || out.DisputeUntil != 0 {
		t.Fatalf("expected cleared dispute metadata, got tier_cap=%d dispute_until=%d", out.TierCap, out.DisputeUntil)
	}
	if out.DisputeCase != "" || out.DisputeRef != "" {
		t.Fatalf("expected cleared dispute case metadata, got case=%q ref=%q", out.DisputeCase, out.DisputeRef)
	}
	if got := s.effectiveTierFor("exit-a", 3); got != 3 {
		t.Fatalf("expected restored eligibility tier 3, got %d", got)
	}
}
