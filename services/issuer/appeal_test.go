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

func TestHandleOpenAndResolveAppeal(t *testing.T) {
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
	s.subjects["client-a"] = proto.SubjectProfile{
		Subject:    "client-a",
		Kind:       proto.SubjectKindClient,
		Tier:       2,
		Reputation: 0.9,
		Bond:       150,
	}
	openBody, _ := json.Marshal(proto.OpenAppealRequest{
		Subject:     "client-a",
		Until:       time.Now().Add(time.Hour).Unix(),
		CaseID:      "case-appeal-200",
		EvidenceRef: "evidence://appeal-note-200",
		Reason:      "manual-review",
	})
	openReq := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/appeal/open", bytes.NewReader(openBody))
	openReq.Header.Set("X-Admin-Token", "test-admin")
	openRR := httptest.NewRecorder()
	s.handleOpenAppeal(openRR, openReq)
	if openRR.Code != http.StatusOK {
		t.Fatalf("open appeal expected 200, got %d", openRR.Code)
	}
	var opened proto.SubjectProfile
	if err := json.NewDecoder(openRR.Body).Decode(&opened); err != nil {
		t.Fatalf("decode open appeal response: %v", err)
	}
	if opened.AppealUntil <= time.Now().Unix() {
		t.Fatalf("expected active appeal window")
	}
	if opened.AppealCase != "case-appeal-200" || opened.AppealRef != "evidence://appeal-note-200" {
		t.Fatalf("expected appeal metadata persisted, got case=%q ref=%q", opened.AppealCase, opened.AppealRef)
	}

	resolveBody, _ := json.Marshal(proto.ResolveAppealRequest{
		Subject: "client-a",
		Reason:  "resolved",
	})
	resolveReq := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/appeal/resolve", bytes.NewReader(resolveBody))
	resolveReq.Header.Set("X-Admin-Token", "test-admin")
	resolveRR := httptest.NewRecorder()
	s.handleResolveAppeal(resolveRR, resolveReq)
	if resolveRR.Code != http.StatusOK {
		t.Fatalf("resolve appeal expected 200, got %d", resolveRR.Code)
	}
	var resolved proto.SubjectProfile
	if err := json.NewDecoder(resolveRR.Body).Decode(&resolved); err != nil {
		t.Fatalf("decode resolve appeal response: %v", err)
	}
	if resolved.AppealUntil != 0 {
		t.Fatalf("expected cleared appeal, got %d", resolved.AppealUntil)
	}
	if resolved.AppealCase != "" || resolved.AppealRef != "" {
		t.Fatalf("expected cleared appeal metadata, got case=%q ref=%q", resolved.AppealCase, resolved.AppealRef)
	}
}

func TestEffectiveTierForAppealRelaxesDisputeCap(t *testing.T) {
	now := time.Now()
	s := &Service{
		subjects: map[string]proto.SubjectProfile{
			"client-a": {
				Subject:      "client-a",
				Kind:         proto.SubjectKindClient,
				Tier:         3,
				Reputation:   0.99,
				Bond:         700,
				TierCap:      1,
				DisputeUntil: now.Add(2 * time.Hour).Unix(),
				AppealUntil:  now.Add(90 * time.Minute).Unix(),
			},
		},
	}
	if got := s.effectiveTierFor("client-a", 3); got != 2 {
		t.Fatalf("expected appeal-relaxed effective tier 2, got %d", got)
	}
	s.subjects["client-a"] = proto.SubjectProfile{
		Subject:      "client-a",
		Kind:         proto.SubjectKindClient,
		Tier:         3,
		Reputation:   0.99,
		Bond:         700,
		TierCap:      1,
		DisputeUntil: now.Add(2 * time.Hour).Unix(),
	}
	if got := s.effectiveTierFor("client-a", 3); got != 1 {
		t.Fatalf("expected strict dispute-capped tier 1 without appeal, got %d", got)
	}
}

func TestBuildRelayTrustFeedIncludesAppealSignal(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	now := time.Now()
	s := &Service{
		pubKey:          pub,
		privKey:         priv,
		subjects:        map[string]proto.SubjectProfile{},
		trustFeedTTL:    30 * time.Second,
		trustConfidence: 0.9,
		trustBondMax:    500,
	}
	s.subjects["exit-a"] = proto.SubjectProfile{
		Subject:      "exit-a",
		Kind:         proto.SubjectKindRelayExit,
		Tier:         3,
		Reputation:   0.97,
		Bond:         600,
		TierCap:      1,
		DisputeUntil: now.Add(2 * time.Hour).Unix(),
		AppealUntil:  now.Add(time.Hour).Unix(),
		DisputeCase:  "case-dispute-300",
		DisputeRef:   "evidence://dispute-300",
		AppealCase:   "case-appeal-300",
		AppealRef:    "evidence://appeal-300",
	}
	feed, err := s.buildRelayTrustFeed(now)
	if err != nil {
		t.Fatalf("buildRelayTrustFeed: %v", err)
	}
	if len(feed.Attestations) != 1 {
		t.Fatalf("expected one attestation, got %d", len(feed.Attestations))
	}
	att := feed.Attestations[0]
	if att.AppealUntil <= now.Unix() {
		t.Fatalf("expected appeal signal in attestation")
	}
	if att.AbusePenalty > 0.56 {
		t.Fatalf("expected appeal-adjusted abuse penalty, got %f", att.AbusePenalty)
	}
	if att.Confidence < 0.49 {
		t.Fatalf("expected appeal-adjusted confidence boost, got %f", att.Confidence)
	}
	if att.DisputeCase != "case-dispute-300" || att.DisputeRef != "evidence://dispute-300" {
		t.Fatalf("expected dispute metadata in trust feed, got case=%q ref=%q", att.DisputeCase, att.DisputeRef)
	}
	if att.AppealCase != "case-appeal-300" || att.AppealRef != "evidence://appeal-300" {
		t.Fatalf("expected appeal metadata in trust feed, got case=%q ref=%q", att.AppealCase, att.AppealRef)
	}
}
