package issuer

import (
	"path/filepath"
	"testing"

	"privacynode/pkg/proto"
)

func TestRecommendedTierFromSignals(t *testing.T) {
	p := proto.SubjectProfile{Tier: 1, Reputation: 0.85, Bond: 10}
	if got := recommendedTier(p); got != 2 {
		t.Fatalf("expected tier 2 from reputation signal, got %d", got)
	}
	p = proto.SubjectProfile{Tier: 1, Reputation: 0.97, Bond: 600}
	if got := recommendedTier(p); got != 3 {
		t.Fatalf("expected tier 3 from strong signals, got %d", got)
	}
}

func TestRecordAuditPersistAndLoad(t *testing.T) {
	file := filepath.Join(t.TempDir(), "audit.json")
	s := &Service{
		auditFile: file,
		auditMax:  10,
		audit:     make([]proto.AuditEvent, 0),
	}
	s.recordAudit(proto.AuditEvent{Action: "subject-upsert", Subject: "alice"})
	s.recordAudit(proto.AuditEvent{Action: "subject-promote", Subject: "alice"})

	s2 := &Service{auditFile: file}
	if err := s2.loadAudit(); err != nil {
		t.Fatalf("loadAudit: %v", err)
	}
	if len(s2.audit) != 2 {
		t.Fatalf("expected 2 audit events, got %d", len(s2.audit))
	}
	if s2.audit[0].ID == 0 || s2.audit[1].ID == 0 {
		t.Fatalf("expected event ids assigned")
	}
	if s2.audit[0].Timestamp == 0 || s2.audit[1].Timestamp == 0 {
		t.Fatalf("expected event timestamps assigned")
	}
}
