package issuer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"privacynode/pkg/proto"
)

func TestSaveLoadSubjects(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "subjects.json")

	s := &Service{subjects: map[string]proto.SubjectProfile{}, subjectsFile: file}
	s.subjects["alice"] = proto.SubjectProfile{Subject: "alice", Tier: 2, Reputation: 0.9, Bond: 200}
	if err := s.saveSubjects(); err != nil {
		t.Fatalf("save failed: %v", err)
	}

	if _, err := os.Stat(file); err != nil {
		t.Fatalf("expected saved file: %v", err)
	}

	s2 := &Service{subjects: map[string]proto.SubjectProfile{}, subjectsFile: file}
	if err := s2.loadSubjects(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	p, ok := s2.subjects["alice"]
	if !ok || p.Tier != 2 {
		t.Fatalf("unexpected loaded profile: %+v", p)
	}
	if p.Kind != proto.SubjectKindRelayExit {
		t.Fatalf("expected default relay subject kind, got %s", p.Kind)
	}
}

func TestLoadSubjectsBackfillsMissingKind(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "subjects.json")
	raw := `{"legacy":{"subject":"legacy","tier":1,"reputation":0.5,"bond":10}}`
	if err := os.WriteFile(file, []byte(raw), 0o644); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}

	s := &Service{subjects: map[string]proto.SubjectProfile{}, subjectsFile: file}
	if err := s.loadSubjects(); err != nil {
		t.Fatalf("load failed: %v", err)
	}
	p := s.subjects["legacy"]
	if p.Kind != proto.SubjectKindRelayExit {
		t.Fatalf("expected missing kind backfilled to relay-exit, got %s", p.Kind)
	}
}

func TestWriteFileAtomicRejectsSymlinkTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"original":true}`), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "subjects.json")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	err := writeFileAtomic(link, []byte(`{"new":true}`), 0o600)
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
	b, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("read target after rejection: %v", readErr)
	}
	if string(b) != `{"original":true}` {
		t.Fatalf("target content unexpectedly changed: %s", string(b))
	}
}

func TestWriteFileAtomicReplacesRegularFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(file, []byte(`{"old":true}`), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if err := writeFileAtomic(file, []byte(`{"new":true}`), 0o600); err != nil {
		t.Fatalf("writeFileAtomic replace: %v", err)
	}
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("read replaced file: %v", err)
	}
	if string(b) != `{"new":true}` {
		t.Fatalf("unexpected replaced content: %s", string(b))
	}
}
