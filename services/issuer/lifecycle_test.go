package issuer

import (
	"testing"
	"time"

	"privacynode/pkg/proto"
)

func TestEffectiveTierFor(t *testing.T) {
	s := &Service{subjects: map[string]proto.SubjectProfile{}}
	s.subjects["alice"] = proto.SubjectProfile{
		Subject:    "alice",
		Kind:       proto.SubjectKindClient,
		Tier:       1,
		Reputation: 0.97,
		Bond:       600,
	}
	if got := s.effectiveTierFor("alice", 3); got != 3 {
		t.Fatalf("expected tier 3, got %d", got)
	}
	if got := s.effectiveTierFor("alice", 2); got != 2 {
		t.Fatalf("expected requested cap at 2, got %d", got)
	}
	if got := s.effectiveTierFor("unknown", 3); got != 1 {
		t.Fatalf("expected unknown subject tier 1, got %d", got)
	}

	s.subjects["bob"] = proto.SubjectProfile{
		Subject:      "bob",
		Kind:         proto.SubjectKindClient,
		Tier:         3,
		Reputation:   0.99,
		Bond:         900,
		TierCap:      1,
		DisputeUntil: time.Now().Add(2 * time.Hour).Unix(),
	}
	if got := s.effectiveTierFor("bob", 3); got != 1 {
		t.Fatalf("expected active dispute tier cap at 1, got %d", got)
	}
}

func TestEffectiveTierForUsesStake(t *testing.T) {
	s := &Service{subjects: map[string]proto.SubjectProfile{}}
	s.subjects["carol"] = proto.SubjectProfile{
		Subject:    "carol",
		Kind:       proto.SubjectKindClient,
		Tier:       1,
		Reputation: 0.96,
		Stake:      550,
	}
	if got := s.effectiveTierFor("carol", 3); got != 3 {
		t.Fatalf("expected tier 3 from stake+reputation, got %d", got)
	}
}

func TestEffectiveTierForRelaySubjectStaysTier1(t *testing.T) {
	s := &Service{subjects: map[string]proto.SubjectProfile{}}
	s.subjects["exit-a"] = proto.SubjectProfile{
		Subject:    "exit-a",
		Kind:       proto.SubjectKindRelayExit,
		Tier:       3,
		Reputation: 0.99,
		Bond:       900,
	}
	if got := s.effectiveTierFor("exit-a", 3); got != 1 {
		t.Fatalf("expected relay subject token tier pinned to 1, got %d", got)
	}
}
