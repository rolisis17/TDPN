package entry

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestVerifyPuzzle(t *testing.T) {
	s := &Service{puzzleSecret: "s"}
	ch := s.challengeFor("127.0.0.1", time.Unix(100, 0))
	nonce, digest, ok := brute(ch, 2, 300000)
	if !ok {
		t.Fatalf("failed to find puzzle solution")
	}
	if !verifyPuzzle(ch, nonce, digest, 2) {
		t.Fatalf("expected valid solution")
	}
}

func TestLimitOpen(t *testing.T) {
	s := &Service{openRPS: 2, buckets: map[string]rateBucket{}}
	ip := "1.2.3.4"
	if _, limited := s.limitOpen(ip); limited {
		t.Fatalf("first request should not be limited")
	}
	if _, limited := s.limitOpen(ip); limited {
		t.Fatalf("second request should not be limited")
	}
	if _, limited := s.limitOpen(ip); !limited {
		t.Fatalf("third request should be limited")
	}
}

func brute(ch string, d int, max int) (string, string, bool) {
	prefix := strings.Repeat("0", d)
	for i := 0; i < max; i++ {
		nonce := fmt.Sprintf("%x", i)
		sum := sha256.Sum256([]byte(ch + ":" + nonce))
		digest := hex.EncodeToString(sum[:])
		if strings.HasPrefix(digest, prefix) {
			return nonce, digest, true
		}
	}
	return "", "", false
}

func TestEffectiveDifficultyAdaptive(t *testing.T) {
	s := &Service{openRPS: 10, puzzleDifficulty: 1, puzzleAdaptive: true, puzzleMax: 6}
	if got := s.effectiveDifficulty(10); got != 1 {
		t.Fatalf("expected base difficulty 1, got %d", got)
	}
	if got := s.effectiveDifficulty(21); got < 2 {
		t.Fatalf("expected increased difficulty, got %d", got)
	}
}

func TestNoteAbuseBansAfterThreshold(t *testing.T) {
	s := &Service{
		openBanThreshold: 2,
		openBanDuration:  30 * time.Second,
		abuse:            map[string]abuseState{},
	}
	ip := "1.2.3.4"
	now := time.Unix(100, 0)
	if s.noteAbuse(ip, now) {
		t.Fatalf("first abuse strike should not ban")
	}
	if s.noteAbuse(ip, now.Add(time.Second)) != true {
		t.Fatalf("second abuse strike should ban")
	}
	if !s.isBanned(ip, now.Add(2*time.Second)) {
		t.Fatalf("expected ip to be banned")
	}
}

func TestBanExpires(t *testing.T) {
	s := &Service{
		openBanThreshold: 1,
		openBanDuration:  5 * time.Second,
		abuse:            map[string]abuseState{},
	}
	ip := "1.2.3.4"
	now := time.Unix(100, 0)
	if !s.noteAbuse(ip, now) {
		t.Fatalf("expected immediate ban at threshold=1")
	}
	if !s.isBanned(ip, now.Add(3*time.Second)) {
		t.Fatalf("expected ban still active")
	}
	if s.isBanned(ip, now.Add(6*time.Second)) {
		t.Fatalf("expected ban expired")
	}
}

func TestAcquireOpenSlotLimit(t *testing.T) {
	s := &Service{openInflightSem: make(chan struct{}, 1)}
	release, ok := s.acquireOpenSlot()
	if !ok {
		t.Fatalf("expected first inflight slot")
	}
	if _, ok := s.acquireOpenSlot(); ok {
		t.Fatalf("expected second inflight slot acquisition to fail")
	}
	release()
	if _, ok := s.acquireOpenSlot(); !ok {
		t.Fatalf("expected slot to be available after release")
	}
}
