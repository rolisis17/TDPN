package app

import "testing"

func TestSolvePuzzle(t *testing.T) {
	nonce, digest, ok := solvePuzzle("abc", 1, 100000)
	if !ok {
		t.Fatalf("expected solver to find a solution")
	}
	if nonce == "" || digest == "" {
		t.Fatalf("expected nonce and digest")
	}
}

func TestSolvePuzzleRejectsDifficultyOverCap(t *testing.T) {
	if nonce, digest, ok := solvePuzzle("abc", clientMaxPuzzleDifficulty+1, 100000); ok || nonce != "" || digest != "" {
		t.Fatalf("expected unsolved result for out-of-range difficulty, got nonce=%q digest=%q ok=%t", nonce, digest, ok)
	}
}
