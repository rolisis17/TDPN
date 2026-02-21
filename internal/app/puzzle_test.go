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
