package directory

import "testing"

func TestPickConsensusTierTiePrefersStricterTier(t *testing.T) {
	tier, ok := pickConsensusTier(map[int]int{
		1: 2,
		3: 2,
	})
	if !ok {
		t.Fatalf("expected consensus tier for tied valid votes")
	}
	if tier != 1 {
		t.Fatalf("expected stricter tier to win tie, got %d", tier)
	}
}

func TestPickConsensusTierNonTiePreservesMajorityWinner(t *testing.T) {
	tier, ok := pickConsensusTier(map[int]int{
		1: 1,
		2: 2,
		3: 3,
	})
	if !ok {
		t.Fatalf("expected consensus tier for non-tied valid votes")
	}
	if tier != 3 {
		t.Fatalf("expected tier with highest vote count to win, got %d", tier)
	}
}
