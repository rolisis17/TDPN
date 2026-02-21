package relay

import "testing"

func TestLooksLikeWireGuardMessage(t *testing.T) {
	if !LooksLikeWireGuardMessage([]byte{1, 0, 0, 0, 10, 11}) {
		t.Fatalf("expected handshake-init like packet to match")
	}
	if !LooksLikeWireGuardMessage([]byte{4, 0, 0, 0, 99}) {
		t.Fatalf("expected transport-like packet to match")
	}
	if LooksLikeWireGuardMessage([]byte{9, 0, 0, 0}) {
		t.Fatalf("unexpected match on invalid type")
	}
	if LooksLikeWireGuardMessage([]byte{1, 1, 0, 0}) {
		t.Fatalf("unexpected match when reserved bytes non-zero")
	}
}
