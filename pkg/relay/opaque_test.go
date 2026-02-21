package relay

import "testing"

func TestOpaqueRoundTrip(t *testing.T) {
	in := []byte{9, 8, 7, 6}
	frame := BuildOpaquePayload(123, in)
	nonce, payload, err := ParseOpaquePayload(frame)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if nonce != 123 {
		t.Fatalf("unexpected nonce: %d", nonce)
	}
	if len(payload) != len(in) {
		t.Fatalf("unexpected payload length: %d", len(payload))
	}
}

func TestOpaqueRejectsShort(t *testing.T) {
	if _, _, err := ParseOpaquePayload([]byte{1, 2, 3}); err == nil {
		t.Fatalf("expected error")
	}
}
