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

func TestLooksLikePlausibleWireGuardMessage(t *testing.T) {
	makePacket := func(msgType byte, size int) []byte {
		pkt := make([]byte, size)
		pkt[0] = msgType
		return pkt
	}
	if !LooksLikePlausibleWireGuardMessage(makePacket(1, wgMinHandshakeInitiation)) {
		t.Fatalf("expected handshake initiation at minimum size to be plausible")
	}
	if LooksLikePlausibleWireGuardMessage(makePacket(1, wgMinHandshakeInitiation-1)) {
		t.Fatalf("expected short handshake initiation to be rejected")
	}
	if !LooksLikePlausibleWireGuardMessage(makePacket(2, wgMinHandshakeResponse)) {
		t.Fatalf("expected handshake response at minimum size to be plausible")
	}
	if LooksLikePlausibleWireGuardMessage(makePacket(2, wgMinHandshakeResponse-1)) {
		t.Fatalf("expected short handshake response to be rejected")
	}
	if !LooksLikePlausibleWireGuardMessage(makePacket(3, wgMinCookieReply)) {
		t.Fatalf("expected cookie reply at minimum size to be plausible")
	}
	if LooksLikePlausibleWireGuardMessage(makePacket(3, wgMinCookieReply-1)) {
		t.Fatalf("expected short cookie reply to be rejected")
	}
	if !LooksLikePlausibleWireGuardMessage(makePacket(4, wgMinTransportData)) {
		t.Fatalf("expected transport data at minimum size to be plausible")
	}
	if LooksLikePlausibleWireGuardMessage(makePacket(4, wgMinTransportData-1)) {
		t.Fatalf("expected short transport data to be rejected")
	}
}
