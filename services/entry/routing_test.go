package entry

import "testing"

func TestRoutePacketTargetClientToExit(t *testing.T) {
	state := sessionState{exitDataAddr: "127.0.0.1:51821"}
	next, target := routePacketTarget(state, "127.0.0.1:40000")
	if target != "127.0.0.1:51821" {
		t.Fatalf("expected exit target, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client addr learned, got %s", next.clientDataAddr)
	}
}

func TestRoutePacketTargetExitToClient(t *testing.T) {
	state := sessionState{
		exitDataAddr:   "127.0.0.1:51821",
		clientDataAddr: "127.0.0.1:40000",
	}
	next, target := routePacketTarget(state, "127.0.0.1:51821")
	if target != "127.0.0.1:40000" {
		t.Fatalf("expected client target, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client addr unchanged, got %s", next.clientDataAddr)
	}
}

func TestRoutePacketTargetExitWithoutClient(t *testing.T) {
	state := sessionState{exitDataAddr: "127.0.0.1:51821"}
	_, target := routePacketTarget(state, "127.0.0.1:51821")
	if target != "" {
		t.Fatalf("expected empty target when client unknown, got %s", target)
	}
}

func TestSameUDPAddrLocalhostEquivalent(t *testing.T) {
	if !sameUDPAddr("localhost:1234", "127.0.0.1:1234") {
		t.Fatalf("expected localhost and 127.0.0.1 to match")
	}
	if sameUDPAddr("127.0.0.1:1234", "127.0.0.1:1235") {
		t.Fatalf("expected different ports to not match")
	}
}
