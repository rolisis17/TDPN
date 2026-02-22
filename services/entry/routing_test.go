package entry

import "testing"

func TestRoutePacketTargetClientToExit(t *testing.T) {
	state := sessionState{exitDataAddr: "127.0.0.1:51821"}
	next, target, ok := routePacketTarget(state, "127.0.0.1:40000", 100, 0)
	if !ok {
		t.Fatalf("expected packet to route")
	}
	if target != "127.0.0.1:51821" {
		t.Fatalf("expected exit target, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client addr learned, got %s", next.clientDataAddr)
	}
	if next.clientLastSeen != 100 {
		t.Fatalf("expected client last seen tracked, got %d", next.clientLastSeen)
	}
}

func TestRoutePacketTargetExitToClient(t *testing.T) {
	state := sessionState{
		exitDataAddr:   "127.0.0.1:51821",
		clientDataAddr: "127.0.0.1:40000",
	}
	next, target, ok := routePacketTarget(state, "127.0.0.1:51821", 120, 0)
	if !ok {
		t.Fatalf("expected packet to route")
	}
	if target != "127.0.0.1:40000" {
		t.Fatalf("expected client target, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client addr unchanged, got %s", next.clientDataAddr)
	}
}

func TestRoutePacketTargetExitWithoutClient(t *testing.T) {
	state := sessionState{exitDataAddr: "127.0.0.1:51821"}
	_, target, ok := routePacketTarget(state, "127.0.0.1:51821", 100, 0)
	if ok {
		t.Fatalf("expected packet drop before client is known")
	}
	if target != "" {
		t.Fatalf("expected empty target when client unknown, got %s", target)
	}
}

func TestRoutePacketTargetRejectsUnknownClientSourceByDefault(t *testing.T) {
	state := sessionState{
		exitDataAddr:   "127.0.0.1:51821",
		clientDataAddr: "127.0.0.1:40000",
		clientLastSeen: 100,
	}
	next, target, ok := routePacketTarget(state, "127.0.0.1:40001", 101, 0)
	if ok {
		t.Fatalf("expected unknown client source to be dropped")
	}
	if target != "" {
		t.Fatalf("expected no target for dropped packet, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client binding unchanged, got %s", next.clientDataAddr)
	}
}

func TestRoutePacketTargetAllowsClientRebindAfterThreshold(t *testing.T) {
	state := sessionState{
		exitDataAddr:   "127.0.0.1:51821",
		clientDataAddr: "127.0.0.1:40000",
		clientLastSeen: 100,
	}
	next, target, ok := routePacketTarget(state, "127.0.0.1:40001", 111, 10)
	if !ok {
		t.Fatalf("expected client rebind to be allowed after inactivity")
	}
	if target != "127.0.0.1:51821" {
		t.Fatalf("expected rebind packet to route to exit, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40001" {
		t.Fatalf("expected client address rebound, got %s", next.clientDataAddr)
	}
}

func TestRoutePacketTargetRejectsClientRebindBeforeThreshold(t *testing.T) {
	state := sessionState{
		exitDataAddr:   "127.0.0.1:51821",
		clientDataAddr: "127.0.0.1:40000",
		clientLastSeen: 100,
	}
	next, target, ok := routePacketTarget(state, "127.0.0.1:40001", 105, 10)
	if ok {
		t.Fatalf("expected client rebind rejected before inactivity threshold")
	}
	if target != "" {
		t.Fatalf("expected no target for rejected rebind, got %s", target)
	}
	if next.clientDataAddr != "127.0.0.1:40000" {
		t.Fatalf("expected client address unchanged, got %s", next.clientDataAddr)
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
