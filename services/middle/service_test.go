package middle

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRouteMiddlePacketEntryToExitLearnsEntry(t *testing.T) {
	entry := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000}
	exit := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001}
	now := time.Unix(1_700_000_000, 0).UTC()

	next, target, ok := routeMiddlePacket(middleRouteState{}, entry, entry, exit, 1200, now)
	if !ok {
		t.Fatal("expected entry packet to route")
	}
	if !sameUDPAddr(target, exit) {
		t.Fatalf("expected target exit addr, got %v", target)
	}
	if !sameUDPAddr(next.entryAddr, entry) {
		t.Fatalf("expected learned entry addr, got %v", next.entryAddr)
	}
	if next.entryToExit != 1 || next.exitToEntry != 0 {
		t.Fatalf("unexpected counters entry_to_exit=%d exit_to_entry=%d", next.entryToExit, next.exitToEntry)
	}
	if next.lastLen != 1200 || next.lastSrc != entry.String() || next.lastTarget != exit.String() || !next.lastAt.Equal(now) {
		t.Fatalf("unexpected last packet metadata: %+v", next)
	}
}

func TestRouteMiddlePacketExitToEntryUsesStaticEntry(t *testing.T) {
	exit := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001}
	now := time.Unix(1_700_000_001, 0).UTC()

	entry := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000}
	next, target, ok := routeMiddlePacket(middleRouteState{}, exit, entry, exit, 256, now)
	if !ok {
		t.Fatal("expected static exit response to route")
	}
	if !sameUDPAddr(target, entry) {
		t.Fatalf("expected target entry addr, got %v", target)
	}
	if next.entryToExit != 0 || next.exitToEntry != 1 {
		t.Fatalf("unexpected counters entry_to_exit=%d exit_to_entry=%d", next.entryToExit, next.exitToEntry)
	}
}

func TestRouteMiddlePacketExitToEntryAfterEntryObserved(t *testing.T) {
	entry := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000}
	exit := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001}
	state, _, ok := routeMiddlePacket(middleRouteState{}, entry, entry, exit, 1200, time.Unix(1_700_000_000, 0).UTC())
	if !ok {
		t.Fatal("expected initial entry packet to route")
	}

	now := time.Unix(1_700_000_002, 0).UTC()
	next, target, ok := routeMiddlePacket(state, exit, entry, exit, 512, now)
	if !ok {
		t.Fatal("expected exit response to route")
	}
	if !sameUDPAddr(target, entry) {
		t.Fatalf("expected target entry addr, got %v", target)
	}
	if next.entryToExit != 1 || next.exitToEntry != 1 {
		t.Fatalf("unexpected counters entry_to_exit=%d exit_to_entry=%d", next.entryToExit, next.exitToEntry)
	}
	if next.lastLen != 512 || next.lastSrc != exit.String() || next.lastTarget != entry.String() || !next.lastAt.Equal(now) {
		t.Fatalf("unexpected last packet metadata: %+v", next)
	}
}

func TestRouteMiddlePacketDropsNilAddrs(t *testing.T) {
	exit := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001}
	now := time.Unix(1_700_000_003, 0).UTC()

	for name, tc := range map[string]struct {
		entry *net.UDPAddr
		src   *net.UDPAddr
		exit  *net.UDPAddr
	}{
		"nil-entry": {entry: nil, src: exit, exit: exit},
		"nil-src":   {entry: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000}, src: nil, exit: exit},
		"nil-exit":  {entry: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000}, src: exit, exit: nil},
	} {
		t.Run(name, func(t *testing.T) {
			next, target, ok := routeMiddlePacket(middleRouteState{}, tc.src, tc.entry, tc.exit, 99, now)
			if ok {
				t.Fatalf("expected nil-address packet to drop, target=%v", target)
			}
			if next.entryAddr != nil || next.entryToExit != 0 || next.exitToEntry != 0 {
				t.Fatalf("state changed on dropped packet: %+v", next)
			}
		})
	}
}

func TestRouteMiddlePacketRejectsUnconfiguredSources(t *testing.T) {
	entryA := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41000}
	entryB := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41002}
	exit := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 41001}
	state, _, ok := routeMiddlePacket(middleRouteState{}, entryA, entryA, exit, 1200, time.Unix(1_700_000_000, 0).UTC())
	if !ok {
		t.Fatal("expected initial entry packet to route")
	}

	next, target, ok := routeMiddlePacket(state, entryB, entryA, exit, 256, time.Unix(1_700_000_400, 0).UTC())
	if ok {
		t.Fatalf("expected unconfigured entry source to drop, target=%v", target)
	}
	if !sameUDPAddr(next.entryAddr, entryA) {
		t.Fatalf("expected learned entry to stay pinned to entryA, got %v", next.entryAddr)
	}
}

func TestRunRequiresExplicitStaticRoutePeers(t *testing.T) {
	ctx := context.Background()
	t.Run("missing entry", func(t *testing.T) {
		svc := &Service{
			dataAddr:     "127.0.0.1:0",
			exitDataAddr: "127.0.0.1:41001",
			observedFile: "",
		}
		err := svc.Run(ctx)
		if err == nil || !strings.Contains(err.Error(), "MIDDLE_ENTRY_DATA_ADDR is required") {
			t.Fatalf("Run error=%v want missing entry data addr", err)
		}
	})
	t.Run("missing exit", func(t *testing.T) {
		svc := &Service{
			dataAddr:      "127.0.0.1:0",
			entryDataAddr: "127.0.0.1:41000",
			observedFile:  "",
		}
		err := svc.Run(ctx)
		if err == nil || !strings.Contains(err.Error(), "MIDDLE_EXIT_DATA_ADDR is required") {
			t.Fatalf("Run error=%v want missing exit data addr", err)
		}
	})
}

func TestHandleReadyRequiresStaticRoutePeers(t *testing.T) {
	svc := &Service{
		udpConn:       &net.UDPConn{},
		entryDataAddr: "",
		exitDataAddr:  "127.0.0.1:41001",
	}
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/v1/ready", nil)
	svc.handleReady(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status=%d want 503 body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "middle static route not configured") {
		t.Fatalf("ready body=%q want static route guidance", rr.Body.String())
	}
}
