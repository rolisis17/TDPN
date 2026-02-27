package app

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/relay"
)

func TestDrainOpaqueDownlinkLiveModeDropsNonWireGuard(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	defer server.Close()

	outerConn, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial outer udp: %v", err)
	}
	defer outerConn.Close()

	sinkListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen sink udp: %v", err)
	}
	defer sinkListener.Close()

	sinkConn, err := net.DialUDP("udp", nil, sinkListener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial sink udp: %v", err)
	}
	defer sinkConn.Close()

	const sessionID = "session-live"
	wgPayload := make([]byte, 32)
	wgPayload[0] = 4
	nonWGPayload := []byte("not-wireguard")

	go func() {
		time.Sleep(20 * time.Millisecond)
		target := outerConn.LocalAddr().(*net.UDPAddr)
		nonWGFrame := relay.BuildDatagram(sessionID, relay.BuildOpaquePayload(1, nonWGPayload))
		wgFrame := relay.BuildDatagram(sessionID, relay.BuildOpaquePayload(2, wgPayload))
		_, _ = server.WriteToUDP(nonWGFrame, target)
		_, _ = server.WriteToUDP(wgFrame, target)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client := &Client{liveWGMode: true}
	count, err := client.drainOpaqueDownlink(ctx, outerConn, sessionID, sinkConn, 350*time.Millisecond)
	if err != nil {
		t.Fatalf("drainOpaqueDownlink: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 forwarded downlink packet, got %d", count)
	}

	buf := make([]byte, 256)
	if err := sinkListener.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("set sink deadline: %v", err)
	}
	n, _, err := sinkListener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read sink packet: %v", err)
	}
	if !bytes.Equal(buf[:n], wgPayload) {
		t.Fatalf("expected only WG-like payload on sink, got=%x want=%x", buf[:n], wgPayload)
	}
}

func TestDrainOpaqueDownlinkNonLiveAllowsOpaquePayload(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	defer server.Close()

	outerConn, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial outer udp: %v", err)
	}
	defer outerConn.Close()

	sinkListener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen sink udp: %v", err)
	}
	defer sinkListener.Close()

	sinkConn, err := net.DialUDP("udp", nil, sinkListener.LocalAddr().(*net.UDPAddr))
	if err != nil {
		t.Fatalf("dial sink udp: %v", err)
	}
	defer sinkConn.Close()

	const sessionID = "session-dev"
	payload := []byte("opaque-dev-payload")
	go func() {
		time.Sleep(20 * time.Millisecond)
		target := outerConn.LocalAddr().(*net.UDPAddr)
		frame := relay.BuildDatagram(sessionID, relay.BuildOpaquePayload(1, payload))
		_, _ = server.WriteToUDP(frame, target)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	client := &Client{liveWGMode: false}
	count, err := client.drainOpaqueDownlink(ctx, outerConn, sessionID, sinkConn, 300*time.Millisecond)
	if err != nil {
		t.Fatalf("drainOpaqueDownlink: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 forwarded packet, got %d", count)
	}
	buf := make([]byte, 256)
	if err := sinkListener.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("set sink deadline: %v", err)
	}
	n, _, err := sinkListener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read sink packet: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("unexpected payload on sink got=%q want=%q", string(buf[:n]), string(payload))
	}
}

func TestForwardOpaqueFromUDPLiveModeDropsNonWireGuard(t *testing.T) {
	innerAddr := freeUDPAddr(t)
	c := &Client{
		innerUDPAddr:      innerAddr,
		innerMaxPkts:      2,
		opaqueInitialUpMS: 350,
		liveWGMode:        true,
	}

	nonWGPayload := []byte("not-wireguard")
	wgPayload := make([]byte, 32)
	wgPayload[0] = 4

	go func() {
		time.Sleep(40 * time.Millisecond)
		target, err := net.ResolveUDPAddr("udp", innerAddr)
		if err != nil {
			return
		}
		conn, err := net.DialUDP("udp", nil, target)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(nonWGPayload)
		_, _ = conn.Write(wgPayload)
	}()

	var forwarded [][]byte
	sendFrame := func(payload []byte) error {
		forwarded = append(forwarded, append([]byte(nil), payload...))
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	count, err := c.forwardOpaqueFromUDP(ctx, sendFrame)
	if err != nil {
		t.Fatalf("forwardOpaqueFromUDP: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one live-compatible packet forwarded, got %d", count)
	}
	if len(forwarded) != 1 {
		t.Fatalf("expected one payload forwarded, got %d", len(forwarded))
	}
	if !bytes.Equal(forwarded[0], wgPayload) {
		t.Fatalf("unexpected forwarded payload got=%x want=%x", forwarded[0], wgPayload)
	}
}

func TestSendOpaqueTrafficSessionModeRequiresInitialUplink(t *testing.T) {
	entry, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen entry udp: %v", err)
	}
	defer entry.Close()

	c := &Client{
		innerSource:       "udp",
		innerUDPAddr:      freeUDPAddr(t),
		wgBackend:         "command",
		liveWGMode:        false,
		opaqueSessionSec:  1,
		opaqueInitialUpMS: 200,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err = c.sendOpaqueTraffic(ctx, entry.LocalAddr().String(), "session-no-uplink")
	if err == nil {
		t.Fatalf("expected missing uplink error")
	}
	if !strings.Contains(err.Error(), "received no UDP packets") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendOpaqueTrafficSessionModeForwardsDelayedDownlink(t *testing.T) {
	entry, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen entry udp: %v", err)
	}
	defer entry.Close()

	sink, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen sink udp: %v", err)
	}
	defer sink.Close()

	const sessionID = "session-persistent"
	downPayload := []byte("delayed-downlink")
	go func() {
		buf := make([]byte, 64*1024)
		n, src, readErr := entry.ReadFromUDP(buf)
		if readErr != nil || n <= 0 {
			return
		}
		time.Sleep(120 * time.Millisecond)
		frame := relay.BuildDatagram(sessionID, relay.BuildOpaquePayload(1, downPayload))
		_, _ = entry.WriteToUDP(frame, src)
	}()

	innerAddr := freeUDPAddr(t)
	go func() {
		time.Sleep(80 * time.Millisecond)
		innerTarget, err := net.ResolveUDPAddr("udp", innerAddr)
		if err != nil {
			return
		}
		conn, err := net.DialUDP("udp", nil, innerTarget)
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte{1, 2, 3, 4, 5})
	}()

	c := &Client{
		innerSource:       "udp",
		innerUDPAddr:      innerAddr,
		opaqueSinkAddr:    sink.LocalAddr().String(),
		wgBackend:         "command",
		liveWGMode:        false,
		opaqueSessionSec:  1,
		opaqueInitialUpMS: 500,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	if err := c.sendOpaqueTraffic(ctx, entry.LocalAddr().String(), sessionID); err != nil {
		t.Fatalf("sendOpaqueTraffic session mode failed: %v", err)
	}

	buf := make([]byte, 256)
	if err := sink.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatalf("set sink deadline: %v", err)
	}
	n, _, err := sink.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read sink packet: %v", err)
	}
	if !bytes.Equal(buf[:n], downPayload) {
		t.Fatalf("unexpected sink payload got=%q want=%q", string(buf[:n]), string(downPayload))
	}
}

func TestWGKernelProxyTrafficRoundTrip(t *testing.T) {
	entry, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen entry udp: %v", err)
	}
	defer entry.Close()

	c := &Client{
		wgBackend:         "command",
		wgKernelProxy:     true,
		wgProxyAddr:       "127.0.0.1:0",
		liveWGMode:        false,
		opaqueSessionSec:  1,
		opaqueInitialUpMS: 600,
	}

	const sessionID = "sid-kernel-proxy"
	proxy, err := c.newWGKernelProxy(entry.LocalAddr().String(), sessionID)
	if err != nil {
		t.Fatalf("newWGKernelProxy: %v", err)
	}
	defer proxy.close()

	uplink := make([]byte, 32)
	uplink[0] = 4
	uplink[4] = 0x42
	downlink := append([]byte("downlink-"), uplink...)

	entryErr := make(chan error, 1)
	go func() {
		buf := make([]byte, 64*1024)
		_ = entry.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := entry.ReadFromUDP(buf)
		if err != nil {
			entryErr <- err
			return
		}
		sid, payload, err := relay.ParseDatagram(buf[:n])
		if err != nil {
			entryErr <- err
			return
		}
		if sid != sessionID {
			entryErr <- errors.New("session mismatch")
			return
		}
		_, raw, err := relay.ParseOpaquePayload(payload)
		if err != nil {
			entryErr <- err
			return
		}
		if !bytes.Equal(raw, uplink) {
			entryErr <- errors.New("uplink payload mismatch")
			return
		}
		frame := relay.BuildDatagram(sessionID, relay.BuildOpaquePayload(1, downlink))
		_, err = entry.WriteToUDP(frame, src)
		entryErr <- err
	}()

	peerTarget, err := net.ResolveUDPAddr("udp", proxy.listenAddr())
	if err != nil {
		t.Fatalf("resolve proxy listen addr: %v", err)
	}
	peerConn, err := net.DialUDP("udp", nil, peerTarget)
	if err != nil {
		t.Fatalf("dial proxy listen addr: %v", err)
	}
	defer peerConn.Close()

	downlinkCh := make(chan []byte, 1)
	go func() {
		time.Sleep(80 * time.Millisecond)
		_, _ = peerConn.Write(uplink)
		buf := make([]byte, 64*1024)
		_ = peerConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := peerConn.Read(buf)
		if err != nil {
			downlinkCh <- nil
			return
		}
		downlinkCh <- append([]byte(nil), buf[:n]...)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := c.runWGKernelProxyTraffic(ctx, proxy); err != nil {
		t.Fatalf("runWGKernelProxyTraffic: %v", err)
	}
	if err := <-entryErr; err != nil {
		t.Fatalf("entry flow failed: %v", err)
	}
	gotDown := <-downlinkCh
	if !bytes.Equal(gotDown, downlink) {
		t.Fatalf("downlink mismatch got=%x want=%x", gotDown, downlink)
	}
}

func freeUDPAddr(t *testing.T) string {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp addr: %v", err)
	}
	defer l.Close()
	return l.LocalAddr().String()
}
