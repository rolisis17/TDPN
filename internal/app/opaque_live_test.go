package app

import (
	"bytes"
	"context"
	"net"
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
	wgPayload := []byte{1, 0, 0, 0, 9, 8, 7}
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
