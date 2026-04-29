package exit

import (
	"crypto/ed25519"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleHealthRemainsLivenessWhenDependenciesNotReady(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()

	s.handleHealth(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("health status=%d want=%d", rr.Code, http.StatusOK)
	}
	if strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Fatalf("health body=%q want=ok", rr.Body.String())
	}
}

func TestHandleReadyRequiresDataPlaneAndIssuerKeys(t *testing.T) {
	s := &Service{issuerPubs: map[string]ed25519.PublicKey{"issuer": make(ed25519.PublicKey, ed25519.PublicKeySize)}}
	req := httptest.NewRequest(http.MethodGet, "/v1/ready", nil)
	rr := httptest.NewRecorder()

	s.handleReady(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status=%d want=%d", rr.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rr.Body.String(), "exit data plane not ready") {
		t.Fatalf("ready body=%q want data-plane reason", rr.Body.String())
	}

	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	s = &Service{udpConn: conn}
	rr = httptest.NewRecorder()
	s.handleReady(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status=%d want=%d", rr.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rr.Body.String(), "exit issuer keys not ready") {
		t.Fatalf("ready body=%q want issuer-key reason", rr.Body.String())
	}
}

func TestHandleReadyRequiresCommandEgressWhenConfigured(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	s := &Service{
		udpConn:       conn,
		issuerPubs:    map[string]ed25519.PublicKey{"issuer": pub},
		egressBackend: "command",
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/ready", nil)
	rr := httptest.NewRecorder()

	s.handleReady(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status=%d want=%d", rr.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rr.Body.String(), "exit egress not ready") {
		t.Fatalf("ready body=%q want egress reason", rr.Body.String())
	}

	s.egressConfigured = true
	rr = httptest.NewRecorder()
	s.handleReady(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("ready status=%d want=%d", rr.Code, http.StatusOK)
	}
	if strings.TrimSpace(rr.Body.String()) != "ready" {
		t.Fatalf("ready body=%q want=ready", rr.Body.String())
	}
}
