package entry

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleHealthRemainsLivenessWhenDataPlaneNotReady(t *testing.T) {
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

func TestHandleReadyRequiresDataPlane(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodGet, "/v1/ready", nil)
	rr := httptest.NewRecorder()

	s.handleReady(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready status=%d want=%d", rr.Code, http.StatusServiceUnavailable)
	}
	if !strings.Contains(rr.Body.String(), "entry data plane not ready") {
		t.Fatalf("ready body=%q want data-plane reason", rr.Body.String())
	}
}

func TestHandleReadyOKWhenDataPlaneReady(t *testing.T) {
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer conn.Close()

	s := &Service{udpConn: conn}
	req := httptest.NewRequest(http.MethodGet, "/v1/ready", nil)
	rr := httptest.NewRecorder()

	s.handleReady(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("ready status=%d want=%d", rr.Code, http.StatusOK)
	}
	if strings.TrimSpace(rr.Body.String()) != "ready" {
		t.Fatalf("ready body=%q want=ready", rr.Body.String())
	}
}
