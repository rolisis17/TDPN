package directory

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestPickEntryEndpointRotates(t *testing.T) {
	s := &Service{entryEndpoints: []string{"a", "b"}, endpointRotateSec: 10}
	if got := s.pickEntryEndpoint(time.Unix(0, 0)); got != "a" {
		t.Fatalf("expected a, got %s", got)
	}
	if got := s.pickEntryEndpoint(time.Unix(10, 0)); got != "b" {
		t.Fatalf("expected b, got %s", got)
	}
}

func TestHandleHealth(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	rr := httptest.NewRecorder()
	s.handleHealth(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if strings.TrimSpace(rr.Body.String()) != "ok" {
		t.Fatalf("expected ok body, got %q", rr.Body.String())
	}
}

func TestHandleHealthMethodNotAllowed(t *testing.T) {
	s := &Service{}
	req := httptest.NewRequest(http.MethodPost, "/v1/health", nil)
	rr := httptest.NewRecorder()
	s.handleHealth(rr, req)
	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}
