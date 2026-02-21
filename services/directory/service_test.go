package directory

import (
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
