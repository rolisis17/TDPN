package issuer

import (
	"path/filepath"
	"testing"
)

func TestLoadOrCreateKeypairPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "issuer.key")
	s := &Service{privateKeyPath: path}
	pub1, _, err := s.loadOrCreateKeypair()
	if err != nil {
		t.Fatalf("first load/create failed: %v", err)
	}
	pub2, _, err := s.loadOrCreateKeypair()
	if err != nil {
		t.Fatalf("second load/create failed: %v", err)
	}
	if string(pub1) != string(pub2) {
		t.Fatalf("expected persisted pubkey")
	}
}
