package directory

import (
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"privacynode/pkg/crypto"
)

func TestIssuerVerificationKeysForTrustFeedUsesAnchorsWhenMatched(t *testing.T) {
	pubA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	got, err := issuerVerificationKeysForTrustFeed([]ed25519.PublicKey{pubA}, []ed25519.PublicKey{pubB, pubA})
	if err != nil {
		t.Fatalf("expected anchor match, got error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected anchor set returned, got len=%d", len(got))
	}
}

func TestIssuerVerificationKeysForTrustFeedRejectsAnchorMismatch(t *testing.T) {
	pubA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	_, err = issuerVerificationKeysForTrustFeed([]ed25519.PublicKey{pubA}, []ed25519.PublicKey{pubB})
	if err == nil {
		t.Fatalf("expected mismatch error")
	}
}

func TestLoadIssuerTrustedKeysParsesFile(t *testing.T) {
	pubA, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubB, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "issuer_keys.txt")
	content := "# comment\n" +
		"http://issuer-a.local " + base64.RawURLEncoding.EncodeToString(pubA) + "\n" +
		base64.RawURLEncoding.EncodeToString(pubB) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write keys: %v", err)
	}

	keys, err := loadIssuerTrustedKeys(path)
	if err != nil {
		t.Fatalf("load keys: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}
}

func TestIssuerTrustURLsRequireAnchors(t *testing.T) {
	t.Run("loopback only", func(t *testing.T) {
		if issuerTrustURLsRequireAnchors([]string{"http://127.0.0.1:8082", "http://localhost:8083"}) {
			t.Fatalf("expected loopback issuer trust URLs to not require anchors")
		}
	})

	t.Run("non-loopback", func(t *testing.T) {
		if !issuerTrustURLsRequireAnchors([]string{"https://issuer.example.com"}) {
			t.Fatalf("expected non-loopback issuer trust URL to require anchors")
		}
	})

	t.Run("mixed set", func(t *testing.T) {
		if !issuerTrustURLsRequireAnchors([]string{"http://127.0.0.1:8082", "https://issuer.example.com"}) {
			t.Fatalf("expected mixed issuer trust URL set to require anchors")
		}
	})
}
