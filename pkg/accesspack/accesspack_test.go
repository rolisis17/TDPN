package accesspack

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyAccessPack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pack := testPack()
	signed, err := Sign(pack, priv, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verified, err := Verify(signed, pub, time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Pack.Signature == nil {
		t.Fatalf("signature missing after verify")
	}
	if verified.Pack.AccessPaths[0].PathID != "main-site" {
		t.Fatalf("access paths not normalized by priority: %+v", verified.Pack.AccessPaths)
	}
}

func TestVerifyRejectsTamperedPack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed, err := Sign(testPack(), priv, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	signed.AccessPaths[0].URL = "https://evil.example"
	_, err = Verify(signed, pub, time.Date(2026, 5, 10, 1, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatalf("expected tampered pack to fail verification")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("expected signature verification error, got %v", err)
	}
}

func TestVerifyRejectsExpiredPack(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	signed, err := Sign(testPack(), priv, "")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	_, err = Verify(signed, pub, time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC))
	if err == nil {
		t.Fatalf("expected expired pack to fail verification")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestSignRejectsUnsupportedURLSchemes(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	for name, mutate := range map[string]func(*Pack){
		"source ftp": func(pack *Pack) {
			pack.Sources[0].URL = "ftp://mirror.example/pack.json"
		},
		"access path ssh": func(pack *Pack) {
			pack.AccessPaths[0].URL = "ssh://demo.example"
		},
		"organization javascript": func(pack *Pack) {
			pack.Organization.HomeURL = "javascript://demo.example/payload"
		},
	} {
		pack := testPack()
		mutate(&pack)
		if _, err := Sign(pack, priv, ""); err == nil || !strings.Contains(err.Error(), "scheme must be http, https, or mailto") {
			t.Fatalf("%s should reject unsupported URL scheme, got %v", name, err)
		}
	}
}

func testPack() Pack {
	return Pack{
		SchemaVersion: SchemaVersion,
		PackID:        "arp-test-demo",
		Organization: Organization{
			OrgID:   "demo-org",
			Name:    "Demo Org",
			HomeURL: "https://demo.example",
		},
		IssuedAtUTC:      "2026-05-10T00:00:00Z",
		ExpiresAtUTC:     "2099-01-01T00:00:00Z",
		IntendedAudience: "Test users",
		Sources: []Source{
			{SourceID: "mirror-source", Kind: "mirror", URL: "https://mirror.example/pack.json", Priority: 20},
			{SourceID: "official-source", Kind: "official", URL: "https://demo.example/pack.json", Priority: 10},
		},
		AccessPaths: []AccessPath{
			{PathID: "mirror-site", Kind: "mirror", URL: "https://mirror.example", Priority: 20},
			{PathID: "main-site", Kind: "website", URL: "https://demo.example", Priority: 10},
		},
		SafetyNotes: []string{"Verify the signature first."},
	}
}
