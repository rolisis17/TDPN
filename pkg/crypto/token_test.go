package crypto

import (
	"testing"
	"time"
)

func TestSignAndVerifyClaims(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	in := CapabilityClaims{
		Issuer:     "issuer",
		Audience:   "exit",
		Subject:    "user-1",
		Tier:       1,
		ExpiryUnix: time.Now().Add(time.Minute).Unix(),
		TokenID:    "token-1",
		DenyPorts:  []int{25},
		BWKbps:     100,
		ConnRate:   10,
		MaxConns:   10,
	}

	tok, err := SignClaims(in, priv)
	if err != nil {
		t.Fatalf("sign failed: %v", err)
	}

	out, err := VerifyClaims(tok, pub)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}

	if out.TokenID != in.TokenID || out.Tier != in.Tier {
		t.Fatalf("claims mismatch: got %+v want %+v", out, in)
	}
	if out.Subject != "user-1" {
		t.Fatalf("expected subject claim user-1, got %s", out.Subject)
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	pub, _, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}

	if _, err := VerifyClaims("invalid", pub); err == nil {
		t.Fatalf("expected malformed token to fail")
	}
}
