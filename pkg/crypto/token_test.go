package crypto

import (
	"strings"
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

func TestNormalizeTokenType(t *testing.T) {
	if got := NormalizeTokenType(""); got != TokenTypeClientAccess {
		t.Fatalf("default token type mismatch: got=%s", got)
	}
	if got := NormalizeTokenType("CLIENT_ACCESS"); got != TokenTypeClientAccess {
		t.Fatalf("normalize client token type mismatch: got=%s", got)
	}
	if got := NormalizeTokenType(TokenTypeProviderRole); got != TokenTypeProviderRole {
		t.Fatalf("normalize provider token type mismatch: got=%s", got)
	}
	if got := NormalizeTokenType("unknown"); got != "" {
		t.Fatalf("expected unknown token type rejected, got=%s", got)
	}
}

func TestPathOpenProofSignVerify(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	input := PathOpenProofInput{
		Token:           "tok-1",
		ExitID:          "exit-a",
		TokenProofNonce: "nonce-a",
		ClientInnerPub:  "pub-a",
		Transport:       "policy-json",
		RequestedMTU:    1280,
		RequestedRegion: "local",
	}
	proof, err := SignPathOpenProof(priv, input)
	if err != nil {
		t.Fatalf("sign proof failed: %v", err)
	}
	if err := VerifyPathOpenProof(proof, pub, input); err != nil {
		t.Fatalf("verify proof failed: %v", err)
	}

	mutated := input
	mutated.ExitID = "exit-b"
	if err := VerifyPathOpenProof(proof, pub, mutated); err == nil {
		t.Fatalf("expected proof verification failure on mutated request")
	}
}

func TestNormalizeEd25519PublicKey(t *testing.T) {
	pub, _, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	enc := EncodeEd25519PublicKey(pub)
	normalized, err := NormalizeEd25519PublicKey(enc)
	if err != nil {
		t.Fatalf("normalize failed: %v", err)
	}
	if normalized != enc {
		t.Fatalf("normalized key mismatch: got=%s want=%s", normalized, enc)
	}
	if _, err := NormalizeEd25519PublicKey(strings.Repeat("a", 8)); err == nil {
		t.Fatalf("expected invalid key to fail normalization")
	}
}
