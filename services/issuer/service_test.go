package issuer

import (
	"testing"
	"time"

	"privacynode/pkg/crypto"
)

func TestBaseClaimsForTier1(t *testing.T) {
	exp := time.Now().Add(10 * time.Minute)
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	popPubB64 := crypto.EncodeEd25519PublicKey(popPub)
	claims := baseClaimsForTier("issuer", "subject-a", 4, "exit", crypto.TokenTypeClientAccess, popPubB64, 1, exp, []string{"exit-a"})
	if claims.Tier != 1 {
		t.Fatalf("expected tier 1, got %d", claims.Tier)
	}
	if claims.Subject != "subject-a" {
		t.Fatalf("expected claims subject subject-a, got %s", claims.Subject)
	}
	if claims.KeyEpoch != 4 {
		t.Fatalf("expected key epoch 4, got %d", claims.KeyEpoch)
	}
	if claims.Audience != "exit" {
		t.Fatalf("expected audience exit, got %s", claims.Audience)
	}
	if claims.TokenType != crypto.TokenTypeClientAccess {
		t.Fatalf("unexpected token type %s", claims.TokenType)
	}
	if claims.CNFEd25519 != popPubB64 {
		t.Fatalf("unexpected cnf key")
	}
	if claims.BWKbps != 512 {
		t.Fatalf("unexpected bandwidth: %d", claims.BWKbps)
	}
	if len(claims.DenyPorts) != 1 || claims.DenyPorts[0] != 25 {
		t.Fatalf("tier 1 should deny smtp")
	}
	if len(claims.ExitScope) != 1 || claims.ExitScope[0] != "exit-a" {
		t.Fatalf("unexpected exit scope")
	}
}

func TestBaseProviderClaims(t *testing.T) {
	exp := time.Now().Add(10 * time.Minute)
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	popPubB64 := crypto.EncodeEd25519PublicKey(popPub)
	claims := baseProviderClaims("issuer", "relay-1", 7, 3, popPubB64, exp)
	if claims.Audience != "provider" {
		t.Fatalf("expected provider audience, got %s", claims.Audience)
	}
	if claims.TokenType != crypto.TokenTypeProviderRole {
		t.Fatalf("unexpected token type %s", claims.TokenType)
	}
	if claims.Subject != "relay-1" {
		t.Fatalf("unexpected subject %s", claims.Subject)
	}
	if claims.KeyEpoch != 7 {
		t.Fatalf("unexpected key epoch %d", claims.KeyEpoch)
	}
	if claims.Tier != 3 {
		t.Fatalf("unexpected provider tier %d", claims.Tier)
	}
	if claims.CNFEd25519 != popPubB64 {
		t.Fatalf("unexpected provider cnf key")
	}
	if len(claims.ExitScope) != 0 {
		t.Fatalf("provider claims should not have exit scope")
	}
}

func TestNewReadsTokenTTLFromEnv(t *testing.T) {
	t.Setenv("ISSUER_TOKEN_TTL_SEC", "45")
	svc := New()
	if svc.tokenTTL != 45*time.Second {
		t.Fatalf("expected token ttl 45s, got %s", svc.tokenTTL)
	}
}
