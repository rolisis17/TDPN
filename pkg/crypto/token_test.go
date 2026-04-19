package crypto

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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

func TestSignClaimsRejectsMalformedPrivateKey(t *testing.T) {
	claims := CapabilityClaims{
		Issuer:     "issuer",
		Audience:   "exit",
		Subject:    "user-1",
		Tier:       1,
		ExpiryUnix: time.Now().Add(time.Minute).Unix(),
		TokenID:    "token-1",
		BWKbps:     100,
		ConnRate:   10,
		MaxConns:   10,
	}

	_, err := SignClaims(claims, ed25519.PrivateKey("bad-key"))
	if err == nil {
		t.Fatalf("expected malformed private key to fail signing")
	}
	if !strings.Contains(err.Error(), "invalid private key size") {
		t.Fatalf("unexpected malformed key error: %v", err)
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

func TestVerifyClaimsRejectsOversizedToken(t *testing.T) {
	pub, _, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	oversized := strings.Repeat("a", maxSignedTokenChars+1)
	if _, err := VerifyClaims(oversized, pub); err == nil {
		t.Fatalf("expected oversized token rejection")
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
		MiddleRelayID:   "middle-a",
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
	if err := VerifyPathOpenProofStrict(proof, pub, input); err != nil {
		t.Fatalf("strict verify proof failed: %v", err)
	}

	mutated := input
	mutated.MiddleRelayID = "middle-b"
	if err := VerifyPathOpenProof(proof, pub, mutated); err == nil {
		t.Fatalf("expected proof verification failure on mutated request")
	}
}

func TestVerifyPathOpenProofRejectsOversizedProof(t *testing.T) {
	pub, _, err := GenerateEd25519Keypair()
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
	oversized := strings.Repeat("a", maxPathOpenProofChars+1)
	if err := VerifyPathOpenProof(oversized, pub, input); err == nil {
		t.Fatalf("expected oversized proof rejection")
	}
}

func TestPathOpenProofVerifyLegacyNoRequestedRegion(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	input := PathOpenProofInput{
		Token:           "tok-legacy-region",
		ExitID:          "exit-a",
		MiddleRelayID:   "middle-a",
		TokenProofNonce: "nonce-a",
		ClientInnerPub:  "pub-a",
		Transport:       "policy-json",
		RequestedMTU:    1280,
		RequestedRegion: "ap-southeast-2",
	}
	proof := signLegacyPathOpenProofNoRegion(t, priv, input)
	if err := VerifyPathOpenProofCompat(proof, pub, input); err != nil {
		t.Fatalf("expected legacy no-region proof to verify in compatibility mode, got: %v", err)
	}
	if err := VerifyPathOpenProof(proof, pub, input); err == nil {
		t.Fatalf("expected default verifier to reject legacy no-region proof")
	}
	if err := VerifyPathOpenProofStrict(proof, pub, input); err == nil {
		t.Fatalf("expected strict verifier to reject legacy no-region proof")
	}
}

func TestPathOpenProofVerifyLegacyCoreContract(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	input := PathOpenProofInput{
		Token:           "tok-legacy-core",
		ExitID:          "exit-a",
		MiddleRelayID:   "middle-a",
		TokenProofNonce: "nonce-a",
		ClientInnerPub:  "pub-a",
		Transport:       "policy-json",
		RequestedMTU:    1280,
		RequestedRegion: "us-east-1",
	}
	proof := signLegacyPathOpenProofCoreOnly(t, priv, input)
	if err := VerifyPathOpenProofCompat(proof, pub, input); err != nil {
		t.Fatalf("expected legacy core-only proof to verify in compatibility mode, got: %v", err)
	}
	if err := VerifyPathOpenProof(proof, pub, input); err == nil {
		t.Fatalf("expected default verifier to reject legacy core-only proof")
	}
	if err := VerifyPathOpenProofStrict(proof, pub, input); err == nil {
		t.Fatalf("expected strict verifier to reject legacy core-only proof")
	}

	mutated := input
	mutated.Token = "tok-mutated"
	if err := VerifyPathOpenProof(proof, pub, mutated); err == nil {
		t.Fatalf("expected legacy proof verification failure when core field is mutated")
	}
}

func TestPathOpenProofVerifyStrictRejectsLegacyNoMiddleRelayBinding(t *testing.T) {
	pub, priv, err := GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	input := PathOpenProofInput{
		Token:           "tok-legacy-no-middle",
		ExitID:          "exit-a",
		MiddleRelayID:   "middle-a",
		TokenProofNonce: "nonce-a",
		ClientInnerPub:  "pub-a",
		Transport:       "policy-json",
		RequestedMTU:    1280,
		RequestedRegion: "us-east-1",
	}
	proof := signLegacyPathOpenProofNoMiddle(t, priv, input)
	if err := VerifyPathOpenProofCompat(proof, pub, input); err != nil {
		t.Fatalf("expected legacy no-middle proof to verify for compatibility, got: %v", err)
	}
	if err := VerifyPathOpenProof(proof, pub, input); err == nil {
		t.Fatalf("expected default verifier to reject legacy no-middle proof")
	}
	if err := VerifyPathOpenProofStrict(proof, pub, input); err == nil {
		t.Fatalf("expected strict verifier to reject legacy no-middle proof")
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

func signLegacyPathOpenProofNoRegion(t *testing.T, priv ed25519.PrivateKey, input PathOpenProofInput) string {
	t.Helper()
	normalized := normalizePathOpenProofInput(input)
	payload := struct {
		Context         string `json:"ctx"`
		Token           string `json:"token"`
		ExitID          string `json:"exit_id"`
		MiddleRelayID   string `json:"middle_relay_id"`
		TokenProofNonce string `json:"token_proof_nonce"`
		ClientInnerPub  string `json:"client_inner_pub"`
		Transport       string `json:"transport"`
		RequestedMTU    int    `json:"requested_mtu"`
	}{
		Context:         pathOpenProofContext,
		Token:           normalized.Token,
		ExitID:          normalized.ExitID,
		MiddleRelayID:   normalized.MiddleRelayID,
		TokenProofNonce: normalized.TokenProofNonce,
		ClientInnerPub:  normalized.ClientInnerPub,
		Transport:       normalized.Transport,
		RequestedMTU:    normalized.RequestedMTU,
	}
	msg, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal legacy no-region payload: %v", err)
	}
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig)
}

func signLegacyPathOpenProofCoreOnly(t *testing.T, priv ed25519.PrivateKey, input PathOpenProofInput) string {
	t.Helper()
	normalized := normalizePathOpenProofInput(input)
	payload := struct {
		Context         string `json:"ctx"`
		Token           string `json:"token"`
		ExitID          string `json:"exit_id"`
		TokenProofNonce string `json:"token_proof_nonce"`
		ClientInnerPub  string `json:"client_inner_pub"`
	}{
		Context:         pathOpenProofContext,
		Token:           normalized.Token,
		ExitID:          normalized.ExitID,
		TokenProofNonce: normalized.TokenProofNonce,
		ClientInnerPub:  normalized.ClientInnerPub,
	}
	msg, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal legacy core payload: %v", err)
	}
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig)
}

func signLegacyPathOpenProofNoMiddle(t *testing.T, priv ed25519.PrivateKey, input PathOpenProofInput) string {
	t.Helper()
	normalized := normalizePathOpenProofInput(input)
	payload := struct {
		Context         string `json:"ctx"`
		Token           string `json:"token"`
		ExitID          string `json:"exit_id"`
		TokenProofNonce string `json:"token_proof_nonce"`
		ClientInnerPub  string `json:"client_inner_pub"`
		Transport       string `json:"transport"`
		RequestedMTU    int    `json:"requested_mtu"`
	}{
		Context:         pathOpenProofContext,
		Token:           normalized.Token,
		ExitID:          normalized.ExitID,
		TokenProofNonce: normalized.TokenProofNonce,
		ClientInnerPub:  normalized.ClientInnerPub,
		Transport:       normalized.Transport,
		RequestedMTU:    normalized.RequestedMTU,
	}
	msg, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal legacy no-middle payload: %v", err)
	}
	sig := ed25519.Sign(priv, msg)
	return base64.RawURLEncoding.EncodeToString(sig)
}
