package issuer

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestValidateRuntimeConfigBetaStrict(t *testing.T) {
	s := &Service{
		betaStrict:   true,
		adminToken:   "super-secret-admin-token",
		keyRotateSec: 60,
		tokenTTL:     10 * time.Minute,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected strict config valid, got %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsDefaultAdminToken(t *testing.T) {
	s := &Service{
		betaStrict:   true,
		adminToken:   "dev-admin-token",
		keyRotateSec: 60,
		tokenTTL:     10 * time.Minute,
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected strict config rejection")
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsShortAdminToken(t *testing.T) {
	s := &Service{
		betaStrict:   true,
		adminToken:   "short-token",
		keyRotateSec: 60,
		tokenTTL:     10 * time.Minute,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection")
	}
	if err.Error() != "BETA_STRICT_MODE requires ISSUER_ADMIN_TOKEN length>=16" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictSignedOnlyAllowsEmptyToken(t *testing.T) {
	s := &Service{
		betaStrict:         true,
		adminToken:         "",
		adminAllowToken:    false,
		adminAllowTokenSet: true,
		adminRequireSigned: true,
		adminPubKeys: map[string]ed25519.PublicKey{
			"k1": make(ed25519.PublicKey, ed25519.PublicKeySize),
		},
		keyRotateSec: 60,
		tokenTTL:     10 * time.Minute,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected strict config valid in signed-only mode, got %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsExposedAnonCredentialIDs(t *testing.T) {
	s := &Service{
		betaStrict:       true,
		adminToken:       "super-secret-admin-token",
		keyRotateSec:     60,
		tokenTTL:         10 * time.Minute,
		anonCredExposeID: true,
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected strict config rejection")
	}
}

func TestValidateRuntimeConfigPublicBindRejectsWeakTokenAdmin(t *testing.T) {
	s := &Service{
		addr:            "0.0.0.0:8082",
		adminToken:      "change-me",
		adminAllowToken: true,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected public bind rejection for weak admin token")
	}
	if !strings.Contains(err.Error(), "public bind requires strong ISSUER_ADMIN_TOKEN") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindRejectsLegacyKeyPath(t *testing.T) {
	s := &Service{
		addr:            "0.0.0.0:8082",
		adminToken:      "super-secret-admin-token",
		adminAllowToken: true,
		privateKeyPath:  "data/issuer_ed25519.key",
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected legacy key path rejection on public bind")
	}
	if !strings.Contains(err.Error(), "public bind rejects legacy ISSUER_PRIVATE_KEY_FILE path data/issuer_ed25519.key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRequireAdminSignedModeRejectsTokenFallbackByDefault(t *testing.T) {
	s := &Service{
		adminToken:                    "super-secret-admin-token",
		adminAllowToken:               true,
		adminAllowTokenSet:            true,
		adminRequireSigned:            true,
		adminSignedAllowTokenFallback: false,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/upsert", strings.NewReader(`{}`))
	req.Header.Set("X-Admin-Token", "super-secret-admin-token")
	rr := httptest.NewRecorder()
	if s.requireAdmin(rr, req) {
		t.Fatalf("expected signed-admin mode to reject token fallback by default")
	}
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rr.Code)
	}
}

func TestRequireAdminSignedModeAllowsExplicitTokenFallback(t *testing.T) {
	s := &Service{
		adminToken:                    "super-secret-admin-token",
		adminAllowToken:               true,
		adminAllowTokenSet:            true,
		adminRequireSigned:            true,
		adminSignedAllowTokenFallback: true,
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/admin/subject/upsert", strings.NewReader(`{}`))
	req.Header.Set("X-Admin-Token", "super-secret-admin-token")
	rr := httptest.NewRecorder()
	if !s.requireAdmin(rr, req) {
		t.Fatalf("expected explicit signed-admin token fallback to authorize request")
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
