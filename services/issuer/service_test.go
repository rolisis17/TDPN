package issuer

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"privacynode/pkg/crypto"
	"privacynode/pkg/proto"
	"privacynode/pkg/settlement"
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

func TestIssueTokenRequestRejectsPublicProviderRoleIssuance(t *testing.T) {
	pub, priv, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	popPub, _, err := crypto.GenerateEd25519Keypair()
	if err != nil {
		t.Fatalf("pop keygen failed: %v", err)
	}
	s := &Service{
		issuerID: "issuer-main",
		pubKey:   pub,
		privKey:  priv,
		keyEpoch: 1,
		tokenTTL: 10 * time.Minute,
	}
	req := proto.IssueTokenRequest{
		Tier:      2,
		Subject:   "provider-operator-a",
		TokenType: crypto.TokenTypeProviderRole,
		PopPubKey: crypto.EncodeEd25519PublicKey(popPub),
	}
	rr := httptest.NewRecorder()
	s.issueTokenRequest(t.Context(), rr, req, false)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected provider_role issuance forbidden on public endpoint, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestNewReadsTokenTTLFromEnv(t *testing.T) {
	t.Setenv("ISSUER_TOKEN_TTL_SEC", "45")
	svc := New()
	if svc.tokenTTL != 45*time.Second {
		t.Fatalf("expected token ttl 45s, got %s", svc.tokenTTL)
	}
}

func TestNewDoesNotFallbackToDevAdminTokenByDefault(t *testing.T) {
	t.Setenv("ISSUER_ADMIN_TOKEN", "")
	t.Setenv("ISSUER_ALLOW_DANGEROUS_DEV_ADMIN_TOKEN_FALLBACK", "0")

	svc := New()
	if svc.adminToken != "" {
		t.Fatalf("expected empty ISSUER_ADMIN_TOKEN by default, got %q", svc.adminToken)
	}
}

func TestNewAllowsExplicitDevAdminTokenFallback(t *testing.T) {
	t.Setenv("ISSUER_ADMIN_TOKEN", "")
	t.Setenv("ISSUER_ALLOW_DANGEROUS_DEV_ADMIN_TOKEN_FALLBACK", "1")

	svc := New()
	if svc.adminToken != "dev-admin-token" {
		t.Fatalf("expected explicit dev fallback token, got %q", svc.adminToken)
	}
}

func TestValidateRuntimeConfigBetaStrict(t *testing.T) {
	s := &Service{
		betaStrict:          true,
		adminToken:          "super-secret-admin-token",
		requirePaymentProof: true,
		keyRotateSec:        60,
		tokenTTL:            10 * time.Minute,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected strict config valid, got %v", err)
	}
}

func TestValidateRuntimeConfigProdStrictRejectsInsecureSkipVerify(t *testing.T) {
	t.Setenv("MTLS_ENABLE", "1")
	t.Setenv("MTLS_INSECURE_SKIP_VERIFY", "1")
	s := &Service{
		prodStrict: true,
		betaStrict: true,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected prod strict to reject MTLS_INSECURE_SKIP_VERIFY")
	}
	if err.Error() != "PROD_STRICT_MODE forbids MTLS_INSECURE_SKIP_VERIFY" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsDefaultAdminToken(t *testing.T) {
	s := &Service{
		betaStrict:          true,
		adminToken:          "dev-admin-token",
		requirePaymentProof: true,
		keyRotateSec:        60,
		tokenTTL:            10 * time.Minute,
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected strict config rejection")
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsShortAdminToken(t *testing.T) {
	s := &Service{
		betaStrict:          true,
		adminToken:          "short-token",
		requirePaymentProof: true,
		keyRotateSec:        60,
		tokenTTL:            10 * time.Minute,
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
		betaStrict:          true,
		adminToken:          "",
		adminAllowToken:     false,
		adminAllowTokenSet:  true,
		adminRequireSigned:  true,
		requirePaymentProof: true,
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
		betaStrict:          true,
		adminToken:          "super-secret-admin-token",
		requirePaymentProof: true,
		keyRotateSec:        60,
		tokenTTL:            10 * time.Minute,
		anonCredExposeID:    true,
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected strict config rejection")
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMissingPaymentProofRequirement(t *testing.T) {
	s := &Service{
		betaStrict:   true,
		adminToken:   "super-secret-admin-token",
		keyRotateSec: 60,
		tokenTTL:     10 * time.Minute,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection")
	}
	if err.Error() != "BETA_STRICT_MODE requires ISSUER_REQUIRE_PAYMENT_PROOF=1" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestHandleCriticalStartupLoadErrorFailsClosedInStrictMode(t *testing.T) {
	s := &Service{betaStrict: true}
	loadErr := errors.New("read failed")
	err := s.handleCriticalStartupLoadError("revocations", loadErr)
	if err == nil {
		t.Fatalf("expected strict startup load failure")
	}
	if !strings.Contains(err.Error(), "strict mode") {
		t.Fatalf("expected strict mode error, got %v", err)
	}
}

func TestHandleCriticalStartupLoadErrorWarnsOutsideStrictMode(t *testing.T) {
	s := &Service{}
	loadErr := errors.New("read failed")
	if err := s.handleCriticalStartupLoadError("revocations", loadErr); err != nil {
		t.Fatalf("expected non-strict startup load warning path, got %v", err)
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

func TestValidateRuntimeConfigPublicBindRejectsWeakSponsorToken(t *testing.T) {
	s := &Service{
		addr:            "0.0.0.0:8082",
		adminToken:      "super-secret-admin-token",
		adminAllowToken: true,
		sponsorAPIToken: "dev-sponsor-token",
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected public bind rejection for weak sponsor token")
	}
	if !strings.Contains(err.Error(), "public bind requires strong ISSUER_SPONSOR_API_TOKEN") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindTokenAuthRequiresMTLS(t *testing.T) {
	s := &Service{
		addr:            "0.0.0.0:8082",
		adminToken:      "super-secret-admin-token",
		adminAllowToken: true,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected public bind rejection when token auth is enabled without mTLS")
	}
	if !strings.Contains(err.Error(), "public bind requires MTLS_ENABLE=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindSignedOnlyRequiresMTLS(t *testing.T) {
	s := &Service{
		addr:                "0.0.0.0:8082",
		adminAllowToken:     false,
		adminAllowTokenSet:  true,
		adminRequireSigned:  true,
		requirePaymentProof: true,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected public bind rejection when mTLS is disabled")
	}
	if !strings.Contains(err.Error(), "public bind requires MTLS_ENABLE=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindTokenAuthAllowsExplicitInsecureOverride(t *testing.T) {
	t.Setenv("ISSUER_ALLOW_DANGEROUS_INSECURE_TOKEN_AUTH_PUBLIC_BIND", "1")
	s := &Service{
		addr:                "0.0.0.0:8082",
		adminToken:          "super-secret-admin-token",
		adminAllowToken:     true,
		requirePaymentProof: true,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected explicit dangerous override to allow config, got %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindSignedOnlyAllowsExplicitInsecureOverride(t *testing.T) {
	t.Setenv("ISSUER_ALLOW_DANGEROUS_INSECURE_TOKEN_AUTH_PUBLIC_BIND", "1")
	s := &Service{
		addr:                "0.0.0.0:8082",
		adminAllowToken:     false,
		adminAllowTokenSet:  true,
		adminRequireSigned:  true,
		adminPubKeys:        map[string]ed25519.PublicKey{"k1": make(ed25519.PublicKey, ed25519.PublicKeySize)},
		requirePaymentProof: true,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected explicit dangerous override to allow config, got %v", err)
	}
}

func TestValidateRuntimeConfigLocalhostBindRequiresLoopbackDNSResolution(t *testing.T) {
	prevLookup := lookupIPAddr
	lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "localhost" {
			t.Fatalf("unexpected host lookup %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("203.0.113.10")}}, nil
	}
	t.Cleanup(func() {
		lookupIPAddr = prevLookup
	})

	s := &Service{
		addr:                "localhost:8082",
		adminToken:          "super-secret-admin-token",
		adminAllowToken:     true,
		requirePaymentProof: true,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected localhost bind to be treated as public when DNS resolves non-loopback")
	}
	if !strings.Contains(err.Error(), "public bind requires MTLS_ENABLE=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigLocalhostBindAllowsAllLoopbackDNSResolution(t *testing.T) {
	prevLookup := lookupIPAddr
	lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		if host != "localhost" {
			t.Fatalf("unexpected host lookup %q", host)
		}
		return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("::1")}}, nil
	}
	t.Cleanup(func() {
		lookupIPAddr = prevLookup
	})

	s := &Service{
		addr:                "localhost:8082",
		adminToken:          "super-secret-admin-token",
		adminAllowToken:     true,
		requirePaymentProof: true,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected localhost bind with all-loopback DNS answers to remain local-only, got %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindRequiresPaymentProof(t *testing.T) {
	t.Setenv("ISSUER_ALLOW_DANGEROUS_INSECURE_TOKEN_AUTH_PUBLIC_BIND", "1")
	s := &Service{
		addr:               "0.0.0.0:8082",
		adminAllowToken:    false,
		adminAllowTokenSet: true,
		adminRequireSigned: true,
		adminPubKeys: map[string]ed25519.PublicKey{
			"k1": make(ed25519.PublicKey, ed25519.PublicKeySize),
		},
		requirePaymentProof: false,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected public bind rejection when payment proof is disabled")
	}
	if !strings.Contains(err.Error(), "public bind requires ISSUER_REQUIRE_PAYMENT_PROOF=1") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindAllowsPaymentProofDangerousOverride(t *testing.T) {
	t.Setenv("ISSUER_ALLOW_DANGEROUS_PUBLIC_ISSUE_WITHOUT_PAYMENT_PROOF", "1")
	t.Setenv("ISSUER_ALLOW_DANGEROUS_INSECURE_TOKEN_AUTH_PUBLIC_BIND", "1")
	s := &Service{
		addr:               "0.0.0.0:8082",
		adminAllowToken:    false,
		adminAllowTokenSet: true,
		adminRequireSigned: true,
		adminPubKeys: map[string]ed25519.PublicKey{
			"k1": make(ed25519.PublicKey, ed25519.PublicKeySize),
		},
		requirePaymentProof: false,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected dangerous override to allow public bind without payment proof, got %v", err)
	}
}

func TestNewSponsorTokenDefaultsDisabled(t *testing.T) {
	t.Setenv("ISSUER_SPONSOR_API_TOKEN", "")
	s := New()
	if strings.TrimSpace(s.sponsorAPIToken) != "" {
		t.Fatalf("expected sponsor api token default disabled, got %q", s.sponsorAPIToken)
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

func TestHandleSettlementStatusIncludesLifecycleCounters(t *testing.T) {
	now := time.Unix(1713300000, 0).UTC()
	stub := &issuerSettlementReconcileStub{
		report: settlement.ReconcileReport{
			GeneratedAt:               now,
			ShadowAdapterConfigured:   true,
			ShadowAttemptedOperations: 9,
			ShadowSubmittedOperations: 7,
			ShadowFailedOperations:    2,
			PendingOperations:         4,
			SubmittedOperations:       7,
			ConfirmedOperations:       3,
			FailedOperations:          1,
		},
	}
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      stub,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()
	s.handleSettlementStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Status                    string `json:"status"`
		GeneratedAt               int64  `json:"generated_at"`
		ShadowAdapterConfigured   bool   `json:"shadow_adapter_configured"`
		ShadowAttemptedOperations int    `json:"shadow_attempted_operations"`
		ShadowSubmittedOperations int    `json:"shadow_submitted_operations"`
		ShadowFailedOperations    int    `json:"shadow_failed_operations"`
		PendingOperations         int    `json:"pending_operations"`
		SubmittedOperations       int    `json:"submitted_operations"`
		ConfirmedOperations       int    `json:"confirmed_operations"`
		FailedOperations          int    `json:"failed_operations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "backlog" {
		t.Fatalf("expected backlog status, got %q", resp.Status)
	}
	if resp.GeneratedAt != now.Unix() {
		t.Fatalf("expected generated_at %d, got %d", now.Unix(), resp.GeneratedAt)
	}
	if !resp.ShadowAdapterConfigured || resp.ShadowAttemptedOperations != 9 || resp.ShadowSubmittedOperations != 7 || resp.ShadowFailedOperations != 2 {
		t.Fatalf("unexpected shadow telemetry: %+v", resp)
	}
	if resp.PendingOperations != 4 || resp.SubmittedOperations != 7 || resp.ConfirmedOperations != 3 || resp.FailedOperations != 1 {
		t.Fatalf("unexpected lifecycle counters: %+v", resp)
	}
	if stub.calls != 1 {
		t.Fatalf("expected reconcile call count 1, got %d", stub.calls)
	}
}

func TestHandleSettlementStatusIncludesConfirmedCounterWhenNoBacklog(t *testing.T) {
	now := time.Unix(1713400000, 0).UTC()
	stub := &issuerSettlementReconcileStub{
		report: settlement.ReconcileReport{
			GeneratedAt:               now,
			ShadowAdapterConfigured:   true,
			ShadowAttemptedOperations: 3,
			ShadowSubmittedOperations: 3,
			ShadowFailedOperations:    0,
			PendingOperations:         0,
			SubmittedOperations:       2,
			ConfirmedOperations:       5,
			FailedOperations:          0,
		},
	}
	s := &Service{
		adminToken:      "admin-secret-token",
		adminAllowToken: true,
		settlement:      stub,
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/settlement/status", nil)
	req.Header.Set("X-Admin-Token", "admin-secret-token")
	rr := httptest.NewRecorder()
	s.handleSettlementStatus(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d body=%s", rr.Code, rr.Body.String())
	}
	var resp struct {
		Status                    string `json:"status"`
		GeneratedAt               int64  `json:"generated_at"`
		ShadowAdapterConfigured   bool   `json:"shadow_adapter_configured"`
		ShadowAttemptedOperations int    `json:"shadow_attempted_operations"`
		ShadowSubmittedOperations int    `json:"shadow_submitted_operations"`
		ShadowFailedOperations    int    `json:"shadow_failed_operations"`
		PendingOperations         int    `json:"pending_operations"`
		SubmittedOperations       int    `json:"submitted_operations"`
		ConfirmedOperations       int    `json:"confirmed_operations"`
		FailedOperations          int    `json:"failed_operations"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.Status != "ok" {
		t.Fatalf("expected ok status, got %q", resp.Status)
	}
	if resp.GeneratedAt != now.Unix() {
		t.Fatalf("expected generated_at %d, got %d", now.Unix(), resp.GeneratedAt)
	}
	if !resp.ShadowAdapterConfigured || resp.ShadowAttemptedOperations != 3 || resp.ShadowSubmittedOperations != 3 || resp.ShadowFailedOperations != 0 {
		t.Fatalf("unexpected shadow telemetry: %+v", resp)
	}
	if resp.PendingOperations != 0 || resp.SubmittedOperations != 2 || resp.ConfirmedOperations != 5 || resp.FailedOperations != 0 {
		t.Fatalf("unexpected lifecycle counters: %+v", resp)
	}
	if stub.calls != 1 {
		t.Fatalf("expected reconcile call count 1, got %d", stub.calls)
	}
}

func TestNewSettlementServiceFromEnvWiresBlockchainModeForCosmosAdapter(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", srv.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "issuer-mode-test")
	t.Setenv("COSMOS_SETTLEMENT_MAX_RETRIES", "0")
	t.Setenv("COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS", "500")

	svc := newSettlementServiceFromEnv()
	ctx := context.Background()

	const reservationID = "res-blockchain-on"
	const sessionID = "sess-blockchain-on"
	reservation, err := svc.ReserveSponsorCredits(ctx, settlement.SponsorCreditReservation{
		ReservationID: reservationID,
		SponsorID:     "sponsor-a",
		SubjectID:     "subject-a",
		SessionID:     sessionID,
		AmountMicros:  1000,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != settlement.OperationStatusSubmitted {
		t.Fatalf("expected submitted reservation when cosmos adapter is configured, got %s", reservation.Status)
	}

	_, err = svc.AuthorizePayment(ctx, settlement.PaymentProof{
		ReservationID: reservationID,
		SponsorID:     "sponsor-a",
		SubjectID:     "subject-a",
		SessionID:     sessionID,
	})
	if err == nil {
		t.Fatalf("expected AuthorizePayment to fail until chain finality in blockchain mode")
	}
	if !strings.Contains(err.Error(), "chain") {
		t.Fatalf("expected chain finality error, got %v", err)
	}
}

func TestNewSettlementServiceFromEnvKeepsMemoryModeWhenChainAdapterDisabled(t *testing.T) {
	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", "")

	svc := newSettlementServiceFromEnv()
	ctx := context.Background()

	const reservationID = "res-memory-on"
	const sessionID = "sess-memory-on"
	reservation, err := svc.ReserveSponsorCredits(ctx, settlement.SponsorCreditReservation{
		ReservationID: reservationID,
		SponsorID:     "sponsor-a",
		SubjectID:     "subject-a",
		SessionID:     sessionID,
		AmountMicros:  1000,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveSponsorCredits: %v", err)
	}
	if reservation.Status != settlement.OperationStatusConfirmed {
		t.Fatalf("expected confirmed reservation in default memory mode, got %s", reservation.Status)
	}

	auth, err := svc.AuthorizePayment(ctx, settlement.PaymentProof{
		ReservationID: reservationID,
		SponsorID:     "sponsor-a",
		SubjectID:     "subject-a",
		SessionID:     sessionID,
	})
	if err != nil {
		t.Fatalf("AuthorizePayment: %v", err)
	}
	if auth.ReservationID != reservationID {
		t.Fatalf("expected authorization for reservation %s, got %s", reservationID, auth.ReservationID)
	}
}
