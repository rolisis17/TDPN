package directory

import (
	"strings"
	"testing"
	"time"
)

func TestValidateRuntimeConfigProdStrictRejectsInsecureSkipVerify(t *testing.T) {
	t.Setenv("MTLS_ENABLE", "1")
	t.Setenv("MTLS_INSECURE_SKIP_VERIFY", "1")

	s := &Service{
		prodStrict: true,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected prod strict to reject MTLS_INSECURE_SKIP_VERIFY")
	}
	if err.Error() != "PROD_STRICT_MODE forbids MTLS_INSECURE_SKIP_VERIFY" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewDoesNotFallbackToDevAdminTokenByDefault(t *testing.T) {
	t.Setenv("DIRECTORY_ADMIN_TOKEN", "")
	t.Setenv("DIRECTORY_ALLOW_DANGEROUS_DEV_ADMIN_TOKEN_FALLBACK", "0")

	s := New()
	if s.adminToken != "" {
		t.Fatalf("expected empty DIRECTORY_ADMIN_TOKEN by default, got %q", s.adminToken)
	}
}

func TestNewAllowsExplicitDevAdminTokenFallback(t *testing.T) {
	t.Setenv("DIRECTORY_ADMIN_TOKEN", "")
	t.Setenv("DIRECTORY_ALLOW_DANGEROUS_DEV_ADMIN_TOKEN_FALLBACK", "1")

	s := New()
	if s.adminToken != "dev-admin-token" {
		t.Fatalf("expected explicit dev fallback token, got %q", s.adminToken)
	}
}

func TestValidateRuntimeConfigBetaStrict(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "directory-admin-012345",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected strict config valid, got %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindRejectsWeakAdminToken(t *testing.T) {
	s := &Service{
		addr:       "0.0.0.0:8081",
		adminToken: "dev-admin-token",
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected public bind rejection for weak admin token")
	}
	if err.Error() != "public bind requires strong DIRECTORY_ADMIN_TOKEN (len>=16, non-default)" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigLoopbackAllowsWeakAdminTokenOutsideStrict(t *testing.T) {
	s := &Service{
		addr:       "127.0.0.1:8081",
		adminToken: "dev-admin-token",
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected loopback dev config valid, got %v", err)
	}
}

func TestValidateRuntimeConfigPublicBindRejectsLegacyKeyPath(t *testing.T) {
	s := &Service{
		addr:           "0.0.0.0:8081",
		adminToken:     "directory-admin-012345",
		privateKeyPath: "data/directory_ed25519.key",
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected legacy key path rejection on public bind")
	}
	if err.Error() != "public bind rejects legacy DIRECTORY_PRIVATE_KEY_FILE path data/directory_ed25519.key" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsDefaultAdminToken(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "dev-admin-token",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for default admin token")
	}
	if err.Error() != "BETA_STRICT_MODE requires non-default DIRECTORY_ADMIN_TOKEN" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsEmptyAdminToken(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for empty admin token")
	}
	if err.Error() != "BETA_STRICT_MODE requires non-default DIRECTORY_ADMIN_TOKEN" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsShortAdminToken(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "short-token",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for short admin token")
	}
	if err.Error() != "BETA_STRICT_MODE requires DIRECTORY_ADMIN_TOKEN length>=16" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsWeakSettings(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "directory-admin-012345",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: false,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	if err := s.validateRuntimeConfig(); err == nil {
		t.Fatalf("expected strict config rejection")
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsWeakQuorumVotes(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             1,
		adminToken:               "directory-admin-012345",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for weak peer quorum votes")
	}
	if err.Error() != "BETA_STRICT_MODE requires DIRECTORY_PEER_MIN_VOTES>=2" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsWeakDiscoveryVotes(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "directory-admin-012345",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    1,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for weak discovery votes")
	}
	if err.Error() != "BETA_STRICT_MODE requires DIRECTORY_PEER_DISCOVERY_MIN_VOTES>=2" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMissingDiscoverySourceCap(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "directory-admin-012345",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   0,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for missing discovery per-source cap")
	}
	if err.Error() != "BETA_STRICT_MODE requires DIRECTORY_PEER_DISCOVERY_MAX_PER_SOURCE>0" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsMissingDiscoveryOperatorCap(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "directory-admin-012345",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    0,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for missing discovery per-operator cap")
	}
	if err.Error() != "BETA_STRICT_MODE requires DIRECTORY_PEER_DISCOVERY_MAX_PER_OPERATOR>0" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsWeakFinalSources(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "directory-admin-012345",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 1,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for weak final source quorum")
	}
	if err.Error() != "BETA_STRICT_MODE requires DIRECTORY_FINAL_ADJUDICATION_MIN_SOURCES>=2" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsWeakIssuerURLSet(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "directory-admin-012345",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      2,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for insufficient issuer trust urls")
	}
	if err.Error() != "BETA_STRICT_MODE requires at least 2 DIRECTORY_ISSUER_TRUST_URLS" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsWeakIssuerVotes(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		adminToken:               "directory-admin-012345",
		issuerTrustURLs:          []string{"http://127.0.0.1:8082", "http://127.0.0.1:8083"},
		issuerMinOperators:       2,
		issuerTrustMinVotes:      1,
		issuerDisputeMinVotes:    2,
		issuerAppealMinVotes:     2,
		peerDiscoveryMinVotes:    2,
		peerDiscoveryRequireHint: true,
		peerDiscoveryMaxPerSrc:   4,
		peerDiscoveryMaxPerOp:    4,
		peerTrustStrict:          true,
		finalAdjudicationOps:     2,
		finalAdjudicationSources: 2,
		finalDisputeMinVotes:     2,
		finalAppealMinVotes:      2,
		keyRotateEvery:           time.Second,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected strict config rejection for weak issuer trust votes")
	}
	if err.Error() != "BETA_STRICT_MODE requires DIRECTORY_ISSUER_TRUST_MIN_VOTES>=2" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsNonLoopbackIssuerTrustURLsWithoutAnchors(t *testing.T) {
	s := &Service{
		issuerTrustURLs:       []string{"https://issuer.example.com"},
		issuerTrustedKeysFile: t.TempDir() + "/issuer-trust-anchors.txt",
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected non-loopback issuer trust URLs without anchors to be rejected")
	}
	if !strings.Contains(err.Error(), "non-loopback issuer trust urls require configured issuer trust anchors") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigAllowsDangerousOverrideForIssuerTrustURLsWithoutAnchors(t *testing.T) {
	t.Setenv(allowDangerousIssuerTrustWithoutAnchors, "1")

	s := &Service{
		issuerTrustURLs:       []string{"https://issuer.example.com"},
		issuerTrustedKeysFile: t.TempDir() + "/issuer-trust-anchors.txt",
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected dangerous override to allow missing issuer trust anchors, got %v", err)
	}
}

func TestValidateRuntimeConfigAllowsLoopbackIssuerTrustURLsWithoutAnchors(t *testing.T) {
	s := &Service{
		issuerTrustURLs:       []string{"http://127.0.0.1:8082", "http://localhost:8083"},
		issuerTrustedKeysFile: t.TempDir() + "/issuer-trust-anchors.txt",
	}
	if err := s.validateRuntimeConfig(); err != nil {
		t.Fatalf("expected loopback issuer trust URLs to allow missing anchors, got %v", err)
	}
}
