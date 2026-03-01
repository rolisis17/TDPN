package directory

import (
	"testing"
	"time"
)

func TestValidateRuntimeConfigBetaStrict(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		issuerTrustURLs:          []string{"http://issuer-a.local", "http://issuer-b.local"},
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

func TestValidateRuntimeConfigBetaStrictRejectsWeakSettings(t *testing.T) {
	s := &Service{
		betaStrict:               true,
		peerDiscoveryEnabled:     true,
		peerMinOperators:         2,
		peerMinVotes:             2,
		issuerTrustURLs:          []string{"http://issuer-a.local", "http://issuer-b.local"},
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
		issuerTrustURLs:          []string{"http://issuer-a.local", "http://issuer-b.local"},
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
		issuerTrustURLs:          []string{"http://issuer-a.local", "http://issuer-b.local"},
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
		issuerTrustURLs:          []string{"http://issuer-a.local", "http://issuer-b.local"},
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
		issuerTrustURLs:          []string{"http://issuer-a.local", "http://issuer-b.local"},
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
		issuerTrustURLs:          []string{"http://issuer-a.local", "http://issuer-b.local"},
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
		issuerTrustURLs:          []string{"http://issuer-a.local"},
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
		issuerTrustURLs:          []string{"http://issuer-a.local", "http://issuer-b.local"},
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
