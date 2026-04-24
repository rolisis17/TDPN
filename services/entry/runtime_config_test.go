package entry

import (
	"strings"
	"testing"
)

func TestValidateRuntimeConfigProdStrictRejectsInsecureSkipVerify(t *testing.T) {
	t.Setenv("MTLS_ENABLE", "1")
	t.Setenv("MTLS_INSECURE_SKIP_VERIFY", "1")

	s := &Service{
		prodStrict:            true,
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-012345",
		puzzleDifficulty:      1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected prod strict to reject MTLS_INSECURE_SKIP_VERIFY")
	}
	if err.Error() != "PROD_STRICT_MODE forbids MTLS_INSECURE_SKIP_VERIFY" {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsDirectoryTrustTOFU(t *testing.T) {
	s := &Service{
		betaStrict:           true,
		liveWGMode:           true,
		directoryTrustStrict: true,
		directoryTrustTOFU:   true,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected beta strict to reject ENTRY_DIRECTORY_TRUST_TOFU")
	}
	if !strings.Contains(err.Error(), "ENTRY_DIRECTORY_TRUST_TOFU=0") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigBetaStrictRejectsDangerousOutboundPrivateDNS(t *testing.T) {
	t.Setenv(allowDangerousOutboundPrivateDNS, "1")

	s := &Service{
		betaStrict:            true,
		liveWGMode:            true,
		directoryTrustStrict:  true,
		requireDistinctExitOp: true,
		operatorID:            "op-entry",
		puzzleSecret:          "entry-secret-012345",
		puzzleDifficulty:      1,
	}
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected beta strict to reject dangerous outbound private DNS override")
	}
	expected := "BETA_STRICT_MODE forbids " + allowDangerousOutboundPrivateDNS
	if err.Error() != expected {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsMalformedRequireMiddleRelayEnv(t *testing.T) {
	t.Setenv("ENTRY_REQUIRE_MIDDLE_RELAY", "maybe")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected malformed ENTRY_REQUIRE_MIDDLE_RELAY to fail closed")
	}
	if !strings.Contains(err.Error(), "ENTRY_REQUIRE_MIDDLE_RELAY invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsMalformedStrictModeEnv(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "definitely")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected malformed strict-mode env to fail closed")
	}
	if !strings.Contains(err.Error(), "BETA_STRICT_MODE/ENTRY_BETA_STRICT invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsEmptyStrictModeEnv(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "   ")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected empty strict-mode env to fail closed")
	}
	if !strings.Contains(err.Error(), "BETA_STRICT_MODE/ENTRY_BETA_STRICT invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestNewBetaStrictConflictPreservesStrictMode(t *testing.T) {
	t.Setenv("BETA_STRICT_MODE", "0")
	t.Setenv("ENTRY_BETA_STRICT", "1")

	s := New()
	if !s.betaStrict {
		t.Fatalf("expected beta strict mode enabled when strict env vars conflict")
	}
}

func TestNewProdStrictConflictPreservesStrictMode(t *testing.T) {
	t.Setenv("PROD_STRICT_MODE", "0")
	t.Setenv("ENTRY_PROD_STRICT", "1")

	s := New()
	if !s.prodStrict {
		t.Fatalf("expected prod strict mode enabled when strict env vars conflict")
	}
}

func TestValidateRuntimeConfigRejectsMalformedDirectoryTrustStrictEnv(t *testing.T) {
	t.Setenv("ENTRY_DIRECTORY_TRUST_STRICT", "definitely")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected malformed ENTRY_DIRECTORY_TRUST_STRICT to fail closed")
	}
	if !strings.Contains(err.Error(), "ENTRY_DIRECTORY_TRUST_STRICT/DIRECTORY_TRUST_STRICT invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsEmptyDirectoryTrustStrictEnv(t *testing.T) {
	t.Setenv("ENTRY_DIRECTORY_TRUST_STRICT", "   ")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected empty ENTRY_DIRECTORY_TRUST_STRICT to fail closed")
	}
	if !strings.Contains(err.Error(), "ENTRY_DIRECTORY_TRUST_STRICT/DIRECTORY_TRUST_STRICT invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateRuntimeConfigRejectsEmptyRequireMiddleRelayEnv(t *testing.T) {
	t.Setenv("ENTRY_REQUIRE_MIDDLE_RELAY", " ")

	s := New()
	err := s.validateRuntimeConfig()
	if err == nil {
		t.Fatalf("expected empty ENTRY_REQUIRE_MIDDLE_RELAY to fail closed")
	}
	if !strings.Contains(err.Error(), "ENTRY_REQUIRE_MIDDLE_RELAY invalid") {
		t.Fatalf("unexpected error: %v", err)
	}
}
