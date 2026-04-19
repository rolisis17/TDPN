package entry

import (
	"strings"
	"testing"
)

func TestValidateRuntimeConfigProdStrictRejectsInsecureSkipVerify(t *testing.T) {
	t.Setenv("MTLS_ENABLE", "1")
	t.Setenv("MTLS_INSECURE_SKIP_VERIFY", "1")

	s := &Service{
		prodStrict: true,
		betaStrict: true,
		liveWGMode: true,
		directoryTrustStrict: true,
		requireDistinctExitOp: true,
		operatorID: "op-entry",
		puzzleSecret: "entry-secret-012345",
		puzzleDifficulty: 1,
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
