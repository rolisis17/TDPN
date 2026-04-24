package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFileStoreRejectsConflictingCanonicalPolicySnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpngovernance.json")
	payload := `{"policies":{"legacy-a":{"PolicyID":" Policy-1 ","Title":"Policy A","Version":1,"ActivatedAtUnix":1},"legacy-b":{"PolicyID":"policy-1","Title":"Policy B","Version":1,"ActivatedAtUnix":1}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected conflicting canonical policy snapshot to fail")
	}
	if !strings.Contains(err.Error(), "conflicting policy entries") {
		t.Fatalf("expected conflicting policy validation error, got: %v", err)
	}
}

func TestNewFileStoreRejectsDecisionReferencingMissingPolicy(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpngovernance.json")
	payload := `{"decisions":{"legacy-a":{"DecisionID":"decision-1","PolicyID":"policy-missing","ProposalID":"proposal-1","Outcome":"approve","Decider":"council","DecidedAtUnix":1}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected orphaned decision snapshot to fail")
	}
	if !strings.Contains(err.Error(), "references missing policy") {
		t.Fatalf("expected missing policy validation error, got: %v", err)
	}
}
