package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewFileStoreRejectsConflictingCanonicalAccrualSnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnrewards.json")
	payload := `{"accruals":{"legacy-a":{"AccrualID":" Acc-1 ","SessionID":"sess-a","ProviderID":"provider-a","AssetDenom":"uusdc","Amount":10},"legacy-b":{"AccrualID":"acc-1","SessionID":"sess-b","ProviderID":"provider-b","AssetDenom":"uusdc","Amount":10}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected conflicting canonical accrual snapshot to fail")
	}
	if !strings.Contains(err.Error(), "conflicting accrual entries") {
		t.Fatalf("expected conflicting accrual validation error, got: %v", err)
	}
}

func TestNewFileStoreRejectsDuplicateProviderWeeklyAccrualSnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnrewards.json")
	payload := `{"accruals":{"acc-weekly-a":{"AccrualID":"acc-weekly-a","SessionID":"sess-weekly-a","ProviderID":"provider-weekly","AssetDenom":"uusdc","Amount":10,"AccruedAtUnix":1700000000,"PayoutStartUnix":1699833600,"PayoutEndUnix":1700438400},"acc-weekly-b":{"AccrualID":"acc-weekly-b","SessionID":"sess-weekly-b","ProviderID":"provider-weekly","AssetDenom":"uusdc","Amount":11,"AccruedAtUnix":1700604800,"PayoutStartUnix":1699833600,"PayoutEndUnix":1700438400}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected duplicate provider weekly accrual snapshot to fail")
	}
	if !strings.Contains(err.Error(), "weekly epoch") {
		t.Fatalf("expected weekly epoch validation error, got: %v", err)
	}
}

func TestNewFileStoreRejectsMissingPeriodWeeklyAccrualSnapshotCollision(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnrewards.json")
	payload := `{"accruals":{"acc-weekly-a":{"AccrualID":"acc-weekly-a","SessionID":"sess-weekly-a","ProviderID":"provider-weekly","AssetDenom":"uusdc","Amount":10,"AccruedAtUnix":1700000000,"PayoutStartUnix":1699833600,"PayoutEndUnix":1700438400},"acc-weekly-missing":{"AccrualID":"acc-weekly-missing","SessionID":"sess-weekly-missing","ProviderID":"provider-weekly","AssetDenom":"uusdc","Amount":11,"AccruedAtUnix":1700003600}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected missing-period weekly accrual snapshot collision to fail")
	}
	if !strings.Contains(err.Error(), "weekly epoch") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected weekly missing-period validation error, got: %v", err)
	}
}

func TestNewFileStoreAllowsDuplicateProviderNonWeeklyAccrualSnapshot(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnrewards.json")
	payload := `{"accruals":{"acc-session-a":{"AccrualID":"acc-session-a","SessionID":"sess-session-a","ProviderID":"provider-session","AssetDenom":"uusdc","Amount":10,"AccruedAtUnix":1700000000},"acc-session-b":{"AccrualID":"acc-session-b","SessionID":"sess-session-b","ProviderID":"provider-session","AssetDenom":"uusdc","Amount":11,"AccruedAtUnix":1700003600}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("expected duplicate provider non-weekly accrual snapshot to load, got: %v", err)
	}
	if got := len(store.ListAccruals()); got != 2 {
		t.Fatalf("expected 2 accruals, got %d", got)
	}
}

func TestNewFileStoreAllowsSameProviderDistinctWeeklyPayoutSnapshots(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "vpnrewards.json")
	payload := `{"accruals":{"acc-weekly-a":{"AccrualID":"acc-weekly-a","SessionID":"sess-weekly-a","ProviderID":"provider-weekly","AssetDenom":"uusdc","Amount":10,"AccruedAtUnix":1700000000,"PayoutStartUnix":1699833600,"PayoutEndUnix":1700438400},"acc-weekly-b":{"AccrualID":"acc-weekly-b","SessionID":"sess-weekly-b","ProviderID":"provider-weekly","AssetDenom":"uusdc","Amount":11,"AccruedAtUnix":1700000000,"PayoutStartUnix":1700438400,"PayoutEndUnix":1701043200}}}`
	if err := os.WriteFile(storePath, []byte(payload), 0o600); err != nil {
		t.Fatalf("write seeded snapshot: %v", err)
	}

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("expected distinct weekly payout snapshots to load, got: %v", err)
	}
	if got := len(store.ListAccruals()); got != 2 {
		t.Fatalf("expected 2 accruals, got %d", got)
	}
}
