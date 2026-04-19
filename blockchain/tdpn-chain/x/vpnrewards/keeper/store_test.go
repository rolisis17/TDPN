package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

type trackingStore struct {
	accruals      map[string]types.RewardAccrual
	distributions map[string]types.DistributionRecord

	upsertAccrualCalls      int
	getAccrualCalls         int
	upsertDistributionCalls int
	getDistributionCalls    int
}

func newTrackingStore() *trackingStore {
	return &trackingStore{
		accruals:      make(map[string]types.RewardAccrual),
		distributions: make(map[string]types.DistributionRecord),
	}
}

func (s *trackingStore) UpsertAccrual(record types.RewardAccrual) {
	s.upsertAccrualCalls++
	s.accruals[record.AccrualID] = record
}

func (s *trackingStore) GetAccrual(accrualID string) (types.RewardAccrual, bool) {
	s.getAccrualCalls++
	record, ok := s.accruals[accrualID]
	return record, ok
}

func (s *trackingStore) ListAccruals() []types.RewardAccrual {
	records := make([]types.RewardAccrual, 0, len(s.accruals))
	for _, record := range s.accruals {
		records = append(records, record)
	}
	return records
}

func (s *trackingStore) UpsertDistribution(record types.DistributionRecord) {
	s.upsertDistributionCalls++
	s.distributions[record.DistributionID] = record
}

func (s *trackingStore) GetDistribution(distributionID string) (types.DistributionRecord, bool) {
	s.getDistributionCalls++
	record, ok := s.distributions[distributionID]
	return record, ok
}

func (s *trackingStore) ListDistributions() []types.DistributionRecord {
	records := make([]types.DistributionRecord, 0, len(s.distributions))
	for _, record := range s.distributions {
		records = append(records, record)
	}
	return records
}

func TestNewKeeperWithStoreNilFallsBackToInMemory(t *testing.T) {
	t.Parallel()

	k := NewKeeperWithStore(nil)

	record := types.RewardAccrual{
		AccrualID:  "acc-fallback",
		ProviderID: "provider-fallback",
		Amount:     1,
	}
	k.UpsertAccrual(record)

	got, ok := k.GetAccrual(record.AccrualID)
	if !ok {
		t.Fatal("expected accrual to be present with nil-store fallback")
	}
	if got.AccrualID != record.AccrualID {
		t.Fatalf("expected accrual id %q, got %q", record.AccrualID, got.AccrualID)
	}
}

func TestKeeperDelegatesUpsertAndGetToCustomStore(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	accrual := types.RewardAccrual{
		AccrualID:  "acc-1",
		ProviderID: "provider-1",
		Amount:     100,
	}
	k.UpsertAccrual(accrual)

	if store.upsertAccrualCalls != 1 {
		t.Fatalf("expected 1 accrual upsert call, got %d", store.upsertAccrualCalls)
	}

	gotAccrual, ok := k.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatal("expected accrual from custom store")
	}
	if gotAccrual.Amount != accrual.Amount {
		t.Fatalf("expected accrual amount %d, got %d", accrual.Amount, gotAccrual.Amount)
	}
	if store.getAccrualCalls != 1 {
		t.Fatalf("expected 1 accrual get call, got %d", store.getAccrualCalls)
	}

	distribution := types.DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-1",
	}
	k.UpsertDistribution(distribution)

	if store.upsertDistributionCalls != 1 {
		t.Fatalf("expected 1 distribution upsert call, got %d", store.upsertDistributionCalls)
	}

	gotDistribution, ok := k.GetDistribution(distribution.DistributionID)
	if !ok {
		t.Fatal("expected distribution from custom store")
	}
	if gotDistribution.PayoutRef != distribution.PayoutRef {
		t.Fatalf("expected payout ref %q, got %q", distribution.PayoutRef, gotDistribution.PayoutRef)
	}
	if store.getDistributionCalls != 1 {
		t.Fatalf("expected 1 distribution get call, got %d", store.getDistributionCalls)
	}
}

func TestKeeperCreateAndRecordUseCustomStoreWithStatusProgression(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "acc-1",
		ProviderID: "provider-1",
		Amount:     100,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}
	if accrual.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf("expected accrual status %q, got %q", chaintypes.ReconciliationPending, accrual.OperationState)
	}
	if store.upsertAccrualCalls == 0 || store.getAccrualCalls == 0 {
		t.Fatalf("expected create path to touch custom accrual store, got upsert=%d get=%d", store.upsertAccrualCalls, store.getAccrualCalls)
	}

	_, err = k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-1",
	})
	if err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}
	if store.upsertDistributionCalls == 0 || store.getDistributionCalls == 0 {
		t.Fatalf("expected record path to touch custom distribution store, got upsert=%d get=%d", store.upsertDistributionCalls, store.getDistributionCalls)
	}

	updated, ok := k.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatal("expected accrual to exist after recording distribution")
	}
	if updated.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected accrual state %q after distribution, got %q", chaintypes.ReconciliationConfirmed, updated.OperationState)
	}
}

func TestFileStorePersistsAcrossReopen(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnrewards.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	accrual := types.RewardAccrual{
		AccrualID:      "acc-file-1",
		SessionID:      "session-file-1",
		ProviderID:     "provider-file-1",
		AssetDenom:     "uusdc",
		Amount:         42,
		AccruedAtUnix:  1700000000,
		OperationState: chaintypes.ReconciliationSubmitted,
	}
	distribution := types.DistributionRecord{
		DistributionID: "dist-file-1",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-file-1",
		DistributedAt:  1700000001,
		Status:         chaintypes.ReconciliationConfirmed,
	}

	store.UpsertAccrual(accrual)
	store.UpsertDistribution(distribution)

	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopening file store returned unexpected error: %v", err)
	}

	gotAccrual, ok := reopened.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatal("expected accrual to be loaded from file store")
	}
	if gotAccrual != accrual {
		t.Fatalf("expected reopened accrual %+v, got %+v", accrual, gotAccrual)
	}

	gotDistribution, ok := reopened.GetDistribution(distribution.DistributionID)
	if !ok {
		t.Fatal("expected distribution to be loaded from file store")
	}
	if gotDistribution != distribution {
		t.Fatalf("expected reopened distribution %+v, got %+v", distribution, gotDistribution)
	}
}

func TestNewFileStoreInvalidPath(t *testing.T) {
	t.Parallel()

	blockerFile := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockerFile, []byte("blocker"), 0o644); err != nil {
		t.Fatalf("failed to seed blocker file: %v", err)
	}

	_, err := NewFileStore(filepath.Join(blockerFile, "vpnrewards.json"))
	if err == nil {
		t.Fatal("expected NewFileStore to fail when parent path is not a directory")
	}
}

func TestFileStoreListAccrualsAndDistributionsAcrossReopen(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnrewards.json")
	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	accrualA := types.RewardAccrual{
		AccrualID:      "acc-file-a",
		ProviderID:     "provider-a",
		Amount:         11,
		OperationState: chaintypes.ReconciliationPending,
	}
	accrualB := types.RewardAccrual{
		AccrualID:      "acc-file-b",
		ProviderID:     "provider-b",
		Amount:         22,
		OperationState: chaintypes.ReconciliationSubmitted,
	}
	distA := types.DistributionRecord{
		DistributionID: "dist-file-a",
		AccrualID:      accrualA.AccrualID,
		PayoutRef:      "payout-a",
		Status:         chaintypes.ReconciliationSubmitted,
	}
	distB := types.DistributionRecord{
		DistributionID: "dist-file-b",
		AccrualID:      accrualB.AccrualID,
		PayoutRef:      "payout-b",
		Status:         chaintypes.ReconciliationConfirmed,
	}

	store.UpsertAccrual(accrualA)
	store.UpsertAccrual(accrualB)
	store.UpsertDistribution(distA)
	store.UpsertDistribution(distB)

	reopened, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("reopening file store returned unexpected error: %v", err)
	}

	accruals := reopened.ListAccruals()
	if len(accruals) != 2 {
		t.Fatalf("expected 2 accruals after reopen, got %d", len(accruals))
	}
	accrualByID := make(map[string]types.RewardAccrual, len(accruals))
	for _, record := range accruals {
		accrualByID[record.AccrualID] = record
	}
	if accrualByID[accrualA.AccrualID] != accrualA {
		t.Fatalf("expected accrual %q to round-trip through list", accrualA.AccrualID)
	}
	if accrualByID[accrualB.AccrualID] != accrualB {
		t.Fatalf("expected accrual %q to round-trip through list", accrualB.AccrualID)
	}

	distributions := reopened.ListDistributions()
	if len(distributions) != 2 {
		t.Fatalf("expected 2 distributions after reopen, got %d", len(distributions))
	}
	distributionByID := make(map[string]types.DistributionRecord, len(distributions))
	for _, record := range distributions {
		distributionByID[record.DistributionID] = record
	}
	if distributionByID[distA.DistributionID] != distA {
		t.Fatalf("expected distribution %q to round-trip through list", distA.DistributionID)
	}
	if distributionByID[distB.DistributionID] != distB {
		t.Fatalf("expected distribution %q to round-trip through list", distB.DistributionID)
	}
}

func TestNewFileStoreWhitespaceSeedInitializesEmptyState(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnrewards.json")
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		t.Fatalf("failed creating store dir: %v", err)
	}
	if err := os.WriteFile(storePath, []byte("  \n\t "), 0o644); err != nil {
		t.Fatalf("failed seeding whitespace state file: %v", err)
	}

	store, err := NewFileStore(storePath)
	if err != nil {
		t.Fatalf("NewFileStore with whitespace seed returned unexpected error: %v", err)
	}

	if got := len(store.ListAccruals()); got != 0 {
		t.Fatalf("expected empty accrual list for whitespace seed, got %d", got)
	}
	if got := len(store.ListDistributions()); got != 0 {
		t.Fatalf("expected empty distribution list for whitespace seed, got %d", got)
	}

	payload, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("failed reading persisted store file: %v", err)
	}
	content := string(payload)
	if !strings.Contains(content, "\"accruals\"") || !strings.Contains(content, "\"distributions\"") {
		t.Fatalf("expected initialized file to contain store keys, got: %s", content)
	}
}

func TestNewFileStoreInvalidJSON(t *testing.T) {
	t.Parallel()

	storePath := filepath.Join(t.TempDir(), "state", "vpnrewards.json")
	if err := os.MkdirAll(filepath.Dir(storePath), 0o755); err != nil {
		t.Fatalf("failed creating store dir: %v", err)
	}
	if err := os.WriteFile(storePath, []byte("{bad-json"), 0o644); err != nil {
		t.Fatalf("failed seeding invalid JSON file: %v", err)
	}

	_, err := NewFileStore(storePath)
	if err == nil {
		t.Fatal("expected NewFileStore to fail with invalid JSON state")
	}
}
