package keeper

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

type trackingStore struct {
	eligibilities map[string]types.ValidatorEligibility
	statusRecords map[string]types.ValidatorStatusRecord

	upsertEligibilityCalls int
	getEligibilityCalls    int
	upsertStatusCalls      int
	getStatusCalls         int
	listEligibilityCalls   int
	listStatusCalls        int
}

func newTrackingStore() *trackingStore {
	return &trackingStore{
		eligibilities: make(map[string]types.ValidatorEligibility),
		statusRecords: make(map[string]types.ValidatorStatusRecord),
	}
}

func (s *trackingStore) UpsertEligibility(record types.ValidatorEligibility) {
	s.upsertEligibilityCalls++
	s.eligibilities[record.ValidatorID] = record
}

func (s *trackingStore) GetEligibility(validatorID string) (types.ValidatorEligibility, bool) {
	s.getEligibilityCalls++
	record, ok := s.eligibilities[validatorID]
	return record, ok
}

func (s *trackingStore) ListEligibilities() []types.ValidatorEligibility {
	s.listEligibilityCalls++
	ids := make([]string, 0, len(s.eligibilities))
	for id := range s.eligibilities {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.ValidatorEligibility, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.eligibilities[id])
	}
	return records
}

func (s *trackingStore) UpsertStatusRecord(record types.ValidatorStatusRecord) {
	s.upsertStatusCalls++
	s.statusRecords[record.StatusID] = record
}

func (s *trackingStore) GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool) {
	s.getStatusCalls++
	record, ok := s.statusRecords[statusID]
	return record, ok
}

func (s *trackingStore) ListStatusRecords() []types.ValidatorStatusRecord {
	s.listStatusCalls++
	ids := make([]string, 0, len(s.statusRecords))
	for id := range s.statusRecords {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	records := make([]types.ValidatorStatusRecord, 0, len(ids))
	for _, id := range ids {
		records = append(records, s.statusRecords[id])
	}
	return records
}

func TestNewKeeperWithStoreNilFallsBackToInMemory(t *testing.T) {
	t.Parallel()

	k := NewKeeperWithStore(nil)
	eligibility := types.ValidatorEligibility{
		ValidatorID:     "val-fallback",
		OperatorAddress: "tdpnvaloper1fallback",
		Eligible:        true,
	}
	k.UpsertEligibility(eligibility)

	got, ok := k.GetEligibility(eligibility.ValidatorID)
	if !ok {
		t.Fatal("expected eligibility with nil-store fallback")
	}
	if got.ValidatorID != eligibility.ValidatorID {
		t.Fatalf("expected validator id %q, got %q", eligibility.ValidatorID, got.ValidatorID)
	}
}

func TestKeeperDelegatesUpsertAndGetToCustomStore(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	eligibility := types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1xyz",
		Eligible:        true,
	}
	k.UpsertEligibility(eligibility)
	if store.upsertEligibilityCalls != 1 {
		t.Fatalf("expected 1 eligibility upsert call, got %d", store.upsertEligibilityCalls)
	}

	gotEligibility, ok := k.GetEligibility(eligibility.ValidatorID)
	if !ok {
		t.Fatal("expected eligibility from custom store")
	}
	if gotEligibility.OperatorAddress != eligibility.OperatorAddress {
		t.Fatalf("expected operator %q, got %q", eligibility.OperatorAddress, gotEligibility.OperatorAddress)
	}
	if store.getEligibilityCalls != 1 {
		t.Fatalf("expected 1 eligibility get call, got %d", store.getEligibilityCalls)
	}

	statusRecord := types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  10,
	}
	k.UpsertStatusRecord(statusRecord)
	if store.upsertStatusCalls != 1 {
		t.Fatalf("expected 1 status upsert call, got %d", store.upsertStatusCalls)
	}

	gotStatus, ok := k.GetStatusRecord(statusRecord.StatusID)
	if !ok {
		t.Fatal("expected status from custom store")
	}
	if gotStatus.LifecycleStatus != statusRecord.LifecycleStatus {
		t.Fatalf("expected lifecycle %q, got %q", statusRecord.LifecycleStatus, gotStatus.LifecycleStatus)
	}
	if store.getStatusCalls != 1 {
		t.Fatalf("expected 1 status get call, got %d", store.getStatusCalls)
	}
}

func TestKeeperCreateAndRecordUseCustomStore(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	createdEligibility, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	})
	if err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}
	if createdEligibility.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, createdEligibility.Status)
	}
	if store.upsertEligibilityCalls == 0 || store.getEligibilityCalls == 0 {
		t.Fatalf(
			"expected create path to touch custom eligibility store, got upsert=%d get=%d",
			store.upsertEligibilityCalls,
			store.getEligibilityCalls,
		)
	}

	createdStatus, err := k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  100,
	})
	if err != nil {
		t.Fatalf("CreateStatusRecord returned unexpected error: %v", err)
	}
	if createdStatus.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationSubmitted, createdStatus.Status)
	}
	if store.upsertStatusCalls == 0 || store.getStatusCalls == 0 {
		t.Fatalf(
			"expected status path to touch custom status store, got upsert=%d get=%d",
			store.upsertStatusCalls,
			store.getStatusCalls,
		)
	}
}

func TestNewFileStorePersistsAcrossReopen(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vpnvalidator-store.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	eligibility := types.ValidatorEligibility{
		ValidatorID:     "val-persist",
		OperatorAddress: "tdpnvaloper1persist",
		Eligible:        true,
		Status:          chaintypes.ReconciliationConfirmed,
	}
	store.UpsertEligibility(eligibility)

	statusRecord := types.ValidatorStatusRecord{
		StatusID:        "status-persist",
		ValidatorID:     "val-persist",
		LifecycleStatus: types.ValidatorLifecycleJailed,
		EvidenceHeight:  42,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertStatusRecord(statusRecord)

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen NewFileStore returned unexpected error: %v", err)
	}

	gotEligibility, ok := reopened.GetEligibility(eligibility.ValidatorID)
	if !ok {
		t.Fatal("expected persisted eligibility after reopen")
	}
	if gotEligibility != eligibility {
		t.Fatalf("expected persisted eligibility %+v, got %+v", eligibility, gotEligibility)
	}

	gotStatus, ok := reopened.GetStatusRecord(statusRecord.StatusID)
	if !ok {
		t.Fatal("expected persisted status after reopen")
	}
	if gotStatus != statusRecord {
		t.Fatalf("expected persisted status %+v, got %+v", statusRecord, gotStatus)
	}
}

func TestNewFileStoreInvalidPath(t *testing.T) {
	t.Parallel()

	_, err := NewFileStore(t.TempDir())
	if err == nil {
		t.Fatal("expected NewFileStore to fail for directory path")
	}
}

func TestFileStoreListOrderingAndGetPaths(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vpnvalidator-store-ordering.json")
	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	validatorIDs := []string{"val-2", "val-10", "val-1"}
	for _, id := range validatorIDs {
		store.UpsertEligibility(types.ValidatorEligibility{
			ValidatorID:     id,
			OperatorAddress: "tdpnvaloper1ordering",
			Eligible:        true,
			Status:          chaintypes.ReconciliationPending,
		})
	}
	statusIDs := []string{"status-2", "status-10", "status-1"}
	for _, id := range statusIDs {
		store.UpsertStatusRecord(types.ValidatorStatusRecord{
			StatusID:        id,
			ValidatorID:     "val-1",
			LifecycleStatus: types.ValidatorLifecycleActive,
			EvidenceHeight:  10,
			Status:          chaintypes.ReconciliationSubmitted,
		})
	}

	gotEligibilities := store.ListEligibilities()
	if len(gotEligibilities) != len(validatorIDs) {
		t.Fatalf("expected %d eligibilities, got %d", len(validatorIDs), len(gotEligibilities))
	}
	expectedValidatorIDs := append([]string(nil), validatorIDs...)
	sort.Strings(expectedValidatorIDs)
	for i, expectedID := range expectedValidatorIDs {
		if gotEligibilities[i].ValidatorID != expectedID {
			t.Fatalf("expected eligibility index %d id %q, got %q", i, expectedID, gotEligibilities[i].ValidatorID)
		}
		if _, ok := store.GetEligibility(expectedID); !ok {
			t.Fatalf("expected GetEligibility(%q) to succeed", expectedID)
		}
	}

	gotStatusRecords := store.ListStatusRecords()
	if len(gotStatusRecords) != len(statusIDs) {
		t.Fatalf("expected %d status records, got %d", len(statusIDs), len(gotStatusRecords))
	}
	expectedStatusIDs := append([]string(nil), statusIDs...)
	sort.Strings(expectedStatusIDs)
	for i, expectedID := range expectedStatusIDs {
		if gotStatusRecords[i].StatusID != expectedID {
			t.Fatalf("expected status index %d id %q, got %q", i, expectedID, gotStatusRecords[i].StatusID)
		}
		if _, ok := store.GetStatusRecord(expectedID); !ok {
			t.Fatalf("expected GetStatusRecord(%q) to succeed", expectedID)
		}
	}
}

func TestFileStoreWhitespaceSnapshotLoadsAndPersists(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "vpnvalidator-store-whitespace.json")
	if err := os.WriteFile(path, []byte("  \n\t "), 0o600); err != nil {
		t.Fatalf("write whitespace snapshot: %v", err)
	}

	store, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("NewFileStore with whitespace snapshot returned unexpected error: %v", err)
	}
	if got := store.ListEligibilities(); len(got) != 0 {
		t.Fatalf("expected no eligibilities from whitespace snapshot, got %d", len(got))
	}
	if got := store.ListStatusRecords(); len(got) != 0 {
		t.Fatalf("expected no status records from whitespace snapshot, got %d", len(got))
	}

	store.UpsertEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-whitespace",
		OperatorAddress: "tdpnvaloper1whitespace",
		Eligible:        true,
		Status:          chaintypes.ReconciliationConfirmed,
	})

	reopened, err := NewFileStore(path)
	if err != nil {
		t.Fatalf("reopen NewFileStore returned unexpected error: %v", err)
	}
	got, ok := reopened.GetEligibility("val-whitespace")
	if !ok {
		t.Fatal("expected persisted eligibility after whitespace bootstrap")
	}
	if got.ValidatorID != "val-whitespace" || got.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("unexpected persisted eligibility: %+v", got)
	}
}
