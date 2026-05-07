package keeper

import (
	"errors"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

type erroringKeeperStore struct {
	eligibilities map[string]types.ValidatorEligibility
	statusRecords map[string]types.ValidatorStatusRecord

	eligibilityReadErr  error
	statusReadErr       error
	eligibilityWriteErr error
	statusWriteErr      error
}

func newErroringKeeperStore() *erroringKeeperStore {
	return &erroringKeeperStore{
		eligibilities: make(map[string]types.ValidatorEligibility),
		statusRecords: make(map[string]types.ValidatorStatusRecord),
	}
}

func (s *erroringKeeperStore) UpsertEligibility(record types.ValidatorEligibility) {
	_ = s.UpsertEligibilityWithError(record)
}

func (s *erroringKeeperStore) UpsertEligibilityWithError(record types.ValidatorEligibility) error {
	if s.eligibilityWriteErr != nil {
		return s.eligibilityWriteErr
	}
	s.eligibilities[record.ValidatorID] = record
	return nil
}

func (s *erroringKeeperStore) GetEligibility(validatorID string) (types.ValidatorEligibility, bool) {
	record, ok := s.eligibilities[validatorID]
	return record, ok
}

func (s *erroringKeeperStore) ListEligibilities() []types.ValidatorEligibility {
	records, err := s.ListEligibilitiesWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *erroringKeeperStore) ListEligibilitiesWithError() ([]types.ValidatorEligibility, error) {
	if s.eligibilityReadErr != nil {
		return nil, s.eligibilityReadErr
	}
	records := make([]types.ValidatorEligibility, 0, len(s.eligibilities))
	for _, record := range s.eligibilities {
		records = append(records, record)
	}
	return records, nil
}

func (s *erroringKeeperStore) UpsertStatusRecord(record types.ValidatorStatusRecord) {
	_ = s.UpsertStatusRecordWithError(record)
}

func (s *erroringKeeperStore) UpsertStatusRecordWithError(record types.ValidatorStatusRecord) error {
	if s.statusWriteErr != nil {
		return s.statusWriteErr
	}
	s.statusRecords[record.StatusID] = record
	return nil
}

func (s *erroringKeeperStore) GetStatusRecord(statusID string) (types.ValidatorStatusRecord, bool) {
	record, ok := s.statusRecords[statusID]
	return record, ok
}

func (s *erroringKeeperStore) ListStatusRecords() []types.ValidatorStatusRecord {
	records, err := s.ListStatusRecordsWithError()
	if err != nil {
		return nil
	}
	return records
}

func (s *erroringKeeperStore) ListStatusRecordsWithError() ([]types.ValidatorStatusRecord, error) {
	if s.statusReadErr != nil {
		return nil, s.statusReadErr
	}
	records := make([]types.ValidatorStatusRecord, 0, len(s.statusRecords))
	for _, record := range s.statusRecords {
		records = append(records, record)
	}
	return records, nil
}

func testEligibility(id string) types.ValidatorEligibility {
	return types.ValidatorEligibility{
		ValidatorID:     id,
		OperatorAddress: "op-" + strings.ToLower(strings.TrimSpace(id)),
		Eligible:        true,
		Status:          chaintypes.ReconciliationPending,
	}
}

func testStatusRecord(id string, validatorID string) types.ValidatorStatusRecord {
	return types.ValidatorStatusRecord{
		StatusID:        id,
		ValidatorID:     validatorID,
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  10,
		Status:          chaintypes.ReconciliationSubmitted,
	}
}

func TestKeeperReadAwareStoreErrorsFailClosed(t *testing.T) {
	t.Parallel()

	readErr := errors.New("backend read failed")
	eligibilityStore := newErroringKeeperStore()
	eligibilityStore.eligibilityReadErr = readErr
	eligibilityKeeper := NewKeeperWithStore(eligibilityStore)

	if _, err := eligibilityKeeper.CreateEligibility(testEligibility("val-read")); err == nil || !strings.Contains(err.Error(), "load eligibilities") {
		t.Fatalf("expected eligibility create read error, got %v", err)
	}
	if _, ok := eligibilityKeeper.GetEligibility("val-read"); ok {
		t.Fatal("expected eligibility lookup to fail closed on read error")
	}
	if got := eligibilityKeeper.ListEligibilities(); got != nil {
		t.Fatalf("expected nil eligibility list on read error, got %+v", got)
	}
	if _, err := eligibilityKeeper.ListEligibilitiesWithError(); err == nil || !strings.Contains(err.Error(), "load eligibilities") {
		t.Fatalf("expected eligibility list read error, got %v", err)
	}

	missingEligibilityStore := newErroringKeeperStore()
	missingEligibilityStore.eligibilityReadErr = readErr
	missingEligibilityKeeper := NewKeeperWithStore(missingEligibilityStore)
	if _, err := missingEligibilityKeeper.CreateStatusRecord(testStatusRecord("status-eligibility-read", "val-read")); err == nil || !strings.Contains(err.Error(), "load eligibilities") {
		t.Fatalf("expected status create eligibility read error, got %v", err)
	}

	statusStore := newErroringKeeperStore()
	statusStore.eligibilities["val-status-read"] = testEligibility("val-status-read")
	statusStore.statusReadErr = readErr
	statusKeeper := NewKeeperWithStore(statusStore)

	if _, err := statusKeeper.CreateStatusRecord(testStatusRecord("status-read", "val-status-read")); err == nil || !strings.Contains(err.Error(), "load status records") {
		t.Fatalf("expected status create read error, got %v", err)
	}
	if _, ok := statusKeeper.GetStatusRecord("status-read"); ok {
		t.Fatal("expected status lookup to fail closed on read error")
	}
	if got := statusKeeper.ListStatusRecords(); got != nil {
		t.Fatalf("expected nil status list on read error, got %+v", got)
	}
	if _, err := statusKeeper.ListStatusRecordsWithError(); err == nil || !strings.Contains(err.Error(), "load status records") {
		t.Fatalf("expected status list read error, got %v", err)
	}
}

func TestKeeperWriteAwareStoreErrorsAreReturned(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("backend write failed")
	eligibilityStore := newErroringKeeperStore()
	eligibilityStore.eligibilityWriteErr = writeErr
	eligibilityKeeper := NewKeeperWithStore(eligibilityStore)
	eligibility := testEligibility("val-write")

	if err := eligibilityKeeper.UpsertEligibilityWithError(eligibility); err == nil || !strings.Contains(err.Error(), "persist eligibility") {
		t.Fatalf("expected eligibility upsert write error, got %v", err)
	}
	if _, ok := eligibilityStore.eligibilities[eligibility.ValidatorID]; ok {
		t.Fatal("expected failed eligibility upsert to leave store unchanged")
	}
	if _, err := eligibilityKeeper.CreateEligibility(eligibility); err == nil || !strings.Contains(err.Error(), "persist eligibility") {
		t.Fatalf("expected eligibility create write error, got %v", err)
	}

	statusStore := newErroringKeeperStore()
	statusStore.eligibilities["val-status-write"] = testEligibility("val-status-write")
	statusStore.statusWriteErr = writeErr
	statusKeeper := NewKeeperWithStore(statusStore)
	statusRecord := testStatusRecord("status-write", "val-status-write")

	if err := statusKeeper.UpsertStatusRecordWithError(statusRecord); err == nil || !strings.Contains(err.Error(), "persist status record") {
		t.Fatalf("expected status upsert write error, got %v", err)
	}
	if _, ok := statusStore.statusRecords[statusRecord.StatusID]; ok {
		t.Fatal("expected failed status upsert to leave store unchanged")
	}
	if _, err := statusKeeper.CreateStatusRecord(statusRecord); err == nil || !strings.Contains(err.Error(), "persist status record") {
		t.Fatalf("expected status create write error, got %v", err)
	}
}

func TestKeeperCanonicalReplayWriteErrorsAreReturned(t *testing.T) {
	t.Parallel()

	writeErr := errors.New("backend canonical write failed")
	eligibilityStore := newErroringKeeperStore()
	legacyEligibility := testEligibility("VAL-CANON-WRITE")
	legacyEligibility.OperatorAddress = "op-val-canon-write"
	eligibilityStore.eligibilities[legacyEligibility.ValidatorID] = legacyEligibility
	eligibilityStore.eligibilityWriteErr = writeErr
	eligibilityKeeper := NewKeeperWithStore(eligibilityStore)

	if _, err := eligibilityKeeper.CreateEligibility(testEligibility("val-canon-write")); err == nil || !strings.Contains(err.Error(), "persist eligibility") {
		t.Fatalf("expected canonical eligibility replay write error, got %v", err)
	}

	statusStore := newErroringKeeperStore()
	statusStore.eligibilities["val-canon-status-write"] = testEligibility("val-canon-status-write")
	legacyStatus := testStatusRecord("STATUS-CANON-WRITE", "val-canon-status-write")
	statusStore.statusRecords[legacyStatus.StatusID] = legacyStatus
	statusStore.statusWriteErr = writeErr
	statusKeeper := NewKeeperWithStore(statusStore)

	if _, err := statusKeeper.CreateStatusRecord(testStatusRecord("status-canon-write", "val-canon-status-write")); err == nil || !strings.Contains(err.Error(), "persist status record") {
		t.Fatalf("expected canonical status replay write error, got %v", err)
	}
}

func TestKeeperCanonicalReplayConflictsFromListFallback(t *testing.T) {
	t.Parallel()

	eligibilityStore := newErroringKeeperStore()
	legacyEligibility := testEligibility("VAL-LIST-CONFLICT")
	legacyEligibility.OperatorAddress = "op-val-list-conflict"
	eligibilityStore.eligibilities[legacyEligibility.ValidatorID] = legacyEligibility
	eligibilityKeeper := NewKeeperWithStore(eligibilityStore)

	conflictingEligibility := testEligibility("val-list-conflict")
	conflictingEligibility.Eligible = false
	if _, err := eligibilityKeeper.CreateEligibility(conflictingEligibility); err == nil || !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected canonical eligibility list conflict, got %v", err)
	}

	statusStore := newErroringKeeperStore()
	statusStore.eligibilities["val-list-status-conflict"] = testEligibility("val-list-status-conflict")
	legacyStatus := testStatusRecord("STATUS-LIST-CONFLICT", "val-list-status-conflict")
	statusStore.statusRecords[legacyStatus.StatusID] = legacyStatus
	statusKeeper := NewKeeperWithStore(statusStore)

	conflictingStatus := testStatusRecord("status-list-conflict", "val-list-status-conflict")
	conflictingStatus.EvidenceHeight++
	if _, err := statusKeeper.CreateStatusRecord(conflictingStatus); err == nil || !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected canonical status list conflict, got %v", err)
	}
}

func TestKeeperCreateStatusRejectsMismatchedEligibilityRecord(t *testing.T) {
	t.Parallel()

	store := newErroringKeeperStore()
	mismatchedEligibility := testEligibility("val-other")
	store.eligibilities["val-wanted"] = mismatchedEligibility
	k := NewKeeperWithStore(store)

	_, err := k.CreateStatusRecord(testStatusRecord("status-mismatch", "val-wanted"))
	if err == nil {
		t.Fatal("expected mismatched eligibility error")
	}
	if !strings.Contains(err.Error(), `does not match eligibility "val-other"`) {
		t.Fatalf("expected mismatch error, got %v", err)
	}
}

func TestFileStoreRollbackOnPersistFailure(t *testing.T) {
	t.Parallel()

	store := &FileStore{
		path:          t.TempDir(),
		eligibilities: make(map[string]types.ValidatorEligibility),
		statusRecords: make(map[string]types.ValidatorStatusRecord),
	}

	existingEligibility := testEligibility("val-existing")
	store.eligibilities[existingEligibility.ValidatorID] = existingEligibility
	replacementEligibility := existingEligibility
	replacementEligibility.PolicyReason = "updated"
	if err := store.UpsertEligibilityWithError(replacementEligibility); err == nil {
		t.Fatal("expected eligibility persist failure for directory path")
	}
	if got := store.eligibilities[existingEligibility.ValidatorID]; got != existingEligibility {
		t.Fatalf("expected existing eligibility rollback, got %+v", got)
	}

	newEligibility := testEligibility("val-new")
	if err := store.UpsertEligibilityWithError(newEligibility); err == nil {
		t.Fatal("expected new eligibility persist failure for directory path")
	}
	if _, ok := store.eligibilities[newEligibility.ValidatorID]; ok {
		t.Fatal("expected failed new eligibility insert to be removed")
	}

	existingStatus := testStatusRecord("status-existing", "val-existing")
	store.statusRecords[existingStatus.StatusID] = existingStatus
	replacementStatus := existingStatus
	replacementStatus.RecordedAtUnix = 20
	if err := store.UpsertStatusRecordWithError(replacementStatus); err == nil {
		t.Fatal("expected status persist failure for directory path")
	}
	if got := store.statusRecords[existingStatus.StatusID]; got != existingStatus {
		t.Fatalf("expected existing status rollback, got %+v", got)
	}

	newStatus := testStatusRecord("status-new", "val-existing")
	if err := store.UpsertStatusRecordWithError(newStatus); err == nil {
		t.Fatal("expected new status persist failure for directory path")
	}
	if _, ok := store.statusRecords[newStatus.StatusID]; ok {
		t.Fatal("expected failed new status insert to be removed")
	}

	if _, err := NewFileStore(""); err == nil {
		t.Fatal("expected empty file store path to be rejected")
	}
}

func TestKVStoreRejectsEmptyOversizedAndNonCanonicalInputs(t *testing.T) {
	t.Parallel()

	nilBackedStore := NewKVStore(nil)
	nilBackedStore.UpsertEligibility(testEligibility("val-nil-backend"))
	if _, ok := nilBackedStore.GetEligibility("val-nil-backend"); !ok {
		t.Fatal("expected nil backend to fall back to map store")
	}

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	store.UpsertEligibility(types.ValidatorEligibility{ValidatorID: "val-invalid-upsert"})
	if _, ok := store.GetEligibility("val-invalid-upsert"); ok {
		t.Fatal("expected invalid eligibility upsert to be ignored")
	}
	if _, ok := store.GetEligibility("   "); ok {
		t.Fatal("expected empty eligibility lookup to fail")
	}
	if _, ok := store.GetEligibility("val-missing"); ok {
		t.Fatal("expected missing eligibility lookup to fail")
	}

	backend.Set(eligibilityKey("val-empty"), nil)
	if _, ok := store.GetEligibility("val-empty"); ok {
		t.Fatal("expected empty eligibility payload to fail")
	}
	backend.Set(eligibilityKey("val-huge"), make([]byte, maxKVPayloadBytes+1))
	if _, ok := store.GetEligibility("val-huge"); ok {
		t.Fatal("expected oversized eligibility payload to fail")
	}
	backend.Set(eligibilityKey("val-invalid"), []byte(`{"ValidatorID":"val-invalid"}`))
	if _, ok := store.GetEligibility("val-invalid"); ok {
		t.Fatal("expected invalid eligibility payload to fail")
	}

	store.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-invalid-upsert",
		ValidatorID:     "val-invalid-upsert",
		LifecycleStatus: "offline",
	})
	if _, ok := store.GetStatusRecord("status-invalid-upsert"); ok {
		t.Fatal("expected invalid status upsert to be ignored")
	}
	if _, ok := store.GetStatusRecord("   "); ok {
		t.Fatal("expected empty status lookup to fail")
	}
	if _, ok := store.GetStatusRecord("status-missing"); ok {
		t.Fatal("expected missing status lookup to fail")
	}

	backend.Set(statusKey("status-empty"), nil)
	if _, ok := store.GetStatusRecord("status-empty"); ok {
		t.Fatal("expected empty status payload to fail")
	}
	backend.Set(statusKey("status-huge"), make([]byte, maxKVPayloadBytes+1))
	if _, ok := store.GetStatusRecord("status-huge"); ok {
		t.Fatal("expected oversized status payload to fail")
	}
	backend.Set(statusKey("status-invalid"), []byte(`{"StatusID":"status-invalid","ValidatorID":"val-invalid","LifecycleStatus":"offline"}`))
	if _, ok := store.GetStatusRecord("status-invalid"); ok {
		t.Fatal("expected invalid status payload to fail")
	}

	for _, tc := range []struct {
		name string
		key  []byte
	}{
		{name: "missing prefix", key: []byte("wrong/val-1")},
		{name: "empty id", key: []byte(eligibilityPrefix + "   ")},
		{name: "non-canonical id", key: []byte(eligibilityPrefix + "VAL-1")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parsePrefixedID(tc.key, eligibilityPrefix); err == nil {
				t.Fatal("expected prefixed id parse error")
			}
		})
	}
}

func TestKeeperCompareRecordTieBreakers(t *testing.T) {
	t.Parallel()

	if compareEligibilityRecord(testEligibility("val-a"), testEligibility("val-b")) >= 0 {
		t.Fatal("expected eligibility validator id to sort first")
	}
	operatorA := testEligibility("val-same")
	operatorA.OperatorAddress = "op-a"
	operatorB := operatorA
	operatorB.OperatorAddress = "op-b"
	if compareEligibilityRecord(operatorA, operatorB) >= 0 {
		t.Fatal("expected eligibility operator address to break ties")
	}
	ineligible := testEligibility("val-same")
	ineligible.Eligible = false
	eligible := testEligibility("val-same")
	if compareEligibilityRecord(ineligible, eligible) >= 0 {
		t.Fatal("expected ineligible record to sort before eligible record")
	}
	if compareEligibilityRecord(eligible, ineligible) <= 0 {
		t.Fatal("expected eligible record to sort after ineligible record")
	}
	policyA := testEligibility("val-same")
	policyA.PolicyReason = "a"
	policyB := policyA
	policyB.PolicyReason = "b"
	if compareEligibilityRecord(policyA, policyB) >= 0 {
		t.Fatal("expected policy reason to break eligibility ties")
	}
	updatedEarly := testEligibility("val-same")
	updatedEarly.UpdatedAtUnix = 1
	updatedLate := updatedEarly
	updatedLate.UpdatedAtUnix = 2
	if compareEligibilityRecord(updatedEarly, updatedLate) >= 0 {
		t.Fatal("expected earlier eligibility update time to sort first")
	}
	if compareEligibilityRecord(updatedLate, updatedEarly) <= 0 {
		t.Fatal("expected later eligibility update time to sort after earlier time")
	}

	if compareStatusRecord(testStatusRecord("status-a", "val-1"), testStatusRecord("status-b", "val-1")) >= 0 {
		t.Fatal("expected status id to sort first")
	}
	validatorA := testStatusRecord("status-same", "val-a")
	validatorB := validatorA
	validatorB.ValidatorID = "val-b"
	if compareStatusRecord(validatorA, validatorB) >= 0 {
		t.Fatal("expected status validator id to break ties")
	}
	consensusA := testStatusRecord("status-same", "val-same")
	consensusA.ConsensusAddress = "cons-a"
	consensusB := consensusA
	consensusB.ConsensusAddress = "cons-b"
	if compareStatusRecord(consensusA, consensusB) >= 0 {
		t.Fatal("expected consensus address to break status ties")
	}
	lifecycleA := testStatusRecord("status-same", "val-same")
	lifecycleA.LifecycleStatus = types.ValidatorLifecycleActive
	lifecycleB := lifecycleA
	lifecycleB.LifecycleStatus = types.ValidatorLifecycleJailed
	if compareStatusRecord(lifecycleA, lifecycleB) >= 0 {
		t.Fatal("expected lifecycle status to break ties")
	}
	heightLow := testStatusRecord("status-same", "val-same")
	heightLow.EvidenceHeight = 1
	heightHigh := heightLow
	heightHigh.EvidenceHeight = 2
	if compareStatusRecord(heightLow, heightHigh) >= 0 {
		t.Fatal("expected lower evidence height to sort first")
	}
	if compareStatusRecord(heightHigh, heightLow) <= 0 {
		t.Fatal("expected higher evidence height to sort after lower height")
	}
	evidenceA := testStatusRecord("status-same", "val-same")
	evidenceA.EvidenceRef = "obj://a"
	evidenceB := evidenceA
	evidenceB.EvidenceRef = "obj://b"
	if compareStatusRecord(evidenceA, evidenceB) >= 0 {
		t.Fatal("expected evidence ref to break status ties")
	}
	recordedEarly := testStatusRecord("status-same", "val-same")
	recordedEarly.RecordedAtUnix = 1
	recordedLate := recordedEarly
	recordedLate.RecordedAtUnix = 2
	if compareStatusRecord(recordedEarly, recordedLate) >= 0 {
		t.Fatal("expected earlier recorded time to sort first")
	}
	if compareStatusRecord(recordedLate, recordedEarly) <= 0 {
		t.Fatal("expected later recorded time to sort after earlier time")
	}
}
