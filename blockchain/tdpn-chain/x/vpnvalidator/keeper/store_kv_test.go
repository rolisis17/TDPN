package keeper

import (
	"encoding/json"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestKVStoreUpsertGetList(t *testing.T) {
	t.Parallel()

	store := NewKVStore(kvtypes.NewMapStore())

	eligibility := types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
		Status:          chaintypes.ReconciliationPending,
	}
	store.UpsertEligibility(eligibility)

	gotEligibility, ok := store.GetEligibility(eligibility.ValidatorID)
	if !ok {
		t.Fatal("expected eligibility to exist")
	}
	if gotEligibility != eligibility {
		t.Fatalf("expected eligibility %+v, got %+v", eligibility, gotEligibility)
	}

	statusRecord := types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  10,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertStatusRecord(statusRecord)

	gotStatus, ok := store.GetStatusRecord(statusRecord.StatusID)
	if !ok {
		t.Fatal("expected status record to exist")
	}
	if gotStatus != statusRecord {
		t.Fatalf("expected status record %+v, got %+v", statusRecord, gotStatus)
	}

	eligibilities := store.ListEligibilities()
	if len(eligibilities) != 1 {
		t.Fatalf("expected 1 eligibility, got %d", len(eligibilities))
	}
	if eligibilities[0] != eligibility {
		t.Fatalf("expected listed eligibility %+v, got %+v", eligibility, eligibilities[0])
	}

	statuses := store.ListStatusRecords()
	if len(statuses) != 1 {
		t.Fatalf("expected 1 status, got %d", len(statuses))
	}
	if statuses[0] != statusRecord {
		t.Fatalf("expected listed status %+v, got %+v", statusRecord, statuses[0])
	}
}

func TestKVStoreMalformedPayloadsFailClosed(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	validEligibility := types.ValidatorEligibility{
		ValidatorID:     "val-ok",
		OperatorAddress: "tdpnvaloper1ok",
		Eligible:        false,
		Status:          chaintypes.ReconciliationPending,
	}
	store.UpsertEligibility(validEligibility)
	backend.Set(eligibilityKey("val-bad"), []byte("{"))

	validStatusRecord := types.ValidatorStatusRecord{
		StatusID:        "status-ok",
		ValidatorID:     "val-ok",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  10,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertStatusRecord(validStatusRecord)
	backend.Set(statusKey("status-bad"), []byte("{"))

	if _, ok := store.GetEligibility("val-bad"); ok {
		t.Fatal("expected malformed eligibility payload lookup to fail")
	}
	gotEligibility, ok := store.GetEligibility(validEligibility.ValidatorID)
	if !ok {
		t.Fatal("expected valid eligibility lookup to succeed")
	}
	if gotEligibility != validEligibility {
		t.Fatalf("expected valid eligibility %+v, got %+v", validEligibility, gotEligibility)
	}

	eligibilities := store.ListEligibilities()
	if len(eligibilities) != 0 {
		t.Fatalf("expected eligibility listing to fail closed, got %d records", len(eligibilities))
	}
	if _, err := store.ListEligibilitiesWithError(); err == nil {
		t.Fatal("expected malformed eligibility payload to return list decode error")
	}

	if _, ok := store.GetStatusRecord("status-bad"); ok {
		t.Fatal("expected malformed status payload lookup to fail")
	}
	gotStatus, ok := store.GetStatusRecord(validStatusRecord.StatusID)
	if !ok {
		t.Fatal("expected valid status lookup to succeed")
	}
	if gotStatus != validStatusRecord {
		t.Fatalf("expected valid status %+v, got %+v", validStatusRecord, gotStatus)
	}

	statusRecords := store.ListStatusRecords()
	if len(statusRecords) != 0 {
		t.Fatalf("expected status listing to fail closed, got %d records", len(statusRecords))
	}
	if _, err := store.ListStatusRecordsWithError(); err == nil {
		t.Fatal("expected malformed status payload to return list decode error")
	}
}

func TestKVStoreRejectsKeyPayloadIdentityMismatch(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	mismatchedEligibility := types.ValidatorEligibility{
		ValidatorID:     "val-payload",
		OperatorAddress: "tdpnvaloper1identity",
		Eligible:        true,
		Status:          chaintypes.ReconciliationPending,
	}
	eligibilityPayload, err := json.Marshal(mismatchedEligibility)
	if err != nil {
		t.Fatalf("marshal mismatched eligibility: %v", err)
	}
	backend.Set(eligibilityKey("val-key"), eligibilityPayload)

	if _, ok := store.GetEligibility("val-key"); ok {
		t.Fatal("expected eligibility key/payload mismatch to be rejected")
	}
	if _, err := store.ListEligibilitiesWithError(); err == nil {
		t.Fatal("expected eligibility list key/payload mismatch to return decode error")
	}

	mismatchedStatus := types.ValidatorStatusRecord{
		StatusID:        "status-payload",
		ValidatorID:     "val-key",
		LifecycleStatus: types.ValidatorLifecycleJailed,
		EvidenceHeight:  9,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	statusPayload, err := json.Marshal(mismatchedStatus)
	if err != nil {
		t.Fatalf("marshal mismatched status: %v", err)
	}
	backend.Set(statusKey("status-key"), statusPayload)

	if _, ok := store.GetStatusRecord("status-key"); ok {
		t.Fatal("expected status key/payload mismatch to be rejected")
	}
	if _, err := store.ListStatusRecordsWithError(); err == nil {
		t.Fatal("expected status list key/payload mismatch to return decode error")
	}
}
