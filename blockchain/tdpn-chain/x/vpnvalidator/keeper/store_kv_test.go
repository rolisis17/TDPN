package keeper

import (
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

func TestKVStoreListOrderingAndSkipsMalformedEntries(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	store.UpsertEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-2",
		OperatorAddress: "tdpnvaloper1kv",
		Eligible:        true,
		Status:          chaintypes.ReconciliationPending,
	})
	store.UpsertEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1kv",
		Eligible:        false,
		Status:          chaintypes.ReconciliationPending,
	})
	backend.Set([]byte("eligibility/bad-json"), []byte("{not-valid-json"))

	store.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-2",
		ValidatorID:     "val-2",
		LifecycleStatus: types.ValidatorLifecycleJailed,
		EvidenceHeight:  20,
		Status:          chaintypes.ReconciliationSubmitted,
	})
	store.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  10,
		Status:          chaintypes.ReconciliationSubmitted,
	})
	backend.Set([]byte("status/bad-json"), []byte("{not-valid-json"))

	eligibilities := store.ListEligibilities()
	if len(eligibilities) != 2 {
		t.Fatalf("expected 2 valid eligibilities, got %d", len(eligibilities))
	}
	if eligibilities[0].ValidatorID != "val-1" || eligibilities[1].ValidatorID != "val-2" {
		t.Fatalf("expected eligibility list ordered by key, got %+v", eligibilities)
	}
	if _, ok := store.GetEligibility("bad-json"); ok {
		t.Fatal("expected malformed eligibility payload to be rejected by GetEligibility")
	}

	statusRecords := store.ListStatusRecords()
	if len(statusRecords) != 2 {
		t.Fatalf("expected 2 valid status records, got %d", len(statusRecords))
	}
	if statusRecords[0].StatusID != "status-1" || statusRecords[1].StatusID != "status-2" {
		t.Fatalf("expected status list ordered by key, got %+v", statusRecords)
	}
	if _, ok := store.GetStatusRecord("bad-json"); ok {
		t.Fatal("expected malformed status payload to be rejected by GetStatusRecord")
	}
}
