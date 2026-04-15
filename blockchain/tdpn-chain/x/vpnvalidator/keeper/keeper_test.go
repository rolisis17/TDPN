package keeper

import (
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestKeeperEligibilityUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetEligibility("missing"); ok {
		t.Fatal("expected missing eligibility lookup to return ok=false")
	}

	initial := types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}
	k.UpsertEligibility(initial)

	got, ok := k.GetEligibility(initial.ValidatorID)
	if !ok {
		t.Fatal("expected inserted eligibility to be found")
	}
	if got.Eligible != initial.Eligible {
		t.Fatalf("expected eligible=%v, got %v", initial.Eligible, got.Eligible)
	}

	updated := initial
	updated.Eligible = false
	k.UpsertEligibility(updated)

	got, ok = k.GetEligibility(initial.ValidatorID)
	if !ok {
		t.Fatal("expected updated eligibility to be found")
	}
	if got.Eligible != updated.Eligible {
		t.Fatalf("expected updated eligible=%v, got %v", updated.Eligible, got.Eligible)
	}
}

func TestKeeperStatusUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetStatusRecord("missing"); ok {
		t.Fatal("expected missing status lookup to return ok=false")
	}

	initial := types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  10,
	}
	k.UpsertStatusRecord(initial)

	got, ok := k.GetStatusRecord(initial.StatusID)
	if !ok {
		t.Fatal("expected inserted status to be found")
	}
	if got.LifecycleStatus != initial.LifecycleStatus {
		t.Fatalf("expected lifecycle %q, got %q", initial.LifecycleStatus, got.LifecycleStatus)
	}

	updated := initial
	updated.LifecycleStatus = types.ValidatorLifecycleJailed
	k.UpsertStatusRecord(updated)

	got, ok = k.GetStatusRecord(initial.StatusID)
	if !ok {
		t.Fatal("expected updated status to be found")
	}
	if got.LifecycleStatus != updated.LifecycleStatus {
		t.Fatalf("expected updated lifecycle %q, got %q", updated.LifecycleStatus, got.LifecycleStatus)
	}
}

func TestKeeperCreateEligibilityDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	input := types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}

	created, err := k.CreateEligibility(input)
	if err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, created.Status)
	}

	idempotent, err := k.CreateEligibility(input)
	if err != nil {
		t.Fatalf("CreateEligibility idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent result to match created record, got %+v vs %+v", idempotent, created)
	}

	explicitPending := input
	explicitPending.Status = chaintypes.ReconciliationPending
	idempotent, err = k.CreateEligibility(explicitPending)
	if err != nil {
		t.Fatalf("CreateEligibility explicit pending call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected explicit pending result to match created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperCreateEligibilityConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	initial := types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}
	if _, err := k.CreateEligibility(initial); err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.Eligible = false
	_, err := k.CreateEligibility(conflict)
	if err == nil {
		t.Fatal("expected conflict error for eligibility with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperCreateEligibilityValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID: "val-1",
	})
	if err == nil {
		t.Fatal("expected validation error for missing operator address")
	}
}

func TestKeeperCreateStatusDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}); err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}

	input := types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  100,
	}

	created, err := k.CreateStatusRecord(input)
	if err != nil {
		t.Fatalf("CreateStatusRecord returned unexpected error: %v", err)
	}
	if created.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationSubmitted, created.Status)
	}

	idempotent, err := k.CreateStatusRecord(input)
	if err != nil {
		t.Fatalf("CreateStatusRecord idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent result to match created record, got %+v vs %+v", idempotent, created)
	}

	explicitSubmitted := input
	explicitSubmitted.Status = chaintypes.ReconciliationSubmitted
	idempotent, err = k.CreateStatusRecord(explicitSubmitted)
	if err != nil {
		t.Fatalf("CreateStatusRecord explicit submitted call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected explicit submitted result to match created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperCreateStatusConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}); err != nil {
		t.Fatalf("CreateEligibility returned unexpected error: %v", err)
	}

	initial := types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  100,
	}
	if _, err := k.CreateStatusRecord(initial); err != nil {
		t.Fatalf("CreateStatusRecord returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.EvidenceHeight = 101
	_, err := k.CreateStatusRecord(conflict)
	if err == nil {
		t.Fatal("expected conflict error for status with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperCreateStatusValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:    "status-1",
		ValidatorID: "val-1",
	})
	if err == nil {
		t.Fatal("expected validation error for missing lifecycle status")
	}
}

func TestKeeperCreateStatusEligibilityNotFound(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	_, err := k.CreateStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "missing",
		LifecycleStatus: types.ValidatorLifecycleActive,
	})
	if err == nil {
		t.Fatal("expected eligibility not found error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found message, got: %v", err)
	}
}

func TestKeeperListEligibilitiesDeterministicByValidatorID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertEligibility(types.ValidatorEligibility{ValidatorID: "val-3", OperatorAddress: "op-3", Eligible: true})
	k.UpsertEligibility(types.ValidatorEligibility{ValidatorID: "val-1", OperatorAddress: "op-1", Eligible: true})
	k.UpsertEligibility(types.ValidatorEligibility{ValidatorID: "val-2", OperatorAddress: "op-2", Eligible: true})

	list := k.ListEligibilities()
	if len(list) != 3 {
		t.Fatalf("expected 3 eligibilities, got %d", len(list))
	}
	if list[0].ValidatorID != "val-1" || list[1].ValidatorID != "val-2" || list[2].ValidatorID != "val-3" {
		t.Fatalf("expected sorted validator ids [val-1 val-2 val-3], got [%s %s %s]",
			list[0].ValidatorID, list[1].ValidatorID, list[2].ValidatorID)
	}
}

func TestKeeperListStatusRecordsDeterministicByStatusID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertStatusRecord(types.ValidatorStatusRecord{StatusID: "status-3", ValidatorID: "val-1", LifecycleStatus: types.ValidatorLifecycleActive})
	k.UpsertStatusRecord(types.ValidatorStatusRecord{StatusID: "status-1", ValidatorID: "val-1", LifecycleStatus: types.ValidatorLifecycleActive})
	k.UpsertStatusRecord(types.ValidatorStatusRecord{StatusID: "status-2", ValidatorID: "val-1", LifecycleStatus: types.ValidatorLifecycleActive})

	list := k.ListStatusRecords()
	if len(list) != 3 {
		t.Fatalf("expected 3 status records, got %d", len(list))
	}
	if list[0].StatusID != "status-1" || list[1].StatusID != "status-2" || list[2].StatusID != "status-3" {
		t.Fatalf("expected sorted status ids [status-1 status-2 status-3], got [%s %s %s]",
			list[0].StatusID, list[1].StatusID, list[2].StatusID)
	}
}
