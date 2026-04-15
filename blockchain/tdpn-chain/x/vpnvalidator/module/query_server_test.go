package module

import (
	"errors"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnvalidator/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestQueryServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewQueryServer(k)

	_, eligibilityErr := server.GetValidatorEligibility(GetValidatorEligibilityRequest{ValidatorID: "val-nil"})
	if !errors.Is(eligibilityErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for eligibility query, got %v", eligibilityErr)
	}

	_, statusErr := server.GetValidatorStatusRecord(GetValidatorStatusRecordRequest{StatusID: "status-nil"})
	if !errors.Is(statusErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for status query, got %v", statusErr)
	}

	_, listEligibilityErr := server.ListValidatorEligibilities(ListValidatorEligibilitiesRequest{})
	if !errors.Is(listEligibilityErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list eligibilities query, got %v", listEligibilityErr)
	}

	_, listStatusErr := server.ListValidatorStatusRecords(ListValidatorStatusRecordsRequest{})
	if !errors.Is(listStatusErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list status query, got %v", listStatusErr)
	}
}

func TestQueryServerNotFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewQueryServer(&k)

	_, eligibilityErr := server.GetValidatorEligibility(GetValidatorEligibilityRequest{ValidatorID: "val-missing"})
	if !errors.Is(eligibilityErr, ErrEligibilityNotFound) {
		t.Fatalf("expected ErrEligibilityNotFound, got %v", eligibilityErr)
	}

	_, statusErr := server.GetValidatorStatusRecord(GetValidatorStatusRecordRequest{StatusID: "status-missing"})
	if !errors.Is(statusErr, ErrStatusNotFound) {
		t.Fatalf("expected ErrStatusNotFound, got %v", statusErr)
	}
}

func TestQueryServerFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	expectedEligibility := types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "tdpnvaloper1abc",
		Eligible:        true,
	}
	expectedStatus := types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
		EvidenceHeight:  10,
	}
	k.UpsertEligibility(expectedEligibility)
	k.UpsertStatusRecord(expectedStatus)

	server := NewQueryServer(&k)

	eligibilityResp, eligibilityErr := server.GetValidatorEligibility(GetValidatorEligibilityRequest{ValidatorID: "val-1"})
	if eligibilityErr != nil {
		t.Fatalf("expected eligibility query success, got %v", eligibilityErr)
	}
	if eligibilityResp.Eligibility.ValidatorID != expectedEligibility.ValidatorID {
		t.Fatalf("unexpected validator id: %q", eligibilityResp.Eligibility.ValidatorID)
	}

	statusResp, statusErr := server.GetValidatorStatusRecord(GetValidatorStatusRecordRequest{StatusID: "status-1"})
	if statusErr != nil {
		t.Fatalf("expected status query success, got %v", statusErr)
	}
	if statusResp.Record.StatusID != expectedStatus.StatusID {
		t.Fatalf("unexpected status id: %q", statusResp.Record.StatusID)
	}
}

func TestQueryServerListNonEmpty(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-3",
		OperatorAddress: "op-3",
		Eligible:        true,
	})
	k.UpsertEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-1",
		OperatorAddress: "op-1",
		Eligible:        true,
	})
	k.UpsertEligibility(types.ValidatorEligibility{
		ValidatorID:     "val-2",
		OperatorAddress: "op-2",
		Eligible:        false,
	})

	k.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-3",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleSuspended,
	})
	k.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-1",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleActive,
	})
	k.UpsertStatusRecord(types.ValidatorStatusRecord{
		StatusID:        "status-2",
		ValidatorID:     "val-1",
		LifecycleStatus: types.ValidatorLifecycleJailed,
	})

	server := NewQueryServer(&k)

	eligibilityResp, eligibilityErr := server.ListValidatorEligibilities(ListValidatorEligibilitiesRequest{})
	if eligibilityErr != nil {
		t.Fatalf("expected list eligibilities success, got %v", eligibilityErr)
	}
	if len(eligibilityResp.Eligibilities) != 3 {
		t.Fatalf("expected 3 eligibilities, got %d", len(eligibilityResp.Eligibilities))
	}
	if eligibilityResp.Eligibilities[0].ValidatorID != "val-1" ||
		eligibilityResp.Eligibilities[1].ValidatorID != "val-2" ||
		eligibilityResp.Eligibilities[2].ValidatorID != "val-3" {
		t.Fatalf(
			"expected sorted validator ids [val-1 val-2 val-3], got [%s %s %s]",
			eligibilityResp.Eligibilities[0].ValidatorID,
			eligibilityResp.Eligibilities[1].ValidatorID,
			eligibilityResp.Eligibilities[2].ValidatorID,
		)
	}

	statusResp, statusErr := server.ListValidatorStatusRecords(ListValidatorStatusRecordsRequest{})
	if statusErr != nil {
		t.Fatalf("expected list status success, got %v", statusErr)
	}
	if len(statusResp.Records) != 3 {
		t.Fatalf("expected 3 status records, got %d", len(statusResp.Records))
	}
	if statusResp.Records[0].StatusID != "status-1" ||
		statusResp.Records[1].StatusID != "status-2" ||
		statusResp.Records[2].StatusID != "status-3" {
		t.Fatalf(
			"expected sorted status ids [status-1 status-2 status-3], got [%s %s %s]",
			statusResp.Records[0].StatusID,
			statusResp.Records[1].StatusID,
			statusResp.Records[2].StatusID,
		)
	}
}
