package module

import (
	"errors"
	"reflect"
	"strconv"
	"strings"
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

	_, previewErr := server.PreviewEpochSelection(PreviewEpochSelectionRequest{})
	if !errors.Is(previewErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for preview epoch selection query, got %v", previewErr)
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

func TestQueryServerPreviewEpochSelectionDeterministic(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewQueryServer(&k)

	policy := baselinePreviewPolicy()
	stableHigh := previewCandidate("stable-high", "op-stable-high", "asn-stable-high", "us", 90)
	stableHigh.StableSeatPreferred = true
	stableLow := previewCandidate("stable-low", "op-stable-low", "asn-stable-low", "eu", 80)
	stableLow.StableSeatPreferred = true
	rotateTop := previewCandidate("rotate-top", "op-rotate-top", "asn-rotate-top", "apac", 99)
	rotateNext := previewCandidate("rotate-next", "op-rotate-next", "asn-rotate-next", "latam", 70)

	respA, err := server.PreviewEpochSelection(PreviewEpochSelectionRequest{
		Policy: policy,
		Candidates: []types.EpochValidatorCandidate{
			rotateTop,
			stableLow,
			rotateNext,
			stableHigh,
		},
	})
	if err != nil {
		t.Fatalf("expected preview success, got %v", err)
	}

	respB, err := server.PreviewEpochSelection(PreviewEpochSelectionRequest{
		Policy: policy,
		Candidates: []types.EpochValidatorCandidate{
			stableHigh,
			rotateNext,
			rotateTop,
			stableLow,
		},
	})
	if err != nil {
		t.Fatalf("expected preview success for shuffled candidates, got %v", err)
	}

	if !reflect.DeepEqual(respA.Result.SelectedValidatorIDs(), respB.Result.SelectedValidatorIDs()) {
		t.Fatalf(
			"expected deterministic preview selection IDs %v and %v to match",
			respA.Result.SelectedValidatorIDs(),
			respB.Result.SelectedValidatorIDs(),
		)
	}

	if len(respA.Result.StableSeats) != 1 || respA.Result.StableSeats[0].ValidatorID != "stable-high" {
		t.Fatalf("expected stable seat [stable-high], got %+v", respA.Result.StableSeats)
	}
	if len(respA.Result.RotatingSeats) != 2 {
		t.Fatalf("expected 2 rotating seats, got %d", len(respA.Result.RotatingSeats))
	}
	if respA.Result.RotatingSeats[0].ValidatorID != "rotate-top" || respA.Result.RotatingSeats[1].ValidatorID != "stable-low" {
		t.Fatalf("expected rotating seats [rotate-top stable-low], got %+v", respA.Result.RotatingSeats)
	}
}

func TestQueryServerPreviewEpochSelectionValidationErrorPropagation(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewQueryServer(&k)

	_, err := server.PreviewEpochSelection(PreviewEpochSelectionRequest{
		Policy: types.EpochSelectionPolicy{
			Epoch:             10,
			StableSeatCount:   0,
			RotatingSeatCount: 0,
		},
	})
	if err == nil {
		t.Fatal("expected preview validation error for empty seat policy")
	}
	if !strings.Contains(err.Error(), "at least one stable or rotating seat is required") {
		t.Fatalf("expected seat validation error, got %v", err)
	}
}

func TestQueryServerPreviewEpochSelectionRejectsOversizedCandidateSet(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewQueryServer(&k)

	policy := baselinePreviewPolicy()
	candidates := make([]types.EpochValidatorCandidate, 0, maxPreviewEpochCandidateRecords+1)
	for i := 0; i < maxPreviewEpochCandidateRecords+1; i++ {
		suffix := strconv.Itoa(i)
		candidates = append(candidates, previewCandidate("val-"+suffix, "op-"+suffix, "asn-"+suffix, "us", 100))
	}

	_, err := server.PreviewEpochSelection(PreviewEpochSelectionRequest{
		Policy:     policy,
		Candidates: candidates,
	})
	if err == nil {
		t.Fatal("expected oversized candidate set to be rejected")
	}
	if !strings.Contains(err.Error(), "candidate set too large") {
		t.Fatalf("expected oversized candidate set error, got %v", err)
	}
}

func baselinePreviewPolicy() types.EpochSelectionPolicy {
	return types.EpochSelectionPolicy{
		Epoch:               10,
		StableSeatCount:     1,
		RotatingSeatCount:   2,
		MinStake:            100,
		MinStakeAgeEpochs:   3,
		MinHealthScore:      70,
		MinResourceHeadroom: 20,
		WarmupEpochs:        2,
		CooldownEpochs:      3,
		MaxSeatsPerOperator: 10,
		MaxSeatsPerASN:      10,
		MaxSeatsPerRegion:   10,
	}
}

func previewCandidate(validatorID string, operatorID string, asn string, region string, score int64) types.EpochValidatorCandidate {
	return types.EpochValidatorCandidate{
		ValidatorID:               validatorID,
		OperatorID:                operatorID,
		ASN:                       asn,
		Region:                    region,
		Stake:                     1_000,
		StakeAgeEpochs:            6,
		HealthScore:               95,
		ResourceHeadroom:          60,
		ConsecutiveEligibleEpochs: 4,
		LastRemovedEpoch:          -1,
		Score:                     score,
	}
}
