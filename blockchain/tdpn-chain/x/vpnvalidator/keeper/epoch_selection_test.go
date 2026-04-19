package keeper

import (
	"reflect"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnvalidator/types"
)

func TestKeeperSelectEpochValidators(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	policy := types.EpochSelectionPolicy{
		Epoch:               12,
		StableSeatCount:     1,
		RotatingSeatCount:   2,
		MinStake:            100,
		MinStakeAgeEpochs:   3,
		MinHealthScore:      70,
		MinResourceHeadroom: 20,
		WarmupEpochs:        2,
		CooldownEpochs:      3,
		MaxSeatsPerOperator: 1,
		MaxSeatsPerASN:      1,
		MaxSeatsPerRegion:   2,
	}

	stable := types.EpochValidatorCandidate{
		ValidatorID:               "stable-1",
		OperatorID:                "op-stable-1",
		ASN:                       "asn-stable-1",
		Region:                    "us",
		Stake:                     200,
		StakeAgeEpochs:            6,
		HealthScore:               95,
		ResourceHeadroom:          50,
		ConsecutiveEligibleEpochs: 4,
		LastRemovedEpoch:          -1,
		Score:                     90,
		StableSeatPreferred:       true,
	}
	rotatingTop := types.EpochValidatorCandidate{
		ValidatorID:               "rotating-top",
		OperatorID:                "op-rotating-top",
		ASN:                       "asn-rotating-top",
		Region:                    "eu",
		Stake:                     200,
		StakeAgeEpochs:            6,
		HealthScore:               95,
		ResourceHeadroom:          50,
		ConsecutiveEligibleEpochs: 4,
		LastRemovedEpoch:          -1,
		Score:                     99,
	}
	blockedByOperatorCap := types.EpochValidatorCandidate{
		ValidatorID:               "blocked-op",
		OperatorID:                "op-rotating-top",
		ASN:                       "asn-other",
		Region:                    "apac",
		Stake:                     200,
		StakeAgeEpochs:            6,
		HealthScore:               95,
		ResourceHeadroom:          50,
		ConsecutiveEligibleEpochs: 4,
		LastRemovedEpoch:          -1,
		Score:                     95,
	}
	rotatingNext := types.EpochValidatorCandidate{
		ValidatorID:               "rotating-next",
		OperatorID:                "op-rotating-next",
		ASN:                       "asn-rotating-next",
		Region:                    "apac",
		Stake:                     200,
		StakeAgeEpochs:            6,
		HealthScore:               95,
		ResourceHeadroom:          50,
		ConsecutiveEligibleEpochs: 4,
		LastRemovedEpoch:          -1,
		Score:                     94,
	}

	result, err := k.SelectEpochValidators(policy, []types.EpochValidatorCandidate{
		rotatingNext,
		blockedByOperatorCap,
		rotatingTop,
		stable,
	})
	if err != nil {
		t.Fatalf("SelectEpochValidators returned unexpected error: %v", err)
	}

	expectedStable := []string{"stable-1"}
	gotStable := []string{result.StableSeats[0].ValidatorID}
	if !reflect.DeepEqual(gotStable, expectedStable) {
		t.Fatalf("expected stable seats %v, got %v", expectedStable, gotStable)
	}

	expectedSelected := []string{"stable-1", "rotating-top", "rotating-next"}
	if !reflect.DeepEqual(result.SelectedValidatorIDs(), expectedSelected) {
		t.Fatalf("expected selected validator ids %v, got %v", expectedSelected, result.SelectedValidatorIDs())
	}
}
