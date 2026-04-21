package types

import (
	"reflect"
	"strings"
	"testing"
)

func TestSelectEpochValidatorsDeterministicRankingWithTieBreaker(t *testing.T) {
	t.Parallel()

	policy := baselineEpochSelectionPolicy()
	policy.StableSeatCount = 0
	policy.RotatingSeatCount = 3

	inputA := []EpochValidatorCandidate{
		newCandidate("val-c", "op-c", "asn-c", "eu", 100),
		newCandidate("val-a", "op-a", "asn-a", "us", 100),
		newCandidate("val-b", "op-b", "asn-b", "apac", 100),
	}
	inputB := []EpochValidatorCandidate{
		inputA[1],
		inputA[2],
		inputA[0],
	}

	resultA, err := SelectEpochValidators(policy, inputA)
	if err != nil {
		t.Fatalf("SelectEpochValidators returned unexpected error: %v", err)
	}
	resultB, err := SelectEpochValidators(policy, inputB)
	if err != nil {
		t.Fatalf("SelectEpochValidators returned unexpected error for shuffled input: %v", err)
	}

	expected := []string{"val-a", "val-b", "val-c"}
	if !reflect.DeepEqual(resultA.SelectedValidatorIDs(), expected) {
		t.Fatalf("expected deterministic ranking %v, got %v", expected, resultA.SelectedValidatorIDs())
	}
	if !reflect.DeepEqual(resultB.SelectedValidatorIDs(), expected) {
		t.Fatalf("expected deterministic ranking for shuffled input %v, got %v", expected, resultB.SelectedValidatorIDs())
	}
}

func TestSelectEpochValidatorsAppliesHardGatesWarmupAndCooldown(t *testing.T) {
	t.Parallel()

	policy := baselineEpochSelectionPolicy()
	policy.StableSeatCount = 1
	policy.RotatingSeatCount = 0

	eligible := newCandidate("eligible", "op-eligible", "asn-eligible", "us", 200)
	eligible.StableSeatPreferred = true

	failStake := newCandidate("fail-stake", "op-1", "asn-1", "eu", 300)
	failStake.Stake = policy.MinStake - 1

	failStakeAge := newCandidate("fail-stake-age", "op-2", "asn-2", "eu", 300)
	failStakeAge.StakeAgeEpochs = policy.MinStakeAgeEpochs - 1

	failHealth := newCandidate("fail-health", "op-3", "asn-3", "eu", 300)
	failHealth.HealthScore = policy.MinHealthScore - 1

	failResource := newCandidate("fail-resource", "op-4", "asn-4", "eu", 300)
	failResource.ResourceHeadroom = policy.MinResourceHeadroom - 1

	failSanction := newCandidate("fail-sanction", "op-5", "asn-5", "eu", 300)
	failSanction.HasActiveSanction = true

	failIncident := newCandidate("fail-incident", "op-6", "asn-6", "eu", 300)
	failIncident.HasUnresolvedCriticalIssues = true

	failWarmup := newCandidate("fail-warmup", "op-7", "asn-7", "eu", 300)
	failWarmup.ConsecutiveEligibleEpochs = policy.WarmupEpochs - 1

	failCooldown := newCandidate("fail-cooldown", "op-8", "asn-8", "eu", 300)
	failCooldown.LastRemovedEpoch = policy.Epoch - 1

	result, err := SelectEpochValidators(policy, []EpochValidatorCandidate{
		failStake,
		failStakeAge,
		failHealth,
		failResource,
		failSanction,
		failIncident,
		failWarmup,
		failCooldown,
		eligible,
	})
	if err != nil {
		t.Fatalf("SelectEpochValidators returned unexpected error: %v", err)
	}

	if len(result.StableSeats) != 1 {
		t.Fatalf("expected 1 selected stable validator, got %d", len(result.StableSeats))
	}
	if got := result.StableSeats[0].ValidatorID; got != "eligible" {
		t.Fatalf("expected only eligible candidate to be selected, got %q", got)
	}
	if len(result.RotatingSeats) != 0 {
		t.Fatalf("expected 0 rotating seats, got %d", len(result.RotatingSeats))
	}
}

func TestSelectEpochValidatorsFillsStableBeforeRotating(t *testing.T) {
	t.Parallel()

	policy := baselineEpochSelectionPolicy()
	policy.StableSeatCount = 2
	policy.RotatingSeatCount = 1

	stableHigh := newCandidate("stable-high", "op-stable-high", "asn-stable-high", "us", 90)
	stableHigh.StableSeatPreferred = true

	stableLow := newCandidate("stable-low", "op-stable-low", "asn-stable-low", "eu", 80)
	stableLow.StableSeatPreferred = true

	rotateTop := newCandidate("rotate-top", "op-rotate-top", "asn-rotate-top", "apac", 99)
	rotateNext := newCandidate("rotate-next", "op-rotate-next", "asn-rotate-next", "latam", 70)

	result, err := SelectEpochValidators(policy, []EpochValidatorCandidate{
		rotateTop,
		stableLow,
		stableHigh,
		rotateNext,
	})
	if err != nil {
		t.Fatalf("SelectEpochValidators returned unexpected error: %v", err)
	}

	stableIDs := []string{result.StableSeats[0].ValidatorID, result.StableSeats[1].ValidatorID}
	expectedStable := []string{"stable-high", "stable-low"}
	if !reflect.DeepEqual(stableIDs, expectedStable) {
		t.Fatalf("expected stable seats %v, got %v", expectedStable, stableIDs)
	}
	if len(result.RotatingSeats) != 1 || result.RotatingSeats[0].ValidatorID != "rotate-top" {
		t.Fatalf("expected rotating seat [rotate-top], got %v", result.RotatingSeats)
	}
}

func TestSelectEpochValidatorsFallsBackWhenStablePoolIsUndersized(t *testing.T) {
	t.Parallel()

	policy := baselineEpochSelectionPolicy()
	policy.StableSeatCount = 2
	policy.RotatingSeatCount = 1

	stableOnly := newCandidate("stable-only", "op-stable", "asn-stable", "us", 95)
	stableOnly.StableSeatPreferred = true

	rotateTop := newCandidate("rotate-top", "op-rotate-top", "asn-rotate-top", "eu", 90)
	rotateNext := newCandidate("rotate-next", "op-rotate-next", "asn-rotate-next", "apac", 85)
	rotateLow := newCandidate("rotate-low", "op-rotate-low", "asn-rotate-low", "latam", 80)

	result, err := SelectEpochValidators(policy, []EpochValidatorCandidate{
		rotateLow,
		rotateTop,
		stableOnly,
		rotateNext,
	})
	if err != nil {
		t.Fatalf("SelectEpochValidators returned unexpected error: %v", err)
	}

	stableIDs := []string{result.StableSeats[0].ValidatorID, result.StableSeats[1].ValidatorID}
	expectedStable := []string{"stable-only", "rotate-top"}
	if !reflect.DeepEqual(stableIDs, expectedStable) {
		t.Fatalf("expected stable fallback seats %v, got %v", expectedStable, stableIDs)
	}
	if len(result.RotatingSeats) != 1 || result.RotatingSeats[0].ValidatorID != "rotate-next" {
		t.Fatalf("expected rotating seat [rotate-next], got %v", result.RotatingSeats)
	}
}

func TestSelectEpochValidatorsAppliesConcentrationCaps(t *testing.T) {
	t.Parallel()

	policy := baselineEpochSelectionPolicy()
	policy.StableSeatCount = 0
	policy.RotatingSeatCount = 3
	policy.MaxSeatsPerOperator = 1
	policy.MaxSeatsPerASN = 1
	policy.MaxSeatsPerRegion = 1

	allowedTop := newCandidate("allowed-top", "op-a", "asn-a", "us", 100)
	blockedByOperator := newCandidate("blocked-op", "op-a", "asn-b", "eu", 99)
	blockedByASN := newCandidate("blocked-asn", "op-b", "asn-a", "eu", 98)
	blockedByRegion := newCandidate("blocked-region", "op-c", "asn-c", "us", 97)
	allowedSecond := newCandidate("allowed-second", "op-d", "asn-d", "apac", 96)
	allowedThird := newCandidate("allowed-third", "op-e", "asn-e", "latam", 95)

	result, err := SelectEpochValidators(policy, []EpochValidatorCandidate{
		allowedThird,
		blockedByRegion,
		blockedByASN,
		blockedByOperator,
		allowedTop,
		allowedSecond,
	})
	if err != nil {
		t.Fatalf("SelectEpochValidators returned unexpected error: %v", err)
	}

	expected := []string{"allowed-top", "allowed-second", "allowed-third"}
	if !reflect.DeepEqual(result.SelectedValidatorIDs(), expected) {
		t.Fatalf("expected cap-compliant selected validators %v, got %v", expected, result.SelectedValidatorIDs())
	}
}

func TestSelectEpochValidatorsAppliesConcentrationCapsCaseInsensitive(t *testing.T) {
	t.Parallel()

	policy := baselineEpochSelectionPolicy()
	policy.StableSeatCount = 0
	policy.RotatingSeatCount = 3
	policy.MaxSeatsPerOperator = 1
	policy.MaxSeatsPerASN = 1
	policy.MaxSeatsPerRegion = 1

	allowedTop := newCandidate("allowed-top", "Operator-A", "ASN-A", "US", 100)
	blockedByOperatorCase := newCandidate("blocked-op-case", "operator-a", "asn-b", "eu", 99)
	blockedByASNCase := newCandidate("blocked-asn-case", "operator-b", "asn-a", "apac", 98)
	blockedByRegionCase := newCandidate("blocked-region-case", "operator-c", "asn-c", "us", 97)
	allowedSecond := newCandidate("allowed-second", "operator-d", "asn-d", "apac", 96)
	allowedThird := newCandidate("allowed-third", "operator-e", "asn-e", "latam", 95)

	result, err := SelectEpochValidators(policy, []EpochValidatorCandidate{
		allowedThird,
		blockedByRegionCase,
		blockedByASNCase,
		blockedByOperatorCase,
		allowedTop,
		allowedSecond,
	})
	if err != nil {
		t.Fatalf("SelectEpochValidators returned unexpected error: %v", err)
	}

	expected := []string{"allowed-top", "allowed-second", "allowed-third"}
	if !reflect.DeepEqual(result.SelectedValidatorIDs(), expected) {
		t.Fatalf("expected case-insensitive cap-compliant selected validators %v, got %v", expected, result.SelectedValidatorIDs())
	}
}

func TestSelectEpochValidatorsRejectsDuplicateValidatorIDs(t *testing.T) {
	t.Parallel()

	policy := baselineEpochSelectionPolicy()
	duplicateA := newCandidate("dup", "op-a", "asn-a", "us", 100)
	duplicateB := newCandidate("dup", "op-b", "asn-b", "eu", 90)

	_, err := SelectEpochValidators(policy, []EpochValidatorCandidate{duplicateA, duplicateB})
	if err == nil {
		t.Fatal("expected duplicate validator id error")
	}
	if err.Error() != `duplicate validator id "dup"` {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestSelectEpochValidatorsRejectsDuplicateValidatorIDsCaseInsensitive(t *testing.T) {
	t.Parallel()

	policy := baselineEpochSelectionPolicy()
	duplicateA := newCandidate("Dup-Validator", "op-a", "asn-a", "us", 100)
	duplicateB := newCandidate(" dup-validator ", "op-b", "asn-b", "eu", 90)

	_, err := SelectEpochValidators(policy, []EpochValidatorCandidate{duplicateA, duplicateB})
	if err == nil {
		t.Fatal("expected duplicate validator id error for case/whitespace variant")
	}
	if !strings.Contains(err.Error(), "duplicate validator id") {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func baselineEpochSelectionPolicy() EpochSelectionPolicy {
	return EpochSelectionPolicy{
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

func newCandidate(validatorID string, operatorID string, asn string, region string, score int64) EpochValidatorCandidate {
	return EpochValidatorCandidate{
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
