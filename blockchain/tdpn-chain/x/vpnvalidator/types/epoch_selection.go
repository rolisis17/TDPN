package types

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// EpochSelectionPolicy defines deterministic validator-set policy inputs for an epoch.
type EpochSelectionPolicy struct {
	Epoch               int64
	StableSeatCount     int
	RotatingSeatCount   int
	MinStake            int64
	MinStakeAgeEpochs   int64
	MinHealthScore      int64
	MinResourceHeadroom int64
	WarmupEpochs        int64
	CooldownEpochs      int64
	MaxSeatsPerOperator int
	MaxSeatsPerASN      int
	MaxSeatsPerRegion   int
}

func (p EpochSelectionPolicy) ValidateBasic() error {
	if p.Epoch < 0 {
		return errors.New("epoch cannot be negative")
	}
	if p.StableSeatCount < 0 {
		return errors.New("stable seat count cannot be negative")
	}
	if p.RotatingSeatCount < 0 {
		return errors.New("rotating seat count cannot be negative")
	}
	if p.TotalSeatCount() <= 0 {
		return errors.New("at least one stable or rotating seat is required")
	}
	if p.MinStake < 0 {
		return errors.New("minimum stake cannot be negative")
	}
	if p.MinStakeAgeEpochs < 0 {
		return errors.New("minimum stake age cannot be negative")
	}
	if p.MinHealthScore < 0 {
		return errors.New("minimum health score cannot be negative")
	}
	if p.MinResourceHeadroom < 0 {
		return errors.New("minimum resource headroom cannot be negative")
	}
	if p.WarmupEpochs < 0 {
		return errors.New("warmup epochs cannot be negative")
	}
	if p.CooldownEpochs < 0 {
		return errors.New("cooldown epochs cannot be negative")
	}
	if p.MaxSeatsPerOperator < 0 {
		return errors.New("operator seat cap cannot be negative")
	}
	if p.MaxSeatsPerASN < 0 {
		return errors.New("asn seat cap cannot be negative")
	}
	if p.MaxSeatsPerRegion < 0 {
		return errors.New("region seat cap cannot be negative")
	}
	return nil
}

func (p EpochSelectionPolicy) TotalSeatCount() int {
	return p.StableSeatCount + p.RotatingSeatCount
}

// EpochValidatorCandidate captures objective candidate inputs required for deterministic selection.
type EpochValidatorCandidate struct {
	ValidatorID                 string
	OperatorID                  string
	ASN                         string
	Region                      string
	Stake                       int64
	StakeAgeEpochs              int64
	HealthScore                 int64
	ResourceHeadroom            int64
	HasActiveSanction           bool
	HasUnresolvedCriticalIssues bool
	ConsecutiveEligibleEpochs   int64
	LastRemovedEpoch            int64
	Score                       int64
	StableSeatPreferred         bool
}

func (c EpochValidatorCandidate) ValidateBasic() error {
	if c.ValidatorID == "" {
		return errors.New("validator id is required")
	}
	if c.OperatorID == "" {
		return errors.New("operator id is required")
	}
	if c.ASN == "" {
		return errors.New("asn is required")
	}
	if c.Region == "" {
		return errors.New("region is required")
	}
	if c.Stake < 0 {
		return errors.New("stake cannot be negative")
	}
	if c.StakeAgeEpochs < 0 {
		return errors.New("stake age cannot be negative")
	}
	if c.HealthScore < 0 {
		return errors.New("health score cannot be negative")
	}
	if c.ResourceHeadroom < 0 {
		return errors.New("resource headroom cannot be negative")
	}
	if c.ConsecutiveEligibleEpochs < 0 {
		return errors.New("consecutive eligible epochs cannot be negative")
	}
	if c.LastRemovedEpoch < -1 {
		return errors.New("last removed epoch cannot be less than -1")
	}
	return nil
}

// EpochSelectionResult is the deterministic validator-set output for one epoch.
type EpochSelectionResult struct {
	StableSeats   []EpochValidatorCandidate
	RotatingSeats []EpochValidatorCandidate
}

func (r EpochSelectionResult) SelectedValidatorIDs() []string {
	ids := make([]string, 0, len(r.StableSeats)+len(r.RotatingSeats))
	for _, candidate := range r.StableSeats {
		ids = append(ids, candidate.ValidatorID)
	}
	for _, candidate := range r.RotatingSeats {
		ids = append(ids, candidate.ValidatorID)
	}
	return ids
}

// SelectEpochValidators applies hard gates, warm-up/cooldown checks, deterministic ranking,
// stable-then-rotating fill, and concentration caps.
func SelectEpochValidators(policy EpochSelectionPolicy, candidates []EpochValidatorCandidate) (EpochSelectionResult, error) {
	if err := policy.ValidateBasic(); err != nil {
		return EpochSelectionResult{}, err
	}

	rankedEligible, err := rankEligibleCandidates(policy, candidates)
	if err != nil {
		return EpochSelectionResult{}, err
	}

	selectionTracker := makeSelectionTracker()
	alreadySelected := make(map[string]struct{}, policy.TotalSeatCount())

	stablePreferred := make([]EpochValidatorCandidate, 0, len(rankedEligible))
	for _, candidate := range rankedEligible {
		if candidate.StableSeatPreferred {
			stablePreferred = append(stablePreferred, candidate)
		}
	}

	stableSeats := selectWithConcentrationCaps(
		policy.StableSeatCount,
		stablePreferred,
		policy,
		selectionTracker,
		alreadySelected,
	)
	if len(stableSeats) < policy.StableSeatCount {
		fallbackPool := remainingCandidates(rankedEligible, alreadySelected)
		stableSeats = append(stableSeats, selectWithConcentrationCaps(
			policy.StableSeatCount-len(stableSeats),
			fallbackPool,
			policy,
			selectionTracker,
			alreadySelected,
		)...)
	}

	rotatingPool := remainingCandidates(rankedEligible, alreadySelected)
	rotatingSeats := selectWithConcentrationCaps(
		policy.RotatingSeatCount,
		rotatingPool,
		policy,
		selectionTracker,
		alreadySelected,
	)

	return EpochSelectionResult{
		StableSeats:   stableSeats,
		RotatingSeats: rotatingSeats,
	}, nil
}

func rankEligibleCandidates(policy EpochSelectionPolicy, candidates []EpochValidatorCandidate) ([]EpochValidatorCandidate, error) {
	validated := make([]EpochValidatorCandidate, 0, len(candidates))
	seenValidatorIDs := make(map[string]struct{}, len(candidates))

	for _, candidate := range candidates {
		if err := candidate.ValidateBasic(); err != nil {
			return nil, fmt.Errorf("candidate %q: %w", candidate.ValidatorID, err)
		}
		canonicalValidatorID := canonicalSelectionIdentity(candidate.ValidatorID)
		if _, exists := seenValidatorIDs[canonicalValidatorID]; exists {
			return nil, fmt.Errorf("duplicate validator id %q", candidate.ValidatorID)
		}
		seenValidatorIDs[canonicalValidatorID] = struct{}{}
		validated = append(validated, candidate)
	}

	eligible := make([]EpochValidatorCandidate, 0, len(validated))
	for _, candidate := range validated {
		if !passesHardGates(policy, candidate) {
			continue
		}
		if !passesWarmupAndCooldown(policy, candidate) {
			continue
		}
		eligible = append(eligible, candidate)
	}

	slices.SortFunc(eligible, compareCandidateRank)
	return eligible, nil
}

func passesHardGates(policy EpochSelectionPolicy, candidate EpochValidatorCandidate) bool {
	switch {
	case candidate.Stake < policy.MinStake:
		return false
	case candidate.StakeAgeEpochs < policy.MinStakeAgeEpochs:
		return false
	case candidate.HasActiveSanction:
		return false
	case candidate.HasUnresolvedCriticalIssues:
		return false
	case candidate.HealthScore < policy.MinHealthScore:
		return false
	case candidate.ResourceHeadroom < policy.MinResourceHeadroom:
		return false
	default:
		return true
	}
}

func passesWarmupAndCooldown(policy EpochSelectionPolicy, candidate EpochValidatorCandidate) bool {
	if candidate.ConsecutiveEligibleEpochs < policy.WarmupEpochs {
		return false
	}
	if policy.CooldownEpochs <= 0 || candidate.LastRemovedEpoch < 0 {
		return true
	}
	if policy.Epoch <= candidate.LastRemovedEpoch {
		return false
	}
	return policy.Epoch-candidate.LastRemovedEpoch >= policy.CooldownEpochs
}

func compareCandidateRank(a, b EpochValidatorCandidate) int {
	switch {
	case a.Score > b.Score:
		return -1
	case a.Score < b.Score:
		return 1
	}

	aValidatorID := canonicalSelectionIdentity(a.ValidatorID)
	bValidatorID := canonicalSelectionIdentity(b.ValidatorID)
	switch {
	case aValidatorID < bValidatorID:
		return -1
	case aValidatorID > bValidatorID:
		return 1
	}
	switch {
	case a.ValidatorID < b.ValidatorID:
		return -1
	case a.ValidatorID > b.ValidatorID:
		return 1
	}

	aOperatorID := canonicalSelectionIdentity(a.OperatorID)
	bOperatorID := canonicalSelectionIdentity(b.OperatorID)
	switch {
	case aOperatorID < bOperatorID:
		return -1
	case aOperatorID > bOperatorID:
		return 1
	}
	switch {
	case a.OperatorID < b.OperatorID:
		return -1
	case a.OperatorID > b.OperatorID:
		return 1
	}

	aASN := canonicalSelectionIdentity(a.ASN)
	bASN := canonicalSelectionIdentity(b.ASN)
	switch {
	case aASN < bASN:
		return -1
	case aASN > bASN:
		return 1
	}
	switch {
	case a.ASN < b.ASN:
		return -1
	case a.ASN > b.ASN:
		return 1
	}

	aRegion := canonicalSelectionIdentity(a.Region)
	bRegion := canonicalSelectionIdentity(b.Region)
	switch {
	case aRegion < bRegion:
		return -1
	case aRegion > bRegion:
		return 1
	}
	switch {
	case a.Region < b.Region:
		return -1
	case a.Region > b.Region:
		return 1
	default:
		return 0
	}
}

type selectionTracker struct {
	byOperator map[string]int
	byASN      map[string]int
	byRegion   map[string]int
}

func makeSelectionTracker() *selectionTracker {
	return &selectionTracker{
		byOperator: make(map[string]int),
		byASN:      make(map[string]int),
		byRegion:   make(map[string]int),
	}
}

func (t *selectionTracker) canSelect(policy EpochSelectionPolicy, candidate EpochValidatorCandidate) bool {
	operatorID := canonicalSelectionIdentity(candidate.OperatorID)
	if exceedsCap(policy.MaxSeatsPerOperator, t.byOperator[operatorID]) {
		return false
	}
	asn := canonicalSelectionIdentity(candidate.ASN)
	if exceedsCap(policy.MaxSeatsPerASN, t.byASN[asn]) {
		return false
	}
	region := canonicalSelectionIdentity(candidate.Region)
	if exceedsCap(policy.MaxSeatsPerRegion, t.byRegion[region]) {
		return false
	}
	return true
}

func (t *selectionTracker) noteSelected(candidate EpochValidatorCandidate) {
	operatorID := canonicalSelectionIdentity(candidate.OperatorID)
	asn := canonicalSelectionIdentity(candidate.ASN)
	region := canonicalSelectionIdentity(candidate.Region)

	t.byOperator[operatorID]++
	t.byASN[asn]++
	t.byRegion[region]++
}

func exceedsCap(capValue int, selectedCount int) bool {
	return capValue > 0 && selectedCount >= capValue
}

func selectWithConcentrationCaps(
	limit int,
	pool []EpochValidatorCandidate,
	policy EpochSelectionPolicy,
	tracker *selectionTracker,
	alreadySelected map[string]struct{},
) []EpochValidatorCandidate {
	if limit <= 0 {
		return nil
	}

	selected := make([]EpochValidatorCandidate, 0, min(limit, len(pool)))
	for _, candidate := range pool {
		if len(selected) == limit {
			break
		}
		canonicalValidatorID := canonicalSelectionIdentity(candidate.ValidatorID)
		if _, exists := alreadySelected[canonicalValidatorID]; exists {
			continue
		}
		if !tracker.canSelect(policy, candidate) {
			continue
		}

		alreadySelected[canonicalValidatorID] = struct{}{}
		tracker.noteSelected(candidate)
		selected = append(selected, candidate)
	}
	return selected
}

func remainingCandidates(ranked []EpochValidatorCandidate, alreadySelected map[string]struct{}) []EpochValidatorCandidate {
	remaining := make([]EpochValidatorCandidate, 0, len(ranked))
	for _, candidate := range ranked {
		canonicalValidatorID := canonicalSelectionIdentity(candidate.ValidatorID)
		if _, exists := alreadySelected[canonicalValidatorID]; exists {
			continue
		}
		remaining = append(remaining, candidate)
	}
	return remaining
}

func canonicalSelectionIdentity(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func min(a int, b int) int {
	if a < b {
		return a
	}
	return b
}
