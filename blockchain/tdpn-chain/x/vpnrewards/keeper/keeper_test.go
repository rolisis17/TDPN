package keeper

import (
	"errors"
	"strings"
	"testing"
	"time"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

type failSafeDistributionStore struct {
	accruals      map[string]types.RewardAccrual
	distributions map[string]types.DistributionRecord

	failAccrualUpserts      int
	failDistributionUpserts int
}

func newFailSafeDistributionStore() *failSafeDistributionStore {
	return &failSafeDistributionStore{
		accruals:      make(map[string]types.RewardAccrual),
		distributions: make(map[string]types.DistributionRecord),
	}
}

func validRewardProofRecord(proofPath string) types.RewardProofRecord {
	return types.RewardProofRecord{
		ProofPath:         proofPath,
		TrafficProofRef:   "obj://" + proofPath,
		RewardID:          "reward-" + strings.ReplaceAll(proofPath, "/", "-"),
		ProviderSubjectID: "provider-proof",
		SessionID:         "session-proof",
		PayoutStartUnix:   1776643200,
		PayoutEndUnix:     1776643200 + weeklyEpochSeconds,
		RewardMicros:      100,
		Currency:          "uusdc",
		IssuedAtUnix:      1777248001,
		Verified:          true,
		VerifierID:        "verifier-proof",
		VerifiedAtUnix:    1777248010,
	}
}

func (s *failSafeDistributionStore) UpsertAccrual(record types.RewardAccrual) {
	s.accruals[record.AccrualID] = record
}

func (s *failSafeDistributionStore) UpsertAccrualWithError(record types.RewardAccrual) error {
	if s.failAccrualUpserts > 0 {
		s.failAccrualUpserts--
		return errors.New("forced accrual write failure")
	}
	s.UpsertAccrual(record)
	return nil
}

func (s *failSafeDistributionStore) GetAccrual(accrualID string) (types.RewardAccrual, bool) {
	record, ok := s.accruals[accrualID]
	return record, ok
}

func (s *failSafeDistributionStore) ListAccruals() []types.RewardAccrual {
	records := make([]types.RewardAccrual, 0, len(s.accruals))
	for _, record := range s.accruals {
		records = append(records, record)
	}
	return records
}

func (s *failSafeDistributionStore) UpsertDistribution(record types.DistributionRecord) {
	s.distributions[record.DistributionID] = record
}

func (s *failSafeDistributionStore) UpsertDistributionWithError(record types.DistributionRecord) error {
	if s.failDistributionUpserts > 0 {
		s.failDistributionUpserts--
		return errors.New("forced distribution write failure")
	}
	s.UpsertDistribution(record)
	return nil
}

func (s *failSafeDistributionStore) GetDistribution(distributionID string) (types.DistributionRecord, bool) {
	record, ok := s.distributions[distributionID]
	return record, ok
}

func (s *failSafeDistributionStore) ListDistributions() []types.DistributionRecord {
	records := make([]types.DistributionRecord, 0, len(s.distributions))
	for _, record := range s.distributions {
		records = append(records, record)
	}
	return records
}

func TestKeeperAccrualUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetAccrual("missing"); ok {
		t.Fatal("expected missing accrual lookup to return ok=false")
	}

	initial := types.RewardAccrual{
		AccrualID:  "acc-1",
		SessionID:  "sess-1",
		ProviderID: "provider-1",
		AssetDenom: "uusdc",
		Amount:     10,
	}
	k.UpsertAccrual(initial)

	got, ok := k.GetAccrual(initial.AccrualID)
	if !ok {
		t.Fatal("expected inserted accrual to be found")
	}
	if got.Amount != initial.Amount {
		t.Fatalf("expected amount %d, got %d", initial.Amount, got.Amount)
	}

	updated := initial
	updated.Amount = 20
	k.UpsertAccrual(updated)

	got, ok = k.GetAccrual(initial.AccrualID)
	if !ok {
		t.Fatal("expected updated accrual to be found")
	}
	if got.Amount != updated.Amount {
		t.Fatalf("expected updated amount %d, got %d", updated.Amount, got.Amount)
	}
}

func TestKeeperDistributionUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetDistribution("missing"); ok {
		t.Fatal("expected missing distribution lookup to return ok=false")
	}

	initial := types.DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      "acc-1",
		PayoutRef:      "payout-1",
	}
	k.UpsertDistribution(initial)

	got, ok := k.GetDistribution(initial.DistributionID)
	if !ok {
		t.Fatal("expected inserted distribution to be found")
	}
	if got.PayoutRef != initial.PayoutRef {
		t.Fatalf("expected payout ref %q, got %q", initial.PayoutRef, got.PayoutRef)
	}

	updated := initial
	updated.PayoutRef = "payout-2"
	k.UpsertDistribution(updated)

	got, ok = k.GetDistribution(initial.DistributionID)
	if !ok {
		t.Fatal("expected updated distribution to be found")
	}
	if got.PayoutRef != updated.PayoutRef {
		t.Fatalf("expected updated payout ref %q, got %q", updated.PayoutRef, got.PayoutRef)
	}
}

func TestKeeperListAccrualsDeterministicOrder(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertAccrual(types.RewardAccrual{
		AccrualID:  "acc-20",
		ProviderID: "provider-1",
		Amount:     20,
	})
	k.UpsertAccrual(types.RewardAccrual{
		AccrualID:  "acc-03",
		ProviderID: "provider-1",
		Amount:     3,
	})
	k.UpsertAccrual(types.RewardAccrual{
		AccrualID:  "acc-10",
		ProviderID: "provider-1",
		Amount:     10,
	})

	first := k.ListAccruals()
	second := k.ListAccruals()

	if len(first) != 3 {
		t.Fatalf("expected 3 accruals, got %d", len(first))
	}
	expectedIDs := []string{"acc-03", "acc-10", "acc-20"}
	for i, expected := range expectedIDs {
		if first[i].AccrualID != expected {
			t.Fatalf("expected accrual id at index %d to be %q, got %q", i, expected, first[i].AccrualID)
		}
		if second[i].AccrualID != expected {
			t.Fatalf("expected second accrual list id at index %d to be %q, got %q", i, expected, second[i].AccrualID)
		}
	}
}

func TestKeeperListDistributionsDeterministicOrder(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertDistribution(types.DistributionRecord{
		DistributionID: "dist-20",
		AccrualID:      "acc-1",
		PayoutRef:      "payout-20",
	})
	k.UpsertDistribution(types.DistributionRecord{
		DistributionID: "dist-03",
		AccrualID:      "acc-1",
		PayoutRef:      "payout-03",
	})
	k.UpsertDistribution(types.DistributionRecord{
		DistributionID: "dist-10",
		AccrualID:      "acc-1",
		PayoutRef:      "payout-10",
	})

	first := k.ListDistributions()
	second := k.ListDistributions()

	if len(first) != 3 {
		t.Fatalf("expected 3 distributions, got %d", len(first))
	}
	expectedIDs := []string{"dist-03", "dist-10", "dist-20"}
	for i, expected := range expectedIDs {
		if first[i].DistributionID != expected {
			t.Fatalf("expected distribution id at index %d to be %q, got %q", i, expected, first[i].DistributionID)
		}
		if second[i].DistributionID != expected {
			t.Fatalf("expected second distribution list id at index %d to be %q, got %q", i, expected, second[i].DistributionID)
		}
	}
}

func TestKeeperUpsertProofAllowsExactReplayAndRejectsConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	proof := validRewardProofRecord("traffic/proof-replay-1")
	if err := k.UpsertProofWithError(proof); err != nil {
		t.Fatalf("UpsertProofWithError returned unexpected error: %v", err)
	}

	replay := proof
	replay.TrustContract = types.RewardProofTrustContractObjectiveTrafficV1
	if err := k.UpsertProofWithError(replay); err != nil {
		t.Fatalf("expected exact proof replay to succeed, got %v", err)
	}

	conflict := proof
	conflict.RewardMicros++
	err := k.UpsertProofWithError(conflict)
	if err == nil {
		t.Fatal("expected conflicting proof upsert to fail")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error, got %v", err)
	}

	got, ok := k.GetProof(proof.ProofPath)
	if !ok {
		t.Fatal("expected original proof to remain stored")
	}
	if got != normalizeProof(proof) {
		t.Fatalf("expected conflicting upsert to preserve original proof %+v, got %+v", normalizeProof(proof), got)
	}
}

func TestKeeperProofReadWriteListAndVerifiedAccess(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	first := validRewardProofRecord("traffic/proof-list-b")
	second := validRewardProofRecord("traffic/proof-list-a")
	second.RewardID = "reward-proof-list-a"
	unverified := validRewardProofRecord("traffic/proof-list-c")
	unverified.RewardID = "reward-proof-list-c"
	unverified.Verified = false
	unverified.VerifierID = ""
	unverified.VerifiedAtUnix = 0

	k.UpsertProof(first)
	if err := k.UpsertProofWithError(second); err != nil {
		t.Fatalf("UpsertProofWithError returned unexpected error: %v", err)
	}
	if err := k.UpsertProofWithError(unverified); err != nil {
		t.Fatalf("UpsertProofWithError unverified proof returned unexpected error: %v", err)
	}

	got, ok := k.GetVerifiedProof(first.ProofPath)
	if !ok {
		t.Fatal("expected verified proof lookup to succeed")
	}
	if got != normalizeProof(first) {
		t.Fatalf("expected verified proof %+v, got %+v", normalizeProof(first), got)
	}
	if _, ok := k.GetVerifiedProof(unverified.ProofPath); ok {
		t.Fatal("expected unverified proof to be hidden from verified lookup")
	}
	if _, ok := k.GetVerifiedProof("traffic/missing-proof"); ok {
		t.Fatal("expected missing proof to be absent from verified lookup")
	}

	proofs := k.ListProofs()
	if len(proofs) != 3 {
		t.Fatalf("expected 3 proofs, got %d", len(proofs))
	}
	if proofs[0].ProofPath != second.ProofPath || proofs[1].ProofPath != first.ProofPath || proofs[2].ProofPath != unverified.ProofPath {
		t.Fatalf("expected sorted proof paths, got [%s %s %s]", proofs[0].ProofPath, proofs[1].ProofPath, proofs[2].ProofPath)
	}

	proofsWithError, err := k.ListProofsWithError()
	if err != nil {
		t.Fatalf("ListProofsWithError returned unexpected error: %v", err)
	}
	if len(proofsWithError) != len(proofs) {
		t.Fatalf("expected ListProofsWithError length %d, got %d", len(proofs), len(proofsWithError))
	}
}

func TestKeeperProofStoreUnsupportedFailsClosed(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)

	err := k.UpsertProofWithError(validRewardProofRecord("traffic/proof-unsupported"))
	if err == nil {
		t.Fatal("expected proof write to fail when store lacks proof support")
	}
	if !strings.Contains(err.Error(), "proof store is not supported") {
		t.Fatalf("expected unsupported proof store error, got %v", err)
	}
	if _, ok := k.GetProof("traffic/proof-unsupported"); ok {
		t.Fatal("expected unsupported proof store lookup to fail closed")
	}
	if proofs := k.ListProofs(); len(proofs) != 0 {
		t.Fatalf("expected unsupported proof store list to be empty, got %d", len(proofs))
	}
}

func TestKeeperCreateAccrualDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	input := types.RewardAccrual{
		AccrualID:  "acc-1",
		SessionID:  "sess-1",
		ProviderID: "provider-1",
		AssetDenom: "uusdc",
		Amount:     25,
	}

	created, err := k.CreateAccrual(input)
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}
	if created.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf("expected operation state %q, got %q", chaintypes.ReconciliationPending, created.OperationState)
	}

	idempotent, err := k.CreateAccrual(input)
	if err != nil {
		t.Fatalf("CreateAccrual idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent result to match created record, got %+v vs %+v", idempotent, created)
	}

	explicitPending := input
	explicitPending.OperationState = chaintypes.ReconciliationPending
	idempotent, err = k.CreateAccrual(explicitPending)
	if err != nil {
		t.Fatalf("CreateAccrual explicit pending idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected explicit pending result to match created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperCreateAccrualConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	initial := types.RewardAccrual{
		AccrualID:  "acc-1",
		SessionID:  "sess-1",
		ProviderID: "provider-1",
		AssetDenom: "uusdc",
		Amount:     10,
	}
	if _, err := k.CreateAccrual(initial); err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.Amount = 11
	_, err := k.CreateAccrual(conflict)
	if err == nil {
		t.Fatal("expected conflict error for accrual with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperCreateAccrualRejectsDuplicateProviderWeeklyEpoch(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	first := types.RewardAccrual{
		AccrualID:       "acc-weekly-1",
		SessionID:       "sess-weekly-1",
		ProviderID:      "provider-weekly-1",
		AssetDenom:      "uusdc",
		Amount:          10,
		AccruedAtUnix:   1700000000,
		PayoutStartUnix: 1699833600,
		PayoutEndUnix:   1699833600 + weeklyEpochSeconds,
	}
	if _, err := k.CreateAccrual(first); err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	duplicateWeek := types.RewardAccrual{
		AccrualID:       "acc-weekly-2",
		SessionID:       "sess-weekly-2",
		ProviderID:      "provider-weekly-1",
		AssetDenom:      "uusdc",
		Amount:          11,
		AccruedAtUnix:   first.AccruedAtUnix + 3600,
		PayoutStartUnix: first.PayoutStartUnix,
		PayoutEndUnix:   first.PayoutEndUnix,
	}
	_, err := k.CreateAccrual(duplicateWeek)
	if err == nil {
		t.Fatal("expected conflict for duplicate provider weekly epoch")
	}
	if !strings.Contains(err.Error(), "weekly epoch") {
		t.Fatalf("expected weekly epoch conflict, got %v", err)
	}

	nextWeek := duplicateWeek
	nextWeek.AccrualID = "acc-weekly-3"
	nextWeek.AccruedAtUnix = first.AccruedAtUnix + weeklyEpochSeconds
	nextWeek.PayoutStartUnix = first.PayoutStartUnix + weeklyEpochSeconds
	nextWeek.PayoutEndUnix = first.PayoutEndUnix + weeklyEpochSeconds
	if _, err := k.CreateAccrual(nextWeek); err != nil {
		t.Fatalf("expected next-week accrual to succeed, got %v", err)
	}
}

func TestKeeperCreateAccrualAllowsMultipleSessionRewardsInSameWeek(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	first := types.RewardAccrual{
		AccrualID:     "acc-session-reward-1",
		SessionID:     "sess-session-reward-1",
		ProviderID:    "provider-session-reward-1",
		AssetDenom:    "uusdc",
		Amount:        10,
		AccruedAtUnix: 1700000000,
	}
	if _, err := k.CreateAccrual(first); err != nil {
		t.Fatalf("CreateAccrual first session reward returned unexpected error: %v", err)
	}

	second := types.RewardAccrual{
		AccrualID:     "acc-session-reward-2",
		SessionID:     "sess-session-reward-2",
		ProviderID:    "provider-session-reward-1",
		AssetDenom:    "uusdc",
		Amount:        11,
		AccruedAtUnix: first.AccruedAtUnix + 3600,
	}
	if _, err := k.CreateAccrual(second); err != nil {
		t.Fatalf("expected second non-weekly session reward to succeed, got %v", err)
	}
}

func TestKeeperCreateAccrualRejectsMissingPeriodAgainstExistingWeeklyPayout(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	weekly := types.RewardAccrual{
		AccrualID:       "acc-weekly-period-1",
		SessionID:       "sess-weekly-period-1",
		ProviderID:      "provider-weekly-period-1",
		AssetDenom:      "uusdc",
		Amount:          10,
		AccruedAtUnix:   1776643200,
		PayoutStartUnix: 1776643200,
		PayoutEndUnix:   1776643200 + weeklyEpochSeconds,
	}
	if _, err := k.CreateAccrual(weekly); err != nil {
		t.Fatalf("CreateAccrual weekly seed returned unexpected error: %v", err)
	}

	missingPeriod := types.RewardAccrual{
		AccrualID:     "acc-weekly-period-2",
		SessionID:     "sess-weekly-period-2",
		ProviderID:    weekly.ProviderID,
		AssetDenom:    "uusdc",
		Amount:        11,
		AccruedAtUnix: weekly.AccruedAtUnix + 3600,
	}
	_, err := k.CreateAccrual(missingPeriod)
	if err == nil {
		t.Fatal("expected missing-period accrual to conflict with existing weekly payout")
	}
	if !strings.Contains(err.Error(), "weekly epoch") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected weekly missing-period conflict, got %v", err)
	}
	if _, ok := k.GetAccrual(missingPeriod.AccrualID); ok {
		t.Fatal("expected missing-period conflict to leave no stored accrual")
	}
}

func TestKeeperCreateAccrualRejectsWeeklyPayoutAgainstExistingMissingPeriod(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	missingPeriod := types.RewardAccrual{
		AccrualID:     "acc-weekly-period-existing-missing-1",
		SessionID:     "sess-weekly-period-existing-missing-1",
		ProviderID:    "provider-weekly-period-existing-missing",
		AssetDenom:    "uusdc",
		Amount:        10,
		AccruedAtUnix: 1776643200,
	}
	if _, err := k.CreateAccrual(missingPeriod); err != nil {
		t.Fatalf("CreateAccrual missing-period seed returned unexpected error: %v", err)
	}

	weekly := types.RewardAccrual{
		AccrualID:       "acc-weekly-period-existing-missing-2",
		SessionID:       "sess-weekly-period-existing-missing-2",
		ProviderID:      missingPeriod.ProviderID,
		AssetDenom:      "uusdc",
		Amount:          11,
		AccruedAtUnix:   missingPeriod.AccruedAtUnix,
		PayoutStartUnix: 1776643200,
		PayoutEndUnix:   1776643200 + weeklyEpochSeconds,
	}
	_, err := k.CreateAccrual(weekly)
	if err == nil {
		t.Fatal("expected weekly payout to conflict with existing missing-period accrual")
	}
	if !strings.Contains(err.Error(), "weekly epoch") || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("expected weekly missing-period conflict, got %v", err)
	}
	if _, ok := k.GetAccrual(weekly.AccrualID); ok {
		t.Fatal("expected weekly conflict to leave no stored accrual")
	}
}

func TestKeeperCreateAccrualWeeklyEpochStartsMondayUTC(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	mondayStart := time.Date(2026, 4, 27, 0, 0, 0, 0, time.UTC)

	first := types.RewardAccrual{
		AccrualID:       "acc-monday-epoch-1",
		SessionID:       "sess-monday-epoch-1",
		ProviderID:      "provider-monday-epoch",
		AssetDenom:      "uusdc",
		Amount:          10,
		AccruedAtUnix:   mondayStart.Unix(),
		PayoutStartUnix: mondayStart.Unix(),
		PayoutEndUnix:   mondayStart.Add(7 * 24 * time.Hour).Unix(),
	}
	if _, err := k.CreateAccrual(first); err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	sundaySameWeek := first
	sundaySameWeek.AccrualID = "acc-monday-epoch-2"
	sundaySameWeek.SessionID = "sess-monday-epoch-2"
	sundaySameWeek.Amount = 11
	if _, err := k.CreateAccrual(sundaySameWeek); err == nil {
		t.Fatal("expected conflict before next Monday 00:00 UTC")
	} else if !strings.Contains(err.Error(), "weekly epoch") {
		t.Fatalf("expected weekly epoch conflict, got %v", err)
	}

	nextMonday := sundaySameWeek
	nextMonday.AccrualID = "acc-monday-epoch-3"
	nextMonday.SessionID = "sess-monday-epoch-3"
	nextMonday.AccruedAtUnix = mondayStart.Add(7 * 24 * time.Hour).Unix()
	nextMonday.PayoutStartUnix = mondayStart.Add(7 * 24 * time.Hour).Unix()
	nextMonday.PayoutEndUnix = mondayStart.Add(14 * 24 * time.Hour).Unix()
	if _, err := k.CreateAccrual(nextMonday); err != nil {
		t.Fatalf("expected next Monday accrual to succeed, got %v", err)
	}
}

func TestKeeperCreateAccrualValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "acc-1",
		SessionID:  "sess-1",
		AssetDenom: "uusdc",
		Amount:     10,
	})
	if err == nil {
		t.Fatal("expected validation error for missing provider id")
	}
}

func TestKeeperRecordDistributionDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "acc-1",
		SessionID:  "sess-1",
		ProviderID: "provider-1",
		AssetDenom: "uusdc",
		Amount:     20,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}
	if accrual.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf("expected initial operation state %q, got %q", chaintypes.ReconciliationPending, accrual.OperationState)
	}

	input := types.DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      "acc-1",
		PayoutRef:      "payout-1",
	}

	recorded, err := k.RecordDistribution(input)
	if err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}
	if recorded.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected status %q, got %q", chaintypes.ReconciliationSubmitted, recorded.Status)
	}

	idempotent, err := k.RecordDistribution(input)
	if err != nil {
		t.Fatalf("RecordDistribution idempotent call returned unexpected error: %v", err)
	}
	if idempotent != recorded {
		t.Fatalf("expected idempotent result to match recorded distribution, got %+v vs %+v", idempotent, recorded)
	}

	explicitSubmitted := input
	explicitSubmitted.Status = chaintypes.ReconciliationSubmitted
	idempotent, err = k.RecordDistribution(explicitSubmitted)
	if err != nil {
		t.Fatalf("RecordDistribution explicit submitted idempotent call returned unexpected error: %v", err)
	}
	if idempotent != recorded {
		t.Fatalf("expected explicit submitted result to match recorded distribution, got %+v vs %+v", idempotent, recorded)
	}
}

func TestKeeperRecordDistributionFailsSafeWhenAccrualAdvanceWriteFails(t *testing.T) {
	t.Parallel()

	store := newFailSafeDistributionStore()
	k := NewKeeperWithStore(store)

	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "acc-failsafe-accrual-write",
		SessionID:      "sess-failsafe-accrual-write",
		ProviderID:     "provider-failsafe-accrual-write",
		AssetDenom:     "uusdc",
		Amount:         20,
		OperationState: chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	store.failAccrualUpserts = 1

	_, err = k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-failsafe-accrual-write",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-failsafe-accrual-write",
	})
	if err == nil {
		t.Fatal("expected RecordDistribution to fail when accrual advancement write fails")
	}
	if !strings.Contains(err.Error(), "persist accrual") {
		t.Fatalf("expected accrual persistence failure, got %v", err)
	}

	if _, ok := k.GetDistribution("dist-failsafe-accrual-write"); ok {
		t.Fatal("expected no distribution to be persisted when accrual advancement write fails")
	}

	accrualAfter, ok := k.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatalf("expected accrual %q to remain available", accrual.AccrualID)
	}
	if accrualAfter.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf(
			"expected accrual state %q to remain unchanged after failed record, got %q",
			chaintypes.ReconciliationPending,
			accrualAfter.OperationState,
		)
	}
}

func TestKeeperRecordDistributionRollsBackAccrualAdvanceWhenDistributionWriteFails(t *testing.T) {
	t.Parallel()

	store := newFailSafeDistributionStore()
	k := NewKeeperWithStore(store)

	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "acc-failsafe-distribution-write",
		SessionID:      "sess-failsafe-distribution-write",
		ProviderID:     "provider-failsafe-distribution-write",
		AssetDenom:     "uusdc",
		Amount:         20,
		OperationState: chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	store.failDistributionUpserts = 1

	_, err = k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-failsafe-distribution-write",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-failsafe-distribution-write",
	})
	if err == nil {
		t.Fatal("expected RecordDistribution to fail when distribution write fails")
	}
	if !strings.Contains(err.Error(), "persist distribution") {
		t.Fatalf("expected distribution persistence failure, got %v", err)
	}

	if _, ok := k.GetDistribution("dist-failsafe-distribution-write"); ok {
		t.Fatal("expected failed distribution write to leave no stored distribution")
	}

	accrualAfter, ok := k.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatalf("expected accrual %q to remain available", accrual.AccrualID)
	}
	if accrualAfter.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf(
			"expected accrual state %q after rollback, got %q",
			chaintypes.ReconciliationPending,
			accrualAfter.OperationState,
		)
	}
}

func TestKeeperRecordDistributionConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "acc-1",
		SessionID:  "sess-1",
		ProviderID: "provider-1",
		AssetDenom: "uusdc",
		Amount:     20,
	}); err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	initial := types.DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      "acc-1",
		PayoutRef:      "payout-1",
	}
	if _, err := k.RecordDistribution(initial); err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.PayoutRef = "payout-2"
	_, err := k.RecordDistribution(conflict)
	if err == nil {
		t.Fatal("expected conflict error for distribution with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperRecordDistributionRejectsDuplicateAccrualWithDifferentDistributionID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "acc-dup-1",
		SessionID:  "sess-dup-1",
		ProviderID: "provider-dup-1",
		AssetDenom: "uusdc",
		Amount:     20,
	}); err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	if _, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-dup-1",
		AccrualID:      "acc-dup-1",
		PayoutRef:      "payout-dup-1",
	}); err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}

	_, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-dup-2",
		AccrualID:      "acc-dup-1",
		PayoutRef:      "payout-dup-2",
	})
	if err == nil {
		t.Fatal("expected conflict for second distribution id on same accrual")
	}
	if !strings.Contains(err.Error(), "accrual_id") {
		t.Fatalf("expected accrual_id conflict detail, got: %v", err)
	}
}

func TestKeeperRecordDistributionValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-1",
	})
	if err == nil {
		t.Fatal("expected validation error for missing accrual id")
	}
}

func TestKeeperRecordDistributionRejectsMissingPayoutRefWithoutAdvancingAccrual(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "acc-missing-payout-ref",
		SessionID:      "sess-missing-payout-ref",
		ProviderID:     "provider-missing-payout-ref",
		AssetDenom:     "uusdc",
		Amount:         20,
		OperationState: chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	_, err = k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-missing-payout-ref",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      " \t ",
	})
	if err == nil {
		t.Fatal("expected missing payout ref validation error")
	}
	if !strings.Contains(err.Error(), "payout ref is required") {
		t.Fatalf("expected payout ref validation error, got %v", err)
	}

	if _, ok := k.GetDistribution("dist-missing-payout-ref"); ok {
		t.Fatal("expected rejected distribution to not be persisted")
	}

	accrualAfter, ok := k.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatalf("expected accrual %q to remain available", accrual.AccrualID)
	}
	if accrualAfter.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf(
			"expected accrual state %q to remain unchanged after payout-ref rejection, got %q",
			chaintypes.ReconciliationPending,
			accrualAfter.OperationState,
		)
	}
}

func TestKeeperRecordDistributionMissingAccrual(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      "missing",
		PayoutRef:      "payout-1",
	})
	if err == nil {
		t.Fatal("expected missing accrual error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected not found error, got: %v", err)
	}
}

func TestKeeperRecordDistributionAdvancesAccrualState(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		initial                chaintypes.ReconciliationStatus
		distributionStatus     chaintypes.ReconciliationStatus
		allowFinalityAuthority bool
		expectAfter            chaintypes.ReconciliationStatus
	}{
		{
			name:        "pending advances to submitted",
			initial:     chaintypes.ReconciliationPending,
			expectAfter: chaintypes.ReconciliationSubmitted,
		},
		{
			name:        "submitted remains submitted",
			initial:     chaintypes.ReconciliationSubmitted,
			expectAfter: chaintypes.ReconciliationSubmitted,
		},
		{
			name:                   "confirmed distribution confirms accrual with finality authority",
			initial:                chaintypes.ReconciliationSubmitted,
			distributionStatus:     chaintypes.ReconciliationConfirmed,
			allowFinalityAuthority: true,
			expectAfter:            chaintypes.ReconciliationConfirmed,
		},
		{
			name:                   "failed distribution fails accrual with finality authority",
			initial:                chaintypes.ReconciliationSubmitted,
			distributionStatus:     chaintypes.ReconciliationFailed,
			allowFinalityAuthority: true,
			expectAfter:            chaintypes.ReconciliationFailed,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			k := NewKeeper()
			accrual, err := k.CreateAccrual(types.RewardAccrual{
				AccrualID:      "acc-1",
				SessionID:      "sess-1",
				ProviderID:     "provider-1",
				AssetDenom:     "uusdc",
				Amount:         20,
				OperationState: tc.initial,
			})
			if err != nil {
				t.Fatalf("CreateAccrual returned unexpected error: %v", err)
			}
			if accrual.OperationState != tc.initial {
				t.Fatalf("expected initial state %q, got %q", tc.initial, accrual.OperationState)
			}

			distribution := types.DistributionRecord{
				DistributionID: "dist-1",
				AccrualID:      accrual.AccrualID,
				PayoutRef:      "payout-1",
				Status:         tc.distributionStatus,
			}
			if tc.allowFinalityAuthority {
				_, err = k.RecordDistributionWithFinalityAuthority(distribution)
			} else {
				_, err = k.RecordDistribution(distribution)
			}
			if err != nil {
				t.Fatalf("RecordDistribution returned unexpected error: %v", err)
			}

			updated, ok := k.GetAccrual(accrual.AccrualID)
			if !ok {
				t.Fatal("expected accrual to exist after distribution recording")
			}
			if updated.OperationState != tc.expectAfter {
				t.Fatalf("expected accrual state %q after distribution, got %q", tc.expectAfter, updated.OperationState)
			}
		})
	}
}

func TestKeeperRecordDistributionRejectsNewTerminalWithoutFinalityAuthority(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "acc-terminal-new",
		SessionID:      "sess-terminal-new",
		ProviderID:     "provider-terminal-new",
		AssetDenom:     "uusdc",
		Amount:         20,
		OperationState: chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	_, err = k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-terminal-new",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-terminal-new",
		Status:         chaintypes.ReconciliationConfirmed,
	})
	if err == nil {
		t.Fatal("expected new terminal distribution without finality authority to fail")
	}
	if !strings.Contains(err.Error(), "requires finality authority") {
		t.Fatalf("expected finality authority error, got %v", err)
	}
	if _, ok := k.GetDistribution("dist-terminal-new"); ok {
		t.Fatal("expected rejected terminal distribution to not be persisted")
	}

	updated, ok := k.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatal("expected accrual to remain available")
	}
	if updated.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf("expected accrual to remain pending, got %q", updated.OperationState)
	}
}

func TestKeeperRecordDistributionFinalityAuthorityTransitionsStatusOnly(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "acc-finality-transition",
		SessionID:      "sess-finality-transition",
		ProviderID:     "provider-finality-transition",
		AssetDenom:     "uusdc",
		Amount:         20,
		OperationState: chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}
	initial := types.DistributionRecord{
		DistributionID: "dist-finality-transition",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-finality-transition",
		DistributedAt:  1777248001,
		Status:         chaintypes.ReconciliationSubmitted,
	}
	if _, err := k.RecordDistribution(initial); err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}

	confirmed := initial
	confirmed.Status = chaintypes.ReconciliationConfirmed
	if _, err := k.RecordDistribution(confirmed); err == nil {
		t.Fatal("expected normal RecordDistribution to reject status-only finality change")
	}
	recorded, err := k.RecordDistributionWithFinalityAuthority(confirmed)
	if err != nil {
		t.Fatalf("RecordDistributionWithFinalityAuthority returned unexpected error: %v", err)
	}
	if recorded.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected distribution status confirmed, got %q", recorded.Status)
	}
	updatedAccrual, ok := k.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatal("expected accrual after finality")
	}
	if updatedAccrual.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected accrual state confirmed, got %q", updatedAccrual.OperationState)
	}

	replayed, err := k.RecordDistributionWithFinalityAuthority(confirmed)
	if err != nil {
		t.Fatalf("finality replay returned unexpected error: %v", err)
	}
	if !distributionRecordsEqual(replayed, confirmed.Canonicalize()) {
		t.Fatalf("unexpected finality replay record: got=%+v want=%+v", replayed, confirmed.Canonicalize())
	}

	failed := confirmed
	failed.Status = chaintypes.ReconciliationFailed
	if _, err := k.RecordDistributionWithFinalityAuthority(failed); err == nil {
		t.Fatal("expected terminal-to-terminal finality change to be rejected")
	}
	changedPayoutRef := initial
	changedPayoutRef.Status = chaintypes.ReconciliationFailed
	changedPayoutRef.PayoutRef = "payout-finality-tampered"
	if _, err := k.RecordDistributionWithFinalityAuthority(changedPayoutRef); err == nil {
		t.Fatal("expected finality transition with changed immutable payout ref to be rejected")
	}
}

func TestKeeperCreateAccrualAllowsReplayAfterStateAdvanceWithoutDowngrade(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	input := types.RewardAccrual{
		AccrualID:      "acc-state-advance-replay",
		SessionID:      "sess-state-advance-replay",
		ProviderID:     "provider-state-advance-replay",
		AssetDenom:     "uusdc",
		Amount:         20,
		OperationState: chaintypes.ReconciliationPending,
	}
	accrual, err := k.CreateAccrual(input)
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}
	if _, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-state-advance-replay",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-state-advance-replay",
		Status:         chaintypes.ReconciliationSubmitted,
	}); err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}

	replayed, err := k.CreateAccrual(input)
	if err != nil {
		t.Fatalf("CreateAccrual replay after state advance returned unexpected error: %v", err)
	}
	if replayed.OperationState != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected replay to preserve submitted state, got %q", replayed.OperationState)
	}
}

func TestKeeperCreateAccrualCanonicalCreateReplayGetAndList(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	created, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "  ACC-Canon-1 ",
		SessionID:      " Session-Canon-1 ",
		ProviderID:     " Provider-Canon-1 ",
		AssetDenom:     " UUSDC ",
		Amount:         35,
		OperationState: " PENDING ",
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}
	if created.AccrualID != "acc-canon-1" {
		t.Fatalf("expected canonical accrual id, got %q", created.AccrualID)
	}
	if created.SessionID != "session-canon-1" {
		t.Fatalf("expected canonical session id, got %q", created.SessionID)
	}
	if created.ProviderID != "provider-canon-1" {
		t.Fatalf("expected canonical provider id, got %q", created.ProviderID)
	}
	if created.AssetDenom != "uusdc" {
		t.Fatalf("expected canonical asset denom, got %q", created.AssetDenom)
	}
	if created.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf("expected canonical operation state %q, got %q", chaintypes.ReconciliationPending, created.OperationState)
	}

	replayed, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:      "acc-canon-1",
		SessionID:      "SESSION-CANON-1",
		ProviderID:     "provider-canon-1",
		AssetDenom:     "uusdc",
		Amount:         35,
		OperationState: "pending",
	})
	if err != nil {
		t.Fatalf("CreateAccrual replay returned unexpected error: %v", err)
	}
	if replayed != created {
		t.Fatalf("expected replay result %+v to equal created %+v", replayed, created)
	}

	fromGet, ok := k.GetAccrual("  ACC-CANON-1 ")
	if !ok {
		t.Fatal("expected canonicalized get to find accrual")
	}
	if fromGet != created {
		t.Fatalf("expected canonicalized get result %+v to equal created %+v", fromGet, created)
	}

	listed := k.ListAccruals()
	if len(listed) != 1 {
		t.Fatalf("expected 1 accrual in list, got %d", len(listed))
	}
	if listed[0] != created {
		t.Fatalf("expected listed accrual %+v, got %+v", created, listed[0])
	}
}

func TestKeeperCreateAccrualCanonicalConflictSemantics(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  " Acc-Conflict-1 ",
		SessionID:  "Sess-Conflict-1",
		ProviderID: "Provider-Conflict-1",
		AssetDenom: "UUSDC",
		Amount:     40,
	}); err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	_, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "acc-conflict-1",
		SessionID:  "sess-conflict-1",
		ProviderID: "provider-conflict-1",
		AssetDenom: "uusdc",
		Amount:     40,
	})
	if err != nil {
		t.Fatalf("expected canonical-equivalent replay to be idempotent, got %v", err)
	}

	_, err = k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "  ACC-CONFLICT-1 ",
		SessionID:  "sess-conflict-1",
		ProviderID: "provider-conflict-1",
		AssetDenom: "uatom",
		Amount:     40,
	})
	if err == nil {
		t.Fatal("expected conflict error for canonical ID collision with different canonical payload")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got %v", err)
	}
}

func TestKeeperRecordDistributionCanonicalCreateReplayGetAndList(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	accrual, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  " ACC-CANON-DIST-1 ",
		SessionID:  "sess-canon-dist-1",
		ProviderID: "provider-canon-dist-1",
		AssetDenom: "uusdc",
		Amount:     50,
	})
	if err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	recorded, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: " DIST-CANON-1 ",
		AccrualID:      " ACC-CANON-DIST-1 ",
		PayoutRef:      "payout-canon-1",
		Status:         " SUBMITTED ",
	})
	if err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}
	if recorded.DistributionID != "dist-canon-1" {
		t.Fatalf("expected canonical distribution id, got %q", recorded.DistributionID)
	}
	if recorded.AccrualID != accrual.AccrualID {
		t.Fatalf("expected canonical accrual id %q, got %q", accrual.AccrualID, recorded.AccrualID)
	}
	if recorded.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected canonical status %q, got %q", chaintypes.ReconciliationSubmitted, recorded.Status)
	}

	replayed, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-canon-1",
		AccrualID:      "acc-canon-dist-1",
		PayoutRef:      "payout-canon-1",
		Status:         "submitted",
	})
	if err != nil {
		t.Fatalf("RecordDistribution replay returned unexpected error: %v", err)
	}
	if replayed != recorded {
		t.Fatalf("expected replayed distribution %+v to equal recorded %+v", replayed, recorded)
	}

	fromGet, ok := k.GetDistribution(" Dist-Canon-1 ")
	if !ok {
		t.Fatal("expected canonicalized get to find distribution")
	}
	if fromGet != recorded {
		t.Fatalf("expected canonicalized get distribution %+v, got %+v", recorded, fromGet)
	}

	listed := k.ListDistributions()
	if len(listed) != 1 {
		t.Fatalf("expected 1 distribution in list, got %d", len(listed))
	}
	if listed[0] != recorded {
		t.Fatalf("expected listed distribution %+v, got %+v", recorded, listed[0])
	}
}

func TestKeeperRecordDistributionCanonicalConflictSemantics(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "acc-conflict-dist-1",
		SessionID:  "sess-conflict-dist-1",
		ProviderID: "provider-conflict-dist-1",
		AssetDenom: "uusdc",
		Amount:     15,
	}); err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	if _, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: " Dist-Conflict-1 ",
		AccrualID:      " ACC-CONFLICT-DIST-1 ",
		PayoutRef:      "payout-conflict-1",
	}); err != nil {
		t.Fatalf("RecordDistribution returned unexpected error: %v", err)
	}

	_, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-conflict-1",
		AccrualID:      "acc-conflict-dist-1",
		PayoutRef:      "payout-conflict-1",
		Status:         "submitted",
	})
	if err != nil {
		t.Fatalf("expected canonical-equivalent replay to be idempotent, got %v", err)
	}

	_, err = k.RecordDistribution(types.DistributionRecord{
		DistributionID: " DIST-CONFLICT-1 ",
		AccrualID:      " acc-conflict-dist-1 ",
		PayoutRef:      "payout-conflict-2",
	})
	if err == nil {
		t.Fatal("expected conflict error for canonical distribution ID collision with different payload")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got %v", err)
	}
}

func TestKeeperListAccrualsFailsClosedOnCorruptListing(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)
	k := NewKeeperWithStore(store)

	backend.Set(accrualKey("acc-corrupt"), []byte("{"))

	_, err := k.ListAccrualsWithError()
	if err == nil {
		t.Fatal("expected list accruals to fail closed on corrupt listing")
	}
	if !strings.Contains(err.Error(), "load accruals") {
		t.Fatalf("expected accrual load error context, got: %v", err)
	}

	if list := k.ListAccruals(); list != nil {
		t.Fatalf("expected fail-closed ListAccruals fallback to return nil, got %+v", list)
	}
}

func TestKeeperRecordDistributionFailsClosedOnCorruptDistributionListing(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)
	k := NewKeeperWithStore(store)

	if _, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "acc-corrupt-dist",
		SessionID:  "sess-corrupt-dist",
		ProviderID: "provider-corrupt-dist",
		AssetDenom: "uusdc",
		Amount:     20,
	}); err != nil {
		t.Fatalf("CreateAccrual returned unexpected error: %v", err)
	}

	backend.Set(distributionKey("dist-corrupt"), []byte("{"))

	_, err := k.RecordDistribution(types.DistributionRecord{
		DistributionID: "dist-new",
		AccrualID:      "acc-corrupt-dist",
		PayoutRef:      "payout-new",
	})
	if err == nil {
		t.Fatal("expected RecordDistribution to fail closed on corrupt distribution listing")
	}
	if !strings.Contains(err.Error(), "load distributions") {
		t.Fatalf("expected distribution load error context, got: %v", err)
	}
}
