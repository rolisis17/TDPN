package keeper

import (
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnrewards/types"
)

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

func TestKeeperCreateAccrualValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID: "acc-1",
		SessionID: "sess-1",
		Amount:    10,
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

func TestKeeperRecordDistributionConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAccrual(types.RewardAccrual{
		AccrualID:  "acc-1",
		SessionID:  "sess-1",
		ProviderID: "provider-1",
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
		name        string
		initial     chaintypes.ReconciliationStatus
		expectAfter chaintypes.ReconciliationStatus
	}{
		{
			name:        "pending advances to confirmed",
			initial:     chaintypes.ReconciliationPending,
			expectAfter: chaintypes.ReconciliationConfirmed,
		},
		{
			name:        "submitted advances to confirmed",
			initial:     chaintypes.ReconciliationSubmitted,
			expectAfter: chaintypes.ReconciliationConfirmed,
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
				Amount:         20,
				OperationState: tc.initial,
			})
			if err != nil {
				t.Fatalf("CreateAccrual returned unexpected error: %v", err)
			}
			if accrual.OperationState != tc.initial {
				t.Fatalf("expected initial state %q, got %q", tc.initial, accrual.OperationState)
			}

			_, err = k.RecordDistribution(types.DistributionRecord{
				DistributionID: "dist-1",
				AccrualID:      accrual.AccrualID,
				PayoutRef:      "payout-1",
			})
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
