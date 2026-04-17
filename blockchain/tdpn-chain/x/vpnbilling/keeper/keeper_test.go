package keeper

import (
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnbilling/types"
)

func TestKeeperReservationUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetReservation("missing"); ok {
		t.Fatal("expected missing reservation lookup to return ok=false")
	}

	initial := types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		Amount:        100,
	}
	k.UpsertReservation(initial)

	got, ok := k.GetReservation(initial.ReservationID)
	if !ok {
		t.Fatal("expected inserted reservation to be found")
	}
	if got.Amount != initial.Amount {
		t.Fatalf("expected amount %d, got %d", initial.Amount, got.Amount)
	}

	updated := initial
	updated.Amount = 250
	k.UpsertReservation(updated)

	got, ok = k.GetReservation(initial.ReservationID)
	if !ok {
		t.Fatal("expected updated reservation to be found")
	}
	if got.Amount != updated.Amount {
		t.Fatalf("expected updated amount %d, got %d", updated.Amount, got.Amount)
	}
}

func TestKeeperSettlementUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetSettlement("missing"); ok {
		t.Fatal("expected missing settlement lookup to return ok=false")
	}

	initial := types.SettlementRecord{
		SettlementID: "set-1",
		SessionID:    "sess-1",
		BilledAmount: 50,
	}
	k.UpsertSettlement(initial)

	got, ok := k.GetSettlement(initial.SettlementID)
	if !ok {
		t.Fatal("expected inserted settlement to be found")
	}
	if got.BilledAmount != initial.BilledAmount {
		t.Fatalf("expected billed amount %d, got %d", initial.BilledAmount, got.BilledAmount)
	}

	updated := initial
	updated.BilledAmount = 75
	k.UpsertSettlement(updated)

	got, ok = k.GetSettlement(initial.SettlementID)
	if !ok {
		t.Fatal("expected updated settlement to be found")
	}
	if got.BilledAmount != updated.BilledAmount {
		t.Fatalf("expected updated billed amount %d, got %d", updated.BilledAmount, got.BilledAmount)
	}
}

func TestKeeperCreateReservationDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	input := types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		Amount:        100,
	}

	created, err := k.CreateReservation(input)
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected status %q, got %q", chaintypes.ReconciliationPending, created.Status)
	}

	idempotent, err := k.CreateReservation(input)
	if err != nil {
		t.Fatalf("CreateReservation idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent result to match created record, got %+v vs %+v", idempotent, created)
	}

	explicitPending := input
	explicitPending.Status = chaintypes.ReconciliationPending
	idempotent, err = k.CreateReservation(explicitPending)
	if err != nil {
		t.Fatalf("CreateReservation explicit pending idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected explicit pending result to match created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperCreateReservationConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	initial := types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		Amount:        100,
	}
	if _, err := k.CreateReservation(initial); err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.Amount = 200
	_, err := k.CreateReservation(conflict)
	if err == nil {
		t.Fatal("expected conflict error for reservation with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperCreateReservationValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-1",
		Amount:        100,
	})
	if err == nil {
		t.Fatal("expected validation error for missing session id")
	}
}

func TestKeeperFinalizeSettlementDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	reservation, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		AssetDenom:    "uusdc",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	input := types.SettlementRecord{
		SettlementID:  "set-1",
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		BilledAmount:  50,
		AssetDenom:    reservation.AssetDenom,
	}

	finalized, err := k.FinalizeSettlement(input)
	if err != nil {
		t.Fatalf("FinalizeSettlement returned unexpected error: %v", err)
	}
	if finalized.OperationState != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected operation state %q, got %q", chaintypes.ReconciliationSubmitted, finalized.OperationState)
	}

	idempotent, err := k.FinalizeSettlement(input)
	if err != nil {
		t.Fatalf("FinalizeSettlement idempotent call returned unexpected error: %v", err)
	}
	if idempotent != finalized {
		t.Fatalf("expected idempotent result to match finalized record, got %+v vs %+v", idempotent, finalized)
	}

	explicitSubmitted := input
	explicitSubmitted.OperationState = chaintypes.ReconciliationSubmitted
	idempotent, err = k.FinalizeSettlement(explicitSubmitted)
	if err != nil {
		t.Fatalf("FinalizeSettlement explicit submitted idempotent call returned unexpected error: %v", err)
	}
	if idempotent != finalized {
		t.Fatalf("expected explicit submitted result to match finalized record, got %+v vs %+v", idempotent, finalized)
	}
}

func TestKeeperFinalizeSettlementConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	reservation, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		AssetDenom:    "uusdc",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	initial := types.SettlementRecord{
		SettlementID:  "set-1",
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		BilledAmount:  50,
		AssetDenom:    reservation.AssetDenom,
	}
	if _, err = k.FinalizeSettlement(initial); err != nil {
		t.Fatalf("FinalizeSettlement returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.BilledAmount = 70
	_, err = k.FinalizeSettlement(conflict)
	if err == nil {
		t.Fatal("expected conflict error for settlement with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperFinalizeSettlementRejectsSessionMismatch(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	reservation, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-session-mismatch",
		SessionID:     "sess-a",
		AssetDenom:    "uusdc",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	_, err = k.FinalizeSettlement(types.SettlementRecord{
		SettlementID:  "set-session-mismatch",
		ReservationID: reservation.ReservationID,
		SessionID:     "sess-b",
		BilledAmount:  10,
		AssetDenom:    reservation.AssetDenom,
	})
	if err == nil {
		t.Fatal("expected session mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match reservation session") {
		t.Fatalf("expected session mismatch error message, got: %v", err)
	}
}

func TestKeeperFinalizeSettlementRejectsAssetDenomMismatch(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	reservation, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-denom-mismatch",
		SessionID:     "sess-1",
		AssetDenom:    "uusdc",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	_, err = k.FinalizeSettlement(types.SettlementRecord{
		SettlementID:  "set-denom-mismatch",
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		BilledAmount:  10,
		AssetDenom:    "utdpn",
	})
	if err == nil {
		t.Fatal("expected asset denom mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match reservation asset denom") {
		t.Fatalf("expected asset denom mismatch error message, got: %v", err)
	}
}

func TestKeeperFinalizeSettlementRejectsOvercharge(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	reservation, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-overcharge",
		SessionID:     "sess-1",
		AssetDenom:    "uusdc",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	_, err = k.FinalizeSettlement(types.SettlementRecord{
		SettlementID:  "set-overcharge",
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		BilledAmount:  101,
		AssetDenom:    reservation.AssetDenom,
	})
	if err == nil {
		t.Fatal("expected overcharge error")
	}
	if !strings.Contains(err.Error(), "exceeds reserved amount") {
		t.Fatalf("expected overcharge error message, got: %v", err)
	}
}

func TestKeeperFinalizeSettlementValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.FinalizeSettlement(types.SettlementRecord{
		SettlementID: "set-1",
		BilledAmount: 50,
	})
	if err == nil {
		t.Fatal("expected validation error for missing session id")
	}
}

func TestKeeperFinalizeSettlementAdvancesReservationStatus(t *testing.T) {
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
			reservation, err := k.CreateReservation(types.CreditReservation{
				ReservationID: "res-1",
				SessionID:     "sess-1",
				Amount:        100,
				Status:        tc.initial,
			})
			if err != nil {
				t.Fatalf("CreateReservation returned unexpected error: %v", err)
			}
			if reservation.Status != tc.initial {
				t.Fatalf("expected initial status %q, got %q", tc.initial, reservation.Status)
			}

			_, err = k.FinalizeSettlement(types.SettlementRecord{
				SettlementID:  "set-1",
				ReservationID: reservation.ReservationID,
				SessionID:     reservation.SessionID,
				BilledAmount:  10,
			})
			if err != nil {
				t.Fatalf("FinalizeSettlement returned unexpected error: %v", err)
			}

			updated, ok := k.GetReservation(reservation.ReservationID)
			if !ok {
				t.Fatal("expected reservation to exist after settlement finalization")
			}
			if updated.Status != tc.expectAfter {
				t.Fatalf("expected reservation status %q after finalize, got %q", tc.expectAfter, updated.Status)
			}
		})
	}
}

func TestKeeperListReservationsDeterministicOrder(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	input := []types.CreditReservation{
		{ReservationID: "res-20", SessionID: "sess-20", Amount: 20},
		{ReservationID: "res-01", SessionID: "sess-01", Amount: 1},
		{ReservationID: "res-03", SessionID: "sess-03", Amount: 3},
	}

	for _, record := range input {
		k.UpsertReservation(record)
	}

	list := k.ListReservations()
	if len(list) != len(input) {
		t.Fatalf("expected %d reservations, got %d", len(input), len(list))
	}

	expectedOrder := []string{"res-01", "res-03", "res-20"}
	for i, id := range expectedOrder {
		if list[i].ReservationID != id {
			t.Fatalf("expected reservation[%d] id %q, got %q", i, id, list[i].ReservationID)
		}
	}
}

func TestKeeperListSettlementsDeterministicOrder(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	input := []types.SettlementRecord{
		{SettlementID: "set-20", SessionID: "sess-20", BilledAmount: 20},
		{SettlementID: "set-01", SessionID: "sess-01", BilledAmount: 1},
		{SettlementID: "set-03", SessionID: "sess-03", BilledAmount: 3},
	}

	for _, record := range input {
		k.UpsertSettlement(record)
	}

	list := k.ListSettlements()
	if len(list) != len(input) {
		t.Fatalf("expected %d settlements, got %d", len(input), len(list))
	}

	expectedOrder := []string{"set-01", "set-03", "set-20"}
	for i, id := range expectedOrder {
		if list[i].SettlementID != id {
			t.Fatalf("expected settlement[%d] id %q, got %q", i, id, list[i].SettlementID)
		}
	}
}

func TestKeeperCreateReservationCanonicalizationCreateGetList(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	created, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "  RES-1  ",
		SponsorID:     "  Sponsor-1  ",
		SessionID:     "  Sess-1  ",
		AssetDenom:    "  UUSDC  ",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}
	if created.ReservationID != "res-1" {
		t.Fatalf("expected canonical reservation id %q, got %q", "res-1", created.ReservationID)
	}
	if created.SponsorID != "sponsor-1" {
		t.Fatalf("expected canonical sponsor id %q, got %q", "sponsor-1", created.SponsorID)
	}
	if created.SessionID != "sess-1" {
		t.Fatalf("expected canonical session id %q, got %q", "sess-1", created.SessionID)
	}
	if created.AssetDenom != "uusdc" {
		t.Fatalf("expected canonical denom %q, got %q", "uusdc", created.AssetDenom)
	}

	got, ok := k.GetReservation(" RES-1 ")
	if !ok {
		t.Fatal("expected canonicalized get reservation lookup to succeed")
	}
	if got != created {
		t.Fatalf("expected get result to match created record, got %+v vs %+v", got, created)
	}

	list := k.ListReservations()
	if len(list) != 1 {
		t.Fatalf("expected one reservation in list, got %d", len(list))
	}
	if list[0] != created {
		t.Fatalf("expected listed reservation to be canonicalized created record, got %+v vs %+v", list[0], created)
	}
}

func TestKeeperCreateReservationIdempotentReplayCanonicalVariants(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	first, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-1",
		SponsorID:     "sponsor-a",
		SessionID:     "sess-1",
		AssetDenom:    "uusdc",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	replay, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "  RES-1  ",
		SponsorID:     "  SPONSOR-A  ",
		SessionID:     "  SESS-1  ",
		AssetDenom:    "  UUSDC  ",
		Amount:        100,
		Status:        chaintypes.ReconciliationPending,
	})
	if err != nil {
		t.Fatalf("CreateReservation replay returned unexpected error: %v", err)
	}
	if replay != first {
		t.Fatalf("expected canonical idempotent replay to match first record, got %+v vs %+v", replay, first)
	}
}

func TestKeeperCreateReservationConflictCanonicalBoundary(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-1",
		SponsorID:     "sponsor-a",
		SessionID:     "sess-1",
		AssetDenom:    "uusdc",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	_, err = k.CreateReservation(types.CreditReservation{
		ReservationID: "  RES-1  ",
		SponsorID:     "  SPONSOR-A  ",
		SessionID:     "  SESS-1  ",
		AssetDenom:    "  UUSDC  ",
		Amount:        101,
	})
	if err == nil {
		t.Fatal("expected conflict error for canonicalized reservation id with different amount")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperFinalizeSettlementCanonicalizationCreateGetListAndReplay(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	reservation, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "  RES-1  ",
		SessionID:     "  SESS-1  ",
		AssetDenom:    "  UUSDC  ",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	finalized, err := k.FinalizeSettlement(types.SettlementRecord{
		SettlementID:  "  SET-1  ",
		ReservationID: "  RES-1  ",
		SessionID:     "  SESS-1  ",
		BilledAmount:  50,
		AssetDenom:    "  UUSDC  ",
	})
	if err != nil {
		t.Fatalf("FinalizeSettlement returned unexpected error: %v", err)
	}
	if finalized.SettlementID != "set-1" {
		t.Fatalf("expected canonical settlement id %q, got %q", "set-1", finalized.SettlementID)
	}
	if finalized.ReservationID != reservation.ReservationID {
		t.Fatalf("expected canonical reservation id %q, got %q", reservation.ReservationID, finalized.ReservationID)
	}
	if finalized.SessionID != reservation.SessionID {
		t.Fatalf("expected canonical session id %q, got %q", reservation.SessionID, finalized.SessionID)
	}
	if finalized.AssetDenom != reservation.AssetDenom {
		t.Fatalf("expected canonical denom %q, got %q", reservation.AssetDenom, finalized.AssetDenom)
	}

	got, ok := k.GetSettlement(" SET-1 ")
	if !ok {
		t.Fatal("expected canonicalized get settlement lookup to succeed")
	}
	if got != finalized {
		t.Fatalf("expected get result to match finalized record, got %+v vs %+v", got, finalized)
	}

	list := k.ListSettlements()
	if len(list) != 1 {
		t.Fatalf("expected one settlement in list, got %d", len(list))
	}
	if list[0] != finalized {
		t.Fatalf("expected listed settlement to be canonicalized finalized record, got %+v vs %+v", list[0], finalized)
	}

	replay, err := k.FinalizeSettlement(types.SettlementRecord{
		SettlementID:   "set-1",
		ReservationID:  "res-1",
		SessionID:      "sess-1",
		BilledAmount:   50,
		AssetDenom:     "uusdc",
		OperationState: chaintypes.ReconciliationSubmitted,
	})
	if err != nil {
		t.Fatalf("FinalizeSettlement replay returned unexpected error: %v", err)
	}
	if replay != finalized {
		t.Fatalf("expected canonical idempotent replay to match finalized record, got %+v vs %+v", replay, finalized)
	}
}

func TestKeeperFinalizeSettlementConflictCanonicalBoundary(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	reservation, err := k.CreateReservation(types.CreditReservation{
		ReservationID: "res-1",
		SessionID:     "sess-1",
		AssetDenom:    "uusdc",
		Amount:        100,
	})
	if err != nil {
		t.Fatalf("CreateReservation returned unexpected error: %v", err)
	}

	_, err = k.FinalizeSettlement(types.SettlementRecord{
		SettlementID:  "set-1",
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		BilledAmount:  50,
		AssetDenom:    reservation.AssetDenom,
	})
	if err != nil {
		t.Fatalf("FinalizeSettlement returned unexpected error: %v", err)
	}

	_, err = k.FinalizeSettlement(types.SettlementRecord{
		SettlementID:  "  SET-1  ",
		ReservationID: "  RES-1  ",
		SessionID:     "  SESS-1  ",
		BilledAmount:  51,
		AssetDenom:    "  UUSDC  ",
	})
	if err == nil {
		t.Fatal("expected conflict error for canonicalized settlement id with different billed amount")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}
