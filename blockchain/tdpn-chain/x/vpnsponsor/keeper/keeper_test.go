package keeper

import (
	"strings"
	"testing"
	"time"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestKeeperAuthorizationUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetAuthorization("missing"); ok {
		t.Fatal("expected missing authorization lookup to return ok=false")
	}

	initial := types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}
	k.UpsertAuthorization(initial)

	got, ok := k.GetAuthorization(initial.AuthorizationID)
	if !ok {
		t.Fatal("expected inserted authorization to be found")
	}
	if got.MaxCredits != initial.MaxCredits {
		t.Fatalf("expected max credits %d, got %d", initial.MaxCredits, got.MaxCredits)
	}

	updated := initial
	updated.MaxCredits = 300
	k.UpsertAuthorization(updated)

	got, ok = k.GetAuthorization(initial.AuthorizationID)
	if !ok {
		t.Fatal("expected updated authorization to be found")
	}
	if got.MaxCredits != updated.MaxCredits {
		t.Fatalf("expected updated max credits %d, got %d", updated.MaxCredits, got.MaxCredits)
	}
}

func TestKeeperDelegationUpsertAndGet(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, ok := k.GetDelegation("missing"); ok {
		t.Fatal("expected missing delegation lookup to return ok=false")
	}

	initial := types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-1",
		Credits:         10,
	}
	k.UpsertDelegation(initial)

	got, ok := k.GetDelegation(initial.ReservationID)
	if !ok {
		t.Fatal("expected inserted delegation to be found")
	}
	if got.Credits != initial.Credits {
		t.Fatalf("expected credits %d, got %d", initial.Credits, got.Credits)
	}

	updated := initial
	updated.Credits = 20
	k.UpsertDelegation(updated)

	got, ok = k.GetDelegation(initial.ReservationID)
	if !ok {
		t.Fatal("expected updated delegation to be found")
	}
	if got.Credits != updated.Credits {
		t.Fatalf("expected updated credits %d, got %d", updated.Credits, got.Credits)
	}
}

func TestKeeperCreateAuthorizationDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	input := types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}

	created, err := k.CreateAuthorization(input)
	if err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, created.Status)
	}

	idempotent, err := k.CreateAuthorization(input)
	if err != nil {
		t.Fatalf("CreateAuthorization idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent result to match created record, got %+v vs %+v", idempotent, created)
	}

	explicitPending := input
	explicitPending.Status = chaintypes.ReconciliationPending
	idempotent, err = k.CreateAuthorization(explicitPending)
	if err != nil {
		t.Fatalf("CreateAuthorization explicit pending call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected explicit pending result to match created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperCreateAuthorizationConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	initial := types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}
	if _, err := k.CreateAuthorization(initial); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.MaxCredits = 200
	_, err := k.CreateAuthorization(conflict)
	if err == nil {
		t.Fatal("expected conflict error for authorization with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperCreateAuthorizationValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		AppID:           "app-1",
		MaxCredits:      100,
	})
	if err == nil {
		t.Fatal("expected validation error for missing sponsor id")
	}
}

func TestKeeperDelegateSessionCreditDefaultsAndIdempotency(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	input := types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		EndUserID:       "user-1",
		SessionID:       "sess-1",
		Credits:         10,
	}

	created, err := k.DelegateSessionCredit(input)
	if err != nil {
		t.Fatalf("DelegateSessionCredit returned unexpected error: %v", err)
	}
	if created.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default status %q, got %q", chaintypes.ReconciliationPending, created.Status)
	}

	idempotent, err := k.DelegateSessionCredit(input)
	if err != nil {
		t.Fatalf("DelegateSessionCredit idempotent call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent result to match created record, got %+v vs %+v", idempotent, created)
	}

	explicitPending := input
	explicitPending.Status = chaintypes.ReconciliationPending
	idempotent, err = k.DelegateSessionCredit(explicitPending)
	if err != nil {
		t.Fatalf("DelegateSessionCredit explicit pending call returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected explicit pending result to match created record, got %+v vs %+v", idempotent, created)
	}
}

func TestKeeperDelegateSessionCreditConflict(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	initial := types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-1",
		Credits:         10,
	}
	if _, err := k.DelegateSessionCredit(initial); err != nil {
		t.Fatalf("DelegateSessionCredit returned unexpected error: %v", err)
	}

	conflict := initial
	conflict.Credits = 20
	_, err := k.DelegateSessionCredit(conflict)
	if err == nil {
		t.Fatal("expected conflict error for delegation with same id but different fields")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
	}
}

func TestKeeperDelegateSessionCreditValidation(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID: "res-1",
		SponsorID:     "sponsor-1",
		SessionID:     "sess-1",
		Credits:       10,
	})
	if err == nil {
		t.Fatal("expected validation error for missing authorization id")
	}
}

func TestKeeperDelegateSessionCreditMissingAuthorization(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	_, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "missing",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-1",
		Credits:         10,
	})
	if err == nil {
		t.Fatal("expected missing authorization error")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Fatalf("expected missing authorization error message, got: %v", err)
	}
}

func TestKeeperDelegateSessionCreditAuthorizationLinkageMismatch(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	_, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-other",
		AppID:           "app-1",
		SessionID:       "sess-1",
		Credits:         10,
	})
	if err == nil {
		t.Fatal("expected linkage mismatch error")
	}
	if !strings.Contains(err.Error(), "linkage does not match") {
		t.Fatalf("expected linkage mismatch error message, got: %v", err)
	}
}

func TestKeeperDelegateSessionCreditExpiredAuthorization(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
		ExpiresAtUnix:   time.Now().Unix() - 1,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	_, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-1",
		Credits:         10,
	})
	if err == nil {
		t.Fatal("expected expired authorization error")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired authorization error message, got: %v", err)
	}
}

func TestKeeperDelegateSessionCreditMaxCreditsExceeded(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	if _, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-1",
		Credits:         60,
	}); err != nil {
		t.Fatalf("first DelegateSessionCredit returned unexpected error: %v", err)
	}

	_, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID:   "res-2",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-2",
		Credits:         41,
	})
	if err == nil {
		t.Fatal("expected max credits exceeded error")
	}
	if !strings.Contains(err.Error(), "max credits exceeded") {
		t.Fatalf("expected max credits exceeded error message, got: %v", err)
	}
}

func TestKeeperListAuthorizationsDeterministicByAuthorizationID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-3",
		SponsorID:       "sponsor-3",
		AppID:           "app-3",
		MaxCredits:      300,
	})
	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	})
	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-2",
		SponsorID:       "sponsor-2",
		AppID:           "app-2",
		MaxCredits:      200,
	})

	list := k.ListAuthorizations()
	if len(list) != 3 {
		t.Fatalf("expected 3 authorizations, got %d", len(list))
	}
	if list[0].AuthorizationID != "auth-1" || list[1].AuthorizationID != "auth-2" || list[2].AuthorizationID != "auth-3" {
		t.Fatalf(
			"expected authorizations sorted by AuthorizationID asc, got [%s, %s, %s]",
			list[0].AuthorizationID,
			list[1].AuthorizationID,
			list[2].AuthorizationID,
		)
	}
}

func TestKeeperListDelegationsDeterministicByReservationID(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "res-3",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-3",
		Credits:         30,
	})
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-1",
		Credits:         10,
	})
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "res-2",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-2",
		Credits:         20,
	})

	list := k.ListDelegations()
	if len(list) != 3 {
		t.Fatalf("expected 3 delegations, got %d", len(list))
	}
	if list[0].ReservationID != "res-1" || list[1].ReservationID != "res-2" || list[2].ReservationID != "res-3" {
		t.Fatalf(
			"expected delegations sorted by ReservationID asc, got [%s, %s, %s]",
			list[0].ReservationID,
			list[1].ReservationID,
			list[2].ReservationID,
		)
	}
}
