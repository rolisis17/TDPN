package keeper

import (
	"math"
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

func TestKeeperCreateAuthorizationCanonicalizationAndLookup(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	input := types.SponsorAuthorization{
		AuthorizationID: "  Auth-1  ",
		SponsorID:       "  Sponsor-1  ",
		AppID:           "  App-1  ",
		MaxCredits:      100,
	}

	created, err := k.CreateAuthorization(input)
	if err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}
	if created.AuthorizationID != "auth-1" {
		t.Fatalf("expected canonical authorization id %q, got %q", "auth-1", created.AuthorizationID)
	}
	if created.SponsorID != "sponsor-1" {
		t.Fatalf("expected canonical sponsor id %q, got %q", "sponsor-1", created.SponsorID)
	}
	if created.AppID != "app-1" {
		t.Fatalf("expected canonical app id %q, got %q", "app-1", created.AppID)
	}

	replay := types.SponsorAuthorization{
		AuthorizationID: "AUTH-1",
		SponsorID:       "sponsor-1",
		AppID:           "APP-1",
		MaxCredits:      100,
	}

	idempotent, err := k.CreateAuthorization(replay)
	if err != nil {
		t.Fatalf("CreateAuthorization replay returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent replay to match created record, got %+v vs %+v", idempotent, created)
	}

	got, ok := k.GetAuthorization("  AUTH-1  ")
	if !ok {
		t.Fatal("expected canonicalized authorization lookup to succeed")
	}
	if got != created {
		t.Fatalf("expected canonicalized lookup to return %+v, got %+v", created, got)
	}
}

func TestKeeperCreateAuthorizationCanonicalConflictBoundary(t *testing.T) {
	t.Parallel()

	k := NewKeeper()

	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "Auth-1",
		SponsorID:       "Sponsor-1",
		AppID:           "App-1",
		MaxCredits:      100,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	_, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: " auth-1 ",
		SponsorID:       "sponsor-2",
		AppID:           "app-1",
		MaxCredits:      100,
	})
	if err == nil {
		t.Fatal("expected conflict error for canonical id replay with changed sponsor id")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
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

func TestKeeperDelegateSessionCreditCanonicalizationAndLookup(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "  Auth-1  ",
		SponsorID:       "  Sponsor-1  ",
		AppID:           "  App-1  ",
		MaxCredits:      100,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	input := types.DelegatedSessionCredit{
		ReservationID:   "  Res-1  ",
		AuthorizationID: "  Auth-1  ",
		SponsorID:       "  Sponsor-1  ",
		AppID:           "  App-1  ",
		EndUserID:       "  User-1  ",
		SessionID:       "  Sess-1  ",
		Credits:         10,
	}

	created, err := k.DelegateSessionCredit(input)
	if err != nil {
		t.Fatalf("DelegateSessionCredit returned unexpected error: %v", err)
	}
	if created.ReservationID != "res-1" {
		t.Fatalf("expected canonical reservation id %q, got %q", "res-1", created.ReservationID)
	}
	if created.AuthorizationID != "auth-1" {
		t.Fatalf("expected canonical authorization id %q, got %q", "auth-1", created.AuthorizationID)
	}
	if created.SponsorID != "sponsor-1" {
		t.Fatalf("expected canonical sponsor id %q, got %q", "sponsor-1", created.SponsorID)
	}
	if created.AppID != "app-1" {
		t.Fatalf("expected canonical app id %q, got %q", "app-1", created.AppID)
	}
	if created.EndUserID != "User-1" {
		t.Fatalf("expected trimmed end user id %q, got %q", "User-1", created.EndUserID)
	}
	if created.SessionID != "Sess-1" {
		t.Fatalf("expected trimmed session id %q, got %q", "Sess-1", created.SessionID)
	}

	replay := types.DelegatedSessionCredit{
		ReservationID:   "RES-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "APP-1",
		EndUserID:       "User-1",
		SessionID:       "Sess-1",
		Credits:         10,
	}

	idempotent, err := k.DelegateSessionCredit(replay)
	if err != nil {
		t.Fatalf("DelegateSessionCredit replay returned unexpected error: %v", err)
	}
	if idempotent != created {
		t.Fatalf("expected idempotent replay to match created record, got %+v vs %+v", idempotent, created)
	}

	got, ok := k.GetDelegation("  RES-1  ")
	if !ok {
		t.Fatal("expected canonicalized delegation lookup to succeed")
	}
	if got != created {
		t.Fatalf("expected canonicalized lookup to return %+v, got %+v", created, got)
	}
}

func TestKeeperDelegateSessionCreditCanonicalConflictBoundaryForSessionCase(t *testing.T) {
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
		ReservationID:   "Res-1",
		AuthorizationID: "Auth-1",
		SponsorID:       "Sponsor-1",
		AppID:           "App-1",
		EndUserID:       "User-1",
		SessionID:       "Sess-1",
		Credits:         10,
	}); err != nil {
		t.Fatalf("DelegateSessionCredit returned unexpected error: %v", err)
	}

	_, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID:   "  res-1  ",
		AuthorizationID: " auth-1 ",
		SponsorID:       " sponsor-1 ",
		AppID:           " app-1 ",
		EndUserID:       "User-1",
		SessionID:       "sess-1",
		Credits:         10,
	})
	if err == nil {
		t.Fatal("expected conflict error for replay with case-distinct session id")
	}
	if !strings.Contains(err.Error(), "conflicting fields") {
		t.Fatalf("expected conflict error message, got: %v", err)
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

	nowUnix := time.Now().Unix()
	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
		ExpiresAtUnix:   nowUnix - 1,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	_, err := k.DelegateSessionCreditAtUnix(types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-1",
		Credits:         10,
	}, nowUnix)
	if err == nil {
		t.Fatal("expected expired authorization error")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired authorization error message, got: %v", err)
	}
}

func TestKeeperDelegateSessionCreditCurrentTimeRequiredForExpiringAuthorization(t *testing.T) {
	t.Parallel()

	nowUnix := time.Now().Unix()
	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
		ExpiresAtUnix:   nowUnix + 100,
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
		t.Fatal("expected current unix time required error")
	}
	if !strings.Contains(err.Error(), "current unix time is required") {
		t.Fatalf("expected current unix time required error message, got: %v", err)
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

func TestKeeperDelegateSessionCreditOverflowSafeCreditsExceeded(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      math.MaxInt64,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	if _, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-1",
		Credits:         math.MaxInt64,
	}); err != nil {
		t.Fatalf("first DelegateSessionCredit returned unexpected error: %v", err)
	}

	_, err := k.DelegateSessionCredit(types.DelegatedSessionCredit{
		ReservationID:   "res-2",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-2",
		Credits:         1,
	})
	if err == nil {
		t.Fatal("expected overflow-safe max credits exceeded error")
	}
	if !strings.Contains(err.Error(), "max credits exceeded") {
		t.Fatalf("expected max credits exceeded error message, got: %v", err)
	}
}

func TestKeeperDelegateSessionCreditAtUnixExpiryPrecedesOverflowWithCanonicalBacklog(t *testing.T) {
	t.Parallel()

	nowUnix := time.Now().Unix()
	k := NewKeeper()
	if _, err := k.CreateAuthorization(types.SponsorAuthorization{
		AuthorizationID: "Auth-1",
		SponsorID:       "Sponsor-1",
		AppID:           "App-1",
		MaxCredits:      math.MaxInt64,
		ExpiresAtUnix:   nowUnix + 10,
	}); err != nil {
		t.Fatalf("CreateAuthorization returned unexpected error: %v", err)
	}

	// Seed a legacy-style backlog entry directly in store to ensure canonicalized overflow accounting.
	k.store.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "LEGACY-RES-1",
		AuthorizationID: " AUTH-1 ",
		SponsorID:       " SPONSOR-1 ",
		AppID:           " APP-1 ",
		SessionID:       "sess-legacy",
		Credits:         math.MaxInt64,
	})

	_, err := k.DelegateSessionCreditAtUnix(types.DelegatedSessionCredit{
		ReservationID:   "res-2",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-2",
		Credits:         1,
	}, nowUnix+1)
	if err == nil {
		t.Fatal("expected max credits exceeded error before authorization expiry")
	}
	if !strings.Contains(err.Error(), "max credits exceeded") {
		t.Fatalf("expected max credits exceeded error message, got: %v", err)
	}

	_, err = k.DelegateSessionCreditAtUnix(types.DelegatedSessionCredit{
		ReservationID:   "res-3",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		SessionID:       "sess-3",
		Credits:         1,
	}, nowUnix+10)
	if err == nil {
		t.Fatal("expected expired authorization error at expiry boundary")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired authorization error message, got: %v", err)
	}

	list := k.ListDelegations()
	if len(list) != 1 {
		t.Fatalf("expected failed delegations to leave backlog unchanged, got %d records", len(list))
	}
	if list[0].ReservationID != "legacy-res-1" {
		t.Fatalf("expected canonical reservation id %q, got %q", "legacy-res-1", list[0].ReservationID)
	}
	if list[0].AuthorizationID != "auth-1" {
		t.Fatalf("expected canonical authorization id %q, got %q", "auth-1", list[0].AuthorizationID)
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

func TestKeeperUpsertAuthorizationCanonicalLookupContract(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "  Auth-Legacy-1  ",
		SponsorID:       "  Sponsor-Legacy-1  ",
		AppID:           "  App-Legacy-1  ",
		MaxCredits:      250,
	})

	got, ok := k.GetAuthorization("auth-legacy-1")
	if !ok {
		t.Fatal("expected canonical authorization lookup to succeed for upserted legacy-case id")
	}
	if got.AuthorizationID != "auth-legacy-1" {
		t.Fatalf("expected canonical authorization id %q, got %q", "auth-legacy-1", got.AuthorizationID)
	}
	if got.SponsorID != "sponsor-legacy-1" {
		t.Fatalf("expected canonical sponsor id %q, got %q", "sponsor-legacy-1", got.SponsorID)
	}
	if got.AppID != "app-legacy-1" {
		t.Fatalf("expected canonical app id %q, got %q", "app-legacy-1", got.AppID)
	}
}

func TestKeeperUpsertDelegationCanonicalLookupContract(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "  Res-Legacy-1  ",
		AuthorizationID: "  Auth-Legacy-1  ",
		SponsorID:       "  Sponsor-Legacy-1  ",
		AppID:           "  App-Legacy-1  ",
		EndUserID:       "  EndUser-Legacy-1  ",
		SessionID:       "  Session-Legacy-1  ",
		Credits:         42,
	})

	got, ok := k.GetDelegation("res-legacy-1")
	if !ok {
		t.Fatal("expected canonical delegation lookup to succeed for upserted legacy-case id")
	}
	if got.ReservationID != "res-legacy-1" {
		t.Fatalf("expected canonical reservation id %q, got %q", "res-legacy-1", got.ReservationID)
	}
	if got.AuthorizationID != "auth-legacy-1" {
		t.Fatalf("expected canonical authorization id %q, got %q", "auth-legacy-1", got.AuthorizationID)
	}
	if got.SponsorID != "sponsor-legacy-1" {
		t.Fatalf("expected canonical sponsor id %q, got %q", "sponsor-legacy-1", got.SponsorID)
	}
	if got.AppID != "app-legacy-1" {
		t.Fatalf("expected canonical app id %q, got %q", "app-legacy-1", got.AppID)
	}
	if got.EndUserID != "EndUser-Legacy-1" {
		t.Fatalf("expected trimmed end user id %q, got %q", "EndUser-Legacy-1", got.EndUserID)
	}
	if got.SessionID != "Session-Legacy-1" {
		t.Fatalf("expected trimmed session id %q, got %q", "Session-Legacy-1", got.SessionID)
	}
}
