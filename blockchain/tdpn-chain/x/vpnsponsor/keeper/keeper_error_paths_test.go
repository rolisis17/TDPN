package keeper

import (
	"path/filepath"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestKeeperListWithErrorNormalizesAndSorts(t *testing.T) {
	t.Parallel()

	k := NewKeeper()
	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "  Auth-2  ",
		SponsorID:       "  Sponsor-2  ",
		AppID:           "  App-2  ",
		MaxCredits:      20,
	})
	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "  Auth-1  ",
		SponsorID:       "  Sponsor-1  ",
		AppID:           "  App-1  ",
		MaxCredits:      10,
	})
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "  Res-2  ",
		AuthorizationID: "  Auth-2  ",
		SponsorID:       "  Sponsor-2  ",
		AppID:           "  App-2  ",
		EndUserID:       "  User-2  ",
		SessionID:       "  Session-2  ",
		Credits:         2,
	})
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "  Res-1  ",
		AuthorizationID: "  Auth-1  ",
		SponsorID:       "  Sponsor-1  ",
		AppID:           "  App-1  ",
		EndUserID:       "  User-1  ",
		SessionID:       "  Session-1  ",
		Credits:         1,
	})

	authorizations, err := k.ListAuthorizationsWithError()
	if err != nil {
		t.Fatalf("ListAuthorizationsWithError returned unexpected error: %v", err)
	}
	if len(authorizations) != 2 {
		t.Fatalf("expected 2 authorizations, got %d", len(authorizations))
	}
	if authorizations[0].AuthorizationID != "auth-1" || authorizations[1].AuthorizationID != "auth-2" {
		t.Fatalf("expected normalized sorted authorization ids, got %+v", authorizations)
	}
	if authorizations[0].Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default authorization status %q, got %q", chaintypes.ReconciliationPending, authorizations[0].Status)
	}

	delegations, err := k.ListDelegationsWithError()
	if err != nil {
		t.Fatalf("ListDelegationsWithError returned unexpected error: %v", err)
	}
	if len(delegations) != 2 {
		t.Fatalf("expected 2 delegations, got %d", len(delegations))
	}
	if delegations[0].ReservationID != "res-1" || delegations[1].ReservationID != "res-2" {
		t.Fatalf("expected normalized sorted delegation ids, got %+v", delegations)
	}
	if delegations[0].Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected default delegation status %q, got %q", chaintypes.ReconciliationPending, delegations[0].Status)
	}
}

func TestKeeperListWithErrorFallsBackForStoresWithoutStrictReads(t *testing.T) {
	t.Parallel()

	store := newTrackingStore()
	k := NewKeeperWithStore(store)
	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-legacy-read-2",
		SponsorID:       "sponsor-legacy-read",
		AppID:           "app-legacy-read",
		MaxCredits:      20,
	})
	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-legacy-read-1",
		SponsorID:       "sponsor-legacy-read",
		AppID:           "app-legacy-read",
		MaxCredits:      10,
	})
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "res-legacy-read-2",
		AuthorizationID: "auth-legacy-read-2",
		SponsorID:       "sponsor-legacy-read",
		AppID:           "app-legacy-read",
		SessionID:       "session-legacy-read-2",
		Credits:         2,
	})
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "res-legacy-read-1",
		AuthorizationID: "auth-legacy-read-1",
		SponsorID:       "sponsor-legacy-read",
		AppID:           "app-legacy-read",
		SessionID:       "session-legacy-read-1",
		Credits:         1,
	})

	authorizations, err := k.ListAuthorizationsWithError()
	if err != nil {
		t.Fatalf("ListAuthorizationsWithError returned unexpected error: %v", err)
	}
	if len(authorizations) != 2 || authorizations[0].AuthorizationID != "auth-legacy-read-1" {
		t.Fatalf("expected sorted fallback authorization list, got %+v", authorizations)
	}
	if store.listAuthorizationCalls == 0 {
		t.Fatal("expected fallback path to list authorizations through the custom store")
	}

	delegations, err := k.ListDelegationsWithError()
	if err != nil {
		t.Fatalf("ListDelegationsWithError returned unexpected error: %v", err)
	}
	if len(delegations) != 2 || delegations[0].ReservationID != "res-legacy-read-1" {
		t.Fatalf("expected sorted fallback delegation list, got %+v", delegations)
	}
	if store.listDelegationCalls == 0 {
		t.Fatal("expected fallback path to list delegations through the custom store")
	}
}

func TestKeeperListAuthorizationsWithErrorFailsClosedOnMalformedKVSnapshot(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	k := NewKeeperWithStore(NewKVStore(backend))
	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-good",
		SponsorID:       "sponsor-good",
		AppID:           "app-good",
		MaxCredits:      10,
	})
	backend.Set([]byte("authorization/bad-json"), []byte("{not-valid-json"))

	records, err := k.ListAuthorizationsWithError()
	if err == nil {
		t.Fatal("expected malformed authorization snapshot to fail strict listing")
	}
	if records != nil {
		t.Fatalf("expected no records on strict authorization decode failure, got %+v", records)
	}
	if !strings.Contains(err.Error(), "load authorizations") {
		t.Fatalf("expected load authorizations error, got: %v", err)
	}
}

func TestKeeperListDelegationsWithErrorFailsClosedOnMalformedKVSnapshot(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	k := NewKeeperWithStore(NewKVStore(backend))
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "res-good",
		AuthorizationID: "auth-good",
		SponsorID:       "sponsor-good",
		AppID:           "app-good",
		SessionID:       "session-good",
		Credits:         10,
	})
	backend.Set([]byte("delegation/bad-json"), []byte("{not-valid-json"))

	records, err := k.ListDelegationsWithError()
	if err == nil {
		t.Fatal("expected malformed delegation snapshot to fail strict listing")
	}
	if records != nil {
		t.Fatalf("expected no records on strict delegation decode failure, got %+v", records)
	}
	if !strings.Contains(err.Error(), "load delegations") {
		t.Fatalf("expected load delegations error, got: %v", err)
	}
}

func TestFileStorePersistErrorRollsBackAuthorizationAndDelegation(t *testing.T) {
	t.Parallel()

	store, err := NewFileStore(filepath.Join(t.TempDir(), "vpnsponsor.json"))
	if err != nil {
		t.Fatalf("NewFileStore returned unexpected error: %v", err)
	}

	initialAuth := types.SponsorAuthorization{
		AuthorizationID: "auth-existing",
		SponsorID:       "sponsor-existing",
		AppID:           "app-existing",
		MaxCredits:      100,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	if err := store.UpsertAuthorizationWithError(initialAuth); err != nil {
		t.Fatalf("seed authorization returned unexpected error: %v", err)
	}

	initialDelegation := types.DelegatedSessionCredit{
		ReservationID:   "res-existing",
		AuthorizationID: initialAuth.AuthorizationID,
		SponsorID:       initialAuth.SponsorID,
		AppID:           initialAuth.AppID,
		EndUserID:       "user-existing",
		SessionID:       "session-existing",
		Credits:         10,
		Status:          chaintypes.ReconciliationConfirmed,
	}
	if err := store.UpsertDelegationWithError(initialDelegation); err != nil {
		t.Fatalf("seed delegation returned unexpected error: %v", err)
	}

	store.path = filepath.Join(t.TempDir(), "\x00vpnsponsor.json")

	newAuth := types.SponsorAuthorization{
		AuthorizationID: "auth-new",
		SponsorID:       "sponsor-new",
		AppID:           "app-new",
		MaxCredits:      50,
		Status:          chaintypes.ReconciliationPending,
	}
	if err := store.UpsertAuthorizationWithError(newAuth); err == nil {
		t.Fatal("expected new authorization persist failure")
	}
	if _, ok := store.GetAuthorization(newAuth.AuthorizationID); ok {
		t.Fatal("expected failed new authorization to be rolled back")
	}

	updatedAuth := initialAuth
	updatedAuth.MaxCredits = 200
	if err := store.UpsertAuthorizationWithError(updatedAuth); err == nil {
		t.Fatal("expected existing authorization persist failure")
	}
	gotAuth, ok := store.GetAuthorization(initialAuth.AuthorizationID)
	if !ok {
		t.Fatal("expected original authorization to remain present")
	}
	if gotAuth != initialAuth {
		t.Fatalf("expected original authorization after rollback, got %+v", gotAuth)
	}

	newDelegation := types.DelegatedSessionCredit{
		ReservationID:   "res-new",
		AuthorizationID: initialAuth.AuthorizationID,
		SponsorID:       initialAuth.SponsorID,
		AppID:           initialAuth.AppID,
		EndUserID:       "user-new",
		SessionID:       "session-new",
		Credits:         5,
		Status:          chaintypes.ReconciliationPending,
	}
	if err := store.UpsertDelegationWithError(newDelegation); err == nil {
		t.Fatal("expected new delegation persist failure")
	}
	if _, ok := store.GetDelegation(newDelegation.ReservationID); ok {
		t.Fatal("expected failed new delegation to be rolled back")
	}

	updatedDelegation := initialDelegation
	updatedDelegation.Credits = 20
	if err := store.UpsertDelegationWithError(updatedDelegation); err == nil {
		t.Fatal("expected existing delegation persist failure")
	}
	gotDelegation, ok := store.GetDelegation(initialDelegation.ReservationID)
	if !ok {
		t.Fatal("expected original delegation to remain present")
	}
	if gotDelegation != initialDelegation {
		t.Fatalf("expected original delegation after rollback, got %+v", gotDelegation)
	}
}
