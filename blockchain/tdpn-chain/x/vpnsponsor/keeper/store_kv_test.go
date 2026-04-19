package keeper

import (
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	kvtypes "github.com/tdpn/tdpn-chain/types/kv"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestKVStoreUpsertGetList(t *testing.T) {
	t.Parallel()

	store := NewKVStore(kvtypes.NewMapStore())

	authorization := types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
		Status:          chaintypes.ReconciliationPending,
	}
	store.UpsertAuthorization(authorization)

	gotAuthorization, ok := store.GetAuthorization(authorization.AuthorizationID)
	if !ok {
		t.Fatal("expected authorization to exist")
	}
	if gotAuthorization != authorization {
		t.Fatalf("expected authorization %+v, got %+v", authorization, gotAuthorization)
	}

	delegation := types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: authorization.AuthorizationID,
		SponsorID:       authorization.SponsorID,
		AppID:           authorization.AppID,
		EndUserID:       "user-1",
		SessionID:       "sess-1",
		Credits:         10,
		Status:          chaintypes.ReconciliationSubmitted,
	}
	store.UpsertDelegation(delegation)

	gotDelegation, ok := store.GetDelegation(delegation.ReservationID)
	if !ok {
		t.Fatal("expected delegation to exist")
	}
	if gotDelegation != delegation {
		t.Fatalf("expected delegation %+v, got %+v", delegation, gotDelegation)
	}

	authorizations := store.ListAuthorizations()
	if len(authorizations) != 1 {
		t.Fatalf("expected 1 authorization, got %d", len(authorizations))
	}
	if authorizations[0] != authorization {
		t.Fatalf("expected listed authorization %+v, got %+v", authorization, authorizations[0])
	}

	delegations := store.ListDelegations()
	if len(delegations) != 1 {
		t.Fatalf("expected 1 delegation, got %d", len(delegations))
	}
	if delegations[0] != delegation {
		t.Fatalf("expected listed delegation %+v, got %+v", delegation, delegations[0])
	}
}

func TestKVStoreListOrderingAndSkipsMalformedEntries(t *testing.T) {
	t.Parallel()

	backend := kvtypes.NewMapStore()
	store := NewKVStore(backend)

	store.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-2",
		SponsorID:       "sponsor-kv",
		AppID:           "app-kv",
		MaxCredits:      20,
		Status:          chaintypes.ReconciliationPending,
	})
	store.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-kv",
		AppID:           "app-kv",
		MaxCredits:      10,
		Status:          chaintypes.ReconciliationPending,
	})
	backend.Set([]byte("authorization/bad-json"), []byte("{not-valid-json"))

	store.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "res-2",
		AuthorizationID: "auth-2",
		SponsorID:       "sponsor-kv",
		AppID:           "app-kv",
		SessionID:       "sess-2",
		Credits:         2,
		Status:          chaintypes.ReconciliationSubmitted,
	})
	store.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-kv",
		AppID:           "app-kv",
		SessionID:       "sess-1",
		Credits:         1,
		Status:          chaintypes.ReconciliationSubmitted,
	})
	backend.Set([]byte("delegation/bad-json"), []byte("{not-valid-json"))

	authorizations := store.ListAuthorizations()
	if len(authorizations) != 2 {
		t.Fatalf("expected 2 valid authorizations, got %d", len(authorizations))
	}
	if authorizations[0].AuthorizationID != "auth-1" || authorizations[1].AuthorizationID != "auth-2" {
		t.Fatalf("expected authorization list ordered by key, got %+v", authorizations)
	}
	if _, ok := store.GetAuthorization("bad-json"); ok {
		t.Fatal("expected malformed authorization payload to be rejected by GetAuthorization")
	}

	delegations := store.ListDelegations()
	if len(delegations) != 2 {
		t.Fatalf("expected 2 valid delegations, got %d", len(delegations))
	}
	if delegations[0].ReservationID != "res-1" || delegations[1].ReservationID != "res-2" {
		t.Fatalf("expected delegation list ordered by key, got %+v", delegations)
	}
	if _, ok := store.GetDelegation("bad-json"); ok {
		t.Fatal("expected malformed delegation payload to be rejected by GetDelegation")
	}
}
