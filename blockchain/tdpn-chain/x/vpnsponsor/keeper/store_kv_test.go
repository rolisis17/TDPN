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
