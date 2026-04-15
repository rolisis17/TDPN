package module

import (
	"errors"
	"testing"

	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestQueryServerNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	server := NewQueryServer(k)

	_, authorizationErr := server.GetAuthorization(GetAuthorizationRequest{AuthorizationID: "auth-nil"})
	if !errors.Is(authorizationErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for authorization query, got %v", authorizationErr)
	}

	_, delegationErr := server.GetDelegation(GetDelegationRequest{ReservationID: "res-nil"})
	if !errors.Is(delegationErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for delegation query, got %v", delegationErr)
	}

	_, listAuthorizationsErr := server.ListAuthorizations(ListAuthorizationsRequest{})
	if !errors.Is(listAuthorizationsErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list authorizations query, got %v", listAuthorizationsErr)
	}

	_, listDelegationsErr := server.ListDelegations(ListDelegationsRequest{})
	if !errors.Is(listDelegationsErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper for list delegations query, got %v", listDelegationsErr)
	}
}

func TestQueryServerNotFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	server := NewQueryServer(&k)

	_, authorizationErr := server.GetAuthorization(GetAuthorizationRequest{AuthorizationID: "auth-missing"})
	if !errors.Is(authorizationErr, ErrAuthorizationNotFound) {
		t.Fatalf("expected ErrAuthorizationNotFound, got %v", authorizationErr)
	}

	_, delegationErr := server.GetDelegation(GetDelegationRequest{ReservationID: "res-missing"})
	if !errors.Is(delegationErr, ErrDelegationNotFound) {
		t.Fatalf("expected ErrDelegationNotFound, got %v", delegationErr)
	}
}

func TestQueryServerFound(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	expectedAuthorization := types.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}
	expectedDelegation := types.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		SessionID:       "sess-1",
		Credits:         20,
	}
	k.UpsertAuthorization(expectedAuthorization)
	k.UpsertDelegation(expectedDelegation)

	server := NewQueryServer(&k)

	authorizationResp, authorizationErr := server.GetAuthorization(GetAuthorizationRequest{AuthorizationID: "auth-1"})
	if authorizationErr != nil {
		t.Fatalf("expected authorization query success, got %v", authorizationErr)
	}
	if authorizationResp.Authorization.AuthorizationID != expectedAuthorization.AuthorizationID {
		t.Fatalf("unexpected authorization id: %q", authorizationResp.Authorization.AuthorizationID)
	}

	delegationResp, delegationErr := server.GetDelegation(GetDelegationRequest{ReservationID: "res-1"})
	if delegationErr != nil {
		t.Fatalf("expected delegation query success, got %v", delegationErr)
	}
	if delegationResp.Delegation.ReservationID != expectedDelegation.ReservationID {
		t.Fatalf("unexpected delegation reservation id: %q", delegationResp.Delegation.ReservationID)
	}
}

func TestQueryServerListNonEmpty(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
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

	server := NewQueryServer(&k)

	authorizationsResp, authorizationsErr := server.ListAuthorizations(ListAuthorizationsRequest{})
	if authorizationsErr != nil {
		t.Fatalf("expected list authorizations success, got %v", authorizationsErr)
	}
	if len(authorizationsResp.Authorizations) != 3 {
		t.Fatalf("expected 3 authorizations, got %d", len(authorizationsResp.Authorizations))
	}
	if authorizationsResp.Authorizations[0].AuthorizationID != "auth-1" ||
		authorizationsResp.Authorizations[1].AuthorizationID != "auth-2" ||
		authorizationsResp.Authorizations[2].AuthorizationID != "auth-3" {
		t.Fatalf(
			"expected sorted authorization ids [auth-1 auth-2 auth-3], got [%s %s %s]",
			authorizationsResp.Authorizations[0].AuthorizationID,
			authorizationsResp.Authorizations[1].AuthorizationID,
			authorizationsResp.Authorizations[2].AuthorizationID,
		)
	}

	delegationsResp, delegationsErr := server.ListDelegations(ListDelegationsRequest{})
	if delegationsErr != nil {
		t.Fatalf("expected list delegations success, got %v", delegationsErr)
	}
	if len(delegationsResp.Delegations) != 3 {
		t.Fatalf("expected 3 delegations, got %d", len(delegationsResp.Delegations))
	}
	if delegationsResp.Delegations[0].ReservationID != "res-1" ||
		delegationsResp.Delegations[1].ReservationID != "res-2" ||
		delegationsResp.Delegations[2].ReservationID != "res-3" {
		t.Fatalf(
			"expected sorted reservation ids [res-1 res-2 res-3], got [%s %s %s]",
			delegationsResp.Delegations[0].ReservationID,
			delegationsResp.Delegations[1].ReservationID,
			delegationsResp.Delegations[2].ReservationID,
		)
	}
}
