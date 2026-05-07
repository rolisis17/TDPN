package module

import (
	"context"
	"errors"
	"testing"

	sponsorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestGRPCAdaptersCanceledContextFailsClosedAcrossSurface(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgServerAdapter(&k)
	queryAdapter := NewGRPCQueryServerAdapter(&k)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, createErr := msgAdapter.CreateAuthorization(ctx, &sponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &sponsorpb.SponsorAuthorization{
			AuthorizationId: "auth-canceled-surface",
			SponsorId:       "sponsor-canceled-surface",
			AppId:           "app-canceled-surface",
			MaxCredits:      100,
			ExpiresAtUnix:   4102444800,
		},
	})
	if !errors.Is(createErr, context.Canceled) {
		t.Fatalf("expected context.Canceled from CreateAuthorization, got %v", createErr)
	}
	if _, ok := k.GetAuthorization("auth-canceled-surface"); ok {
		t.Fatal("did not expect authorization persistence on canceled context")
	}

	k.UpsertAuthorization(types.SponsorAuthorization{
		AuthorizationID: "auth-query-canceled",
		SponsorID:       "sponsor-query-canceled",
		AppID:           "app-query-canceled",
		MaxCredits:      100,
		ExpiresAtUnix:   4102444800,
	})
	k.UpsertDelegation(types.DelegatedSessionCredit{
		ReservationID:   "res-query-canceled",
		AuthorizationID: "auth-query-canceled",
		SponsorID:       "sponsor-query-canceled",
		AppID:           "app-query-canceled",
		SessionID:       "sess-query-canceled",
		Credits:         10,
	})

	if _, err := queryAdapter.SponsorAuthorization(ctx, &sponsorpb.QuerySponsorAuthorizationRequest{AuthorizationId: "auth-query-canceled"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from SponsorAuthorization, got %v", err)
	}
	if _, err := queryAdapter.DelegatedSessionCredit(ctx, &sponsorpb.QueryDelegatedSessionCreditRequest{ReservationId: "res-query-canceled"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from DelegatedSessionCredit, got %v", err)
	}
	if _, err := queryAdapter.ListSponsorAuthorizations(ctx, &sponsorpb.QueryListSponsorAuthorizationsRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from ListSponsorAuthorizations, got %v", err)
	}
	if _, err := queryAdapter.ListDelegatedSessionCredits(ctx, &sponsorpb.QueryListDelegatedSessionCreditsRequest{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled from ListDelegatedSessionCredits, got %v", err)
	}
}
