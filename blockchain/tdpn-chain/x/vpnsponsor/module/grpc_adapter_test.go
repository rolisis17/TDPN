package module

import (
	"context"
	"errors"
	"testing"

	sponsorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1"
	chaintypes "github.com/tdpn/tdpn-chain/types"
	"github.com/tdpn/tdpn-chain/x/vpnsponsor/keeper"
	sponsortypes "github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestGRPCMsgServerAdapterCreateAuthorization(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgServerAdapter(&k)

	resp, err := adapter.CreateAuthorization(context.Background(), &sponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &sponsorpb.SponsorAuthorization{
			AuthorizationId: "auth-1",
			SponsorId:       "sponsor-1",
			AppId:           "app-1",
			MaxCredits:      100,
			ExpiresAtUnix:   4102444800,
		},
	})
	if err != nil {
		t.Fatalf("expected create authorization success, got %v", err)
	}
	if resp.GetAuthorization() == nil {
		t.Fatal("expected authorization in response")
	}
	if resp.GetAuthorization().GetAuthorizationId() != "auth-1" {
		t.Fatalf("expected authorization_id auth-1, got %q", resp.GetAuthorization().GetAuthorizationId())
	}
}

func TestGRPCMsgServerAdapterCreateAuthorizationConflictClassification(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgServerAdapter(&k)

	_, err := adapter.CreateAuthorization(context.Background(), &sponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &sponsorpb.SponsorAuthorization{
			AuthorizationId: "auth-conflict-1",
			SponsorId:       "sponsor-conflict",
			AppId:           "app-conflict",
			MaxCredits:      100,
			ExpiresAtUnix:   4102444800,
		},
	})
	if err != nil {
		t.Fatalf("seed create authorization failed: %v", err)
	}

	_, err = adapter.CreateAuthorization(context.Background(), &sponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &sponsorpb.SponsorAuthorization{
			AuthorizationId: "auth-conflict-1",
			SponsorId:       "sponsor-conflict",
			AppId:           "app-conflict",
			MaxCredits:      101,
			ExpiresAtUnix:   4102444800,
		},
	})
	if err == nil {
		t.Fatal("expected authorization conflict error")
	}
	if !errors.Is(err, ErrAuthorizationConflict) {
		t.Fatalf("expected ErrAuthorizationConflict, got %v", err)
	}

	stored, ok := k.GetAuthorization("auth-conflict-1")
	if !ok {
		t.Fatal("expected seeded authorization to remain stored")
	}
	if stored.MaxCredits != 100 {
		t.Fatalf("expected stored max_credits to remain 100 after conflict, got %d", stored.MaxCredits)
	}
}

func TestGRPCMsgServerAdapterDelegateSessionCredit(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCMsgServerAdapter(&k)

	_, err := adapter.CreateAuthorization(context.Background(), &sponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &sponsorpb.SponsorAuthorization{
			AuthorizationId: "auth-1",
			SponsorId:       "sponsor-1",
			AppId:           "app-1",
			MaxCredits:      100,
			ExpiresAtUnix:   4102444800,
		},
	})
	if err != nil {
		t.Fatalf("expected create authorization success, got %v", err)
	}

	resp, err := adapter.DelegateSessionCredit(context.Background(), &sponsorpb.MsgDelegateSessionCreditRequest{
		Delegation: &sponsorpb.DelegatedSessionCredit{
			ReservationId:   "res-1",
			AuthorizationId: "auth-1",
			SponsorId:       "sponsor-1",
			AppId:           "app-1",
			EndUserId:       "user-1",
			SessionId:       "sess-1",
			Credits:         10,
		},
	})
	if err != nil {
		t.Fatalf("expected delegate session credit success, got %v", err)
	}
	if resp.GetDelegation() == nil {
		t.Fatal("expected delegation in response")
	}
	if resp.GetDelegation().GetAuthorizationId() != "auth-1" {
		t.Fatalf("expected response authorization_id auth-1, got %q", resp.GetDelegation().GetAuthorizationId())
	}

	stored, ok := k.GetDelegation("res-1")
	if !ok {
		t.Fatal("expected delegation to be persisted")
	}
	if stored.AuthorizationID != "auth-1" {
		t.Fatalf("expected persisted authorization id auth-1, got %q", stored.AuthorizationID)
	}
}

func TestGRPCQueryServerAdapterNotFoundReturnsFoundFalse(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	adapter := NewGRPCQueryServerAdapter(&k)

	authorizationResp, err := adapter.SponsorAuthorization(context.Background(), &sponsorpb.QuerySponsorAuthorizationRequest{
		AuthorizationId: "missing-auth",
	})
	if err != nil {
		t.Fatalf("expected nil error for missing authorization lookup, got %v", err)
	}
	if authorizationResp.GetFound() {
		t.Fatal("expected found=false for missing authorization")
	}

	delegationResp, err := adapter.DelegatedSessionCredit(context.Background(), &sponsorpb.QueryDelegatedSessionCreditRequest{
		ReservationId: "missing-reservation",
	})
	if err != nil {
		t.Fatalf("expected nil error for missing delegation lookup, got %v", err)
	}
	if delegationResp.GetFound() {
		t.Fatal("expected found=false for missing delegation")
	}
}

func TestGRPCQueryServerAdapterFoundAndList(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	k.UpsertAuthorization(sponsortypes.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
		ExpiresAtUnix:   4102444800,
		Status:          chaintypes.ReconciliationPending,
	})
	k.UpsertDelegation(sponsortypes.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		EndUserID:       "user-1",
		SessionID:       "sess-1",
		Credits:         10,
		Status:          chaintypes.ReconciliationSubmitted,
	})
	adapter := NewGRPCQueryServerAdapter(&k)

	authorizationResp, err := adapter.SponsorAuthorization(context.Background(), &sponsorpb.QuerySponsorAuthorizationRequest{
		AuthorizationId: "auth-1",
	})
	if err != nil {
		t.Fatalf("expected authorization lookup success, got %v", err)
	}
	if !authorizationResp.GetFound() {
		t.Fatal("expected found=true for authorization lookup")
	}
	if authorizationResp.GetAuthorization().GetAuthorizationId() != "auth-1" {
		t.Fatalf("expected authorization_id auth-1, got %q", authorizationResp.GetAuthorization().GetAuthorizationId())
	}

	delegationResp, err := adapter.DelegatedSessionCredit(context.Background(), &sponsorpb.QueryDelegatedSessionCreditRequest{
		ReservationId: "res-1",
	})
	if err != nil {
		t.Fatalf("expected delegation lookup success, got %v", err)
	}
	if !delegationResp.GetFound() {
		t.Fatal("expected found=true for delegation lookup")
	}
	if delegationResp.GetDelegation().GetReservationId() != "res-1" {
		t.Fatalf("expected reservation_id res-1, got %q", delegationResp.GetDelegation().GetReservationId())
	}
	if delegationResp.GetDelegation().GetStatus() != sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED {
		t.Fatalf("expected submitted status, got %v", delegationResp.GetDelegation().GetStatus())
	}

	listAuthResp, err := adapter.ListSponsorAuthorizations(context.Background(), &sponsorpb.QueryListSponsorAuthorizationsRequest{})
	if err != nil {
		t.Fatalf("expected list authorizations success, got %v", err)
	}
	if len(listAuthResp.GetAuthorizations()) != 1 {
		t.Fatalf("expected 1 authorization, got %d", len(listAuthResp.GetAuthorizations()))
	}
	if listAuthResp.GetAuthorizations()[0].GetAuthorizationId() != "auth-1" {
		t.Fatalf("expected listed authorization_id auth-1, got %q", listAuthResp.GetAuthorizations()[0].GetAuthorizationId())
	}

	listDelegationsResp, err := adapter.ListDelegatedSessionCredits(context.Background(), &sponsorpb.QueryListDelegatedSessionCreditsRequest{})
	if err != nil {
		t.Fatalf("expected list delegations success, got %v", err)
	}
	if len(listDelegationsResp.GetDelegations()) != 1 {
		t.Fatalf("expected 1 delegation, got %d", len(listDelegationsResp.GetDelegations()))
	}
	if listDelegationsResp.GetDelegations()[0].GetReservationId() != "res-1" {
		t.Fatalf("expected listed reservation_id res-1, got %q", listDelegationsResp.GetDelegations()[0].GetReservationId())
	}
}

func TestGRPCAdaptersNilKeeperPropagatesErrNilKeeper(t *testing.T) {
	t.Parallel()

	var k *keeper.Keeper
	msgAdapter := NewGRPCMsgServerAdapter(k)
	queryAdapter := NewGRPCQueryServerAdapter(k)

	_, msgErr := msgAdapter.CreateAuthorization(context.Background(), &sponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &sponsorpb.SponsorAuthorization{
			AuthorizationId: "auth-nil",
			SponsorId:       "sponsor-nil",
			AppId:           "app-nil",
			MaxCredits:      1,
		},
	})
	if !errors.Is(msgErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from msg adapter, got %v", msgErr)
	}

	_, queryErr := queryAdapter.ListSponsorAuthorizations(context.Background(), &sponsorpb.QueryListSponsorAuthorizationsRequest{})
	if !errors.Is(queryErr, ErrNilKeeper) {
		t.Fatalf("expected ErrNilKeeper from query adapter, got %v", queryErr)
	}
}

func TestGRPCAdaptersNilRequestsAreFailSafe(t *testing.T) {
	t.Parallel()

	k := keeper.NewKeeper()
	msgAdapter := NewGRPCMsgServerAdapter(&k)
	queryAdapter := NewGRPCQueryServerAdapter(&k)

	_, createErr := msgAdapter.CreateAuthorization(context.Background(), nil)
	if !errors.Is(createErr, ErrInvalidAuthorization) {
		t.Fatalf("expected ErrInvalidAuthorization for nil create request, got %v", createErr)
	}

	_, delegateErr := msgAdapter.DelegateSessionCredit(context.Background(), nil)
	if !errors.Is(delegateErr, ErrInvalidDelegation) {
		t.Fatalf("expected ErrInvalidDelegation for nil delegate request, got %v", delegateErr)
	}

	authorizationResp, authorizationErr := queryAdapter.SponsorAuthorization(context.Background(), nil)
	if authorizationErr != nil {
		t.Fatalf("expected nil error for nil authorization query request, got %v", authorizationErr)
	}
	if authorizationResp.GetFound() {
		t.Fatal("expected found=false for nil authorization query request")
	}
	if authorizationResp.GetAuthorization() != nil {
		t.Fatal("expected nil authorization when found=false")
	}

	delegationResp, delegationErr := queryAdapter.DelegatedSessionCredit(context.Background(), nil)
	if delegationErr != nil {
		t.Fatalf("expected nil error for nil delegation query request, got %v", delegationErr)
	}
	if delegationResp.GetFound() {
		t.Fatal("expected found=false for nil delegation query request")
	}
	if delegationResp.GetDelegation() != nil {
		t.Fatal("expected nil delegation when found=false")
	}
}

func TestStatusMappingFromAndToProtoCoversExplicitAndDefaultBranches(t *testing.T) {
	t.Parallel()

	fromProtoCases := []struct {
		name string
		in   sponsorpb.ReconciliationStatus
		want chaintypes.ReconciliationStatus
	}{
		{
			name: "pending",
			in:   sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
			want: chaintypes.ReconciliationPending,
		},
		{
			name: "submitted",
			in:   sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
			want: chaintypes.ReconciliationSubmitted,
		},
		{
			name: "confirmed",
			in:   sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
			want: chaintypes.ReconciliationConfirmed,
		},
		{
			name: "failed",
			in:   sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
			want: chaintypes.ReconciliationFailed,
		},
		{
			name: "default-unspecified",
			in:   sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
			want: "",
		},
	}
	for _, tc := range fromProtoCases {
		tc := tc
		t.Run("fromProto/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := statusFromProto(tc.in)
			if got != tc.want {
				t.Fatalf("statusFromProto(%v): expected %q, got %q", tc.in, tc.want, got)
			}
		})
	}

	toProtoCases := []struct {
		name string
		in   chaintypes.ReconciliationStatus
		want sponsorpb.ReconciliationStatus
	}{
		{
			name: "pending",
			in:   chaintypes.ReconciliationPending,
			want: sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
		},
		{
			name: "submitted",
			in:   chaintypes.ReconciliationSubmitted,
			want: sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
		{
			name: "confirmed",
			in:   chaintypes.ReconciliationConfirmed,
			want: sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
		},
		{
			name: "failed",
			in:   chaintypes.ReconciliationFailed,
			want: sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_FAILED,
		},
		{
			name: "default-empty",
			in:   "",
			want: sponsorpb.ReconciliationStatus_RECONCILIATION_STATUS_UNSPECIFIED,
		},
	}
	for _, tc := range toProtoCases {
		tc := tc
		t.Run("toProto/"+tc.name, func(t *testing.T) {
			t.Parallel()
			got := statusToProto(tc.in)
			if got != tc.want {
				t.Fatalf("statusToProto(%q): expected %v, got %v", tc.in, tc.want, got)
			}
		})
	}
}
