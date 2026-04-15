package app

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	vpnbillingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	vpnrewardspb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnrewards/v1"
	vpnslashingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnslashing/v1"
	vpnsponsorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

func TestRegisterGRPCServicesNilInputs(t *testing.T) {
	var nilScaffold *ChainScaffold
	if err := nilScaffold.RegisterGRPCServices(grpc.NewServer()); !errors.Is(err, errNilChainScaffold) {
		t.Fatalf("expected errNilChainScaffold, got %v", err)
	}

	scaffold := NewChainScaffold()
	if err := scaffold.RegisterGRPCServices(nil); !errors.Is(err, errNilGRPCRegistrar) {
		t.Fatalf("expected errNilGRPCRegistrar, got %v", err)
	}
}

func TestRegisterGRPCServicesBillingAndSponsorRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scaffold := NewChainScaffold()
	grpcServer := grpc.NewServer()
	if err := scaffold.RegisterGRPCServices(grpcServer); err != nil {
		t.Fatalf("register grpc services: %v", err)
	}
	serviceInfo := grpcServer.GetServiceInfo()
	for _, serviceName := range []string{
		"tdpn.vpnvalidator.v1.Msg",
		"tdpn.vpnvalidator.v1.Query",
		"tdpn.vpngovernance.v1.Msg",
		"tdpn.vpngovernance.v1.Query",
	} {
		if _, ok := serviceInfo[serviceName]; !ok {
			t.Fatalf("expected grpc service registration for %s", serviceName)
		}
	}

	lis := bufconn.Listen(1024 * 1024)
	defer lis.Close()

	done := make(chan error, 1)
	go func() {
		done <- grpcServer.Serve(lis)
	}()
	defer func() {
		grpcServer.Stop()
		select {
		case <-done:
		default:
		}
	}()

	conn, err := grpc.DialContext(
		ctx,
		"bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial grpc bufconn: %v", err)
	}
	defer conn.Close()

	billingMsg := vpnbillingpb.NewMsgClient(conn)
	billingQuery := vpnbillingpb.NewQueryClient(conn)

	if _, err := billingMsg.ReserveCredits(ctx, &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: "res-grpc-1",
			SponsorId:     "sponsor-grpc-1",
			SessionId:     "sess-grpc-1",
			AssetDenom:    "utdpn",
			Amount:        1000,
		},
	}); err != nil {
		t.Fatalf("reserve credits: %v", err)
	}

	reservationResp, err := billingQuery.CreditReservation(ctx, &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: "res-grpc-1",
	})
	if err != nil {
		t.Fatalf("query reservation: %v", err)
	}
	if !reservationResp.GetFound() {
		t.Fatalf("expected reservation found=true")
	}

	reservationList, err := billingQuery.ListCreditReservations(ctx, &vpnbillingpb.QueryListCreditReservationsRequest{})
	if err != nil {
		t.Fatalf("list reservations: %v", err)
	}
	if len(reservationList.GetReservations()) == 0 {
		t.Fatalf("expected at least one reservation in list")
	}

	rewardsQuery := vpnrewardspb.NewQueryClient(conn)
	if _, err := rewardsQuery.ListRewardAccruals(ctx, &vpnrewardspb.QueryListRewardAccrualsRequest{}); err != nil {
		t.Fatalf("rewards list accruals: %v", err)
	}

	slashingQuery := vpnslashingpb.NewQueryClient(conn)
	if _, err := slashingQuery.ListSlashEvidence(ctx, &vpnslashingpb.QueryListSlashEvidenceRequest{}); err != nil {
		t.Fatalf("slashing list evidence: %v", err)
	}

	sponsorMsg := vpnsponsorpb.NewMsgClient(conn)
	sponsorQuery := vpnsponsorpb.NewQueryClient(conn)

	if _, err := sponsorMsg.CreateAuthorization(ctx, &vpnsponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &vpnsponsorpb.SponsorAuthorization{
			AuthorizationId: "auth-grpc-1",
			SponsorId:       "sponsor-grpc-1",
			AppId:           "app-grpc-1",
			MaxCredits:      2000,
		},
	}); err != nil {
		t.Fatalf("create sponsor authorization: %v", err)
	}

	if _, err := sponsorMsg.DelegateSessionCredit(ctx, &vpnsponsorpb.MsgDelegateSessionCreditRequest{
		Delegation: &vpnsponsorpb.DelegatedSessionCredit{
			ReservationId:   "res-delegate-grpc-1",
			AuthorizationId: "auth-grpc-1",
			SponsorId:       "sponsor-grpc-1",
			AppId:           "app-grpc-1",
			EndUserId:       "end-user-1",
			SessionId:       "sess-delegate-grpc-1",
			Credits:         500,
		},
	}); err != nil {
		t.Fatalf("delegate session credit: %v", err)
	}

	delegationResp, err := sponsorQuery.DelegatedSessionCredit(ctx, &vpnsponsorpb.QueryDelegatedSessionCreditRequest{
		ReservationId: "res-delegate-grpc-1",
	})
	if err != nil {
		t.Fatalf("query delegated session credit: %v", err)
	}
	if !delegationResp.GetFound() {
		t.Fatalf("expected delegation found=true")
	}
	if delegationResp.GetDelegation().GetAuthorizationId() != "auth-grpc-1" {
		t.Fatalf("expected authorization id auth-grpc-1, got %q", delegationResp.GetDelegation().GetAuthorizationId())
	}
}
