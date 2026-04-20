package app

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	vpnbillingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnbilling/v1"
	vpngovernancepb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpngovernance/v1"
	vpnrewardspb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnrewards/v1"
	vpnslashingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnslashing/v1"
	vpnsponsorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnsponsor/v1"
	vpnvalidatorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnvalidator/v1"
	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
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
	grpcServer := grpc.NewServer(grpc.UnaryInterceptor(func(
		ctx context.Context,
		req any,
		info *grpc.UnaryServerInfo,
		handler grpc.UnaryHandler,
	) (any, error) {
		_ = info
		return handler(sponsormodule.WithCurrentTimeUnix(ctx, time.Now().Unix()), req)
	}))
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
	rewardsMsg := vpnrewardspb.NewMsgClient(conn)
	rewardsQuery := vpnrewardspb.NewQueryClient(conn)
	sponsorMsg := vpnsponsorpb.NewMsgClient(conn)
	sponsorQuery := vpnsponsorpb.NewQueryClient(conn)

	reservationInputID := "  ReS-GRPC-CANON-1  "
	reservationCanonicalID := "res-grpc-canon-1"
	reservationMixedQueryID := "  RES-GRPC-CANON-1  "
	reservationCanonicalSponsorID := "sponsor-grpc-canon-1"
	reservationCanonicalSessionID := "sess-grpc-canon-1"
	reserveResp, err := billingMsg.ReserveCredits(ctx, &vpnbillingpb.MsgReserveCreditsRequest{
		Reservation: &vpnbillingpb.CreditReservation{
			ReservationId: reservationInputID,
			SponsorId:     "  SpOnSoR-GRPC-CANON-1  ",
			SessionId:     "  SeSs-GRPC-CANON-1  ",
			AssetDenom:    "  UTDPN  ",
			Amount:        1000,
		},
	})
	if err != nil {
		t.Fatalf("reserve credits: %v", err)
	}
	if reserveResp.GetReservation() == nil || reserveResp.GetReservation().GetReservationId() != reservationCanonicalID {
		t.Fatalf("unexpected reserve response: %+v", reserveResp.GetReservation())
	}
	if got := reserveResp.GetReservation().GetSponsorId(); got != reservationCanonicalSponsorID {
		t.Fatalf("expected canonical sponsor id %q, got %q", reservationCanonicalSponsorID, got)
	}
	if got := reserveResp.GetReservation().GetSessionId(); got != reservationCanonicalSessionID {
		t.Fatalf("expected canonical session id %q, got %q", reservationCanonicalSessionID, got)
	}
	if got := reserveResp.GetReservation().GetAssetDenom(); got != "utdpn" {
		t.Fatalf("expected canonical denom utdpn, got %q", got)
	}

	reservationByCanonicalID, err := billingQuery.CreditReservation(ctx, &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: reservationCanonicalID,
	})
	if err != nil {
		t.Fatalf("query reservation by canonical id: %v", err)
	}
	if !reservationByCanonicalID.GetFound() {
		t.Fatalf("expected reservation found=true for canonical id")
	}
	if got := reservationByCanonicalID.GetReservation().GetReservationId(); got != reservationCanonicalID {
		t.Fatalf("expected canonical reservation id %q, got %q", reservationCanonicalID, got)
	}
	if got := reservationByCanonicalID.GetReservation().GetSponsorId(); got != reservationCanonicalSponsorID {
		t.Fatalf("expected canonical queried sponsor id %q, got %q", reservationCanonicalSponsorID, got)
	}
	if got := reservationByCanonicalID.GetReservation().GetSessionId(); got != reservationCanonicalSessionID {
		t.Fatalf("expected canonical queried session id %q, got %q", reservationCanonicalSessionID, got)
	}
	if got := reservationByCanonicalID.GetReservation().GetAssetDenom(); got != "utdpn" {
		t.Fatalf("expected canonical queried denom utdpn, got %q", got)
	}

	reservationByMixedID, err := billingQuery.CreditReservation(ctx, &vpnbillingpb.QueryCreditReservationRequest{
		ReservationId: reservationMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query reservation by mixed-case id: %v", err)
	}
	if !reservationByMixedID.GetFound() {
		t.Fatalf("expected reservation found=true for mixed-case id")
	}
	if got := reservationByMixedID.GetReservation().GetReservationId(); got != reservationCanonicalID {
		t.Fatalf("expected mixed-case reservation query to resolve canonical id %q, got %q", reservationCanonicalID, got)
	}

	reservationList, err := billingQuery.ListCreditReservations(ctx, &vpnbillingpb.QueryListCreditReservationsRequest{})
	if err != nil {
		t.Fatalf("list reservations: %v", err)
	}
	foundReservation := false
	for _, item := range reservationList.GetReservations() {
		if item.GetReservationId() == reservationCanonicalID {
			foundReservation = true
			break
		}
	}
	if !foundReservation {
		t.Fatalf("expected canonical reservation %q in list", reservationCanonicalID)
	}

	settlementInputID := "  SeT-GRPC-CANON-1  "
	settlementCanonicalID := "set-grpc-canon-1"
	settlementMixedQueryID := "  SET-GRPC-CANON-1  "
	finalizeResp, err := billingMsg.FinalizeUsage(ctx, &vpnbillingpb.MsgFinalizeUsageRequest{
		Settlement: &vpnbillingpb.SettlementRecord{
			SettlementId:  settlementInputID,
			ReservationId: reservationMixedQueryID,
			SessionId:     "  SESS-GRPC-CANON-1  ",
			BilledAmount:  750,
			UsageBytes:    2048,
			AssetDenom:    "  UTDPN  ",
		},
	})
	if err != nil {
		t.Fatalf("finalize usage: %v", err)
	}
	if finalizeResp.GetSettlement() == nil || finalizeResp.GetSettlement().GetSettlementId() != settlementCanonicalID {
		t.Fatalf("unexpected finalize response: %+v", finalizeResp.GetSettlement())
	}
	if got := finalizeResp.GetSettlement().GetReservationId(); got != reservationCanonicalID {
		t.Fatalf("expected canonical settlement reservation id %q, got %q", reservationCanonicalID, got)
	}
	if got := finalizeResp.GetSettlement().GetSessionId(); got != reservationCanonicalSessionID {
		t.Fatalf("expected canonical settlement session id %q, got %q", reservationCanonicalSessionID, got)
	}
	if got := finalizeResp.GetSettlement().GetAssetDenom(); got != "utdpn" {
		t.Fatalf("expected canonical settlement denom utdpn, got %q", got)
	}

	settlementByCanonicalID, err := billingQuery.SettlementRecord(ctx, &vpnbillingpb.QuerySettlementRecordRequest{
		SettlementId: settlementCanonicalID,
	})
	if err != nil {
		t.Fatalf("query settlement by canonical id: %v", err)
	}
	if !settlementByCanonicalID.GetFound() {
		t.Fatalf("expected settlement found=true for canonical id")
	}
	if got := settlementByCanonicalID.GetSettlement().GetSettlementId(); got != settlementCanonicalID {
		t.Fatalf("expected canonical settlement id %q, got %q", settlementCanonicalID, got)
	}
	if got := settlementByCanonicalID.GetSettlement().GetReservationId(); got != reservationCanonicalID {
		t.Fatalf("expected canonical queried reservation id %q, got %q", reservationCanonicalID, got)
	}
	if got := settlementByCanonicalID.GetSettlement().GetSessionId(); got != reservationCanonicalSessionID {
		t.Fatalf("expected canonical queried session id %q, got %q", reservationCanonicalSessionID, got)
	}
	if got := settlementByCanonicalID.GetSettlement().GetAssetDenom(); got != "utdpn" {
		t.Fatalf("expected canonical queried settlement denom utdpn, got %q", got)
	}

	settlementByMixedID, err := billingQuery.SettlementRecord(ctx, &vpnbillingpb.QuerySettlementRecordRequest{
		SettlementId: settlementMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query settlement by mixed-case id: %v", err)
	}
	if !settlementByMixedID.GetFound() {
		t.Fatalf("expected settlement found=true for mixed-case id")
	}
	if got := settlementByMixedID.GetSettlement().GetSettlementId(); got != settlementCanonicalID {
		t.Fatalf("expected mixed-case settlement query to resolve canonical id %q, got %q", settlementCanonicalID, got)
	}

	settlementList, err := billingQuery.ListSettlementRecords(ctx, &vpnbillingpb.QueryListSettlementRecordsRequest{})
	if err != nil {
		t.Fatalf("list settlements: %v", err)
	}
	foundSettlement := false
	for _, item := range settlementList.GetSettlements() {
		if item.GetSettlementId() == settlementCanonicalID {
			foundSettlement = true
			break
		}
	}
	if !foundSettlement {
		t.Fatalf("expected canonical settlement %q in list", settlementCanonicalID)
	}

	accrualInputID := "  AcCrUaL-GRPC-CANON-1  "
	accrualCanonicalID := "accrual-grpc-canon-1"
	accrualMixedQueryID := "  ACCRUAL-GRPC-CANON-1  "
	accrualResp, err := rewardsMsg.RecordAccrual(ctx, &vpnrewardspb.MsgRecordAccrualRequest{
		Accrual: &vpnrewardspb.RewardAccrual{
			AccrualId:      accrualInputID,
			SessionId:      "  SeSs-ReWaRd-GrPc-CaNoN-1  ",
			ProviderId:     "  PrOvIdEr-ReWaRd-GrPc-CaNoN-1  ",
			AssetDenom:     "  UTDPN  ",
			Amount:         300,
			OperationState: vpnrewardspb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
	})
	if err != nil {
		t.Fatalf("record reward accrual: %v", err)
	}
	if accrualResp.GetAccrual() == nil || accrualResp.GetAccrual().GetAccrualId() != accrualCanonicalID {
		t.Fatalf("unexpected reward accrual response: %+v", accrualResp.GetAccrual())
	}
	if got := accrualResp.GetAccrual().GetSessionId(); got != "sess-reward-grpc-canon-1" {
		t.Fatalf("expected canonical accrual session id sess-reward-grpc-canon-1, got %q", got)
	}
	if got := accrualResp.GetAccrual().GetProviderId(); got != "provider-reward-grpc-canon-1" {
		t.Fatalf("expected canonical accrual provider id provider-reward-grpc-canon-1, got %q", got)
	}
	if got := accrualResp.GetAccrual().GetAssetDenom(); got != "utdpn" {
		t.Fatalf("expected canonical accrual denom utdpn, got %q", got)
	}

	accrualByCanonicalID, err := rewardsQuery.RewardAccrual(ctx, &vpnrewardspb.QueryRewardAccrualRequest{
		AccrualId: accrualCanonicalID,
	})
	if err != nil {
		t.Fatalf("query reward accrual by canonical id: %v", err)
	}
	if !accrualByCanonicalID.GetFound() {
		t.Fatalf("expected reward accrual found=true for canonical id")
	}
	if got := accrualByCanonicalID.GetAccrual().GetAccrualId(); got != accrualCanonicalID {
		t.Fatalf("expected canonical queried accrual id %q, got %q", accrualCanonicalID, got)
	}

	accrualByMixedID, err := rewardsQuery.RewardAccrual(ctx, &vpnrewardspb.QueryRewardAccrualRequest{
		AccrualId: accrualMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query reward accrual by mixed-case id: %v", err)
	}
	if !accrualByMixedID.GetFound() {
		t.Fatalf("expected reward accrual found=true for mixed-case id")
	}
	if got := accrualByMixedID.GetAccrual().GetAccrualId(); got != accrualCanonicalID {
		t.Fatalf("expected mixed-case accrual query to resolve canonical id %q, got %q", accrualCanonicalID, got)
	}

	accrualList, err := rewardsQuery.ListRewardAccruals(ctx, &vpnrewardspb.QueryListRewardAccrualsRequest{})
	if err != nil {
		t.Fatalf("rewards list accruals: %v", err)
	}
	foundAccrual := false
	for _, item := range accrualList.GetAccruals() {
		if item.GetAccrualId() == accrualCanonicalID {
			foundAccrual = true
			break
		}
	}
	if !foundAccrual {
		t.Fatalf("expected canonical reward accrual %q in list", accrualCanonicalID)
	}

	distributionInputID := "  DiSt-ReWaRd-GRPC-CANON-1  "
	distributionCanonicalID := "dist-reward-grpc-canon-1"
	distributionMixedQueryID := "  DIST-REWARD-GRPC-CANON-1  "
	distributionResp, err := rewardsMsg.RecordDistribution(ctx, &vpnrewardspb.MsgRecordDistributionRequest{
		Distribution: &vpnrewardspb.DistributionRecord{
			DistributionId: distributionInputID,
			AccrualId:      "  ACCRUAL-GRPC-CANON-1  ",
			PayoutRef:      "payout-reward-grpc-canon-1",
		},
	})
	if err != nil {
		t.Fatalf("record reward distribution: %v", err)
	}
	if distributionResp.GetDistribution() == nil || distributionResp.GetDistribution().GetDistributionId() != distributionCanonicalID {
		t.Fatalf("unexpected reward distribution response: %+v", distributionResp.GetDistribution())
	}
	if got := distributionResp.GetDistribution().GetAccrualId(); got != accrualCanonicalID {
		t.Fatalf("expected canonical distribution accrual id %q, got %q", accrualCanonicalID, got)
	}

	distributionByCanonicalID, err := rewardsQuery.DistributionRecord(ctx, &vpnrewardspb.QueryDistributionRecordRequest{
		DistributionId: distributionCanonicalID,
	})
	if err != nil {
		t.Fatalf("query reward distribution by canonical id: %v", err)
	}
	if !distributionByCanonicalID.GetFound() {
		t.Fatalf("expected reward distribution found=true for canonical id")
	}
	if got := distributionByCanonicalID.GetDistribution().GetDistributionId(); got != distributionCanonicalID {
		t.Fatalf("expected canonical queried distribution id %q, got %q", distributionCanonicalID, got)
	}
	if got := distributionByCanonicalID.GetDistribution().GetAccrualId(); got != accrualCanonicalID {
		t.Fatalf("expected canonical queried distribution accrual id %q, got %q", accrualCanonicalID, got)
	}

	distributionByMixedID, err := rewardsQuery.DistributionRecord(ctx, &vpnrewardspb.QueryDistributionRecordRequest{
		DistributionId: distributionMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query reward distribution by mixed-case id: %v", err)
	}
	if !distributionByMixedID.GetFound() {
		t.Fatalf("expected reward distribution found=true for mixed-case id")
	}
	if got := distributionByMixedID.GetDistribution().GetDistributionId(); got != distributionCanonicalID {
		t.Fatalf("expected mixed-case distribution query to resolve canonical id %q, got %q", distributionCanonicalID, got)
	}

	distributionList, err := rewardsQuery.ListDistributionRecords(ctx, &vpnrewardspb.QueryListDistributionRecordsRequest{})
	if err != nil {
		t.Fatalf("rewards list distribution records: %v", err)
	}
	foundDistribution := false
	for _, item := range distributionList.GetDistributions() {
		if item.GetDistributionId() == distributionCanonicalID {
			foundDistribution = true
			break
		}
	}
	if !foundDistribution {
		t.Fatalf("expected canonical reward distribution %q in list", distributionCanonicalID)
	}

	slashingQuery := vpnslashingpb.NewQueryClient(conn)
	if _, err := slashingQuery.ListSlashEvidence(ctx, &vpnslashingpb.QueryListSlashEvidenceRequest{}); err != nil {
		t.Fatalf("slashing list evidence: %v", err)
	}
	if _, err := slashingQuery.ListPenaltyDecisions(ctx, &vpnslashingpb.QueryListPenaltyDecisionsRequest{}); err != nil {
		t.Fatalf("slashing list penalty decisions: %v", err)
	}

	authorizationInputID := "  AuTh-GRPC-CANON-1  "
	authorizationCanonicalID := "auth-grpc-canon-1"
	authorizationMixedQueryID := "  AUTH-GRPC-CANON-1  "
	createAuthorizationResp, err := sponsorMsg.CreateAuthorization(ctx, &vpnsponsorpb.MsgCreateAuthorizationRequest{
		Authorization: &vpnsponsorpb.SponsorAuthorization{
			AuthorizationId: authorizationInputID,
			SponsorId:       "  SpOnSoR-GRPC-CANON-1  ",
			AppId:           "  APP-GRPC-CANON-1  ",
			MaxCredits:      2000,
		},
	})
	if err != nil {
		t.Fatalf("create sponsor authorization: %v", err)
	}
	if createAuthorizationResp.GetAuthorization() == nil || createAuthorizationResp.GetAuthorization().GetAuthorizationId() != authorizationCanonicalID {
		t.Fatalf("unexpected sponsor authorization response: %+v", createAuthorizationResp.GetAuthorization())
	}
	if got := createAuthorizationResp.GetAuthorization().GetSponsorId(); got != reservationCanonicalSponsorID {
		t.Fatalf("expected canonical authorization sponsor id %q, got %q", reservationCanonicalSponsorID, got)
	}
	if got := createAuthorizationResp.GetAuthorization().GetAppId(); got != "app-grpc-canon-1" {
		t.Fatalf("expected canonical authorization app id app-grpc-canon-1, got %q", got)
	}

	authorizationByCanonicalID, err := sponsorQuery.SponsorAuthorization(ctx, &vpnsponsorpb.QuerySponsorAuthorizationRequest{
		AuthorizationId: authorizationCanonicalID,
	})
	if err != nil {
		t.Fatalf("query sponsor authorization by canonical id: %v", err)
	}
	if !authorizationByCanonicalID.GetFound() {
		t.Fatalf("expected sponsor authorization found=true for canonical id")
	}
	if got := authorizationByCanonicalID.GetAuthorization().GetAuthorizationId(); got != authorizationCanonicalID {
		t.Fatalf("expected canonical queried authorization id %q, got %q", authorizationCanonicalID, got)
	}

	authorizationByMixedID, err := sponsorQuery.SponsorAuthorization(ctx, &vpnsponsorpb.QuerySponsorAuthorizationRequest{
		AuthorizationId: authorizationMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query sponsor authorization by mixed-case id: %v", err)
	}
	if !authorizationByMixedID.GetFound() {
		t.Fatalf("expected sponsor authorization found=true for mixed-case id")
	}
	if got := authorizationByMixedID.GetAuthorization().GetAuthorizationId(); got != authorizationCanonicalID {
		t.Fatalf("expected mixed-case authorization query to resolve canonical id %q, got %q", authorizationCanonicalID, got)
	}

	authorizationList, err := sponsorQuery.ListSponsorAuthorizations(ctx, &vpnsponsorpb.QueryListSponsorAuthorizationsRequest{})
	if err != nil {
		t.Fatalf("list sponsor authorizations: %v", err)
	}
	foundAuthorization := false
	for _, item := range authorizationList.GetAuthorizations() {
		if item.GetAuthorizationId() == authorizationCanonicalID {
			foundAuthorization = true
			break
		}
	}
	if !foundAuthorization {
		t.Fatalf("expected canonical sponsor authorization %q in list", authorizationCanonicalID)
	}

	delegationInputReservationID := "  ReS-Delegate-GRPC-CANON-1  "
	delegationCanonicalReservationID := "res-delegate-grpc-canon-1"
	delegationMixedQueryID := "  RES-DELEGATE-GRPC-CANON-1  "
	delegateResp, err := sponsorMsg.DelegateSessionCredit(ctx, &vpnsponsorpb.MsgDelegateSessionCreditRequest{
		Delegation: &vpnsponsorpb.DelegatedSessionCredit{
			ReservationId:   delegationInputReservationID,
			AuthorizationId: "  AUTH-GRPC-CANON-1  ",
			SponsorId:       "  SPONSOR-GRPC-CANON-1  ",
			AppId:           "  APP-GRPC-CANON-1  ",
			EndUserId:       "  EndUser-Case-1  ",
			SessionId:       "  SessIon-Case-1  ",
			Credits:         500,
		},
	})
	if err != nil {
		t.Fatalf("delegate session credit: %v", err)
	}
	if delegateResp.GetDelegation() == nil || delegateResp.GetDelegation().GetReservationId() != delegationCanonicalReservationID {
		t.Fatalf("unexpected delegate session credit response: %+v", delegateResp.GetDelegation())
	}
	if got := delegateResp.GetDelegation().GetAuthorizationId(); got != authorizationCanonicalID {
		t.Fatalf("expected canonical delegation authorization id %q, got %q", authorizationCanonicalID, got)
	}
	if got := delegateResp.GetDelegation().GetSponsorId(); got != reservationCanonicalSponsorID {
		t.Fatalf("expected canonical delegation sponsor id %q, got %q", reservationCanonicalSponsorID, got)
	}
	if got := delegateResp.GetDelegation().GetAppId(); got != "app-grpc-canon-1" {
		t.Fatalf("expected canonical delegation app id app-grpc-canon-1, got %q", got)
	}
	if got := delegateResp.GetDelegation().GetEndUserId(); got != "EndUser-Case-1" {
		t.Fatalf("expected trim-only delegation end-user id EndUser-Case-1, got %q", got)
	}
	if got := delegateResp.GetDelegation().GetSessionId(); got != "SessIon-Case-1" {
		t.Fatalf("expected trim-only delegation session id SessIon-Case-1, got %q", got)
	}

	delegationByCanonicalID, err := sponsorQuery.DelegatedSessionCredit(ctx, &vpnsponsorpb.QueryDelegatedSessionCreditRequest{
		ReservationId: delegationCanonicalReservationID,
	})
	if err != nil {
		t.Fatalf("query delegated session credit by canonical id: %v", err)
	}
	if !delegationByCanonicalID.GetFound() {
		t.Fatalf("expected delegation found=true for canonical id")
	}
	if got := delegationByCanonicalID.GetDelegation().GetReservationId(); got != delegationCanonicalReservationID {
		t.Fatalf("expected canonical queried delegation reservation id %q, got %q", delegationCanonicalReservationID, got)
	}
	if got := delegationByCanonicalID.GetDelegation().GetAuthorizationId(); got != authorizationCanonicalID {
		t.Fatalf("expected canonical queried authorization id %q, got %q", authorizationCanonicalID, got)
	}
	if got := delegationByCanonicalID.GetDelegation().GetEndUserId(); got != "EndUser-Case-1" {
		t.Fatalf("expected trim-only queried delegation end-user id EndUser-Case-1, got %q", got)
	}
	if got := delegationByCanonicalID.GetDelegation().GetSessionId(); got != "SessIon-Case-1" {
		t.Fatalf("expected trim-only queried delegation session id SessIon-Case-1, got %q", got)
	}

	delegationByMixedID, err := sponsorQuery.DelegatedSessionCredit(ctx, &vpnsponsorpb.QueryDelegatedSessionCreditRequest{
		ReservationId: delegationMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query delegated session credit by mixed-case id: %v", err)
	}
	if !delegationByMixedID.GetFound() {
		t.Fatalf("expected delegation found=true for mixed-case id")
	}
	if got := delegationByMixedID.GetDelegation().GetReservationId(); got != delegationCanonicalReservationID {
		t.Fatalf("expected mixed-case delegation query to resolve canonical reservation id %q, got %q", delegationCanonicalReservationID, got)
	}

	delegationList, err := sponsorQuery.ListDelegatedSessionCredits(ctx, &vpnsponsorpb.QueryListDelegatedSessionCreditsRequest{})
	if err != nil {
		t.Fatalf("list delegated session credits: %v", err)
	}
	foundDelegation := false
	for _, item := range delegationList.GetDelegations() {
		if item.GetReservationId() == delegationCanonicalReservationID {
			foundDelegation = true
			break
		}
	}
	if !foundDelegation {
		t.Fatalf("expected canonical delegated session credit %q in list", delegationCanonicalReservationID)
	}
}

func TestRegisterGRPCServicesSlashingViolationTypeRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scaffold := NewChainScaffold()
	grpcServer := grpc.NewServer()
	if err := scaffold.RegisterGRPCServices(grpcServer); err != nil {
		t.Fatalf("register grpc services: %v", err)
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

	slashingMsg := vpnslashingpb.NewMsgClient(conn)
	slashingQuery := vpnslashingpb.NewQueryClient(conn)

	const evidenceID = "slash-grpc-rt-1"
	const inputViolationType = "  Session-Replay-Proof  "
	const expectedViolationType = "session-replay-proof"

	submitResp, err := slashingMsg.SubmitEvidence(ctx, &vpnslashingpb.MsgSubmitEvidenceRequest{
		Evidence: &vpnslashingpb.SlashEvidence{
			EvidenceId:      evidenceID,
			SessionId:       "sess-grpc-rt-1",
			ProviderId:      "provider-grpc-rt-1",
			ViolationType:   inputViolationType,
			Kind:            "objective",
			ProofHash:       "obj://slash/grpc/rt/1",
			SubmittedAtUnix: 1713002001,
		},
	})
	if err != nil {
		t.Fatalf("submit slash evidence: %v", err)
	}
	if submitResp.GetEvidence() == nil || submitResp.GetEvidence().GetEvidenceId() != evidenceID {
		t.Fatalf("unexpected submit slash evidence response: %+v", submitResp.GetEvidence())
	}
	if got := submitResp.GetEvidence().GetViolationType(); got != expectedViolationType {
		t.Fatalf("expected submitted violation type %q, got %q", expectedViolationType, got)
	}

	evidenceByID, err := slashingQuery.SlashEvidence(ctx, &vpnslashingpb.QuerySlashEvidenceRequest{
		EvidenceId: evidenceID,
	})
	if err != nil {
		t.Fatalf("query slash evidence: %v", err)
	}
	if !evidenceByID.GetFound() {
		t.Fatalf("expected slash evidence found=true")
	}
	if evidenceByID.GetEvidence() == nil {
		t.Fatalf("expected slash evidence payload in query response")
	}
	if got := evidenceByID.GetEvidence().GetViolationType(); got != expectedViolationType {
		t.Fatalf("expected query slash evidence violation type %q, got %q", expectedViolationType, got)
	}

	evidenceList, err := slashingQuery.ListSlashEvidence(ctx, &vpnslashingpb.QueryListSlashEvidenceRequest{})
	if err != nil {
		t.Fatalf("list slash evidence: %v", err)
	}
	foundEvidence := false
	for _, item := range evidenceList.GetEvidence() {
		if item.GetEvidenceId() == evidenceID {
			foundEvidence = true
			if got := item.GetViolationType(); got != expectedViolationType {
				t.Fatalf("expected list slash evidence violation type %q, got %q", expectedViolationType, got)
			}
			break
		}
	}
	if !foundEvidence {
		t.Fatalf("expected slash evidence %q in list", evidenceID)
	}
}

func TestRegisterGRPCServicesValidatorAndGovernanceRoundTrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	scaffold := NewChainScaffold()
	grpcServer := grpc.NewServer()
	if err := scaffold.RegisterGRPCServices(grpcServer); err != nil {
		t.Fatalf("register grpc services: %v", err)
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

	validatorMsg := vpnvalidatorpb.NewMsgClient(conn)
	validatorQuery := vpnvalidatorpb.NewQueryClient(conn)
	governanceMsg := vpngovernancepb.NewMsgClient(conn)
	governanceQuery := vpngovernancepb.NewQueryClient(conn)

	eligibilityInputID := "  VaLiDaToR-GrPc-Rt-1  "
	eligibilityCanonicalID := "validator-grpc-rt-1"
	eligibilityMixedQueryID := "  VALIDATOR-GRPC-RT-1  "
	eligibilityResp, err := validatorMsg.SetValidatorEligibility(ctx, &vpnvalidatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &vpnvalidatorpb.ValidatorEligibility{
			ValidatorId:     eligibilityInputID,
			OperatorAddress: "tdpnvaloper1grpcroundtrip",
			Eligible:        true,
			PolicyReason:    "bootstrap policy allowlist",
			UpdatedAtUnix:   1713001001,
			Status:          vpnvalidatorpb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
	})
	if err != nil {
		t.Fatalf("set validator eligibility: %v", err)
	}
	if eligibilityResp.GetEligibility() == nil || eligibilityResp.GetEligibility().GetValidatorId() != eligibilityCanonicalID {
		t.Fatalf("unexpected eligibility response: %+v", eligibilityResp.GetEligibility())
	}

	eligibilityByID, err := validatorQuery.ValidatorEligibility(ctx, &vpnvalidatorpb.QueryValidatorEligibilityRequest{
		ValidatorId: eligibilityCanonicalID,
	})
	if err != nil {
		t.Fatalf("query validator eligibility: %v", err)
	}
	if !eligibilityByID.GetFound() {
		t.Fatalf("expected validator eligibility found=true")
	}
	if got := eligibilityByID.GetEligibility().GetValidatorId(); got != eligibilityCanonicalID {
		t.Fatalf("expected canonical validator id %q, got %q", eligibilityCanonicalID, got)
	}
	if got := eligibilityByID.GetEligibility().GetOperatorAddress(); got != "tdpnvaloper1grpcroundtrip" {
		t.Fatalf("expected operator address tdpnvaloper1grpcroundtrip, got %q", got)
	}
	eligibilityByMixedID, err := validatorQuery.ValidatorEligibility(ctx, &vpnvalidatorpb.QueryValidatorEligibilityRequest{
		ValidatorId: eligibilityMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query validator eligibility with mixed-case id: %v", err)
	}
	if !eligibilityByMixedID.GetFound() {
		t.Fatalf("expected mixed-case validator eligibility lookup found=true")
	}
	if got := eligibilityByMixedID.GetEligibility().GetValidatorId(); got != eligibilityCanonicalID {
		t.Fatalf("expected mixed-case query to resolve canonical validator id %q, got %q", eligibilityCanonicalID, got)
	}

	eligibilityList, err := validatorQuery.ListValidatorEligibilities(ctx, &vpnvalidatorpb.QueryListValidatorEligibilitiesRequest{})
	if err != nil {
		t.Fatalf("list validator eligibilities: %v", err)
	}
	foundEligibility := false
	for _, item := range eligibilityList.GetEligibilities() {
		if item.GetValidatorId() == eligibilityCanonicalID {
			foundEligibility = true
			break
		}
	}
	if !foundEligibility {
		t.Fatalf("expected canonical validator eligibility %q in list", eligibilityCanonicalID)
	}

	previewResp, err := validatorQuery.PreviewEpochSelection(ctx, &vpnvalidatorpb.QueryPreviewEpochSelectionRequest{
		Policy: &vpnvalidatorpb.EpochSelectionPolicy{
			Epoch:               17,
			StableSeatCount:     1,
			RotatingSeatCount:   0,
			MinStake:            1,
			MinStakeAgeEpochs:   1,
			MinHealthScore:      1,
			MinResourceHeadroom: 1,
		},
		Candidates: []*vpnvalidatorpb.EpochValidatorCandidate{
			{
				ValidatorId:         eligibilityCanonicalID,
				OperatorId:          "operator-grpc-rt-1",
				Asn:                 "64513",
				Region:              "au-south",
				Stake:               100,
				StakeAgeEpochs:      9,
				HealthScore:         100,
				ResourceHeadroom:    100,
				Score:               100,
				StableSeatPreferred: true,
			},
		},
	})
	if err != nil {
		t.Fatalf("preview epoch selection: %v", err)
	}
	if previewResp.GetResult() == nil {
		t.Fatalf("expected non-nil preview epoch selection result")
	}
	if len(previewResp.GetResult().GetStableSeats())+len(previewResp.GetResult().GetRotatingSeats()) == 0 {
		t.Fatalf("expected preview epoch selection to choose candidate, got %+v", previewResp.GetResult())
	}

	statusInputID := "  VaLiDaToR-Status-GRPC-RT-1  "
	statusCanonicalID := "validator-status-grpc-rt-1"
	statusMixedQueryID := "  VALIDATOR-STATUS-GRPC-RT-1  "
	statusResp, err := validatorMsg.RecordValidatorStatus(ctx, &vpnvalidatorpb.MsgRecordValidatorStatusRequest{
		Record: &vpnvalidatorpb.ValidatorStatusRecord{
			StatusId:         statusInputID,
			ValidatorId:      eligibilityMixedQueryID,
			ConsensusAddress: "tdpnvalcons1grpcroundtrip",
			LifecycleStatus:  "active",
			EvidenceHeight:   42,
			EvidenceRef:      "obj://validator/grpc/42",
			RecordedAtUnix:   1713001002,
			Status:           vpnvalidatorpb.ReconciliationStatus_RECONCILIATION_STATUS_PENDING,
		},
	})
	if err != nil {
		t.Fatalf("record validator status: %v", err)
	}
	if statusResp.GetRecord() == nil || statusResp.GetRecord().GetStatusId() != statusCanonicalID {
		t.Fatalf("unexpected validator status response: %+v", statusResp.GetRecord())
	}
	if got := statusResp.GetRecord().GetValidatorId(); got != eligibilityCanonicalID {
		t.Fatalf("expected canonical status validator id %q, got %q", eligibilityCanonicalID, got)
	}

	statusByID, err := validatorQuery.ValidatorStatusRecord(ctx, &vpnvalidatorpb.QueryValidatorStatusRecordRequest{
		StatusId: statusCanonicalID,
	})
	if err != nil {
		t.Fatalf("query validator status: %v", err)
	}
	if !statusByID.GetFound() {
		t.Fatalf("expected validator status found=true")
	}
	if got := statusByID.GetRecord().GetStatusId(); got != statusCanonicalID {
		t.Fatalf("expected canonical status id %q, got %q", statusCanonicalID, got)
	}
	if got := statusByID.GetRecord().GetValidatorId(); got != eligibilityCanonicalID {
		t.Fatalf("expected canonical validator id %q on status query, got %q", eligibilityCanonicalID, got)
	}
	if got := statusByID.GetRecord().GetLifecycleStatus(); got != "active" {
		t.Fatalf("expected lifecycle status active, got %q", got)
	}
	statusByMixedID, err := validatorQuery.ValidatorStatusRecord(ctx, &vpnvalidatorpb.QueryValidatorStatusRecordRequest{
		StatusId: statusMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query validator status with mixed-case id: %v", err)
	}
	if !statusByMixedID.GetFound() {
		t.Fatalf("expected mixed-case validator status lookup found=true")
	}
	if got := statusByMixedID.GetRecord().GetStatusId(); got != statusCanonicalID {
		t.Fatalf("expected mixed-case status query to resolve canonical status id %q, got %q", statusCanonicalID, got)
	}

	statusList, err := validatorQuery.ListValidatorStatusRecords(ctx, &vpnvalidatorpb.QueryListValidatorStatusRecordsRequest{})
	if err != nil {
		t.Fatalf("list validator status records: %v", err)
	}
	foundStatus := false
	for _, item := range statusList.GetRecords() {
		if item.GetStatusId() == statusCanonicalID {
			foundStatus = true
			break
		}
	}
	if !foundStatus {
		t.Fatalf("expected canonical validator status %q in list", statusCanonicalID)
	}

	policyInputID := "  GoVeRnAnCe-Policy-GRPC-RT-1  "
	policyCanonicalID := "governance-policy-grpc-rt-1"
	policyMixedQueryID := "  GOVERNANCE-POLICY-GRPC-RT-1  "
	policyResp, err := governanceMsg.CreatePolicy(ctx, &vpngovernancepb.MsgCreatePolicyRequest{
		Policy: &vpngovernancepb.GovernancePolicy{
			PolicyId:        policyInputID,
			Title:           "Bootstrap validator policy",
			Description:     "deterministic roundtrip policy",
			Version:         1,
			ActivatedAtUnix: 1713001003,
			Status:          vpngovernancepb.ReconciliationStatus_RECONCILIATION_STATUS_CONFIRMED,
		},
	})
	if err != nil {
		t.Fatalf("create governance policy: %v", err)
	}
	if policyResp.GetPolicy() == nil || policyResp.GetPolicy().GetPolicyId() != policyCanonicalID {
		t.Fatalf("unexpected policy response: %+v", policyResp.GetPolicy())
	}
	if policyResp.GetIdempotentReplay() || policyResp.GetConflict() {
		t.Fatalf("unexpected policy replay/conflict flags: replay=%v conflict=%v", policyResp.GetIdempotentReplay(), policyResp.GetConflict())
	}

	policyByID, err := governanceQuery.GovernancePolicy(ctx, &vpngovernancepb.QueryGovernancePolicyRequest{
		PolicyId: policyCanonicalID,
	})
	if err != nil {
		t.Fatalf("query governance policy: %v", err)
	}
	if !policyByID.GetFound() {
		t.Fatalf("expected governance policy found=true")
	}
	if got := policyByID.GetPolicy().GetPolicyId(); got != policyCanonicalID {
		t.Fatalf("expected canonical policy id %q, got %q", policyCanonicalID, got)
	}
	if got := policyByID.GetPolicy().GetTitle(); got != "Bootstrap validator policy" {
		t.Fatalf("expected policy title Bootstrap validator policy, got %q", got)
	}
	policyByMixedID, err := governanceQuery.GovernancePolicy(ctx, &vpngovernancepb.QueryGovernancePolicyRequest{
		PolicyId: policyMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query governance policy with mixed-case id: %v", err)
	}
	if !policyByMixedID.GetFound() {
		t.Fatalf("expected mixed-case governance policy lookup found=true")
	}
	if got := policyByMixedID.GetPolicy().GetPolicyId(); got != policyCanonicalID {
		t.Fatalf("expected mixed-case policy query to resolve canonical policy id %q, got %q", policyCanonicalID, got)
	}

	policyList, err := governanceQuery.ListGovernancePolicies(ctx, &vpngovernancepb.QueryListGovernancePoliciesRequest{})
	if err != nil {
		t.Fatalf("list governance policies: %v", err)
	}
	foundPolicy := false
	for _, item := range policyList.GetPolicies() {
		if item.GetPolicyId() == policyCanonicalID {
			foundPolicy = true
			break
		}
	}
	if !foundPolicy {
		t.Fatalf("expected canonical governance policy %q in list", policyCanonicalID)
	}

	decisionInputID := "  GoVeRnAnCe-Decision-GRPC-RT-1  "
	decisionCanonicalID := "governance-decision-grpc-rt-1"
	decisionMixedQueryID := "  GOVERNANCE-DECISION-GRPC-RT-1  "
	proposalInputID := "  PrOpOsAl-GRPC-RT-1  "
	proposalCanonicalID := "proposal-grpc-rt-1"
	decisionResp, err := governanceMsg.RecordDecision(ctx, &vpngovernancepb.MsgRecordDecisionRequest{
		Decision: &vpngovernancepb.GovernanceDecision{
			DecisionId:    decisionInputID,
			PolicyId:      policyMixedQueryID,
			ProposalId:    proposalInputID,
			Outcome:       "approve",
			Decider:       "bootstrap-multisig",
			Reason:        "objective criteria met",
			DecidedAtUnix: 1713001004,
			Status:        vpngovernancepb.ReconciliationStatus_RECONCILIATION_STATUS_SUBMITTED,
		},
	})
	if err != nil {
		t.Fatalf("record governance decision: %v", err)
	}
	if decisionResp.GetDecision() == nil || decisionResp.GetDecision().GetDecisionId() != decisionCanonicalID {
		t.Fatalf("unexpected decision response: %+v", decisionResp.GetDecision())
	}
	if decisionResp.GetIdempotentReplay() || decisionResp.GetConflict() {
		t.Fatalf("unexpected decision replay/conflict flags: replay=%v conflict=%v", decisionResp.GetIdempotentReplay(), decisionResp.GetConflict())
	}
	if got := decisionResp.GetDecision().GetPolicyId(); got != policyCanonicalID {
		t.Fatalf("expected canonical decision policy id %q, got %q", policyCanonicalID, got)
	}
	if got := decisionResp.GetDecision().GetProposalId(); got != proposalCanonicalID {
		t.Fatalf("expected canonical decision proposal id %q, got %q", proposalCanonicalID, got)
	}

	decisionByID, err := governanceQuery.GovernanceDecision(ctx, &vpngovernancepb.QueryGovernanceDecisionRequest{
		DecisionId: decisionCanonicalID,
	})
	if err != nil {
		t.Fatalf("query governance decision: %v", err)
	}
	if !decisionByID.GetFound() {
		t.Fatalf("expected governance decision found=true")
	}
	if got := decisionByID.GetDecision().GetDecisionId(); got != decisionCanonicalID {
		t.Fatalf("expected canonical decision id %q, got %q", decisionCanonicalID, got)
	}
	if got := decisionByID.GetDecision().GetPolicyId(); got != policyCanonicalID {
		t.Fatalf("expected decision policy id %q, got %q", policyCanonicalID, got)
	}
	if got := decisionByID.GetDecision().GetProposalId(); got != proposalCanonicalID {
		t.Fatalf("expected decision proposal id %q, got %q", proposalCanonicalID, got)
	}
	decisionByMixedID, err := governanceQuery.GovernanceDecision(ctx, &vpngovernancepb.QueryGovernanceDecisionRequest{
		DecisionId: decisionMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query governance decision with mixed-case id: %v", err)
	}
	if !decisionByMixedID.GetFound() {
		t.Fatalf("expected mixed-case governance decision lookup found=true")
	}
	if got := decisionByMixedID.GetDecision().GetDecisionId(); got != decisionCanonicalID {
		t.Fatalf("expected mixed-case decision query to resolve canonical decision id %q, got %q", decisionCanonicalID, got)
	}

	decisionList, err := governanceQuery.ListGovernanceDecisions(ctx, &vpngovernancepb.QueryListGovernanceDecisionsRequest{})
	if err != nil {
		t.Fatalf("list governance decisions: %v", err)
	}
	foundDecision := false
	for _, item := range decisionList.GetDecisions() {
		if item.GetDecisionId() == decisionCanonicalID {
			foundDecision = true
			break
		}
	}
	if !foundDecision {
		t.Fatalf("expected canonical governance decision %q in list", decisionCanonicalID)
	}

	actionInputID := "  GoVeRnAnCe-Audit-GRPC-RT-1  "
	actionCanonicalID := "governance-audit-grpc-rt-1"
	actionMixedQueryID := "  GOVERNANCE-AUDIT-GRPC-RT-1  "
	actionResp, err := governanceMsg.RecordAuditAction(ctx, &vpngovernancepb.MsgRecordAuditActionRequest{
		Action: &vpngovernancepb.GovernanceAuditAction{
			ActionId:        actionInputID,
			Action:          "manual_override",
			Actor:           "bootstrap-admin",
			Reason:          "bootstrap policy exception",
			EvidencePointer: "ipfs://governance/audit/grpc-rt-1",
			TimestampUnix:   1713001005,
		},
	})
	if err != nil {
		t.Fatalf("record governance audit action: %v", err)
	}
	if actionResp.GetAction() == nil || actionResp.GetAction().GetActionId() != actionCanonicalID {
		t.Fatalf("unexpected audit action response: %+v", actionResp.GetAction())
	}
	if actionResp.GetIdempotentReplay() || actionResp.GetConflict() {
		t.Fatalf("unexpected audit action replay/conflict flags: replay=%v conflict=%v", actionResp.GetIdempotentReplay(), actionResp.GetConflict())
	}

	actionByID, err := governanceQuery.GovernanceAuditAction(ctx, &vpngovernancepb.QueryGovernanceAuditActionRequest{
		ActionId: actionCanonicalID,
	})
	if err != nil {
		t.Fatalf("query governance audit action: %v", err)
	}
	if !actionByID.GetFound() {
		t.Fatalf("expected governance audit action found=true")
	}
	if got := actionByID.GetAction().GetActionId(); got != actionCanonicalID {
		t.Fatalf("expected canonical action id %q, got %q", actionCanonicalID, got)
	}
	if got := actionByID.GetAction().GetActor(); got != "bootstrap-admin" {
		t.Fatalf("expected actor bootstrap-admin, got %q", got)
	}
	actionByMixedID, err := governanceQuery.GovernanceAuditAction(ctx, &vpngovernancepb.QueryGovernanceAuditActionRequest{
		ActionId: actionMixedQueryID,
	})
	if err != nil {
		t.Fatalf("query governance audit action with mixed-case id: %v", err)
	}
	if !actionByMixedID.GetFound() {
		t.Fatalf("expected mixed-case governance audit action lookup found=true")
	}
	if got := actionByMixedID.GetAction().GetActionId(); got != actionCanonicalID {
		t.Fatalf("expected mixed-case action query to resolve canonical action id %q, got %q", actionCanonicalID, got)
	}

	actionList, err := governanceQuery.ListGovernanceAuditActions(ctx, &vpngovernancepb.QueryListGovernanceAuditActionsRequest{})
	if err != nil {
		t.Fatalf("list governance audit actions: %v", err)
	}
	foundAction := false
	for _, item := range actionList.GetActions() {
		if item.GetActionId() == actionCanonicalID {
			foundAction = true
			break
		}
	}
	if !foundAction {
		t.Fatalf("expected canonical governance audit action %q in list", actionCanonicalID)
	}
}
