package app

import (
	"context"
	"strings"
	"testing"

	billingtypes "github.com/tdpn/tdpn-chain/x/vpnbilling/types"
	rewardstypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
	sponsortypes "github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestBillingQueryServer_AccessorHappyPathAndNotFound(t *testing.T) {
	scaffold := NewChainScaffold()
	queryServer := scaffold.BillingQueryServer()
	msgServer := scaffold.BillingMsgServer()

	missingReservation, err := queryServer.GetReservation(context.Background(), BillingGetReservationRequest{
		ReservationID: "missing-reservation",
	})
	if err != nil {
		t.Fatalf("expected missing reservation query to succeed, got %v", err)
	}
	if missingReservation.Found {
		t.Fatal("expected missing reservation query to return found=false")
	}

	reservation := billingtypes.CreditReservation{
		ReservationID: "res-query-1",
		SponsorID:     "sponsor-1",
		SessionID:     "session-1",
		AssetDenom:    "utdpn",
		Amount:        100,
	}
	if _, err := msgServer.CreateReservation(context.Background(), BillingCreateReservationRequest{Record: reservation}); err != nil {
		t.Fatalf("expected create reservation to succeed, got %v", err)
	}

	foundReservation, err := queryServer.GetReservation(context.Background(), BillingGetReservationRequest{
		ReservationID: reservation.ReservationID,
	})
	if err != nil {
		t.Fatalf("expected reservation query to succeed, got %v", err)
	}
	if !foundReservation.Found {
		t.Fatal("expected reservation query to return found=true")
	}
	if foundReservation.Reservation.ReservationID != reservation.ReservationID {
		t.Fatalf("expected reservation id %q, got %q", reservation.ReservationID, foundReservation.Reservation.ReservationID)
	}

	missingSettlement, err := queryServer.GetSettlement(context.Background(), BillingGetSettlementRequest{
		SettlementID: "missing-settlement",
	})
	if err != nil {
		t.Fatalf("expected missing settlement query to succeed, got %v", err)
	}
	if missingSettlement.Found {
		t.Fatal("expected missing settlement query to return found=false")
	}

	settlement := billingtypes.SettlementRecord{
		SettlementID:  "set-query-1",
		ReservationID: reservation.ReservationID,
		SessionID:     reservation.SessionID,
		BilledAmount:  20,
		UsageBytes:    1024,
		AssetDenom:    "utdpn",
	}
	if _, err := msgServer.FinalizeSettlement(context.Background(), BillingFinalizeSettlementRequest{Record: settlement}); err != nil {
		t.Fatalf("expected finalize settlement to succeed, got %v", err)
	}

	foundSettlement, err := queryServer.GetSettlement(context.Background(), BillingGetSettlementRequest{
		SettlementID: settlement.SettlementID,
	})
	if err != nil {
		t.Fatalf("expected settlement query to succeed, got %v", err)
	}
	if !foundSettlement.Found {
		t.Fatal("expected settlement query to return found=true")
	}
	if foundSettlement.Settlement.SettlementID != settlement.SettlementID {
		t.Fatalf("expected settlement id %q, got %q", settlement.SettlementID, foundSettlement.Settlement.SettlementID)
	}

	anotherReservation := billingtypes.CreditReservation{
		ReservationID: "res-query-0",
		SponsorID:     "sponsor-0",
		SessionID:     "session-0",
		AssetDenom:    "utdpn",
		Amount:        50,
	}
	if _, err := msgServer.CreateReservation(context.Background(), BillingCreateReservationRequest{Record: anotherReservation}); err != nil {
		t.Fatalf("expected create second reservation to succeed, got %v", err)
	}

	anotherSettlement := billingtypes.SettlementRecord{
		SettlementID:  "set-query-0",
		ReservationID: anotherReservation.ReservationID,
		SessionID:     anotherReservation.SessionID,
		BilledAmount:  10,
		UsageBytes:    512,
		AssetDenom:    "utdpn",
	}
	if _, err := msgServer.FinalizeSettlement(context.Background(), BillingFinalizeSettlementRequest{Record: anotherSettlement}); err != nil {
		t.Fatalf("expected finalize second settlement to succeed, got %v", err)
	}

	reservationList, err := queryServer.ListReservations(context.Background(), BillingListReservationsRequest{})
	if err != nil {
		t.Fatalf("expected reservation list query to succeed, got %v", err)
	}
	if len(reservationList.Reservations) != 2 {
		t.Fatalf("expected 2 reservations, got %d", len(reservationList.Reservations))
	}
	if reservationList.Reservations[0].ReservationID != "res-query-0" || reservationList.Reservations[1].ReservationID != "res-query-1" {
		t.Fatalf("expected sorted reservation ids [res-query-0 res-query-1], got [%s %s]", reservationList.Reservations[0].ReservationID, reservationList.Reservations[1].ReservationID)
	}

	settlementList, err := queryServer.ListSettlements(context.Background(), BillingListSettlementsRequest{})
	if err != nil {
		t.Fatalf("expected settlement list query to succeed, got %v", err)
	}
	if len(settlementList.Settlements) != 2 {
		t.Fatalf("expected 2 settlements, got %d", len(settlementList.Settlements))
	}
	if settlementList.Settlements[0].SettlementID != "set-query-0" || settlementList.Settlements[1].SettlementID != "set-query-1" {
		t.Fatalf("expected sorted settlement ids [set-query-0 set-query-1], got [%s %s]", settlementList.Settlements[0].SettlementID, settlementList.Settlements[1].SettlementID)
	}
}

func TestBillingQueryServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.BillingQueryServer()

	_, err := server.GetReservation(context.Background(), BillingGetReservationRequest{ReservationID: "res-1"})
	if err == nil {
		t.Fatal("expected nil scaffold billing query to fail")
	}
	if !strings.Contains(err.Error(), "vpnbilling keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.GetSettlement(context.Background(), BillingGetSettlementRequest{SettlementID: "set-1"})
	if err == nil {
		t.Fatal("expected nil scaffold billing settlement query to fail")
	}
	if !strings.Contains(err.Error(), "vpnbilling keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListReservations(context.Background(), BillingListReservationsRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold billing reservation list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnbilling keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListSettlements(context.Background(), BillingListSettlementsRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold billing settlement list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnbilling keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRewardsQueryServer_AccessorHappyPathAndNotFound(t *testing.T) {
	scaffold := NewChainScaffold()
	queryServer := scaffold.RewardsQueryServer()
	msgServer := scaffold.RewardsMsgServer()

	missingAccrual, err := queryServer.GetAccrual(context.Background(), RewardsGetAccrualRequest{
		AccrualID: "missing-accrual",
	})
	if err != nil {
		t.Fatalf("expected missing accrual query to succeed, got %v", err)
	}
	if missingAccrual.Found {
		t.Fatal("expected missing accrual query to return found=false")
	}

	accrual := rewardstypes.RewardAccrual{
		AccrualID:  "acc-query-1",
		SessionID:  "session-1",
		ProviderID: "provider-1",
		AssetDenom: "utdpn",
		Amount:     10,
	}
	if _, err := msgServer.CreateAccrual(context.Background(), RewardsCreateAccrualRequest{Record: accrual}); err != nil {
		t.Fatalf("expected create accrual to succeed, got %v", err)
	}

	foundAccrual, err := queryServer.GetAccrual(context.Background(), RewardsGetAccrualRequest{
		AccrualID: accrual.AccrualID,
	})
	if err != nil {
		t.Fatalf("expected accrual query to succeed, got %v", err)
	}
	if !foundAccrual.Found {
		t.Fatal("expected accrual query to return found=true")
	}
	if foundAccrual.Accrual.AccrualID != accrual.AccrualID {
		t.Fatalf("expected accrual id %q, got %q", accrual.AccrualID, foundAccrual.Accrual.AccrualID)
	}

	missingDistribution, err := queryServer.GetDistribution(context.Background(), RewardsGetDistributionRequest{
		DistributionID: "missing-distribution",
	})
	if err != nil {
		t.Fatalf("expected missing distribution query to succeed, got %v", err)
	}
	if missingDistribution.Found {
		t.Fatal("expected missing distribution query to return found=false")
	}

	distribution := rewardstypes.DistributionRecord{
		DistributionID: "dist-query-1",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-1",
	}
	if _, err := msgServer.RecordDistribution(context.Background(), RewardsRecordDistributionRequest{Record: distribution}); err != nil {
		t.Fatalf("expected record distribution to succeed, got %v", err)
	}

	foundDistribution, err := queryServer.GetDistribution(context.Background(), RewardsGetDistributionRequest{
		DistributionID: distribution.DistributionID,
	})
	if err != nil {
		t.Fatalf("expected distribution query to succeed, got %v", err)
	}
	if !foundDistribution.Found {
		t.Fatal("expected distribution query to return found=true")
	}
	if foundDistribution.Distribution.DistributionID != distribution.DistributionID {
		t.Fatalf("expected distribution id %q, got %q", distribution.DistributionID, foundDistribution.Distribution.DistributionID)
	}

	anotherAccrual := rewardstypes.RewardAccrual{
		AccrualID:  "acc-query-0",
		SessionID:  "session-0",
		ProviderID: "provider-0",
		AssetDenom: "utdpn",
		Amount:     5,
	}
	if _, err := msgServer.CreateAccrual(context.Background(), RewardsCreateAccrualRequest{Record: anotherAccrual}); err != nil {
		t.Fatalf("expected create second accrual to succeed, got %v", err)
	}

	anotherDistribution := rewardstypes.DistributionRecord{
		DistributionID: "dist-query-0",
		AccrualID:      anotherAccrual.AccrualID,
		PayoutRef:      "payout-0",
	}
	if _, err := msgServer.RecordDistribution(context.Background(), RewardsRecordDistributionRequest{Record: anotherDistribution}); err != nil {
		t.Fatalf("expected second distribution record to succeed, got %v", err)
	}

	accrualList, err := queryServer.ListAccruals(context.Background(), RewardsListAccrualsRequest{})
	if err != nil {
		t.Fatalf("expected accrual list query to succeed, got %v", err)
	}
	if len(accrualList.Accruals) != 2 {
		t.Fatalf("expected 2 accruals, got %d", len(accrualList.Accruals))
	}
	if accrualList.Accruals[0].AccrualID != "acc-query-0" || accrualList.Accruals[1].AccrualID != "acc-query-1" {
		t.Fatalf("expected sorted accrual ids [acc-query-0 acc-query-1], got [%s %s]", accrualList.Accruals[0].AccrualID, accrualList.Accruals[1].AccrualID)
	}

	distributionList, err := queryServer.ListDistributions(context.Background(), RewardsListDistributionsRequest{})
	if err != nil {
		t.Fatalf("expected distribution list query to succeed, got %v", err)
	}
	if len(distributionList.Distributions) != 2 {
		t.Fatalf("expected 2 distributions, got %d", len(distributionList.Distributions))
	}
	if distributionList.Distributions[0].DistributionID != "dist-query-0" || distributionList.Distributions[1].DistributionID != "dist-query-1" {
		t.Fatalf("expected sorted distribution ids [dist-query-0 dist-query-1], got [%s %s]", distributionList.Distributions[0].DistributionID, distributionList.Distributions[1].DistributionID)
	}
}

func TestRewardsQueryServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.RewardsQueryServer()

	_, err := server.GetAccrual(context.Background(), RewardsGetAccrualRequest{AccrualID: "acc-1"})
	if err == nil {
		t.Fatal("expected nil scaffold rewards query to fail")
	}
	if !strings.Contains(err.Error(), "vpnrewards keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.GetDistribution(context.Background(), RewardsGetDistributionRequest{DistributionID: "dist-1"})
	if err == nil {
		t.Fatal("expected nil scaffold rewards distribution query to fail")
	}
	if !strings.Contains(err.Error(), "vpnrewards keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListAccruals(context.Background(), RewardsListAccrualsRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold rewards accrual list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnrewards keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListDistributions(context.Background(), RewardsListDistributionsRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold rewards distribution list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnrewards keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSlashingQueryServer_AccessorHappyPathAndNotFound(t *testing.T) {
	scaffold := NewChainScaffold()
	queryServer := scaffold.SlashingQueryServer()
	msgServer := scaffold.SlashingMsgServer()

	missingEvidence, err := queryServer.GetEvidence(context.Background(), SlashingGetEvidenceRequest{
		EvidenceID: "missing-evidence",
	})
	if err != nil {
		t.Fatalf("expected missing evidence query to succeed, got %v", err)
	}
	if missingEvidence.Found {
		t.Fatal("expected missing evidence query to return found=false")
	}

	evidence := slashingtypes.SlashEvidence{
		EvidenceID:    "ev-query-1",
		Kind:          slashingtypes.EvidenceKindObjective,
		ViolationType: "double-sign",
		ProofHash:     "sha256:98c28e7336b1709232b3cf6d5a5af8c4d0a779fe32360f37d8a1c832f03e5cbf",
	}
	if _, err := msgServer.SubmitEvidence(context.Background(), SlashingSubmitEvidenceRequest{Record: evidence}); err != nil {
		t.Fatalf("expected submit evidence to succeed, got %v", err)
	}

	foundEvidence, err := queryServer.GetEvidence(context.Background(), SlashingGetEvidenceRequest{
		EvidenceID: evidence.EvidenceID,
	})
	if err != nil {
		t.Fatalf("expected evidence query to succeed, got %v", err)
	}
	if !foundEvidence.Found {
		t.Fatal("expected evidence query to return found=true")
	}
	if foundEvidence.Evidence.EvidenceID != evidence.EvidenceID {
		t.Fatalf("expected evidence id %q, got %q", evidence.EvidenceID, foundEvidence.Evidence.EvidenceID)
	}

	missingPenalty, err := queryServer.GetPenalty(context.Background(), SlashingGetPenaltyRequest{
		PenaltyID: "missing-penalty",
	})
	if err != nil {
		t.Fatalf("expected missing penalty query to succeed, got %v", err)
	}
	if missingPenalty.Found {
		t.Fatal("expected missing penalty query to return found=false")
	}

	penalty := slashingtypes.PenaltyDecision{
		PenaltyID:       "pen-query-1",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 25,
	}
	if _, err := msgServer.ApplyPenalty(context.Background(), SlashingApplyPenaltyRequest{Record: penalty}); err != nil {
		t.Fatalf("expected apply penalty to succeed, got %v", err)
	}

	foundPenalty, err := queryServer.GetPenalty(context.Background(), SlashingGetPenaltyRequest{
		PenaltyID: penalty.PenaltyID,
	})
	if err != nil {
		t.Fatalf("expected penalty query to succeed, got %v", err)
	}
	if !foundPenalty.Found {
		t.Fatal("expected penalty query to return found=true")
	}
	if foundPenalty.Penalty.PenaltyID != penalty.PenaltyID {
		t.Fatalf("expected penalty id %q, got %q", penalty.PenaltyID, foundPenalty.Penalty.PenaltyID)
	}

	anotherEvidence := slashingtypes.SlashEvidence{
		EvidenceID:    "ev-query-0",
		Kind:          slashingtypes.EvidenceKindObjective,
		ViolationType: "double-sign",
		ProofHash:     "sha256:8df34bb962577b90d574a51ed2ca75759f1f2a17e6f59f8adf173808261ed7e6",
	}
	if _, err := msgServer.SubmitEvidence(context.Background(), SlashingSubmitEvidenceRequest{Record: anotherEvidence}); err != nil {
		t.Fatalf("expected submit second evidence to succeed, got %v", err)
	}

	anotherPenalty := slashingtypes.PenaltyDecision{
		PenaltyID:       "pen-query-0",
		EvidenceID:      anotherEvidence.EvidenceID,
		SlashBasisPoint: 10,
	}
	if _, err := msgServer.ApplyPenalty(context.Background(), SlashingApplyPenaltyRequest{Record: anotherPenalty}); err != nil {
		t.Fatalf("expected apply second penalty to succeed, got %v", err)
	}

	evidenceList, err := queryServer.ListEvidence(context.Background(), SlashingListEvidenceRequest{})
	if err != nil {
		t.Fatalf("expected evidence list query to succeed, got %v", err)
	}
	if len(evidenceList.Evidence) != 2 {
		t.Fatalf("expected 2 evidence records, got %d", len(evidenceList.Evidence))
	}
	if evidenceList.Evidence[0].EvidenceID != "ev-query-0" || evidenceList.Evidence[1].EvidenceID != "ev-query-1" {
		t.Fatalf("expected sorted evidence ids [ev-query-0 ev-query-1], got [%s %s]", evidenceList.Evidence[0].EvidenceID, evidenceList.Evidence[1].EvidenceID)
	}

	penaltyList, err := queryServer.ListPenalties(context.Background(), SlashingListPenaltiesRequest{})
	if err != nil {
		t.Fatalf("expected penalties list query to succeed, got %v", err)
	}
	if len(penaltyList.Penalties) != 2 {
		t.Fatalf("expected 2 penalties, got %d", len(penaltyList.Penalties))
	}
	if penaltyList.Penalties[0].PenaltyID != "pen-query-0" || penaltyList.Penalties[1].PenaltyID != "pen-query-1" {
		t.Fatalf("expected sorted penalty ids [pen-query-0 pen-query-1], got [%s %s]", penaltyList.Penalties[0].PenaltyID, penaltyList.Penalties[1].PenaltyID)
	}
}

func TestSlashingQueryServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.SlashingQueryServer()

	_, err := server.GetEvidence(context.Background(), SlashingGetEvidenceRequest{EvidenceID: "ev-1"})
	if err == nil {
		t.Fatal("expected nil scaffold slashing query to fail")
	}
	if !strings.Contains(err.Error(), "vpnslashing keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.GetPenalty(context.Background(), SlashingGetPenaltyRequest{PenaltyID: "pen-1"})
	if err == nil {
		t.Fatal("expected nil scaffold slashing penalty query to fail")
	}
	if !strings.Contains(err.Error(), "vpnslashing keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListEvidence(context.Background(), SlashingListEvidenceRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold slashing evidence list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnslashing keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListPenalties(context.Background(), SlashingListPenaltiesRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold slashing penalties list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnslashing keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSponsorQueryServer_AccessorHappyPathAndNotFound(t *testing.T) {
	scaffold := NewChainScaffold()
	queryServer := scaffold.SponsorQueryServer()
	msgServer := scaffold.SponsorMsgServer()

	missingAuthorization, err := queryServer.GetAuthorization(context.Background(), SponsorGetAuthorizationRequest{
		AuthorizationID: "missing-authorization",
	})
	if err != nil {
		t.Fatalf("expected missing authorization query to succeed, got %v", err)
	}
	if missingAuthorization.Found {
		t.Fatal("expected missing authorization query to return found=false")
	}

	authorization := sponsortypes.SponsorAuthorization{
		AuthorizationID: "auth-query-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      100,
	}
	if _, err := msgServer.CreateAuthorization(context.Background(), SponsorCreateAuthorizationRequest{Record: authorization}); err != nil {
		t.Fatalf("expected create authorization to succeed, got %v", err)
	}

	foundAuthorization, err := queryServer.GetAuthorization(context.Background(), SponsorGetAuthorizationRequest{
		AuthorizationID: authorization.AuthorizationID,
	})
	if err != nil {
		t.Fatalf("expected authorization query to succeed, got %v", err)
	}
	if !foundAuthorization.Found {
		t.Fatal("expected authorization query to return found=true")
	}
	if foundAuthorization.Authorization.AuthorizationID != authorization.AuthorizationID {
		t.Fatalf("expected authorization id %q, got %q", authorization.AuthorizationID, foundAuthorization.Authorization.AuthorizationID)
	}

	missingDelegation, err := queryServer.GetDelegation(context.Background(), SponsorGetDelegationRequest{
		ReservationID: "missing-delegation",
	})
	if err != nil {
		t.Fatalf("expected missing delegation query to succeed, got %v", err)
	}
	if missingDelegation.Found {
		t.Fatal("expected missing delegation query to return found=false")
	}

	delegation := sponsortypes.DelegatedSessionCredit{
		ReservationID:   "res-query-1",
		AuthorizationID: authorization.AuthorizationID,
		SponsorID:       authorization.SponsorID,
		AppID:           authorization.AppID,
		SessionID:       "session-1",
		Credits:         50,
	}
	if _, err := msgServer.DelegateCredit(context.Background(), SponsorDelegateCreditRequest{Record: delegation}); err != nil {
		t.Fatalf("expected delegate credit to succeed, got %v", err)
	}

	foundDelegation, err := queryServer.GetDelegation(context.Background(), SponsorGetDelegationRequest{
		ReservationID: delegation.ReservationID,
	})
	if err != nil {
		t.Fatalf("expected delegation query to succeed, got %v", err)
	}
	if !foundDelegation.Found {
		t.Fatal("expected delegation query to return found=true")
	}
	if foundDelegation.Delegation.ReservationID != delegation.ReservationID {
		t.Fatalf("expected delegation reservation id %q, got %q", delegation.ReservationID, foundDelegation.Delegation.ReservationID)
	}

	anotherAuthorization := sponsortypes.SponsorAuthorization{
		AuthorizationID: "auth-query-0",
		SponsorID:       "sponsor-0",
		AppID:           "app-0",
		MaxCredits:      75,
	}
	if _, err := msgServer.CreateAuthorization(context.Background(), SponsorCreateAuthorizationRequest{Record: anotherAuthorization}); err != nil {
		t.Fatalf("expected create second authorization to succeed, got %v", err)
	}

	anotherDelegation := sponsortypes.DelegatedSessionCredit{
		ReservationID:   "res-query-0",
		AuthorizationID: anotherAuthorization.AuthorizationID,
		SponsorID:       anotherAuthorization.SponsorID,
		AppID:           anotherAuthorization.AppID,
		SessionID:       "session-0",
		Credits:         25,
	}
	if _, err := msgServer.DelegateCredit(context.Background(), SponsorDelegateCreditRequest{Record: anotherDelegation}); err != nil {
		t.Fatalf("expected delegate second credit to succeed, got %v", err)
	}

	authorizationList, err := queryServer.ListAuthorizations(context.Background(), SponsorListAuthorizationsRequest{})
	if err != nil {
		t.Fatalf("expected authorization list query to succeed, got %v", err)
	}
	if len(authorizationList.Authorizations) != 2 {
		t.Fatalf("expected 2 authorizations, got %d", len(authorizationList.Authorizations))
	}
	if authorizationList.Authorizations[0].AuthorizationID != "auth-query-0" || authorizationList.Authorizations[1].AuthorizationID != "auth-query-1" {
		t.Fatalf("expected sorted authorization ids [auth-query-0 auth-query-1], got [%s %s]", authorizationList.Authorizations[0].AuthorizationID, authorizationList.Authorizations[1].AuthorizationID)
	}

	delegationList, err := queryServer.ListDelegations(context.Background(), SponsorListDelegationsRequest{})
	if err != nil {
		t.Fatalf("expected delegation list query to succeed, got %v", err)
	}
	if len(delegationList.Delegations) != 2 {
		t.Fatalf("expected 2 delegations, got %d", len(delegationList.Delegations))
	}
	if delegationList.Delegations[0].ReservationID != "res-query-0" || delegationList.Delegations[1].ReservationID != "res-query-1" {
		t.Fatalf("expected sorted delegation reservation ids [res-query-0 res-query-1], got [%s %s]", delegationList.Delegations[0].ReservationID, delegationList.Delegations[1].ReservationID)
	}
}

func TestSponsorQueryServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.SponsorQueryServer()

	_, err := server.GetAuthorization(context.Background(), SponsorGetAuthorizationRequest{AuthorizationID: "auth-1"})
	if err == nil {
		t.Fatal("expected nil scaffold sponsor query to fail")
	}
	if !strings.Contains(err.Error(), "vpnsponsor keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.GetDelegation(context.Background(), SponsorGetDelegationRequest{ReservationID: "res-1"})
	if err == nil {
		t.Fatal("expected nil scaffold sponsor delegation query to fail")
	}
	if !strings.Contains(err.Error(), "vpnsponsor keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListAuthorizations(context.Background(), SponsorListAuthorizationsRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold sponsor authorization list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnsponsor keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}

	_, err = server.ListDelegations(context.Background(), SponsorListDelegationsRequest{})
	if err == nil {
		t.Fatal("expected nil scaffold sponsor delegation list query to fail")
	}
	if !strings.Contains(err.Error(), "vpnsponsor keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}
