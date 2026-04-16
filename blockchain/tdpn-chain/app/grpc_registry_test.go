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

	finalizeResp, err := billingMsg.FinalizeUsage(ctx, &vpnbillingpb.MsgFinalizeUsageRequest{
		Settlement: &vpnbillingpb.SettlementRecord{
			SettlementId:  "set-grpc-1",
			ReservationId: "res-grpc-1",
			SessionId:     "sess-grpc-1",
			BilledAmount:  750,
			UsageBytes:    2048,
			AssetDenom:    "utdpn",
		},
	})
	if err != nil {
		t.Fatalf("finalize usage: %v", err)
	}
	if finalizeResp.GetSettlement() == nil || finalizeResp.GetSettlement().GetSettlementId() != "set-grpc-1" {
		t.Fatalf("expected finalized settlement set-grpc-1, got %+v", finalizeResp.GetSettlement())
	}

	settlementList, err := billingQuery.ListSettlementRecords(ctx, &vpnbillingpb.QueryListSettlementRecordsRequest{})
	if err != nil {
		t.Fatalf("list settlements: %v", err)
	}
	foundSettlement := false
	for _, item := range settlementList.GetSettlements() {
		if item.GetSettlementId() == "set-grpc-1" {
			foundSettlement = true
			break
		}
	}
	if !foundSettlement {
		t.Fatalf("expected settlement set-grpc-1 in list")
	}

	rewardsQuery := vpnrewardspb.NewQueryClient(conn)
	if _, err := rewardsQuery.ListRewardAccruals(ctx, &vpnrewardspb.QueryListRewardAccrualsRequest{}); err != nil {
		t.Fatalf("rewards list accruals: %v", err)
	}
	if _, err := rewardsQuery.ListDistributionRecords(ctx, &vpnrewardspb.QueryListDistributionRecordsRequest{}); err != nil {
		t.Fatalf("rewards list distribution records: %v", err)
	}

	slashingQuery := vpnslashingpb.NewQueryClient(conn)
	if _, err := slashingQuery.ListSlashEvidence(ctx, &vpnslashingpb.QueryListSlashEvidenceRequest{}); err != nil {
		t.Fatalf("slashing list evidence: %v", err)
	}
	if _, err := slashingQuery.ListPenaltyDecisions(ctx, &vpnslashingpb.QueryListPenaltyDecisionsRequest{}); err != nil {
		t.Fatalf("slashing list penalty decisions: %v", err)
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

	delegationList, err := sponsorQuery.ListDelegatedSessionCredits(ctx, &vpnsponsorpb.QueryListDelegatedSessionCreditsRequest{})
	if err != nil {
		t.Fatalf("list delegated session credits: %v", err)
	}
	foundDelegation := false
	for _, item := range delegationList.GetDelegations() {
		if item.GetReservationId() == "res-delegate-grpc-1" {
			foundDelegation = true
			break
		}
	}
	if !foundDelegation {
		t.Fatalf("expected delegated session credit res-delegate-grpc-1 in list")
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

	eligibilityID := "validator-grpc-rt-1"
	eligibilityResp, err := validatorMsg.SetValidatorEligibility(ctx, &vpnvalidatorpb.MsgSetValidatorEligibilityRequest{
		Eligibility: &vpnvalidatorpb.ValidatorEligibility{
			ValidatorId:     eligibilityID,
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
	if eligibilityResp.GetEligibility() == nil || eligibilityResp.GetEligibility().GetValidatorId() != eligibilityID {
		t.Fatalf("unexpected eligibility response: %+v", eligibilityResp.GetEligibility())
	}

	eligibilityByID, err := validatorQuery.ValidatorEligibility(ctx, &vpnvalidatorpb.QueryValidatorEligibilityRequest{
		ValidatorId: eligibilityID,
	})
	if err != nil {
		t.Fatalf("query validator eligibility: %v", err)
	}
	if !eligibilityByID.GetFound() {
		t.Fatalf("expected validator eligibility found=true")
	}
	if got := eligibilityByID.GetEligibility().GetOperatorAddress(); got != "tdpnvaloper1grpcroundtrip" {
		t.Fatalf("expected operator address tdpnvaloper1grpcroundtrip, got %q", got)
	}

	eligibilityList, err := validatorQuery.ListValidatorEligibilities(ctx, &vpnvalidatorpb.QueryListValidatorEligibilitiesRequest{})
	if err != nil {
		t.Fatalf("list validator eligibilities: %v", err)
	}
	foundEligibility := false
	for _, item := range eligibilityList.GetEligibilities() {
		if item.GetValidatorId() == eligibilityID {
			foundEligibility = true
			break
		}
	}
	if !foundEligibility {
		t.Fatalf("expected validator eligibility %q in list", eligibilityID)
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
				ValidatorId:         eligibilityID,
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

	statusID := "validator-status-grpc-rt-1"
	statusResp, err := validatorMsg.RecordValidatorStatus(ctx, &vpnvalidatorpb.MsgRecordValidatorStatusRequest{
		Record: &vpnvalidatorpb.ValidatorStatusRecord{
			StatusId:         statusID,
			ValidatorId:      eligibilityID,
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
	if statusResp.GetRecord() == nil || statusResp.GetRecord().GetStatusId() != statusID {
		t.Fatalf("unexpected validator status response: %+v", statusResp.GetRecord())
	}

	statusByID, err := validatorQuery.ValidatorStatusRecord(ctx, &vpnvalidatorpb.QueryValidatorStatusRecordRequest{
		StatusId: statusID,
	})
	if err != nil {
		t.Fatalf("query validator status: %v", err)
	}
	if !statusByID.GetFound() {
		t.Fatalf("expected validator status found=true")
	}
	if got := statusByID.GetRecord().GetLifecycleStatus(); got != "active" {
		t.Fatalf("expected lifecycle status active, got %q", got)
	}

	statusList, err := validatorQuery.ListValidatorStatusRecords(ctx, &vpnvalidatorpb.QueryListValidatorStatusRecordsRequest{})
	if err != nil {
		t.Fatalf("list validator status records: %v", err)
	}
	foundStatus := false
	for _, item := range statusList.GetRecords() {
		if item.GetStatusId() == statusID {
			foundStatus = true
			break
		}
	}
	if !foundStatus {
		t.Fatalf("expected validator status %q in list", statusID)
	}

	policyID := "governance-policy-grpc-rt-1"
	policyResp, err := governanceMsg.CreatePolicy(ctx, &vpngovernancepb.MsgCreatePolicyRequest{
		Policy: &vpngovernancepb.GovernancePolicy{
			PolicyId:        policyID,
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
	if policyResp.GetPolicy() == nil || policyResp.GetPolicy().GetPolicyId() != policyID {
		t.Fatalf("unexpected policy response: %+v", policyResp.GetPolicy())
	}
	if policyResp.GetIdempotentReplay() || policyResp.GetConflict() {
		t.Fatalf("unexpected policy replay/conflict flags: replay=%v conflict=%v", policyResp.GetIdempotentReplay(), policyResp.GetConflict())
	}

	policyByID, err := governanceQuery.GovernancePolicy(ctx, &vpngovernancepb.QueryGovernancePolicyRequest{
		PolicyId: policyID,
	})
	if err != nil {
		t.Fatalf("query governance policy: %v", err)
	}
	if !policyByID.GetFound() {
		t.Fatalf("expected governance policy found=true")
	}
	if got := policyByID.GetPolicy().GetTitle(); got != "Bootstrap validator policy" {
		t.Fatalf("expected policy title Bootstrap validator policy, got %q", got)
	}

	policyList, err := governanceQuery.ListGovernancePolicies(ctx, &vpngovernancepb.QueryListGovernancePoliciesRequest{})
	if err != nil {
		t.Fatalf("list governance policies: %v", err)
	}
	foundPolicy := false
	for _, item := range policyList.GetPolicies() {
		if item.GetPolicyId() == policyID {
			foundPolicy = true
			break
		}
	}
	if !foundPolicy {
		t.Fatalf("expected governance policy %q in list", policyID)
	}

	decisionID := "governance-decision-grpc-rt-1"
	decisionResp, err := governanceMsg.RecordDecision(ctx, &vpngovernancepb.MsgRecordDecisionRequest{
		Decision: &vpngovernancepb.GovernanceDecision{
			DecisionId:    decisionID,
			PolicyId:      policyID,
			ProposalId:    "proposal-grpc-rt-1",
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
	if decisionResp.GetDecision() == nil || decisionResp.GetDecision().GetDecisionId() != decisionID {
		t.Fatalf("unexpected decision response: %+v", decisionResp.GetDecision())
	}
	if decisionResp.GetIdempotentReplay() || decisionResp.GetConflict() {
		t.Fatalf("unexpected decision replay/conflict flags: replay=%v conflict=%v", decisionResp.GetIdempotentReplay(), decisionResp.GetConflict())
	}

	decisionByID, err := governanceQuery.GovernanceDecision(ctx, &vpngovernancepb.QueryGovernanceDecisionRequest{
		DecisionId: decisionID,
	})
	if err != nil {
		t.Fatalf("query governance decision: %v", err)
	}
	if !decisionByID.GetFound() {
		t.Fatalf("expected governance decision found=true")
	}
	if got := decisionByID.GetDecision().GetPolicyId(); got != policyID {
		t.Fatalf("expected decision policy id %q, got %q", policyID, got)
	}

	decisionList, err := governanceQuery.ListGovernanceDecisions(ctx, &vpngovernancepb.QueryListGovernanceDecisionsRequest{})
	if err != nil {
		t.Fatalf("list governance decisions: %v", err)
	}
	foundDecision := false
	for _, item := range decisionList.GetDecisions() {
		if item.GetDecisionId() == decisionID {
			foundDecision = true
			break
		}
	}
	if !foundDecision {
		t.Fatalf("expected governance decision %q in list", decisionID)
	}

	actionID := "governance-audit-grpc-rt-1"
	actionResp, err := governanceMsg.RecordAuditAction(ctx, &vpngovernancepb.MsgRecordAuditActionRequest{
		Action: &vpngovernancepb.GovernanceAuditAction{
			ActionId:        actionID,
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
	if actionResp.GetAction() == nil || actionResp.GetAction().GetActionId() != actionID {
		t.Fatalf("unexpected audit action response: %+v", actionResp.GetAction())
	}
	if actionResp.GetIdempotentReplay() || actionResp.GetConflict() {
		t.Fatalf("unexpected audit action replay/conflict flags: replay=%v conflict=%v", actionResp.GetIdempotentReplay(), actionResp.GetConflict())
	}

	actionByID, err := governanceQuery.GovernanceAuditAction(ctx, &vpngovernancepb.QueryGovernanceAuditActionRequest{
		ActionId: actionID,
	})
	if err != nil {
		t.Fatalf("query governance audit action: %v", err)
	}
	if !actionByID.GetFound() {
		t.Fatalf("expected governance audit action found=true")
	}
	if got := actionByID.GetAction().GetActor(); got != "bootstrap-admin" {
		t.Fatalf("expected actor bootstrap-admin, got %q", got)
	}

	actionList, err := governanceQuery.ListGovernanceAuditActions(ctx, &vpngovernancepb.QueryListGovernanceAuditActionsRequest{})
	if err != nil {
		t.Fatalf("list governance audit actions: %v", err)
	}
	foundAction := false
	for _, item := range actionList.GetActions() {
		if item.GetActionId() == actionID {
			foundAction = true
			break
		}
	}
	if !foundAction {
		t.Fatalf("expected governance audit action %q in list", actionID)
	}
}
