package app

import (
	"context"
	"errors"
	"strings"
	"testing"

	chaintypes "github.com/tdpn/tdpn-chain/types"
	rewardstypes "github.com/tdpn/tdpn-chain/x/vpnrewards/types"
	slashingtypes "github.com/tdpn/tdpn-chain/x/vpnslashing/types"
	sponsormodule "github.com/tdpn/tdpn-chain/x/vpnsponsor/module"
	sponsortypes "github.com/tdpn/tdpn-chain/x/vpnsponsor/types"
)

func TestRewardsMsgServer_AccessorAndFlow(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.RewardsMsgServer()

	accrual := rewardstypes.RewardAccrual{
		AccrualID:  "acc-1",
		SessionID:  "sess-1",
		ProviderID: "provider-1",
		AssetDenom: "utdpn",
		Amount:     50,
	}
	accrualResp, err := server.CreateAccrual(context.Background(), RewardsCreateAccrualRequest{Record: accrual})
	if err != nil {
		t.Fatalf("expected create accrual success, got %v", err)
	}
	if accrualResp.Replay {
		t.Fatal("expected first accrual create to not be replay")
	}
	if accrualResp.Accrual.OperationState != chaintypes.ReconciliationPending {
		t.Fatalf("expected default accrual status %q, got %q", chaintypes.ReconciliationPending, accrualResp.Accrual.OperationState)
	}

	dist := rewardstypes.DistributionRecord{
		DistributionID: "dist-1",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "pay-1",
	}
	distResp, err := server.RecordDistribution(context.Background(), RewardsRecordDistributionRequest{Record: dist})
	if err != nil {
		t.Fatalf("expected distribution record success, got %v", err)
	}
	if distResp.Replay {
		t.Fatal("expected first distribution to not be replay")
	}
	if distResp.Distribution.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected distribution status %q, got %q", chaintypes.ReconciliationSubmitted, distResp.Distribution.Status)
	}

	updatedAccrual, ok := scaffold.RewardsModule.Keeper.GetAccrual(accrual.AccrualID)
	if !ok {
		t.Fatal("expected accrual to exist")
	}
	if updatedAccrual.OperationState != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected accrual status %q after distribution, got %q", chaintypes.ReconciliationConfirmed, updatedAccrual.OperationState)
	}

	replayResp, err := server.RecordDistribution(context.Background(), RewardsRecordDistributionRequest{Record: dist})
	if err != nil {
		t.Fatalf("expected replay distribution success, got %v", err)
	}
	if !replayResp.Replay {
		t.Fatal("expected replay=true for duplicate distribution")
	}
}

func TestRewardsMsgServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.RewardsMsgServer()

	_, err := server.CreateAccrual(context.Background(), RewardsCreateAccrualRequest{
		Record: rewardstypes.RewardAccrual{
			AccrualID:  "acc-nil",
			ProviderID: "provider-1",
			Amount:     1,
		},
	})
	if err == nil {
		t.Fatal("expected nil scaffold rewards server error")
	}
	if !strings.Contains(err.Error(), "vpnrewards keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSlashingMsgServer_AccessorAndFlow(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SlashingMsgServer()

	evidence := slashingtypes.SlashEvidence{
		EvidenceID:    "evidence-1",
		Kind:          slashingtypes.EvidenceKindObjective,
		ViolationType: "double-sign",
		ProofHash:     "sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090",
	}
	evResp, err := server.SubmitEvidence(context.Background(), SlashingSubmitEvidenceRequest{Record: evidence})
	if err != nil {
		t.Fatalf("expected submit evidence success, got %v", err)
	}
	if evResp.Replay {
		t.Fatal("expected first evidence submit to not be replay")
	}
	if evResp.Evidence.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected evidence status %q, got %q", chaintypes.ReconciliationSubmitted, evResp.Evidence.Status)
	}

	penalty := slashingtypes.PenaltyDecision{
		PenaltyID:       "penalty-1",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 50,
	}
	penaltyResp, err := server.ApplyPenalty(context.Background(), SlashingApplyPenaltyRequest{Record: penalty})
	if err != nil {
		t.Fatalf("expected apply penalty success, got %v", err)
	}
	if penaltyResp.Replay {
		t.Fatal("expected first penalty apply to not be replay")
	}
	if penaltyResp.Penalty.Status != chaintypes.ReconciliationSubmitted {
		t.Fatalf("expected penalty status %q, got %q", chaintypes.ReconciliationSubmitted, penaltyResp.Penalty.Status)
	}

	updatedEvidence, ok := scaffold.SlashingModule.Keeper.GetEvidence(evidence.EvidenceID)
	if !ok {
		t.Fatal("expected evidence to exist")
	}
	if updatedEvidence.Status != chaintypes.ReconciliationConfirmed {
		t.Fatalf("expected evidence status %q after penalty, got %q", chaintypes.ReconciliationConfirmed, updatedEvidence.Status)
	}
}

func TestSlashingMsgServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.SlashingMsgServer()

	_, err := server.SubmitEvidence(context.Background(), SlashingSubmitEvidenceRequest{
		Record: slashingtypes.SlashEvidence{
			EvidenceID:    "evidence-nil",
			Kind:          slashingtypes.EvidenceKindObjective,
			ViolationType: "double-sign",
			ProofHash:     "sha256:97a85b9f687bba82d44975f5f92f40894dc150ae53b4683e2e1509313bac6f73",
		},
	})
	if err == nil {
		t.Fatal("expected nil scaffold slashing server error")
	}
	if !strings.Contains(err.Error(), "vpnslashing keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSponsorMsgServer_AccessorAndFlow(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SponsorMsgServer()

	auth := sponsortypes.SponsorAuthorization{
		AuthorizationID: "auth-1",
		SponsorID:       "sponsor-1",
		AppID:           "app-1",
		MaxCredits:      1000,
	}
	authResp, err := server.CreateAuthorization(context.Background(), SponsorCreateAuthorizationRequest{Record: auth})
	if err != nil {
		t.Fatalf("expected create authorization success, got %v", err)
	}
	if authResp.Replay {
		t.Fatal("expected first authorization create to not be replay")
	}
	if authResp.Authorization.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected authorization status %q, got %q", chaintypes.ReconciliationPending, authResp.Authorization.Status)
	}

	delegation := sponsortypes.DelegatedSessionCredit{
		ReservationID:   "res-1",
		AuthorizationID: auth.AuthorizationID,
		SponsorID:       auth.SponsorID,
		AppID:           auth.AppID,
		SessionID:       "sess-1",
		Credits:         500,
	}
	delegationResp, err := server.DelegateCredit(context.Background(), SponsorDelegateCreditRequest{Record: delegation})
	if err != nil {
		t.Fatalf("expected delegate credit success, got %v", err)
	}
	if delegationResp.Replay {
		t.Fatal("expected first delegation to not be replay")
	}
	if delegationResp.Delegation.Status != chaintypes.ReconciliationPending {
		t.Fatalf("expected delegation status %q, got %q", chaintypes.ReconciliationPending, delegationResp.Delegation.Status)
	}

	replayResp, err := server.DelegateCredit(context.Background(), SponsorDelegateCreditRequest{Record: delegation})
	if err != nil {
		t.Fatalf("expected replay delegation success, got %v", err)
	}
	if !replayResp.Replay {
		t.Fatal("expected replay=true for duplicate delegation")
	}
}

func TestSponsorMsgServer_MissingAuthorization(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SponsorMsgServer()

	_, err := server.DelegateCredit(context.Background(), SponsorDelegateCreditRequest{
		Record: sponsortypes.DelegatedSessionCredit{
			ReservationID:   "res-missing-auth",
			AuthorizationID: "missing",
			SponsorID:       "sponsor-1",
			AppID:           "app-1",
			SessionID:       "sess-1",
			Credits:         1,
		},
	})
	if err == nil {
		t.Fatal("expected missing authorization error")
	}
	if !strings.Contains(err.Error(), "authorization not found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSponsorMsgServer_DelegateCreditRequiresContextTimeForExpiringAuthorization(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SponsorMsgServer()

	auth := sponsortypes.SponsorAuthorization{
		AuthorizationID: "auth-expiring-no-time",
		SponsorID:       "sponsor-expiring-no-time",
		AppID:           "app-expiring-no-time",
		MaxCredits:      1000,
		ExpiresAtUnix:   4102444800,
	}
	if _, err := server.CreateAuthorization(context.Background(), SponsorCreateAuthorizationRequest{Record: auth}); err != nil {
		t.Fatalf("expected create authorization success, got %v", err)
	}

	delegation := sponsortypes.DelegatedSessionCredit{
		ReservationID:   "res-expiring-no-time",
		AuthorizationID: auth.AuthorizationID,
		SponsorID:       auth.SponsorID,
		AppID:           auth.AppID,
		SessionID:       "sess-expiring-no-time",
		Credits:         10,
	}

	_, err := server.DelegateCredit(context.Background(), SponsorDelegateCreditRequest{Record: delegation})
	if err == nil {
		t.Fatal("expected missing context current time to fail for expiring authorization")
	}
	if !errors.Is(err, sponsormodule.ErrInvalidDelegation) {
		t.Fatalf("expected ErrInvalidDelegation, got %v", err)
	}
	if !strings.Contains(err.Error(), "current unix time is required") {
		t.Fatalf("expected current time requirement details in error, got %v", err)
	}
	if _, exists := scaffold.SponsorModule.Keeper.GetDelegation(delegation.ReservationID); exists {
		t.Fatalf("expected no delegation write when current time is missing for reservation %s", delegation.ReservationID)
	}
}

func TestSponsorMsgServer_DelegateCreditAcceptsContextTimeForExpiringAuthorization(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SponsorMsgServer()

	auth := sponsortypes.SponsorAuthorization{
		AuthorizationID: "auth-expiring-with-time",
		SponsorID:       "sponsor-expiring-with-time",
		AppID:           "app-expiring-with-time",
		MaxCredits:      1000,
		ExpiresAtUnix:   4102444800,
	}
	if _, err := server.CreateAuthorization(context.Background(), SponsorCreateAuthorizationRequest{Record: auth}); err != nil {
		t.Fatalf("expected create authorization success, got %v", err)
	}

	delegation := sponsortypes.DelegatedSessionCredit{
		ReservationID:   "res-expiring-with-time",
		AuthorizationID: auth.AuthorizationID,
		SponsorID:       auth.SponsorID,
		AppID:           auth.AppID,
		SessionID:       "sess-expiring-with-time",
		Credits:         10,
	}
	ctx := sponsormodule.WithCurrentTimeUnix(context.Background(), auth.ExpiresAtUnix-1)

	resp, err := server.DelegateCredit(ctx, SponsorDelegateCreditRequest{Record: delegation})
	if err != nil {
		t.Fatalf("expected delegation success with explicit context time, got %v", err)
	}
	if resp.Replay {
		t.Fatal("expected first delegation with explicit context time to not be replay")
	}
	if _, exists := scaffold.SponsorModule.Keeper.GetDelegation(delegation.ReservationID); !exists {
		t.Fatalf("expected delegation write with explicit context time for reservation %s", delegation.ReservationID)
	}
}

func TestSponsorMsgServer_DelegateCreditRejectsNilContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SponsorMsgServer()

	auth := sponsortypes.SponsorAuthorization{
		AuthorizationID: "auth-nil-context",
		SponsorID:       "sponsor-nil-context",
		AppID:           "app-nil-context",
		MaxCredits:      1000,
	}
	if _, err := server.CreateAuthorization(context.Background(), SponsorCreateAuthorizationRequest{Record: auth}); err != nil {
		t.Fatalf("expected create authorization success, got %v", err)
	}

	delegation := sponsortypes.DelegatedSessionCredit{
		ReservationID:   "res-nil-context",
		AuthorizationID: auth.AuthorizationID,
		SponsorID:       auth.SponsorID,
		AppID:           auth.AppID,
		SessionID:       "sess-nil-context",
		Credits:         10,
	}

	_, err := server.DelegateCredit(nil, SponsorDelegateCreditRequest{Record: delegation})
	if err == nil {
		t.Fatal("expected nil context to fail delegate credit")
	}
	if !errors.Is(err, sponsormodule.ErrInvalidDelegation) {
		t.Fatalf("expected ErrInvalidDelegation for nil context, got %v", err)
	}
	if !strings.Contains(err.Error(), "context is required") {
		t.Fatalf("expected context required details in error, got %v", err)
	}
	if _, exists := scaffold.SponsorModule.Keeper.GetDelegation(delegation.ReservationID); exists {
		t.Fatalf("expected no delegation write on nil context for reservation %s", delegation.ReservationID)
	}
}

func TestSponsorMsgServer_NilScaffold(t *testing.T) {
	var scaffold *ChainScaffold
	server := scaffold.SponsorMsgServer()

	_, err := server.CreateAuthorization(context.Background(), SponsorCreateAuthorizationRequest{
		Record: sponsortypes.SponsorAuthorization{
			AuthorizationID: "auth-nil",
			SponsorID:       "sponsor-1",
			AppID:           "app-1",
			MaxCredits:      1,
		},
	})
	if err == nil {
		t.Fatal("expected nil scaffold sponsor server error")
	}
	if !strings.Contains(err.Error(), "vpnsponsor keeper is not wired") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSponsorMsgServer_DelegateCreditHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SponsorMsgServer()

	auth := sponsortypes.SponsorAuthorization{
		AuthorizationID: "auth-canceled-ctx-1",
		SponsorID:       "sponsor-canceled-ctx-1",
		AppID:           "app-canceled-ctx-1",
		MaxCredits:      1000,
	}
	if _, err := server.CreateAuthorization(context.Background(), SponsorCreateAuthorizationRequest{Record: auth}); err != nil {
		t.Fatalf("expected create authorization success, got %v", err)
	}

	delegation := sponsortypes.DelegatedSessionCredit{
		ReservationID:   "res-canceled-ctx-1",
		AuthorizationID: auth.AuthorizationID,
		SponsorID:       auth.SponsorID,
		AppID:           auth.AppID,
		SessionID:       "sess-canceled-ctx-1",
		Credits:         50,
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.DelegateCredit(canceledCtx, SponsorDelegateCreditRequest{Record: delegation}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.SponsorModule.Keeper.GetDelegation(delegation.ReservationID); exists {
		t.Fatalf("expected no delegation write on canceled context for reservation %s", delegation.ReservationID)
	}
}

func TestSponsorMsgServer_CreateAuthorizationHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SponsorMsgServer()

	authorization := sponsortypes.SponsorAuthorization{
		AuthorizationID: "auth-canceled-ctx-2",
		SponsorID:       "sponsor-canceled-ctx-2",
		AppID:           "app-canceled-ctx-2",
		MaxCredits:      125,
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.CreateAuthorization(canceledCtx, SponsorCreateAuthorizationRequest{Record: authorization}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.SponsorModule.Keeper.GetAuthorization(authorization.AuthorizationID); exists {
		t.Fatalf("expected no authorization write on canceled context for authorization %s", authorization.AuthorizationID)
	}
}

func TestRewardsMsgServer_CreateAccrualHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.RewardsMsgServer()

	accrual := rewardstypes.RewardAccrual{
		AccrualID:  "acc-canceled-ctx-1",
		SessionID:  "sess-canceled-ctx-1",
		ProviderID: "provider-canceled-ctx-1",
		AssetDenom: "utdpn",
		Amount:     5,
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.CreateAccrual(canceledCtx, RewardsCreateAccrualRequest{Record: accrual}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.RewardsModule.Keeper.GetAccrual(accrual.AccrualID); exists {
		t.Fatalf("expected no accrual write on canceled context for accrual %s", accrual.AccrualID)
	}
}

func TestRewardsMsgServer_RecordDistributionHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.RewardsMsgServer()

	accrual := rewardstypes.RewardAccrual{
		AccrualID:  "acc-canceled-ctx-2",
		SessionID:  "sess-canceled-ctx-2",
		ProviderID: "provider-canceled-ctx-2",
		AssetDenom: "utdpn",
		Amount:     11,
	}
	if _, err := server.CreateAccrual(context.Background(), RewardsCreateAccrualRequest{Record: accrual}); err != nil {
		t.Fatalf("expected create accrual success, got %v", err)
	}

	distribution := rewardstypes.DistributionRecord{
		DistributionID: "dist-canceled-ctx-2",
		AccrualID:      accrual.AccrualID,
		PayoutRef:      "payout-canceled-ctx-2",
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.RecordDistribution(canceledCtx, RewardsRecordDistributionRequest{Record: distribution}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.RewardsModule.Keeper.GetDistribution(distribution.DistributionID); exists {
		t.Fatalf("expected no distribution write on canceled context for distribution %s", distribution.DistributionID)
	}
}

func TestSlashingMsgServer_SubmitEvidenceHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SlashingMsgServer()

	evidence := slashingtypes.SlashEvidence{
		EvidenceID:    "evidence-canceled-ctx-1",
		Kind:          slashingtypes.EvidenceKindObjective,
		ViolationType: "double-sign",
		ProofHash:     "sha256:991f4ec8f0f9dc31c0f8243e304fb5f87bc9ec89e7c0f9eb9cd0af2fbd2db10f",
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.SubmitEvidence(canceledCtx, SlashingSubmitEvidenceRequest{Record: evidence}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.SlashingModule.Keeper.GetEvidence(evidence.EvidenceID); exists {
		t.Fatalf("expected no evidence write on canceled context for evidence %s", evidence.EvidenceID)
	}
}

func TestSlashingMsgServer_ApplyPenaltyHonorsCanceledContext(t *testing.T) {
	scaffold := NewChainScaffold()
	server := scaffold.SlashingMsgServer()

	evidence := slashingtypes.SlashEvidence{
		EvidenceID:    "evidence-canceled-ctx-2",
		Kind:          slashingtypes.EvidenceKindObjective,
		ViolationType: "double-sign",
		ProofHash:     "sha256:77eca79149ed12a1d5f4191e4ea292072ee2d851bf9ce9ff7e4a0ab9ccb85fa8",
	}
	if _, err := server.SubmitEvidence(context.Background(), SlashingSubmitEvidenceRequest{Record: evidence}); err != nil {
		t.Fatalf("expected submit evidence success, got %v", err)
	}

	penalty := slashingtypes.PenaltyDecision{
		PenaltyID:       "penalty-canceled-ctx-2",
		EvidenceID:      evidence.EvidenceID,
		SlashBasisPoint: 15,
	}

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := server.ApplyPenalty(canceledCtx, SlashingApplyPenaltyRequest{Record: penalty}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled error, got %v", err)
	}

	if _, exists := scaffold.SlashingModule.Keeper.GetPenalty(penalty.PenaltyID); exists {
		t.Fatalf("expected no penalty write on canceled context for penalty %s", penalty.PenaltyID)
	}
}
