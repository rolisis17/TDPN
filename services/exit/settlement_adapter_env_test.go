package exit

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"privacynode/pkg/settlement"
)

type exitScopedCosmosRequest struct {
	path            string
	auth            string
	rewardProofAuth string
	finalityAuth    string
	status          string
}

func waitExitScopedCosmosRequest(t *testing.T, ch <-chan exitScopedCosmosRequest) exitScopedCosmosRequest {
	t.Helper()
	select {
	case got := <-ch:
		return got
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for scoped Cosmos adapter request")
		return exitScopedCosmosRequest{}
	}
}

func TestNewSettlementServiceFromEnvCosmosScopedBridgeAuthAndTrustedFinality(t *testing.T) {
	seenCh := make(chan exitScopedCosmosRequest, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = r.Body.Close()
		var payload struct {
			Status string `json:"Status"`
		}
		_ = json.Unmarshal(body, &payload)
		seenCh <- exitScopedCosmosRequest{
			path:            r.URL.Path,
			auth:            r.Header.Get("Authorization"),
			rewardProofAuth: r.Header.Get("X-GPM-Reward-Proof-Authorization"),
			finalityAuth:    r.Header.Get("X-GPM-Finality-Authorization"),
			status:          payload.Status,
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("SETTLEMENT_CHAIN_ADAPTER", "cosmos")
	t.Setenv("COSMOS_SETTLEMENT_ENDPOINT", srv.URL)
	t.Setenv("COSMOS_SETTLEMENT_API_KEY", "exit-bridge-token")
	t.Setenv("COSMOS_SETTLEMENT_TRUSTED_BRIDGE_FINALITY", "true")
	t.Setenv("COSMOS_SETTLEMENT_REWARD_PROOF_AUTH_TOKEN", "exit-proof-token")
	t.Setenv("COSMOS_SETTLEMENT_FINALITY_AUTH_TOKEN", "exit-finality-token")
	t.Setenv("COSMOS_SETTLEMENT_QUEUE_SIZE", "8")
	t.Setenv("COSMOS_SETTLEMENT_MAX_RETRIES", "1")
	t.Setenv("COSMOS_SETTLEMENT_BASE_BACKOFF_MS", "5")
	t.Setenv("COSMOS_SETTLEMENT_HTTP_TIMEOUT_MS", "500")
	t.Setenv("COSMOS_SETTLEMENT_SUBMIT_MODE", "")

	svc := newSettlementServiceFromEnv()
	registrar, ok := svc.(interface {
		RegisterRewardProof(context.Context, settlement.RewardProofRecord) error
	})
	if !ok {
		t.Fatalf("settlement service does not expose reward proof registration")
	}

	now := time.Now().UTC()
	if err := registrar.RegisterRewardProof(context.Background(), settlement.RewardProofRecord{
		ProofPath:         "traffic-proof/exit-scoped-env",
		TrafficProofRef:   "obj://traffic-proof/exit-scoped-env",
		TrustContract:     settlement.RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          "rew-exit-scoped-env",
		ProviderSubjectID: "provider-exit-scoped-env",
		SessionID:         "sess-exit-scoped-env",
		PayoutPeriodStart: now.Add(-time.Hour),
		PayoutPeriodEnd:   now,
		RewardMicros:      100,
		Currency:          "TDPNC",
		IssuedAt:          now,
		Verified:          true,
		VerifierID:        "exit-proof-verifier",
		VerifiedAt:        now,
	}); err != nil {
		t.Fatalf("RegisterRewardProof: %v", err)
	}
	proofReq := waitExitScopedCosmosRequest(t, seenCh)
	if proofReq.path != "/x/vpnrewards/proofs" {
		t.Fatalf("expected reward proof path, got %s", proofReq.path)
	}
	if proofReq.auth != "Bearer exit-bridge-token" {
		t.Fatalf("expected bridge auth on reward proof request, got %q", proofReq.auth)
	}
	if proofReq.rewardProofAuth != "Bearer exit-proof-token" {
		t.Fatalf("expected reward proof scoped auth header, got %q", proofReq.rewardProofAuth)
	}
	if proofReq.finalityAuth != "" {
		t.Fatalf("expected no finality auth on reward proof request, got %q", proofReq.finalityAuth)
	}

	reservation, err := svc.ReserveFunds(context.Background(), settlement.FundReservation{
		ReservationID: "res-exit-finality-env",
		SessionID:     "sess-exit-finality-env",
		SubjectID:     "subject-exit-finality-env",
		AmountMicros:  1000,
		Currency:      "TDPNC",
	})
	if err != nil {
		t.Fatalf("ReserveFunds: %v", err)
	}
	if reservation.Status != settlement.OperationStatusSubmitted {
		t.Fatalf("expected local reservation submitted while chain finality is bridged, got %s", reservation.Status)
	}

	firstReservationReq := waitExitScopedCosmosRequest(t, seenCh)
	secondReservationReq := waitExitScopedCosmosRequest(t, seenCh)
	if firstReservationReq.path != "/x/vpnbilling/reservations" || secondReservationReq.path != "/x/vpnbilling/reservations" {
		t.Fatalf("unexpected trusted finality request paths: first=%s second=%s", firstReservationReq.path, secondReservationReq.path)
	}
	if firstReservationReq.status != string(settlement.OperationStatusSubmitted) {
		t.Fatalf("expected first reservation write submitted, got %q", firstReservationReq.status)
	}
	if firstReservationReq.finalityAuth != "" {
		t.Fatalf("expected no finality auth on submitted reservation write, got %q", firstReservationReq.finalityAuth)
	}
	if secondReservationReq.status != string(settlement.OperationStatusConfirmed) {
		t.Fatalf("expected second reservation write confirmed, got %q", secondReservationReq.status)
	}
	if secondReservationReq.auth != "Bearer exit-bridge-token" {
		t.Fatalf("expected bridge auth on finality request, got %q", secondReservationReq.auth)
	}
	if secondReservationReq.finalityAuth != "Bearer exit-finality-token" {
		t.Fatalf("expected finality scoped auth header, got %q", secondReservationReq.finalityAuth)
	}
}
