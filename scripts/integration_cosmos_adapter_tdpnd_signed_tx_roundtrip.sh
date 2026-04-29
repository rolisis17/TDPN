#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE="$(mktemp -t tdpnd-adapter-signed-tx-roundtrip.XXXXXX.log)"
GO_PROG_FILE="$(mktemp -t tdpnd-adapter-signed-tx-roundtrip.XXXXXX.go)"
TDPND_PID=""
STARTUP_MAX_ATTEMPTS="${COSMOS_ADAPTER_TDPND_SIGNED_TX_STARTUP_MAX_ATTEMPTS:-5}"

if ! [[ "${STARTUP_MAX_ATTEMPTS}" =~ ^[0-9]+$ ]] || [[ "${STARTUP_MAX_ATTEMPTS}" -lt 1 ]]; then
  echo "COSMOS_ADAPTER_TDPND_SIGNED_TX_STARTUP_MAX_ATTEMPTS must be an integer >= 1"
  exit 2
fi

signal_runtime() {
  local sig="$1"
  if [[ -n "${TDPND_PID}" ]]; then
    kill "-${sig}" "${TDPND_PID}" 2>/dev/null || true
    if command -v pkill >/dev/null 2>&1; then
      pkill "-${sig}" -P "${TDPND_PID}" 2>/dev/null || true
    fi
  fi
}

wait_for_runtime_exit() {
  local attempts="$1"
  for _ in $(seq 1 "${attempts}"); do
    if ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

cleanup() {
  set +e
  if [[ -n "${TDPND_PID}" ]] && kill -0 "${TDPND_PID}" 2>/dev/null; then
    signal_runtime INT
    wait_for_runtime_exit 20 || true
    if kill -0 "${TDPND_PID}" 2>/dev/null; then
      signal_runtime TERM
      wait_for_runtime_exit 20 || true
    fi
    if kill -0 "${TDPND_PID}" 2>/dev/null; then
      signal_runtime KILL
    fi
    wait "${TDPND_PID}" 2>/dev/null || true
  fi
  rm -f "${LOG_FILE}" "${GO_PROG_FILE}"
  set -e
}
trap cleanup EXIT

pick_port() {
  for _ in $(seq 1 40); do
    local port
    port=$((36000 + RANDOM % 10000))
    if ! (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1; then
      echo "${port}"
      return 0
    fi
  done
  return 1
}

wait_for_health_ready() {
  local url="$1"
  for _ in $(seq 1 60); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before health became ready"
      cat "${LOG_FILE}"
      return 1
    fi
    local code
    code="$(curl -s -m 2 -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for settlement bridge health at ${url}"
  cat "${LOG_FILE}"
  return 1
}

TOKEN="adapter-signed-tx-roundtrip-token"
REWARD_PROOF_TOKEN="adapter-signed-tx-proof-token"
FINALITY_TOKEN="adapter-signed-tx-finality-token"
ENDPOINT=""
bind_retry_log_match() {
  grep -Eqi 'address already in use|bind: address already in use|failed to listen on .*address already in use' "${LOG_FILE}" 2>/dev/null
}

launch_runtime() {
  local port="$1"
  (
    cd blockchain/tdpn-chain
    go run ./cmd/tdpnd --settlement-http-listen "127.0.0.1:${port}" --settlement-http-auth-token "${TOKEN}" --settlement-http-reward-proof-auth-token "${REWARD_PROOF_TOKEN}" --settlement-http-finality-auth-token "${FINALITY_TOKEN}" --settlement-http-reward-proof-verifier-id "adapter-signed-tx-verifier"
  ) >"${LOG_FILE}" 2>&1 &
  TDPND_PID=$!
  ENDPOINT="http://127.0.0.1:${port}"
}

runtime_started="0"
for attempt in $(seq 1 "${STARTUP_MAX_ATTEMPTS}"); do
  PORT="$(pick_port)"
  if [[ -z "${PORT}" ]]; then
    echo "failed to allocate signed-tx roundtrip port"
    exit 1
  fi
  : >"${LOG_FILE}"
  launch_runtime "${PORT}"
  if wait_for_health_ready "${ENDPOINT}/health"; then
    runtime_started="1"
    break
  fi
  if [[ "${attempt}" -lt "${STARTUP_MAX_ATTEMPTS}" ]] && bind_retry_log_match; then
    if kill -0 "${TDPND_PID}" 2>/dev/null; then
      signal_runtime INT
      wait_for_runtime_exit 20 || true
      if kill -0 "${TDPND_PID}" 2>/dev/null; then
        signal_runtime TERM
        wait_for_runtime_exit 20 || true
      fi
      if kill -0 "${TDPND_PID}" 2>/dev/null; then
        signal_runtime KILL
        wait_for_runtime_exit 20 || true
      fi
      wait "${TDPND_PID}" 2>/dev/null || true
    fi
    TDPND_PID=""
    continue
  fi
  break
done

if [[ "${runtime_started}" != "1" ]]; then
  echo "failed to start signed-tx roundtrip runtime after ${STARTUP_MAX_ATTEMPTS} attempts"
  cat "${LOG_FILE}"
  exit 1
fi

cat >"${GO_PROG_FILE}" <<'GO'
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"privacynode/pkg/settlement"
)

type signedTxBroadcast struct {
	Mode string `json:"mode"`
	Tx   struct {
		MessageType    string          `json:"message_type"`
		Message        json.RawMessage `json:"message"`
		IdempotencyKey string          `json:"idempotency_key"`
	} `json:"tx"`
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func assert(cond bool, msg string) {
	if !cond {
		panic(msg)
	}
}

func waitForFundReservationStatus(ctx context.Context, adapter *settlement.CosmosAdapter, reservationID string, want settlement.OperationStatus) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, found, err := adapter.FundReservationStatus(ctx, reservationID)
		must(err)
		if found && status == want {
			return
		}
		if time.Now().After(deadline) {
			panic(fmt.Sprintf("reservation %s did not reach %s (found=%t status=%s)", reservationID, want, found, status))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func waitForSessionSettlementVisible(ctx context.Context, adapter *settlement.CosmosAdapter, settlementID string) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		found, err := adapter.HasSessionSettlement(ctx, settlementID)
		must(err)
		if found {
			return
		}
		if time.Now().After(deadline) {
			panic(fmt.Sprintf("settlement %s did not become bridge-visible", settlementID))
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func startSignedTxRelay(targetBaseURL, bearerToken string, rewardProofToken string, finalityToken string) (string, func()) {
	client := &http.Client{Timeout: 2 * time.Second}
	mux := http.NewServeMux()

	copyHeaders := func(src *http.Request, dst *http.Request) {
		for key, values := range src.Header {
			for _, value := range values {
				dst.Header.Add(key, value)
			}
		}
	}

	proxyRequest := func(method, path string, body io.Reader, src *http.Request, forceIdempotency string) (*http.Response, error) {
		req, err := http.NewRequest(method, targetBaseURL+path, body)
		if err != nil {
			return nil, err
		}
		if src != nil {
			copyHeaders(src, req)
		}
		if bearerToken != "" && strings.TrimSpace(req.Header.Get("Authorization")) == "" {
			req.Header.Set("Authorization", "Bearer "+bearerToken)
		}
		if path == "/x/vpnrewards/proofs" && rewardProofToken != "" && strings.TrimSpace(req.Header.Get("X-GPM-Reward-Proof-Authorization")) == "" {
			req.Header.Set("X-GPM-Reward-Proof-Authorization", "Bearer "+rewardProofToken)
		}
		if finalityToken != "" && strings.TrimSpace(req.Header.Get("X-GPM-Finality-Authorization")) == "" {
			req.Header.Set("X-GPM-Finality-Authorization", "Bearer "+finalityToken)
		}
		if forceIdempotency != "" {
			req.Header.Set("Idempotency-Key", forceIdempotency)
		}
		return client.Do(req)
	}

	allowedWritePaths := map[string]struct{}{
		"/x/vpnbilling/reservations": {},
		"/x/vpnbilling/settlements":  {},
		"/x/vpnrewards/proofs":       {},
		"/x/vpnrewards/issues":       {},
		"/x/vpnsponsor/reservations": {},
		"/x/vpnslashing/evidence":    {},
	}

	mux.HandleFunc("/cosmos/tx/v1beta1/txs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()

		var envelope signedTxBroadcast
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			http.Error(w, "invalid broadcast payload", http.StatusBadRequest)
			return
		}
		path := strings.TrimSpace(envelope.Tx.MessageType)
		if _, ok := allowedWritePaths[path]; !ok {
			http.Error(w, "unsupported message_type", http.StatusBadRequest)
			return
		}
		bodyReader := bytes.NewReader(envelope.Tx.Message)
		resp, err := proxyRequest(http.MethodPost, path, bodyReader, r, envelope.Tx.IdempotencyKey)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for key, values := range resp.Header {
			for _, value := range values {
				w.Header().Add(key, value)
			}
		}
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			w.Header().Del("Content-Length")
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"tx_response":{"code":0}}`))
			return
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	for _, passthroughPrefix := range []string{"/health", "/x/"} {
		prefix := passthroughPrefix
		mux.HandleFunc(prefix, func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			resp, err := proxyRequest(http.MethodGet, r.URL.Path, nil, r, "")
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			defer resp.Body.Close()
			for key, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
		})
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	server := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  30 * time.Second,
	}
	go func() {
		_ = server.Serve(ln)
	}()

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}
	return "http://" + ln.Addr().String(), stop
}

func main() {
	tdpndEndpoint := strings.TrimSpace(os.Getenv("TDPND_ENDPOINT"))
	token := strings.TrimSpace(os.Getenv("TDPND_TOKEN"))
	rewardProofToken := strings.TrimSpace(os.Getenv("TDPND_REWARD_PROOF_TOKEN"))
	finalityToken := strings.TrimSpace(os.Getenv("TDPND_FINALITY_TOKEN"))
	if tdpndEndpoint == "" || token == "" {
		panic("missing TDPND_ENDPOINT or TDPND_TOKEN")
	}

	relayEndpoint, stopRelay := startSignedTxRelay(tdpndEndpoint, token, rewardProofToken, finalityToken)
	defer stopRelay()

	adapter, err := settlement.NewCosmosAdapter(settlement.CosmosAdapterConfig{
		Endpoint:              relayEndpoint,
		APIKey:                token,
		RewardProofAuthToken:  rewardProofToken,
		FinalityAuthToken:     finalityToken,
		QueueSize:             32,
		MaxRetries:            1,
		BaseBackoff:           10 * time.Millisecond,
		HTTPTimeout:           2 * time.Second,
		SubmitMode:            settlement.CosmosSubmitModeSignedTx,
		SignedTxBroadcastPath: "/cosmos/tx/v1beta1/txs",
		SignedTxChainID:       "tdpn-local-1",
		SignedTxSigner:        "relay-signer-1",
		SignedTxSecret:        "relay-secret-1",
		SignedTxKeyID:         "relay-key-1",
	})
	must(err)
	defer adapter.Close()

	svc := settlement.NewMemoryService(
		settlement.WithChainAdapter(adapter),
		settlement.WithCurrency("TDPNC"),
		settlement.WithPricePerMiBMicros(1000),
	)

	ctx := context.Background()
	sessionID := "sess-adapter-signed-tx-1"
	reservationID := "res-" + sessionID

	reservation := settlement.FundReservation{
		ReservationID: reservationID,
		SessionID:     sessionID,
		SubjectID:     "client-signed-tx-1",
		AmountMicros:  20000,
		Currency:      "TDPNC",
		CreatedAt:     time.Now().UTC(),
		Status:        settlement.OperationStatusPending,
	}
	_, err = adapter.SubmitFundReservation(ctx, reservation)
	must(err)
	waitForFundReservationStatus(ctx, adapter, reservation.ReservationID, settlement.OperationStatusPending)

	reservation.Status = settlement.OperationStatusConfirmed
	_, err = adapter.SubmitFundReservation(ctx, reservation)
	must(err)
	waitForFundReservationStatus(ctx, adapter, reservation.ReservationID, settlement.OperationStatusConfirmed)

	settlementRecord := settlement.SessionSettlement{
		SettlementID:  "set-" + sessionID,
		ReservationID: reservation.ReservationID,
		SessionID:     sessionID,
		SubjectID:     reservation.SubjectID,
		ChargedMicros: 4000,
		Currency:      reservation.Currency,
		SettledAt:     time.Now().UTC(),
		Status:        settlement.OperationStatusConfirmed,
	}
	_, err = adapter.SubmitSessionSettlement(ctx, settlementRecord)
	must(err)
	waitForSessionSettlementVisible(ctx, adapter, settlementRecord.SettlementID)

	periodStart := time.Date(2025, 12, 29, 0, 0, 0, 0, time.UTC)
	periodEnd := periodStart.AddDate(0, 0, 7)
	issuedAt := periodEnd.Add(time.Second)
	rewardRequest := settlement.RewardIssue{
		RewardID:          "reward-signed-tx-1",
		ProviderSubjectID: "provider-signed-tx-1",
		SessionID:         sessionID,
		TrafficProofRef:   "obj://traffic-proof/reward-signed-tx-1",
		PayoutPeriodStart: periodStart,
		PayoutPeriodEnd:   periodEnd,
		RewardMicros:      500,
		Currency:          "TDPNC",
		IssuedAt:          issuedAt,
	}
	_, err = adapter.SubmitRewardProof(ctx, settlement.RewardProofRecord{
		ProofPath:         "traffic-proof/reward-signed-tx-1",
		TrafficProofRef:   rewardRequest.TrafficProofRef,
		TrustContract:     settlement.RewardProofTrustContractObjectiveTrafficV1,
		RewardID:          rewardRequest.RewardID,
		ProviderSubjectID: rewardRequest.ProviderSubjectID,
		SessionID:         rewardRequest.SessionID,
		PayoutPeriodStart: periodStart,
		PayoutPeriodEnd:   periodEnd,
		RewardMicros:      rewardRequest.RewardMicros,
		Currency:          rewardRequest.Currency,
		IssuedAt:          rewardRequest.IssuedAt,
		Verified:          true,
		VerifierID:        "adapter-signed-tx-verifier",
		VerifiedAt:        issuedAt.Add(time.Second),
	})
	must(err)
	reward, err := svc.IssueReward(ctx, rewardRequest)
	must(err)
	assert(reward.AdapterSubmitted, "expected reward adapter submission")
	assert(!reward.AdapterDeferred, "expected reward not deferred")

	sponsorReservation, err := svc.ReserveSponsorCredits(ctx, settlement.SponsorCreditReservation{
		ReservationID: "sres-signed-tx-1",
		SponsorID:     "sponsor-signed-tx-1",
		SubjectID:     "app-signed-tx-1",
		SessionID:     "sess-sponsor-signed-tx-1",
		AmountMicros:  1000,
		Currency:      "TDPNC",
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(2 * time.Minute),
	})
	must(err)
	assert(sponsorReservation.AdapterSubmitted, "expected sponsor reservation adapter submission")
	assert(!sponsorReservation.AdapterDeferred, "expected sponsor reservation not deferred")

	slashEvidence, err := svc.SubmitSlashEvidence(ctx, settlement.SlashEvidence{
		EvidenceID:    "evidence-signed-tx-1",
		SubjectID:     "provider-signed-tx-1",
		SessionID:     sessionID,
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:445c7d70c1d8751f5afd8ae43c764b3fc401dbd4274b1c680be7c00206b612ce",
		SlashMicros:   2500,
		Currency:      "TDPNC",
		ObservedAt:    time.Now().UTC(),
	})
	must(err)
	assert(slashEvidence.AdapterSubmitted, "expected slash evidence adapter submission")
	assert(!slashEvidence.AdapterDeferred, "expected slash evidence not deferred")

	checkVisible := func() (bool, string) {
		settlementVisible, err := adapter.HasSessionSettlement(ctx, settlementRecord.SettlementID)
		must(err)
		rewardVisible, err := adapter.HasRewardIssue(ctx, reward.RewardID)
		must(err)
		sponsorVisible, err := adapter.HasSponsorReservation(ctx, sponsorReservation.ReservationID)
		must(err)
		slashVisible, err := adapter.HasSlashEvidence(ctx, slashEvidence.EvidenceID)
		must(err)
		visible := settlementVisible && rewardVisible && sponsorVisible && slashVisible
		return visible, fmt.Sprintf("settlement=%t reward=%t sponsor=%t slash=%t", settlementVisible, rewardVisible, sponsorVisible, slashVisible)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		report, err := svc.Reconcile(ctx)
		must(err)
		visible, visibility := checkVisible()
		if report.PendingAdapterOperations == 0 && visible {
			break
		}
		if time.Now().After(deadline) {
			panic(fmt.Sprintf("signed-tx roundtrip did not reach bridge visibility (pending=%d submitted=%d confirmed=%d failed=%d %s)", report.PendingAdapterOperations, report.SubmittedOperations, report.ConfirmedOperations, report.FailedOperations, visibility))
		}
		time.Sleep(25 * time.Millisecond)
	}
}
GO

TDPND_ENDPOINT="${ENDPOINT}" TDPND_TOKEN="${TOKEN}" TDPND_REWARD_PROOF_TOKEN="${REWARD_PROOF_TOKEN}" TDPND_FINALITY_TOKEN="${FINALITY_TOKEN}" go run "${GO_PROG_FILE}"

signal_runtime INT
if ! wait_for_runtime_exit 30; then
  signal_runtime TERM
fi
if ! wait_for_runtime_exit 20; then
  signal_runtime KILL
  wait_for_runtime_exit 20 || true
fi
if kill -0 "${TDPND_PID}" 2>/dev/null; then
  echo "tdpnd did not exit after INT/TERM/KILL sequence"
  cat "${LOG_FILE}"
  exit 1
fi
wait "${TDPND_PID}" 2>/dev/null || true
TDPND_PID=""

echo "cosmos adapter signed-tx to tdpnd bridge roundtrip integration check ok"
