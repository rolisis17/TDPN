#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE="$(mktemp -t tdpnd-adapter-roundtrip.XXXXXX.log)"
GO_PROG_FILE="$(mktemp -t tdpnd-adapter-roundtrip.XXXXXX.go)"
TDPND_PID=""

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
    port=$((32000 + RANDOM % 10000))
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

PORT="$(pick_port)"
if [[ -z "${PORT}" ]]; then
  echo "failed to allocate adapter roundtrip port"
  exit 1
fi
TOKEN="adapter-roundtrip-token"
ENDPOINT="http://127.0.0.1:${PORT}"

(
  cd blockchain/tdpn-chain
  go run ./cmd/tdpnd --settlement-http-listen "127.0.0.1:${PORT}" --settlement-http-auth-token "${TOKEN}"
) >"${LOG_FILE}" 2>&1 &
TDPND_PID=$!

wait_for_health_ready "${ENDPOINT}/health"

cat >"${GO_PROG_FILE}" <<'GO'
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"privacynode/pkg/settlement"
)

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

func main() {
	endpoint := os.Getenv("COSMOS_BRIDGE_URL")
	token := os.Getenv("COSMOS_BRIDGE_TOKEN")
	if endpoint == "" || token == "" {
		panic("missing COSMOS_BRIDGE_URL or COSMOS_BRIDGE_TOKEN")
	}

	adapter, err := settlement.NewCosmosAdapter(settlement.CosmosAdapterConfig{
		Endpoint:    endpoint,
		APIKey:      token,
		QueueSize:   32,
		MaxRetries:  1,
		BaseBackoff: 10 * time.Millisecond,
		HTTPTimeout: 2 * time.Second,
	})
	must(err)
	defer adapter.Close()

	svc := settlement.NewMemoryService(
		settlement.WithChainAdapter(adapter),
		settlement.WithCurrency("TDPNC"),
		settlement.WithPricePerMiBMicros(1000),
	)

	ctx := context.Background()
	sessionID := "sess-adapter-bridge-1"

	_, err = svc.ReserveFunds(ctx, settlement.FundReservation{
		ReservationID: "res-" + sessionID,
		SessionID:     sessionID,
		SubjectID:     "client-adapter-1",
		AmountMicros:  20000,
		Currency:      "TDPNC",
	})
	must(err)

	must(svc.RecordUsage(ctx, settlement.UsageRecord{
		SessionID:    sessionID,
		SubjectID:    "client-adapter-1",
		EntryRelayID: "entry-adapter-1",
		ExitRelayID:  "exit-adapter-1",
		BytesIngress: 2 * 1024 * 1024,
		BytesEgress:  2 * 1024 * 1024,
		RecordedAt:   time.Now().UTC(),
	}))

	settlementRecord, err := svc.SettleSession(ctx, sessionID)
	must(err)
	assert(settlementRecord.AdapterSubmitted, "expected settlement adapter submission")
	assert(!settlementRecord.AdapterDeferred, "expected settlement not deferred")

	reward, err := svc.IssueReward(ctx, settlement.RewardIssue{
		RewardID:          "reward-adapter-1",
		ProviderSubjectID: "provider-adapter-1",
		SessionID:         sessionID,
		RewardMicros:      500,
		Currency:          "TDPNC",
		IssuedAt:          time.Now().UTC(),
	})
	must(err)
	assert(reward.AdapterSubmitted, "expected reward adapter submission")
	assert(!reward.AdapterDeferred, "expected reward not deferred")

	sponsorReservation, err := svc.ReserveSponsorCredits(ctx, settlement.SponsorCreditReservation{
		ReservationID: "sres-adapter-1",
		SponsorID:     "sponsor-adapter-1",
		SubjectID:     "app-adapter-1",
		SessionID:     "sess-sponsor-adapter-1",
		AmountMicros:  1000,
		Currency:      "TDPNC",
		CreatedAt:     time.Now().UTC(),
		ExpiresAt:     time.Now().UTC().Add(2 * time.Minute),
	})
	must(err)
	assert(sponsorReservation.AdapterSubmitted, "expected sponsor reservation adapter submission")
	assert(!sponsorReservation.AdapterDeferred, "expected sponsor reservation not deferred")

	slashEvidence, err := svc.SubmitSlashEvidence(ctx, settlement.SlashEvidence{
		EvidenceID:    "evidence-adapter-1",
		SubjectID:     "provider-adapter-1",
		SessionID:     sessionID,
		ViolationType: "double-sign",
		EvidenceRef:   "sha256:adapterevidence",
		SlashMicros:   0,
		Currency:      "TDPNC",
		ObservedAt:    time.Now().UTC(),
	})
	must(err)
	assert(slashEvidence.AdapterSubmitted, "expected slash evidence adapter submission")
	assert(!slashEvidence.AdapterDeferred, "expected slash evidence not deferred")

	checkVisible := func() bool {
		settlementVisible, err := adapter.HasSessionSettlement(ctx, settlementRecord.SettlementID)
		must(err)
		rewardVisible, err := adapter.HasRewardIssue(ctx, reward.RewardID)
		must(err)
		sponsorVisible, err := adapter.HasSponsorReservation(ctx, sponsorReservation.ReservationID)
		must(err)
		slashVisible, err := adapter.HasSlashEvidence(ctx, slashEvidence.EvidenceID)
		must(err)
		return settlementVisible && rewardVisible && sponsorVisible && slashVisible
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		report, err := svc.Reconcile(ctx)
		must(err)
		if report.PendingAdapterOperations == 0 && report.ConfirmedOperations >= 4 && checkVisible() {
			break
		}
		if time.Now().After(deadline) {
			panic(fmt.Sprintf("roundtrip did not reach confirmed visibility (pending=%d confirmed=%d)", report.PendingAdapterOperations, report.ConfirmedOperations))
		}
		time.Sleep(25 * time.Millisecond)
	}
}
GO

COSMOS_BRIDGE_URL="${ENDPOINT}" COSMOS_BRIDGE_TOKEN="${TOKEN}" go run "${GO_PROG_FILE}"

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

echo "cosmos adapter to tdpnd bridge roundtrip integration check ok"
