#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE="$(mktemp -t tdpnd-settlement-bridge-live.XXXXXX.log)"
RESP_FILE="$(mktemp -t tdpnd-settlement-bridge-resp.XXXXXX.json)"
GRPC_HELPER_FILE=""
GRPC_PREVIEW_HELPER_FILE=""
CHAIN_TMP_DIR=""
TDPND_PID=""

write_bearer_curl_config() {
  local token="$1"
  local old_umask
  local cfg_file
  if [[ -z "$token" ]]; then
    echo "refusing empty bearer token for curl auth config" >&2
    return 1
  fi
  if ((${#token} > 4096)); then
    echo "refusing oversized bearer token for curl auth config" >&2
    return 1
  fi
  if printf '%s' "$token" | LC_ALL=C grep -q '[[:cntrl:][:space:]]'; then
    echo "refusing bearer token with whitespace/control characters for curl auth config" >&2
    return 1
  fi
  if [[ "$token" == *\"* || "$token" == *\\* ]]; then
    echo "refusing bearer token with unsafe quote/backslash characters for curl auth config" >&2
    return 1
  fi
  old_umask="$(umask)"
  umask 077
  cfg_file="$(mktemp -t tdpnd-settlement-bridge-auth.XXXXXX.cfg)"
  umask "$old_umask"
  printf 'header = "Authorization: Bearer %s"\n' "$token" >"${cfg_file}"
  printf '%s\n' "${cfg_file}"
}

curl_with_bearer_config() {
  local token="$1"
  shift
  local cfg_file
  local rc
  cfg_file="$(write_bearer_curl_config "$token")"
  if curl --config "${cfg_file}" "$@"; then
    rc=0
  else
    rc=$?
  fi
  rm -f "${cfg_file}"
  return "${rc}"
}

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
  rm -f "${LOG_FILE}" "${RESP_FILE}"
  if [[ -n "${GRPC_HELPER_FILE}" ]]; then
    rm -f "${GRPC_HELPER_FILE}"
  fi
  if [[ -n "${GRPC_PREVIEW_HELPER_FILE}" ]]; then
    rm -f "${GRPC_PREVIEW_HELPER_FILE}"
  fi
  if [[ -n "${CHAIN_TMP_DIR}" ]]; then
    rm -rf "${CHAIN_TMP_DIR}"
  fi
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
      return 2
    fi
    local code
    code="$(curl -s -m 2 -o "${RESP_FILE}" -w "%{http_code}" "${url}" 2>/dev/null || true)"
    if [[ "${code}" == "200" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 3
}

startup_bind_conflict_in_log() {
  grep -Eiq 'address already in use|EADDRINUSE|bind: Only one usage of each socket address' "${LOG_FILE}"
}

start_runtime_with_retry() {
  local max_attempts="$1"
  local attempt
  for attempt in $(seq 1 "${max_attempts}"); do
    PORT="$(pick_port)"
    if [[ -z "${PORT}" ]]; then
      echo "failed to allocate settlement bridge smoke-test port"
      return 1
    fi

    GRPC_PORT="$(pick_port)"
    if [[ -z "${GRPC_PORT}" ]]; then
      echo "failed to allocate grpc smoke-test port"
      return 1
    fi

    : > "${LOG_FILE}"
    (
      cd blockchain/tdpn-chain
      go run ./cmd/tdpnd --grpc-listen "127.0.0.1:${GRPC_PORT}" --grpc-auth-token "${TOKEN}" --settlement-http-listen "127.0.0.1:${PORT}" --settlement-http-auth-token "${TOKEN}"
    ) >"${LOG_FILE}" 2>&1 &
    TDPND_PID=$!
    BASE_URL="http://127.0.0.1:${PORT}"

    local ready_rc=0
    if wait_for_health_ready "${BASE_URL}/health"; then
      return 0
    else
      ready_rc=$?
    fi

    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      wait "${TDPND_PID}" 2>/dev/null || true
      TDPND_PID=""
    fi

    if [[ "${ready_rc}" == "2" ]] && startup_bind_conflict_in_log; then
      if (( attempt < max_attempts )); then
        echo "tdpnd startup bind conflict on attempt ${attempt}/${max_attempts}; retrying with new ports"
        continue
      fi
      echo "tdpnd startup bind conflict after ${max_attempts} attempt(s)"
      cat "${LOG_FILE}"
      return 1
    fi

    if [[ "${ready_rc}" == "2" ]]; then
      echo "tdpnd exited before settlement bridge health became ready"
      cat "${LOG_FILE}"
      return 1
    fi

    echo "timed out waiting for settlement bridge health at ${BASE_URL}/health"
    cat "${LOG_FILE}"
    return 1
  done
  return 1
}

post_expect_status() {
  local url="$1"
  local payload="$2"
  local expected="$3"
  local token="${4:-}"
  local code
  if [[ -n "${token}" ]]; then
    code="$(curl_with_bearer_config "${token}" -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "Content-Type: application/json" -d "${payload}" "${url}" || true)"
  else
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" -H "Content-Type: application/json" -d "${payload}" "${url}" || true)"
  fi
  if [[ "${code}" != "${expected}" ]]; then
    echo "unexpected status for ${url}: expected ${expected}, got ${code}"
    echo "response:"
    cat "${RESP_FILE}"
    echo
    echo "tdpnd log:"
    cat "${LOG_FILE}"
    return 1
  fi
}

get_expect_status() {
  local url="$1"
  local expected="$2"
  local token="${3:-}"
  local code
  if [[ -n "${token}" ]]; then
    code="$(curl_with_bearer_config "${token}" -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" "${url}" || true)"
  else
    code="$(curl -sS -m 4 -o "${RESP_FILE}" -w "%{http_code}" "${url}" || true)"
  fi
  if [[ "${code}" != "${expected}" ]]; then
    echo "unexpected status for ${url}: expected ${expected}, got ${code}"
    echo "response:"
    cat "${RESP_FILE}"
    echo
    echo "tdpnd log:"
    cat "${LOG_FILE}"
    return 1
  fi
}

TOKEN="bridge-smoke-token"
STARTUP_MAX_ATTEMPTS="${TDPND_SETTLEMENT_BRIDGE_LIVE_SMOKE_STARTUP_MAX_ATTEMPTS:-3}"
if ! [[ "${STARTUP_MAX_ATTEMPTS}" =~ ^[0-9]+$ ]] || (( STARTUP_MAX_ATTEMPTS < 1 )); then
  echo "TDPND_SETTLEMENT_BRIDGE_LIVE_SMOKE_STARTUP_MAX_ATTEMPTS must be an integer >= 1"
  exit 1
fi
PORT=""
GRPC_PORT=""
BASE_URL=""

mkdir -p "${ROOT_DIR}/blockchain/tdpn-chain/.tmp"
CHAIN_TMP_DIR="$(mktemp -d "${ROOT_DIR}/blockchain/tdpn-chain/.tmp/tdpnd-live-smoke-XXXXXX")"

GRPC_HELPER_FILE="$(mktemp "${CHAIN_TMP_DIR}/tdpnd-slashing-penalty-seed-XXXXXX.go")"
cat >"${GRPC_HELPER_FILE}" <<'EOF'
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	vpnslashingpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnslashing/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintf(os.Stderr, "usage: %s <grpc-port> <token> <evidence-id> <penalty-id>\n", os.Args[0])
		os.Exit(2)
	}

	grpcPort, err := strconv.Atoi(os.Args[1])
	if err != nil || grpcPort <= 0 {
		fmt.Fprintf(os.Stderr, "invalid grpc port %q: %v\n", os.Args[1], err)
		os.Exit(2)
	}

	target := fmt.Sprintf("127.0.0.1:%d", grpcPort)
	var conn *grpc.ClientConn
	for attempt := 0; attempt < 50; attempt++ {
		dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err = grpc.DialContext(dialCtx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		cancel()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial grpc %s: %v\n", target, err)
		os.Exit(1)
	}
	defer conn.Close()

	client := vpnslashingpb.NewMsgClient(conn)
	callCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+os.Args[2])
	resp, err := client.RecordPenalty(callCtx, &vpnslashingpb.MsgRecordPenaltyRequest{
		Penalty: &vpnslashingpb.PenaltyDecision{
			PenaltyId:       os.Args[4],
			EvidenceId:      os.Args[3],
			SlashBasisPoint: 25,
			Jailed:          false,
			AppliedAtUnix:   1735689604,
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "record penalty: %v\n", err)
		os.Exit(1)
	}
	if resp.GetPenalty().GetPenaltyId() != os.Args[4] {
		fmt.Fprintf(os.Stderr, "unexpected penalty id %q\n", resp.GetPenalty().GetPenaltyId())
		os.Exit(1)
	}
}
EOF

GRPC_PREVIEW_HELPER_FILE="$(mktemp "${CHAIN_TMP_DIR}/tdpnd-validator-preview-seed-XXXXXX.go")"
cat >"${GRPC_PREVIEW_HELPER_FILE}" <<'EOF'
package main

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	vpnvalidatorpb "github.com/tdpn/tdpn-chain/proto/gen/go/tdpn/vpnvalidator/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func main() {
	if len(os.Args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: %s <grpc-port> <token> <validator-id>\n", os.Args[0])
		os.Exit(2)
	}

	grpcPort, err := strconv.Atoi(os.Args[1])
	if err != nil || grpcPort <= 0 {
		fmt.Fprintf(os.Stderr, "invalid grpc port %q: %v\n", os.Args[1], err)
		os.Exit(2)
	}

	target := fmt.Sprintf("127.0.0.1:%d", grpcPort)
	var conn *grpc.ClientConn
	for attempt := 0; attempt < 50; attempt++ {
		dialCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		conn, err = grpc.DialContext(dialCtx, target, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
		cancel()
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial grpc %s: %v\n", target, err)
		os.Exit(1)
	}
	defer conn.Close()

	client := vpnvalidatorpb.NewQueryClient(conn)
	previewReq := &vpnvalidatorpb.QueryPreviewEpochSelectionRequest{
		Policy: &vpnvalidatorpb.EpochSelectionPolicy{
			Epoch:               29,
			StableSeatCount:     1,
			RotatingSeatCount:   0,
			MinStake:            1,
			MinStakeAgeEpochs:   1,
			MinHealthScore:      1,
			MinResourceHeadroom: 1,
		},
		Candidates: []*vpnvalidatorpb.EpochValidatorCandidate{
			{
				ValidatorId:         os.Args[3],
				OperatorId:          "operator-preview-1",
				Asn:                 "64514",
				Region:              "au-east",
				Stake:               100,
				StakeAgeEpochs:      9,
				HealthScore:         100,
				ResourceHeadroom:    100,
				Score:               100,
				StableSeatPreferred: true,
			},
		},
	}

	if _, err := client.PreviewEpochSelection(context.Background(), previewReq); status.Code(err) != codes.Unauthenticated {
		fmt.Fprintf(os.Stderr, "expected unauthenticated preview call to fail with codes.Unauthenticated, got %v\n", err)
		os.Exit(1)
	}

	callCtx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+os.Args[2])
	resp, err := client.PreviewEpochSelection(callCtx, previewReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "preview epoch selection: %v\n", err)
		os.Exit(1)
	}
	if resp.GetResult() == nil {
		fmt.Fprintln(os.Stderr, "expected non-nil preview epoch selection result")
		os.Exit(1)
	}
	if len(resp.GetResult().GetStableSeats())+len(resp.GetResult().GetRotatingSeats()) == 0 {
		fmt.Fprintf(os.Stderr, "expected preview epoch selection to choose validator %q, got %+v\n", os.Args[3], resp.GetResult())
		os.Exit(1)
	}
}
EOF

start_runtime_with_retry "${STARTUP_MAX_ATTEMPTS}"

post_expect_status "${BASE_URL}/x/vpnbilling/settlements" '{"SettlementID":"set-unauth-1","ReservationID":"bill-res-unauth-1","SessionID":"sess-unauth-1","SubjectID":"subject-unauth-1","ChargedMicros":250,"Currency":"TDPNC","SettledAt":"2026-01-01T00:00:00Z"}' "401"
post_expect_status "${BASE_URL}/x/vpnrewards/issues" '{"RewardID":"reward-unauth-1","ProviderSubjectID":"provider-unauth-1","SessionID":"sess-unauth-1","RewardMicros":100,"Currency":"TDPNC","IssuedAt":"2026-01-01T00:00:00Z"}' "401"
post_expect_status "${BASE_URL}/x/vpnsponsor/reservations" '{"ReservationID":"res-unauth-1","SponsorID":"sponsor-unauth-1","SubjectID":"app-unauth-1","SessionID":"sess-unauth-1","AmountMicros":500,"Currency":"TDPNC","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}' "401"
post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-unauth-1","SubjectID":"provider-1","SessionID":"sess-1","ViolationType":"double-sign","EvidenceRef":"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","ObservedAt":"2026-01-01T00:00:00Z"}' "401"
post_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities" '{"ValidatorID":"val-unauth-1","OperatorAddress":"op-unauth-1","Eligible":true,"PolicyReason":"auth smoke","UpdatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "401"
post_expect_status "${BASE_URL}/x/vpnvalidator/status-records" '{"StatusID":"status-unauth-1","ValidatorID":"val-unauth-1","ConsensusAddress":"cons-unauth-1","LifecycleStatus":"active","EvidenceHeight":5,"EvidenceRef":"sha256:ea30d9de50b2769225f23768fa2b7f58d3fd014d31b95fa87fbef67c3fa1da59","RecordedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "401"
post_expect_status "${BASE_URL}/x/vpngovernance/policies" '{"PolicyID":"policy-unauth-1","Title":"unauth-policy","Description":"auth smoke policy","Version":1,"ActivatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "401"
post_expect_status "${BASE_URL}/x/vpngovernance/decisions" '{"DecisionID":"decision-unauth-1","PolicyID":"policy-unauth-1","ProposalID":"proposal-unauth-1","Outcome":"approve","Decider":"bootstrap-multisig","Reason":"auth smoke decision","DecidedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "401"
post_expect_status "${BASE_URL}/x/vpngovernance/audit-actions" '{"ActionID":"action-unauth-1","Action":"policy.unauth","Actor":"bootstrap-multisig","Reason":"auth smoke audit","EvidencePointer":"obj://audit/action-unauth-1","Timestamp":"2026-01-01T00:00:00Z"}' "401"

post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-invalid-violation-objective","SubjectID":"provider-1","SessionID":"sess-1","ViolationType":"objective","EvidenceRef":"sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad","ObservedAt":"2026-01-01T00:00:00Z"}' "400" "${TOKEN}"
grep -q 'violation_type must be one of' "${RESP_FILE}"
post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-invalid-violation-manual-review","SubjectID":"provider-1","SessionID":"sess-1","ViolationType":"manual-review-only","EvidenceRef":"sha256:cb8379ac2098aa165029e3938a51da0bcecfc008fd6795f401178647f96c5b34","ObservedAt":"2026-01-01T00:00:00Z"}' "400" "${TOKEN}"
grep -q 'violation_type must be one of' "${RESP_FILE}"
post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-missing-session-1","SubjectID":"provider-1","ViolationType":"double-sign","EvidenceRef":"sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090","ObservedAt":"2026-01-01T00:00:00Z"}' "400" "${TOKEN}"
grep -q 'session_id is required' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-invalid-ref-1","SubjectID":"provider-1","SessionID":"sess-1","ViolationType":"double-sign","EvidenceRef":"proof-invalid-ref-1","ObservedAt":"2026-01-01T00:00:00Z"}' "400" "${TOKEN}"
grep -q 'objective format' "${RESP_FILE}"
post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-invalid-ref-short-sha","SubjectID":"provider-1","SessionID":"sess-1","ViolationType":"double-sign","EvidenceRef":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde","ObservedAt":"2026-01-01T00:00:00Z"}' "400" "${TOKEN}"
grep -q 'objective format' "${RESP_FILE}"
post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-invalid-ref-obj-space","SubjectID":"provider-1","SessionID":"sess-1","ViolationType":"double-sign","EvidenceRef":"obj://bucket/key with-space","ObservedAt":"2026-01-01T00:00:00Z"}' "400" "${TOKEN}"
grep -q 'objective format' "${RESP_FILE}"
post_expect_status "${BASE_URL}/x/vpnvalidator/status-records" '{"StatusID":"status-invalid-ref-short-sha","ValidatorID":"val-unauth-1","ConsensusAddress":"cons-unauth-1","LifecycleStatus":"active","EvidenceHeight":5,"EvidenceRef":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde","RecordedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "400" "${TOKEN}"
grep -q 'objective format' "${RESP_FILE}"
post_expect_status "${BASE_URL}/x/vpnvalidator/status-records" '{"StatusID":"status-invalid-ref-obj-space","ValidatorID":"val-unauth-1","ConsensusAddress":"cons-unauth-1","LifecycleStatus":"active","EvidenceHeight":5,"EvidenceRef":"obj://validator/status with-space","RecordedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "400" "${TOKEN}"
grep -q 'objective format' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnbilling/settlements" '{"SettlementID":"set-live-1","ReservationID":"bill-res-live-1","SessionID":"sess-live-1","SubjectID":"subject-live-1","ChargedMicros":250,"Currency":"TDPNC","SettledAt":"2026-01-01T00:00:00Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnrewards/issues" '{"RewardID":"reward-live-1","ProviderSubjectID":"provider-live-1","SessionID":"sess-live-1","RewardMicros":100,"Currency":"TDPNC","IssuedAt":"2026-01-01T00:00:00Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnsponsor/reservations" '{"ReservationID":"res-live-1","SponsorID":"sponsor-live-1","SubjectID":"app-live-1","SessionID":"sess-live-1","AmountMicros":500,"Currency":"TDPNC","CreatedAt":"2026-01-01T00:00:00Z","ExpiresAt":"2026-12-31T00:00:00Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnslashing/evidence" '{"EvidenceID":"ev-live-1","SubjectID":"provider-live-1","SessionID":"sess-live-1","ViolationType":"double-sign","EvidenceRef":"sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090","ObservedAt":"2026-01-01T00:00:00Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

# Canonicalization path coverage: mixed-case and whitespace IDs should persist in canonical form.
post_expect_status "${BASE_URL}/x/vpnbilling/settlements" '{"SettlementID":"  SET-CANON-LIVE-1  ","ReservationID":"  BILL-RES-CANON-LIVE-1  ","SessionID":"  SESS-CANON-LIVE-1  ","SubjectID":"  SUBJECT-CANON-LIVE-1  ","ChargedMicros":275,"Currency":" TdPnC ","SettledAt":"2026-01-01T00:00:10Z"}' "200" "${TOKEN}"
grep -q '"id"[[:space:]]*:[[:space:]]*"set-canon-live-1"' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnrewards/issues" '{"RewardID":"  REWARD-CANON-LIVE-1  ","ProviderSubjectID":"  PROVIDER-CANON-LIVE-1  ","SessionID":"  SESS-CANON-LIVE-1  ","RewardMicros":125,"Currency":" TdPnC ","IssuedAt":"2026-01-01T00:00:11Z"}' "200" "${TOKEN}"
grep -q '"id"[[:space:]]*:[[:space:]]*"dist:reward-canon-live-1"' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnsponsor/reservations" '{"ReservationID":"  RES-CANON-LIVE-1  ","SponsorID":"  SPONSOR-CANON-LIVE-1  ","SubjectID":"  APP-CANON-LIVE-1  ","SessionID":"  Sess-Canon-Live-1  ","AmountMicros":650,"Currency":" TdPnC ","CreatedAt":"2026-01-01T00:00:12Z","ExpiresAt":"2026-12-31T00:00:00Z"}' "200" "${TOKEN}"
grep -q '"id"[[:space:]]*:[[:space:]]*"res-canon-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnbilling/settlements/set-canon-live-1" "200"
grep -q '"SettlementID"[[:space:]]*:[[:space:]]*"set-canon-live-1"' "${RESP_FILE}"
grep -q '"ReservationID"[[:space:]]*:[[:space:]]*"bill-res-canon-live-1"' "${RESP_FILE}"
grep -q '"SessionID"[[:space:]]*:[[:space:]]*"sess-canon-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnrewards/accruals/reward-canon-live-1" "200"
grep -q '"AccrualID"[[:space:]]*:[[:space:]]*"reward-canon-live-1"' "${RESP_FILE}"
grep -q '"ProviderID"[[:space:]]*:[[:space:]]*"provider-canon-live-1"' "${RESP_FILE}"
grep -q '"SessionID"[[:space:]]*:[[:space:]]*"sess-canon-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnsponsor/delegations/res-canon-live-1" "200"
grep -q '"ReservationID"[[:space:]]*:[[:space:]]*"res-canon-live-1"' "${RESP_FILE}"
grep -q '"SponsorID"[[:space:]]*:[[:space:]]*"sponsor-canon-live-1"' "${RESP_FILE}"
grep -q '"AppID"[[:space:]]*:[[:space:]]*"app-canon-live-1"' "${RESP_FILE}"
grep -q '"SessionID"[[:space:]]*:[[:space:]]*"Sess-Canon-Live-1"' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities" '{"ValidatorID":"  VAL-CANON-LIVE-1  ","OperatorAddress":"  OP-CANON-LIVE-1  ","Eligible":true,"PolicyReason":"  Bootstrap Canon Policy  ","UpdatedAt":"2026-01-01T00:00:20Z","Status":"CONFIRMED"}' "200" "${TOKEN}"
grep -q '"id"[[:space:]]*:[[:space:]]*"val-canon-live-1"' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnvalidator/status-records" '{"StatusID":"  STATUS-CANON-LIVE-1  ","ValidatorID":"  VAL-CANON-LIVE-1  ","ConsensusAddress":"  CONS-CANON-LIVE-1  ","LifecycleStatus":"  ACTIVE  ","EvidenceHeight":9,"EvidenceRef":" SHA256:581690E6640665ABD76F2545C1B8C0A864548CB4074F83BE5DC0C8CE742A2677 ","RecordedAt":"2026-01-01T00:00:21Z","Status":"SUBMITTED"}' "200" "${TOKEN}"
grep -q '"id"[[:space:]]*:[[:space:]]*"status-canon-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities/val-canon-live-1" "200"
grep -q '"ValidatorID"[[:space:]]*:[[:space:]]*"val-canon-live-1"' "${RESP_FILE}"
grep -q '"OperatorAddress"[[:space:]]*:[[:space:]]*"op-canon-live-1"' "${RESP_FILE}"
# Legacy compatibility path: mixed-case lookup should resolve through canonical id helper.
get_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities/VAL-CANON-LIVE-1" "200"
grep -q '"ValidatorID"[[:space:]]*:[[:space:]]*"val-canon-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/status-records/status-canon-live-1" "200"
grep -q '"StatusID"[[:space:]]*:[[:space:]]*"status-canon-live-1"' "${RESP_FILE}"
grep -q '"ValidatorID"[[:space:]]*:[[:space:]]*"val-canon-live-1"' "${RESP_FILE}"
grep -q '"LifecycleStatus"[[:space:]]*:[[:space:]]*"active"' "${RESP_FILE}"
grep -q '"EvidenceRef"[[:space:]]*:[[:space:]]*"sha256:581690e6640665abd76f2545c1b8c0a864548cb4074f83be5dc0c8ce742a2677"' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpngovernance/policies" '{"PolicyID":"  POLICY-CANON-LIVE-1  ","Title":"  Canon Governance Policy  ","Description":"  Canon policy description  ","Version":1,"ActivatedAt":"2026-01-01T00:00:30Z","Status":"SUBMITTED"}' "200" "${TOKEN}"
grep -q '"id"[[:space:]]*:[[:space:]]*"policy-canon-live-1"' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpngovernance/decisions" '{"DecisionID":"  DECISION-CANON-LIVE-1  ","PolicyID":"  POLICY-CANON-LIVE-1  ","ProposalID":"  PROPOSAL-CANON-LIVE-1  ","Outcome":"  APPROVE  ","Decider":"  BOOTSTRAP-MULTISIG-CANON  ","Reason":"  Canon decision reason  ","DecidedAt":"2026-01-01T00:00:31Z","Status":"CONFIRMED"}' "200" "${TOKEN}"
grep -q '"id"[[:space:]]*:[[:space:]]*"decision-canon-live-1"' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpngovernance/audit-actions" '{"ActionID":"  ACTION-CANON-LIVE-1  ","Action":"  POLICY.CANON  ","Actor":"  BOOTSTRAP-MULTISIG-CANON  ","Reason":"  Canon audit reason  ","EvidencePointer":" obj://audit/Action-Canon-Live-1 ","Timestamp":"2026-01-01T00:00:32Z"}' "200" "${TOKEN}"
grep -q '"id"[[:space:]]*:[[:space:]]*"action-canon-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/policies/policy-canon-live-1" "200"
grep -q '"PolicyID"[[:space:]]*:[[:space:]]*"policy-canon-live-1"' "${RESP_FILE}"
grep -q '"Title"[[:space:]]*:[[:space:]]*"  Canon Governance Policy  "' "${RESP_FILE}"
# Legacy compatibility path: mixed-case lookup should resolve through canonical id fallback.
get_expect_status "${BASE_URL}/x/vpngovernance/policies/POLICY-CANON-LIVE-1" "200"
grep -q '"PolicyID"[[:space:]]*:[[:space:]]*"policy-canon-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/decisions/decision-canon-live-1" "200"
grep -q '"DecisionID"[[:space:]]*:[[:space:]]*"decision-canon-live-1"' "${RESP_FILE}"
grep -q '"PolicyID"[[:space:]]*:[[:space:]]*"policy-canon-live-1"' "${RESP_FILE}"
grep -q '"ProposalID"[[:space:]]*:[[:space:]]*"proposal-canon-live-1"' "${RESP_FILE}"
grep -q '"Outcome"[[:space:]]*:[[:space:]]*"approve"' "${RESP_FILE}"
grep -q '"Decider"[[:space:]]*:[[:space:]]*"bootstrap-multisig-canon"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/audit-actions/action-canon-live-1" "200"
grep -q '"ActionID"[[:space:]]*:[[:space:]]*"action-canon-live-1"' "${RESP_FILE}"
grep -q '"Action"[[:space:]]*:[[:space:]]*"policy.canon"' "${RESP_FILE}"
grep -q '"Actor"[[:space:]]*:[[:space:]]*"bootstrap-multisig-canon"' "${RESP_FILE}"
grep -q '"EvidencePointer"[[:space:]]*:[[:space:]]*"obj://audit/Action-Canon-Live-1"' "${RESP_FILE}"

(
  cd blockchain/tdpn-chain
  go run "${GRPC_HELPER_FILE}" "${GRPC_PORT}" "${TOKEN}" "ev-live-1" "pen-live-1"
)
rm -f "${GRPC_HELPER_FILE}"
GRPC_HELPER_FILE=""

(
  cd blockchain/tdpn-chain
  go run "${GRPC_PREVIEW_HELPER_FILE}" "${GRPC_PORT}" "${TOKEN}" "val-live-preview-1"
)
rm -f "${GRPC_PREVIEW_HELPER_FILE}"
GRPC_PREVIEW_HELPER_FILE=""

post_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities" '{"ValidatorID":"val-live-1","OperatorAddress":"op-live-1","Eligible":true,"PolicyReason":"bootstrap policy","UpdatedAt":"2026-01-01T00:00:00Z","Status":"confirmed"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpnvalidator/status-records" '{"StatusID":"status-live-1","ValidatorID":"val-live-1","ConsensusAddress":"cons-live-1","LifecycleStatus":"active","EvidenceHeight":7,"EvidenceRef":"sha256:581690e6640665abd76f2545c1b8c0a864548cb4074f83be5dc0c8ce742a2677","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpngovernance/policies" '{"PolicyID":"policy-live-1","Title":"policy-live-title","Description":"policy-live-description","Version":1,"ActivatedAt":"2026-01-01T00:00:00Z","Status":"submitted"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpngovernance/decisions" '{"DecisionID":"decision-live-1","PolicyID":"policy-live-1","ProposalID":"proposal-live-1","Outcome":"approve","Decider":"bootstrap-multisig","Reason":"smoke decision","DecidedAt":"2026-01-01T00:00:02Z","Status":"confirmed"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

post_expect_status "${BASE_URL}/x/vpngovernance/audit-actions" '{"ActionID":"action-live-1","Action":"policy.bootstrap","Actor":"bootstrap-multisig","Reason":"smoke audit","EvidencePointer":"obj://audit/action-live-1","Timestamp":"2026-01-01T00:00:03Z"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"

# Query-by-id coverage for billing/rewards/sponsor/slashing/validator/governance.
get_expect_status "${BASE_URL}/x/vpnbilling/settlements/set-live-1" "200"
grep -q '"settlement"' "${RESP_FILE}"
grep -q '"SettlementID"[[:space:]]*:[[:space:]]*"set-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnbilling/reservations/bill-res-live-1" "200"
grep -q '"reservation"' "${RESP_FILE}"
grep -q '"ReservationID"[[:space:]]*:[[:space:]]*"bill-res-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnrewards/accruals/reward-live-1" "200"
grep -q '"accrual"' "${RESP_FILE}"
grep -q '"AccrualID"[[:space:]]*:[[:space:]]*"reward-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnrewards/distributions/dist:reward-live-1" "200"
grep -q '"distribution"' "${RESP_FILE}"
grep -q '"DistributionID"[[:space:]]*:[[:space:]]*"dist:reward-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnsponsor/authorizations/auth:res-live-1" "200"
grep -q '"authorization"' "${RESP_FILE}"
grep -q '"AuthorizationID"[[:space:]]*:[[:space:]]*"auth:res-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnsponsor/delegations/res-live-1" "200"
grep -q '"delegation"' "${RESP_FILE}"
grep -q '"ReservationID"[[:space:]]*:[[:space:]]*"res-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnslashing/evidence/ev-live-1" "200"
grep -q '"evidence"' "${RESP_FILE}"
grep -q '"EvidenceID"[[:space:]]*:[[:space:]]*"ev-live-1"' "${RESP_FILE}"
grep -q '"ViolationType"[[:space:]]*:[[:space:]]*"double-sign"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnslashing/penalties/pen-live-1" "200"
grep -q '"penalty"' "${RESP_FILE}"
grep -q '"PenaltyID"[[:space:]]*:[[:space:]]*"pen-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities/val-live-1" "200"
grep -q '"eligibility"' "${RESP_FILE}"
grep -q '"ValidatorID"[[:space:]]*:[[:space:]]*"val-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/status-records/status-live-1" "200"
grep -q '"status"' "${RESP_FILE}"
grep -q '"StatusID"[[:space:]]*:[[:space:]]*"status-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/policies/policy-live-1" "200"
grep -q '"policy"' "${RESP_FILE}"
grep -q '"PolicyID"[[:space:]]*:[[:space:]]*"policy-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/decisions/decision-live-1" "200"
grep -q '"decision"' "${RESP_FILE}"
grep -q '"DecisionID"[[:space:]]*:[[:space:]]*"decision-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/audit-actions/action-live-1" "200"
grep -q '"action"' "${RESP_FILE}"
grep -q '"ActionID"[[:space:]]*:[[:space:]]*"action-live-1"' "${RESP_FILE}"

# List coverage for billing/rewards/sponsor/slashing/validator/governance.
get_expect_status "${BASE_URL}/x/vpnbilling/settlements" "200"
grep -q '"settlements"' "${RESP_FILE}"
grep -q '"SettlementID"[[:space:]]*:[[:space:]]*"set-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnbilling/reservations" "200"
grep -q '"reservations"' "${RESP_FILE}"
grep -q '"ReservationID"[[:space:]]*:[[:space:]]*"bill-res-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnrewards/accruals" "200"
grep -q '"accruals"' "${RESP_FILE}"
grep -q '"AccrualID"[[:space:]]*:[[:space:]]*"reward-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnrewards/distributions" "200"
grep -q '"distributions"' "${RESP_FILE}"
grep -q '"DistributionID"[[:space:]]*:[[:space:]]*"dist:reward-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnsponsor/authorizations" "200"
grep -q '"authorizations"' "${RESP_FILE}"
grep -q '"AuthorizationID"[[:space:]]*:[[:space:]]*"auth:res-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnsponsor/delegations" "200"
grep -q '"delegations"' "${RESP_FILE}"
grep -q '"ReservationID"[[:space:]]*:[[:space:]]*"res-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnslashing/evidence" "200"
grep -q '"evidence"' "${RESP_FILE}"
grep -q '"EvidenceID"[[:space:]]*:[[:space:]]*"ev-live-1"' "${RESP_FILE}"
grep -q '"ViolationType"[[:space:]]*:[[:space:]]*"double-sign"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnslashing/penalties" "200"
grep -q '"penalties"' "${RESP_FILE}"
grep -q '"PenaltyID"[[:space:]]*:[[:space:]]*"pen-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/eligibilities" "200"
grep -q '"eligibilities"' "${RESP_FILE}"
grep -q '"ValidatorID"[[:space:]]*:[[:space:]]*"val-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpnvalidator/status-records" "200"
grep -q '"records"' "${RESP_FILE}"
grep -q '"StatusID"[[:space:]]*:[[:space:]]*"status-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/policies" "200"
grep -q '"policies"' "${RESP_FILE}"
grep -q '"PolicyID"[[:space:]]*:[[:space:]]*"policy-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/decisions" "200"
grep -q '"decisions"' "${RESP_FILE}"
grep -q '"DecisionID"[[:space:]]*:[[:space:]]*"decision-live-1"' "${RESP_FILE}"

get_expect_status "${BASE_URL}/x/vpngovernance/audit-actions" "200"
grep -q '"actions"' "${RESP_FILE}"
grep -q '"ActionID"[[:space:]]*:[[:space:]]*"action-live-1"' "${RESP_FILE}"

# Replay/id behavior check: duplicate write should surface replay=true and preserve id.
post_expect_status "${BASE_URL}/x/vpnvalidator/status-records" '{"StatusID":"status-live-1","ValidatorID":"val-live-1","ConsensusAddress":"cons-live-1","LifecycleStatus":"active","EvidenceHeight":7,"EvidenceRef":"sha256:581690e6640665abd76f2545c1b8c0a864548cb4074f83be5dc0c8ce742a2677","RecordedAt":"2026-01-01T00:00:01Z","Status":"submitted"}' "200" "${TOKEN}"
grep -q '"ok"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"
grep -q '"replay"[[:space:]]*:[[:space:]]*true' "${RESP_FILE}"
grep -q '"id"[[:space:]]*:[[:space:]]*"status-live-1"' "${RESP_FILE}"

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

echo "cosmos tdpnd settlement bridge live smoke integration check ok"
