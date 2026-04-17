#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

if ! command -v grpcurl >/dev/null 2>&1; then
  (
    cd blockchain/tdpn-chain
    timeout 60s go test ./cmd/tdpnd -count=1 -run '^TestRunTDPNDGRPCModeAuth.*$'
  )
  echo "cosmos tdpnd grpc auth live smoke integration check ok (runtime test fallback)"
  exit 0
fi

LOG_FILE="$(mktemp -t tdpnd-grpc-auth-live-smoke.XXXXXX.log)"
TDPND_PID=""
AUTH_TOKEN="${TDPND_GRPC_AUTH_LIVE_SMOKE_TOKEN:-tdpn-live-smoke-token}"
STARTUP_MAX_ATTEMPTS="${TDPND_GRPC_AUTH_LIVE_SMOKE_MAX_STARTUP_ATTEMPTS:-3}"
REQUESTED_PORT="${TDPND_GRPC_AUTH_LIVE_SMOKE_PORT:-}"
PREVIEW_EPOCH_SELECTION_PAYLOAD='{"policy":{"epoch":99,"stable_seat_count":1,"rotating_seat_count":0,"min_stake":1,"min_stake_age_epochs":1,"min_health_score":1,"min_resource_headroom":1},"candidates":[{"validator_id":"validator-auth-smoke-1","operator_id":"operator-auth-smoke-1","asn":"64512","region":"au-west","stake":100,"stake_age_epochs":10,"health_score":100,"resource_headroom":100,"score":100,"stable_seat_preferred":true}]}'
VALIDATOR_ELIGIBILITY_WRITE_PAYLOAD='{"eligibility":{"validator_id":"  VaLiDaToR-Auth-Live-Canon-1  ","operator_address":"  OpErAtOr-Auth-Live-Canon-1  ","eligible":true,"policy_reason":"  canonical eligibility smoke  ","updated_at_unix":4102444800}}'
VALIDATOR_ELIGIBILITY_QUERY_PAYLOAD='{"validator_id":"  VALIDATOR-AUTH-LIVE-CANON-1  "}'
VALIDATOR_STATUS_WRITE_PAYLOAD='{"record":{"status_id":"  StAtUs-Auth-Live-Canon-1  ","validator_id":"  VaLiDaToR-Auth-Live-Canon-1  ","consensus_address":"  CoNsEnSuS-Auth-Live-Canon-1  ","lifecycle_status":"  AcTiVe  ","evidence_height":77,"evidence_ref":"  SHA256:ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890  ","recorded_at_unix":4102444801}}'
VALIDATOR_STATUS_QUERY_PAYLOAD='{"status_id":"  STATUS-AUTH-LIVE-CANON-1  "}'
GOVERNANCE_POLICY_WRITE_PAYLOAD='{"policy":{"policy_id":"  PoLiCy-Auth-Live-Canon-1  ","title":"Policy Auth Canonical Smoke","description":"live smoke canonical policy write","version":1,"activated_at_unix":4102444800}}'
GOVERNANCE_POLICY_QUERY_PAYLOAD='{"policy_id":"  POLICY-AUTH-LIVE-CANON-1  "}'
GOVERNANCE_DECISION_WRITE_PAYLOAD='{"decision":{"decision_id":"  DeCiSiOn-Auth-Live-Canon-1  ","policy_id":"  PoLiCy-Auth-Live-Canon-1  ","proposal_id":"  PrOpOsAl-Auth-Live-Canon-1  ","outcome":"  ApPrOvE  ","decider":"  CoUnCiL-Auth-Live-Canon-1  ","reason":"live smoke canonical decision write","decided_at_unix":4102444802}}'
GOVERNANCE_DECISION_QUERY_PAYLOAD='{"decision_id":"  DECISION-AUTH-LIVE-CANON-1  "}'
GOVERNANCE_AUDIT_ACTION_WRITE_PAYLOAD='{"action":{"action_id":"  AuDiT-Auth-Live-Canon-1  ","action":"  AdMiN_AlLoW_VaLiDaToR  ","actor":"  BoOtStRaP-AdMiN-Auth-Live-Canon-1  ","reason":"live smoke canonical audit write","evidence_pointer":"  ipfs://Evidence/Auth-Live-Canon-1  ","timestamp_unix":4102444803}}'
GOVERNANCE_AUDIT_ACTION_QUERY_PAYLOAD='{"action_id":"  AUDIT-AUTH-LIVE-CANON-1  "}'
BILLING_RESERVE_WRITE_PAYLOAD='{"reservation":{"reservation_id":"  ReS-Auth-Live-Canon-1  ","sponsor_id":"  SpOnSoR-Auth-Live-Canon-1  ","session_id":"  SeSs-Auth-Live-Canon-1  ","asset_denom":"  UuSdC  ","amount":125}}'
BILLING_RESERVATION_QUERY_PAYLOAD='{"reservation_id":"  RES-AUTH-LIVE-CANON-1  "}'
BILLING_FINALIZE_WRITE_PAYLOAD='{"settlement":{"settlement_id":"  SeT-Auth-Live-Canon-1  ","reservation_id":"  RES-Auth-Live-Canon-1  ","session_id":"  SeSs-Auth-Live-Canon-1  ","asset_denom":"  UuSdC  ","billed_amount":120,"usage_bytes":2048}}'
BILLING_SETTLEMENT_QUERY_PAYLOAD='{"settlement_id":"  SET-AUTH-LIVE-CANON-1  "}'
REWARDS_ACCRUAL_WRITE_PAYLOAD='{"accrual":{"accrual_id":"  AcCrUaL-Auth-Live-Canon-1  ","session_id":"  SeSs-Auth-Live-Canon-1  ","provider_id":"  PrOvIdEr-Auth-Live-Canon-1  ","asset_denom":"  UuSdC  ","amount":77}}'
REWARDS_ACCRUAL_QUERY_PAYLOAD='{"accrual_id":"  ACCRUAL-AUTH-LIVE-CANON-1  "}'
REWARDS_DISTRIBUTION_WRITE_PAYLOAD='{"distribution":{"distribution_id":"  DiStRiBuTiOn-Auth-Live-Canon-1  ","accrual_id":"  ACCRUAL-AUTH-LIVE-CANON-1  ","payout_ref":"  payout-auth-live-canon-1  "}}'
REWARDS_DISTRIBUTION_QUERY_PAYLOAD='{"distribution_id":"  DISTRIBUTION-AUTH-LIVE-CANON-1  "}'
SPONSOR_AUTHORIZATION_WRITE_PAYLOAD='{"authorization":{"authorization_id":"  AuTh-Sponsor-Live-Canon-1  ","sponsor_id":"  SpOnSoR-Sponsor-Live-Canon-1  ","app_id":"  ApP-Sponsor-Live-Canon-1  ","max_credits":300,"expires_at_unix":4102444800}}'
SPONSOR_AUTHORIZATION_QUERY_PAYLOAD='{"authorization_id":"  AUTH-SPONSOR-LIVE-CANON-1  "}'
SPONSOR_DELEGATION_WRITE_PAYLOAD='{"delegation":{"reservation_id":"  ReS-Sponsor-Live-Canon-1  ","authorization_id":"  AUTH-SPONSOR-LIVE-CANON-1  ","sponsor_id":"  SPONSOR-SPONSOR-LIVE-CANON-1  ","app_id":"  APP-SPONSOR-LIVE-CANON-1  ","end_user_id":"  EndUser-MiXeD-Auth-1  ","session_id":"  SessIoN-MiXeD-Auth-1  ","credits":25}}'
SPONSOR_DELEGATION_QUERY_PAYLOAD='{"reservation_id":"  RES-SPONSOR-LIVE-CANON-1  "}'
MODULE_QUERY_CHECKS=(
  "tdpn.vpnbilling.v1.Query/ListCreditReservations|reservations"
  "tdpn.vpnbilling.v1.Query/ListSettlementRecords|settlements"
  "tdpn.vpnrewards.v1.Query/ListRewardAccruals|accruals"
  "tdpn.vpnrewards.v1.Query/ListDistributionRecords|distributions"
  "tdpn.vpnslashing.v1.Query/ListSlashEvidence|evidence"
  "tdpn.vpnslashing.v1.Query/ListPenaltyDecisions|penalties"
  "tdpn.vpnsponsor.v1.Query/ListSponsorAuthorizations|authorizations"
  "tdpn.vpnsponsor.v1.Query/ListDelegatedSessionCredits|delegations"
  "tdpn.vpnvalidator.v1.Query/ListValidatorEligibilities|eligibilities"
  "tdpn.vpnvalidator.v1.Query/ListValidatorStatusRecords|records"
  "tdpn.vpnvalidator.v1.Query/PreviewEpochSelection|result|${PREVIEW_EPOCH_SELECTION_PAYLOAD}"
  "tdpn.vpngovernance.v1.Query/ListGovernancePolicies|policies"
  "tdpn.vpngovernance.v1.Query/ListGovernanceDecisions|decisions"
  "tdpn.vpngovernance.v1.Query/ListGovernanceAuditActions|actions"
)

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
  rm -f "${LOG_FILE}"
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

wait_for_grpcurl_health_ready() {
  local port="$1"
  for _ in $(seq 1 60); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      return 11
    fi
    if grpcurl -plaintext -max-time 2 -d '{}' "127.0.0.1:${port}" grpc.health.v1.Health/Check >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  return 12
}

is_bind_address_in_use_log() {
  grep -Eqi 'address already in use|bind: .*in use|listen tcp.*in use' "${LOG_FILE}"
}

if [[ ! "${STARTUP_MAX_ATTEMPTS}" =~ ^[0-9]+$ ]] || (( STARTUP_MAX_ATTEMPTS < 1 )); then
  echo "TDPND_GRPC_AUTH_LIVE_SMOKE_MAX_STARTUP_ATTEMPTS must be an integer >= 1"
  exit 2
fi

AUTO_PICKED_PORT="1"
if [[ -n "${REQUESTED_PORT}" ]]; then
  if [[ ! "${REQUESTED_PORT}" =~ ^[0-9]+$ ]] || (( REQUESTED_PORT < 1 || REQUESTED_PORT > 65535 )); then
    echo "TDPND_GRPC_AUTH_LIVE_SMOKE_PORT must be an integer between 1 and 65535"
    exit 2
  fi
  AUTO_PICKED_PORT="0"
fi

PORT=""
for attempt in $(seq 1 "${STARTUP_MAX_ATTEMPTS}"); do
  if [[ "${AUTO_PICKED_PORT}" == "1" ]]; then
    PORT="$(pick_port)"
    if [[ -z "${PORT}" ]]; then
      echo "failed to allocate smoke-test grpc port"
      exit 1
    fi
  else
    PORT="${REQUESTED_PORT}"
  fi

  : >"${LOG_FILE}"
  (
    cd blockchain/tdpn-chain
    go run ./cmd/tdpnd --grpc-listen "127.0.0.1:${PORT}" --grpc-auth-token "${AUTH_TOKEN}"
  ) >"${LOG_FILE}" 2>&1 &
  TDPND_PID=$!

  set +e
  wait_for_grpcurl_health_ready "${PORT}"
  startup_rc=$?
  set -e
  if (( startup_rc == 0 )); then
    break
  fi

  if [[ "${AUTO_PICKED_PORT}" == "1" ]] && (( startup_rc == 11 )) && is_bind_address_in_use_log && (( attempt < STARTUP_MAX_ATTEMPTS )); then
    echo "[integration-cosmos-tdpnd-grpc-auth-live-smoke] startup attempt ${attempt}/${STARTUP_MAX_ATTEMPTS} hit bind/address-in-use on port ${PORT}; retrying with a new auto-picked port"
    wait "${TDPND_PID}" 2>/dev/null || true
    TDPND_PID=""
    continue
  fi

  if (( startup_rc == 11 )); then
    echo "tdpnd exited before becoming ready (attempt ${attempt}/${STARTUP_MAX_ATTEMPTS}, port ${PORT})"
  else
    echo "timed out waiting for grpc health readiness on ${PORT} (attempt ${attempt}/${STARTUP_MAX_ATTEMPTS})"
  fi
  cat "${LOG_FILE}"
  exit 1
done

if [[ -z "${TDPND_PID}" ]] || ! kill -0 "${TDPND_PID}" 2>/dev/null; then
  echo "failed to start tdpnd grpc auth runtime after ${STARTUP_MAX_ATTEMPTS} attempt(s)"
  cat "${LOG_FILE}"
  exit 1
fi

run_authorized_grpc_call() {
  local port="$1"
  local method="$2"
  local payload="${3:-{}}"
  local output
  local rc

  set +e
  output="$(grpcurl -plaintext -max-time 2 -H "authorization: Bearer ${AUTH_TOKEN}" -d "${payload}" "127.0.0.1:${port}" "${method}" 2>&1)"
  rc=$?
  set -e
  if (( rc != 0 )); then
    echo "expected authorized grpc call ${method} to succeed (rc=${rc})"
    echo "grpc output:"
    echo "${output}"
    cat "${LOG_FILE}"
    exit 1
  fi

  printf '%s' "${output}"
}

assert_output_regex() {
  local output="$1"
  local regex="$2"
  local context="$3"
  if ! grep -Eq "${regex}" <<<"${output}"; then
    echo "${context}"
    echo "grpc output:"
    echo "${output}"
    cat "${LOG_FILE}"
    exit 1
  fi
}

# 1) Health must stay open without bearer token.
HEALTH_OUTPUT="$(grpcurl -plaintext -max-time 2 -d '{}' "127.0.0.1:${PORT}" grpc.health.v1.Health/Check 2>&1 || true)"
if ! grep -q 'SERVING' <<<"${HEALTH_OUTPUT}"; then
  echo "expected unauthenticated health check to succeed and report SERVING"
  echo "health output:"
  echo "${HEALTH_OUTPUT}"
  cat "${LOG_FILE}"
  exit 1
fi

# 2) Query RPCs must fail without auth token and succeed with token.
for module_spec in "${MODULE_QUERY_CHECKS[@]}"; do
  IFS='|' read -r module_rpc expected_field request_payload <<<"${module_spec}"
  request_payload="${request_payload:-{}}"

  set +e
  unauth_output="$(grpcurl -plaintext -max-time 2 -d "${request_payload}" "127.0.0.1:${PORT}" "${module_rpc}" 2>&1)"
  unauth_rc=$?
  set -e
  if (( unauth_rc == 0 )); then
    echo "expected module RPC ${module_rpc} to fail without token, but it succeeded"
    echo "module output:"
    echo "${unauth_output}"
    cat "${LOG_FILE}"
    exit 1
  fi
  if ! grep -Eq 'Unauthenticated|missing or invalid bearer token' <<<"${unauth_output}"; then
    echo "expected unauthenticated signal for module RPC ${module_rpc} without token"
    echo "module unauth output:"
    echo "${unauth_output}"
    cat "${LOG_FILE}"
    exit 1
  fi

  set +e
  auth_output="$(grpcurl -plaintext -max-time 2 -H "authorization: Bearer ${AUTH_TOKEN}" -d "${request_payload}" "127.0.0.1:${PORT}" "${module_rpc}" 2>&1)"
  auth_rc=$?
  set -e
  if (( auth_rc != 0 )); then
    echo "expected module RPC ${module_rpc} to succeed with bearer token (rc=${auth_rc})"
    echo "module auth output:"
    echo "${auth_output}"
    cat "${LOG_FILE}"
    exit 1
  fi
  if ! grep -Eq "\"${expected_field}\"[[:space:]]*:" <<<"${auth_output}"; then
    echo "expected authorized module RPC ${module_rpc} response to include ${expected_field} field"
    echo "module auth output:"
    echo "${auth_output}"
    cat "${LOG_FILE}"
    exit 1
  fi
done

# 3) Authenticated write/query RPCs must preserve canonicalized IDs across mixed-case requests.
billing_reserve_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnbilling.v1.Msg/ReserveCredits" "${BILLING_RESERVE_WRITE_PAYLOAD}")"
assert_output_regex "${billing_reserve_output}" '"reservation"[[:space:]]*:' "expected ReserveCredits response to include reservation"
assert_output_regex "${billing_reserve_output}" '"reservationId"[[:space:]]*:[[:space:]]*"res-auth-live-canon-1"' "expected ReserveCredits to return canonical reservationId"
assert_output_regex "${billing_reserve_output}" '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-auth-live-canon-1"' "expected ReserveCredits to return canonical sponsorId"
assert_output_regex "${billing_reserve_output}" '"sessionId"[[:space:]]*:[[:space:]]*"sess-auth-live-canon-1"' "expected ReserveCredits to return canonical sessionId"
assert_output_regex "${billing_reserve_output}" '"assetDenom"[[:space:]]*:[[:space:]]*"uusdc"' "expected ReserveCredits to return canonical assetDenom"

billing_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnbilling.v1.Query/CreditReservation" "${BILLING_RESERVATION_QUERY_PAYLOAD}")"
assert_output_regex "${billing_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected CreditReservation query to return found=true"
assert_output_regex "${billing_query_output}" '"reservationId"[[:space:]]*:[[:space:]]*"res-auth-live-canon-1"' "expected CreditReservation query to return canonical reservationId"
assert_output_regex "${billing_query_output}" '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-auth-live-canon-1"' "expected CreditReservation query to return canonical sponsorId"
assert_output_regex "${billing_query_output}" '"sessionId"[[:space:]]*:[[:space:]]*"sess-auth-live-canon-1"' "expected CreditReservation query to return canonical sessionId"

billing_finalize_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnbilling.v1.Msg/FinalizeUsage" "${BILLING_FINALIZE_WRITE_PAYLOAD}")"
assert_output_regex "${billing_finalize_output}" '"settlement"[[:space:]]*:' "expected FinalizeUsage response to include settlement"
assert_output_regex "${billing_finalize_output}" '"settlementId"[[:space:]]*:[[:space:]]*"set-auth-live-canon-1"' "expected FinalizeUsage to return canonical settlementId"
assert_output_regex "${billing_finalize_output}" '"reservationId"[[:space:]]*:[[:space:]]*"res-auth-live-canon-1"' "expected FinalizeUsage to return canonical reservationId"
assert_output_regex "${billing_finalize_output}" '"sessionId"[[:space:]]*:[[:space:]]*"sess-auth-live-canon-1"' "expected FinalizeUsage to return canonical sessionId"
assert_output_regex "${billing_finalize_output}" '"assetDenom"[[:space:]]*:[[:space:]]*"uusdc"' "expected FinalizeUsage to return canonical assetDenom"

billing_settlement_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnbilling.v1.Query/SettlementRecord" "${BILLING_SETTLEMENT_QUERY_PAYLOAD}")"
assert_output_regex "${billing_settlement_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected SettlementRecord query to return found=true"
assert_output_regex "${billing_settlement_query_output}" '"settlementId"[[:space:]]*:[[:space:]]*"set-auth-live-canon-1"' "expected SettlementRecord query to return canonical settlementId"
assert_output_regex "${billing_settlement_query_output}" '"reservationId"[[:space:]]*:[[:space:]]*"res-auth-live-canon-1"' "expected SettlementRecord query to return canonical reservationId"

rewards_accrual_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnrewards.v1.Msg/RecordAccrual" "${REWARDS_ACCRUAL_WRITE_PAYLOAD}")"
assert_output_regex "${rewards_accrual_output}" '"accrual"[[:space:]]*:' "expected RecordAccrual response to include accrual"
assert_output_regex "${rewards_accrual_output}" '"accrualId"[[:space:]]*:[[:space:]]*"accrual-auth-live-canon-1"' "expected RecordAccrual to return canonical accrualId"
assert_output_regex "${rewards_accrual_output}" '"sessionId"[[:space:]]*:[[:space:]]*"sess-auth-live-canon-1"' "expected RecordAccrual to return canonical sessionId"
assert_output_regex "${rewards_accrual_output}" '"providerId"[[:space:]]*:[[:space:]]*"provider-auth-live-canon-1"' "expected RecordAccrual to return canonical providerId"
assert_output_regex "${rewards_accrual_output}" '"assetDenom"[[:space:]]*:[[:space:]]*"uusdc"' "expected RecordAccrual to return canonical assetDenom"

rewards_accrual_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnrewards.v1.Query/RewardAccrual" "${REWARDS_ACCRUAL_QUERY_PAYLOAD}")"
assert_output_regex "${rewards_accrual_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected RewardAccrual query to return found=true"
assert_output_regex "${rewards_accrual_query_output}" '"accrualId"[[:space:]]*:[[:space:]]*"accrual-auth-live-canon-1"' "expected RewardAccrual query to return canonical accrualId"
assert_output_regex "${rewards_accrual_query_output}" '"providerId"[[:space:]]*:[[:space:]]*"provider-auth-live-canon-1"' "expected RewardAccrual query to return canonical providerId"

rewards_distribution_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnrewards.v1.Msg/RecordDistribution" "${REWARDS_DISTRIBUTION_WRITE_PAYLOAD}")"
assert_output_regex "${rewards_distribution_output}" '"distribution"[[:space:]]*:' "expected RecordDistribution response to include distribution"
assert_output_regex "${rewards_distribution_output}" '"distributionId"[[:space:]]*:[[:space:]]*"distribution-auth-live-canon-1"' "expected RecordDistribution to return canonical distributionId"
assert_output_regex "${rewards_distribution_output}" '"accrualId"[[:space:]]*:[[:space:]]*"accrual-auth-live-canon-1"' "expected RecordDistribution to return canonical accrualId"

rewards_distribution_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnrewards.v1.Query/DistributionRecord" "${REWARDS_DISTRIBUTION_QUERY_PAYLOAD}")"
assert_output_regex "${rewards_distribution_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected DistributionRecord query to return found=true"
assert_output_regex "${rewards_distribution_query_output}" '"distributionId"[[:space:]]*:[[:space:]]*"distribution-auth-live-canon-1"' "expected DistributionRecord query to return canonical distributionId"
assert_output_regex "${rewards_distribution_query_output}" '"accrualId"[[:space:]]*:[[:space:]]*"accrual-auth-live-canon-1"' "expected DistributionRecord query to return canonical accrualId"

sponsor_authorization_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnsponsor.v1.Msg/CreateAuthorization" "${SPONSOR_AUTHORIZATION_WRITE_PAYLOAD}")"
assert_output_regex "${sponsor_authorization_output}" '"authorization"[[:space:]]*:' "expected CreateAuthorization response to include authorization"
assert_output_regex "${sponsor_authorization_output}" '"authorizationId"[[:space:]]*:[[:space:]]*"auth-sponsor-live-canon-1"' "expected CreateAuthorization to return canonical authorizationId"
assert_output_regex "${sponsor_authorization_output}" '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-sponsor-live-canon-1"' "expected CreateAuthorization to return canonical sponsorId"
assert_output_regex "${sponsor_authorization_output}" '"appId"[[:space:]]*:[[:space:]]*"app-sponsor-live-canon-1"' "expected CreateAuthorization to return canonical appId"

sponsor_authorization_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnsponsor.v1.Query/SponsorAuthorization" "${SPONSOR_AUTHORIZATION_QUERY_PAYLOAD}")"
assert_output_regex "${sponsor_authorization_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected SponsorAuthorization query to return found=true"
assert_output_regex "${sponsor_authorization_query_output}" '"authorizationId"[[:space:]]*:[[:space:]]*"auth-sponsor-live-canon-1"' "expected SponsorAuthorization query to return canonical authorizationId"
assert_output_regex "${sponsor_authorization_query_output}" '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-sponsor-live-canon-1"' "expected SponsorAuthorization query to return canonical sponsorId"
assert_output_regex "${sponsor_authorization_query_output}" '"appId"[[:space:]]*:[[:space:]]*"app-sponsor-live-canon-1"' "expected SponsorAuthorization query to return canonical appId"

sponsor_delegation_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnsponsor.v1.Msg/DelegateSessionCredit" "${SPONSOR_DELEGATION_WRITE_PAYLOAD}")"
assert_output_regex "${sponsor_delegation_output}" '"delegation"[[:space:]]*:' "expected DelegateSessionCredit response to include delegation"
assert_output_regex "${sponsor_delegation_output}" '"reservationId"[[:space:]]*:[[:space:]]*"res-sponsor-live-canon-1"' "expected DelegateSessionCredit to return canonical reservationId"
assert_output_regex "${sponsor_delegation_output}" '"authorizationId"[[:space:]]*:[[:space:]]*"auth-sponsor-live-canon-1"' "expected DelegateSessionCredit to return canonical authorizationId"
assert_output_regex "${sponsor_delegation_output}" '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-sponsor-live-canon-1"' "expected DelegateSessionCredit to return canonical sponsorId"
assert_output_regex "${sponsor_delegation_output}" '"appId"[[:space:]]*:[[:space:]]*"app-sponsor-live-canon-1"' "expected DelegateSessionCredit to return canonical appId"
assert_output_regex "${sponsor_delegation_output}" '"endUserId"[[:space:]]*:[[:space:]]*"EndUser-MiXeD-Auth-1"' "expected DelegateSessionCredit to preserve trimmed endUserId casing"
assert_output_regex "${sponsor_delegation_output}" '"sessionId"[[:space:]]*:[[:space:]]*"SessIoN-MiXeD-Auth-1"' "expected DelegateSessionCredit to preserve trimmed sessionId casing"

sponsor_delegation_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnsponsor.v1.Query/DelegatedSessionCredit" "${SPONSOR_DELEGATION_QUERY_PAYLOAD}")"
assert_output_regex "${sponsor_delegation_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected DelegatedSessionCredit query to return found=true"
assert_output_regex "${sponsor_delegation_query_output}" '"reservationId"[[:space:]]*:[[:space:]]*"res-sponsor-live-canon-1"' "expected DelegatedSessionCredit query to return canonical reservationId"
assert_output_regex "${sponsor_delegation_query_output}" '"authorizationId"[[:space:]]*:[[:space:]]*"auth-sponsor-live-canon-1"' "expected DelegatedSessionCredit query to return canonical authorizationId"
assert_output_regex "${sponsor_delegation_query_output}" '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-sponsor-live-canon-1"' "expected DelegatedSessionCredit query to return canonical sponsorId"
assert_output_regex "${sponsor_delegation_query_output}" '"appId"[[:space:]]*:[[:space:]]*"app-sponsor-live-canon-1"' "expected DelegatedSessionCredit query to return canonical appId"
assert_output_regex "${sponsor_delegation_query_output}" '"endUserId"[[:space:]]*:[[:space:]]*"EndUser-MiXeD-Auth-1"' "expected DelegatedSessionCredit query to preserve trimmed endUserId casing"
assert_output_regex "${sponsor_delegation_query_output}" '"sessionId"[[:space:]]*:[[:space:]]*"SessIoN-MiXeD-Auth-1"' "expected DelegatedSessionCredit query to preserve trimmed sessionId casing"

validator_set_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnvalidator.v1.Msg/SetValidatorEligibility" "${VALIDATOR_ELIGIBILITY_WRITE_PAYLOAD}")"
assert_output_regex "${validator_set_output}" '"eligibility"[[:space:]]*:' "expected SetValidatorEligibility response to include eligibility"
assert_output_regex "${validator_set_output}" '"validatorId"[[:space:]]*:[[:space:]]*"validator-auth-live-canon-1"' "expected SetValidatorEligibility to return canonical validatorId"
assert_output_regex "${validator_set_output}" '"operatorAddress"[[:space:]]*:[[:space:]]*"operator-auth-live-canon-1"' "expected SetValidatorEligibility to return canonical operatorAddress"

validator_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnvalidator.v1.Query/ValidatorEligibility" "${VALIDATOR_ELIGIBILITY_QUERY_PAYLOAD}")"
assert_output_regex "${validator_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected ValidatorEligibility query to return found=true"
assert_output_regex "${validator_query_output}" '"validatorId"[[:space:]]*:[[:space:]]*"validator-auth-live-canon-1"' "expected ValidatorEligibility query to return canonical validatorId"

validator_status_record_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnvalidator.v1.Msg/RecordValidatorStatus" "${VALIDATOR_STATUS_WRITE_PAYLOAD}")"
assert_output_regex "${validator_status_record_output}" '"record"[[:space:]]*:' "expected RecordValidatorStatus response to include record"
assert_output_regex "${validator_status_record_output}" '"statusId"[[:space:]]*:[[:space:]]*"status-auth-live-canon-1"' "expected RecordValidatorStatus to return canonical statusId"
assert_output_regex "${validator_status_record_output}" '"validatorId"[[:space:]]*:[[:space:]]*"validator-auth-live-canon-1"' "expected RecordValidatorStatus to return canonical validatorId"

validator_status_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpnvalidator.v1.Query/ValidatorStatusRecord" "${VALIDATOR_STATUS_QUERY_PAYLOAD}")"
assert_output_regex "${validator_status_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected ValidatorStatusRecord query to return found=true"
assert_output_regex "${validator_status_query_output}" '"statusId"[[:space:]]*:[[:space:]]*"status-auth-live-canon-1"' "expected ValidatorStatusRecord query to return canonical statusId"

governance_policy_create_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpngovernance.v1.Msg/CreatePolicy" "${GOVERNANCE_POLICY_WRITE_PAYLOAD}")"
assert_output_regex "${governance_policy_create_output}" '"policy"[[:space:]]*:' "expected CreatePolicy response to include policy"
assert_output_regex "${governance_policy_create_output}" '"policyId"[[:space:]]*:[[:space:]]*"policy-auth-live-canon-1"' "expected CreatePolicy to return canonical policyId"

governance_policy_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpngovernance.v1.Query/GovernancePolicy" "${GOVERNANCE_POLICY_QUERY_PAYLOAD}")"
assert_output_regex "${governance_policy_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected GovernancePolicy query to return found=true"
assert_output_regex "${governance_policy_query_output}" '"policyId"[[:space:]]*:[[:space:]]*"policy-auth-live-canon-1"' "expected GovernancePolicy query to return canonical policyId"

governance_decision_record_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpngovernance.v1.Msg/RecordDecision" "${GOVERNANCE_DECISION_WRITE_PAYLOAD}")"
assert_output_regex "${governance_decision_record_output}" '"decision"[[:space:]]*:' "expected RecordDecision response to include decision"
assert_output_regex "${governance_decision_record_output}" '"decisionId"[[:space:]]*:[[:space:]]*"decision-auth-live-canon-1"' "expected RecordDecision to return canonical decisionId"
assert_output_regex "${governance_decision_record_output}" '"policyId"[[:space:]]*:[[:space:]]*"policy-auth-live-canon-1"' "expected RecordDecision to return canonical policyId"

governance_decision_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpngovernance.v1.Query/GovernanceDecision" "${GOVERNANCE_DECISION_QUERY_PAYLOAD}")"
assert_output_regex "${governance_decision_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected GovernanceDecision query to return found=true"
assert_output_regex "${governance_decision_query_output}" '"decisionId"[[:space:]]*:[[:space:]]*"decision-auth-live-canon-1"' "expected GovernanceDecision query to return canonical decisionId"

governance_audit_record_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpngovernance.v1.Msg/RecordAuditAction" "${GOVERNANCE_AUDIT_ACTION_WRITE_PAYLOAD}")"
assert_output_regex "${governance_audit_record_output}" '"action"[[:space:]]*:' "expected RecordAuditAction response to include action"
assert_output_regex "${governance_audit_record_output}" '"actionId"[[:space:]]*:[[:space:]]*"audit-auth-live-canon-1"' "expected RecordAuditAction to return canonical actionId"

governance_audit_query_output="$(run_authorized_grpc_call "${PORT}" "tdpn.vpngovernance.v1.Query/GovernanceAuditAction" "${GOVERNANCE_AUDIT_ACTION_QUERY_PAYLOAD}")"
assert_output_regex "${governance_audit_query_output}" '"found"[[:space:]]*:[[:space:]]*true' "expected GovernanceAuditAction query to return found=true"
assert_output_regex "${governance_audit_query_output}" '"actionId"[[:space:]]*:[[:space:]]*"audit-auth-live-canon-1"' "expected GovernanceAuditAction query to return canonical actionId"

# 4) Reflection must be disabled in auth-token mode.
set +e
REFLECTION_OUTPUT="$(grpcurl -plaintext -max-time 2 "127.0.0.1:${PORT}" list 2>&1)"
REFLECTION_RC=$?
set -e
if (( REFLECTION_RC == 0 )); then
  echo "expected grpc reflection/list to be disabled in auth mode, but list succeeded"
  echo "reflection output:"
  echo "${REFLECTION_OUTPUT}"
  cat "${LOG_FILE}"
  exit 1
fi
if ! grep -Eqi 'does not support the reflection API|unimplemented|unknown service|not implemented' <<<"${REFLECTION_OUTPUT}"; then
  echo "expected reflection-disabled signal from grpcurl list in auth mode"
  echo "reflection output:"
  echo "${REFLECTION_OUTPUT}"
  cat "${LOG_FILE}"
  exit 1
fi

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

echo "cosmos tdpnd grpc auth live smoke integration check ok"
