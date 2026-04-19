#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

LOG_FILE="$(mktemp -t tdpnd-grpc-live-smoke.XXXXXX.log)"
TDPND_PID=""
START_ATTEMPTS="${TDPND_GRPC_LIVE_SMOKE_START_ATTEMPTS:-6}"
PREVIEW_EPOCH_SELECTION_PAYLOAD='{"policy":{"epoch":99,"stable_seat_count":1,"rotating_seat_count":0,"min_stake":1,"min_stake_age_epochs":1,"min_health_score":1,"min_resource_headroom":1},"candidates":[{"validator_id":"validator-live-smoke-1","operator_id":"operator-live-smoke-1","asn":"64512","region":"au-west","stake":100,"stake_age_epochs":10,"health_score":100,"resource_headroom":100,"score":100,"stable_seat_preferred":true}]}'
VALIDATOR_ELIGIBILITY_SET_PAYLOAD='{"eligibility":{"validator_id":"  VAL-LIVE-SMOKE-ELIG-1  ","operator_address":"  TDPNVALOPER1LIVECANON  ","eligible":true,"policy_reason":" live smoke canonicalization ","updated_at_unix":1700000001}}'
VALIDATOR_ELIGIBILITY_QUERY_PAYLOAD='{"validator_id":"  VAL-LIVE-SMOKE-ELIG-1  "}'
VALIDATOR_STATUS_SET_PAYLOAD='{"record":{"status_id":"  STATUS-LIVE-SMOKE-1  ","validator_id":"  VAL-LIVE-SMOKE-ELIG-1  ","consensus_address":"  TDPNVALCONS1LIVECANON  ","lifecycle_status":"  ACTIVE  ","evidence_height":42}}'
VALIDATOR_STATUS_QUERY_PAYLOAD='{"status_id":"  STATUS-LIVE-SMOKE-1  "}'
GOVERNANCE_POLICY_CREATE_PAYLOAD='{"policy":{"policy_id":"  GOV-LIVE-SMOKE-POLICY-1  ","title":"Live Smoke Policy","description":"canonicalization smoke","version":1,"activated_at_unix":1700000100}}'
GOVERNANCE_POLICY_QUERY_PAYLOAD='{"policy_id":"  GOV-LIVE-SMOKE-POLICY-1  "}'
GOVERNANCE_DECISION_RECORD_PAYLOAD='{"decision":{"decision_id":"  GOV-LIVE-SMOKE-DECISION-1  ","policy_id":"  GOV-LIVE-SMOKE-POLICY-1  ","proposal_id":"  GOV-LIVE-SMOKE-PROPOSAL-1  ","outcome":"  APPROVE  ","decider":"  GOV-DECIDER-LIVE-1  ","reason":" live smoke decision ","decided_at_unix":1700000200}}'
GOVERNANCE_DECISION_QUERY_PAYLOAD='{"decision_id":"  GOV-LIVE-SMOKE-DECISION-1  "}'
GOVERNANCE_AUDIT_ACTION_RECORD_PAYLOAD='{"action":{"action_id":"  GOV-LIVE-SMOKE-ACTION-1  ","action":"  ENFORCE  ","actor":"  GOV-ACTOR-LIVE-1  ","reason":" live smoke audit ","evidence_pointer":" obj://Live/Smoke/Audit/1 ","timestamp_unix":1700000300}}'
GOVERNANCE_AUDIT_ACTION_QUERY_PAYLOAD='{"action_id":"  GOV-LIVE-SMOKE-ACTION-1  "}'
BILLING_RESERVE_WRITE_PAYLOAD='{"reservation":{"reservation_id":"  ReS-LIVE-SMOKE-BILLING-1  ","sponsor_id":"  SpOnSoR-LIVE-SMOKE-BILLING-1  ","session_id":"  SeSsIoN-LIVE-SMOKE-BILLING-1  ","asset_denom":"  UUSDC  ","amount":120}}'
BILLING_RESERVATION_QUERY_MIXED_PAYLOAD='{"reservation_id":"  RES-LIVE-SMOKE-BILLING-1  "}'
BILLING_RESERVATION_QUERY_CANONICAL_PAYLOAD='{"reservation_id":"res-live-smoke-billing-1"}'
BILLING_FINALIZE_WRITE_PAYLOAD='{"settlement":{"settlement_id":"  SeT-LIVE-SMOKE-BILLING-1  ","reservation_id":"  RES-LIVE-SMOKE-BILLING-1  ","session_id":"  SeSsIoN-LIVE-SMOKE-BILLING-1  ","asset_denom":"  UUSDC  ","billed_amount":100,"usage_bytes":4096}}'
BILLING_SETTLEMENT_QUERY_MIXED_PAYLOAD='{"settlement_id":"  SET-LIVE-SMOKE-BILLING-1  "}'
BILLING_SETTLEMENT_QUERY_CANONICAL_PAYLOAD='{"settlement_id":"set-live-smoke-billing-1"}'
REWARDS_ACCRUAL_WRITE_PAYLOAD='{"accrual":{"accrual_id":"  AcCrUaL-LIVE-SMOKE-REWARDS-1  ","session_id":"  SeSsIoN-LIVE-SMOKE-REWARDS-1  ","provider_id":"  PrOvIdEr-LIVE-SMOKE-REWARDS-1  ","asset_denom":"  UUSDC  ","amount":77,"operation_state":"RECONCILIATION_STATUS_SUBMITTED"}}'
REWARDS_ACCRUAL_QUERY_MIXED_PAYLOAD='{"accrual_id":"  ACCRUAL-LIVE-SMOKE-REWARDS-1  "}'
REWARDS_ACCRUAL_QUERY_CANONICAL_PAYLOAD='{"accrual_id":"accrual-live-smoke-rewards-1"}'
REWARDS_DISTRIBUTION_WRITE_PAYLOAD='{"distribution":{"distribution_id":"  DiStRiBuTiOn-LIVE-SMOKE-REWARDS-1  ","accrual_id":"  ACCRUAL-LIVE-SMOKE-REWARDS-1  ","payout_ref":"payout-live-smoke-rewards-1"}}'
REWARDS_DISTRIBUTION_QUERY_MIXED_PAYLOAD='{"distribution_id":"  DISTRIBUTION-LIVE-SMOKE-REWARDS-1  "}'
REWARDS_DISTRIBUTION_QUERY_CANONICAL_PAYLOAD='{"distribution_id":"distribution-live-smoke-rewards-1"}'
SPONSOR_AUTHORIZATION_WRITE_PAYLOAD='{"authorization":{"authorization_id":"  AuTh-LIVE-SMOKE-SPONSOR-1  ","sponsor_id":"  SpOnSoR-LIVE-SMOKE-SPONSOR-1  ","app_id":"  ApP-LIVE-SMOKE-SPONSOR-1  ","max_credits":250,"expires_at_unix":4102444800}}'
SPONSOR_AUTHORIZATION_QUERY_MIXED_PAYLOAD='{"authorization_id":"  AUTH-LIVE-SMOKE-SPONSOR-1  "}'
SPONSOR_AUTHORIZATION_QUERY_CANONICAL_PAYLOAD='{"authorization_id":"auth-live-smoke-sponsor-1"}'
SPONSOR_DELEGATION_WRITE_PAYLOAD='{"delegation":{"reservation_id":"  ReS-LIVE-SMOKE-SPONSOR-1  ","authorization_id":"  AUTH-LIVE-SMOKE-SPONSOR-1  ","sponsor_id":"  SPONSOR-LIVE-SMOKE-SPONSOR-1  ","app_id":"  APP-LIVE-SMOKE-SPONSOR-1  ","end_user_id":"  EndUser-Live-Smoke-1  ","session_id":"  SessIoN-Live-Smoke-1  ","credits":25}}'
SPONSOR_DELEGATION_QUERY_MIXED_PAYLOAD='{"reservation_id":"  RES-LIVE-SMOKE-SPONSOR-1  "}'
SPONSOR_DELEGATION_QUERY_CANONICAL_PAYLOAD='{"reservation_id":"res-live-smoke-sponsor-1"}'

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

validate_positive_int() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]] || (( value < 1 )); then
    echo "${name} must be an integer >= 1 (got: ${value})"
    exit 2
  fi
}

is_port_conflict_log() {
  grep -Eqi 'address already in use|bind: address already in use|failed to listen on .* bind: address already in use' "${LOG_FILE}"
}

wait_for_tcp_ready() {
  local port="$1"
  for _ in $(seq 1 60); do
    if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
      echo "tdpnd exited before becoming ready"
      cat "${LOG_FILE}"
      return 1
    fi
    if (echo >/dev/tcp/127.0.0.1/"${port}") >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.1
  done
  echo "timed out waiting for tdpnd TCP readiness on ${port}"
  cat "${LOG_FILE}"
  return 1
}

wait_for_grpcurl_health() {
  local port="$1"
  for _ in $(seq 1 40); do
    if grpcurl -plaintext -max-time 2 -d '{}' "127.0.0.1:${port}" grpc.health.v1.Health/Check >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.15
  done
  echo "timed out waiting for grpc health check on ${port}"
  cat "${LOG_FILE}"
  return 1
}

wait_for_grpcurl_reflection() {
  local port="$1"
  for _ in $(seq 1 40); do
    local services
    services="$(grpcurl -plaintext -max-time 2 "127.0.0.1:${port}" list 2>/dev/null || true)"
    if [[ -n "${services}" ]] && grep -q '^grpc\.health\.v1\.Health$' <<<"${services}" && grep -q '^grpc\.reflection\.' <<<"${services}"; then
      return 0
    fi
    sleep 0.15
  done
  echo "timed out waiting for grpc reflection services on ${port}"
  cat "${LOG_FILE}"
  return 1
}

assert_grpc_services_include() {
  local services="$1"
  local service_name="$2"
  if ! grep -q "^${service_name}$" <<<"${services}"; then
    echo "expected grpc reflection list to include ${service_name}"
    echo "grpc services:"
    echo "${services}"
    cat "${LOG_FILE}"
    exit 1
  fi
}

assert_grpc_query_dispatch() {
  local port="$1"
  local method="$2"
  local expected_field="$3"
  local payload="${4:-{}}"
  local output
  local rc

  set +e
  output="$(grpcurl -plaintext -max-time 2 -d "${payload}" "127.0.0.1:${port}" "${method}" 2>&1)"
  rc=$?
  set -e
  if (( rc != 0 )); then
    echo "expected grpc query dispatch for ${method} to succeed (rc=${rc})"
    echo "grpc query output:"
    echo "${output}"
    cat "${LOG_FILE}"
    exit 1
  fi
  if ! grep -Eq "\"${expected_field}\"[[:space:]]*:" <<<"${output}"; then
    echo "expected grpc query ${method} response to include ${expected_field} field"
    echo "grpc query output:"
    echo "${output}"
    cat "${LOG_FILE}"
    exit 1
  fi
}

assert_grpc_call_patterns() {
  local port="$1"
  local method="$2"
  local payload="$3"
  shift 3

  local output
  local rc

  set +e
  output="$(grpcurl -plaintext -max-time 2 -d "${payload}" "127.0.0.1:${port}" "${method}" 2>&1)"
  rc=$?
  set -e
  if (( rc != 0 )); then
    echo "expected grpc call ${method} to succeed (rc=${rc})"
    echo "grpc call payload:"
    echo "${payload}"
    echo "grpc call output:"
    echo "${output}"
    cat "${LOG_FILE}"
    exit 1
  fi

  local pattern
  for pattern in "$@"; do
    if ! grep -Eq -- "${pattern}" <<<"${output}"; then
      echo "expected grpc call ${method} response to match pattern: ${pattern}"
      echo "grpc call payload:"
      echo "${payload}"
      echo "grpc call output:"
      echo "${output}"
      cat "${LOG_FILE}"
      exit 1
    fi
  done
}

validate_positive_int "TDPND_GRPC_LIVE_SMOKE_START_ATTEMPTS" "${START_ATTEMPTS}"

PORT=""
started=0
for start_attempt in $(seq 1 "${START_ATTEMPTS}"); do
  PORT="$(pick_port || true)"
  if [[ -z "${PORT}" ]]; then
    echo "failed to allocate smoke-test grpc port"
    exit 1
  fi

  : >"${LOG_FILE}"
  (
    cd blockchain/tdpn-chain
    go run ./cmd/tdpnd --grpc-listen "127.0.0.1:${PORT}"
  ) >"${LOG_FILE}" 2>&1 &
  TDPND_PID=$!

  if command -v grpcurl >/dev/null 2>&1; then
    if wait_for_grpcurl_health "${PORT}" && wait_for_grpcurl_reflection "${PORT}"; then
      started=1
      break
    fi
  else
    if wait_for_tcp_ready "${PORT}"; then
      sleep 0.15
      if wait_for_tcp_ready "${PORT}" && [[ -n "${TDPND_PID}" ]] && kill -0 "${TDPND_PID}" 2>/dev/null; then
        started=1
        break
      fi
      if [[ -n "${TDPND_PID}" ]] && ! kill -0 "${TDPND_PID}" 2>/dev/null; then
        echo "tdpnd exited unexpectedly after TCP fallback readiness checks"
      fi
    fi
  fi

  signal_runtime TERM
  wait_for_runtime_exit 20 || true
  if [[ -n "${TDPND_PID}" ]]; then
    wait "${TDPND_PID}" 2>/dev/null || true
  fi
  TDPND_PID=""

  if (( start_attempt < START_ATTEMPTS )) && is_port_conflict_log; then
    continue
  fi

  echo "tdpnd failed to become ready on ${PORT} (attempt ${start_attempt}/${START_ATTEMPTS})"
  cat "${LOG_FILE}"
  exit 1
done

if (( started != 1 )); then
  echo "tdpnd failed to start after ${START_ATTEMPTS} attempts"
  cat "${LOG_FILE}"
  exit 1
fi

if command -v grpcurl >/dev/null 2>&1; then
  SERVICES="$(grpcurl -plaintext -max-time 2 "127.0.0.1:${PORT}" list 2>/dev/null || true)"
  assert_grpc_services_include "${SERVICES}" "tdpn.vpnbilling.v1.Query"
  assert_grpc_services_include "${SERVICES}" "tdpn.vpnrewards.v1.Query"
  assert_grpc_services_include "${SERVICES}" "tdpn.vpnslashing.v1.Query"
  assert_grpc_services_include "${SERVICES}" "tdpn.vpnsponsor.v1.Query"
  assert_grpc_services_include "${SERVICES}" "tdpn.vpnvalidator.v1.Msg"
  assert_grpc_services_include "${SERVICES}" "tdpn.vpnvalidator.v1.Query"
  assert_grpc_services_include "${SERVICES}" "tdpn.vpngovernance.v1.Msg"
  assert_grpc_services_include "${SERVICES}" "tdpn.vpngovernance.v1.Query"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnbilling.v1.Query/ListCreditReservations" "reservations"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnbilling.v1.Query/ListSettlementRecords" "settlements"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnrewards.v1.Query/ListRewardAccruals" "accruals"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnrewards.v1.Query/ListDistributionRecords" "distributions"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnslashing.v1.Query/ListSlashEvidence" "evidence"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnslashing.v1.Query/ListPenaltyDecisions" "penalties"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnsponsor.v1.Query/ListSponsorAuthorizations" "authorizations"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnsponsor.v1.Query/ListDelegatedSessionCredits" "delegations"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnvalidator.v1.Query/ListValidatorEligibilities" "eligibilities"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnvalidator.v1.Query/ListValidatorStatusRecords" "records"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpnvalidator.v1.Query/PreviewEpochSelection" "result" "${PREVIEW_EPOCH_SELECTION_PAYLOAD}"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpngovernance.v1.Query/ListGovernancePolicies" "policies"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpngovernance.v1.Query/ListGovernanceDecisions" "decisions"
  assert_grpc_query_dispatch "${PORT}" "tdpn.vpngovernance.v1.Query/ListGovernanceAuditActions" "actions"

  # Billing canonicalization compatibility (write mixed-case/whitespace, query mixed-case/canonical).
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnbilling.v1.Msg/ReserveCredits" "${BILLING_RESERVE_WRITE_PAYLOAD}" \
    '"reservation"[[:space:]]*:' \
    '"reservationId"[[:space:]]*:[[:space:]]*"res-live-smoke-billing-1"' \
    '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-live-smoke-billing-1"' \
    '"sessionId"[[:space:]]*:[[:space:]]*"session-live-smoke-billing-1"' \
    '"assetDenom"[[:space:]]*:[[:space:]]*"uusdc"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnbilling.v1.Query/CreditReservation" "${BILLING_RESERVATION_QUERY_MIXED_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"reservationId"[[:space:]]*:[[:space:]]*"res-live-smoke-billing-1"' \
    '"assetDenom"[[:space:]]*:[[:space:]]*"uusdc"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnbilling.v1.Query/CreditReservation" "${BILLING_RESERVATION_QUERY_CANONICAL_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"reservationId"[[:space:]]*:[[:space:]]*"res-live-smoke-billing-1"'

  assert_grpc_call_patterns "${PORT}" "tdpn.vpnbilling.v1.Msg/FinalizeUsage" "${BILLING_FINALIZE_WRITE_PAYLOAD}" \
    '"settlement"[[:space:]]*:' \
    '"settlementId"[[:space:]]*:[[:space:]]*"set-live-smoke-billing-1"' \
    '"reservationId"[[:space:]]*:[[:space:]]*"res-live-smoke-billing-1"' \
    '"sessionId"[[:space:]]*:[[:space:]]*"session-live-smoke-billing-1"' \
    '"assetDenom"[[:space:]]*:[[:space:]]*"uusdc"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnbilling.v1.Query/SettlementRecord" "${BILLING_SETTLEMENT_QUERY_MIXED_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"settlementId"[[:space:]]*:[[:space:]]*"set-live-smoke-billing-1"' \
    '"reservationId"[[:space:]]*:[[:space:]]*"res-live-smoke-billing-1"' \
    '"assetDenom"[[:space:]]*:[[:space:]]*"uusdc"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnbilling.v1.Query/SettlementRecord" "${BILLING_SETTLEMENT_QUERY_CANONICAL_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"settlementId"[[:space:]]*:[[:space:]]*"set-live-smoke-billing-1"'

  # Rewards canonicalization compatibility (write mixed-case/whitespace, query mixed-case/canonical).
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnrewards.v1.Msg/RecordAccrual" "${REWARDS_ACCRUAL_WRITE_PAYLOAD}" \
    '"accrual"[[:space:]]*:' \
    '"accrualId"[[:space:]]*:[[:space:]]*"accrual-live-smoke-rewards-1"' \
    '"sessionId"[[:space:]]*:[[:space:]]*"session-live-smoke-rewards-1"' \
    '"providerId"[[:space:]]*:[[:space:]]*"provider-live-smoke-rewards-1"' \
    '"assetDenom"[[:space:]]*:[[:space:]]*"uusdc"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnrewards.v1.Query/RewardAccrual" "${REWARDS_ACCRUAL_QUERY_MIXED_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"accrualId"[[:space:]]*:[[:space:]]*"accrual-live-smoke-rewards-1"' \
    '"providerId"[[:space:]]*:[[:space:]]*"provider-live-smoke-rewards-1"' \
    '"assetDenom"[[:space:]]*:[[:space:]]*"uusdc"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnrewards.v1.Query/RewardAccrual" "${REWARDS_ACCRUAL_QUERY_CANONICAL_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"accrualId"[[:space:]]*:[[:space:]]*"accrual-live-smoke-rewards-1"'

  assert_grpc_call_patterns "${PORT}" "tdpn.vpnrewards.v1.Msg/RecordDistribution" "${REWARDS_DISTRIBUTION_WRITE_PAYLOAD}" \
    '"distribution"[[:space:]]*:' \
    '"distributionId"[[:space:]]*:[[:space:]]*"distribution-live-smoke-rewards-1"' \
    '"accrualId"[[:space:]]*:[[:space:]]*"accrual-live-smoke-rewards-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnrewards.v1.Query/DistributionRecord" "${REWARDS_DISTRIBUTION_QUERY_MIXED_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"distributionId"[[:space:]]*:[[:space:]]*"distribution-live-smoke-rewards-1"' \
    '"accrualId"[[:space:]]*:[[:space:]]*"accrual-live-smoke-rewards-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnrewards.v1.Query/DistributionRecord" "${REWARDS_DISTRIBUTION_QUERY_CANONICAL_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"distributionId"[[:space:]]*:[[:space:]]*"distribution-live-smoke-rewards-1"'

  # Sponsor canonicalization compatibility (write mixed-case/whitespace, query mixed-case/canonical).
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnsponsor.v1.Msg/CreateAuthorization" "${SPONSOR_AUTHORIZATION_WRITE_PAYLOAD}" \
    '"authorization"[[:space:]]*:' \
    '"authorizationId"[[:space:]]*:[[:space:]]*"auth-live-smoke-sponsor-1"' \
    '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-live-smoke-sponsor-1"' \
    '"appId"[[:space:]]*:[[:space:]]*"app-live-smoke-sponsor-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnsponsor.v1.Query/SponsorAuthorization" "${SPONSOR_AUTHORIZATION_QUERY_MIXED_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"authorizationId"[[:space:]]*:[[:space:]]*"auth-live-smoke-sponsor-1"' \
    '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-live-smoke-sponsor-1"' \
    '"appId"[[:space:]]*:[[:space:]]*"app-live-smoke-sponsor-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnsponsor.v1.Query/SponsorAuthorization" "${SPONSOR_AUTHORIZATION_QUERY_CANONICAL_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"authorizationId"[[:space:]]*:[[:space:]]*"auth-live-smoke-sponsor-1"'

  assert_grpc_call_patterns "${PORT}" "tdpn.vpnsponsor.v1.Msg/DelegateSessionCredit" "${SPONSOR_DELEGATION_WRITE_PAYLOAD}" \
    '"delegation"[[:space:]]*:' \
    '"reservationId"[[:space:]]*:[[:space:]]*"res-live-smoke-sponsor-1"' \
    '"authorizationId"[[:space:]]*:[[:space:]]*"auth-live-smoke-sponsor-1"' \
    '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-live-smoke-sponsor-1"' \
    '"appId"[[:space:]]*:[[:space:]]*"app-live-smoke-sponsor-1"' \
    '"endUserId"[[:space:]]*:[[:space:]]*"EndUser-Live-Smoke-1"' \
    '"sessionId"[[:space:]]*:[[:space:]]*"SessIoN-Live-Smoke-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnsponsor.v1.Query/DelegatedSessionCredit" "${SPONSOR_DELEGATION_QUERY_MIXED_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"reservationId"[[:space:]]*:[[:space:]]*"res-live-smoke-sponsor-1"' \
    '"authorizationId"[[:space:]]*:[[:space:]]*"auth-live-smoke-sponsor-1"' \
    '"sponsorId"[[:space:]]*:[[:space:]]*"sponsor-live-smoke-sponsor-1"' \
    '"appId"[[:space:]]*:[[:space:]]*"app-live-smoke-sponsor-1"' \
    '"endUserId"[[:space:]]*:[[:space:]]*"EndUser-Live-Smoke-1"' \
    '"sessionId"[[:space:]]*:[[:space:]]*"SessIoN-Live-Smoke-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnsponsor.v1.Query/DelegatedSessionCredit" "${SPONSOR_DELEGATION_QUERY_CANONICAL_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"reservationId"[[:space:]]*:[[:space:]]*"res-live-smoke-sponsor-1"'

  # Validator canonicalization compatibility (write mixed-case/whitespace, query mixed-case).
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnvalidator.v1.Msg/SetValidatorEligibility" "${VALIDATOR_ELIGIBILITY_SET_PAYLOAD}" \
    '"eligibility"[[:space:]]*:' \
    '"validatorId"[[:space:]]*:[[:space:]]*"val-live-smoke-elig-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnvalidator.v1.Query/ValidatorEligibility" "${VALIDATOR_ELIGIBILITY_QUERY_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"validatorId"[[:space:]]*:[[:space:]]*"val-live-smoke-elig-1"' \
    '"operatorAddress"[[:space:]]*:[[:space:]]*"tdpnvaloper1livecanon"'

  assert_grpc_call_patterns "${PORT}" "tdpn.vpnvalidator.v1.Msg/RecordValidatorStatus" "${VALIDATOR_STATUS_SET_PAYLOAD}" \
    '"record"[[:space:]]*:' \
    '"statusId"[[:space:]]*:[[:space:]]*"status-live-smoke-1"' \
    '"validatorId"[[:space:]]*:[[:space:]]*"val-live-smoke-elig-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpnvalidator.v1.Query/ValidatorStatusRecord" "${VALIDATOR_STATUS_QUERY_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"statusId"[[:space:]]*:[[:space:]]*"status-live-smoke-1"' \
    '"validatorId"[[:space:]]*:[[:space:]]*"val-live-smoke-elig-1"'

  # Governance canonicalization compatibility (write mixed-case/whitespace, query mixed-case).
  assert_grpc_call_patterns "${PORT}" "tdpn.vpngovernance.v1.Msg/CreatePolicy" "${GOVERNANCE_POLICY_CREATE_PAYLOAD}" \
    '"policy"[[:space:]]*:' \
    '"policyId"[[:space:]]*:[[:space:]]*"gov-live-smoke-policy-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpngovernance.v1.Query/GovernancePolicy" "${GOVERNANCE_POLICY_QUERY_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"policyId"[[:space:]]*:[[:space:]]*"gov-live-smoke-policy-1"'

  assert_grpc_call_patterns "${PORT}" "tdpn.vpngovernance.v1.Msg/RecordDecision" "${GOVERNANCE_DECISION_RECORD_PAYLOAD}" \
    '"decision"[[:space:]]*:' \
    '"decisionId"[[:space:]]*:[[:space:]]*"gov-live-smoke-decision-1"' \
    '"policyId"[[:space:]]*:[[:space:]]*"gov-live-smoke-policy-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpngovernance.v1.Query/GovernanceDecision" "${GOVERNANCE_DECISION_QUERY_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"decisionId"[[:space:]]*:[[:space:]]*"gov-live-smoke-decision-1"' \
    '"policyId"[[:space:]]*:[[:space:]]*"gov-live-smoke-policy-1"'

  assert_grpc_call_patterns "${PORT}" "tdpn.vpngovernance.v1.Msg/RecordAuditAction" "${GOVERNANCE_AUDIT_ACTION_RECORD_PAYLOAD}" \
    '"action"[[:space:]]*:' \
    '"actionId"[[:space:]]*:[[:space:]]*"gov-live-smoke-action-1"' \
    '"actor"[[:space:]]*:[[:space:]]*"gov-actor-live-1"'
  assert_grpc_call_patterns "${PORT}" "tdpn.vpngovernance.v1.Query/GovernanceAuditAction" "${GOVERNANCE_AUDIT_ACTION_QUERY_PAYLOAD}" \
    '"found"[[:space:]]*:[[:space:]]*true' \
    '"actionId"[[:space:]]*:[[:space:]]*"gov-live-smoke-action-1"' \
    '"actor"[[:space:]]*:[[:space:]]*"gov-actor-live-1"'
else
  :
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

echo "cosmos tdpnd grpc live smoke integration check ok"
