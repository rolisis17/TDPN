#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

CAMPAIGN_SCRIPT="${PROFILE_COMPARE_CAMPAIGN_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign.sh}"
CAMPAIGN_CHECK_SCRIPT="${PROFILE_COMPARE_CAMPAIGN_CHECK_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_campaign_signoff.sh \
    [--reports-dir DIR] \
    [--campaign-summary-json PATH] \
    [--campaign-report-md PATH] \
    [--campaign-check-summary-json PATH] \
    [--refresh-campaign [0|1]] \
    [--fail-on-no-go [0|1]] \
    [--allow-concurrent [0|1]] \
    [--allow-summary-overwrite [0|1]] \
    [--require-status-pass [0|1]] \
    [--require-trend-status-pass [0|1]] \
    [--require-min-runs-total N] \
    [--require-max-runs-fail N] \
    [--require-max-runs-warn N] \
    [--require-min-runs-with-summary N] \
    [--require-recommendation-support-rate-pct N] \
    [--require-recommended-profile PROFILE] \
    [--allow-recommended-profiles CSV] \
    [--disallow-experimental-default [0|1]] \
    [--require-trend-source CSV] \
    [--require-selection-policy-present [0|1]] \
    [--require-selection-policy-valid [0|1]] \
    [--require-micro-relay-quality-evidence [0|1]] \
    [--require-micro-relay-quality-status-pass [0|1]] \
    [--require-micro-relay-demotion-policy [0|1]] \
    [--require-micro-relay-promotion-policy [0|1]] \
    [--require-trust-tier-port-unlock-policy [0|1]] \
    [--campaign-execution-mode docker|local] \
    [--campaign-directory-urls URL[,URL...]] \
    [--campaign-bootstrap-directory URL] \
    [--campaign-discovery-wait-sec N] \
    [--campaign-issuer-url URL] \
    [--campaign-entry-url URL] \
    [--campaign-exit-url URL] \
    [--campaign-subject ID | --campaign-anon-cred TOKEN] \
    [--subject ID | --key ID | --invite-key ID | --anon-cred TOKEN] \
    [--campaign-start-local-stack auto|0|1] \
    [--campaign-timeout-sec N] \
    [--campaign-endpoint-preflight-timeout-sec N] \
    [--allow-insecure-probe [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Run optional profile-compare campaign refresh and then apply the
  fail-closed campaign check gate in one command, writing one signoff
  summary artifact for handoff.

Notes:
  - Default behavior refreshes campaign artifacts first (--refresh-campaign 1).
  - Reuse of an existing campaign summary happens only when refresh is disabled
    (--refresh-campaign 0).
  - --subject is a legacy alias of --campaign-subject.
  - --key and --invite-key are aliases of --campaign-subject.
  - --anon-cred remains an alias of --campaign-anon-cred.
  - Subject/anon alias flags accept both `--flag value` and `--flag=value`.
  - In invite-key workflows, prefer --campaign-subject (or --subject/--key/
    --invite-key) with an actual invite key value instead of placeholder text.
  - If no subject flag is provided, subject falls back to env:
    CAMPAIGN_SUBJECT (preferred) then INVITE_KEY.
  - Single-instance lock is enabled by default per reports-dir; bypass only when
    intentionally running concurrent signoff with --allow-concurrent 1 (or
    PROFILE_COMPARE_CAMPAIGN_SIGNOFF_ALLOW_CONCURRENT=1).
  - Signoff emits periodic heartbeat lines while campaign refresh is running.
  - --campaign-timeout-sec defaults to 0 (disabled / preserve existing behavior).
  - --campaign-endpoint-preflight-timeout-sec defaults to 4s per remote endpoint;
    set to 0 to disable preflight and preserve legacy refresh behavior.
  - TLS verification is on by default for endpoint preflight probes; pass
    --allow-insecure-probe 1 only for local self-signed setups.
  - When refresh inputs point at remote/bootstrap endpoints, the signoff step
    prefers a docker-style refresh to avoid local root-only bootstrap failures.
  - Remote endpoint preflight fail-closes campaign stage before refresh command
    execution and emits endpoint-unreachable synthetic diagnostics.
  - Keep --allow-summary-overwrite 0 in normal operation to avoid output
    path collisions across campaign/check/signoff artifacts.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

invite_subject_looks_placeholder_01() {
  local value normalized
  value="$(trim "${1:-}")"
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$normalized" in
    INVITE_KEY|\$\{INVITE_KEY\}|\$INVITE_KEY|"<INVITE_KEY>"|"{{INVITE_KEY}}"|YOUR_INVITE_KEY|REPLACE_WITH_INVITE_KEY)
      return 0
      ;;
  esac
  return 1
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

optional_bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ -z "$value" ]]; then
    return
  fi
  bool_arg_or_die "$name" "$value"
}

is_non_negative_decimal() {
  local value="$1"
  [[ "$value" =~ ^[0-9]+([.][0-9]+)?$ ]]
}

read_lock_metadata_field() {
  local file_path="$1"
  local field_name="$2"
  if [[ ! -f "$file_path" ]]; then
    printf '%s' ""
    return
  fi
  awk -F= -v key="$field_name" '$1 == key {print substr($0, index($0, "=") + 1); exit}' "$file_path"
}

pid_is_running() {
  local pid="${1:-}"
  if [[ ! "$pid" =~ ^[0-9]+$ ]]; then
    return 1
  fi
  if kill -0 "$pid" >/dev/null 2>&1; then
    return 0
  fi
  if [[ -d "/proc/$pid" ]]; then
    return 0
  fi
  return 1
}

detect_local_stack_block_reason() {
  local log_path="$1"
  local reason=""

  if [[ -f "$log_path" ]]; then
    if grep -Eqi -- '--start-local-stack=1 requires root|requires root \(run with sudo\)' "$log_path"; then
      reason="local stack requires root"
    elif grep -Eqi -- 'permission denied|operation not permitted' "$log_path"; then
      reason="local stack permission denied"
    elif grep -Eqi -- 'failed to start local wg-only stack' "$log_path"; then
      reason="local wg-only stack unavailable"
    elif grep -Eqi -- 'profile-compare-campaign: no valid compare summaries were produced' "$log_path" && [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
      reason="local mode produced no summaries on non-root host"
    fi
  fi

  printf '%s' "$reason"
}

quote_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

redact_sensitive_cmd_line() {
  local line="$1"
  line="$(printf '%s' "$line" | sed -E 's/(--campaign-subject )[^ ]+/\1[redacted]/g; s/(--subject )[^ ]+/\1[redacted]/g; s/(--key )[^ ]+/\1[redacted]/g; s/(--invite-key )[^ ]+/\1[redacted]/g; s/(--campaign-anon-cred )[^ ]+/\1[redacted]/g; s/(--anon-cred )[^ ]+/\1[redacted]/g; s/(--token )[^ ]+/\1[redacted]/g; s/(--auth-token )[^ ]+/\1[redacted]/g; s/(--admin-token )[^ ]+/\1[redacted]/g; s/(--authorization )[^ ]+/\1[redacted]/g; s/(--bearer )[^ ]+/\1[redacted]/g; s/(--campaign-subject=)[^ ]+/\1[redacted]/g; s/(--subject=)[^ ]+/\1[redacted]/g; s/(--key=)[^ ]+/\1[redacted]/g; s/(--invite-key=)[^ ]+/\1[redacted]/g; s/(--campaign-anon-cred=)[^ ]+/\1[redacted]/g; s/(--anon-cred=)[^ ]+/\1[redacted]/g; s/(--token=)[^ ]+/\1[redacted]/g; s/(--auth-token=)[^ ]+/\1[redacted]/g; s/(--admin-token=)[^ ]+/\1[redacted]/g; s/(--authorization=)[^ ]+/\1[redacted]/g; s/(--bearer=)[^ ]+/\1[redacted]/g')"
  printf '%s' "$line"
}

json_endpoint_records_from_lines() {
  if [[ $# -eq 0 ]]; then
    printf '%s' "[]"
    return
  fi
  printf '%s\n' "$@" | jq -R 'select(length > 0) | split("\t") | {
    label: .[0],
    url: .[1],
    host: (if ((.[2] // "") == "") then null else .[2] end)
  }' | jq -s .
}

json_endpoint_failures_from_lines() {
  if [[ $# -eq 0 ]]; then
    printf '%s' "[]"
    return
  fi
  printf '%s\n' "$@" | jq -R 'select(length > 0) | split("\t") | {
    label: .[0],
    url: .[1],
    host: (if ((.[2] // "") == "") then null else .[2] end),
    error: (if ((.[3] // "") == "") then null else .[3] end)
  }' | jq -s .
}

extract_url_host() {
  local url="$1"
  local remainder host_port host=""

  if [[ ! "$url" =~ ^https?:// ]]; then
    printf '%s' ""
    return
  fi

  remainder="${url#*://}"
  remainder="${remainder%%/*}"
  host_port="${remainder##*@}"

  if [[ "$host_port" == \[* ]]; then
    if [[ "$host_port" =~ ^(\[[^]]+\]) ]]; then
      host="${BASH_REMATCH[1]}"
    else
      host="$host_port"
    fi
  else
    host="${host_port%%:*}"
  fi

  printf '%s' "$host"
}

ip_literal_is_loopback() {
  local normalized
  normalized="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  normalized="${normalized#[}"
  normalized="${normalized%]}"
  case "$normalized" in
    "::1"|::ffff:127.*)
      return 0
      ;;
  esac
  if [[ "$normalized" == 127.* ]]; then
    return 0
  fi
  return 1
}

host_resolves_to_loopback_only() {
  local normalized host_ips ip resolved_any
  normalized="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')"
  normalized="${normalized#[}"
  normalized="${normalized%]}"
  case "$normalized" in
    ""|localhost|ip6-localhost|::1|127.*|::|0.0.0.0)
      return 0
      ;;
  esac
  if ip_literal_is_loopback "$normalized"; then
    return 0
  fi
  if ! command -v getent >/dev/null 2>&1; then
    return 1
  fi
  host_ips="$(getent ahosts "$normalized" 2>/dev/null | awk '{print $1}' | sort -u || true)"
  if [[ -z "$host_ips" ]]; then
    return 1
  fi
  resolved_any=0
  while IFS= read -r ip; do
    ip="$(printf '%s' "$ip" | tr '[:upper:]' '[:lower:]')"
    if [[ -z "$ip" ]]; then
      continue
    fi
    resolved_any=1
    if ! ip_literal_is_loopback "$ip"; then
      return 1
    fi
  done <<<"$host_ips"
  if [[ "$resolved_any" -ne 1 ]]; then
    return 1
  fi
  return 0
}

is_local_host() {
  host_resolves_to_loopback_only "${1:-}"
}

run_campaign_endpoint_preflight() {
  local log_path="$1"
  local -a candidate_records=()
  local -a remote_records=()
  local -a failed_records=()
  local -a directory_urls=()
  local label endpoint endpoint_url host rc err_file err_text idx

  campaign_preflight_attempted="0"
  campaign_preflight_status="skip"
  campaign_preflight_skipped_reason=""
  campaign_preflight_failure_reason=""
  campaign_preflight_total_endpoints="0"
  campaign_preflight_remote_endpoints="0"
  campaign_preflight_failed_count="0"
  campaign_preflight_candidate_endpoints_json='[]'
  campaign_preflight_remote_endpoints_json='[]'
  campaign_preflight_failed_endpoints_json='[]'

  : >"$log_path"

  add_candidate_endpoint() {
    local endpoint_label="$1"
    local endpoint_url
    endpoint_url="$(trim "${2:-}")"
    if [[ -z "$endpoint_url" ]]; then
      return
    fi
    if [[ ! "$endpoint_url" =~ ^https?:// ]]; then
      return
    fi
    local endpoint_host
    endpoint_host="$(extract_url_host "$endpoint_url")"
    candidate_records+=("${endpoint_label}"$'\t'"${endpoint_url}"$'\t'"${endpoint_host}")
  }

  if [[ -n "$campaign_directory_urls_effective" ]]; then
    IFS=',' read -r -a directory_urls <<<"$campaign_directory_urls_effective"
    idx=0
    for endpoint in "${directory_urls[@]}"; do
      add_candidate_endpoint "directory[$idx]" "$endpoint"
      idx=$((idx + 1))
    done
  fi
  add_candidate_endpoint "bootstrap" "$campaign_bootstrap_directory_effective"
  add_candidate_endpoint "issuer" "$campaign_issuer_url_effective"
  add_candidate_endpoint "entry" "$campaign_entry_url_effective"
  add_candidate_endpoint "exit" "$campaign_exit_url_effective"

  campaign_preflight_total_endpoints="${#candidate_records[@]}"
  campaign_preflight_candidate_endpoints_json="$(json_endpoint_records_from_lines "${candidate_records[@]}")"

  if [[ "${#candidate_records[@]}" -eq 0 ]]; then
    campaign_preflight_status="skip"
    campaign_preflight_skipped_reason="no http endpoints configured"
    return 0
  fi

  for endpoint in "${candidate_records[@]}"; do
    IFS=$'\t' read -r label endpoint_url host <<<"$endpoint"
    if ! is_local_host "$host"; then
      remote_records+=("$endpoint")
    fi
  done

  campaign_preflight_remote_endpoints="${#remote_records[@]}"
  campaign_preflight_remote_endpoints_json="$(json_endpoint_records_from_lines "${remote_records[@]}")"

  if [[ "${#remote_records[@]}" -eq 0 ]]; then
    campaign_preflight_status="skip"
    campaign_preflight_skipped_reason="no remote http endpoints configured"
    return 0
  fi

  if [[ "$allow_insecure_probe" == "1" ]]; then
    for endpoint in "${remote_records[@]}"; do
      IFS=$'\t' read -r label endpoint_url host <<<"$endpoint"
      failed_records+=("${label}"$'\t'"${endpoint_url}"$'\t'"${host}"$'\t'"--allow-insecure-probe=1 is only permitted for local loopback endpoints")
    done
    campaign_preflight_status="fail"
    campaign_preflight_failed_count="${#failed_records[@]}"
    campaign_preflight_failure_reason="--allow-insecure-probe=1 is not allowed for remote endpoints"
    campaign_preflight_failed_endpoints_json="$(json_endpoint_failures_from_lines "${failed_records[@]}")"
    printf '[profile-compare-campaign-signoff] %s campaign endpoint preflight failed reason=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$campaign_preflight_failure_reason" >>"$log_path"
    return 2
  fi

  campaign_preflight_attempted="1"

  if ! command -v curl >/dev/null 2>&1; then
    campaign_preflight_status="fail"
    campaign_preflight_failed_count="1"
    campaign_preflight_failure_reason="endpoint preflight failed: curl command not available"
    campaign_preflight_failed_endpoints_json='[{"label":"runtime","url":null,"host":null,"error":"curl command not available"}]'
    printf '[profile-compare-campaign-signoff] %s campaign endpoint preflight failed reason=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$campaign_preflight_failure_reason" >>"$log_path"
    return 127
  fi

  for endpoint in "${remote_records[@]}"; do
    IFS=$'\t' read -r label endpoint_url host <<<"$endpoint"
    printf '[profile-compare-campaign-signoff] %s campaign endpoint preflight checking label=%s url=%s timeout_sec=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$label" \
      "$endpoint_url" \
      "$campaign_endpoint_preflight_timeout_sec" >>"$log_path"
    err_file="$(mktemp "$log_dir/profile_compare_campaign_signoff_${run_stamp}_preflight_err.XXXXXX")"
    local -a curl_opts=(--silent --show-error --fail --noproxy '*' --connect-timeout "$campaign_endpoint_preflight_timeout_sec" --max-time "$campaign_endpoint_preflight_timeout_sec" --output /dev/null)
    if [[ "$allow_insecure_probe" == "1" ]]; then
      curl_opts+=(--insecure)
    fi
    if curl "${curl_opts[@]}" "$endpoint_url" > /dev/null 2>"$err_file"; then
      printf '[profile-compare-campaign-signoff] %s campaign endpoint preflight pass label=%s url=%s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "$label" \
        "$endpoint_url" >>"$log_path"
      rm -f "$err_file"
      continue
    else
      rc=$?
    fi

    err_text="$(tr '\n' ' ' <"$err_file" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
    rm -f "$err_file"
    if [[ -z "$err_text" ]]; then
      err_text="curl rc=$rc"
    else
      err_text="curl rc=$rc: $err_text"
    fi
    failed_records+=("${label}"$'\t'"${endpoint_url}"$'\t'"${host}"$'\t'"${err_text}")
    campaign_preflight_status="fail"
    campaign_preflight_failed_count="${#failed_records[@]}"
    campaign_preflight_failed_endpoints_json="$(json_endpoint_failures_from_lines "${failed_records[@]}")"
    campaign_preflight_failure_reason="endpoint preflight failed for ${label} (${endpoint_url}): ${err_text}"
    printf '[profile-compare-campaign-signoff] %s campaign endpoint preflight fail label=%s url=%s error=%s\n' \
      "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      "$label" \
      "$endpoint_url" \
      "$err_text" >>"$log_path"
    return "$rc"
  done

  campaign_preflight_status="pass"
  campaign_preflight_failed_count="0"
  campaign_preflight_failed_endpoints_json='[]'
  return 0
}

run_campaign_refresh_monitored() {
  local attempt_label="$1"
  local log_path="$2"
  shift 2
  local -a cmd=("$@")
  local start_sec now_sec elapsed_sec next_heartbeat_sec
  local heartbeat_count_local=0
  local timeout_triggered_local=0
  local pid=""
  local cmd_rc=0

  campaign_timeout_triggered="0"
  campaign_duration_sec="0"
  campaign_failure_reason=""
  campaign_heartbeat_count="0"

  echo "[profile-compare-campaign-signoff] $(date -u +%Y-%m-%dT%H:%M:%SZ) campaign refresh started attempt=$attempt_label timeout_sec=$campaign_timeout_sec log=$log_path"
  "${cmd[@]}" >"$log_path" 2>&1 &
  pid=$!
  start_sec="$(date +%s)"
  next_heartbeat_sec=$((start_sec + campaign_heartbeat_interval_sec))

  while kill -0 "$pid" >/dev/null 2>&1; do
    sleep 1
    now_sec="$(date +%s)"
    elapsed_sec=$((now_sec - start_sec))

    if (( now_sec >= next_heartbeat_sec )); then
      heartbeat_count_local=$((heartbeat_count_local + 1))
      echo "[profile-compare-campaign-signoff] $(date -u +%Y-%m-%dT%H:%M:%SZ) campaign refresh heartbeat attempt=$attempt_label elapsed_sec=$elapsed_sec timeout_sec=$campaign_timeout_sec log=$log_path"
      next_heartbeat_sec=$((now_sec + campaign_heartbeat_interval_sec))
    fi

    if (( campaign_timeout_sec > 0 && elapsed_sec >= campaign_timeout_sec )); then
      timeout_triggered_local=1
      campaign_timeout_triggered="1"
      campaign_failure_reason="campaign refresh timed out after ${campaign_timeout_sec}s (attempt=${attempt_label})"
      echo "[profile-compare-campaign-signoff] $(date -u +%Y-%m-%dT%H:%M:%SZ) campaign refresh timeout attempt=$attempt_label elapsed_sec=$elapsed_sec timeout_sec=$campaign_timeout_sec log=$log_path"
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
      break
    fi
  done

  if [[ "$timeout_triggered_local" == "1" ]]; then
    wait "$pid" >/dev/null 2>&1 || true
    campaign_duration_sec=$(( $(date +%s) - start_sec ))
    campaign_heartbeat_count="$heartbeat_count_local"
    return 124
  fi

  if wait "$pid"; then
    cmd_rc=0
  else
    cmd_rc=$?
  fi

  campaign_duration_sec=$(( $(date +%s) - start_sec ))
  campaign_heartbeat_count="$heartbeat_count_local"

  if [[ "$cmd_rc" == "0" ]]; then
    echo "[profile-compare-campaign-signoff] $(date -u +%Y-%m-%dT%H:%M:%SZ) campaign refresh completed attempt=$attempt_label duration_sec=$campaign_duration_sec heartbeats=$campaign_heartbeat_count log=$log_path"
  else
    campaign_failure_reason="campaign refresh command failed rc=$cmd_rc (attempt=${attempt_label})"
    echo "[profile-compare-campaign-signoff] $(date -u +%Y-%m-%dT%H:%M:%SZ) campaign refresh failed attempt=$attempt_label rc=$cmd_rc duration_sec=$campaign_duration_sec heartbeats=$campaign_heartbeat_count log=$log_path"
  fi

  return "$cmd_rc"
}

need_cmd jq
need_cmd date
need_cmd mktemp
need_cmd sed

reports_dir="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
campaign_summary_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_SUMMARY_JSON:-}"
campaign_report_md="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_REPORT_MD:-}"
campaign_check_summary_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_CHECK_SUMMARY_JSON:-}"
refresh_campaign="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REFRESH_CAMPAIGN:-1}"
fail_on_no_go="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_FAIL_ON_NO_GO:-1}"
allow_concurrent="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_ALLOW_CONCURRENT:-0}"
allow_summary_overwrite="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_ALLOW_SUMMARY_OVERWRITE:-0}"
summary_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SUMMARY_JSON:-}"
show_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SHOW_JSON:-0}"
print_summary_json="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_PRINT_SUMMARY_JSON:-0}"
campaign_timeout_sec="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC:-0}"
campaign_heartbeat_interval_sec="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_HEARTBEAT_INTERVAL_SEC:-15}"
campaign_endpoint_preflight_timeout_sec="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_ENDPOINT_PREFLIGHT_TIMEOUT_SEC:-4}"
allow_insecure_probe="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_ALLOW_INSECURE_PROBE:-0}"

require_status_pass="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_STATUS_PASS:-}"
require_trend_status_pass="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_TREND_STATUS_PASS:-}"
require_min_runs_total="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MIN_RUNS_TOTAL:-}"
require_max_runs_fail="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MAX_RUNS_FAIL:-}"
require_max_runs_warn="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MAX_RUNS_WARN:-}"
require_min_runs_with_summary="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MIN_RUNS_WITH_SUMMARY:-}"
require_recommendation_support_rate_pct="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_RECOMMENDATION_SUPPORT_RATE_PCT:-}"
require_recommended_profile="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_RECOMMENDED_PROFILE:-}"
allow_recommended_profiles="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_ALLOW_RECOMMENDED_PROFILES:-}"
disallow_experimental_default="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_DISALLOW_EXPERIMENTAL_DEFAULT:-}"
require_trend_source="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_TREND_SOURCE:-}"
require_selection_policy_present="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_SELECTION_POLICY_PRESENT:-}"
require_selection_policy_valid="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_SELECTION_POLICY_VALID:-}"
require_micro_relay_quality_evidence="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MICRO_RELAY_QUALITY_EVIDENCE:-}"
require_micro_relay_quality_status_pass="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MICRO_RELAY_QUALITY_STATUS_PASS:-}"
require_micro_relay_demotion_policy="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MICRO_RELAY_DEMOTION_POLICY:-}"
require_micro_relay_promotion_policy="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_MICRO_RELAY_PROMOTION_POLICY:-}"
require_trust_tier_port_unlock_policy="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REQUIRE_TRUST_TIER_PORT_UNLOCK_POLICY:-}"
campaign_execution_mode="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_EXECUTION_MODE:-}"
campaign_directory_urls="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_DIRECTORY_URLS:-}"
campaign_bootstrap_directory="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_BOOTSTRAP_DIRECTORY:-}"
campaign_discovery_wait_sec="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_DISCOVERY_WAIT_SEC:-}"
campaign_issuer_url="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_ISSUER_URL:-}"
campaign_entry_url="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_ENTRY_URL:-}"
campaign_exit_url="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_EXIT_URL:-}"
campaign_subject="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_SUBJECT:-}"
campaign_anon_cred="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_ANON_CRED:-}"
subject_alias=""
subject_alias_flag=""
anon_cred_alias=""
campaign_subject_cli_provided="0"
campaign_subject_source=""
campaign_start_local_stack="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_START_LOCAL_STACK:-}"
original_args=("$@")

set_subject_alias_or_die() {
  local alias_flag="$1"
  local alias_value="$2"

  alias_value="$(trim "$alias_value")"
  if [[ -z "$alias_value" ]]; then
    echo "$alias_flag requires a non-empty value"
    exit 2
  fi

  if [[ -z "$subject_alias_flag" ]]; then
    subject_alias="$alias_value"
    subject_alias_flag="$alias_flag"
    return
  fi
  if [[ "$subject_alias" != "$alias_value" ]]; then
    echo "conflicting subject values: $subject_alias_flag and $alias_flag must match when both are provided"
    exit 2
  fi
}

require_flag_value_or_die() {
  local flag="$1"
  local value="${2:-}"

  if [[ -z "$value" || "$value" == --* ]]; then
    echo "$flag requires a value"
    exit 2
  fi
}

require_non_empty_value_or_die() {
  local flag="$1"
  local value="${2:-}"

  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    echo "$flag requires a non-empty value"
    exit 2
  fi
  printf '%s' "$value"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --campaign-summary-json)
      campaign_summary_json="${2:-}"
      shift 2
      ;;
    --campaign-report-md)
      campaign_report_md="${2:-}"
      shift 2
      ;;
    --campaign-check-summary-json)
      campaign_check_summary_json="${2:-}"
      shift 2
      ;;
    --refresh-campaign)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_campaign="${2:-}"
        shift 2
      else
        refresh_campaign="1"
        shift
      fi
      ;;
    --fail-on-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_no_go="${2:-}"
        shift 2
      else
        fail_on_no_go="1"
        shift
      fi
      ;;
    --allow-concurrent)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_concurrent="${2:-}"
        shift 2
      else
        allow_concurrent="1"
        shift
      fi
      ;;
    --allow-summary-overwrite)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_summary_overwrite="${2:-}"
        shift 2
      else
        allow_summary_overwrite="1"
        shift
      fi
      ;;
    --require-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_status_pass="${2:-}"
        shift 2
      else
        require_status_pass="1"
        shift
      fi
      ;;
    --require-trend-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trend_status_pass="${2:-}"
        shift 2
      else
        require_trend_status_pass="1"
        shift
      fi
      ;;
    --require-min-runs-total)
      require_min_runs_total="${2:-}"
      shift 2
      ;;
    --require-max-runs-fail)
      require_max_runs_fail="${2:-}"
      shift 2
      ;;
    --require-max-runs-warn)
      require_max_runs_warn="${2:-}"
      shift 2
      ;;
    --require-min-runs-with-summary)
      require_min_runs_with_summary="${2:-}"
      shift 2
      ;;
    --require-recommendation-support-rate-pct)
      require_recommendation_support_rate_pct="${2:-}"
      shift 2
      ;;
    --require-recommended-profile)
      require_recommended_profile="${2:-}"
      shift 2
      ;;
    --allow-recommended-profiles)
      allow_recommended_profiles="${2:-}"
      shift 2
      ;;
    --disallow-experimental-default)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        disallow_experimental_default="${2:-}"
        shift 2
      else
        disallow_experimental_default="1"
        shift
      fi
      ;;
    --require-trend-source)
      require_trend_source="${2:-}"
      shift 2
      ;;
    --require-selection-policy-present)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_present="${2:-}"
        shift 2
      else
        require_selection_policy_present="1"
        shift
      fi
      ;;
    --require-selection-policy-valid)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_selection_policy_valid="${2:-}"
        shift 2
      else
        require_selection_policy_valid="1"
        shift
      fi
      ;;
    --require-micro-relay-quality-evidence)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_micro_relay_quality_evidence="${2:-}"
        shift 2
      else
        require_micro_relay_quality_evidence="1"
        shift
      fi
      ;;
    --require-micro-relay-quality-status-pass)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_micro_relay_quality_status_pass="${2:-}"
        shift 2
      else
        require_micro_relay_quality_status_pass="1"
        shift
      fi
      ;;
    --require-micro-relay-demotion-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_micro_relay_demotion_policy="${2:-}"
        shift 2
      else
        require_micro_relay_demotion_policy="1"
        shift
      fi
      ;;
    --require-micro-relay-promotion-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_micro_relay_promotion_policy="${2:-}"
        shift 2
      else
        require_micro_relay_promotion_policy="1"
        shift
      fi
      ;;
    --require-trust-tier-port-unlock-policy)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_trust_tier_port_unlock_policy="${2:-}"
        shift 2
      else
        require_trust_tier_port_unlock_policy="1"
        shift
      fi
      ;;
    --campaign-execution-mode)
      campaign_execution_mode="${2:-}"
      shift 2
      ;;
    --campaign-directory-urls)
      campaign_directory_urls="${2:-}"
      shift 2
      ;;
    --campaign-bootstrap-directory)
      campaign_bootstrap_directory="${2:-}"
      shift 2
      ;;
    --campaign-discovery-wait-sec)
      campaign_discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --campaign-issuer-url)
      campaign_issuer_url="${2:-}"
      shift 2
      ;;
    --campaign-entry-url)
      campaign_entry_url="${2:-}"
      shift 2
      ;;
    --campaign-exit-url)
      campaign_exit_url="${2:-}"
      shift 2
      ;;
    --campaign-subject)
      require_flag_value_or_die "$1" "${2:-}"
      campaign_subject="$(require_non_empty_value_or_die "$1" "${2:-}")"
      campaign_subject_cli_provided="1"
      shift 2
      ;;
    --campaign-subject=*)
      campaign_subject="$(require_non_empty_value_or_die "--campaign-subject" "${1#--campaign-subject=}")"
      campaign_subject_cli_provided="1"
      shift
      ;;
    --campaign-anon-cred)
      require_flag_value_or_die "$1" "${2:-}"
      campaign_anon_cred="$(require_non_empty_value_or_die "$1" "${2:-}")"
      shift 2
      ;;
    --campaign-anon-cred=*)
      campaign_anon_cred="$(require_non_empty_value_or_die "--campaign-anon-cred" "${1#--campaign-anon-cred=}")"
      shift
      ;;
    --subject)
      require_flag_value_or_die "$1" "${2:-}"
      set_subject_alias_or_die "--subject" "${2:-}"
      campaign_subject_cli_provided="1"
      shift 2
      ;;
    --subject=*)
      set_subject_alias_or_die "--subject" "${1#--subject=}"
      campaign_subject_cli_provided="1"
      shift
      ;;
    --key)
      require_flag_value_or_die "$1" "${2:-}"
      set_subject_alias_or_die "--key" "${2:-}"
      campaign_subject_cli_provided="1"
      shift 2
      ;;
    --key=*)
      set_subject_alias_or_die "--key" "${1#--key=}"
      campaign_subject_cli_provided="1"
      shift
      ;;
    --invite-key)
      require_flag_value_or_die "$1" "${2:-}"
      set_subject_alias_or_die "--invite-key" "${2:-}"
      campaign_subject_cli_provided="1"
      shift 2
      ;;
    --invite-key=*)
      set_subject_alias_or_die "--invite-key" "${1#--invite-key=}"
      campaign_subject_cli_provided="1"
      shift
      ;;
    --anon-cred)
      require_flag_value_or_die "$1" "${2:-}"
      anon_cred_alias="$(require_non_empty_value_or_die "$1" "${2:-}")"
      shift 2
      ;;
    --anon-cred=*)
      anon_cred_alias="$(require_non_empty_value_or_die "--anon-cred" "${1#--anon-cred=}")"
      shift
      ;;
    --campaign-start-local-stack)
      campaign_start_local_stack="${2:-}"
      shift 2
      ;;
    --campaign-timeout-sec)
      campaign_timeout_sec="${2:-}"
      shift 2
      ;;
    --campaign-endpoint-preflight-timeout-sec)
      campaign_endpoint_preflight_timeout_sec="${2:-}"
      shift 2
      ;;
    --allow-insecure-probe)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_insecure_probe="${2:-}"
        shift 2
      else
        allow_insecure_probe="1"
        shift
      fi
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_json="${2:-}"
        shift 2
      else
        show_json="1"
        shift
      fi
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--refresh-campaign" "$refresh_campaign"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--allow-concurrent" "$allow_concurrent"
bool_arg_or_die "--allow-summary-overwrite" "$allow_summary_overwrite"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

optional_bool_arg_or_die "--require-status-pass" "$require_status_pass"
optional_bool_arg_or_die "--require-trend-status-pass" "$require_trend_status_pass"
optional_bool_arg_or_die "--disallow-experimental-default" "$disallow_experimental_default"
optional_bool_arg_or_die "--require-selection-policy-present" "$require_selection_policy_present"
optional_bool_arg_or_die "--require-selection-policy-valid" "$require_selection_policy_valid"
optional_bool_arg_or_die "--require-micro-relay-quality-evidence" "$require_micro_relay_quality_evidence"
optional_bool_arg_or_die "--require-micro-relay-quality-status-pass" "$require_micro_relay_quality_status_pass"
optional_bool_arg_or_die "--require-micro-relay-demotion-policy" "$require_micro_relay_demotion_policy"
optional_bool_arg_or_die "--require-micro-relay-promotion-policy" "$require_micro_relay_promotion_policy"
optional_bool_arg_or_die "--require-trust-tier-port-unlock-policy" "$require_trust_tier_port_unlock_policy"

for int_arg in "$require_min_runs_total" "$require_max_runs_fail" "$require_max_runs_warn" "$require_min_runs_with_summary"; do
  if [[ -n "$int_arg" && ! "$int_arg" =~ ^[0-9]+$ ]]; then
    echo "run count thresholds must be non-negative integers"
    exit 2
  fi
done
if [[ -n "$require_recommendation_support_rate_pct" ]] && ! is_non_negative_decimal "$require_recommendation_support_rate_pct"; then
  echo "--require-recommendation-support-rate-pct must be a non-negative number"
  exit 2
fi
if [[ -n "$campaign_execution_mode" && "$campaign_execution_mode" != "docker" && "$campaign_execution_mode" != "local" ]]; then
  echo "--campaign-execution-mode must be docker or local"
  exit 2
fi
if [[ -n "$campaign_discovery_wait_sec" && ! "$campaign_discovery_wait_sec" =~ ^[0-9]+$ ]]; then
  echo "--campaign-discovery-wait-sec must be an integer"
  exit 2
fi
if [[ -n "$campaign_timeout_sec" && ! "$campaign_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--campaign-timeout-sec must be a non-negative integer"
  exit 2
fi
if [[ -n "$campaign_endpoint_preflight_timeout_sec" && ! "$campaign_endpoint_preflight_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--campaign-endpoint-preflight-timeout-sec must be a non-negative integer"
  exit 2
fi
bool_arg_or_die "--allow-insecure-probe" "$allow_insecure_probe"
if [[ -n "$campaign_heartbeat_interval_sec" && ! "$campaign_heartbeat_interval_sec" =~ ^[0-9]+$ ]]; then
  echo "PROFILE_COMPARE_CAMPAIGN_SIGNOFF_HEARTBEAT_INTERVAL_SEC must be a positive integer"
  exit 2
fi
if (( campaign_heartbeat_interval_sec < 1 )); then
  echo "PROFILE_COMPARE_CAMPAIGN_SIGNOFF_HEARTBEAT_INTERVAL_SEC must be >= 1"
  exit 2
fi
if [[ -n "$campaign_start_local_stack" ]]; then
  case "$campaign_start_local_stack" in
    auto|0|1) ;;
    *)
      echo "--campaign-start-local-stack must be one of: auto, 0, 1"
      exit 2
      ;;
  esac
fi
if [[ -n "$subject_alias" && -n "$campaign_subject" && "$subject_alias" != "$campaign_subject" ]]; then
  if [[ "$subject_alias_flag" == "--subject" ]]; then
    echo "conflicting subject values: --subject and --campaign-subject must match when both are provided"
  else
    echo "conflicting subject values: ${subject_alias_flag:---subject} and --campaign-subject must match when both are provided"
  fi
  exit 2
fi
if [[ -n "$anon_cred_alias" && -n "$campaign_anon_cred" && "$anon_cred_alias" != "$campaign_anon_cred" ]]; then
  echo "conflicting anon credential values: --anon-cred and --campaign-anon-cred must match when both are provided"
  exit 2
fi
if [[ -n "$subject_alias" ]]; then
  campaign_subject="$subject_alias"
fi
if [[ -n "$anon_cred_alias" ]]; then
  campaign_anon_cred="$anon_cred_alias"
fi
if [[ -z "$campaign_subject" && -z "$campaign_anon_cred" && "$campaign_subject_cli_provided" != "1" ]]; then
  if [[ -n "${CAMPAIGN_SUBJECT:-}" ]]; then
    campaign_subject="$(trim "${CAMPAIGN_SUBJECT:-}")"
    if [[ -n "$campaign_subject" ]]; then
      campaign_subject_source="env:CAMPAIGN_SUBJECT"
    fi
  elif [[ -n "${INVITE_KEY:-}" ]]; then
    campaign_subject="$(trim "${INVITE_KEY:-}")"
    if [[ -n "$campaign_subject" ]]; then
      campaign_subject_source="env:INVITE_KEY"
    fi
  fi
fi
if [[ -n "$campaign_subject" && -z "$campaign_subject_source" ]]; then
  campaign_subject_source="explicit"
fi
if [[ -n "$campaign_subject" ]] && invite_subject_looks_placeholder_01 "$campaign_subject"; then
  echo "[profile-compare-campaign-signoff] failure_kind=missing_invite_subject_precondition reason=placeholder_subject"
  echo "profile-compare-campaign-signoff failed: campaign subject appears to be placeholder text ($campaign_subject)"
  echo "provide a real invite key via --campaign-subject/--subject/--key/--invite-key, or set CAMPAIGN_SUBJECT/INVITE_KEY"
  exit 2
fi
if [[ -n "$campaign_subject" && -n "$campaign_anon_cred" ]]; then
  echo "use either --campaign-subject or --campaign-anon-cred, not both"
  exit 2
fi

if [[ ! -x "$CAMPAIGN_SCRIPT" ]]; then
  echo "missing executable campaign script: $CAMPAIGN_SCRIPT"
  exit 2
fi
if [[ ! -x "$CAMPAIGN_CHECK_SCRIPT" ]]; then
  echo "missing executable campaign-check script: $CAMPAIGN_CHECK_SCRIPT"
  exit 2
fi

reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

lock_dir="$reports_dir/.profile_compare_campaign_signoff.lock"
lock_metadata_file="$lock_dir/metadata"
lock_acquired=0
lock_owner_pid=""
lock_owner_start_time_utc=""
lock_owner_cmd=""
lock_override_enabled="0"
if [[ "$allow_concurrent" == "1" ]]; then
  lock_override_enabled="1"
fi

cleanup_signoff_lock() {
  if [[ "$lock_acquired" == "1" && -d "$lock_dir" ]]; then
    rm -rf "$lock_dir" >/dev/null 2>&1 || true
  fi
}
trap cleanup_signoff_lock EXIT

if [[ "$lock_override_enabled" != "1" ]]; then
  invocation_cmd_line="$(redact_sensitive_cmd_line "$(quote_cmd "$0" "${original_args[@]}")")"
  invocation_cmd_line="$(printf '%s' "$invocation_cmd_line" | tr '\n' ' ')"
  lock_self_start_time_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  stale_lock_cleaned=0
  while true; do
    if mkdir "$lock_dir" >/dev/null 2>&1; then
      lock_acquired=1
      {
        printf 'pid=%s\n' "$$"
        printf 'start_time_utc=%s\n' "$lock_self_start_time_utc"
        printf 'cmd=%s\n' "$invocation_cmd_line"
      } >"$lock_metadata_file"
      break
    fi

    lock_owner_pid="$(read_lock_metadata_field "$lock_metadata_file" "pid")"
    lock_owner_start_time_utc="$(read_lock_metadata_field "$lock_metadata_file" "start_time_utc")"
    lock_owner_cmd="$(read_lock_metadata_field "$lock_metadata_file" "cmd")"

    if [[ -n "$lock_owner_pid" && "$stale_lock_cleaned" == "0" ]] && ! pid_is_running "$lock_owner_pid"; then
      if rm -rf "$lock_dir" >/dev/null 2>&1; then
        stale_lock_cleaned=1
        continue
      fi
    fi

    echo "profile-compare-campaign-signoff: another signoff run is already active for this reports-dir"
    echo "reports_dir: $reports_dir"
    echo "lock_dir: $lock_dir"
    echo "active_pid: ${lock_owner_pid:-unknown}"
    echo "active_start_time_utc: ${lock_owner_start_time_utc:-unknown}"
    echo "active_cmd: ${lock_owner_cmd:-unknown}"
    echo "to bypass intentionally, rerun with --allow-concurrent 1 (or PROFILE_COMPARE_CAMPAIGN_SIGNOFF_ALLOW_CONCURRENT=1)"
    exit 3
  done
fi

if [[ -n "$campaign_summary_json" ]]; then
  campaign_summary_json="$(abs_path "$campaign_summary_json")"
else
  campaign_summary_json="$reports_dir/profile_compare_campaign_summary.json"
fi
if [[ -n "$campaign_report_md" ]]; then
  campaign_report_md="$(abs_path "$campaign_report_md")"
else
  campaign_report_md="$reports_dir/profile_compare_campaign_report.md"
fi
if [[ -n "$campaign_check_summary_json" ]]; then
  campaign_check_summary_json="$(abs_path "$campaign_check_summary_json")"
else
  campaign_check_summary_json="$reports_dir/profile_compare_campaign_check_summary.json"
fi
if [[ -n "$summary_json" ]]; then
  summary_json="$(abs_path "$summary_json")"
else
  summary_json="$reports_dir/profile_compare_campaign_signoff_summary.json"
fi

campaign_summary_available="0"
campaign_summary_valid="0"
campaign_summary_status=""
campaign_summary_decision=""
campaign_summary_refresh_campaign="0"
if [[ -f "$campaign_summary_json" ]]; then
  campaign_summary_available="1"
  if jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object") and (.trend | type == "object")' "$campaign_summary_json" >/dev/null 2>&1; then
    campaign_summary_valid="1"
    campaign_summary_status="$(jq -r '.status // ""' "$campaign_summary_json")"
    campaign_summary_decision="$(jq -r '.decision.recommended_default_profile // ""' "$campaign_summary_json")"
    campaign_summary_refresh_campaign="$(jq -r '(.inputs.refresh_campaign // false) | if . then "1" else "0" end' "$campaign_summary_json")"
  fi
fi

campaign_refresh_effective="$refresh_campaign"
campaign_execution_mode_effective="$campaign_execution_mode"
campaign_directory_urls_effective="$campaign_directory_urls"
campaign_bootstrap_directory_effective="$campaign_bootstrap_directory"
campaign_discovery_wait_sec_effective="$campaign_discovery_wait_sec"
campaign_issuer_url_effective="$campaign_issuer_url"
campaign_entry_url_effective="$campaign_entry_url"
campaign_exit_url_effective="$campaign_exit_url"
campaign_subject_effective="$campaign_subject"
campaign_anon_cred_effective="$campaign_anon_cred"
campaign_start_local_stack_effective="$campaign_start_local_stack"

if [[ "$campaign_refresh_effective" == "1" && -z "$campaign_execution_mode_effective" ]]; then
  if [[ -n "$campaign_directory_urls_effective" || -n "$campaign_bootstrap_directory_effective" || -n "$campaign_issuer_url_effective" || -n "$campaign_entry_url_effective" || -n "$campaign_exit_url_effective" ]]; then
    campaign_execution_mode_effective="docker"
  fi
fi

if [[ "$campaign_refresh_effective" == "1" && "$campaign_execution_mode_effective" == "docker" && -z "$campaign_start_local_stack_effective" ]]; then
  campaign_start_local_stack_effective="0"
fi

mkdir -p "$(dirname "$campaign_summary_json")" "$(dirname "$campaign_report_md")" "$(dirname "$campaign_check_summary_json")" "$(dirname "$summary_json")"

if [[ "$allow_summary_overwrite" == "0" ]]; then
  if [[ "$summary_json" == "$campaign_summary_json" || "$summary_json" == "$campaign_check_summary_json" || "$summary_json" == "$campaign_report_md" ]]; then
    echo "profile-compare-campaign-signoff failed: summary-json path collides with campaign artifact path"
    exit 2
  fi
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"
campaign_log_initial="$log_dir/profile_compare_campaign_signoff_${run_stamp}_campaign.log"
campaign_log_fallback="$log_dir/profile_compare_campaign_signoff_${run_stamp}_campaign_fallback.log"
campaign_log_effective="$campaign_log_initial"
campaign_preflight_log="$log_dir/profile_compare_campaign_signoff_${run_stamp}_campaign_preflight.log"
check_log="$log_dir/profile_compare_campaign_signoff_${run_stamp}_campaign_check.log"

campaign_attempted=0
campaign_status="skip"
campaign_rc=0
campaign_cmd_line=""
campaign_cmd_line_initial=""
campaign_cmd_line_fallback=""
campaign_cmd_line_effective=""
campaign_summary_reused="0"
campaign_timeout_triggered="0"
campaign_duration_sec="0"
campaign_failure_reason=""
campaign_heartbeat_count="0"

campaign_fallback_eligible="0"
campaign_fallback_attempted="0"
campaign_fallback_triggered="0"
campaign_fallback_reason=""
campaign_fallback_initial_mode=""
campaign_fallback_initial_start_local_stack=""
campaign_fallback_initial_rc="0"
campaign_fallback_effective_mode=""
campaign_fallback_effective_start_local_stack=""
campaign_stage_primary_failure=""
campaign_stage_primary_failure_count="0"

campaign_preflight_enabled="0"
campaign_preflight_attempted="0"
campaign_preflight_status="skip"
campaign_preflight_skipped_reason=""
campaign_preflight_failure_reason=""
campaign_preflight_total_endpoints="0"
campaign_preflight_remote_endpoints="0"
campaign_preflight_failed_count="0"
campaign_preflight_candidate_endpoints_json='[]'
campaign_preflight_remote_endpoints_json='[]'
campaign_preflight_failed_endpoints_json='[]'

check_attempted=0
check_status="skip"
check_rc=0
check_cmd_line=""

status="ok"
final_rc=0
failure_stage=""

build_campaign_cmd() {
  campaign_cmd=(
    "$CAMPAIGN_SCRIPT"
    --reports-dir "$reports_dir"
    --summary-json "$campaign_summary_json"
    --report-md "$campaign_report_md"
    --print-summary-json 0
  )
  if [[ -n "$campaign_execution_mode_effective" ]]; then
    campaign_cmd+=(--execution-mode "$campaign_execution_mode_effective")
  fi
  if [[ -n "$campaign_directory_urls_effective" ]]; then
    campaign_cmd+=(--directory-urls "$campaign_directory_urls_effective")
  fi
  if [[ -n "$campaign_bootstrap_directory_effective" ]]; then
    campaign_cmd+=(--bootstrap-directory "$campaign_bootstrap_directory_effective")
  fi
  if [[ -n "$campaign_discovery_wait_sec_effective" ]]; then
    campaign_cmd+=(--discovery-wait-sec "$campaign_discovery_wait_sec_effective")
  fi
  if [[ -n "$campaign_issuer_url_effective" ]]; then
    campaign_cmd+=(--issuer-url "$campaign_issuer_url_effective")
  fi
  if [[ -n "$campaign_entry_url_effective" ]]; then
    campaign_cmd+=(--entry-url "$campaign_entry_url_effective")
  fi
  if [[ -n "$campaign_exit_url_effective" ]]; then
    campaign_cmd+=(--exit-url "$campaign_exit_url_effective")
  fi
  if [[ -n "$campaign_subject_effective" ]]; then
    campaign_cmd+=(--subject "$campaign_subject_effective")
  fi
  if [[ -n "$campaign_anon_cred_effective" ]]; then
    campaign_cmd+=(--anon-cred "$campaign_anon_cred_effective")
  fi
  if [[ -n "$campaign_start_local_stack_effective" ]]; then
    campaign_cmd+=(--start-local-stack "$campaign_start_local_stack_effective")
  fi
  campaign_cmd_line="$(redact_sensitive_cmd_line "$(quote_cmd "${campaign_cmd[@]}")")"
}

build_campaign_cmd
campaign_cmd_line_initial="$campaign_cmd_line"
campaign_cmd_line_effective="$campaign_cmd_line"

if [[ "$refresh_campaign" == "1" ]]; then
  campaign_attempted=1
  if (( campaign_endpoint_preflight_timeout_sec > 0 )); then
    campaign_preflight_enabled="1"
    echo "[profile-compare-campaign-signoff] $(date -u +%Y-%m-%dT%H:%M:%SZ) campaign endpoint preflight enabled timeout_sec=$campaign_endpoint_preflight_timeout_sec log=$campaign_preflight_log"
    if run_campaign_endpoint_preflight "$campaign_preflight_log"; then
      echo "[profile-compare-campaign-signoff] $(date -u +%Y-%m-%dT%H:%M:%SZ) campaign endpoint preflight result status=$campaign_preflight_status attempted=$campaign_preflight_attempted remote_endpoints=$campaign_preflight_remote_endpoints failed_endpoints=$campaign_preflight_failed_count"
    else
      campaign_rc=$?
      campaign_status="fail"
      campaign_log_effective="$campaign_preflight_log"
      if [[ -n "$campaign_preflight_failure_reason" ]]; then
        campaign_failure_reason="$campaign_preflight_failure_reason"
      elif [[ -z "$campaign_failure_reason" ]]; then
        campaign_failure_reason="campaign endpoint preflight failed"
      fi
      campaign_stage_primary_failure="endpoint_unreachable"
      if [[ "$campaign_preflight_failed_count" =~ ^[0-9]+$ ]] && (( campaign_preflight_failed_count > 0 )); then
        campaign_stage_primary_failure_count="$campaign_preflight_failed_count"
      else
        campaign_stage_primary_failure_count="1"
      fi
      status="fail"
      final_rc="$campaign_rc"
      failure_stage="campaign"
      echo "[profile-compare-campaign-signoff] $(date -u +%Y-%m-%dT%H:%M:%SZ) campaign endpoint preflight failed reason=$campaign_failure_reason log=$campaign_preflight_log"
    fi
  else
    campaign_preflight_enabled="0"
    campaign_preflight_status="skip"
    campaign_preflight_skipped_reason="endpoint preflight disabled"
  fi

  if [[ -z "$failure_stage" ]]; then
    if run_campaign_refresh_monitored "initial" "$campaign_log_initial" "${campaign_cmd[@]}"; then
      campaign_status="pass"
      campaign_rc=0
      campaign_log_effective="$campaign_log_initial"
    else
      campaign_rc=$?
      campaign_status="fail"
      campaign_log_effective="$campaign_log_initial"

      if [[ -z "$campaign_execution_mode" && "${campaign_execution_mode_effective:-local}" == "local" ]]; then
        campaign_fallback_eligible="1"
        campaign_fallback_reason="$(detect_local_stack_block_reason "$campaign_log_initial")"
        if [[ -n "$campaign_fallback_reason" ]]; then
          campaign_fallback_attempted="1"
          campaign_fallback_triggered="1"
          campaign_fallback_initial_mode="${campaign_execution_mode_effective:-local}"
          campaign_fallback_initial_start_local_stack="${campaign_start_local_stack_effective:-auto}"
          campaign_fallback_initial_rc="$campaign_rc"

          campaign_execution_mode_effective="docker"
          if [[ -z "$campaign_start_local_stack_effective" || "$campaign_start_local_stack_effective" == "auto" ]]; then
            campaign_start_local_stack_effective="0"
          fi
          campaign_fallback_effective_mode="$campaign_execution_mode_effective"
          campaign_fallback_effective_start_local_stack="${campaign_start_local_stack_effective:-auto}"

          build_campaign_cmd
          campaign_cmd_line_fallback="$campaign_cmd_line"
          campaign_cmd_line_effective="$campaign_cmd_line"
          campaign_log_effective="$campaign_log_fallback"

          if run_campaign_refresh_monitored "fallback" "$campaign_log_fallback" "${campaign_cmd[@]}"; then
            campaign_status="pass"
            campaign_rc=0
          else
            campaign_rc=$?
            campaign_status="fail"
          fi
        fi
      fi

      if [[ "$campaign_status" != "pass" ]]; then
        if [[ -z "$campaign_stage_primary_failure" ]]; then
          if [[ "$campaign_timeout_triggered" == "1" ]]; then
            campaign_stage_primary_failure="campaign_timeout"
          else
            campaign_stage_primary_failure="campaign_failure"
          fi
        fi
        if [[ "$campaign_stage_primary_failure_count" == "0" ]]; then
          campaign_stage_primary_failure_count="1"
        fi
        status="fail"
        final_rc="$campaign_rc"
        failure_stage="campaign"
      fi
    fi
  fi
else
  if [[ "$campaign_summary_valid" == "1" ]]; then
    campaign_summary_reused="1"
  fi
fi

check_cmd=(
  "$CAMPAIGN_CHECK_SCRIPT"
  --campaign-summary-json "$campaign_summary_json"
  --summary-json "$campaign_check_summary_json"
  --fail-on-no-go "$fail_on_no_go"
  --show-json "$show_json"
  --print-summary-json 0
)

if [[ -n "$require_status_pass" ]]; then
  check_cmd+=(--require-status-pass "$require_status_pass")
fi
if [[ -n "$require_trend_status_pass" ]]; then
  check_cmd+=(--require-trend-status-pass "$require_trend_status_pass")
fi
if [[ -n "$require_min_runs_total" ]]; then
  check_cmd+=(--require-min-runs-total "$require_min_runs_total")
fi
if [[ -n "$require_max_runs_fail" ]]; then
  check_cmd+=(--require-max-runs-fail "$require_max_runs_fail")
fi
if [[ -n "$require_max_runs_warn" ]]; then
  check_cmd+=(--require-max-runs-warn "$require_max_runs_warn")
fi
if [[ -n "$require_min_runs_with_summary" ]]; then
  check_cmd+=(--require-min-runs-with-summary "$require_min_runs_with_summary")
fi
if [[ -n "$require_recommendation_support_rate_pct" ]]; then
  check_cmd+=(--require-recommendation-support-rate-pct "$require_recommendation_support_rate_pct")
fi
if [[ -n "$require_recommended_profile" ]]; then
  check_cmd+=(--require-recommended-profile "$require_recommended_profile")
fi
if [[ -n "$allow_recommended_profiles" ]]; then
  check_cmd+=(--allow-recommended-profiles "$allow_recommended_profiles")
fi
if [[ -n "$disallow_experimental_default" ]]; then
  check_cmd+=(--disallow-experimental-default "$disallow_experimental_default")
fi
if [[ -n "$require_trend_source" ]]; then
  check_cmd+=(--require-trend-source "$require_trend_source")
fi
if [[ -n "$require_selection_policy_present" ]]; then
  check_cmd+=(--require-selection-policy-present "$require_selection_policy_present")
fi
if [[ -n "$require_selection_policy_valid" ]]; then
  check_cmd+=(--require-selection-policy-valid "$require_selection_policy_valid")
fi
if [[ -n "$require_micro_relay_quality_evidence" ]]; then
  check_cmd+=(--require-micro-relay-quality-evidence "$require_micro_relay_quality_evidence")
fi
if [[ -n "$require_micro_relay_quality_status_pass" ]]; then
  check_cmd+=(--require-micro-relay-quality-status-pass "$require_micro_relay_quality_status_pass")
fi
if [[ -n "$require_micro_relay_demotion_policy" ]]; then
  check_cmd+=(--require-micro-relay-demotion-policy "$require_micro_relay_demotion_policy")
fi
if [[ -n "$require_micro_relay_promotion_policy" ]]; then
  check_cmd+=(--require-micro-relay-promotion-policy "$require_micro_relay_promotion_policy")
fi
if [[ -n "$require_trust_tier_port_unlock_policy" ]]; then
  check_cmd+=(--require-trust-tier-port-unlock-policy "$require_trust_tier_port_unlock_policy")
fi

check_cmd_line="$(quote_cmd "${check_cmd[@]}")"

if [[ -z "$failure_stage" ]]; then
  check_attempted=1
  if "${check_cmd[@]}" >"$check_log" 2>&1; then
    check_status="pass"
    check_rc=0
  else
    check_rc=$?
    check_status="fail"
    status="fail"
    final_rc="$check_rc"
    failure_stage="campaign_check"
  fi
fi

if [[ -z "$failure_stage" ]]; then
  final_rc=0
  status="ok"
fi

decision="unknown"
decision_context="none"
decision_reason=""
recommended_profile=""
support_rate_pct="0"
trend_source_value=""
selection_policy_evidence_present="0"
selection_policy_evidence_valid="0"
decision_diagnostics_json='{"source_schema":"none","legacy":null,"aggregated_diagnostics":{"transport_mismatch_failures":0,"token_proof_invalid_failures":0,"unknown_exit_failures":0,"directory_trust_failures":0,"root_required_failures":0,"endpoint_unreachable_failures":0},"likely_primary_failure":"none","operator_hint":""}'
next_operator_action=""
campaign_check_summary_present=0
if [[ "$check_attempted" == "1" && -f "$campaign_check_summary_json" ]] && jq -e . "$campaign_check_summary_json" >/dev/null 2>&1; then
  campaign_check_summary_present=1
  decision="$(jq -r '.decision // "unknown"' "$campaign_check_summary_json")"
  decision_context="campaign_check_summary"
  recommended_profile="$(jq -r '.observed.recommended_profile // ""' "$campaign_check_summary_json")"
  support_rate_pct="$(jq -r '.observed.support_rate_pct // .observed.recommendation_support_rate_pct // 0' "$campaign_check_summary_json")"
  trend_source_value="$(jq -r '.observed.trend_source // ""' "$campaign_check_summary_json")"
  selection_policy_evidence_present="$(jq -r 'if (.observed.selection_policy_evidence.present // false) then "1" else "0" end' "$campaign_check_summary_json" 2>/dev/null || printf '0')"
  selection_policy_evidence_valid="$(jq -r 'if (.observed.selection_policy_evidence.valid // false) then "1" else "0" end' "$campaign_check_summary_json" 2>/dev/null || printf '0')"
fi

if [[ "$check_attempted" == "1" && -f "$campaign_summary_json" ]] && jq -e . "$campaign_summary_json" >/dev/null 2>&1; then
  diagnostics_ingested="$(jq -c '
    def to_nonneg_int:
      if . == null then 0
      elif type == "number" then (if . < 0 then 0 else floor end)
      elif type == "string" then ((tonumber? // 0) | if . < 0 then 0 else floor end)
      else 0
      end;
    def normalized_primary:
      if . == null then "none"
      elif type == "string" then (if . == "" then "none" else . end)
      else (tostring)
      end;
    def infer_primary_from_legacy($legacy):
      ($legacy | tostring | ascii_downcase) as $txt
      | if ($txt | contains("token_proof_invalid")) then "token_proof_invalid"
        elif ($txt | contains("unknown_exit")) then "unknown_exit"
        elif ($txt | contains("transport_mismatch")) then "transport_mismatch"
        elif ($txt | contains("directory_trust")) then "directory_trust"
        elif ($txt | contains("root_required")) then "root_required"
        elif ($txt | contains("endpoint_unreachable")) then "endpoint_unreachable"
        else "none"
        end;
    . as $root
    | ($root.diagnostics // $root.summary.diagnostics // null) as $legacy
    | ($root.aggregated_diagnostics // null) as $current_agg
    | ($root.likely_primary_failure // null) as $current_primary
    | ($root.operator_hint // null) as $current_hint
    | (if $current_agg != null or $current_primary != null or $current_hint != null then "current"
       elif $legacy != null then "legacy"
       else "none"
       end) as $source_schema
    | (if $current_agg != null then $current_agg else $legacy end) as $agg_source
    | {
        source_schema: $source_schema,
        legacy: $legacy,
        aggregated_diagnostics: {
          transport_mismatch_failures: (($agg_source.transport_mismatch_failures // 0) | to_nonneg_int),
          token_proof_invalid_failures: (($agg_source.token_proof_invalid_failures // 0) | to_nonneg_int),
          unknown_exit_failures: (($agg_source.unknown_exit_failures // 0) | to_nonneg_int),
          directory_trust_failures: (($agg_source.directory_trust_failures // 0) | to_nonneg_int),
          root_required_failures: (($agg_source.root_required_failures // 0) | to_nonneg_int),
          endpoint_unreachable_failures: (($agg_source.endpoint_unreachable_failures // 0) | to_nonneg_int)
        },
        likely_primary_failure: (
          ($current_primary | normalized_primary) as $explicit
          | if $explicit != "none" then $explicit
            elif (($agg_source.token_proof_invalid_failures // 0) | to_nonneg_int) > 0 then "token_proof_invalid"
            elif (($agg_source.unknown_exit_failures // 0) | to_nonneg_int) > 0 then "unknown_exit"
            elif (($agg_source.transport_mismatch_failures // 0) | to_nonneg_int) > 0 then "transport_mismatch"
            elif (($agg_source.directory_trust_failures // 0) | to_nonneg_int) > 0 then "directory_trust"
            elif (($agg_source.root_required_failures // 0) | to_nonneg_int) > 0 then "root_required"
            elif (($agg_source.endpoint_unreachable_failures // 0) | to_nonneg_int) > 0 then "endpoint_unreachable"
            else infer_primary_from_legacy($legacy)
            end
        ),
        operator_hint: (
          if $current_hint == null then ""
          elif ($current_hint | type) == "string" then $current_hint
          else ($current_hint | tostring)
          end
        )
      }
  ' "$campaign_summary_json" 2>/dev/null || true)"
  if [[ -n "$diagnostics_ingested" ]] && jq -e . >/dev/null 2>&1 <<<"$diagnostics_ingested"; then
    decision_diagnostics_json="$diagnostics_ingested"
  fi
fi

diagnostics_primary_failure="$(jq -r '.likely_primary_failure // "none"' <<<"$decision_diagnostics_json" 2>/dev/null || printf '%s' "none")"
diagnostics_operator_hint="$(jq -r '.operator_hint // ""' <<<"$decision_diagnostics_json" 2>/dev/null || printf '%s' "")"
case "$diagnostics_primary_failure" in
  token_proof_invalid|unknown_exit)
    next_operator_action="Use a fresh invite key from active issuer and rerun signoff"
    ;;
  transport_mismatch)
    next_operator_action="Rerun with remote docker campaign and opaque/udp transport defaults"
    ;;
  directory_trust)
    next_operator_action="Run trust/runtime reset path then rerun"
    ;;
  root_required)
    next_operator_action="Run signoff with sudo (root) or force docker campaign refresh mode, then rerun"
    ;;
  endpoint_unreachable)
    next_operator_action="Verify directory/issuer/entry/exit endpoints are reachable, then rerun signoff"
    ;;
  *)
    if [[ -n "$diagnostics_operator_hint" ]]; then
      next_operator_action="$diagnostics_operator_hint"
    else
      next_operator_action=""
    fi
    ;;
esac

if ! is_non_negative_decimal "$support_rate_pct"; then
  support_rate_pct="0"
fi
if [[ "$failure_stage" == "campaign" ]]; then
  synthetic_failure_kind="${campaign_stage_primary_failure:-campaign_failure}"
  synthetic_endpoint_unreachable_failures=0
  if [[ "$synthetic_failure_kind" == "endpoint_unreachable" ]]; then
    if [[ "$campaign_stage_primary_failure_count" =~ ^[0-9]+$ ]] && (( campaign_stage_primary_failure_count > 0 )); then
      synthetic_endpoint_unreachable_failures="$campaign_stage_primary_failure_count"
    else
      synthetic_endpoint_unreachable_failures=1
    fi
  fi
  decision="NO-GO"
  decision_context="synthetic_campaign_failure"
  campaign_check_summary_present=0
  recommended_profile=""
  support_rate_pct="0"
  trend_source_value=""
  if [[ -n "$campaign_failure_reason" ]]; then
    decision_reason="$campaign_failure_reason"
  elif [[ "$campaign_timeout_triggered" == "1" ]]; then
    decision_reason="campaign refresh timed out after ${campaign_timeout_sec}s"
  else
    decision_reason="campaign stage failed before campaign-check"
  fi
  case "$synthetic_failure_kind" in
    campaign_timeout)
      next_operator_action="Investigate campaign timeout, verify endpoint availability, and rerun signoff"
      ;;
    endpoint_unreachable)
      next_operator_action="Verify directory/issuer/entry/exit endpoints are reachable, then rerun signoff"
      ;;
    *)
      next_operator_action="Inspect campaign log and rerun signoff after fixing campaign-stage failure"
      ;;
  esac
  decision_diagnostics_json="$(jq -nc \
    --arg synthetic_failure_kind "$synthetic_failure_kind" \
    --argjson endpoint_unreachable_failures "$synthetic_endpoint_unreachable_failures" \
    --arg operator_hint "$next_operator_action" \
    '{
      source_schema: "synthetic_stage_failure",
      legacy: null,
      aggregated_diagnostics: {
        transport_mismatch_failures: 0,
        token_proof_invalid_failures: 0,
        unknown_exit_failures: 0,
        directory_trust_failures: 0,
        root_required_failures: 0,
        endpoint_unreachable_failures: $endpoint_unreachable_failures
      },
      likely_primary_failure: $synthetic_failure_kind,
      operator_hint: $operator_hint
    }')"
fi
if [[ "$decision" == "unknown" && "$failure_stage" == "campaign_check" ]]; then
  decision="NO-GO"
  decision_context="synthetic_campaign_check_failure"
  check_failure_line=""
  if [[ -f "$check_log" ]]; then
    check_failure_line="$(grep -E 'profile-compare-campaign-check failed:' "$check_log" | tail -n 1 || true)"
  fi
  if [[ "$check_failure_line" == *"campaign summary JSON not found"* ]]; then
    decision_reason="campaign summary JSON missing"
  elif [[ "$check_failure_line" == *"invalid campaign summary JSON schema"* ]]; then
    decision_reason="campaign summary JSON invalid schema"
  elif [[ -n "$check_failure_line" ]]; then
    decision_reason="$check_failure_line"
  elif [[ ! -f "$campaign_summary_json" ]]; then
    decision_reason="campaign summary JSON missing"
  elif ! jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object") and (.trend | type == "object")' "$campaign_summary_json" >/dev/null 2>&1; then
    decision_reason="campaign summary JSON invalid schema"
  else
    decision_reason="campaign-check stage failed before emitting decision summary"
  fi
fi

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
campaign_subject_configured="0"
if [[ -n "$campaign_subject" ]]; then
  campaign_subject_configured="1"
fi
campaign_anon_cred_configured="0"
if [[ -n "$campaign_anon_cred" ]]; then
  campaign_anon_cred_configured="1"
fi
campaign_subject_effective_configured="0"
if [[ -n "$campaign_subject_effective" ]]; then
  campaign_subject_effective_configured="1"
fi
campaign_anon_cred_effective_configured="0"
if [[ -n "$campaign_anon_cred_effective" ]]; then
  campaign_anon_cred_effective_configured="1"
fi

jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$status" \
  --argjson final_rc "$final_rc" \
  --arg failure_stage "$failure_stage" \
  --arg reports_dir "$reports_dir" \
  --arg campaign_summary_json "$campaign_summary_json" \
  --arg campaign_report_md "$campaign_report_md" \
  --arg campaign_check_summary_json "$campaign_check_summary_json" \
  --arg summary_json "$summary_json" \
  --arg campaign_log_initial "$campaign_log_initial" \
  --arg campaign_log_fallback "$campaign_log_fallback" \
  --arg campaign_log_effective "$campaign_log_effective" \
  --arg campaign_preflight_log "$campaign_preflight_log" \
  --arg check_log "$check_log" \
  --arg campaign_cmd_initial "$campaign_cmd_line_initial" \
  --arg campaign_cmd_fallback "$campaign_cmd_line_fallback" \
  --arg campaign_cmd_effective "$campaign_cmd_line_effective" \
  --arg check_cmd "$check_cmd_line" \
  --arg decision "$decision" \
  --arg decision_context "$decision_context" \
  --arg decision_reason "$decision_reason" \
  --argjson decision_diagnostics "$decision_diagnostics_json" \
  --arg next_operator_action "$next_operator_action" \
  --arg recommended_profile "$recommended_profile" \
  --arg support_rate_pct "$support_rate_pct" \
  --arg trend_source "$trend_source_value" \
  --arg refresh_campaign "$refresh_campaign" \
  --arg campaign_refresh_effective "$campaign_refresh_effective" \
  --arg campaign_summary_reused "$campaign_summary_reused" \
  --arg fail_on_no_go "$fail_on_no_go" \
  --arg allow_concurrent "$allow_concurrent" \
  --arg lock_override_enabled "$lock_override_enabled" \
  --arg lock_dir "$lock_dir" \
  --arg require_status_pass "$require_status_pass" \
  --arg require_trend_status_pass "$require_trend_status_pass" \
  --arg require_min_runs_total "$require_min_runs_total" \
  --arg require_max_runs_fail "$require_max_runs_fail" \
  --arg require_max_runs_warn "$require_max_runs_warn" \
  --arg require_min_runs_with_summary "$require_min_runs_with_summary" \
  --arg require_recommendation_support_rate_pct "$require_recommendation_support_rate_pct" \
  --arg require_recommended_profile "$require_recommended_profile" \
  --arg allow_recommended_profiles "$allow_recommended_profiles" \
  --arg disallow_experimental_default "$disallow_experimental_default" \
  --arg require_trend_source "$require_trend_source" \
  --arg require_selection_policy_present "$require_selection_policy_present" \
  --arg require_selection_policy_valid "$require_selection_policy_valid" \
  --arg require_micro_relay_quality_evidence "$require_micro_relay_quality_evidence" \
  --arg require_micro_relay_quality_status_pass "$require_micro_relay_quality_status_pass" \
  --arg require_micro_relay_demotion_policy "$require_micro_relay_demotion_policy" \
  --arg require_micro_relay_promotion_policy "$require_micro_relay_promotion_policy" \
  --arg require_trust_tier_port_unlock_policy "$require_trust_tier_port_unlock_policy" \
  --arg campaign_execution_mode "$campaign_execution_mode" \
  --arg campaign_execution_mode_effective "$campaign_execution_mode_effective" \
  --arg campaign_directory_urls "$campaign_directory_urls" \
  --arg campaign_directory_urls_effective "$campaign_directory_urls_effective" \
  --arg campaign_bootstrap_directory "$campaign_bootstrap_directory" \
  --arg campaign_bootstrap_directory_effective "$campaign_bootstrap_directory_effective" \
  --arg campaign_discovery_wait_sec "$campaign_discovery_wait_sec" \
  --arg campaign_discovery_wait_sec_effective "$campaign_discovery_wait_sec_effective" \
  --arg campaign_issuer_url "$campaign_issuer_url" \
  --arg campaign_issuer_url_effective "$campaign_issuer_url_effective" \
  --arg campaign_entry_url "$campaign_entry_url" \
  --arg campaign_entry_url_effective "$campaign_entry_url_effective" \
  --arg campaign_exit_url "$campaign_exit_url" \
  --arg campaign_exit_url_effective "$campaign_exit_url_effective" \
  --arg campaign_subject_configured "$campaign_subject_configured" \
  --arg campaign_subject_source "$campaign_subject_source" \
  --arg campaign_subject_effective_configured "$campaign_subject_effective_configured" \
  --arg campaign_anon_cred_configured "$campaign_anon_cred_configured" \
  --arg campaign_anon_cred_effective_configured "$campaign_anon_cred_effective_configured" \
  --arg campaign_start_local_stack "$campaign_start_local_stack" \
  --arg campaign_start_local_stack_effective "$campaign_start_local_stack_effective" \
  --arg campaign_timeout_sec "$campaign_timeout_sec" \
  --arg campaign_endpoint_preflight_timeout_sec "$campaign_endpoint_preflight_timeout_sec" \
  --arg campaign_heartbeat_interval_sec "$campaign_heartbeat_interval_sec" \
  --arg campaign_preflight_enabled "$campaign_preflight_enabled" \
  --arg campaign_preflight_attempted "$campaign_preflight_attempted" \
  --arg campaign_preflight_status "$campaign_preflight_status" \
  --arg campaign_preflight_skipped_reason "$campaign_preflight_skipped_reason" \
  --arg campaign_preflight_failure_reason "$campaign_preflight_failure_reason" \
  --arg campaign_preflight_total_endpoints "$campaign_preflight_total_endpoints" \
  --arg campaign_preflight_remote_endpoints "$campaign_preflight_remote_endpoints" \
  --arg campaign_preflight_failed_count "$campaign_preflight_failed_count" \
  --argjson campaign_preflight_candidate_endpoints "$campaign_preflight_candidate_endpoints_json" \
  --argjson campaign_preflight_remote_endpoints_list "$campaign_preflight_remote_endpoints_json" \
  --argjson campaign_preflight_failed_endpoints "$campaign_preflight_failed_endpoints_json" \
  --arg campaign_fallback_eligible "$campaign_fallback_eligible" \
  --arg campaign_fallback_attempted "$campaign_fallback_attempted" \
  --arg campaign_fallback_triggered "$campaign_fallback_triggered" \
  --arg campaign_fallback_reason "$campaign_fallback_reason" \
  --arg campaign_fallback_initial_mode "$campaign_fallback_initial_mode" \
  --arg campaign_fallback_initial_start_local_stack "$campaign_fallback_initial_start_local_stack" \
  --arg campaign_fallback_effective_mode "$campaign_fallback_effective_mode" \
  --arg campaign_fallback_effective_start_local_stack "$campaign_fallback_effective_start_local_stack" \
  --argjson campaign_fallback_initial_rc "$campaign_fallback_initial_rc" \
  --argjson campaign_attempted "$campaign_attempted" \
  --arg campaign_status "$campaign_status" \
  --argjson campaign_rc "$campaign_rc" \
  --arg campaign_timeout_triggered "$campaign_timeout_triggered" \
  --arg campaign_duration_sec "$campaign_duration_sec" \
  --arg campaign_failure_reason "$campaign_failure_reason" \
  --arg campaign_heartbeat_count "$campaign_heartbeat_count" \
  --argjson check_attempted "$check_attempted" \
  --arg check_status "$check_status" \
  --argjson check_rc "$check_rc" \
  --argjson campaign_check_summary_present "$campaign_check_summary_present" \
  --arg selection_policy_evidence_present "$selection_policy_evidence_present" \
  --arg selection_policy_evidence_valid "$selection_policy_evidence_valid" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    final_rc: $final_rc,
    failure_stage: $failure_stage,
    inputs: {
      reports_dir: $reports_dir,
      refresh_campaign: ($refresh_campaign == "1"),
      refresh_campaign_effective: ($campaign_refresh_effective == "1"),
      campaign_summary_reused: ($campaign_summary_reused == "1"),
      fail_on_no_go: ($fail_on_no_go == "1"),
      signoff_lock: {
        enabled: ($lock_override_enabled != "1"),
        override_enabled: ($lock_override_enabled == "1"),
        allow_concurrent: ($allow_concurrent == "1"),
        lock_dir: $lock_dir
      },
      policy: {
        require_status_pass: (if $require_status_pass == "" then null else ($require_status_pass | tonumber) end),
        require_trend_status_pass: (if $require_trend_status_pass == "" then null else ($require_trend_status_pass | tonumber) end),
        require_min_runs_total: (if $require_min_runs_total == "" then null else ($require_min_runs_total | tonumber) end),
        require_max_runs_fail: (if $require_max_runs_fail == "" then null else ($require_max_runs_fail | tonumber) end),
        require_max_runs_warn: (if $require_max_runs_warn == "" then null else ($require_max_runs_warn | tonumber) end),
        require_min_runs_with_summary: (if $require_min_runs_with_summary == "" then null else ($require_min_runs_with_summary | tonumber) end),
        require_recommendation_support_rate_pct: (if $require_recommendation_support_rate_pct == "" then null else ($require_recommendation_support_rate_pct | tonumber) end),
        require_recommended_profile: (if $require_recommended_profile == "" then null else $require_recommended_profile end),
        allow_recommended_profiles: (if $allow_recommended_profiles == "" then null else ($allow_recommended_profiles | split(",") | map(gsub("^\\s+|\\s+$"; "") | select(length > 0))) end),
        disallow_experimental_default: (if $disallow_experimental_default == "" then null else ($disallow_experimental_default | tonumber) end),
        require_trend_source: (if $require_trend_source == "" then null else ($require_trend_source | split(",") | map(gsub("^\\s+|\\s+$"; "") | select(length > 0))) end),
        require_selection_policy_present: (if $require_selection_policy_present == "" then null else ($require_selection_policy_present | tonumber) end),
        require_selection_policy_valid: (if $require_selection_policy_valid == "" then null else ($require_selection_policy_valid | tonumber) end),
        require_micro_relay_quality_evidence: (if $require_micro_relay_quality_evidence == "" then null else ($require_micro_relay_quality_evidence | tonumber) end),
        require_micro_relay_quality_status_pass: (if $require_micro_relay_quality_status_pass == "" then null else ($require_micro_relay_quality_status_pass | tonumber) end),
        require_micro_relay_demotion_policy: (if $require_micro_relay_demotion_policy == "" then null else ($require_micro_relay_demotion_policy | tonumber) end),
        require_micro_relay_promotion_policy: (if $require_micro_relay_promotion_policy == "" then null else ($require_micro_relay_promotion_policy | tonumber) end),
        require_trust_tier_port_unlock_policy: (if $require_trust_tier_port_unlock_policy == "" then null else ($require_trust_tier_port_unlock_policy | tonumber) end)
      },
      campaign_refresh_overrides: {
        execution_mode: (if $campaign_execution_mode == "" then null else $campaign_execution_mode end),
        directory_urls: (if $campaign_directory_urls == "" then null else $campaign_directory_urls end),
        bootstrap_directory: (if $campaign_bootstrap_directory == "" then null else $campaign_bootstrap_directory end),
        discovery_wait_sec: (if $campaign_discovery_wait_sec == "" then null else ($campaign_discovery_wait_sec | tonumber) end),
        issuer_url: (if $campaign_issuer_url == "" then null else $campaign_issuer_url end),
        entry_url: (if $campaign_entry_url == "" then null else $campaign_entry_url end),
        exit_url: (if $campaign_exit_url == "" then null else $campaign_exit_url end),
        subject_source: (if $campaign_subject_source == "" then null else $campaign_subject_source end),
        subject_configured: ($campaign_subject_configured == "1"),
        anon_cred_configured: ($campaign_anon_cred_configured == "1"),
        start_local_stack: (if $campaign_start_local_stack == "" then null else $campaign_start_local_stack end)
      },
      campaign_refresh_overrides_effective: {
        execution_mode: (if $campaign_execution_mode_effective == "" then null else $campaign_execution_mode_effective end),
        directory_urls: (if $campaign_directory_urls_effective == "" then null else $campaign_directory_urls_effective end),
        bootstrap_directory: (if $campaign_bootstrap_directory_effective == "" then null else $campaign_bootstrap_directory_effective end),
        discovery_wait_sec: (if $campaign_discovery_wait_sec_effective == "" then null else ($campaign_discovery_wait_sec_effective | tonumber) end),
        issuer_url: (if $campaign_issuer_url_effective == "" then null else $campaign_issuer_url_effective end),
        entry_url: (if $campaign_entry_url_effective == "" then null else $campaign_entry_url_effective end),
        exit_url: (if $campaign_exit_url_effective == "" then null else $campaign_exit_url_effective end),
        subject_configured: ($campaign_subject_effective_configured == "1"),
        anon_cred_configured: ($campaign_anon_cred_effective_configured == "1"),
        start_local_stack: (if $campaign_start_local_stack_effective == "" then null else $campaign_start_local_stack_effective end)
      },
      campaign_refresh_runtime: {
        timeout_sec: ($campaign_timeout_sec | tonumber),
        heartbeat_interval_sec: ($campaign_heartbeat_interval_sec | tonumber)
      },
      campaign_endpoint_preflight: {
        enabled: ($campaign_preflight_enabled == "1"),
        attempted: ($campaign_preflight_attempted == "1"),
        status: $campaign_preflight_status,
        timeout_sec: ($campaign_endpoint_preflight_timeout_sec | tonumber),
        total_http_endpoints: ($campaign_preflight_total_endpoints | tonumber),
        remote_http_endpoints: ($campaign_preflight_remote_endpoints | tonumber),
        failed_endpoints_count: ($campaign_preflight_failed_count | tonumber),
        skipped_reason: (if $campaign_preflight_skipped_reason == "" then null else $campaign_preflight_skipped_reason end),
        failure_reason: (if $campaign_preflight_failure_reason == "" then null else $campaign_preflight_failure_reason end),
        log: $campaign_preflight_log,
        candidate_endpoints: $campaign_preflight_candidate_endpoints,
        remote_endpoints: $campaign_preflight_remote_endpoints_list,
        failed_endpoints: $campaign_preflight_failed_endpoints
      },
      campaign_refresh_fallback: {
        eligible: ($campaign_fallback_eligible == "1"),
        attempted: ($campaign_fallback_attempted == "1"),
        triggered: ($campaign_fallback_triggered == "1"),
        reason: (if $campaign_fallback_reason == "" then null else $campaign_fallback_reason end),
        initial_mode: (if $campaign_fallback_initial_mode == "" then null else $campaign_fallback_initial_mode end),
        initial_start_local_stack: (if $campaign_fallback_initial_start_local_stack == "" then null else $campaign_fallback_initial_start_local_stack end),
        initial_rc: (if $campaign_fallback_attempted == "1" then $campaign_fallback_initial_rc else null end),
        effective_mode: (if $campaign_fallback_effective_mode == "" then null else $campaign_fallback_effective_mode end),
        effective_start_local_stack: (if $campaign_fallback_effective_start_local_stack == "" then null else $campaign_fallback_effective_start_local_stack end)
      }
    },
    stages: {
      campaign: {
        attempted: ($campaign_attempted == 1),
        status: $campaign_status,
        rc: $campaign_rc,
        command: $campaign_cmd_effective,
        log: $campaign_log_effective,
        timeout_sec: ($campaign_timeout_sec | tonumber),
        timed_out: ($campaign_timeout_triggered == "1"),
        duration_sec: ($campaign_duration_sec | tonumber),
        heartbeat_count: ($campaign_heartbeat_count | tonumber),
        failure_reason: (if $campaign_failure_reason == "" then null else $campaign_failure_reason end),
        preflight: {
          enabled: ($campaign_preflight_enabled == "1"),
          attempted: ($campaign_preflight_attempted == "1"),
          status: $campaign_preflight_status,
          timeout_sec: ($campaign_endpoint_preflight_timeout_sec | tonumber),
          failed_endpoints_count: ($campaign_preflight_failed_count | tonumber),
          skipped_reason: (if $campaign_preflight_skipped_reason == "" then null else $campaign_preflight_skipped_reason end),
          failure_reason: (if $campaign_preflight_failure_reason == "" then null else $campaign_preflight_failure_reason end),
          log: $campaign_preflight_log,
          failed_endpoints: $campaign_preflight_failed_endpoints
        },
        initial_command: $campaign_cmd_initial,
        initial_log: $campaign_log_initial,
        fallback_command: (if $campaign_cmd_fallback == "" then null else $campaign_cmd_fallback end),
        fallback_log: (if $campaign_fallback_attempted == "1" then $campaign_log_fallback else null end),
        summary_json: $campaign_summary_json,
        report_md: $campaign_report_md
      },
      campaign_check: {
        attempted: ($check_attempted == 1),
        status: $check_status,
        rc: $check_rc,
        command: $check_cmd,
        log: $check_log,
        summary_json: $campaign_check_summary_json
      }
    },
    decision: {
      decision: $decision,
      go: ($decision == "GO"),
      context: $decision_context,
      reason: (if $decision_reason == "" then null else $decision_reason end),
      from_campaign_check_summary: ($campaign_check_summary_present == 1),
      diagnostics: $decision_diagnostics,
      next_operator_action: $next_operator_action,
      recommended_profile: $recommended_profile,
      support_rate_pct: ($support_rate_pct | tonumber),
      trend_source: $trend_source,
      selection_policy_evidence: {
        present: ($selection_policy_evidence_present == "1"),
        valid: ($selection_policy_evidence_valid == "1")
      }
    },
    artifacts: {
      summary_json: $summary_json,
      campaign_summary_json: $campaign_summary_json,
      campaign_report_md: $campaign_report_md,
      campaign_check_summary_json: $campaign_check_summary_json
    }
  }' >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

if [[ "$campaign_fallback_triggered" == "1" ]]; then
  echo "[profile-compare-campaign-signoff] campaign auto-fallback: mode=${campaign_fallback_initial_mode:-local}->${campaign_fallback_effective_mode:-docker} reason=${campaign_fallback_reason:-unknown}"
fi

echo "[profile-compare-campaign-signoff] status=$status final_rc=$final_rc decision=$decision recommended_profile=${recommended_profile:-unset} summary_json=$summary_json"
if [[ "$status" != "ok" ]]; then
  echo "[profile-compare-campaign-signoff] failure_stage=$failure_stage campaign_log=$campaign_log_effective check_log=$check_log"
  if [[ "$failure_stage" == "campaign" && -n "$campaign_failure_reason" ]]; then
    echo "[profile-compare-campaign-signoff] campaign_failure_reason=$campaign_failure_reason"
  fi
fi
if [[ "$show_json" == "1" ]]; then
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  echo "[profile-compare-campaign-signoff] summary_json_payload:"
  cat "$summary_json"
fi

exit "$final_rc"
