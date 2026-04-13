#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg date awk sed; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/client_vpn_profile_compare.sh \
    [--profiles CSV] \
    [--rounds N] \
    [--pause-sec N] \
    [--min-pass-rate-pct N] \
    [--fail-on-any-fail [0|1]] \
    [--directory-urls URL[,URL...]] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--issuer-urls URL[,URL...]] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--subject ID | --anon-cred TOKEN] \
    [--min-sources N] \
    [--min-operators N] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--operator-floor-check [0|1]] \
    [--issuer-quorum-check [0|1]] \
    [--issuer-min-operators N] \
    [--interface IFACE] \
    [--proxy-addr HOST:PORT] \
    [--private-key-file PATH] \
    [--allowed-ips CIDR] \
    [--install-route [0|1]] \
    [--startup-sync-timeout-sec N] \
    [--ready-timeout-sec N] \
    [--mtls-ca-file PATH] \
    [--mtls-client-cert-file PATH] \
    [--mtls-client-key-file PATH] \
    [--run-preflight [0|1]] \
    [--status-check [0|1]] \
    [--pre-real-host-readiness [0|1]] \
    [--runtime-doctor [0|1]] \
    [--runtime-fix [0|1]] \
    [--runtime-fix-prune-wg-only-dir [0|1]] \
    [--trust-reset-on-key-mismatch [0|1]] \
    [--trust-reset-scope scoped|global] \
    [--public-ip-url URL] \
    [--country-url URL] \
    [--curl-timeout-sec N] \
    [--smoke-extra-arg ARG]... \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run repeatable real `client-vpn-smoke` comparisons for route profiles
  (`1hop`, `2hop`, `3hop`) and emit one summary JSON + markdown report with
  reliability/latency-oriented recommendations.

Notes:
  - `1hop` is experimental/non-default by policy and only runs in non-strict
    mode (`--beta-profile 0 --prod-profile 0`).
  - This runner forces `client-vpn-smoke --record-result 0
    --manual-validation-report 0 --incident-snapshot-on-fail 0` to avoid
    polluting manual-validation state during benchmarking.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
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

print_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

append_opt() {
  local array_name="$1"
  local flag="$2"
  local value="${3:-}"
  if [[ -n "$value" ]]; then
    eval "$array_name+=(\"\$flag\" \"\$value\")"
  fi
}

prepare_log_dir() {
  local dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}

normalize_compare_profile() {
  local profile
  profile="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$profile" in
    1hop|1-hop|hop1|hop-1|onehop|speed-1hop|speed1hop|fast-1hop|fast1hop|speed|fast)
      printf '%s\n' "1hop"
      ;;
    2hop|2-hop|hop2|hop-2|twohop|balanced)
      printf '%s\n' "2hop"
      ;;
    3hop|3-hop|hop3|hop-3|threehop|private|privacy)
      printf '%s\n' "3hop"
      ;;
    *)
      return 1
      ;;
  esac
}

extract_bool() {
  local expr="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    printf '%s\n' "false"
    return 0
  fi
  jq -r "$expr // false" "$file" 2>/dev/null | sed 's/^$/false/' | tail -n 1
}

extract_text() {
  local expr="$1"
  local file="$2"
  if [[ ! -f "$file" ]]; then
    printf '%s\n' ""
    return 0
  fi
  jq -r "$expr // \"\"" "$file" 2>/dev/null | tail -n 1
}

append_run_record() {
  local profile="$1"
  local round="$2"
  local status="$3"
  local rc="$4"
  local duration_sec="$5"
  local smoke_status="$6"
  local smoke_stage="$7"
  local smoke_notes="$8"
  local public_ip_result="$9"
  local country_result="${10}"
  local trust_reset_attempted="${11}"
  local trust_reset_retry_succeeded="${12}"
  local smoke_summary_json="${13}"
  local output_log="${14}"
  local command="${15}"
  local skip_reason="${16}"

  jq -cn \
    --arg profile "$profile" \
    --argjson round "$round" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --argjson duration_sec "$duration_sec" \
    --arg smoke_status "$smoke_status" \
    --arg smoke_stage "$smoke_stage" \
    --arg smoke_notes "$smoke_notes" \
    --arg public_ip_result "$public_ip_result" \
    --arg country_result "$country_result" \
    --arg trust_reset_attempted "$trust_reset_attempted" \
    --arg trust_reset_retry_succeeded "$trust_reset_retry_succeeded" \
    --arg smoke_summary_json "$smoke_summary_json" \
    --arg output_log "$output_log" \
    --arg command "$command" \
    --arg skip_reason "$skip_reason" \
    '{
      profile: $profile,
      round: $round,
      status: $status,
      rc: $rc,
      duration_sec: $duration_sec,
      smoke_status: $smoke_status,
      smoke_stage: $smoke_stage,
      smoke_notes: $smoke_notes,
      public_ip_result: $public_ip_result,
      country_result: $country_result,
      trust_reset_attempted: ($trust_reset_attempted == "true"),
      trust_reset_retry_succeeded: ($trust_reset_retry_succeeded == "true"),
      smoke_summary_json: $smoke_summary_json,
      output_log: $output_log,
      command: $command,
      skip_reason: $skip_reason
    }'
}

smoke_script="${CLIENT_VPN_PROFILE_COMPARE_SMOKE_SCRIPT:-$ROOT_DIR/scripts/client_vpn_smoke.sh}"
if [[ ! -x "$smoke_script" ]]; then
  echo "missing executable client-vpn-smoke script: $smoke_script"
  exit 2
fi

original_args=("$@")

profiles_csv="1hop,2hop,3hop"
rounds="3"
pause_sec="1"
min_pass_rate_pct="95"
fail_on_any_fail="0"

directory_urls=""
bootstrap_directory=""
discovery_wait_sec=""
issuer_url=""
issuer_urls=""
entry_url=""
exit_url=""
subject=""
anon_cred=""
min_sources=""
min_operators=""
beta_profile="0"
prod_profile="0"
operator_floor_check=""
issuer_quorum_check=""
issuer_min_operators=""
interface_name=""
proxy_addr=""
private_key_file=""
allowed_ips=""
install_route=""
startup_sync_timeout_sec=""
ready_timeout_sec=""
mtls_ca_file=""
mtls_client_cert_file=""
mtls_client_key_file=""
run_preflight="1"
status_check="1"
pre_real_host_readiness="0"
runtime_doctor="1"
runtime_fix="0"
runtime_fix_prune_wg_only_dir="1"
trust_reset_on_key_mismatch="1"
trust_reset_scope="scoped"
public_ip_url=""
country_url=""
curl_timeout_sec=""
summary_json=""
report_md=""
print_summary_json="0"
declare -a smoke_extra_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profiles) profiles_csv="${2:-}"; shift 2 ;;
    --rounds) rounds="${2:-}"; shift 2 ;;
    --pause-sec) pause_sec="${2:-}"; shift 2 ;;
    --min-pass-rate-pct) min_pass_rate_pct="${2:-}"; shift 2 ;;
    --fail-on-any-fail)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_any_fail="${2:-}"
        shift 2
      else
        fail_on_any_fail="1"
        shift
      fi
      ;;
    --directory-urls) directory_urls="${2:-}"; shift 2 ;;
    --bootstrap-directory) bootstrap_directory="${2:-}"; shift 2 ;;
    --discovery-wait-sec) discovery_wait_sec="${2:-}"; shift 2 ;;
    --issuer-url) issuer_url="${2:-}"; shift 2 ;;
    --issuer-urls) issuer_urls="${2:-}"; shift 2 ;;
    --entry-url) entry_url="${2:-}"; shift 2 ;;
    --exit-url) exit_url="${2:-}"; shift 2 ;;
    --subject) subject="${2:-}"; shift 2 ;;
    --anon-cred) anon_cred="${2:-}"; shift 2 ;;
    --min-sources) min_sources="${2:-}"; shift 2 ;;
    --min-operators) min_operators="${2:-}"; shift 2 ;;
    --beta-profile) beta_profile="${2:-1}"; shift 2 ;;
    --prod-profile) prod_profile="${2:-1}"; shift 2 ;;
    --operator-floor-check) operator_floor_check="${2:-1}"; shift 2 ;;
    --issuer-quorum-check) issuer_quorum_check="${2:-1}"; shift 2 ;;
    --issuer-min-operators) issuer_min_operators="${2:-}"; shift 2 ;;
    --interface) interface_name="${2:-}"; shift 2 ;;
    --proxy-addr) proxy_addr="${2:-}"; shift 2 ;;
    --private-key-file) private_key_file="${2:-}"; shift 2 ;;
    --allowed-ips) allowed_ips="${2:-}"; shift 2 ;;
    --install-route) install_route="${2:-1}"; shift 2 ;;
    --startup-sync-timeout-sec) startup_sync_timeout_sec="${2:-}"; shift 2 ;;
    --ready-timeout-sec) ready_timeout_sec="${2:-}"; shift 2 ;;
    --mtls-ca-file) mtls_ca_file="${2:-}"; shift 2 ;;
    --mtls-client-cert-file) mtls_client_cert_file="${2:-}"; shift 2 ;;
    --mtls-client-key-file) mtls_client_key_file="${2:-}"; shift 2 ;;
    --run-preflight) run_preflight="${2:-1}"; shift 2 ;;
    --status-check) status_check="${2:-1}"; shift 2 ;;
    --pre-real-host-readiness) pre_real_host_readiness="${2:-1}"; shift 2 ;;
    --runtime-doctor) runtime_doctor="${2:-1}"; shift 2 ;;
    --runtime-fix) runtime_fix="${2:-1}"; shift 2 ;;
    --runtime-fix-prune-wg-only-dir) runtime_fix_prune_wg_only_dir="${2:-1}"; shift 2 ;;
    --trust-reset-on-key-mismatch) trust_reset_on_key_mismatch="${2:-1}"; shift 2 ;;
    --trust-reset-scope) trust_reset_scope="${2:-}"; shift 2 ;;
    --public-ip-url) public_ip_url="${2:-}"; shift 2 ;;
    --country-url) country_url="${2:-}"; shift 2 ;;
    --curl-timeout-sec) curl_timeout_sec="${2:-}"; shift 2 ;;
    --smoke-extra-arg)
      smoke_extra_args+=("${2:-}")
      shift 2
      ;;
    --summary-json) summary_json="${2:-}"; shift 2 ;;
    --report-md) report_md="${2:-}"; shift 2 ;;
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

if ! [[ "$rounds" =~ ^[0-9]+$ ]] || ((rounds < 1)); then
  echo "--rounds must be >= 1"
  exit 2
fi
if ! [[ "$pause_sec" =~ ^[0-9]+$ ]]; then
  echo "--pause-sec must be >= 0"
  exit 2
fi
if ! [[ "$min_pass_rate_pct" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
  echo "--min-pass-rate-pct must be numeric"
  exit 2
fi
bool_arg_or_die "--fail-on-any-fail" "$fail_on_any_fail"
bool_arg_or_die "--run-preflight" "$run_preflight"
bool_arg_or_die "--status-check" "$status_check"
bool_arg_or_die "--pre-real-host-readiness" "$pre_real_host_readiness"
bool_arg_or_die "--runtime-doctor" "$runtime_doctor"
bool_arg_or_die "--runtime-fix" "$runtime_fix"
bool_arg_or_die "--runtime-fix-prune-wg-only-dir" "$runtime_fix_prune_wg_only_dir"
bool_arg_or_die "--trust-reset-on-key-mismatch" "$trust_reset_on_key_mismatch"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

trust_reset_scope="$(trim "$trust_reset_scope" | tr '[:upper:]' '[:lower:]')"
if [[ "$trust_reset_scope" != "scoped" && "$trust_reset_scope" != "global" ]]; then
  echo "--trust-reset-scope must be one of: scoped, global"
  exit 2
fi

declare -a profiles=()
IFS=',' read -r -a raw_profiles <<<"$profiles_csv"
for raw in "${raw_profiles[@]}"; do
  raw="$(trim "$raw")"
  [[ -z "$raw" ]] && continue
  normalized="$(normalize_compare_profile "$raw" || true)"
  if [[ -z "$normalized" ]]; then
    echo "unknown profile in --profiles: $raw"
    echo "allowed: 1hop,2hop,3hop (aliases: speed,speed-1hop,balanced,private,fast,privacy)"
    exit 2
  fi
  duplicate="0"
  for existing in "${profiles[@]}"; do
    if [[ "$existing" == "$normalized" ]]; then
      duplicate="1"
      break
    fi
  done
  if [[ "$duplicate" == "0" ]]; then
    profiles+=("$normalized")
  fi
done
if [[ "${#profiles[@]}" -eq 0 ]]; then
  echo "--profiles resolved to an empty set"
  exit 2
fi

profile_inputs_json="$(printf '%s\n' "${profiles[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"

log_dir="$(prepare_log_dir)"
run_stamp="$(date +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/client_vpn_profile_compare_${run_stamp}.json"
fi
if [[ -z "$report_md" ]]; then
  report_md="$log_dir/client_vpn_profile_compare_${run_stamp}.md"
fi
summary_json="$(abs_path "$summary_json")"
report_md="$(abs_path "$report_md")"
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
summary_log="$log_dir/client_vpn_profile_compare_${run_stamp}.log"
: >"$summary_log"

runs_file="$(mktemp)"
cleanup() {
  rm -f "$runs_file"
}
trap cleanup EXIT

run_idx="0"
total_planned_runs=$(( ${#profiles[@]} * rounds ))
for profile in "${profiles[@]}"; do
  for round in $(seq 1 "$rounds"); do
    run_idx=$((run_idx + 1))
    run_log="$log_dir/client_vpn_profile_compare_${run_stamp}_${profile}_r${round}.log"
    run_summary_json="$log_dir/client_vpn_profile_compare_${run_stamp}_${profile}_r${round}.json"
    : >"$run_log"

    skip_reason=""
    if [[ "$profile" == "1hop" && ( "$beta_profile" == "1" || "$prod_profile" == "1" ) ]]; then
      skip_reason="1hop is experimental and requires --beta-profile 0 --prod-profile 0"
    fi

    if [[ -n "$skip_reason" ]]; then
      echo "[client-vpn-profile-compare] profile=$profile round=$round status=skip reason=$skip_reason" | tee -a "$summary_log"
      append_run_record "$profile" "$round" "skip" "0" "0" "skipped" "skip" "$skip_reason" "" "" "false" "false" "$run_summary_json" "$run_log" "" "$skip_reason" >>"$runs_file"
      continue
    fi

    declare -a run_cmd=("$smoke_script")
    append_opt run_cmd "--directory-urls" "$directory_urls"
    append_opt run_cmd "--bootstrap-directory" "$bootstrap_directory"
    append_opt run_cmd "--discovery-wait-sec" "$discovery_wait_sec"
    append_opt run_cmd "--issuer-url" "$issuer_url"
    append_opt run_cmd "--issuer-urls" "$issuer_urls"
    append_opt run_cmd "--entry-url" "$entry_url"
    append_opt run_cmd "--exit-url" "$exit_url"
    append_opt run_cmd "--subject" "$subject"
    append_opt run_cmd "--anon-cred" "$anon_cred"
    append_opt run_cmd "--min-sources" "$min_sources"
    append_opt run_cmd "--min-operators" "$min_operators"
    run_cmd+=(--path-profile "$profile")
    append_opt run_cmd "--beta-profile" "$beta_profile"
    append_opt run_cmd "--prod-profile" "$prod_profile"
    append_opt run_cmd "--operator-floor-check" "$operator_floor_check"
    append_opt run_cmd "--issuer-quorum-check" "$issuer_quorum_check"
    append_opt run_cmd "--issuer-min-operators" "$issuer_min_operators"
    append_opt run_cmd "--interface" "$interface_name"
    append_opt run_cmd "--proxy-addr" "$proxy_addr"
    append_opt run_cmd "--private-key-file" "$private_key_file"
    append_opt run_cmd "--allowed-ips" "$allowed_ips"
    append_opt run_cmd "--install-route" "$install_route"
    append_opt run_cmd "--startup-sync-timeout-sec" "$startup_sync_timeout_sec"
    append_opt run_cmd "--ready-timeout-sec" "$ready_timeout_sec"
    append_opt run_cmd "--mtls-ca-file" "$mtls_ca_file"
    append_opt run_cmd "--mtls-client-cert-file" "$mtls_client_cert_file"
    append_opt run_cmd "--mtls-client-key-file" "$mtls_client_key_file"
    append_opt run_cmd "--run-preflight" "$run_preflight"
    append_opt run_cmd "--status-check" "$status_check"
    append_opt run_cmd "--pre-real-host-readiness" "$pre_real_host_readiness"
    append_opt run_cmd "--runtime-doctor" "$runtime_doctor"
    append_opt run_cmd "--runtime-fix" "$runtime_fix"
    append_opt run_cmd "--runtime-fix-prune-wg-only-dir" "$runtime_fix_prune_wg_only_dir"
    append_opt run_cmd "--trust-reset-on-key-mismatch" "$trust_reset_on_key_mismatch"
    append_opt run_cmd "--trust-reset-scope" "$trust_reset_scope"
    append_opt run_cmd "--public-ip-url" "$public_ip_url"
    append_opt run_cmd "--country-url" "$country_url"
    append_opt run_cmd "--curl-timeout-sec" "$curl_timeout_sec"
    run_cmd+=(--record-result 0 --manual-validation-report 0 --incident-snapshot-on-fail 0 --keep-up 0)
    run_cmd+=(--summary-json "$run_summary_json" --print-summary-json 0)
    if [[ "${#smoke_extra_args[@]}" -gt 0 ]]; then
      run_cmd+=("${smoke_extra_args[@]}")
    fi

    run_cmd_str="$(print_cmd "${run_cmd[@]}")"
    start_sec="$(date +%s)"
    if "${run_cmd[@]}" >"$run_log" 2>&1; then
      run_rc=0
    else
      run_rc=$?
    fi
    end_sec="$(date +%s)"
    duration_sec=$((end_sec - start_sec))

    smoke_status=""
    smoke_stage=""
    smoke_notes=""
    public_ip_result=""
    country_result=""
    trust_reset_attempted="false"
    trust_reset_retry_succeeded="false"
    if [[ -f "$run_summary_json" ]] && jq -e . "$run_summary_json" >/dev/null 2>&1; then
      smoke_status="$(extract_text '.status' "$run_summary_json")"
      smoke_stage="$(extract_text '.stage' "$run_summary_json")"
      smoke_notes="$(extract_text '.notes' "$run_summary_json")"
      public_ip_result="$(extract_text '.outputs.public_ip_result' "$run_summary_json")"
      country_result="$(extract_text '.outputs.country_result' "$run_summary_json")"
      trust_reset_attempted="$(extract_bool '.trust_reset.attempted' "$run_summary_json")"
      trust_reset_retry_succeeded="$(extract_bool '.trust_reset.retry_succeeded' "$run_summary_json")"
    fi

    if [[ "$run_rc" -eq 0 && "$smoke_status" == "pass" ]]; then
      run_status="pass"
    elif [[ "$run_rc" -eq 0 && -z "$smoke_status" ]]; then
      run_status="pass"
      smoke_status="pass"
    else
      run_status="fail"
      if [[ -z "$smoke_status" ]]; then
        smoke_status="fail"
      fi
    fi

    echo "[client-vpn-profile-compare] profile=$profile round=$round status=$run_status rc=$run_rc duration_sec=$duration_sec smoke_stage=${smoke_stage:-unknown} log=$run_log" | tee -a "$summary_log"
    append_run_record \
      "$profile" "$round" "$run_status" "$run_rc" "$duration_sec" \
      "$smoke_status" "$smoke_stage" "$smoke_notes" "$public_ip_result" "$country_result" \
      "$trust_reset_attempted" "$trust_reset_retry_succeeded" \
      "$run_summary_json" "$run_log" "$run_cmd_str" "" >>"$runs_file"

    if (( pause_sec > 0 )) && (( run_idx < total_planned_runs )); then
      sleep "$pause_sec"
    fi
  done
done

runs_json="$(jq -s '.' "$runs_file")"
profile_summary_json="$(jq '
  sort_by(.profile)
  | group_by(.profile)
  | map(
      . as $runs
      | ($runs | map(select(.status != "skip"))) as $executed
      | ($executed | map(select(.status == "pass"))) as $pass
      | ($executed | map(select(.status == "fail"))) as $fail
      | {
          profile: $runs[0].profile,
          runs_total: ($runs | length),
          runs_executed: ($executed | length),
          runs_skipped: ($runs | map(select(.status == "skip")) | length),
          runs_pass: ($pass | length),
          runs_fail: ($fail | length),
          pass_rate_pct: (if ($executed | length) == 0 then 0 else ((($pass | length) * 100.0) / ($executed | length)) end),
          avg_duration_sec: (if ($executed | length) == 0 then 0 else (($executed | map(.duration_sec) | add) / ($executed | length)) end),
          avg_pass_duration_sec: (if ($pass | length) == 0 then 0 else (($pass | map(.duration_sec) | add) / ($pass | length)) end),
          trust_reset_attempts: ($executed | map(if .trust_reset_attempted then 1 else 0 end) | add // 0),
          trust_reset_retry_successes: ($executed | map(if .trust_reset_retry_succeeded then 1 else 0 end) | add // 0),
          public_ip_unique_count: ($executed | map(.public_ip_result) | map(select(length > 0)) | unique | length),
          countries_observed: ($executed | map(.country_result) | map(select(length > 0)) | unique),
          failure_stages: ($fail | map(.smoke_stage) | map(select(length > 0)) | unique),
          skip_reasons: ($runs | map(select(.status == "skip" and (.skip_reason | length > 0)) | .skip_reason) | unique),
          experimental_non_default: ($runs[0].profile == "1hop")
        }
    )
' <<<"$runs_json")"

runs_total="$(jq 'length' <<<"$runs_json")"
runs_executed="$(jq '[.[] | select(.status != "skip")] | length' <<<"$runs_json")"
runs_pass="$(jq '[.[] | select(.status == "pass")] | length' <<<"$runs_json")"
runs_fail="$(jq '[.[] | select(.status == "fail")] | length' <<<"$runs_json")"
runs_skipped="$(jq '[.[] | select(.status == "skip")] | length' <<<"$runs_json")"

profile_2hop_reliable="0"
profile_3hop_reliable="0"
if jq -e --argjson min "$min_pass_rate_pct" 'map(select(.profile == "2hop" and .runs_executed > 0 and .pass_rate_pct >= $min)) | length > 0' <<<"$profile_summary_json" >/dev/null 2>&1; then
  profile_2hop_reliable="1"
fi
if jq -e --argjson min "$min_pass_rate_pct" 'map(select(.profile == "3hop" and .runs_executed > 0 and .pass_rate_pct >= $min)) | length > 0' <<<"$profile_summary_json" >/dev/null 2>&1; then
  profile_3hop_reliable="1"
fi

recommended_default_profile=""
decision_reason=""
if [[ "$profile_2hop_reliable" == "1" ]]; then
  recommended_default_profile="2hop"
  decision_reason="2hop met reliability policy and remains the default privacy/performance baseline."
elif [[ "$profile_3hop_reliable" == "1" ]]; then
  recommended_default_profile="3hop"
  decision_reason="2hop did not meet reliability policy; 3hop is the best reliable non-experimental fallback."
else
  recommended_default_profile="$(jq -r '
    map(select(.profile != "1hop" and .runs_executed > 0))
    | sort_by([.runs_fail, (-.pass_rate_pct), .avg_duration_sec, .profile])
    | (.[0].profile // "")
  ' <<<"$profile_summary_json")"
  if [[ -n "$recommended_default_profile" ]]; then
    decision_reason="no non-experimental profile met reliability policy; selected best available non-experimental profile."
  else
    decision_reason="no non-experimental profile produced executable runs."
  fi
fi

recommended_low_latency_profile="$(jq -r --argjson min "$min_pass_rate_pct" '
  (map(select(.runs_executed > 0 and .pass_rate_pct >= $min)) | sort_by(.avg_duration_sec, .profile) | .[0].profile) //
  (map(select(.runs_executed > 0)) | sort_by(.avg_duration_sec, .profile) | .[0].profile) //
  ""
' <<<"$profile_summary_json")"

if [[ "$profile_3hop_reliable" == "1" ]]; then
  recommended_max_privacy_profile="3hop"
elif [[ "$profile_2hop_reliable" == "1" ]]; then
  recommended_max_privacy_profile="2hop"
else
  recommended_max_privacy_profile=""
fi

if (( runs_executed == 0 )); then
  status="fail"
  notes="No comparison runs were executed"
  final_rc=1
elif (( runs_fail == 0 )); then
  status="pass"
  notes="All executed comparison runs passed"
  final_rc=0
elif (( runs_pass > 0 )); then
  status="warn"
  notes="Some comparison runs failed; inspect profile reliability before default changes"
  final_rc=0
else
  status="fail"
  notes="All executed comparison runs failed"
  final_rc=1
fi

if [[ "$fail_on_any_fail" == "1" && "$runs_fail" -gt 0 ]]; then
  final_rc=1
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg command "$(print_cmd "$0" "${original_args[@]}")" \
  --arg summary_log "$summary_log" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --arg smoke_script "$smoke_script" \
  --argjson rc "$final_rc" \
  --argjson rounds "$rounds" \
  --argjson pause_sec "$pause_sec" \
  --argjson min_pass_rate_pct "$min_pass_rate_pct" \
  --argjson fail_on_any_fail "$fail_on_any_fail" \
  --arg directory_urls "$directory_urls" \
  --arg bootstrap_directory "$bootstrap_directory" \
  --arg issuer_url "$issuer_url" \
  --arg issuer_urls "$issuer_urls" \
  --arg entry_url "$entry_url" \
  --arg exit_url "$exit_url" \
  --arg subject "$subject" \
  --arg anon_cred "$anon_cred" \
  --arg beta_profile "$beta_profile" \
  --arg prod_profile "$prod_profile" \
  --argjson profiles "$profile_inputs_json" \
  --arg decision_reason "$decision_reason" \
  --arg recommended_default_profile "$recommended_default_profile" \
  --arg recommended_low_latency_profile "$recommended_low_latency_profile" \
  --arg recommended_max_privacy_profile "$recommended_max_privacy_profile" \
  --argjson profiles_summary "$profile_summary_json" \
  --argjson runs "$runs_json" \
  --argjson runs_total "$runs_total" \
  --argjson runs_executed "$runs_executed" \
  --argjson runs_pass "$runs_pass" \
  --argjson runs_fail "$runs_fail" \
  --argjson runs_skipped "$runs_skipped" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: $notes,
    command: $command,
    inputs: {
      smoke_script: $smoke_script,
      profiles: $profiles,
      rounds: $rounds,
      pause_sec: $pause_sec,
      min_pass_rate_pct: $min_pass_rate_pct,
      fail_on_any_fail: ($fail_on_any_fail == 1),
      directory_urls: $directory_urls,
      bootstrap_directory: $bootstrap_directory,
      issuer_url: $issuer_url,
      issuer_urls: $issuer_urls,
      entry_url: $entry_url,
      exit_url: $exit_url,
      subject: $subject,
      anon_cred_present: ($anon_cred | length > 0),
      beta_profile: ($beta_profile == "1"),
      prod_profile: ($prod_profile == "1")
    },
    summary: {
      profiles_total: ($profiles | length),
      runs_total: $runs_total,
      runs_executed: $runs_executed,
      runs_pass: $runs_pass,
      runs_fail: $runs_fail,
      runs_skipped: $runs_skipped
    },
    decision: {
      recommended_default_profile: $recommended_default_profile,
      recommended_low_latency_profile: $recommended_low_latency_profile,
      recommended_max_privacy_profile: $recommended_max_privacy_profile,
      rationale: $decision_reason,
      policy: "default prioritizes reliable non-experimental profiles (2hop/3hop); 1hop remains experimental non-default",
      min_pass_rate_pct: $min_pass_rate_pct,
      experimental_non_default_profiles: ["1hop"]
    },
    profiles: $profiles_summary,
    runs: $runs,
    artifacts: {
      summary_log: $summary_log,
      summary_json: $summary_json,
      report_md: $report_md
    }
  }' >"$summary_json"

{
  echo "# Real VPN Route-Profile Comparison Report"
  echo
  echo "- Generated at (UTC): \`$(jq -r '.generated_at_utc' "$summary_json")\`"
  echo "- Status: \`$(jq -r '.status' "$summary_json")\`"
  echo "- Summary JSON: \`$summary_json\`"
  echo "- Summary Log: \`$summary_log\`"
  echo
  echo "## Decision"
  echo
  echo "- Recommended default profile: \`$(jq -r '.decision.recommended_default_profile // ""' "$summary_json")\`"
  echo "- Recommended low-latency profile: \`$(jq -r '.decision.recommended_low_latency_profile // ""' "$summary_json")\`"
  echo "- Recommended max-privacy profile: \`$(jq -r '.decision.recommended_max_privacy_profile // ""' "$summary_json")\`"
  echo "- Rationale: $(jq -r '.decision.rationale' "$summary_json")"
  echo "- Policy: $(jq -r '.decision.policy' "$summary_json")"
  echo
  echo "## Run Summary"
  echo
  echo "- Runs total: \`$(jq -r '.summary.runs_total' "$summary_json")\`"
  echo "- Runs executed: \`$(jq -r '.summary.runs_executed' "$summary_json")\`"
  echo "- Runs pass: \`$(jq -r '.summary.runs_pass' "$summary_json")\`"
  echo "- Runs fail: \`$(jq -r '.summary.runs_fail' "$summary_json")\`"
  echo "- Runs skipped: \`$(jq -r '.summary.runs_skipped' "$summary_json")\`"
  echo
  echo "## Per-Profile Metrics"
  echo
  echo "| Profile | Executed | Pass | Fail | Pass % | Avg Duration (s) | Trust Reset Attempts | Trust Reset Retries Succeeded | Countries | Fail Stages |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|---|---|"
  jq -r '
    .profiles[]
    | "| \(.profile) | \(.runs_executed) | \(.runs_pass) | \(.runs_fail) | \(.pass_rate_pct) | \(.avg_duration_sec) | \(.trust_reset_attempts) | \(.trust_reset_retry_successes) | \((.countries_observed | join(","))) | \((.failure_stages | join(","))) |"
  ' "$summary_json"
} >"$report_md"

echo "client-vpn-profile-compare: status=$status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
echo "report_md: $report_md"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
