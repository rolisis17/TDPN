#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg date awk; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_local.sh \
    [--profiles CSV] \
    [--rounds N] \
    [--timeout-sec N] \
    [--execution-mode docker|local] \
    [--directory-urls URL[,URL...]] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--subject ID | --anon-cred TOKEN] \
    [--min-sources N] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--start-local-stack auto|0|1] \
    [--force-stack-reset [0|1]] \
    [--stack-strict-beta [0|1]] \
    [--base-port N] \
    [--client-iface IFACE] \
    [--exit-iface IFACE] \
    [--cleanup-ifaces [0|1]] \
    [--keep-stack [0|1]] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run repeatable local profile comparisons (`speed`, `balanced`, `private`,
  `speed-1hop`) using `easy_node.sh client-test`, then emit machine-readable
  summary + markdown report artifacts with a default-profile recommendation.

Notes:
  - `speed-1hop` is experimental and is never recommended as a default.
  - if no endpoint URLs are provided, this wrapper can start a local wg-only
    demo stack (`--start-local-stack auto`, default behavior).
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

print_cmd() {
  local line=""
  local arg
  for arg in "$@"; do
    line+=$(printf '%q ' "$arg")
  done
  line="$(printf '%s' "$line" | sed -E 's/(--campaign-subject )[^ ]+/\1[redacted]/g; s/(--subject )[^ ]+/\1[redacted]/g; s/(--key )[^ ]+/\1[redacted]/g; s/(--invite-key )[^ ]+/\1[redacted]/g; s/(--campaign-anon-cred )[^ ]+/\1[redacted]/g; s/(--anon-cred )[^ ]+/\1[redacted]/g; s/(--token )[^ ]+/\1[redacted]/g; s/(--auth-token )[^ ]+/\1[redacted]/g; s/(--admin-token )[^ ]+/\1[redacted]/g; s/(--authorization )[^ ]+/\1[redacted]/g; s/(--bearer )[^ ]+/\1[redacted]/g; s/(--campaign-subject=)[^ ]+/\1[redacted]/g; s/(--subject=)[^ ]+/\1[redacted]/g; s/(--key=)[^ ]+/\1[redacted]/g; s/(--invite-key=)[^ ]+/\1[redacted]/g; s/(--campaign-anon-cred=)[^ ]+/\1[redacted]/g; s/(--anon-cred=)[^ ]+/\1[redacted]/g; s/(--token=)[^ ]+/\1[redacted]/g; s/(--auth-token=)[^ ]+/\1[redacted]/g; s/(--admin-token=)[^ ]+/\1[redacted]/g; s/(--authorization=)[^ ]+/\1[redacted]/g; s/(--bearer=)[^ ]+/\1[redacted]/g')"
  printf '%s\n' "$line"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

tri_state_or_die() {
  local name="$1"
  local value="$2"
  case "$value" in
    auto|0|1) ;;
    *)
      echo "$name must be one of: auto, 0, 1"
      exit 2
      ;;
  esac
}

host_is_loopback_local() {
  local host="${1:-}"
  host="${host#[}"
  host="${host%]}"
  case "$host" in
    127.0.0.1|localhost|::1)
      return 0
      ;;
  esac
  return 1
}

url_host_from_endpoint() {
  local raw="${1:-}"
  local rest hostport host

  if [[ -z "$raw" ]]; then
    printf '%s\n' ""
    return 0
  fi

  if [[ "$raw" == *"://"* ]]; then
    rest="${raw#*://}"
  else
    rest="$raw"
  fi
  hostport="${rest%%/*}"
  hostport="${hostport##*@}"

  if [[ "$hostport" == \[*\]* ]]; then
    host="${hostport#\[}"
    host="${host%%]*}"
    printf '%s\n' "$host"
    return 0
  fi

  host="${hostport%%:*}"
  printf '%s\n' "$host"
}

url_is_non_loopback_host() {
  local host
  host="$(url_host_from_endpoint "${1:-}")"
  if [[ -z "$host" ]]; then
    return 1
  fi
  if host_is_loopback_local "$host"; then
    return 1
  fi
  return 0
}

url_csv_has_non_loopback_host() {
  local csv="$1"
  local item
  IFS=',' read -r -a items <<<"$csv"
  for item in "${items[@]}"; do
    item="$(trim "$item")"
    [[ -z "$item" ]] && continue
    if url_is_non_loopback_host "$item"; then
      return 0
    fi
  done
  return 1
}

rewrite_loopback_url_for_docker_local() {
  local raw="$1"
  local docker_host="${2:-host.docker.internal}"
  local scheme rest hostport host port path

  scheme="${raw%%://*}"
  if [[ "$scheme" == "$raw" ]]; then
    printf '%s\n' "$raw"
    return 0
  fi
  rest="${raw#*://}"
  hostport="${rest%%/*}"
  if [[ "$rest" == */* ]]; then
    path="/${rest#*/}"
  else
    path=""
  fi

  host="$hostport"
  if [[ "$hostport" == \[*\]:* ]]; then
    host="${hostport%%]:*}]"
    host="${host#[}"
    port="${hostport##*]:}"
  elif [[ "$hostport" == *:* ]]; then
    host="${hostport%%:*}"
    port="${hostport##*:}"
  else
    printf '%s\n' "$raw"
    return 0
  fi

  if ! host_is_loopback_local "$host"; then
    printf '%s\n' "$raw"
    return 0
  fi

  printf '%s://%s:%s%s\n' "$scheme" "$docker_host" "$port" "$path"
}

rewrite_url_csv_for_docker_local() {
  local csv="$1"
  local docker_host="${2:-host.docker.internal}"
  local item rewritten joined=""
  IFS=',' read -r -a items <<<"$csv"
  for item in "${items[@]}"; do
    item="${item//[[:space:]]/}"
    [[ -z "$item" ]] && continue
    rewritten="$(rewrite_loopback_url_for_docker_local "$item" "$docker_host")"
    if [[ -n "$joined" ]]; then
      joined+=","
    fi
    joined+="$rewritten"
  done
  printf '%s\n' "$joined"
}

normalize_path_profile_local() {
  local profile
  profile="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$profile" in
    "") printf '%s\n' "" ;;
    speed) printf '%s\n' "speed" ;;
    speed-1hop|speed1hop|fast-1hop|fast1hop|onehop|1hop|1-hop|hop1|hop-1) printf '%s\n' "speed-1hop" ;;
    balanced|2hop|2-hop|hop2|hop-2|twohop) printf '%s\n' "balanced" ;;
    private|privacy|3hop|3-hop|hop3|hop-3|threehop) printf '%s\n' "private" ;;
    fast) printf '%s\n' "speed" ;;
    *) return 1 ;;
  esac
}

count_matches() {
  local pattern="$1"
  local file="$2"
  local count="0"
  if [[ -n "$file" && -f "$file" ]]; then
    count="$(rg -c -- "$pattern" "$file" 2>/dev/null || true)"
  fi
  count="${count:-0}"
  if ! [[ "$count" =~ ^[0-9]+$ ]]; then
    count="0"
  fi
  printf '%s\n' "$count"
}

extract_metric_from_line() {
  local line="$1"
  local key="$2"
  local value
  value="$(printf '%s\n' "$line" | sed -nE "s/.*${key}=([0-9]+).*/\\1/p")"
  if [[ -z "$value" || ! "$value" =~ ^[0-9]+$ ]]; then
    value="0"
  fi
  printf '%s\n' "$value"
}

prepare_log_dir() {
  local dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
  mkdir -p "$dir"
  printf '%s\n' "$dir"
}

original_args=("$@")

profiles_csv="balanced,speed,private,speed-1hop"
rounds="3"
timeout_sec="35"
execution_mode="${PROFILE_COMPARE_LOCAL_CLIENT_TEST_MODE:-local}"
docker_host_alias="${PROFILE_COMPARE_LOCAL_DOCKER_HOST_ALIAS:-host.docker.internal}"
directory_urls=""
bootstrap_directory=""
discovery_wait_sec="20"
issuer_url=""
entry_url=""
exit_url=""
subject=""
anon_cred=""
min_sources="1"
beta_profile="0"
prod_profile="0"
start_local_stack="auto"
force_stack_reset="1"
stack_strict_beta="0"
base_port="${PROFILE_COMPARE_LOCAL_BASE_PORT:-19280}"
client_iface="${PROFILE_COMPARE_LOCAL_CLIENT_IFACE:-wgcstack0}"
exit_iface="${PROFILE_COMPARE_LOCAL_EXIT_IFACE:-wgestack0}"
cleanup_ifaces="1"
keep_stack="0"
summary_json=""
report_md=""
print_summary_json="0"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profiles)
      profiles_csv="${2:-}"
      shift 2
      ;;
    --rounds)
      rounds="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      timeout_sec="${2:-}"
      shift 2
      ;;
    --execution-mode)
      execution_mode="${2:-}"
      shift 2
      ;;
    --directory-urls)
      directory_urls="${2:-}"
      shift 2
      ;;
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --discovery-wait-sec)
      discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --issuer-url)
      issuer_url="${2:-}"
      shift 2
      ;;
    --entry-url)
      entry_url="${2:-}"
      shift 2
      ;;
    --exit-url)
      exit_url="${2:-}"
      shift 2
      ;;
    --subject)
      subject="${2:-}"
      shift 2
      ;;
    --anon-cred)
      anon_cred="${2:-}"
      shift 2
      ;;
    --min-sources)
      min_sources="${2:-}"
      shift 2
      ;;
    --beta-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        beta_profile="${2:-}"
        shift 2
      else
        beta_profile="1"
        shift
      fi
      ;;
    --prod-profile)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        prod_profile="${2:-}"
        shift 2
      else
        prod_profile="1"
        shift
      fi
      ;;
    --start-local-stack)
      start_local_stack="${2:-}"
      shift 2
      ;;
    --force-stack-reset)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        force_stack_reset="${2:-}"
        shift 2
      else
        force_stack_reset="1"
        shift
      fi
      ;;
    --stack-strict-beta)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        stack_strict_beta="${2:-}"
        shift 2
      else
        stack_strict_beta="1"
        shift
      fi
      ;;
    --base-port)
      base_port="${2:-}"
      shift 2
      ;;
    --client-iface)
      client_iface="${2:-}"
      shift 2
      ;;
    --exit-iface)
      exit_iface="${2:-}"
      shift 2
      ;;
    --cleanup-ifaces)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        cleanup_ifaces="${2:-}"
        shift 2
      else
        cleanup_ifaces="1"
        shift
      fi
      ;;
    --keep-stack)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        keep_stack="${2:-}"
        shift 2
      else
        keep_stack="1"
        shift
      fi
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--force-stack-reset" "$force_stack_reset"
bool_arg_or_die "--stack-strict-beta" "$stack_strict_beta"
bool_arg_or_die "--cleanup-ifaces" "$cleanup_ifaces"
bool_arg_or_die "--keep-stack" "$keep_stack"
tri_state_or_die "--start-local-stack" "$start_local_stack"

if [[ "$beta_profile" != "0" && "$beta_profile" != "1" ]]; then
  echo "--beta-profile must be 0 or 1"
  exit 2
fi
if [[ "$prod_profile" != "0" && "$prod_profile" != "1" ]]; then
  echo "--prod-profile must be 0 or 1"
  exit 2
fi
if [[ "$prod_profile" == "1" ]]; then
  beta_profile="1"
fi

if ! [[ "$rounds" =~ ^[0-9]+$ ]] || ((rounds < 1)); then
  echo "--rounds must be >= 1"
  exit 2
fi
if ! [[ "$timeout_sec" =~ ^[0-9]+$ ]] || ((timeout_sec < 5)); then
  echo "--timeout-sec must be >= 5"
  exit 2
fi
if ! [[ "$discovery_wait_sec" =~ ^[0-9]+$ ]] || ((discovery_wait_sec < 1)); then
  echo "--discovery-wait-sec must be >= 1"
  exit 2
fi
if ! [[ "$min_sources" =~ ^[0-9]+$ ]] || ((min_sources < 1)); then
  echo "--min-sources must be >= 1"
  exit 2
fi
if ! [[ "$base_port" =~ ^[0-9]+$ ]] || ((base_port < 1024 || base_port > 65400)); then
  echo "--base-port must be in 1024..65400"
  exit 2
fi
if [[ -z "$client_iface" || -z "$exit_iface" ]]; then
  echo "--client-iface and --exit-iface must be non-empty"
  exit 2
fi
if [[ "$execution_mode" != "docker" && "$execution_mode" != "local" ]]; then
  echo "--execution-mode must be docker or local"
  exit 2
fi
if [[ -z "$docker_host_alias" ]]; then
  echo "PROFILE_COMPARE_LOCAL_DOCKER_HOST_ALIAS must be non-empty when execution mode is docker"
  exit 2
fi
if [[ -n "$subject" && -n "$anon_cred" ]]; then
  echo "provide only one of --subject or --anon-cred"
  exit 2
fi

IFS=',' read -r -a raw_profiles <<<"$profiles_csv"
declare -a profiles=()
declare -A seen_profiles=()
for raw_profile in "${raw_profiles[@]}"; do
  candidate="$(trim "$raw_profile")"
  [[ -z "$candidate" ]] && continue
  normalized="$(normalize_path_profile_local "$candidate" || true)"
  if [[ -z "$normalized" ]]; then
    echo "invalid profile in --profiles: $candidate"
    echo "allowed: 1hop, 2hop, 3hop, speed, balanced, private, speed-1hop (aliases: fast, privacy, onehop)"
    exit 2
  fi
  if [[ -n "${seen_profiles[$normalized]:-}" ]]; then
    continue
  fi
  seen_profiles["$normalized"]="1"
  profiles+=("$normalized")
done
if [[ ${#profiles[@]} -eq 0 ]]; then
  echo "--profiles must include at least one profile"
  exit 2
fi

profile_inputs_json="$(printf '%s\n' "${profiles[@]}" | jq -R . | jq -s '.')"

log_dir="$(prepare_log_dir)"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$log_dir/profile_compare_local_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$report_md" ]]; then
  report_md="$log_dir/profile_compare_local_${run_stamp}.md"
else
  report_md="$(abs_path "$report_md")"
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

summary_log="$log_dir/profile_compare_local_${run_stamp}.log"
: >"$summary_log"

easy_node_script="${PROFILE_COMPARE_LOCAL_EASY_NODE_SCRIPT:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$easy_node_script" ]]; then
  echo "missing easy_node helper script: $easy_node_script"
  exit 2
fi

started_local_stack="0"
stack_bootstrap_log=""

cleanup_local_stack() {
  if [[ "$started_local_stack" == "1" && "$keep_stack" == "0" ]]; then
    "$easy_node_script" wg-only-stack-down \
      --force-iface-cleanup "$cleanup_ifaces" \
      --base-port "$base_port" \
      --client-iface "$client_iface" \
      --exit-iface "$exit_iface" >/dev/null 2>&1 || true
  fi
}
trap cleanup_local_stack EXIT INT TERM

explicit_endpoints=0
if [[ -n "$directory_urls" || -n "$bootstrap_directory" || -n "$issuer_url" || -n "$entry_url" || -n "$exit_url" ]]; then
  explicit_endpoints=1
fi

explicit_remote_endpoints=0
if [[ -n "$directory_urls" ]] && url_csv_has_non_loopback_host "$directory_urls"; then
  explicit_remote_endpoints=1
fi
if [[ "$explicit_remote_endpoints" == "0" && -n "$bootstrap_directory" ]] && url_is_non_loopback_host "$bootstrap_directory"; then
  explicit_remote_endpoints=1
fi
if [[ "$explicit_remote_endpoints" == "0" && -n "$issuer_url" ]] && url_is_non_loopback_host "$issuer_url"; then
  explicit_remote_endpoints=1
fi
if [[ "$explicit_remote_endpoints" == "0" && -n "$entry_url" ]] && url_is_non_loopback_host "$entry_url"; then
  explicit_remote_endpoints=1
fi
if [[ "$explicit_remote_endpoints" == "0" && -n "$exit_url" ]] && url_is_non_loopback_host "$exit_url"; then
  explicit_remote_endpoints=1
fi

transport_auto_client_inner_source="0"
transport_auto_disable_synthetic_fallback="0"
transport_auto_data_plane_mode_opaque="0"
if [[ "$explicit_remote_endpoints" == "1" ]]; then
  if [[ -z "${CLIENT_INNER_SOURCE+x}" ]]; then
    transport_auto_client_inner_source="1"
  fi
  if [[ -z "${CLIENT_DISABLE_SYNTHETIC_FALLBACK+x}" ]]; then
    transport_auto_disable_synthetic_fallback="1"
  fi
  if [[ -z "${DATA_PLANE_MODE+x}" ]]; then
    transport_auto_data_plane_mode_opaque="1"
  fi
fi
if [[ "$start_local_stack" == "auto" ]]; then
  if [[ "$explicit_endpoints" == "1" ]]; then
    start_local_stack="0"
  else
    start_local_stack="1"
  fi
fi

if [[ "$start_local_stack" == "1" ]]; then
  if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    echo "--start-local-stack=1 requires root (run with sudo)"
    exit 2
  fi
  if [[ "$force_stack_reset" == "1" ]]; then
    "$easy_node_script" wg-only-stack-down \
      --force-iface-cleanup "$cleanup_ifaces" \
      --base-port "$base_port" \
      --client-iface "$client_iface" \
      --exit-iface "$exit_iface" >/dev/null 2>&1 || true
  fi

  stack_bootstrap_log="$log_dir/profile_compare_local_stack_bootstrap_${run_stamp}.log"
  if ! "$easy_node_script" wg-only-stack-up \
    --strict-beta "$stack_strict_beta" \
    --detach 1 \
    --base-port "$base_port" \
    --client-iface "$client_iface" \
    --exit-iface "$exit_iface" \
    --control-bind-host 127.0.0.1 \
    --force-iface-reset 1 \
    --cleanup-ifaces "$cleanup_ifaces" >"$stack_bootstrap_log" 2>&1; then
    echo "profile-compare-local failed to start local wg-only stack"
    cat "$stack_bootstrap_log"
    exit 1
  fi

  started_local_stack="1"
  directory_urls="http://127.0.0.1:$((base_port + 1))"
  issuer_url="http://127.0.0.1:$((base_port + 2))"
  entry_url="http://127.0.0.1:$((base_port + 3))"
  exit_url="http://127.0.0.1:$((base_port + 4))"
  bootstrap_directory=""
fi

if [[ -z "$directory_urls" && -z "$bootstrap_directory" ]]; then
  echo "profile-compare-local requires --directory-urls or --bootstrap-directory (or --start-local-stack 1)"
  exit 2
fi
if [[ -z "$bootstrap_directory" && ( -z "$issuer_url" || -z "$entry_url" || -z "$exit_url" ) ]]; then
  echo "when --bootstrap-directory is not provided, --issuer-url/--entry-url/--exit-url are required"
  exit 2
fi

runs_file="$(mktemp)"
trap 'rm -f "$runs_file"; cleanup_local_stack' EXIT INT TERM

append_run_record() {
  local profile="$1"
  local round="$2"
  local status="$3"
  local rc="$4"
  local duration_sec="$5"
  local selection_count="$6"
  local entry_operator_count="$7"
  local exit_operator_count="$8"
  local cross_pair_count="$9"
  local same_operator_count="${10}"
  local missing_operator_count="${11}"
  local bootstrap_failures="${12}"
  local wg_session_count="${13}"
  local direct_exit_mode_events="${14}"
  local direct_exit_fallback_events="${15}"
  local transport_mismatch_failures="${16}"
  local token_proof_invalid_failures="${17}"
  local unknown_exit_failures="${18}"
  local directory_trust_failures="${19}"
  local direct_exit_forced="${20}"
  local output_log="${21}"
  local client_log="${22}"
  local command="${23}"
  local skip_reason="${24}"

  jq -n \
    --arg profile "$profile" \
    --argjson round "$round" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --argjson duration_sec "$duration_sec" \
    --argjson selection_count "$selection_count" \
    --argjson entry_operator_count "$entry_operator_count" \
    --argjson exit_operator_count "$exit_operator_count" \
    --argjson cross_pair_count "$cross_pair_count" \
    --argjson same_operator_count "$same_operator_count" \
    --argjson missing_operator_count "$missing_operator_count" \
    --argjson bootstrap_failures "$bootstrap_failures" \
    --argjson wg_session_count "$wg_session_count" \
    --argjson direct_exit_mode_events "$direct_exit_mode_events" \
    --argjson direct_exit_fallback_events "$direct_exit_fallback_events" \
    --argjson transport_mismatch_failures "$transport_mismatch_failures" \
    --argjson token_proof_invalid_failures "$token_proof_invalid_failures" \
    --argjson unknown_exit_failures "$unknown_exit_failures" \
    --argjson directory_trust_failures "$directory_trust_failures" \
    --arg direct_exit_forced "$direct_exit_forced" \
    --arg output_log "$output_log" \
    --arg client_log "$client_log" \
    --arg command "$command" \
    --arg skip_reason "$skip_reason" \
    '{
      profile: $profile,
      round: $round,
      status: $status,
      rc: $rc,
      duration_sec: $duration_sec,
      selection_count: $selection_count,
      entry_operator_count: $entry_operator_count,
      exit_operator_count: $exit_operator_count,
      cross_pair_count: $cross_pair_count,
      same_operator_count: $same_operator_count,
      missing_operator_count: $missing_operator_count,
      bootstrap_failures: $bootstrap_failures,
      wg_session_count: $wg_session_count,
      direct_exit_mode_events: $direct_exit_mode_events,
      direct_exit_fallback_events: $direct_exit_fallback_events,
      transport_mismatch_failures: $transport_mismatch_failures,
      token_proof_invalid_failures: $token_proof_invalid_failures,
      unknown_exit_failures: $unknown_exit_failures,
      directory_trust_failures: $directory_trust_failures,
      direct_exit_forced: ($direct_exit_forced == "true"),
      output_log: $output_log,
      client_log: $client_log,
      command: $command,
      skip_reason: $skip_reason
    }' >>"$runs_file"
}

for profile in "${profiles[@]}"; do
  for round_idx in $(seq 1 "$rounds"); do
    run_output_log="$log_dir/profile_compare_local_${run_stamp}_${profile}_r${round_idx}.log"
    : >"$run_output_log"

    skip_reason=""
    if [[ "$profile" == "speed-1hop" && ( "$beta_profile" == "1" || "$prod_profile" == "1" ) ]]; then
      skip_reason="speed-1hop is experimental and requires --beta-profile 0 --prod-profile 0"
    fi

    if [[ -n "$skip_reason" ]]; then
      echo "[profile-compare-local] profile=$profile round=$round_idx status=skip reason=$skip_reason" | tee -a "$summary_log"
      append_run_record "$profile" "$round_idx" "skip" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "0" "false" "$run_output_log" "" "" "$skip_reason"
      continue
    fi

    container_directory_urls="$directory_urls"
    container_issuer_url="$issuer_url"
    container_entry_url="$entry_url"
    container_exit_url="$exit_url"
    if [[ "$execution_mode" == "docker" ]]; then
      container_directory_urls="$(rewrite_url_csv_for_docker_local "$directory_urls" "$docker_host_alias")"
      container_issuer_url="$(rewrite_loopback_url_for_docker_local "$issuer_url" "$docker_host_alias")"
      container_entry_url="$(rewrite_loopback_url_for_docker_local "$entry_url" "$docker_host_alias")"
      container_exit_url="$(rewrite_loopback_url_for_docker_local "$exit_url" "$docker_host_alias")"
    fi

    run_cmd_env=(
      "EASY_NODE_CLIENT_TEST_MODE=$execution_mode"
      "EASY_NODE_CLIENT_TEST_CONTAINER_DIRECTORY_URLS=$container_directory_urls"
      "EASY_NODE_CLIENT_TEST_CONTAINER_ISSUER_URL=$container_issuer_url"
      "EASY_NODE_CLIENT_TEST_CONTAINER_ENTRY_URL=$container_entry_url"
      "EASY_NODE_CLIENT_TEST_CONTAINER_EXIT_URL=$container_exit_url"
    )
    if [[ "$transport_auto_client_inner_source" == "1" ]]; then
      run_cmd_env+=("CLIENT_INNER_SOURCE=udp")
    fi
    if [[ "$transport_auto_disable_synthetic_fallback" == "1" ]]; then
      run_cmd_env+=("CLIENT_DISABLE_SYNTHETIC_FALLBACK=1")
    fi
    if [[ "$transport_auto_data_plane_mode_opaque" == "1" ]]; then
      run_cmd_env+=("DATA_PLANE_MODE=opaque")
    fi
    run_cmd=(
      env
      "${run_cmd_env[@]}"
      "$easy_node_script"
      client-test
    )

    if [[ -n "$directory_urls" ]]; then
      run_cmd+=(--directory-urls "$directory_urls")
    fi
    if [[ -n "$bootstrap_directory" ]]; then
      run_cmd+=(--bootstrap-directory "$bootstrap_directory" --discovery-wait-sec "$discovery_wait_sec")
    fi
    if [[ -n "$issuer_url" ]]; then
      run_cmd+=(--issuer-url "$issuer_url")
    fi
    if [[ -n "$entry_url" ]]; then
      run_cmd+=(--entry-url "$entry_url")
    fi
    if [[ -n "$exit_url" ]]; then
      run_cmd+=(--exit-url "$exit_url")
    fi
    if [[ -n "$subject" ]]; then
      run_cmd+=(--subject "$subject")
    fi
    if [[ -n "$anon_cred" ]]; then
      run_cmd+=(--anon-cred "$anon_cred")
    fi

    run_cmd+=(
      --min-sources "$min_sources"
      --timeout-sec "$timeout_sec"
      --path-profile "$profile"
      --min-selection-lines 1
      --min-entry-operators 1
      --min-exit-operators 1
      --require-cross-operator-pair 0
      --beta-profile "$beta_profile"
      --prod-profile "$prod_profile"
    )

    run_cmd_str="$(print_cmd "${run_cmd[@]}")"

    start_sec="$(date +%s)"
    if "${run_cmd[@]}" >"$run_output_log" 2>&1; then
      run_rc=0
      run_status="pass"
    else
      run_rc=$?
      run_status="fail"
    fi
    end_sec="$(date +%s)"
    duration_sec=$((end_sec - start_sec))

    client_log_path="$(awk -F'client test log: ' '/client test log:/ {print $2}' "$run_output_log" | tail -n 1 | tr -d '\r')"
    client_log_path="$(trim "$client_log_path")"
    if [[ -n "$client_log_path" && "$client_log_path" != /* && -f "$ROOT_DIR/$client_log_path" ]]; then
      client_log_path="$ROOT_DIR/$client_log_path"
    fi

    parse_log="$run_output_log"
    if [[ -n "$client_log_path" && -f "$client_log_path" ]]; then
      parse_log="$client_log_path"
    fi

    selection_line="$(rg 'client selection summary:' "$run_output_log" | tail -n 1 || true)"
    selection_count="$(extract_metric_from_line "$selection_line" "selections")"
    entry_operator_count="$(extract_metric_from_line "$selection_line" "entry_ops")"
    exit_operator_count="$(extract_metric_from_line "$selection_line" "exit_ops")"
    cross_pair_count="$(extract_metric_from_line "$selection_line" "cross_pairs")"
    same_operator_count="$(extract_metric_from_line "$selection_line" "same_ops")"
    missing_operator_count="$(extract_metric_from_line "$selection_line" "missing_ops")"

    if [[ "$selection_count" == "0" ]]; then
      selection_count="$(count_matches 'client selected entry=' "$parse_log")"
    fi

    bootstrap_failures="$(count_matches 'client bootstrap (failed|retry failed):' "$parse_log")"
    wg_session_count="$(count_matches 'client received wg-session config:' "$parse_log")"
    direct_exit_mode_events="$(count_matches 'client direct-exit mode engaged' "$parse_log")"
    direct_exit_fallback_events="$(count_matches 'client direct-exit fallback engaged' "$parse_log")"
    transport_mismatch_failures="$(count_matches 'transport must be wireguard-udp in entry live mode' "$parse_log")"
    token_proof_invalid_failures="$(count_matches 'token proof invalid' "$parse_log")"
    unknown_exit_failures="$(count_matches 'path open denied: unknown-exit' "$parse_log")"
    directory_trust_failures="$(count_matches 'directory key is not trusted' "$parse_log")"

    direct_exit_forced="false"
    startup_line="$(rg -m 1 'client role enabled:' "$parse_log" || true)"
    if printf '%s\n' "$startup_line" | rg -q 'direct_exit_forced=true'; then
      direct_exit_forced="true"
    fi

    echo "[profile-compare-local] profile=$profile round=$round_idx status=$run_status rc=$run_rc duration_sec=$duration_sec selection_count=$selection_count bootstrap_failures=$bootstrap_failures log=$run_output_log" | tee -a "$summary_log"

    append_run_record \
      "$profile" "$round_idx" "$run_status" "$run_rc" "$duration_sec" \
      "$selection_count" "$entry_operator_count" "$exit_operator_count" "$cross_pair_count" \
      "$same_operator_count" "$missing_operator_count" "$bootstrap_failures" "$wg_session_count" \
      "$direct_exit_mode_events" "$direct_exit_fallback_events" \
      "$transport_mismatch_failures" "$token_proof_invalid_failures" "$unknown_exit_failures" "$directory_trust_failures" \
      "$direct_exit_forced" \
      "$run_output_log" "$client_log_path" "$run_cmd_str" ""
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
          avg_bootstrap_failures: (if ($executed | length) == 0 then 0 else (($executed | map(.bootstrap_failures) | add) / ($executed | length)) end),
          avg_selection_count: (if ($executed | length) == 0 then 0 else (($executed | map(.selection_count) | add) / ($executed | length)) end),
          avg_entry_operator_count: (if ($executed | length) == 0 then 0 else (($executed | map(.entry_operator_count) | add) / ($executed | length)) end),
          avg_exit_operator_count: (if ($executed | length) == 0 then 0 else (($executed | map(.exit_operator_count) | add) / ($executed | length)) end),
          avg_cross_pair_count: (if ($executed | length) == 0 then 0 else (($executed | map(.cross_pair_count) | add) / ($executed | length)) end),
          avg_transport_mismatch_failures: (if ($executed | length) == 0 then 0 else (($executed | map(.transport_mismatch_failures) | add) / ($executed | length)) end),
          avg_token_proof_invalid_failures: (if ($executed | length) == 0 then 0 else (($executed | map(.token_proof_invalid_failures) | add) / ($executed | length)) end),
          avg_unknown_exit_failures: (if ($executed | length) == 0 then 0 else (($executed | map(.unknown_exit_failures) | add) / ($executed | length)) end),
          avg_directory_trust_failures: (if ($executed | length) == 0 then 0 else (($executed | map(.directory_trust_failures) | add) / ($executed | length)) end),
          direct_exit_forced_runs: ($executed | map(select(.direct_exit_forced == true)) | length),
          direct_exit_mode_events: ($executed | map(.direct_exit_mode_events) | add // 0),
          direct_exit_fallback_events: ($executed | map(.direct_exit_fallback_events) | add // 0),
          skip_reasons: ($runs | map(select(.status == "skip" and (.skip_reason | length) > 0) | .skip_reason) | unique)
        }
    )
' <<<"$runs_json")"

runs_total="$(jq 'length' <<<"$runs_json")"
runs_executed="$(jq '[.[] | select(.status != "skip")] | length' <<<"$runs_json")"
runs_pass="$(jq '[.[] | select(.status == "pass")] | length' <<<"$runs_json")"
runs_fail="$(jq '[.[] | select(.status == "fail")] | length' <<<"$runs_json")"
runs_skipped="$(jq '[.[] | select(.status == "skip")] | length' <<<"$runs_json")"
transport_mismatch_failures_total="$(jq '[.[] | (.transport_mismatch_failures // 0)] | add // 0' <<<"$runs_json")"
token_proof_invalid_failures_total="$(jq '[.[] | (.token_proof_invalid_failures // 0)] | add // 0' <<<"$runs_json")"
unknown_exit_failures_total="$(jq '[.[] | (.unknown_exit_failures // 0)] | add // 0' <<<"$runs_json")"
directory_trust_failures_total="$(jq '[.[] | (.directory_trust_failures // 0)] | add // 0' <<<"$runs_json")"

best_non_experimental_profile="$(jq -r '
  map(select(.profile != "speed-1hop" and .runs_executed > 0))
  | sort_by([.runs_fail, (-.pass_rate_pct), .avg_duration_sec, .profile])
  | (.[0].profile // "")
' <<<"$profile_summary_json")"

balanced_eligible="0"
balanced_avg_duration="0"
if jq -e 'map(select(.profile == "balanced" and .runs_executed > 0 and .runs_fail == 0)) | length > 0' <<<"$profile_summary_json" >/dev/null 2>&1; then
  balanced_eligible="1"
  balanced_avg_duration="$(jq -r 'map(select(.profile == "balanced"))[0].avg_duration_sec // 0' <<<"$profile_summary_json")"
fi

recommended_default_profile=""
decision_reason=""
comparison_policy_note="prefer balanced unless another non-experimental profile is >15% faster with equivalent reliability"

if [[ -n "$best_non_experimental_profile" ]]; then
  if [[ "$balanced_eligible" == "1" ]]; then
    best_avg_duration="$(jq -r --arg p "$best_non_experimental_profile" 'map(select(.profile == $p))[0].avg_duration_sec // 0' <<<"$profile_summary_json")"
    if [[ "$best_non_experimental_profile" != "balanced" ]] && awk -v bal="$balanced_avg_duration" -v best="$best_avg_duration" 'BEGIN { exit !(best > 0 && bal > (best * 1.15)) }'; then
      recommended_default_profile="$best_non_experimental_profile"
      decision_reason="$best_non_experimental_profile is materially faster (>15%) while balanced remains reliable; consider pilot default review."
    else
      recommended_default_profile="balanced"
      decision_reason="balanced remains within 15% of fastest reliable profile and preserves the 2-hop privacy baseline."
    fi
  else
    recommended_default_profile="$best_non_experimental_profile"
    decision_reason="balanced did not meet reliability criteria in this run; using best available non-experimental profile."
  fi
else
  decision_reason="no executable non-experimental profile runs were available"
fi

if ((runs_executed == 0)); then
  status="fail"
  final_rc=1
  notes="No profile runs were executed"
elif ((runs_fail == 0)); then
  status="pass"
  final_rc=0
  notes="All executed profile runs passed"
elif ((runs_pass > 0)); then
  status="warn"
  final_rc=0
  notes="Some profile runs failed; review per-profile reliability before default changes"
else
  status="fail"
  final_rc=1
  notes="All executed profile runs failed"
fi

subject_redacted=""
if [[ -n "$subject" ]]; then
  subject_redacted="[redacted]"
fi
anon_cred_present="0"
if [[ -n "$anon_cred" ]]; then
  anon_cred_present="1"
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg command "$(print_cmd "$0" "${original_args[@]}")" \
  --arg summary_log "$summary_log" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --argjson rc "$final_rc" \
  --argjson rounds "$rounds" \
  --argjson timeout_sec "$timeout_sec" \
  --arg execution_mode "$execution_mode" \
  --arg docker_host_alias "$docker_host_alias" \
  --arg directory_urls "$directory_urls" \
  --arg bootstrap_directory "$bootstrap_directory" \
  --arg issuer_url "$issuer_url" \
  --arg entry_url "$entry_url" \
  --arg exit_url "$exit_url" \
  --arg subject "$subject_redacted" \
  --arg anon_cred_present "$anon_cred_present" \
  --arg min_sources "$min_sources" \
  --arg beta_profile "$beta_profile" \
  --arg prod_profile "$prod_profile" \
  --arg transport_auto_client_inner_source "$transport_auto_client_inner_source" \
  --arg transport_auto_disable_synthetic_fallback "$transport_auto_disable_synthetic_fallback" \
  --arg transport_auto_data_plane_mode_opaque "$transport_auto_data_plane_mode_opaque" \
  --arg explicit_remote_endpoints "$explicit_remote_endpoints" \
  --arg start_local_stack "$start_local_stack" \
  --argjson stack_started "$started_local_stack" \
  --arg stack_strict_beta "$stack_strict_beta" \
  --arg stack_bootstrap_log "$stack_bootstrap_log" \
  --arg base_port "$base_port" \
  --arg client_iface "$client_iface" \
  --arg exit_iface "$exit_iface" \
  --arg cleanup_ifaces "$cleanup_ifaces" \
  --arg keep_stack "$keep_stack" \
  --arg recommended_default_profile "$recommended_default_profile" \
  --arg decision_reason "$decision_reason" \
  --arg comparison_policy_note "$comparison_policy_note" \
  --argjson profiles "$profile_inputs_json" \
  --argjson profiles_summary "$profile_summary_json" \
  --argjson runs "$runs_json" \
  --argjson runs_total "$runs_total" \
  --argjson runs_executed "$runs_executed" \
  --argjson runs_pass "$runs_pass" \
  --argjson runs_fail "$runs_fail" \
  --argjson runs_skipped "$runs_skipped" \
  --argjson transport_mismatch_failures_total "$transport_mismatch_failures_total" \
  --argjson token_proof_invalid_failures_total "$token_proof_invalid_failures_total" \
  --argjson unknown_exit_failures_total "$unknown_exit_failures_total" \
  --argjson directory_trust_failures_total "$directory_trust_failures_total" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: $notes,
    command: $command,
    inputs: {
      profiles: $profiles,
      rounds: $rounds,
      timeout_sec: $timeout_sec,
      execution_mode: $execution_mode,
      docker_host_alias: $docker_host_alias,
      directory_urls: $directory_urls,
      bootstrap_directory: $bootstrap_directory,
      issuer_url: $issuer_url,
      entry_url: $entry_url,
      exit_url: $exit_url,
      subject: $subject,
      anon_cred_present: ($anon_cred_present == "1"),
      min_sources: ($min_sources | tonumber),
      beta_profile: ($beta_profile == "1"),
      prod_profile: ($prod_profile == "1"),
      explicit_remote_endpoints: ($explicit_remote_endpoints == "1"),
      transport_auto_defaults: {
        client_inner_source_udp: ($transport_auto_client_inner_source == "1"),
        disable_synthetic_fallback: ($transport_auto_disable_synthetic_fallback == "1"),
        data_plane_mode_opaque: ($transport_auto_data_plane_mode_opaque == "1")
      },
      start_local_stack: $start_local_stack,
      local_stack_started: ($stack_started == 1),
      local_stack: {
        strict_beta: ($stack_strict_beta == "1"),
        base_port: ($base_port | tonumber),
        client_iface: $client_iface,
        exit_iface: $exit_iface,
        cleanup_ifaces: ($cleanup_ifaces == "1"),
        keep_stack: ($keep_stack == "1")
      }
    },
    summary: {
      profiles_total: ($profiles | length),
      runs_total: $runs_total,
      runs_executed: $runs_executed,
      runs_pass: $runs_pass,
      runs_fail: $runs_fail,
      runs_skipped: $runs_skipped,
      transport_mismatch_failures_total: $transport_mismatch_failures_total,
      token_proof_invalid_failures_total: $token_proof_invalid_failures_total,
      unknown_exit_failures_total: $unknown_exit_failures_total,
      directory_trust_failures_total: $directory_trust_failures_total
    },
    decision: {
      recommended_default_profile: $recommended_default_profile,
      comparison_policy_note: $comparison_policy_note,
      rationale: $decision_reason,
      experimental_non_default_profiles: ["speed-1hop"]
    },
    profiles: $profiles_summary,
    runs: $runs,
    artifacts: {
      summary_log: $summary_log,
      summary_json: $summary_json,
      report_md: $report_md,
      stack_bootstrap_log: $stack_bootstrap_log
    }
  }' >"$summary_json"

{
  echo "# Local Profile Comparison Report"
  echo
  echo "- Generated at (UTC): \`$(jq -r '.generated_at_utc' "$summary_json")\`"
  echo "- Status: \`$(jq -r '.status' "$summary_json")\`"
  echo "- Summary JSON: \`$summary_json\`"
  echo "- Summary Log: \`$summary_log\`"
  if [[ -n "$stack_bootstrap_log" ]]; then
    echo "- Local stack bootstrap log: \`$stack_bootstrap_log\`"
  fi
  echo
  echo "## Decision"
  echo
  echo "- Recommended default: \`$(jq -r '.decision.recommended_default_profile // ""' "$summary_json")\`"
  echo "- Rationale: $(jq -r '.decision.rationale' "$summary_json")"
  echo "- Policy: $(jq -r '.decision.comparison_policy_note' "$summary_json")"
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
  echo "| Profile | Executed | Pass | Fail | Pass % | Avg Duration (s) | Avg Bootstrap Failures | Avg Selections | Direct-Exit Forced Runs |"
  echo "|---|---:|---:|---:|---:|---:|---:|---:|---:|"
  jq -r '.profiles[] | "| \(.profile) | \(.runs_executed) | \(.runs_pass) | \(.runs_fail) | \(.pass_rate_pct) | \(.avg_duration_sec) | \(.avg_bootstrap_failures) | \(.avg_selection_count) | \(.direct_exit_forced_runs) |"' "$summary_json"
} >"$report_md"

echo "profile-compare-local: status=$status"
echo "summary_log: $summary_log"
echo "summary_json: $summary_json"
echo "report_md: $report_md"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
