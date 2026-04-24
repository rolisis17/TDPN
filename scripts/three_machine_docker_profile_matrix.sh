#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/three_machine_docker_profile_matrix.sh \
    [--profiles CSV] \
    [--path-profiles CSV] \
    [--run-validate [0|1]] \
    [--run-soak [0|1]] \
    [--run-peer-failover [0|1]] \
    [--peer-failover-downtime-sec N] \
    [--peer-failover-timeout-sec N] \
    [--keep-stacks [0|1]] \
    [--reset-data [0|1]] \
    [--soak-rounds N] \
    [--soak-pause-sec N] \
    [--discovery-wait-sec N] \
    [--federation-timeout-sec N] \
    [--timeout-sec N] \
    [--min-sources N] \
    [--min-operators N] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--stack-a-base-port N] \
    [--stack-b-base-port N] \
    [--docker-host-alias HOST] \
    [--bootstrap-directory URL] \
    [--subject ID | --anon-cred TOKEN] \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]] \
    [--dry-run [0|1]]

Purpose:
  Run docker 3-machine readiness rehearsals across a path-profile matrix
  (default: 1hop,2hop,3hop), then emit aggregate JSON + markdown report
  artifacts under one reports directory.

Defaults tuned for resilience rehearsal:
  --profiles 1hop,2hop,3hop
  --run-peer-failover 1
  --run-validate 1
  --run-soak 1
  --keep-stacks 0

Notes:
  - Discovery wait is passed through via THREE_MACHINE_DISCOVERY_WAIT_SEC.
  - 1hop is auto-run with --beta-profile 0 and --prod-profile 0
    because strict/beta/prod client-test paths intentionally reject 1hop.
  - Wrapper exits non-zero when any profile run fails.
USAGE
}

trim() {
  local value="${1:-}"
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

int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer"
    exit 2
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

print_cmd() {
  local arg
  local redact_next=0
  for arg in "$@"; do
    if ((redact_next)); then
      printf '%q ' "[REDACTED]"
      redact_next=0
      continue
    fi
    case "$arg" in
      --anon-cred|--invite-key|--campaign-subject|--subject|--token|--auth-token|--admin-token|--authorization|--bearer)
        printf '%q ' "$arg"
        redact_next=1
        continue
        ;;
      --anon-cred=*|--invite-key=*|--campaign-subject=*|--subject=*|--token=*|--auth-token=*|--admin-token=*|--authorization=*|--bearer=*)
        printf '%q ' "${arg%%=*}=[REDACTED]"
        continue
        ;;
    esac
    printf '%q ' "$arg"
  done
  printf '\n'
}

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "$flag requires a value"
    exit 2
  fi
}

normalize_profile() {
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

append_profile_result() {
  local profile="$1"
  local status="$2"
  local readiness_rc="$3"
  local command_rc="$4"
  local notes="$5"
  local profile_summary_json="$6"
  local profile_log="$7"
  local command="$8"

  jq -cn \
    --arg profile "$profile" \
    --arg status "$status" \
    --argjson rc "$readiness_rc" \
    --argjson command_rc "$command_rc" \
    --arg notes "$notes" \
    --arg profile_summary_json "$profile_summary_json" \
    --arg profile_log "$profile_log" \
    --arg command "$command" \
    '{
      profile: $profile,
      status: $status,
      rc: $rc,
      command_rc: $command_rc,
      pass: ($status == "pass" and $rc == 0 and $command_rc == 0),
      notes: $notes,
      artifacts: {
        summary_json: $profile_summary_json,
        log: $profile_log
      },
      command: $command
    }'
}

need_cmd jq
need_cmd date
need_cmd mktemp

readiness_script="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_READINESS_SCRIPT:-$ROOT_DIR/scripts/three_machine_docker_readiness.sh}"
if [[ ! -x "$readiness_script" ]]; then
  echo "missing executable readiness script: $readiness_script"
  exit 2
fi

profiles_csv="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_PROFILES:-1hop,2hop,3hop}"
run_validate="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_RUN_VALIDATE:-1}"
run_soak="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_RUN_SOAK:-1}"
run_peer_failover="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_RUN_PEER_FAILOVER:-1}"
peer_failover_downtime_sec="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_PEER_FAILOVER_DOWNTIME_SEC:-8}"
peer_failover_timeout_sec="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_PEER_FAILOVER_TIMEOUT_SEC:-45}"
keep_stacks="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_KEEP_STACKS:-0}"
reset_data="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_RESET_DATA:-1}"
soak_rounds="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_SOAK_ROUNDS:-6}"
soak_pause_sec="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_SOAK_PAUSE_SEC:-3}"
discovery_wait_sec="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_DISCOVERY_WAIT_SEC:-12}"
federation_timeout_sec="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_FEDERATION_TIMEOUT_SEC:-90}"
timeout_sec="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_TIMEOUT_SEC:-45}"
min_sources="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_MIN_SOURCES:-2}"
min_operators="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_MIN_OPERATORS:-2}"
beta_profile="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_BETA_PROFILE:-1}"
prod_profile="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_PROD_PROFILE:-0}"
stack_a_base_port="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_STACK_A_BASE_PORT:-18080}"
stack_b_base_port="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_STACK_B_BASE_PORT:-28080}"
docker_host_alias="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_DOCKER_HOST_ALIAS:-${THREE_MACHINE_DOCKER_HOST_ALIAS:-host.docker.internal}}"
bootstrap_directory="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_BOOTSTRAP_DIRECTORY:-}"
subject="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_SUBJECT:-}"
anon_cred="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_ANON_CRED:-}"
reports_dir="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_REPORTS_DIR:-}"
summary_json="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_SUMMARY_JSON:-}"
report_md="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_REPORT_MD:-}"
print_summary_json="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_PRINT_SUMMARY_JSON:-0}"
dry_run="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_DRY_RUN:-0}"
profile_3hop_strict="${THREE_MACHINE_DOCKER_PROFILE_MATRIX_3HOP_STRICT:-0}"
original_args=("$@")

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profiles)
      require_value_or_die "$1" "${2:-}"
      profiles_csv="${2:-}"
      shift 2
      ;;
    --path-profiles)
      require_value_or_die "$1" "${2:-}"
      profiles_csv="${2:-}"
      shift 2
      ;;
    --run-validate)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_validate="${2:-}"
        shift 2
      else
        run_validate="1"
        shift
      fi
      ;;
    --run-soak)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_soak="${2:-}"
        shift 2
      else
        run_soak="1"
        shift
      fi
      ;;
    --run-peer-failover)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        run_peer_failover="${2:-}"
        shift 2
      else
        run_peer_failover="1"
        shift
      fi
      ;;
    --peer-failover-downtime-sec)
      require_value_or_die "$1" "${2:-}"
      peer_failover_downtime_sec="${2:-}"
      shift 2
      ;;
    --peer-failover-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      peer_failover_timeout_sec="${2:-}"
      shift 2
      ;;
    --keep-stacks)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        keep_stacks="${2:-}"
        shift 2
      else
        keep_stacks="1"
        shift
      fi
      ;;
    --reset-data)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        reset_data="${2:-}"
        shift 2
      else
        reset_data="1"
        shift
      fi
      ;;
    --soak-rounds)
      require_value_or_die "$1" "${2:-}"
      soak_rounds="${2:-}"
      shift 2
      ;;
    --soak-pause-sec)
      require_value_or_die "$1" "${2:-}"
      soak_pause_sec="${2:-}"
      shift 2
      ;;
    --discovery-wait-sec)
      require_value_or_die "$1" "${2:-}"
      discovery_wait_sec="${2:-}"
      shift 2
      ;;
    --federation-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      federation_timeout_sec="${2:-}"
      shift 2
      ;;
    --timeout-sec)
      require_value_or_die "$1" "${2:-}"
      timeout_sec="${2:-}"
      shift 2
      ;;
    --min-sources)
      require_value_or_die "$1" "${2:-}"
      min_sources="${2:-}"
      shift 2
      ;;
    --min-operators)
      require_value_or_die "$1" "${2:-}"
      min_operators="${2:-}"
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
    --stack-a-base-port)
      require_value_or_die "$1" "${2:-}"
      stack_a_base_port="${2:-}"
      shift 2
      ;;
    --stack-b-base-port)
      require_value_or_die "$1" "${2:-}"
      stack_b_base_port="${2:-}"
      shift 2
      ;;
    --docker-host-alias)
      require_value_or_die "$1" "${2:-}"
      docker_host_alias="${2:-}"
      shift 2
      ;;
    --bootstrap-directory)
      require_value_or_die "$1" "${2:-}"
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --subject)
      require_value_or_die "$1" "${2:-}"
      subject="${2:-}"
      shift 2
      ;;
    --anon-cred)
      require_value_or_die "$1" "${2:-}"
      anon_cred="${2:-}"
      shift 2
      ;;
    --reports-dir)
      require_value_or_die "$1" "${2:-}"
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      require_value_or_die "$1" "${2:-}"
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
    --dry-run)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        dry_run="${2:-}"
        shift 2
      else
        dry_run="1"
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

bool_arg_or_die "--run-validate" "$run_validate"
bool_arg_or_die "--run-soak" "$run_soak"
bool_arg_or_die "--run-peer-failover" "$run_peer_failover"
bool_arg_or_die "--keep-stacks" "$keep_stacks"
bool_arg_or_die "--reset-data" "$reset_data"
bool_arg_or_die "--beta-profile" "$beta_profile"
bool_arg_or_die "--prod-profile" "$prod_profile"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--dry-run" "$dry_run"
bool_arg_or_die "THREE_MACHINE_DOCKER_PROFILE_MATRIX_3HOP_STRICT" "$profile_3hop_strict"

int_arg_or_die "--peer-failover-downtime-sec" "$peer_failover_downtime_sec"
int_arg_or_die "--peer-failover-timeout-sec" "$peer_failover_timeout_sec"
int_arg_or_die "--soak-rounds" "$soak_rounds"
int_arg_or_die "--soak-pause-sec" "$soak_pause_sec"
int_arg_or_die "--discovery-wait-sec" "$discovery_wait_sec"
int_arg_or_die "--federation-timeout-sec" "$federation_timeout_sec"
int_arg_or_die "--timeout-sec" "$timeout_sec"
int_arg_or_die "--min-sources" "$min_sources"
int_arg_or_die "--min-operators" "$min_operators"
int_arg_or_die "--stack-a-base-port" "$stack_a_base_port"
int_arg_or_die "--stack-b-base-port" "$stack_b_base_port"

if [[ -n "$subject" && -n "$anon_cred" ]]; then
  echo "set only one of --subject or --anon-cred"
  exit 2
fi
if [[ -z "$docker_host_alias" ]]; then
  echo "--docker-host-alias must be non-empty"
  exit 2
fi
if (( stack_a_base_port < 1024 || stack_b_base_port < 1024 )); then
  echo "--stack-a-base-port and --stack-b-base-port must be >= 1024"
  exit 2
fi

declare -a profiles=()
IFS=',' read -r -a raw_profiles <<<"$profiles_csv"
for raw in "${raw_profiles[@]}"; do
  raw="$(trim "$raw")"
  [[ -z "$raw" ]] && continue
  normalized="$(normalize_profile "$raw" || true)"
  if [[ -z "$normalized" ]]; then
    echo "unknown profile in --profiles: $raw"
    echo "allowed: 1hop,2hop,3hop (aliases: speed,balanced,private,fast,privacy)"
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
if [[ "$keep_stacks" == "1" && "${#profiles[@]}" -gt 1 ]]; then
  echo "--keep-stacks 1 supports a single profile only (port reuse would conflict across matrix runs)"
  exit 2
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
log_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
mkdir -p "$log_dir"

if [[ -n "$reports_dir" ]]; then
  reports_dir="$(abs_path "$reports_dir")"
else
  reports_dir="$log_dir/three_machine_docker_profile_matrix_${run_stamp}"
fi
if [[ -n "$summary_json" ]]; then
  summary_json="$(abs_path "$summary_json")"
else
  summary_json="$reports_dir/three_machine_docker_profile_matrix_summary.json"
fi
if [[ -n "$report_md" ]]; then
  report_md="$(abs_path "$report_md")"
else
  report_md="$reports_dir/three_machine_docker_profile_matrix_report.md"
fi

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

matrix_log="$reports_dir/three_machine_docker_profile_matrix.log"
runs_file="$(mktemp)"
cleanup() {
  rm -f "$runs_file"
}
trap cleanup EXIT

: >"$matrix_log"

if [[ "$dry_run" == "1" ]]; then
  echo "three-machine-docker-profile-matrix: dry-run"
  echo "readiness_script: $readiness_script"
  echo "reports_dir: $reports_dir"
  echo "summary_json: $summary_json"
  echo "report_md: $report_md"
  for profile_idx in "${!profiles[@]}"; do
    profile="${profiles[$profile_idx]}"
    profile_reset_data="$reset_data"
    profile_distinct_operators="1"
    profile_beta_profile="$beta_profile"
    profile_prod_profile="$prod_profile"
    profile_relaxed_for_1hop="0"
    if [[ "$profile_reset_data" == "1" && "$profile_idx" -gt 0 ]]; then
      profile_reset_data="0"
    fi
    if [[ "$profile" == "1hop" && ( "$profile_beta_profile" != "0" || "$profile_prod_profile" != "0" ) ]]; then
      profile_beta_profile="0"
      profile_prod_profile="0"
      profile_relaxed_for_1hop="1"
    fi
    if [[ "$profile" == "1hop" ]]; then
      profile_distinct_operators="0"
    fi
    profile_summary_json="$reports_dir/three_machine_docker_readiness_${profile}.json"
    profile_log="$reports_dir/three_machine_docker_readiness_${profile}.log"
    run_cmd=(
      "$readiness_script"
      --path-profile "$profile"
      --run-validate "$run_validate"
      --run-soak "$run_soak"
      --run-peer-failover "$run_peer_failover"
      --peer-failover-downtime-sec "$peer_failover_downtime_sec"
      --peer-failover-timeout-sec "$peer_failover_timeout_sec"
      --soak-rounds "$soak_rounds"
      --soak-pause-sec "$soak_pause_sec"
      --keep-stacks "$keep_stacks"
      --reset-data "$profile_reset_data"
      --stack-a-base-port "$stack_a_base_port"
      --stack-b-base-port "$stack_b_base_port"
      --docker-host-alias "$docker_host_alias"
      --min-sources "$min_sources"
      --min-operators "$min_operators"
      --federation-timeout-sec "$federation_timeout_sec"
      --timeout-sec "$timeout_sec"
      --distinct-operators "$profile_distinct_operators"
      --beta-profile "$profile_beta_profile"
      --prod-profile "$profile_prod_profile"
      --summary-json "$profile_summary_json"
      --print-summary-json 0
    )
    if [[ -n "$subject" ]]; then
      run_cmd+=(--subject "$subject")
    fi
    if [[ -n "$anon_cred" ]]; then
      run_cmd+=(--anon-cred "$anon_cred")
    fi
    if [[ -n "$bootstrap_directory" ]]; then
      run_cmd+=(--bootstrap-directory "$bootstrap_directory")
    fi
    run_env=(
      "THREE_MACHINE_DISCOVERY_WAIT_SEC=$discovery_wait_sec"
    )
    if [[ "$profile" == "3hop" && "$profile_3hop_strict" != "1" ]]; then
      run_env+=(
        "CLIENT_REQUIRE_MIDDLE_RELAY=0"
        "THREE_MACHINE_DISTINCT_COUNTRIES=0"
      )
    fi
    if [[ "$profile_relaxed_for_1hop" == "1" ]]; then
      echo "[three-machine-docker-profile-matrix] profile=$profile forcing non-strict flags: --beta-profile 0 --prod-profile 0"
    fi
    if [[ "$profile" == "1hop" ]]; then
      echo "[three-machine-docker-profile-matrix] profile=$profile forcing direct-exit operator policy: --distinct-operators 0"
    fi
    printf 'profile=%s summary_json=%s log=%s\n' "$profile" "$profile_summary_json" "$profile_log"
    printf 'command: '
    print_cmd env "${run_env[@]}" "${run_cmd[@]}"
  done
  exit 0
fi

for profile_idx in "${!profiles[@]}"; do
  profile="${profiles[$profile_idx]}"
  profile_reset_data="$reset_data"
  profile_distinct_operators="1"
  profile_beta_profile="$beta_profile"
  profile_prod_profile="$prod_profile"
  profile_relaxed_for_1hop="0"
  if [[ "$profile_reset_data" == "1" && "$profile_idx" -gt 0 ]]; then
    profile_reset_data="0"
  fi
  if [[ "$profile" == "1hop" && ( "$profile_beta_profile" != "0" || "$profile_prod_profile" != "0" ) ]]; then
    profile_beta_profile="0"
    profile_prod_profile="0"
    profile_relaxed_for_1hop="1"
  fi
  if [[ "$profile" == "1hop" ]]; then
    profile_distinct_operators="0"
  fi
  profile_summary_json="$reports_dir/three_machine_docker_readiness_${profile}.json"
  profile_log="$reports_dir/three_machine_docker_readiness_${profile}.log"
  run_cmd=(
    "$readiness_script"
    --path-profile "$profile"
    --run-validate "$run_validate"
    --run-soak "$run_soak"
    --run-peer-failover "$run_peer_failover"
    --peer-failover-downtime-sec "$peer_failover_downtime_sec"
    --peer-failover-timeout-sec "$peer_failover_timeout_sec"
    --soak-rounds "$soak_rounds"
    --soak-pause-sec "$soak_pause_sec"
    --keep-stacks "$keep_stacks"
    --reset-data "$profile_reset_data"
    --stack-a-base-port "$stack_a_base_port"
    --stack-b-base-port "$stack_b_base_port"
    --docker-host-alias "$docker_host_alias"
    --min-sources "$min_sources"
    --min-operators "$min_operators"
    --federation-timeout-sec "$federation_timeout_sec"
    --timeout-sec "$timeout_sec"
    --distinct-operators "$profile_distinct_operators"
    --beta-profile "$profile_beta_profile"
    --prod-profile "$profile_prod_profile"
    --summary-json "$profile_summary_json"
    --print-summary-json 0
  )
  if [[ -n "$subject" ]]; then
    run_cmd+=(--subject "$subject")
  fi
  if [[ -n "$anon_cred" ]]; then
    run_cmd+=(--anon-cred "$anon_cred")
  fi
  if [[ -n "$bootstrap_directory" ]]; then
    run_cmd+=(--bootstrap-directory "$bootstrap_directory")
  fi

  run_env=(
    "THREE_MACHINE_DISCOVERY_WAIT_SEC=$discovery_wait_sec"
  )
  if [[ "$profile" == "3hop" && "$profile_3hop_strict" != "1" ]]; then
    run_env+=(
      "CLIENT_REQUIRE_MIDDLE_RELAY=0"
      "THREE_MACHINE_DISTINCT_COUNTRIES=0"
    )
  fi
  if [[ "$profile_relaxed_for_1hop" == "1" ]]; then
    echo "[three-machine-docker-profile-matrix] profile=$profile forcing non-strict flags: --beta-profile 0 --prod-profile 0" | tee -a "$matrix_log"
  fi
  if [[ "$profile" == "1hop" ]]; then
    echo "[three-machine-docker-profile-matrix] profile=$profile forcing direct-exit operator policy: --distinct-operators 0" | tee -a "$matrix_log"
  fi

  run_cmd_str="$(print_cmd env "${run_env[@]}" "${run_cmd[@]}")"
  echo "[three-machine-docker-profile-matrix] profile=$profile status=running" | tee -a "$matrix_log"
  set +e
  env "${run_env[@]}" "${run_cmd[@]}" >"$profile_log" 2>&1
  command_rc=$?
  set -e

  readiness_status=""
  readiness_rc="$command_rc"
  readiness_notes=""
  if [[ -f "$profile_summary_json" ]] && jq -e . "$profile_summary_json" >/dev/null 2>&1; then
    readiness_status="$(jq -r '.status // ""' "$profile_summary_json" 2>/dev/null || true)"
    readiness_rc_text="$(jq -r '.rc // empty' "$profile_summary_json" 2>/dev/null || true)"
    readiness_notes="$(jq -r '.notes // ""' "$profile_summary_json" 2>/dev/null || true)"
    if [[ -n "$readiness_rc_text" && "$readiness_rc_text" =~ ^[0-9]+$ ]]; then
      readiness_rc="$readiness_rc_text"
    fi
  fi
  if [[ -z "$readiness_status" ]]; then
    if [[ "$command_rc" == "0" ]]; then
      readiness_status="pass"
    else
      readiness_status="fail"
    fi
  fi
  if [[ -z "$readiness_notes" && "$command_rc" != "0" ]]; then
    readiness_notes="readiness command exited non-zero"
  fi

  append_profile_result \
    "$profile" \
    "$readiness_status" \
    "$readiness_rc" \
    "$command_rc" \
    "$readiness_notes" \
    "$profile_summary_json" \
    "$profile_log" \
    "$run_cmd_str" >>"$runs_file"

  echo "[three-machine-docker-profile-matrix] profile=$profile status=$readiness_status rc=$readiness_rc command_rc=$command_rc summary_json=$profile_summary_json log=$profile_log" | tee -a "$matrix_log"
done

runs_json="$(jq -s '.' "$runs_file")"
profiles_total="$(jq 'length' <<<"$runs_json")"
profiles_pass="$(jq '[.[] | select(.pass == true)] | length' <<<"$runs_json")"
profiles_fail="$(jq '[.[] | select(.pass != true)] | length' <<<"$runs_json")"
failed_profiles_json="$(jq -c '[.[] | select(.pass != true) | .profile] | unique' <<<"$runs_json")"
failed_profiles_csv="$(jq -r 'join(",")' <<<"$failed_profiles_json")"
rerun_failed_profiles_command=""

if [[ "$profiles_fail" != "0" ]]; then
  rerun_cmd=(
    "$0"
    --profiles "$failed_profiles_csv"
    --run-validate "$run_validate"
    --run-soak "$run_soak"
    --run-peer-failover "$run_peer_failover"
    --peer-failover-downtime-sec "$peer_failover_downtime_sec"
    --peer-failover-timeout-sec "$peer_failover_timeout_sec"
    --keep-stacks "$keep_stacks"
    --reset-data "$reset_data"
    --soak-rounds "$soak_rounds"
    --soak-pause-sec "$soak_pause_sec"
    --discovery-wait-sec "$discovery_wait_sec"
    --federation-timeout-sec "$federation_timeout_sec"
    --timeout-sec "$timeout_sec"
    --min-sources "$min_sources"
    --min-operators "$min_operators"
    --beta-profile "$beta_profile"
    --prod-profile "$prod_profile"
    --stack-a-base-port "$stack_a_base_port"
    --stack-b-base-port "$stack_b_base_port"
    --docker-host-alias "$docker_host_alias"
    --print-summary-json 1
  )
  if [[ -n "$bootstrap_directory" ]]; then
    rerun_cmd+=(--bootstrap-directory "$bootstrap_directory")
  fi
  if [[ -n "$subject" ]]; then
    rerun_cmd+=(--subject "$subject")
  fi
  if [[ -n "$anon_cred" ]]; then
    rerun_cmd+=(--anon-cred "$anon_cred")
  fi
  if [[ "$profile_3hop_strict" == "1" ]]; then
    rerun_failed_profiles_command="$(print_cmd env "THREE_MACHINE_DOCKER_PROFILE_MATRIX_3HOP_STRICT=1" "${rerun_cmd[@]}")"
  else
    rerun_failed_profiles_command="$(print_cmd "${rerun_cmd[@]}")"
  fi
fi

if [[ "$profiles_fail" == "0" ]]; then
  status="pass"
  final_rc=0
  decision_reason="all profile rehearsals passed"
else
  status="fail"
  final_rc=1
  decision_reason="one or more profile rehearsals failed"
fi

profiles_json="$(printf '%s\n' "${profiles[@]}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
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
  --arg notes "$decision_reason" \
  --arg command "$(print_cmd "$0" "${original_args[@]}")" \
  --arg readiness_script "$readiness_script" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --arg matrix_log "$matrix_log" \
  --argjson rc "$final_rc" \
  --argjson run_validate "$run_validate" \
  --argjson run_soak "$run_soak" \
  --argjson run_peer_failover "$run_peer_failover" \
  --argjson peer_failover_downtime_sec "$peer_failover_downtime_sec" \
  --argjson peer_failover_timeout_sec "$peer_failover_timeout_sec" \
  --argjson keep_stacks "$keep_stacks" \
  --argjson reset_data "$reset_data" \
  --argjson soak_rounds "$soak_rounds" \
  --argjson soak_pause_sec "$soak_pause_sec" \
  --argjson discovery_wait_sec "$discovery_wait_sec" \
  --argjson federation_timeout_sec "$federation_timeout_sec" \
  --argjson timeout_sec "$timeout_sec" \
  --argjson min_sources "$min_sources" \
  --argjson min_operators "$min_operators" \
  --argjson beta_profile "$beta_profile" \
  --argjson prod_profile "$prod_profile" \
  --argjson stack_a_base_port "$stack_a_base_port" \
  --argjson stack_b_base_port "$stack_b_base_port" \
  --arg docker_host_alias "$docker_host_alias" \
  --arg bootstrap_directory "$bootstrap_directory" \
  --arg subject "$subject_redacted" \
  --arg anon_cred_present "$anon_cred_present" \
  --argjson profiles "$profiles_json" \
  --argjson profiles_total "$profiles_total" \
  --argjson profiles_pass "$profiles_pass" \
  --argjson profiles_fail "$profiles_fail" \
  --argjson failed_profiles "$failed_profiles_json" \
  --arg rerun_failed_profiles_command "$rerun_failed_profiles_command" \
  --argjson runs "$runs_json" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: $notes,
    command: $command,
    inputs: {
      readiness_script: $readiness_script,
      profiles: $profiles,
      run_validate: ($run_validate == 1),
      run_soak: ($run_soak == 1),
      run_peer_failover: ($run_peer_failover == 1),
      peer_failover_downtime_sec: $peer_failover_downtime_sec,
      peer_failover_timeout_sec: $peer_failover_timeout_sec,
      keep_stacks: ($keep_stacks == 1),
      reset_data: ($reset_data == 1),
      reset_data_mode: (if $reset_data == 1 then "initial-run-only" else "preserve-existing" end),
      soak_rounds: $soak_rounds,
      soak_pause_sec: $soak_pause_sec,
      discovery_wait_sec: $discovery_wait_sec,
      federation_timeout_sec: $federation_timeout_sec,
      timeout_sec: $timeout_sec,
      min_sources: $min_sources,
      min_operators: $min_operators,
      beta_profile: ($beta_profile == 1),
      prod_profile: ($prod_profile == 1),
      stack_a_base_port: $stack_a_base_port,
      stack_b_base_port: $stack_b_base_port,
      docker_host_alias: $docker_host_alias,
      bootstrap_directory: $bootstrap_directory,
      subject: $subject,
      anon_cred_present: ($anon_cred_present == "1")
    },
    summary: {
      profiles_total: $profiles_total,
      profiles_pass: $profiles_pass,
      profiles_fail: $profiles_fail
    },
    reduction: {
      available: ($profiles_fail > 0),
      failed_profiles: $failed_profiles,
      failed_profiles_count: ($failed_profiles | length),
      failed_profiles_csv: (
        if ($failed_profiles | length) > 0 then
          ($failed_profiles | join(","))
        else
          null
        end
      ),
      rerun_failed_profiles_command: (
        if $rerun_failed_profiles_command == "" then
          null
        else
          $rerun_failed_profiles_command
        end
      )
    },
    decision: {
      result: (if $profiles_fail == 0 then "pass" else "fail" end),
      pass: ($profiles_fail == 0),
      reason: $notes
    },
    profiles: $runs,
    artifacts: {
      reports_dir: $reports_dir,
      matrix_log: $matrix_log,
      summary_json: $summary_json,
      report_md: $report_md
    }
  }' >"$summary_json"

{
  echo "# Three-Machine Docker Profile Matrix Report"
  echo
  echo "- Generated at (UTC): \`$(jq -r '.generated_at_utc' "$summary_json")\`"
  echo "- Status: \`$(jq -r '.status' "$summary_json")\`"
  echo "- Decision: \`$(jq -r '.decision.result' "$summary_json")\`"
  echo "- Profiles pass/fail: \`$(jq -r '.summary.profiles_pass' "$summary_json")\`/\`$(jq -r '.summary.profiles_fail' "$summary_json")\`"
  echo "- Summary JSON: \`$summary_json\`"
  echo "- Matrix Log: \`$matrix_log\`"
  echo
  echo "## Per-Profile Results"
  echo
  echo "| Profile | Status | RC | Command RC | Summary JSON | Log |"
  echo "|---|---|---:|---:|---|---|"
  jq -r '
    .profiles[]
    | "| \(.profile) | \(.status) | \(.rc) | \(.command_rc) | \(.artifacts.summary_json) | \(.artifacts.log) |"
  ' "$summary_json"
  echo
  echo "## Reduction Helper"
  echo
  echo "- Failed profiles: \`$(jq -r '.reduction.failed_profiles | if length == 0 then "none" else join(",") end' "$summary_json")\`"
  echo "- Rerun failed profiles command: \`$(jq -r '.reduction.rerun_failed_profiles_command // "none"' "$summary_json")\`"
} >"$report_md"

echo "three-machine-docker-profile-matrix: status=$status"
echo "reports_dir: $reports_dir"
echo "summary_json: $summary_json"
echo "report_md: $report_md"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
