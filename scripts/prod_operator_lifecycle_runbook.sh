#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

EASY_NODE_SH="${EASY_NODE_SH:-$ROOT_DIR/scripts/easy_node.sh}"
CURL_BIN="${PROD_OPERATOR_LIFECYCLE_CURL_BIN:-curl}"

MODE_FILE="$ROOT_DIR/deploy/data/easy_node_server_mode.conf"
AUTH_ENV_FILE="$ROOT_DIR/deploy/.env.easy.server"
PROVIDER_ENV_FILE="$ROOT_DIR/deploy/.env.easy.provider"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
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
    echo ""
    return
  fi
  if [[ "$path" == /* ]]; then
    echo "$path"
  else
    echo "$ROOT_DIR/$path"
  fi
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

bool_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

int_or_die() {
  local name="$1"
  local value="$2"
  if [[ ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer >= 0"
    exit 2
  fi
}

json_bool() {
  if [[ "${1:-0}" == "1" ]]; then
    echo "true"
  else
    echo "false"
  fi
}

mode_env_file() {
  local mode="$1"
  if [[ "$mode" == "provider" ]]; then
    echo "$PROVIDER_ENV_FILE"
  else
    echo "$AUTH_ENV_FILE"
  fi
}

active_mode_from_file() {
  if [[ -f "$MODE_FILE" ]]; then
    local mode
    mode="$(awk -F= '$1=="EASY_NODE_SERVER_MODE"{print $2; exit}' "$MODE_FILE")"
    mode="$(trim "$mode")"
    if [[ "$mode" == "authority" || "$mode" == "provider" ]]; then
      echo "$mode"
      return
    fi
  fi
  echo "authority"
}

identity_value() {
  local env_file="$1"
  local key="$2"
  local value=""
  if [[ -f "$env_file" ]]; then
    value="$(awk -F= -v key="$key" '$1==key{print $2; exit}' "$env_file")"
  fi
  trim "$value"
}

normalized_directory_base() {
  local input
  input="$(trim "${1:-}")"
  input="${input%/}"
  if [[ "$input" == */v1/relays ]]; then
    input="${input%/v1/relays}"
  fi
  echo "$input"
}

wait_http_ok() {
  local url="$1"
  local name="$2"
  local attempts="$3"
  local i
  for ((i = 1; i <= attempts; i++)); do
    if "$CURL_BIN" -fsS --connect-timeout 2 --max-time 5 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "$name did not become healthy at $url"
  return 1
}

operator_relay_count() {
  local directory_base="$1"
  local operator_id="$2"
  local payload
  payload="$("$CURL_BIN" -fsS --connect-timeout 2 --max-time 5 "${directory_base}/v1/relays")"
  jq -r --arg operator "$operator_id" '[.relays[]? | select(.operator_id == $operator)] | length' <<<"$payload"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_operator_lifecycle_runbook.sh \
    [--action onboard|offboard] \
    [--mode auto|authority|provider] \
    [--public-host HOST] \
    [--operator-id ID] \
    [--issuer-id ID] \
    [--issuer-admin-token TOKEN] \
    [--directory-admin-token TOKEN] \
    [--entry-puzzle-secret SECRET] \
    [--authority-directory URL] \
    [--authority-issuer URL] \
    [--peer-directories URLS] \
    [--bootstrap-directory URL] \
    [--peer-identity-strict 0|1|auto] \
    [--min-peer-operators N] \
    [--client-allowlist [0|1]] \
    [--allow-anon-cred [0|1]] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--show-admin-token [0|1]] \
    [--preflight-check [0|1]] \
    [--preflight-timeout-sec N] \
    [--health-check [0|1]] \
    [--health-timeout-sec N] \
    [--directory-url URL] \
    [--verify-relays [0|1]] \
    [--verify-absent [0|1]] \
    [--verify-relay-timeout-sec N] \
    [--verify-relay-min-count N] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Operator-safe onboarding/offboarding runbook with health and relay visibility checks.

Actions:
  - onboard (default): optional preflight -> server-up -> optional health checks ->
    optional relay publication verification on directory feed.
  - offboard: server-down -> optional relay disappearance verification.
USAGE
}

for cmd in bash jq date awk mktemp mkdir; do
  need_cmd "$cmd"
done
if [[ ! -x "$EASY_NODE_SH" ]]; then
  echo "missing executable easy_node wrapper: $EASY_NODE_SH"
  exit 2
fi

action="onboard"
mode="auto"
public_host=""
operator_id=""
issuer_id=""
issuer_admin_token=""
directory_admin_token=""
entry_puzzle_secret=""
authority_directory=""
authority_issuer=""
peer_directories=""
bootstrap_directory=""
peer_identity_strict=""
min_peer_operators=""
client_allowlist=""
allow_anon_cred=""
beta_profile=""
prod_profile=""
show_admin_token=""
preflight_check="${PROD_OPERATOR_LIFECYCLE_PREFLIGHT_CHECK:-1}"
preflight_timeout_sec="${PROD_OPERATOR_LIFECYCLE_PREFLIGHT_TIMEOUT_SEC:-30}"
health_check="${PROD_OPERATOR_LIFECYCLE_HEALTH_CHECK:-1}"
health_timeout_sec="${PROD_OPERATOR_LIFECYCLE_HEALTH_TIMEOUT_SEC:-60}"
directory_url=""
verify_relays="${PROD_OPERATOR_LIFECYCLE_VERIFY_RELAYS:-1}"
verify_absent="${PROD_OPERATOR_LIFECYCLE_VERIFY_ABSENT:-1}"
verify_relay_timeout_sec="${PROD_OPERATOR_LIFECYCLE_VERIFY_RELAY_TIMEOUT_SEC:-90}"
verify_relay_min_count="${PROD_OPERATOR_LIFECYCLE_VERIFY_RELAY_MIN_COUNT:-2}"
summary_json=""
print_summary_json="${PROD_OPERATOR_LIFECYCLE_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --action)
      action="${2:-}"
      shift 2
      ;;
    --mode)
      mode="${2:-}"
      shift 2
      ;;
    --public-host)
      public_host="${2:-}"
      shift 2
      ;;
    --operator-id)
      operator_id="${2:-}"
      shift 2
      ;;
    --issuer-id)
      issuer_id="${2:-}"
      shift 2
      ;;
    --issuer-admin-token)
      issuer_admin_token="${2:-}"
      shift 2
      ;;
    --directory-admin-token)
      directory_admin_token="${2:-}"
      shift 2
      ;;
    --entry-puzzle-secret)
      entry_puzzle_secret="${2:-}"
      shift 2
      ;;
    --authority-directory)
      authority_directory="${2:-}"
      shift 2
      ;;
    --authority-issuer)
      authority_issuer="${2:-}"
      shift 2
      ;;
    --peer-directories)
      peer_directories="${2:-}"
      shift 2
      ;;
    --bootstrap-directory)
      bootstrap_directory="${2:-}"
      shift 2
      ;;
    --peer-identity-strict)
      peer_identity_strict="${2:-}"
      shift 2
      ;;
    --min-peer-operators)
      min_peer_operators="${2:-}"
      shift 2
      ;;
    --client-allowlist)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        client_allowlist="${2:-}"
        shift 2
      else
        client_allowlist="1"
        shift
      fi
      ;;
    --allow-anon-cred)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_anon_cred="${2:-}"
        shift 2
      else
        allow_anon_cred="1"
        shift
      fi
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
    --show-admin-token)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_admin_token="${2:-}"
        shift 2
      else
        show_admin_token="1"
        shift
      fi
      ;;
    --preflight-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        preflight_check="${2:-}"
        shift 2
      else
        preflight_check="1"
        shift
      fi
      ;;
    --preflight-timeout-sec)
      preflight_timeout_sec="${2:-}"
      shift 2
      ;;
    --health-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        health_check="${2:-}"
        shift 2
      else
        health_check="1"
        shift
      fi
      ;;
    --health-timeout-sec)
      health_timeout_sec="${2:-}"
      shift 2
      ;;
    --directory-url)
      directory_url="${2:-}"
      shift 2
      ;;
    --verify-relays)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        verify_relays="${2:-}"
        shift 2
      else
        verify_relays="1"
        shift
      fi
      ;;
    --verify-absent)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        verify_absent="${2:-}"
        shift 2
      else
        verify_absent="1"
        shift
      fi
      ;;
    --verify-relay-timeout-sec)
      verify_relay_timeout_sec="${2:-}"
      shift 2
      ;;
    --verify-relay-min-count)
      verify_relay_min_count="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
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
    -h|--help)
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

if [[ "$action" != "onboard" && "$action" != "offboard" ]]; then
  echo "--action must be onboard or offboard"
  exit 2
fi
if [[ "$mode" != "auto" && "$mode" != "authority" && "$mode" != "provider" ]]; then
  echo "--mode must be auto, authority, or provider"
  exit 2
fi
if [[ -n "$peer_identity_strict" && "$peer_identity_strict" != "0" && "$peer_identity_strict" != "1" && "$peer_identity_strict" != "auto" ]]; then
  echo "--peer-identity-strict must be 0, 1, or auto"
  exit 2
fi
if [[ -n "$client_allowlist" ]]; then
  bool_or_die "--client-allowlist" "$client_allowlist"
fi
if [[ -n "$allow_anon_cred" ]]; then
  bool_or_die "--allow-anon-cred" "$allow_anon_cred"
fi
if [[ -n "$beta_profile" ]]; then
  bool_or_die "--beta-profile" "$beta_profile"
fi
if [[ -n "$prod_profile" ]]; then
  bool_or_die "--prod-profile" "$prod_profile"
fi
if [[ -n "$show_admin_token" ]]; then
  bool_or_die "--show-admin-token" "$show_admin_token"
fi
bool_or_die "--preflight-check" "$preflight_check"
bool_or_die "--health-check" "$health_check"
bool_or_die "--verify-relays" "$verify_relays"
bool_or_die "--verify-absent" "$verify_absent"
bool_or_die "--print-summary-json" "$print_summary_json"
int_or_die "--preflight-timeout-sec" "$preflight_timeout_sec"
int_or_die "--health-timeout-sec" "$health_timeout_sec"
int_or_die "--verify-relay-timeout-sec" "$verify_relay_timeout_sec"
int_or_die "--verify-relay-min-count" "$verify_relay_min_count"
if [[ -n "$min_peer_operators" ]]; then
  int_or_die "--min-peer-operators" "$min_peer_operators"
fi

resolved_mode="$mode"
if [[ "$resolved_mode" == "auto" ]]; then
  resolved_mode="$(active_mode_from_file)"
fi

if [[ -z "$summary_json" ]]; then
  mkdir -p "$(default_log_dir)"
  ts="$(date -u +%Y%m%d_%H%M%S)"
  summary_json="$(default_log_dir)/prod_operator_lifecycle_${action}_${ts}.json"
fi
summary_json="$(abs_path "$summary_json")"
mkdir -p "$(dirname "$summary_json")"

resolved_directory_base="$(normalized_directory_base "$directory_url")"
if [[ -z "$resolved_directory_base" ]]; then
  host_for_checks="${public_host:-127.0.0.1}"
  resolved_directory_base="http://${host_for_checks}:8081"
fi

resolved_operator_id="$(trim "$operator_id")"
if [[ -z "$resolved_operator_id" ]]; then
  env_file="$(mode_env_file "$resolved_mode")"
  resolved_operator_id="$(identity_value "$env_file" "DIRECTORY_OPERATOR_ID")"
fi

started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
started_epoch="$(date -u +%s)"
status="ok"
failure_step=""
failure_rc=0
completed_steps_json='[]'
relay_observed_count=-1

step_ok() {
  local name="$1"
  completed_steps_json="$(
    jq -nc --argjson steps "$completed_steps_json" --arg name "$name" '$steps + [$name]'
  )"
}

set_failure() {
  local step="$1"
  local rc="$2"
  status="fail"
  failure_step="$step"
  failure_rc="$rc"
}

if [[ "$action" == "onboard" ]]; then
  if [[ "$preflight_check" == "1" ]]; then
    preflight_cmd=("$EASY_NODE_SH" "server-preflight" "--mode" "$resolved_mode" "--timeout-sec" "$preflight_timeout_sec")
    if [[ -n "$public_host" ]]; then
      preflight_cmd+=("--public-host" "$public_host")
    fi
    if [[ -n "$resolved_operator_id" ]]; then
      preflight_cmd+=("--operator-id" "$resolved_operator_id")
    fi
    if [[ -n "$issuer_id" ]]; then
      preflight_cmd+=("--issuer-id" "$issuer_id")
    fi
    if [[ -n "$authority_directory" ]]; then
      preflight_cmd+=("--authority-directory" "$authority_directory")
    fi
    if [[ -n "$authority_issuer" ]]; then
      preflight_cmd+=("--authority-issuer" "$authority_issuer")
    fi
    if [[ -n "$peer_directories" ]]; then
      preflight_cmd+=("--peer-directories" "$peer_directories")
    fi
    if [[ -n "$bootstrap_directory" ]]; then
      preflight_cmd+=("--bootstrap-directory" "$bootstrap_directory")
    fi
    if [[ -n "$peer_identity_strict" ]]; then
      preflight_cmd+=("--peer-identity-strict" "$peer_identity_strict")
    fi
    if [[ -n "$min_peer_operators" ]]; then
      preflight_cmd+=("--min-peer-operators" "$min_peer_operators")
    fi
    if [[ -n "$beta_profile" ]]; then
      preflight_cmd+=("--beta-profile" "$beta_profile")
    fi
    if [[ -n "$prod_profile" ]]; then
      preflight_cmd+=("--prod-profile" "$prod_profile")
    fi
    set +e
    "${preflight_cmd[@]}"
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      set_failure "server_preflight" "$rc"
    else
      step_ok "server_preflight"
    fi
  fi

  if [[ "$status" == "ok" ]]; then
    server_up_cmd=("$EASY_NODE_SH" "server-up" "--mode" "$resolved_mode")
    if [[ -n "$public_host" ]]; then
      server_up_cmd+=("--public-host" "$public_host")
    fi
    if [[ -n "$resolved_operator_id" ]]; then
      server_up_cmd+=("--operator-id" "$resolved_operator_id")
    fi
    if [[ -n "$issuer_id" ]]; then
      server_up_cmd+=("--issuer-id" "$issuer_id")
    fi
    if [[ -n "$issuer_admin_token" ]]; then
      server_up_cmd+=("--issuer-admin-token" "$issuer_admin_token")
    fi
    if [[ -n "$directory_admin_token" ]]; then
      server_up_cmd+=("--directory-admin-token" "$directory_admin_token")
    fi
    if [[ -n "$entry_puzzle_secret" ]]; then
      server_up_cmd+=("--entry-puzzle-secret" "$entry_puzzle_secret")
    fi
    if [[ -n "$authority_directory" ]]; then
      server_up_cmd+=("--authority-directory" "$authority_directory")
    fi
    if [[ -n "$authority_issuer" ]]; then
      server_up_cmd+=("--authority-issuer" "$authority_issuer")
    fi
    if [[ -n "$peer_directories" ]]; then
      server_up_cmd+=("--peer-directories" "$peer_directories")
    fi
    if [[ -n "$bootstrap_directory" ]]; then
      server_up_cmd+=("--bootstrap-directory" "$bootstrap_directory")
    fi
    if [[ -n "$peer_identity_strict" ]]; then
      server_up_cmd+=("--peer-identity-strict" "$peer_identity_strict")
    fi
    if [[ -n "$client_allowlist" ]]; then
      server_up_cmd+=("--client-allowlist" "$client_allowlist")
    fi
    if [[ -n "$allow_anon_cred" ]]; then
      server_up_cmd+=("--allow-anon-cred" "$allow_anon_cred")
    fi
    if [[ -n "$beta_profile" ]]; then
      server_up_cmd+=("--beta-profile" "$beta_profile")
    fi
    if [[ -n "$prod_profile" ]]; then
      server_up_cmd+=("--prod-profile" "$prod_profile")
    fi
    if [[ -n "$show_admin_token" ]]; then
      server_up_cmd+=("--show-admin-token" "$show_admin_token")
    fi
    set +e
    "${server_up_cmd[@]}"
    rc=$?
    set -e
    if [[ "$rc" -ne 0 ]]; then
      set_failure "server_up" "$rc"
    else
      step_ok "server_up"
      if [[ -z "$resolved_operator_id" ]]; then
        env_file="$(mode_env_file "$resolved_mode")"
        resolved_operator_id="$(identity_value "$env_file" "DIRECTORY_OPERATOR_ID")"
      fi
    fi
  fi

  if [[ "$status" == "ok" && "$health_check" == "1" ]]; then
    need_cmd "$CURL_BIN"
    host_for_health="${public_host:-127.0.0.1}"
    set +e
    wait_http_ok "${resolved_directory_base}/v1/relays" "directory" "$health_timeout_sec"
    rc=$?
    if [[ "$rc" -eq 0 && "$resolved_mode" == "authority" ]]; then
      wait_http_ok "http://${host_for_health}:8082/v1/pubkeys" "issuer" "$health_timeout_sec"
      rc=$?
    fi
    if [[ "$rc" -eq 0 ]]; then
      wait_http_ok "http://${host_for_health}:8083/v1/health" "entry" "$health_timeout_sec"
      rc=$?
    fi
    if [[ "$rc" -eq 0 ]]; then
      wait_http_ok "http://${host_for_health}:8084/v1/health" "exit" "$health_timeout_sec"
      rc=$?
    fi
    set -e
    if [[ "$rc" -ne 0 ]]; then
      set_failure "health_check" "$rc"
    else
      step_ok "health_check"
    fi
  fi

  if [[ "$status" == "ok" && "$verify_relays" == "1" ]]; then
    need_cmd "$CURL_BIN"
    if [[ -z "$resolved_operator_id" ]]; then
      set_failure "relay_verify" 3
      echo "relay verify failed: operator id unavailable (provide --operator-id or ensure env has DIRECTORY_OPERATOR_ID)"
    else
      verify_ok=0
      for ((i = 1; i <= verify_relay_timeout_sec; i++)); do
        set +e
        observed="$(operator_relay_count "$resolved_directory_base" "$resolved_operator_id" 2>/dev/null)"
        rc=$?
        set -e
        if [[ "$rc" -eq 0 && "$observed" =~ ^[0-9]+$ ]]; then
          relay_observed_count="$observed"
          if (( observed >= verify_relay_min_count )); then
            verify_ok=1
            break
          fi
        fi
        sleep 1
      done
      if [[ "$verify_ok" -ne 1 ]]; then
        set_failure "relay_verify" 4
        echo "relay verify failed: operator=$resolved_operator_id observed_count=$relay_observed_count required_min=$verify_relay_min_count directory=$resolved_directory_base"
      else
        step_ok "relay_verify"
      fi
    fi
  fi
else
  server_down_cmd=("$EASY_NODE_SH" "server-down")
  set +e
  "${server_down_cmd[@]}"
  rc=$?
  set -e
  if [[ "$rc" -ne 0 ]]; then
    set_failure "server_down" "$rc"
  else
    step_ok "server_down"
  fi

  if [[ "$status" == "ok" && "$verify_absent" == "1" ]]; then
    need_cmd "$CURL_BIN"
    if [[ -z "$resolved_operator_id" ]]; then
      set_failure "relay_absent_verify" 3
      echo "relay absent verify failed: operator id unavailable (provide --operator-id or ensure env has DIRECTORY_OPERATOR_ID)"
    else
      absent_ok=0
      for ((i = 1; i <= verify_relay_timeout_sec; i++)); do
        set +e
        observed="$(operator_relay_count "$resolved_directory_base" "$resolved_operator_id" 2>/dev/null)"
        rc=$?
        set -e
        if [[ "$rc" -eq 0 && "$observed" =~ ^[0-9]+$ ]]; then
          relay_observed_count="$observed"
          if (( observed == 0 )); then
            absent_ok=1
            break
          fi
        fi
        sleep 1
      done
      if [[ "$absent_ok" -ne 1 ]]; then
        set_failure "relay_absent_verify" 4
        echo "relay absent verify failed: operator=$resolved_operator_id observed_count=$relay_observed_count expected=0 directory=$resolved_directory_base"
      else
        step_ok "relay_absent_verify"
      fi
    fi
  fi
fi

finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
finished_epoch="$(date -u +%s)"
duration_sec=$((finished_epoch - started_epoch))
if [[ "$duration_sec" -lt 0 ]]; then
  duration_sec=0
fi

jq -nc \
  --arg action "$action" \
  --arg status "$status" \
  --arg mode "$resolved_mode" \
  --arg started_at "$started_at" \
  --arg finished_at "$finished_at" \
  --argjson duration_sec "$duration_sec" \
  --arg operator_id "$resolved_operator_id" \
  --arg directory_url "$resolved_directory_base" \
  --arg failure_step "$failure_step" \
  --argjson failure_rc "$failure_rc" \
  --argjson completed_steps "$completed_steps_json" \
  --argjson preflight_check "$(json_bool "$preflight_check")" \
  --argjson health_check "$(json_bool "$health_check")" \
  --argjson verify_relays "$(json_bool "$verify_relays")" \
  --argjson verify_absent "$(json_bool "$verify_absent")" \
  --argjson verify_relay_min_count "$verify_relay_min_count" \
  --argjson verify_relay_timeout_sec "$verify_relay_timeout_sec" \
  --argjson relay_observed_count "$relay_observed_count" \
  --arg peer_identity_strict "$peer_identity_strict" \
  --arg min_peer_operators "$min_peer_operators" \
  --arg client_allowlist "$client_allowlist" \
  --arg allow_anon_cred "$allow_anon_cred" \
  --arg beta_profile "$beta_profile" \
  --arg prod_profile "$prod_profile" \
  --arg summary_json "$summary_json" \
  '{
    action:$action,
    status:$status,
    mode:$mode,
    started_at:$started_at,
    finished_at:$finished_at,
    duration_sec:$duration_sec,
    operator_id:($operator_id // ""),
    directory_url:$directory_url,
    failure_step:($failure_step // ""),
    failure_rc:$failure_rc,
    completed_steps:$completed_steps,
    checks:{
      preflight_enabled:$preflight_check,
      health_enabled:$health_check,
      relay_verify_enabled:$verify_relays,
      relay_absent_verify_enabled:$verify_absent
    },
    relay_policy:{
      verify_min_count:$verify_relay_min_count,
      verify_timeout_sec:$verify_relay_timeout_sec,
      observed_count:$relay_observed_count
    },
    requested_flags:{
      peer_identity_strict:($peer_identity_strict // ""),
      min_peer_operators:($min_peer_operators // ""),
      client_allowlist:($client_allowlist // ""),
      allow_anon_cred:($allow_anon_cred // ""),
      beta_profile:($beta_profile // ""),
      prod_profile:($prod_profile // "")
    },
    summary_json:$summary_json
  }' >"$summary_json"

echo "[prod-operator-lifecycle-runbook] action=$action mode=$resolved_mode status=$status"
echo "[prod-operator-lifecycle-runbook] summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  echo "[prod-operator-lifecycle-runbook] summary_json_payload:"
  cat "$summary_json"
fi

if [[ "$status" != "ok" ]]; then
  exit "$failure_rc"
fi
