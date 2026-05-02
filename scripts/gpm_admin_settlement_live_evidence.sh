#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/gpm_admin_settlement_live_evidence.sh \
    [--bridge-url URL] \
    [--bridge-token TOKEN|--bridge-token-file PATH] \
    [--reward-proof-token TOKEN|--reward-proof-token-file PATH] \
    [--finality-token TOKEN|--finality-token-file PATH] \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--run-id ID] \
    [--currency DENOM] \
    [--http-timeout-sec N] \
    [--require-finality [0|1]] \
    [--start-local-tdpnd [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Capture fail-closed Admin Console settlement evidence against a live/staging
  tdpnd settlement bridge, or against a temporary local tdpnd bridge when
  --start-local-tdpnd 1 is set.

Evidence captured:
  - authenticated bridge health and auth-negative behavior
  - reward issue rejection before objective proof registration
  - objective reward proof registration and query verification
  - reserve -> finality confirmation -> settlement confirmation
  - weekly reward submitted -> finality confirmation -> distribution query
  - slash evidence hold behavior: penalty rejected before evidence finality,
    accepted only after finality confirmation

Defaults:
  --bridge-url from GPM_ADMIN_SETTLEMENT_BRIDGE_URL or COSMOS_BRIDGE_URL
  --reports-dir .easy-node-logs
  --summary-json <reports-dir>/gpm_admin_settlement_live_evidence_summary.json
  --report-md <reports-dir>/gpm_admin_settlement_live_evidence_report.md
  --currency TDPNC
  --http-timeout-sec 8
  --require-finality 1
  --start-local-tdpnd 0
  --print-summary-json 0

Exit behavior:
  Fails closed when bridge URL/tokens/finality inputs are missing, when any
  expected fail-closed guard opens, or when required query evidence is absent.
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
  elif [[ "$path" == /* || "$path" =~ ^[A-Za-z]:[\\/].* ]]; then
    printf '%s' "${path//\\//}"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

require_value_or_die() {
  local flag="$1"
  local value="${2:-}"
  if [[ -z "$value" || "$value" == --* ]]; then
    echo "$flag requires a value"
    exit 2
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

read_secret_file() {
  local file_path="$1"
  file_path="$(abs_path "$file_path")"
  if [[ ! -f "$file_path" ]]; then
    echo "secret file missing: $file_path" >&2
    return 1
  fi
  local value
  value="$(tr -d '\r\n' <"$file_path")"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    echo "secret file is empty: $file_path" >&2
    return 1
  fi
  printf '%s' "$value"
}

validate_bearer_token_literal() {
  local token="$1"
  if [[ -z "$token" ]]; then
    echo "refusing empty bearer token" >&2
    return 1
  fi
  if ((${#token} > 4096)); then
    echo "refusing oversized bearer token" >&2
    return 1
  fi
  if printf '%s' "$token" | LC_ALL=C grep -q '[[:cntrl:][:space:]]'; then
    echo "refusing bearer token with whitespace/control characters" >&2
    return 1
  fi
  if [[ "$token" == *\"* || "$token" == *\\* ]]; then
    echo "refusing bearer token with unsafe quote/backslash characters" >&2
    return 1
  fi
}

write_curl_config() {
  local auth_token="${1:-}"
  local scoped_header="${2:-}"
  local scoped_token="${3:-}"
  local old_umask cfg_file
  old_umask="$(umask)"
  umask 077
  cfg_file="$(mktemp -t gpm-admin-settlement-auth.XXXXXX.cfg)"
  umask "$old_umask"
  : >"$cfg_file"
  if [[ -n "$auth_token" ]]; then
    validate_bearer_token_literal "$auth_token"
    printf 'header = "Authorization: Bearer %s"\n' "$auth_token" >>"$cfg_file"
  fi
  if [[ -n "$scoped_header" || -n "$scoped_token" ]]; then
    if [[ -z "$scoped_header" || -z "$scoped_token" ]]; then
      echo "scoped header and token must be provided together" >&2
      rm -f "$cfg_file"
      return 1
    fi
    if ! [[ "$scoped_header" =~ ^[A-Za-z0-9-]+$ ]]; then
      echo "refusing unsafe scoped bearer header name" >&2
      rm -f "$cfg_file"
      return 1
    fi
    validate_bearer_token_literal "$scoped_token"
    printf 'header = "%s: Bearer %s"\n' "$scoped_header" "$scoped_token" >>"$cfg_file"
  fi
  printf '%s\n' "$cfg_file"
}

url_encode() {
  jq -nr --arg value "$1" '$value | @uri'
}

pick_port() {
  local port
  for _ in $(seq 1 50); do
    port=$((32000 + RANDOM % 10000))
    if ! (echo >/dev/tcp/127.0.0.1/"$port") >/dev/null 2>&1; then
      printf '%s\n' "$port"
      return 0
    fi
  done
  return 1
}

TDPND_PID=""
LOCAL_TDPND_LOG=""
LOCAL_TDPND_BIN=""

signal_runtime() {
  local sig="$1"
  if [[ -n "$TDPND_PID" ]]; then
    kill "-$sig" "$TDPND_PID" 2>/dev/null || true
    if command -v pkill >/dev/null 2>&1; then
      pkill "-$sig" -P "$TDPND_PID" 2>/dev/null || true
    fi
  fi
}

wait_for_runtime_exit() {
  local attempts="$1"
  for _ in $(seq 1 "$attempts"); do
    if [[ -z "$TDPND_PID" ]] || ! kill -0 "$TDPND_PID" 2>/dev/null; then
      return 0
    fi
    sleep 0.1
  done
  return 1
}

cleanup() {
  set +e
  if [[ -n "$TDPND_PID" ]] && kill -0 "$TDPND_PID" 2>/dev/null; then
    signal_runtime INT
    wait_for_runtime_exit 30 || true
    if kill -0 "$TDPND_PID" 2>/dev/null; then
      signal_runtime TERM
      wait_for_runtime_exit 20 || true
    fi
    if kill -0 "$TDPND_PID" 2>/dev/null; then
      signal_runtime KILL
      wait_for_runtime_exit 20 || true
    fi
    wait "$TDPND_PID" 2>/dev/null || true
  fi
  if [[ -n "$LOCAL_TDPND_BIN" ]]; then
    rm -f "$LOCAL_TDPND_BIN"
  fi
}
trap cleanup EXIT

need_cmd curl
need_cmd jq
need_cmd date
need_cmd mktemp
need_cmd mkdir
need_cmd grep

bridge_url="${GPM_ADMIN_SETTLEMENT_BRIDGE_URL:-${COSMOS_BRIDGE_URL:-}}"
bridge_token="${GPM_ADMIN_SETTLEMENT_BRIDGE_TOKEN:-${COSMOS_BRIDGE_TOKEN:-}}"
bridge_token_file="${GPM_ADMIN_SETTLEMENT_BRIDGE_TOKEN_FILE:-${COSMOS_BRIDGE_TOKEN_FILE:-}}"
reward_proof_token="${GPM_ADMIN_SETTLEMENT_REWARD_PROOF_TOKEN:-${COSMOS_BRIDGE_REWARD_PROOF_TOKEN:-}}"
reward_proof_token_file="${GPM_ADMIN_SETTLEMENT_REWARD_PROOF_TOKEN_FILE:-${COSMOS_BRIDGE_REWARD_PROOF_TOKEN_FILE:-}}"
finality_token="${GPM_ADMIN_SETTLEMENT_FINALITY_TOKEN:-${COSMOS_BRIDGE_FINALITY_TOKEN:-}}"
finality_token_file="${GPM_ADMIN_SETTLEMENT_FINALITY_TOKEN_FILE:-${COSMOS_BRIDGE_FINALITY_TOKEN_FILE:-}}"
reports_dir="${GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
summary_json="${GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_SUMMARY_JSON:-}"
report_md="${GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_REPORT_MD:-}"
run_id="${GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_RUN_ID:-}"
currency="${GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_CURRENCY:-TDPNC}"
http_timeout_sec="${GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_HTTP_TIMEOUT_SEC:-8}"
require_finality="${GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_REQUIRE_FINALITY:-1}"
start_local_tdpnd="${GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_START_LOCAL_TDPND:-0}"
print_summary_json="${GPM_ADMIN_SETTLEMENT_LIVE_EVIDENCE_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bridge-url)
      require_value_or_die "$1" "${2:-}"
      bridge_url="${2:-}"
      shift 2
      ;;
    --bridge-token)
      require_value_or_die "$1" "${2:-}"
      bridge_token="${2:-}"
      shift 2
      ;;
    --bridge-token-file)
      require_value_or_die "$1" "${2:-}"
      bridge_token_file="${2:-}"
      shift 2
      ;;
    --reward-proof-token)
      require_value_or_die "$1" "${2:-}"
      reward_proof_token="${2:-}"
      shift 2
      ;;
    --reward-proof-token-file)
      require_value_or_die "$1" "${2:-}"
      reward_proof_token_file="${2:-}"
      shift 2
      ;;
    --finality-token)
      require_value_or_die "$1" "${2:-}"
      finality_token="${2:-}"
      shift 2
      ;;
    --finality-token-file)
      require_value_or_die "$1" "${2:-}"
      finality_token_file="${2:-}"
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
    --run-id)
      require_value_or_die "$1" "${2:-}"
      run_id="${2:-}"
      shift 2
      ;;
    --currency)
      require_value_or_die "$1" "${2:-}"
      currency="${2:-}"
      shift 2
      ;;
    --http-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      http_timeout_sec="${2:-}"
      shift 2
      ;;
    --require-finality)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        require_finality="${2:-}"
        shift 2
      else
        require_finality="1"
        shift
      fi
      ;;
    --start-local-tdpnd)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        start_local_tdpnd="${2:-}"
        shift 2
      else
        start_local_tdpnd="1"
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
      echo "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--require-finality" "$require_finality"
bool_arg_or_die "--start-local-tdpnd" "$start_local_tdpnd"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
int_arg_or_die "--http-timeout-sec" "$http_timeout_sec"
if (( http_timeout_sec < 1 )); then
  echo "--http-timeout-sec must be >= 1"
  exit 2
fi

reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/gpm_admin_settlement_live_evidence_summary.json"
fi
if [[ -z "$report_md" ]]; then
  report_md="$reports_dir/gpm_admin_settlement_live_evidence_report.md"
fi
summary_json="$(abs_path "$summary_json")"
report_md="$(abs_path "$report_md")"
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

if [[ -z "$run_id" ]]; then
  run_id="gpm-admin-settlement-$(date -u +%Y%m%d%H%M%S)-$$"
fi
run_id="$(printf '%s' "$run_id" | tr '[:upper:]' '[:lower:]' | tr -c 'a-z0-9_.:-' '-')"
run_id="${run_id%-}"

steps_json='[]'
signals_json='{}'
final_status="pass"
final_rc=0
failure_reason=""
LAST_RESPONSE_FILE=""

set_signal() {
  local key="$1"
  local value="$2"
  signals_json="$(printf '%s\n' "$signals_json" | jq -c --arg key "$key" --argjson value "$value" '. + {($key): ($value == 1)}')"
}

record_step() {
  local name="$1"
  local status="$2"
  local expected_http="$3"
  local actual_http="$4"
  local response_file="$5"
  local detail="${6:-}"
  local ok_json=0
  if [[ "$status" == "pass" ]]; then
    ok_json=1
  fi
  steps_json="$(printf '%s\n' "$steps_json" | jq -c \
    --arg name "$name" \
    --arg status "$status" \
    --arg expected_http "$expected_http" \
    --arg actual_http "$actual_http" \
    --arg response_file "$response_file" \
    --arg detail "$detail" \
    --argjson ok "$ok_json" \
    '. + [{
      name: $name,
      status: $status,
      ok: ($ok == 1),
      expected_http: (if $expected_http == "" then null else $expected_http end),
      actual_http: (if $actual_http == "" then null else $actual_http end),
      response_file: (if $response_file == "" then null else $response_file end),
      detail: (if $detail == "" then null else $detail end)
    }]')"
}

write_outputs() {
  local generated_at_utc
  generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  local bridge_kind="remote"
  if [[ "$start_local_tdpnd" == "1" ]]; then
    bridge_kind="local_tdpnd"
  fi

  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$final_status" \
    --argjson rc "$final_rc" \
    --arg command "./scripts/gpm_admin_settlement_live_evidence.sh [redacted-token-args]" \
    --arg reports_dir "$reports_dir" \
    --arg summary_json "$summary_json" \
    --arg report_md "$report_md" \
    --arg bridge_url "$bridge_url" \
    --arg bridge_kind "$bridge_kind" \
    --arg run_id "$run_id" \
    --arg currency "$currency" \
    --arg failure_reason "$failure_reason" \
    --arg local_tdpnd_log "$LOCAL_TDPND_LOG" \
    --argjson require_finality "$require_finality" \
    --argjson start_local_tdpnd "$start_local_tdpnd" \
    --argjson bridge_token_configured "$(if [[ -n "$bridge_token" ]]; then printf '1'; else printf '0'; fi)" \
    --argjson reward_proof_token_configured "$(if [[ -n "$reward_proof_token" ]]; then printf '1'; else printf '0'; fi)" \
    --argjson finality_token_configured "$(if [[ -n "$finality_token" ]]; then printf '1'; else printf '0'; fi)" \
    --argjson signals "$signals_json" \
    --argjson steps "$steps_json" \
    '{
      version: 1,
      schema: { id: "gpm_admin_settlement_live_evidence_summary", major: 1, minor: 0 },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      command: $command,
      inputs: {
        bridge_url: (if $bridge_url == "" then null else $bridge_url end),
        bridge_kind: $bridge_kind,
        run_id: $run_id,
        currency: $currency,
        require_finality: ($require_finality == 1),
        start_local_tdpnd: ($start_local_tdpnd == 1),
        bridge_token_configured: ($bridge_token_configured == 1),
        reward_proof_token_configured: ($reward_proof_token_configured == 1),
        finality_token_configured: ($finality_token_configured == 1)
      },
      failure: {
        reason: (if $failure_reason == "" then null else $failure_reason end)
      },
      signals: $signals,
      steps: $steps,
      artifacts: {
        reports_dir: $reports_dir,
        summary_json: $summary_json,
        report_md: $report_md,
        local_tdpnd_log: (if $local_tdpnd_log == "" then null else $local_tdpnd_log end)
      }
    }' >"$summary_json"

  {
    printf '# GPM Admin Settlement Live Evidence\n\n'
    printf -- '- Generated at (UTC): %s\n' "$generated_at_utc"
    printf -- '- Status: %s\n' "$final_status"
    printf -- '- Bridge kind: %s\n' "$bridge_kind"
    printf -- '- Bridge URL: %s\n' "${bridge_url:-unset}"
    printf -- '- Run ID: `%s`\n' "$run_id"
    printf -- '- Currency: `%s`\n' "$currency"
    if [[ -n "$failure_reason" ]]; then
      printf -- '- Failure reason: %s\n' "$failure_reason"
    fi
    printf '\n## Signals\n\n'
    printf '%s\n' "$signals_json" | jq -r 'to_entries | sort_by(.key)[] | "- \(.key): \(.value)"'
    printf '\n## Steps\n\n'
    printf '%s\n' "$steps_json" | jq -r '.[] | "- \(.name): \(.status) (expected=\(.expected_http // "n/a"), actual=\(.actual_http // "n/a"))"'
    printf '\n## Artifacts\n\n'
    printf -- '- Summary JSON: `%s`\n' "$summary_json"
    printf -- '- Report Markdown: `%s`\n' "$report_md"
    if [[ -n "$LOCAL_TDPND_LOG" ]]; then
      printf -- '- Local tdpnd log: `%s`\n' "$LOCAL_TDPND_LOG"
    fi
  } >"$report_md"
}

fail_with() {
  local rc="$1"
  local reason="$2"
  final_status="fail"
  final_rc="$rc"
  failure_reason="$reason"
  write_outputs
  echo "[gpm-admin-settlement-live-evidence] status=fail rc=$final_rc reason=$failure_reason"
  echo "[gpm-admin-settlement-live-evidence] summary_json=$summary_json"
  if [[ "$print_summary_json" == "1" ]]; then
    cat "$summary_json"
  fi
  exit "$final_rc"
}

request_json() {
  local step="$1"
  local method="$2"
  local path="$3"
  local payload="$4"
  local expected_http="$5"
  local auth_mode="${6:-main}"
  local response_file="$reports_dir/${step}.json"
  local url="${bridge_url%/}$path"
  local cfg_file=""
  local code=""
  local scoped_header=""
  local scoped_token=""
  local auth_token="$bridge_token"
  local -a curl_args

  case "$auth_mode" in
    none)
      auth_token=""
      ;;
    main)
      ;;
    proof)
      scoped_header="X-GPM-Reward-Proof-Authorization"
      scoped_token="$reward_proof_token"
      ;;
    finality)
      scoped_header="X-GPM-Finality-Authorization"
      scoped_token="$finality_token"
      ;;
    *)
      fail_with 2 "unknown auth mode for step $step: $auth_mode"
      ;;
  esac

  curl_args=(-sS -m "$http_timeout_sec" -o "$response_file" -w "%{http_code}" -X "$method")
  if [[ -n "$payload" ]]; then
    curl_args+=(-H "Content-Type: application/json" -d "$payload")
  fi
  curl_args+=("$url")

  if [[ -n "$auth_token" || -n "$scoped_header" ]]; then
    cfg_file="$(write_curl_config "$auth_token" "$scoped_header" "$scoped_token")"
    code="$(curl --config "$cfg_file" "${curl_args[@]}" 2>/dev/null || true)"
    rm -f "$cfg_file"
  else
    code="$(curl "${curl_args[@]}" 2>/dev/null || true)"
  fi

  LAST_RESPONSE_FILE="$response_file"
  if [[ "$code" == "$expected_http" ]]; then
    record_step "$step" "pass" "$expected_http" "$code" "$response_file"
    return 0
  fi

  record_step "$step" "fail" "$expected_http" "$code" "$response_file"
  fail_with 1 "step $step expected HTTP $expected_http but got ${code:-curl_error}"
}

assert_response_jq() {
  local step="$1"
  local response_file="$2"
  local expression="$3"
  local detail="$4"
  if jq -e "$expression" "$response_file" >/dev/null 2>&1; then
    record_step "$step" "pass" "" "" "$response_file" "$detail"
    return 0
  fi
  record_step "$step" "fail" "" "" "$response_file" "$detail"
  fail_with 1 "response assertion failed for $step: $detail"
}

wait_for_health_ready() {
  local url="$1"
  local response_file="$reports_dir/local_tdpnd_health.json"
  local code
  for _ in $(seq 1 100); do
    if [[ -n "$TDPND_PID" ]] && ! kill -0 "$TDPND_PID" 2>/dev/null; then
      return 2
    fi
    code="$(curl -sS -m 2 -o "$response_file" -w "%{http_code}" "$url" 2>/dev/null || true)"
    if [[ "$code" == "200" ]]; then
      return 0
    fi
    sleep 0.1
  done
  return 3
}

start_local_bridge() {
  need_cmd go
  local port
  port="$(pick_port)"
  if [[ -z "$port" ]]; then
    fail_with 2 "failed to allocate local tdpnd settlement bridge port"
  fi
  bridge_token="${bridge_token:-gpm-admin-live-bridge-token-$$}"
  reward_proof_token="${reward_proof_token:-gpm-admin-live-proof-token-$$}"
  finality_token="${finality_token:-gpm-admin-live-finality-token-$$}"
  bridge_url="http://127.0.0.1:$port"
  LOCAL_TDPND_LOG="$reports_dir/gpm_admin_settlement_live_evidence_tdpnd.log"
  local bin_suffix=""
  if [[ "$(go env GOOS 2>/dev/null || true)" == "windows" ]]; then
    bin_suffix=".exe"
  fi
  LOCAL_TDPND_BIN="$(mktemp -t "gpm-admin-settlement-tdpnd.XXXXXX${bin_suffix}")"
  mkdir -p "$ROOT_DIR/.gocache"
  export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"
  if ! (
    cd "$ROOT_DIR/blockchain/tdpn-chain"
    go build -o "$LOCAL_TDPND_BIN" ./cmd/tdpnd
  ) >"$LOCAL_TDPND_LOG" 2>&1; then
    fail_with 1 "failed to build local tdpnd settlement bridge; inspect $LOCAL_TDPND_LOG"
  fi
  "$LOCAL_TDPND_BIN" \
    --settlement-http-listen "127.0.0.1:$port" \
    --settlement-http-auth-token "$bridge_token" \
    --settlement-http-reward-proof-auth-token "$reward_proof_token" \
    --settlement-http-finality-auth-token "$finality_token" \
    --settlement-http-reward-proof-verifier-id "gpm-admin-live-evidence" \
    >>"$LOCAL_TDPND_LOG" 2>&1 &
  TDPND_PID=$!
  disown "$TDPND_PID" 2>/dev/null || true
  if ! wait_for_health_ready "$bridge_url/health"; then
    fail_with 1 "local tdpnd settlement bridge did not become healthy; inspect $LOCAL_TDPND_LOG"
  fi
}

if [[ -n "$bridge_token_file" ]]; then
  bridge_token="$(read_secret_file "$bridge_token_file")"
fi
if [[ -n "$reward_proof_token_file" ]]; then
  reward_proof_token="$(read_secret_file "$reward_proof_token_file")"
fi
if [[ -n "$finality_token_file" ]]; then
  finality_token="$(read_secret_file "$finality_token_file")"
fi

if [[ "$start_local_tdpnd" == "1" ]]; then
  start_local_bridge
fi

bridge_url="$(trim "$bridge_url")"
bridge_url="${bridge_url%/}"
if [[ -z "$bridge_url" ]]; then
  fail_with 2 "bridge URL is required; set --bridge-url or GPM_ADMIN_SETTLEMENT_BRIDGE_URL, or use --start-local-tdpnd 1"
fi
case "$bridge_url" in
  http://*|https://*) ;;
  *)
    fail_with 2 "bridge URL must start with http:// or https://"
    ;;
esac
if [[ -z "$bridge_token" ]]; then
  fail_with 2 "bridge token is required; set --bridge-token or --bridge-token-file"
fi
if [[ -z "$reward_proof_token" ]]; then
  fail_with 2 "reward proof token is required; set --reward-proof-token or --reward-proof-token-file"
fi
if [[ "$require_finality" == "1" && -z "$finality_token" ]]; then
  fail_with 2 "finality token is required when --require-finality 1"
fi

validate_bearer_token_literal "$bridge_token" || fail_with 2 "invalid bridge token"
validate_bearer_token_literal "$reward_proof_token" || fail_with 2 "invalid reward proof token"
if [[ -n "$finality_token" ]]; then
  validate_bearer_token_literal "$finality_token" || fail_with 2 "invalid finality token"
fi

subject_id="client-${run_id}"
provider_id="provider-${run_id}"
session_id="session-${run_id}"
reservation_id="bill-res-${run_id}"
settlement_id="set-${run_id}"
reward_id="reward-${run_id}"
proof_path="traffic-proof/${reward_id}"
proof_ref="obj://${proof_path}"
distribution_id="dist:${reward_id}"
evidence_id="slash-${run_id}"
penalty_id="penalty-${run_id}"
amount_micros=25000
charged_micros=21000
reward_micros=700
slash_micros=2500
payout_start="2026-04-20T00:00:00Z"
payout_end="2026-04-27T00:00:00Z"
issued_at="2026-04-27T00:00:01Z"
verified_at="2026-04-27T00:00:02Z"
created_at="2026-04-27T00:00:03Z"
settled_at="2026-04-27T00:00:04Z"
observed_at="2026-04-27T00:00:05Z"

set_signal "bridge_health_ok" 0
set_signal "auth_negative_ok" 0
set_signal "missing_proof_fail_closed_ok" 0
set_signal "reward_proof_registered_ok" 0
set_signal "reward_proof_query_ok" 0
set_signal "reservation_confirmed_ok" 0
set_signal "settlement_confirmed_ok" 0
set_signal "weekly_reward_confirmed_ok" 0
set_signal "slash_hold_fail_closed_ok" 0
set_signal "slash_evidence_mismatch_fail_closed_ok" 0
set_signal "slash_evidence_confirmed_ok" 0
set_signal "penalty_after_confirmation_ok" 0
set_signal "query_by_id_ok" 0

request_json "bridge_health" "GET" "/health" "" "200" "none"
set_signal "bridge_health_ok" 1

unauth_reward_payload="$(jq -cn \
  --arg RewardID "unauth-${reward_id}" \
  --arg ProviderSubjectID "$provider_id" \
  --arg SessionID "$session_id" \
  --arg TrafficProofRef "$proof_ref" \
  --arg Currency "$currency" \
  --arg IssuedAt "$issued_at" \
  --argjson RewardMicros "$reward_micros" \
  '{RewardID:$RewardID,ProviderSubjectID:$ProviderSubjectID,SessionID:$SessionID,TrafficProofRef:$TrafficProofRef,RewardMicros:$RewardMicros,Currency:$Currency,IssuedAt:$IssuedAt}')"
request_json "reward_issue_auth_negative" "POST" "/x/vpnrewards/issues" "$unauth_reward_payload" "401" "none"
set_signal "auth_negative_ok" 1

missing_proof_reward_payload="$(jq -cn \
  --arg RewardID "$reward_id" \
  --arg ProviderSubjectID "$provider_id" \
  --arg SessionID "$session_id" \
  --arg TrafficProofRef "$proof_ref" \
  --arg PayoutPeriodStart "$payout_start" \
  --arg PayoutPeriodEnd "$payout_end" \
  --arg Currency "$currency" \
  --arg IssuedAt "$issued_at" \
  --argjson RewardMicros "$reward_micros" \
  '{RewardID:$RewardID,ProviderSubjectID:$ProviderSubjectID,SessionID:$SessionID,TrafficProofRef:$TrafficProofRef,PayoutPeriodStart:$PayoutPeriodStart,PayoutPeriodEnd:$PayoutPeriodEnd,RewardMicros:$RewardMicros,Currency:$Currency,IssuedAt:$IssuedAt}')"
request_json "reward_missing_objective_proof_fail_closed" "POST" "/x/vpnrewards/issues" "$missing_proof_reward_payload" "409" "main"
assert_response_jq "reward_missing_objective_proof_error_contract" "$LAST_RESPONSE_FILE" '.error | tostring | test("proof|verified|reward"; "i")' "missing objective proof must be rejected before reward issue"
set_signal "missing_proof_fail_closed_ok" 1

proof_payload="$(jq -cn \
  --arg ProofPath "$proof_path" \
  --arg TrafficProofRef "$proof_ref" \
  --arg TrustContract "settlement.reward.objective-traffic.v1" \
  --arg RewardID "$reward_id" \
  --arg ProviderSubjectID "$provider_id" \
  --arg SessionID "$session_id" \
  --arg PayoutPeriodStart "$payout_start" \
  --arg PayoutPeriodEnd "$payout_end" \
  --arg Currency "$currency" \
  --arg IssuedAt "$issued_at" \
  --arg VerifierID "gpm-admin-live-evidence" \
  --arg VerifiedAt "$verified_at" \
  --argjson RewardMicros "$reward_micros" \
  '{ProofPath:$ProofPath,TrafficProofRef:$TrafficProofRef,TrustContract:$TrustContract,RewardID:$RewardID,ProviderSubjectID:$ProviderSubjectID,SessionID:$SessionID,PayoutPeriodStart:$PayoutPeriodStart,PayoutPeriodEnd:$PayoutPeriodEnd,RewardMicros:$RewardMicros,Currency:$Currency,IssuedAt:$IssuedAt,Verified:true,VerifierID:$VerifierID,VerifiedAt:$VerifiedAt}')"
request_json "reward_objective_proof_register" "POST" "/x/vpnrewards/proofs" "$proof_payload" "200" "proof"
assert_response_jq "reward_objective_proof_register_contract" "$LAST_RESPONSE_FILE" '.ok == true' "proof registration must return ok=true"
set_signal "reward_proof_registered_ok" 1

encoded_proof_path="$(url_encode "$proof_path")"
request_json "reward_objective_proof_query" "GET" "/x/vpnrewards/proofs/$encoded_proof_path" "" "200" "main"
assert_response_jq "reward_objective_proof_query_contract" "$LAST_RESPONSE_FILE" ".proof.verified == true and .proof.traffic_proof_ref == \"$proof_ref\" and .proof.trust_contract == \"settlement.reward.objective-traffic.v1\" and .proof.reward_id == \"$reward_id\"" "proof query must show verified objective traffic proof bound to reward material"
set_signal "reward_proof_query_ok" 1

reservation_payload="$(jq -cn \
  --arg ReservationID "$reservation_id" \
  --arg SessionID "$session_id" \
  --arg SubjectID "$subject_id" \
  --arg Currency "$currency" \
  --arg CreatedAt "$created_at" \
  --argjson AmountMicros "$amount_micros" \
  '{ReservationID:$ReservationID,SessionID:$SessionID,SubjectID:$SubjectID,AmountMicros:$AmountMicros,Currency:$Currency,CreatedAt:$CreatedAt}')"
request_json "reservation_submit" "POST" "/x/vpnbilling/reservations" "$reservation_payload" "200" "main"
reservation_confirm_payload="$(printf '%s\n' "$reservation_payload" | jq -c '. + {Status:"confirmed"}')"
request_json "reservation_confirm_finality" "POST" "/x/vpnbilling/reservations" "$reservation_confirm_payload" "200" "finality"
assert_response_jq "reservation_confirm_finality_contract" "$LAST_RESPONSE_FILE" '.ok == true' "reservation finality confirmation must return ok=true"
set_signal "reservation_confirmed_ok" 1

settlement_payload="$(jq -cn \
  --arg SettlementID "$settlement_id" \
  --arg ReservationID "$reservation_id" \
  --arg SessionID "$session_id" \
  --arg SubjectID "$subject_id" \
  --arg Currency "$currency" \
  --arg SettledAt "$settled_at" \
  --arg Status "confirmed" \
  --argjson ChargedMicros "$charged_micros" \
  '{SettlementID:$SettlementID,ReservationID:$ReservationID,SessionID:$SessionID,SubjectID:$SubjectID,ChargedMicros:$ChargedMicros,Currency:$Currency,SettledAt:$SettledAt,Status:$Status}')"
request_json "settlement_confirm_finality" "POST" "/x/vpnbilling/settlements" "$settlement_payload" "200" "finality"
assert_response_jq "settlement_confirm_finality_contract" "$LAST_RESPONSE_FILE" '.ok == true' "settlement finality confirmation must return ok=true"
set_signal "settlement_confirmed_ok" 1

reward_payload="$(jq -cn \
  --arg RewardID "$reward_id" \
  --arg ProviderSubjectID "$provider_id" \
  --arg SessionID "$session_id" \
  --arg TrafficProofRef "$proof_ref" \
  --arg PayoutPeriodStart "$payout_start" \
  --arg PayoutPeriodEnd "$payout_end" \
  --arg Currency "$currency" \
  --arg IssuedAt "$issued_at" \
  --argjson RewardMicros "$reward_micros" \
  '{RewardID:$RewardID,ProviderSubjectID:$ProviderSubjectID,SessionID:$SessionID,TrafficProofRef:$TrafficProofRef,PayoutPeriodStart:$PayoutPeriodStart,PayoutPeriodEnd:$PayoutPeriodEnd,RewardMicros:$RewardMicros,Currency:$Currency,IssuedAt:$IssuedAt}')"
request_json "weekly_reward_submit" "POST" "/x/vpnrewards/issues" "$reward_payload" "200" "main"
reward_confirm_payload="$(printf '%s\n' "$reward_payload" | jq -c '. + {Status:"confirmed"}')"
request_json "weekly_reward_confirm_finality" "POST" "/x/vpnrewards/issues" "$reward_confirm_payload" "200" "finality"
assert_response_jq "weekly_reward_confirm_finality_contract" "$LAST_RESPONSE_FILE" '.ok == true' "weekly reward finality confirmation must return ok=true"
set_signal "weekly_reward_confirmed_ok" 1

encoded_distribution_id="$(url_encode "$distribution_id")"
request_json "weekly_reward_distribution_query" "GET" "/x/vpnrewards/distributions/$encoded_distribution_id" "" "200" "main"
assert_response_jq "weekly_reward_distribution_query_contract" "$LAST_RESPONSE_FILE" ".distribution.DistributionID == \"$distribution_id\" and (.distribution.Status | tostring | test(\"confirmed\"; \"i\"))" "distribution query must show confirmed reward distribution"

evidence_payload="$(jq -cn \
  --arg EvidenceID "$evidence_id" \
  --arg SubjectID "$provider_id" \
  --arg SessionID "$session_id" \
  --arg ViolationType "double-sign" \
  --arg EvidenceRef "sha256:6ca13d52ca70c883e0f0bb101e425a89e8624de51db2d2392593af6a84118090" \
  --arg Currency "$currency" \
  --arg ObservedAt "$observed_at" \
  --argjson SlashMicros "$slash_micros" \
  '{EvidenceID:$EvidenceID,SubjectID:$SubjectID,SessionID:$SessionID,ViolationType:$ViolationType,EvidenceRef:$EvidenceRef,SlashMicros:$SlashMicros,Currency:$Currency,ObservedAt:$ObservedAt}')"
request_json "slash_evidence_submit" "POST" "/x/vpnslashing/evidence" "$evidence_payload" "200" "main"

penalty_payload="$(jq -cn \
  --arg PenaltyID "$penalty_id" \
  --arg EvidenceID "$evidence_id" \
  --arg Currency "$currency" \
  --argjson SlashBasisPoint 25 \
  --argjson SlashMicros "$slash_micros" \
  '{PenaltyID:$PenaltyID,EvidenceID:$EvidenceID,SlashBasisPoint:$SlashBasisPoint,SlashMicros:$SlashMicros,Currency:$Currency}')"
request_json "slash_penalty_before_evidence_finality_fail_closed" "POST" "/x/vpnslashing/penalties" "$penalty_payload" "400" "main"
assert_response_jq "slash_penalty_before_evidence_finality_error_contract" "$LAST_RESPONSE_FILE" '.error | tostring | test("non-final|confirmed|final"; "i")' "penalty must fail closed while slash evidence is not final"
set_signal "slash_hold_fail_closed_ok" 1

slash_mismatch_payload="$(jq -cn --arg Status "confirmed" --arg SessionID "mismatched-${session_id}" '{Status:$Status,SessionID:$SessionID}')"
request_json "slash_evidence_mismatch_finality_fail_closed" "PATCH" "/x/vpnslashing/evidence/$evidence_id" "$slash_mismatch_payload" "409" "finality"
assert_response_jq "slash_evidence_mismatch_finality_error_contract" "$LAST_RESPONSE_FILE" '.error | tostring | test("material mismatch"; "i")' "slash evidence finality must reject optional material that differs from stored evidence"
set_signal "slash_evidence_mismatch_fail_closed_ok" 1

request_json "slash_evidence_confirm_finality" "PATCH" "/x/vpnslashing/evidence/$evidence_id" '{"Status":"confirmed"}' "200" "finality"
assert_response_jq "slash_evidence_confirm_finality_contract" "$LAST_RESPONSE_FILE" '.ok == true' "slash evidence finality confirmation must return ok=true"
set_signal "slash_evidence_confirmed_ok" 1

request_json "slash_penalty_after_evidence_finality" "POST" "/x/vpnslashing/penalties" "$penalty_payload" "200" "main"
assert_response_jq "slash_penalty_after_evidence_finality_contract" "$LAST_RESPONSE_FILE" '.ok == true' "penalty must be accepted after evidence finality"
set_signal "penalty_after_confirmation_ok" 1

request_json "settlement_query_by_id" "GET" "/x/vpnbilling/settlements/$settlement_id" "" "200" "main"
assert_response_jq "settlement_query_by_id_contract" "$LAST_RESPONSE_FILE" ".settlement.SettlementID == \"$settlement_id\" and .settlement.ReservationID == \"$reservation_id\"" "settlement query must be bound to reservation"
request_json "slash_evidence_query_by_id" "GET" "/x/vpnslashing/evidence/$evidence_id" "" "200" "main"
assert_response_jq "slash_evidence_query_by_id_contract" "$LAST_RESPONSE_FILE" ".evidence.EvidenceID == \"$evidence_id\" and (.evidence.Status | tostring | test(\"confirmed\"; \"i\"))" "slash evidence query must show confirmed status"
request_json "slash_penalty_query_by_id" "GET" "/x/vpnslashing/penalties/$penalty_id" "" "200" "main"
assert_response_jq "slash_penalty_query_by_id_contract" "$LAST_RESPONSE_FILE" ".penalty.PenaltyID == \"$penalty_id\" and .penalty.EvidenceID == \"$evidence_id\"" "penalty query must bind to slash evidence"
set_signal "query_by_id_ok" 1

final_status="pass"
final_rc=0
write_outputs
echo "[gpm-admin-settlement-live-evidence] status=pass rc=0 bridge_kind=$(if [[ "$start_local_tdpnd" == "1" ]]; then printf 'local_tdpnd'; else printf 'remote'; fi) summary_json=$summary_json"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit 0
