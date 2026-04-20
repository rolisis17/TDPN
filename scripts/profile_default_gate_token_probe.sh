#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_default_gate_token_probe.sh \
    --directory-url URL \
    --issuer-url URL \
    --exit-url URL \
    --campaign-subject INVITE_KEY \
    [--reports-dir DIR] \
    [--connect-timeout-sec N] \
    [--max-time-sec N] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]] \
    [--show-json [0|1]]

Purpose:
  Run a fast live token-proof binding probe against directory/issuer/exit
  endpoints. This isolates token-proof mismatches before a long profile
  campaign run.

Notes:
  - Probe intentionally omits session_id in path-open request.
  - A response reason like "missing session_id" indicates token proof passed.
  - A response reason like "token proof invalid" indicates key-binding mismatch.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
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
    echo ""
    return
  fi
  if [[ "$path" = /* ]]; then
    echo "$path"
  else
    echo "$ROOT_DIR/$path"
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

normalize_url() {
  local url
  url="$(trim "${1:-}")"
  while [[ "$url" == */ ]]; do
    url="${url%/}"
  done
  printf '%s\n' "$url"
}

url_scheme() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlparse

raw = sys.argv[1].strip()
parsed = urlparse(raw)
print((parsed.scheme or "").lower())
PY
}

url_host() {
  python3 - "$1" <<'PY'
import sys
from urllib.parse import urlparse

raw = sys.argv[1].strip()
parsed = urlparse(raw)
print((parsed.hostname or "").lower())
PY
}

is_loopback_host() {
  local host
  host="$(trim "${1:-}")"
  host="${host,,}"
  if [[ -z "$host" ]]; then
    return 1
  fi
  if [[ "$host" == "localhost" || "$host" == *.localhost || "$host" == "::1" ]]; then
    return 0
  fi
  if [[ "$host" == 127.* ]]; then
    return 0
  fi
  return 1
}

require_secure_url_for_remote() {
  local label="$1"
  local raw_url="$2"
  local scheme host
  scheme="$(url_scheme "$raw_url")"
  host="$(url_host "$raw_url")"
  if [[ "$scheme" != "http" && "$scheme" != "https" ]]; then
    echo "$label must use http:// or https://"
    exit 2
  fi
  if [[ "$scheme" == "http" ]] && ! is_loopback_host "$host"; then
    echo "$label must use https:// for non-loopback hosts (got: $raw_url)"
    exit 2
  fi
}

need_cmd curl
need_cmd jq
need_cmd go
need_cmd python3

directory_url=""
issuer_url=""
exit_url=""
campaign_subject="${CAMPAIGN_SUBJECT:-${INVITE_KEY:-}}"
reports_dir="${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
connect_timeout_sec="${PROFILE_DEFAULT_GATE_TOKEN_PROBE_CONNECT_TIMEOUT_SEC:-4}"
max_time_sec="${PROFILE_DEFAULT_GATE_TOKEN_PROBE_MAX_TIME_SEC:-12}"
summary_json=""
print_summary_json="${PROFILE_DEFAULT_GATE_TOKEN_PROBE_PRINT_SUMMARY_JSON:-0}"
show_json="${PROFILE_DEFAULT_GATE_TOKEN_PROBE_SHOW_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory-url)
      directory_url="${2:-}"
      shift 2
      ;;
    --directory-url=*)
      directory_url="${1#*=}"
      shift
      ;;
    --issuer-url)
      issuer_url="${2:-}"
      shift 2
      ;;
    --issuer-url=*)
      issuer_url="${1#*=}"
      shift
      ;;
    --exit-url)
      exit_url="${2:-}"
      shift 2
      ;;
    --exit-url=*)
      exit_url="${1#*=}"
      shift
      ;;
    --campaign-subject|--subject)
      campaign_subject="${2:-}"
      shift 2
      ;;
    --campaign-subject=*|--subject=*)
      campaign_subject="${1#*=}"
      shift
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --connect-timeout-sec)
      connect_timeout_sec="${2:-}"
      shift 2
      ;;
    --connect-timeout-sec=*)
      connect_timeout_sec="${1#*=}"
      shift
      ;;
    --max-time-sec)
      max_time_sec="${2:-}"
      shift 2
      ;;
    --max-time-sec=*)
      max_time_sec="${1#*=}"
      shift
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
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
    --print-summary-json=*)
      print_summary_json="${1#*=}"
      shift
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
    --show-json=*)
      show_json="${1#*=}"
      shift
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
bool_arg_or_die "--show-json" "$show_json"

if ! [[ "$connect_timeout_sec" =~ ^[0-9]+$ ]] || ((connect_timeout_sec <= 0)); then
  echo "--connect-timeout-sec must be > 0"
  exit 2
fi
if ! [[ "$max_time_sec" =~ ^[0-9]+$ ]] || ((max_time_sec <= 0)); then
  echo "--max-time-sec must be > 0"
  exit 2
fi

directory_url="$(normalize_url "$directory_url")"
issuer_url="$(normalize_url "$issuer_url")"
exit_url="$(normalize_url "$exit_url")"
campaign_subject="$(trim "$campaign_subject")"
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$directory_url" ]]; then
  echo "--directory-url is required"
  exit 2
fi
if [[ -z "$issuer_url" ]]; then
  echo "--issuer-url is required"
  exit 2
fi
if [[ -z "$exit_url" ]]; then
  echo "--exit-url is required"
  exit 2
fi
if [[ -z "$campaign_subject" ]]; then
  echo "--campaign-subject is required (or set CAMPAIGN_SUBJECT/INVITE_KEY)"
  exit 2
fi
require_secure_url_for_remote "--directory-url" "$directory_url"
require_secure_url_for_remote "--issuer-url" "$issuer_url"
require_secure_url_for_remote "--exit-url" "$exit_url"

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_default_gate_token_probe_${run_stamp}.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
mkdir -p "$(dirname "$summary_json")"

issue_body_json="$reports_dir/profile_default_gate_token_probe_${run_stamp}_issue_response.json"
path_open_body_json="$reports_dir/profile_default_gate_token_probe_${run_stamp}_path_open_response.json"
mkdir -p "$reports_dir"

cleanup_files=()
cleanup() {
  if [[ ${#cleanup_files[@]} -gt 0 ]]; then
    rm -f "${cleanup_files[@]}" 2>/dev/null || true
  fi
}
trap cleanup EXIT

status="fail"
rc=1
notes="probe did not run"
failure_stage=""
failure_reason=""
exit_id=""
exit_region=""
token_issue_http_code=0
path_open_http_code=0
path_open_reason=""
token_pop_pub_key=""
generated_pop_pub_key=""
generated_pop_pub_key_matches_token="null"
token_proof_verified=false

generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

key_json="$(go run ./cmd/tokenpop gen --show-private-key)"
token_proof_priv_key="$(printf '%s' "$key_json" | jq -r '.private_key // empty')"
generated_pop_pub_key="$(printf '%s' "$key_json" | jq -r '.public_key // empty')"
token_proof_priv_key_file=""
if [[ -z "$token_proof_priv_key" || -z "$generated_pop_pub_key" ]]; then
  failure_stage="generate_pop_key"
  failure_reason="failed to generate token proof keypair"
else
  token_proof_priv_key_file="$(mktemp)"
  chmod 600 "$token_proof_priv_key_file"
  printf '%s' "$token_proof_priv_key" >"$token_proof_priv_key_file"
  cleanup_files+=("$token_proof_priv_key_file")
fi

relays_json=""
if [[ -z "$failure_stage" ]]; then
  if ! relays_json="$(curl -fsS --connect-timeout "$connect_timeout_sec" --max-time "$max_time_sec" "${directory_url}/v1/relays")"; then
    failure_stage="directory_relays"
    failure_reason="failed to fetch directory relays"
  fi
fi

if [[ -z "$failure_stage" ]]; then
  exit_id="$(printf '%s' "$relays_json" | jq -r '[.relays[]? | select((.role // "") == "exit") | (.relay_id // "")] | map(select(. != "")) | .[0] // ""')"
  exit_region="$(printf '%s' "$relays_json" | jq -r '[.relays[]? | select((.role // "") == "exit") | (.region // "")] | map(select(. != "")) | .[0] // "local"')"
  if [[ -z "$exit_id" ]]; then
    failure_stage="directory_relays"
    failure_reason="no exit relay_id found in directory relay list"
  fi
fi

issue_token_response_body=""
token_value=""
token_value_file=""
if [[ -z "$failure_stage" ]]; then
  issue_body_raw="$(mktemp)"
  cleanup_files+=("$issue_body_raw")
  issue_payload="$(jq -nc \
    --arg pop_pub_key "$generated_pop_pub_key" \
    '{tier:1,subject:input,token_type:"client_access",pop_pub_key:$pop_pub_key}' <<<"$campaign_subject")"
  token_issue_http_code="$(
    curl -sS \
      --connect-timeout "$connect_timeout_sec" \
      --max-time "$max_time_sec" \
      -o "$issue_body_raw" \
      -w '%{http_code}' \
      -X POST "${issuer_url}/v1/token" \
      -H 'Content-Type: application/json' \
      -d "$issue_payload" || printf '%s' "0"
  )"
  issue_token_response_body="$(cat "$issue_body_raw" 2>/dev/null || true)"
  token_value="$(printf '%s' "$issue_token_response_body" | jq -r '.token // empty' 2>/dev/null || true)"
  if jq -e . "$issue_body_raw" >/dev/null 2>&1; then
    jq 'if type == "object" and has("token") then .token = "[REDACTED]" else . end' \
      "$issue_body_raw" >"$issue_body_json" 2>/dev/null || cp "$issue_body_raw" "$issue_body_json"
  else
    cp "$issue_body_raw" "$issue_body_json"
  fi
  if [[ "$token_issue_http_code" != "200" || -z "$token_value" ]]; then
    failure_stage="issue_token"
    failure_reason="issuer token issue failed (http=${token_issue_http_code})"
  else
    token_value_file="$(mktemp)"
    chmod 600 "$token_value_file"
    printf '%s' "$token_value" >"$token_value_file"
    cleanup_files+=("$token_value_file")
  fi
fi

if [[ -z "$failure_stage" ]]; then
  token_payload_json="$(python3 - "$token_value_file" <<'PY'
import base64
import json
import sys

token_file = sys.argv[1]
try:
    with open(token_file, "r", encoding="utf-8") as fh:
        token = fh.read().strip()
except Exception:
    print("{}")
    sys.exit(0)
parts = token.split(".")
if len(parts) == 0 or parts[0] == "":
    print("{}")
    sys.exit(0)
payload = parts[0]
payload += "=" * ((4 - len(payload) % 4) % 4)
try:
    decoded = base64.urlsafe_b64decode(payload.encode("utf-8")).decode("utf-8")
except Exception:
    print("{}")
    sys.exit(0)
print(decoded)
PY
)"
  token_pop_pub_key="$(printf '%s' "$token_payload_json" | jq -r '.cnf_ed25519 // empty' 2>/dev/null || true)"
  if [[ -n "$token_pop_pub_key" ]]; then
    if [[ "$token_pop_pub_key" == "$generated_pop_pub_key" ]]; then
      generated_pop_pub_key_matches_token="true"
    else
      generated_pop_pub_key_matches_token="false"
    fi
  fi
fi

if [[ -z "$failure_stage" ]]; then
  proof_raw="$(go run ./cmd/tokenpop sign \
    --private-key-file "$token_proof_priv_key_file" \
    --token-file "$token_value_file" \
    --exit-id "$exit_id" \
    --proof-nonce "token-probe-nonce-1" \
    --client-inner-pub "abc" \
    --transport "wireguard-udp" \
    --requested-mtu "1280" \
    --requested-region "$exit_region")"
  proof_value="$(printf '%s' "$proof_raw" | jq -r '.proof // empty' 2>/dev/null || true)"
  if [[ -z "$proof_value" ]]; then
    # Backward compatibility for tokenpop versions that output the raw proof string.
    proof_value="$proof_raw"
  fi
  path_open_payload="$(jq -nc \
    --arg exit_id "$exit_id" \
    --rawfile token "$token_value_file" \
    --arg proof "$proof_value" \
    --arg exit_region "$exit_region" \
    '{
      exit_id: $exit_id,
      token: ($token | rtrimstr("\n")),
      token_proof: $proof,
      token_proof_nonce: "token-probe-nonce-1",
      client_inner_pub: "abc",
      transport: "wireguard-udp",
      requested_mtu: 1280,
      requested_region: $exit_region
    }')"
  path_open_payload_file="$(mktemp)"
  chmod 600 "$path_open_payload_file"
  printf '%s' "$path_open_payload" >"$path_open_payload_file"
  cleanup_files+=("$path_open_payload_file")
  path_open_http_code="$(
    curl -sS \
      --connect-timeout "$connect_timeout_sec" \
      --max-time "$max_time_sec" \
      -o "$path_open_body_json" \
      -w '%{http_code}' \
      -X POST "${exit_url}/v1/path/open" \
      -H 'Content-Type: application/json' \
      --data-binary "@${path_open_payload_file}" || printf '%s' "0"
  )"
  path_open_reason="$(jq -r '.reason // ""' "$path_open_body_json" 2>/dev/null || true)"
  if [[ "$path_open_http_code" != "200" ]]; then
    failure_stage="path_open"
    failure_reason="exit path-open request failed (http=${path_open_http_code})"
  elif [[ "$path_open_reason" == "token proof invalid" || "$path_open_reason" == "token proof key invalid" || "$path_open_reason" == "token verification failed" ]]; then
    failure_stage="path_open"
    failure_reason="token proof verification failed at exit (${path_open_reason})"
  else
    token_proof_verified=true
  fi
fi

if [[ -z "$failure_stage" ]]; then
  status="pass"
  rc=0
  notes="token proof probe passed (proof accepted before later validation stage)"
else
  status="fail"
  rc=1
  notes="$failure_reason"
fi

campaign_subject_redacted=""
if [[ -n "$campaign_subject" ]]; then
  campaign_subject_redacted="[redacted]"
fi

jq -n \
  --arg generated_at_utc "$generated_at_utc" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg failure_stage "$failure_stage" \
  --arg failure_reason "$failure_reason" \
  --arg directory_url "$directory_url" \
  --arg issuer_url "$issuer_url" \
  --arg exit_url "$exit_url" \
  --arg campaign_subject "$campaign_subject_redacted" \
  --arg exit_id "$exit_id" \
  --arg exit_region "$exit_region" \
  --argjson rc "$rc" \
  --argjson connect_timeout_sec "$connect_timeout_sec" \
  --argjson max_time_sec "$max_time_sec" \
  --argjson token_issue_http_code "$token_issue_http_code" \
  --argjson path_open_http_code "$path_open_http_code" \
  --arg path_open_reason "$path_open_reason" \
  --arg token_pop_pub_key "$token_pop_pub_key" \
  --arg generated_pop_pub_key "$generated_pop_pub_key" \
  --argjson generated_pop_pub_key_matches_token "$generated_pop_pub_key_matches_token" \
  --argjson token_proof_verified "$( [[ "$token_proof_verified" == true ]] && echo true || echo false )" \
  --arg issue_body_json "$issue_body_json" \
  --arg path_open_body_json "$path_open_body_json" \
  --arg summary_json "$summary_json" \
  '{
    version: 1,
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: $notes,
    failure_stage: (if $failure_stage == "" then null else $failure_stage end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    inputs: {
      directory_url: $directory_url,
      issuer_url: $issuer_url,
      exit_url: $exit_url,
      campaign_subject: $campaign_subject,
      connect_timeout_sec: $connect_timeout_sec,
      max_time_sec: $max_time_sec
    },
    probe: {
      exit_id: $exit_id,
      exit_region: $exit_region,
      token_issue_http_code: $token_issue_http_code,
      path_open_http_code: $path_open_http_code,
      path_open_reason: $path_open_reason,
      token_pop_pub_key: $token_pop_pub_key,
      generated_pop_pub_key: $generated_pop_pub_key,
      generated_pop_pub_key_matches_token: $generated_pop_pub_key_matches_token,
      token_proof_verified: $token_proof_verified
    },
    artifacts: {
      summary_json: $summary_json,
      issue_response_json: $issue_body_json,
      path_open_response_json: $path_open_body_json
    }
  }' >"$summary_json"

echo "profile-default-gate-token-probe: status=$status rc=$rc"
echo "summary_json: $summary_json"

if [[ "$show_json" == "1" ]]; then
  echo "[profile-default-gate-token-probe] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
