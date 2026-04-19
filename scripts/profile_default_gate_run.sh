#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_default_gate_run.sh \
    [--directory-a HOST_OR_URL | --host-a HOST_OR_URL] \
    [--directory-b HOST_OR_URL | --host-b HOST_OR_URL] \
    [--directory-a-port N] \
    [--directory-b-port N] \
    [--endpoint-wait-timeout-sec N] \
    [--endpoint-wait-interval-sec N] \
    [--endpoint-connect-timeout-sec N] \
    [--allow-insecure-probe [0|1]] \
    [--heartbeat-interval-sec N] \
    [--campaign-subject INVITE_KEY | --subject INVITE_KEY | --key INVITE_KEY | --invite-key INVITE_KEY] \
    [profile-compare-campaign-signoff args...]

Purpose:
  Run the final optional profile-default gate refresh/signoff with
  endpoint wait-retry preflight for A/B directory URLs.

Notes:
  - --host-a/--host-b are aliases for --directory-a/--directory-b.
  - --directory-a/--directory-b accept hostnames, host:port, or full http(s) URLs.
  - Host-style inputs are normalized to http://HOST:PORT (default port 8081).
  - TLS verification is on by default for endpoint probes; pass
    --allow-insecure-probe 1 only for local self-signed setups.
  - This helper requires invite-key subject mode; passthrough anon-cred flags
    (--campaign-anon-cred/--anon-cred) are rejected.
  - --key/--invite-key are aliases for --subject.
  - Subject fallback order when CLI subject is omitted:
    CAMPAIGN_SUBJECT env, INVITE_KEY env, CAMPAIGN_SUBJECT file, INVITE_KEY file.
  - Env-file fallback default: $ROOT_DIR/deploy/.env.easy.client
    (override via PROFILE_DEFAULT_GATE_RUN_ENV_CLIENT_FILE).
  - Invite subject placeholders (for example literal INVITE_KEY) fail fast.
  - Host placeholders (for example literal A_HOST/B_HOST) fail fast with
    a copy/paste-ready profile-default-gate-live example command.
  - This wrapper defaults signoff refresh mode to roadmap docker defaults:
    --refresh-campaign 1
    --campaign-execution-mode docker
    --campaign-start-local-stack 0
    --fail-on-no-go 0
    --campaign-timeout-sec 2400
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

strip_optional_wrapping_quotes() {
  local value="$1"
  local first_char="" last_char=""

  if (( ${#value} < 2 )); then
    printf '%s' "$value"
    return
  fi

  first_char="${value:0:1}"
  last_char="${value: -1}"
  if [[ "$first_char" == '"' && "$last_char" == '"' ]]; then
    value="${value:1:${#value}-2}"
  elif [[ "$first_char" == "'" && "$last_char" == "'" ]]; then
    value="${value:1:${#value}-2}"
  fi

  printf '%s' "$value"
}

invite_subject_looks_placeholder_01() {
  local value normalized
  value="$(trim "${1:-}")"
  value="$(strip_optional_wrapping_quotes "$value")"
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$normalized" in
    INVITE_KEY|\$\{INVITE_KEY\}|\$INVITE_KEY|"<INVITE_KEY>"|"{{INVITE_KEY}}"|YOUR_INVITE_KEY|REPLACE_WITH_INVITE_KEY)
      return 0
      ;;
  esac
  return 1
}

matches_placeholder_token_01() {
  local value token normalized
  value="$(trim "${1:-}")"
  token="$(trim "${2:-}")"
  value="$(strip_optional_wrapping_quotes "$value")"
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  token="$(printf '%s' "$token" | tr '[:lower:]' '[:upper:]')"

  case "$normalized" in
    "$token"|\$\{"$token"\}|\$"$token"|"<$token>"|"{{$token}}"|YOUR_"$token"|REPLACE_WITH_"$token")
      return 0
      ;;
  esac
  return 1
}

directory_host_looks_placeholder_01() {
  local value host
  value="$(trim "${1:-}")"
  value="$(strip_optional_wrapping_quotes "$value")"

  host="$value"
  host="${host#http://}"
  host="${host#https://}"
  host="${host%%/*}"
  if [[ "$host" =~ ^\[[^]]+\]:[0-9]+$ ]]; then
    host="${host%%]:*}]"
  elif [[ "$host" =~ :[0-9]+$ ]]; then
    host="${host%:*}"
  fi

  for token in A_HOST B_HOST HOST_A HOST_B DIRECTORY_A_HOST DIRECTORY_B_HOST DIR_A_HOST DIR_B_HOST; do
    if matches_placeholder_token_01 "$host" "$token"; then
      return 0
    fi
  done

  return 1
}

normalize_host_for_compare_01() {
  local host
  host="$(trim "${1:-}")"
  host="${host#[}"
  host="${host%]}"
  printf '%s' "$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
}

ip_literal_is_loopback_01() {
  local normalized
  normalized="$(normalize_host_for_compare_01 "${1:-}")"
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

host_resolves_to_loopback_only_01() {
  local normalized host_ips ip resolved_any
  normalized="$(normalize_host_for_compare_01 "${1:-}")"
  case "$normalized" in
    ""|localhost|ip6-localhost|::1|127.*)
      return 0
      ;;
    ::|0.0.0.0)
      return 0
      ;;
  esac
  if ip_literal_is_loopback_01 "$normalized"; then
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
    ip="$(trim "$ip")"
    if [[ -z "$ip" ]]; then
      continue
    fi
    resolved_any=1
    if ! ip_literal_is_loopback_01 "$ip"; then
      return 1
    fi
  done <<<"$host_ips"
  if [[ "$resolved_any" -ne 1 ]]; then
    return 1
  fi
  return 0
}

is_local_host_for_probe_01() {
  host_resolves_to_loopback_only_01 "${1:-}"
}

extract_host_from_hostport_01() {
  local host_port
  host_port="$(trim "${1:-}")"
  if [[ "$host_port" == \[* ]]; then
    if [[ "$host_port" =~ ^\[([^]]+)\] ]]; then
      printf '%s' "${BASH_REMATCH[1]}"
      return
    fi
  fi
  printf '%s' "${host_port%%:*}"
}

extract_url_host_01() {
  local url="$1"
  local remainder host_port
  if [[ ! "$url" =~ ^https?:// ]]; then
    printf '%s' ""
    return
  fi
  remainder="${url#*://}"
  remainder="${remainder%%/*}"
  host_port="${remainder##*@}"
  printf '%s' "$(extract_host_from_hostport_01 "$host_port")"
}

extract_url_scheme_01() {
  local url="$1"
  if [[ "$url" =~ ^([A-Za-z][A-Za-z0-9+.-]*):// ]]; then
    printf '%s' "$(printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]')"
    return
  fi
  printf '%s' ""
}

endpoint_scheme_for_host_01() {
  local host="$1"
  if is_local_host_for_probe_01 "$host"; then
    printf '%s' "http"
  else
    printf '%s' "https"
  fi
}

fail_placeholder_directory_input_01() {
  local label="$1"
  local raw_input="$2"

  echo "[profile-default-gate-run] $(timestamp_utc) failure_kind=unreachable_directory_endpoint label=$label reason=placeholder_directory_endpoint_input raw_input=$raw_input"
  echo "profile-default-gate-run failed: $label endpoint appears to be placeholder text ($raw_input)"
  echo "replace placeholders with real hosts/URLs for --directory-a/--directory-b (or --host-a/--host-b)"
  echo "example: ./scripts/easy_node.sh profile-default-gate-live --host-a <host-a> --host-b <host-b> --campaign-subject <invite-key>"
  exit 2
}

read_env_key_from_file() {
  local env_file="$1"
  local key="$2"
  local line value

  env_file="$(trim "$env_file")"
  if [[ -z "$env_file" || ! -f "$env_file" ]]; then
    printf '%s' ""
    return 0
  fi

  while IFS= read -r line || [[ -n "$line" ]]; do
    line="$(trim "$line")"
    if [[ -z "$line" || "$line" == \#* ]]; then
      continue
    fi
    if [[ "$line" == export[[:space:]]* ]]; then
      line="$(trim "${line#export}")"
    fi
    if [[ "$line" =~ ^${key}[[:space:]]*=(.*)$ ]]; then
      value="$(trim "${BASH_REMATCH[1]}")"
      value="$(strip_optional_wrapping_quotes "$value")"
      printf '%s' "$value"
      return 0
    fi
  done <"$env_file"

  printf '%s' ""
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

require_value_or_die() {
  local flag="$1"
  local argc="$2"
  if (( argc < 2 )); then
    echo "$flag requires a value"
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

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

array_has_arg_or_equals_prefix() {
  local flag="$1"
  shift
  local arg
  for arg in "$@"; do
    if [[ "$arg" == "$flag" || "$arg" == "$flag="* ]]; then
      return 0
    fi
  done
  return 1
}

extract_flag_value() {
  local flag="$1"
  shift
  local -a args=("$@")
  local value=""
  local idx=0
  local arg
  while (( idx < ${#args[@]} )); do
    arg="${args[$idx]}"
    if [[ "$arg" == "$flag" ]]; then
      if (( idx + 1 < ${#args[@]} )); then
        value="${args[$((idx + 1))]}"
      else
        value=""
      fi
      idx=$((idx + 2))
      continue
    fi
    if [[ "$arg" == "$flag="* ]]; then
      value="${arg#"$flag="}"
    fi
    idx=$((idx + 1))
  done
  printf '%s' "$value"
}

normalize_directory_url() {
  local label="$1"
  local raw_value="$2"
  local default_port="$3"
  local value host_port

  value="$(trim "$raw_value")"
  if [[ -z "$value" ]]; then
    printf '%s' ""
    return
  fi

  if [[ "$value" =~ ^https?:// ]]; then
    while [[ "$value" == */ ]]; do
      value="${value%/}"
    done
    printf '%s' "$value"
    return
  fi

  if [[ "$value" == *"/"* ]]; then
    echo "$label must be a host[:port] or full http(s) URL"
    exit 2
  fi

  host_port="$value"
  if [[ "$host_port" =~ ^\[[^]]+\]$ ]]; then
    host_port="${host_port}:$default_port"
  elif [[ "$host_port" =~ ^\[[^]]+\]:[0-9]+$ ]]; then
    :
  elif [[ "$host_port" =~ :[0-9]+$ ]]; then
    :
  elif [[ "$host_port" == *:* ]]; then
    host_port="[$host_port]:$default_port"
  else
    host_port="${host_port}:$default_port"
  fi

  local host scheme
  host="$(extract_host_from_hostport_01 "$host_port")"
  scheme="$(endpoint_scheme_for_host_01 "$host")"
  printf '%s://%s' "$scheme" "$host_port"
}

split_csv_trim() {
  local csv="$1"
  local -a parts=()
  local part
  IFS=',' read -r -a parts <<<"$csv"
  for part in "${parts[@]}"; do
    part="$(trim "$part")"
    if [[ -n "$part" ]]; then
      printf '%s\n' "$part"
    fi
  done
}

probe_url_for_directory() {
  local url="$1"
  if [[ "$url" =~ ^https?://[^/]+$ ]]; then
    printf '%s/v1/pubkeys' "$url"
  elif [[ "$url" =~ ^https?://[^/]+/$ ]]; then
    printf '%s/v1/pubkeys' "${url%/}"
  else
    printf '%s' "$url"
  fi
}

wait_for_directory_endpoint() {
  local label="$1"
  local directory_url="$2"
  local probe_url start_epoch deadline_epoch now_epoch attempt rc remaining_sec
  local elapsed_sec attempt_start_epoch probe_host probe_scheme
  local err_file err_text

  probe_url="$(probe_url_for_directory "$directory_url")"
  probe_host="$(extract_url_host_01 "$probe_url")"
  probe_scheme="$(extract_url_scheme_01 "$probe_url")"
  if [[ "$probe_scheme" == "http" ]] && ! is_local_host_for_probe_01 "$probe_host"; then
    echo "[profile-default-gate-run] $(timestamp_utc) wait-fail label=$label url=$probe_url error=remote_http_disallowed"
    echo "profile-default-gate-run failed: remote HTTP probe endpoint requires HTTPS ($label) url=$probe_url"
    return 2
  fi
  if [[ "$allow_insecure_probe" == "1" ]] && ! is_local_host_for_probe_01 "$probe_host"; then
    echo "[profile-default-gate-run] $(timestamp_utc) wait-fail label=$label url=$probe_url error=insecure_probe_remote_disallowed"
    echo "profile-default-gate-run failed: --allow-insecure-probe=1 is only allowed for local endpoints ($label) url=$probe_url"
    return 2
  fi
  start_epoch="$(date +%s)"
  deadline_epoch=$((start_epoch + endpoint_wait_timeout_sec))
  attempt=0

  echo "[profile-default-gate-run] $(timestamp_utc) wait-start label=$label url=$probe_url timeout_sec=$endpoint_wait_timeout_sec interval_sec=$endpoint_wait_interval_sec connect_timeout_sec=$endpoint_connect_timeout_sec"

  while true; do
    attempt=$((attempt + 1))
    attempt_start_epoch="$(date +%s)"
    elapsed_sec=$((attempt_start_epoch - start_epoch))
    if (( endpoint_wait_timeout_sec == 0 )); then
      remaining_sec="unbounded"
    else
      remaining_sec=$((deadline_epoch - attempt_start_epoch))
      if (( remaining_sec < 0 )); then
        remaining_sec=0
      fi
    fi
    echo "[profile-default-gate-run] $(timestamp_utc) wait-attempt label=$label phase=probe-start url=$probe_url attempt=$attempt elapsed_sec=$elapsed_sec remaining_sec=$remaining_sec"
    err_file="$(mktemp)"
    local -a curl_opts=(--silent --show-error --fail --noproxy '*' --connect-timeout "$endpoint_connect_timeout_sec" --max-time "$endpoint_connect_timeout_sec" --output /dev/null)
    if [[ "$allow_insecure_probe" == "1" ]]; then
      curl_opts+=(--insecure)
    fi
    if curl "${curl_opts[@]}" "$probe_url" > /dev/null 2>"$err_file"; then
      rm -f "$err_file"
      echo "[profile-default-gate-run] $(timestamp_utc) wait-pass label=$label url=$probe_url attempt=$attempt"
      return 0
    fi

    rc=$?
    err_text="$(tr '\n' ' ' <"$err_file" | sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//')"
    rm -f "$err_file"
    if [[ -z "$err_text" ]]; then
      err_text="curl rc=$rc"
    else
      err_text="curl rc=$rc: $err_text"
    fi

    now_epoch="$(date +%s)"
    elapsed_sec=$((now_epoch - start_epoch))
    if (( endpoint_wait_timeout_sec == 0 || now_epoch >= deadline_epoch )); then
      echo "[profile-default-gate-run] $(timestamp_utc) wait-fail label=$label url=$probe_url attempt=$attempt elapsed_sec=$elapsed_sec error=$err_text"
      echo "[profile-default-gate-run] $(timestamp_utc) failure_kind=unreachable_directory_endpoint label=$label url=$probe_url"
      echo "profile-default-gate-run failed: unreachable directory endpoint ($label) url=$probe_url timeout_sec=$endpoint_wait_timeout_sec"
      echo "last_error: $err_text"
      echo "hint: verify endpoint path and host reachability for $probe_url"
      echo "hint: confirm service is listening on expected host:port and serving /v1/pubkeys"
      echo "hint: if startup is slow, increase --endpoint-wait-timeout-sec (current=$endpoint_wait_timeout_sec)"
      echo "hint: if network handshakes are slow, increase --endpoint-connect-timeout-sec (current=$endpoint_connect_timeout_sec)"
      return 1
    fi

    remaining_sec=$((deadline_epoch - now_epoch))
    echo "[profile-default-gate-run] $(timestamp_utc) wait-retry label=$label url=$probe_url attempt=$attempt elapsed_sec=$elapsed_sec remaining_sec=$remaining_sec error=$err_text"
    echo "[profile-default-gate-run] $(timestamp_utc) wait-next label=$label url=$probe_url next_attempt=$((attempt + 1)) sleep_sec=$endpoint_wait_interval_sec"
    sleep "$endpoint_wait_interval_sec"
  done
}

signoff_script="${PROFILE_DEFAULT_GATE_RUN_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign_signoff.sh}"
directory_a_input="${PROFILE_DEFAULT_GATE_DIRECTORY_A:-${PROFILE_DEFAULT_GATE_HOST_A:-}}"
directory_b_input="${PROFILE_DEFAULT_GATE_DIRECTORY_B:-${PROFILE_DEFAULT_GATE_HOST_B:-}}"
directory_a_port="${PROFILE_DEFAULT_GATE_DIRECTORY_A_PORT:-8081}"
directory_b_port="${PROFILE_DEFAULT_GATE_DIRECTORY_B_PORT:-8081}"
endpoint_wait_timeout_sec="${PROFILE_DEFAULT_GATE_WAIT_TIMEOUT_SEC:-45}"
endpoint_wait_interval_sec="${PROFILE_DEFAULT_GATE_WAIT_INTERVAL_SEC:-2}"
endpoint_connect_timeout_sec="${PROFILE_DEFAULT_GATE_WAIT_CONNECT_TIMEOUT_SEC:-3}"
allow_insecure_probe="${PROFILE_DEFAULT_GATE_RUN_ALLOW_INSECURE_PROBE:-0}"
env_client_file="${PROFILE_DEFAULT_GATE_RUN_ENV_CLIENT_FILE:-$ROOT_DIR/deploy/.env.easy.client}"
campaign_timeout_default_sec="${PROFILE_DEFAULT_GATE_RUN_CAMPAIGN_TIMEOUT_SEC:-2400}"
heartbeat_interval_sec_raw="${PROFILE_DEFAULT_GATE_RUN_HEARTBEAT_INTERVAL_SEC:-60}"
heartbeat_interval_sec_cli=""

campaign_subject_cli=""
subject_alias_cli=""
key_alias_cli=""
invite_key_alias_cli=""

declare -a signoff_passthrough=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --directory-a|--host-a)
      require_value_or_die "$1" "$#"
      directory_a_input="${2:-}"
      shift 2
      ;;
    --directory-b|--host-b)
      require_value_or_die "$1" "$#"
      directory_b_input="${2:-}"
      shift 2
      ;;
    --directory-a-port)
      require_value_or_die "$1" "$#"
      directory_a_port="${2:-}"
      shift 2
      ;;
    --directory-b-port)
      require_value_or_die "$1" "$#"
      directory_b_port="${2:-}"
      shift 2
      ;;
    --endpoint-wait-timeout-sec)
      require_value_or_die "$1" "$#"
      endpoint_wait_timeout_sec="${2:-}"
      shift 2
      ;;
    --endpoint-wait-interval-sec)
      require_value_or_die "$1" "$#"
      endpoint_wait_interval_sec="${2:-}"
      shift 2
      ;;
    --endpoint-connect-timeout-sec)
      require_value_or_die "$1" "$#"
      endpoint_connect_timeout_sec="${2:-}"
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
    --heartbeat-interval-sec)
      require_value_or_die "$1" "$#"
      heartbeat_interval_sec_cli="${2:-}"
      shift 2
      ;;
    --heartbeat-interval-sec=*)
      heartbeat_interval_sec_cli="${1#--heartbeat-interval-sec=}"
      shift
      ;;
    --campaign-subject)
      require_value_or_die "$1" "$#"
      campaign_subject_cli="${2:-}"
      shift 2
      ;;
    --campaign-subject=*)
      campaign_subject_cli="${1#--campaign-subject=}"
      shift
      ;;
    --subject)
      require_value_or_die "$1" "$#"
      subject_alias_cli="${2:-}"
      shift 2
      ;;
    --subject=*)
      subject_alias_cli="${1#--subject=}"
      shift
      ;;
    --key)
      require_value_or_die "$1" "$#"
      key_alias_cli="${2:-}"
      shift 2
      ;;
    --key=*)
      key_alias_cli="${1#--key=}"
      shift
      ;;
    --invite-key)
      require_value_or_die "$1" "$#"
      invite_key_alias_cli="${2:-}"
      shift 2
      ;;
    --invite-key=*)
      invite_key_alias_cli="${1#--invite-key=}"
      shift
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        signoff_passthrough+=("$1")
        shift
      done
      ;;
    *)
      signoff_passthrough+=("$1")
      shift
      ;;
  esac
done

for cmd in curl date mktemp sed tr; do
  need_cmd "$cmd"
done

if [[ ! -x "$signoff_script" ]]; then
  echo "missing executable signoff script: $signoff_script"
  exit 2
fi

int_arg_or_die "--directory-a-port" "$directory_a_port"
int_arg_or_die "--directory-b-port" "$directory_b_port"
int_arg_or_die "--endpoint-wait-timeout-sec" "$endpoint_wait_timeout_sec"
int_arg_or_die "--endpoint-wait-interval-sec" "$endpoint_wait_interval_sec"
int_arg_or_die "--endpoint-connect-timeout-sec" "$endpoint_connect_timeout_sec"
bool_arg_or_die "--allow-insecure-probe" "$allow_insecure_probe"
int_arg_or_die "PROFILE_DEFAULT_GATE_RUN_CAMPAIGN_TIMEOUT_SEC" "$campaign_timeout_default_sec"

if (( directory_a_port < 1 || directory_a_port > 65535 )); then
  echo "--directory-a-port must be in range 1..65535"
  exit 2
fi
if (( directory_b_port < 1 || directory_b_port > 65535 )); then
  echo "--directory-b-port must be in range 1..65535"
  exit 2
fi
if (( endpoint_wait_interval_sec < 1 )); then
  echo "--endpoint-wait-interval-sec must be >= 1"
  exit 2
fi
if (( endpoint_connect_timeout_sec < 1 )); then
  echo "--endpoint-connect-timeout-sec must be >= 1"
  exit 2
fi
if (( campaign_timeout_default_sec < 1 )); then
  echo "PROFILE_DEFAULT_GATE_RUN_CAMPAIGN_TIMEOUT_SEC must be >= 1"
  exit 2
fi

campaign_subject_cli="$(trim "$campaign_subject_cli")"
subject_alias_cli="$(trim "$subject_alias_cli")"
key_alias_cli="$(trim "$key_alias_cli")"
invite_key_alias_cli="$(trim "$invite_key_alias_cli")"
heartbeat_interval_sec_cli="$(trim "$heartbeat_interval_sec_cli")"
if [[ -n "$heartbeat_interval_sec_cli" ]]; then
  int_arg_or_die "--heartbeat-interval-sec" "$heartbeat_interval_sec_cli"
  if (( heartbeat_interval_sec_cli < 1 )); then
    echo "--heartbeat-interval-sec must be >= 1"
    exit 2
  fi
  heartbeat_interval_sec="$heartbeat_interval_sec_cli"
else
  heartbeat_interval_sec="$(trim "$heartbeat_interval_sec_raw")"
  if ! [[ "$heartbeat_interval_sec" =~ ^[0-9]+$ ]] || (( heartbeat_interval_sec < 1 )); then
    heartbeat_interval_sec=60
  fi
fi

subject_reference=""
subject_conflict=false
if [[ -n "$campaign_subject_cli" ]]; then
  subject_reference="$campaign_subject_cli"
fi
for subject_candidate in "$subject_alias_cli" "$key_alias_cli" "$invite_key_alias_cli"; do
  if [[ -z "$subject_candidate" ]]; then
    continue
  fi
  if [[ -z "$subject_reference" ]]; then
    subject_reference="$subject_candidate"
    continue
  fi
  if [[ "$subject_candidate" != "$subject_reference" ]]; then
    subject_conflict=true
    break
  fi
done
if [[ "$subject_conflict" == true ]]; then
  echo "conflicting subject values: --campaign-subject/--subject/--key/--invite-key must match when multiple are provided"
  exit 2
fi

if array_has_arg_or_equals_prefix "--campaign-anon-cred" "${signoff_passthrough[@]}" \
  || array_has_arg_or_equals_prefix "--anon-cred" "${signoff_passthrough[@]}"; then
  echo "profile-default-gate-run requires invite-key subject; anon credential flags are not supported in this helper"
  exit 2
fi

campaign_subject_effective=""
subject_source=""
campaign_subject_env=""
invite_key_env=""
campaign_subject_file=""
invite_key_file=""
if [[ -n "$campaign_subject_cli" ]]; then
  campaign_subject_effective="$campaign_subject_cli"
  subject_source="explicit:--campaign-subject"
elif [[ -n "$subject_alias_cli" ]]; then
  campaign_subject_effective="$subject_alias_cli"
  subject_source="explicit:--subject"
elif [[ -n "$key_alias_cli" ]]; then
  campaign_subject_effective="$key_alias_cli"
  subject_source="explicit:--key"
elif [[ -n "$invite_key_alias_cli" ]]; then
  campaign_subject_effective="$invite_key_alias_cli"
  subject_source="explicit:--invite-key"
else
  campaign_subject_env="$(trim "${CAMPAIGN_SUBJECT:-}")"
  invite_key_env="$(trim "${INVITE_KEY:-}")"
  campaign_subject_file="$(trim "$(read_env_key_from_file "$env_client_file" "CAMPAIGN_SUBJECT")")"
  invite_key_file="$(trim "$(read_env_key_from_file "$env_client_file" "INVITE_KEY")")"

  if [[ -n "$campaign_subject_env" ]]; then
    campaign_subject_effective="$campaign_subject_env"
    subject_source="env:CAMPAIGN_SUBJECT"
  elif [[ -n "$invite_key_env" ]]; then
    campaign_subject_effective="$invite_key_env"
    subject_source="env:INVITE_KEY"
  elif [[ -n "$campaign_subject_file" ]]; then
    campaign_subject_effective="$campaign_subject_file"
    subject_source="file:CAMPAIGN_SUBJECT"
  elif [[ -n "$invite_key_file" ]]; then
    campaign_subject_effective="$invite_key_file"
    subject_source="file:INVITE_KEY"
  fi
fi

if [[ -z "$campaign_subject_effective" ]]; then
  echo "[profile-default-gate-run] $(timestamp_utc) failure_kind=missing_invite_subject_precondition env_client_file=$env_client_file"
  echo "profile-default-gate-run failed: missing invite key subject"
  echo "provide --campaign-subject/--subject/--key/--invite-key, or set CAMPAIGN_SUBJECT/INVITE_KEY"
  echo "or define CAMPAIGN_SUBJECT/INVITE_KEY in $env_client_file"
  echo "override env file path via PROFILE_DEFAULT_GATE_RUN_ENV_CLIENT_FILE"
  exit 2
fi
if invite_subject_looks_placeholder_01 "$campaign_subject_effective"; then
  echo "[profile-default-gate-run] $(timestamp_utc) failure_kind=missing_invite_subject_precondition reason=placeholder_subject"
  echo "profile-default-gate-run failed: invite key subject appears to be placeholder text ($campaign_subject_effective)"
  echo "provide a real invite key via --campaign-subject/--subject/--key/--invite-key, or set CAMPAIGN_SUBJECT/INVITE_KEY"
  exit 2
fi

campaign_directory_urls_passthrough="$(extract_flag_value --campaign-directory-urls "${signoff_passthrough[@]}")"
campaign_directory_urls_passthrough="$(trim "$campaign_directory_urls_passthrough")"
if [[ -z "$directory_a_input" || -z "$directory_b_input" ]]; then
  if [[ -n "$campaign_directory_urls_passthrough" ]]; then
    mapfile -t passthrough_directory_urls < <(split_csv_trim "$campaign_directory_urls_passthrough")
    if (( ${#passthrough_directory_urls[@]} != 2 )); then
      echo "profile-default-gate-run failed: --campaign-directory-urls must include exactly two values (A,B)"
      exit 2
    fi
    if [[ -z "$directory_a_input" ]]; then
      directory_a_input="${passthrough_directory_urls[0]}"
    fi
    if [[ -z "$directory_b_input" ]]; then
      directory_b_input="${passthrough_directory_urls[1]}"
    fi
  fi
fi

directory_a_input="$(trim "$directory_a_input")"
directory_b_input="$(trim "$directory_b_input")"
if [[ -z "$directory_a_input" || -z "$directory_b_input" ]]; then
  echo "profile-default-gate-run failed: missing A/B directory endpoints"
  echo "provide --directory-a and --directory-b (or --host-a/--host-b), or pass --campaign-directory-urls A,B"
  exit 2
fi
if directory_host_looks_placeholder_01 "$directory_a_input"; then
  fail_placeholder_directory_input_01 "directory_a" "$directory_a_input"
fi
if directory_host_looks_placeholder_01 "$directory_b_input"; then
  fail_placeholder_directory_input_01 "directory_b" "$directory_b_input"
fi

directory_a_url="$(normalize_directory_url "--directory-a/--host-a" "$directory_a_input" "$directory_a_port")"
directory_b_url="$(normalize_directory_url "--directory-b/--host-b" "$directory_b_input" "$directory_b_port")"
campaign_directory_urls_effective="${directory_a_url},${directory_b_url}"

if [[ -n "$campaign_directory_urls_passthrough" ]]; then
  mapfile -t passthrough_directory_urls < <(split_csv_trim "$campaign_directory_urls_passthrough")
  if (( ${#passthrough_directory_urls[@]} != 2 )); then
    echo "profile-default-gate-run failed: --campaign-directory-urls must include exactly two values (A,B)"
    exit 2
  fi
  passthrough_directory_a_url="$(normalize_directory_url "--campaign-directory-urls[A]" "${passthrough_directory_urls[0]}" "$directory_a_port")"
  passthrough_directory_b_url="$(normalize_directory_url "--campaign-directory-urls[B]" "${passthrough_directory_urls[1]}" "$directory_b_port")"
  passthrough_effective="${passthrough_directory_a_url},${passthrough_directory_b_url}"
  if [[ "$passthrough_effective" != "$campaign_directory_urls_effective" ]]; then
    echo "profile-default-gate-run failed: A/B endpoint inputs conflict with --campaign-directory-urls"
    echo "a_b_effective=$campaign_directory_urls_effective"
    echo "campaign_directory_urls=$passthrough_effective"
    exit 2
  fi
fi

campaign_bootstrap_passthrough="$(extract_flag_value --campaign-bootstrap-directory "${signoff_passthrough[@]}")"
campaign_bootstrap_passthrough="$(trim "$campaign_bootstrap_passthrough")"
if [[ -n "$campaign_bootstrap_passthrough" ]]; then
  campaign_bootstrap_effective="$(normalize_directory_url "--campaign-bootstrap-directory" "$campaign_bootstrap_passthrough" "$directory_a_port")"
  if [[ "$campaign_bootstrap_effective" != "$directory_a_url" ]]; then
    echo "profile-default-gate-run failed: --campaign-bootstrap-directory must match directory A endpoint"
    echo "directory_a=$directory_a_url"
    echo "campaign_bootstrap_directory=$campaign_bootstrap_effective"
    exit 2
  fi
fi

if ! array_has_arg_or_equals_prefix "--campaign-subject" "${signoff_passthrough[@]}" \
  && ! array_has_arg_or_equals_prefix "--subject" "${signoff_passthrough[@]}" \
  && ! array_has_arg_or_equals_prefix "--key" "${signoff_passthrough[@]}" \
  && ! array_has_arg_or_equals_prefix "--invite-key" "${signoff_passthrough[@]}"; then
  signoff_passthrough+=(--campaign-subject "$campaign_subject_effective")
fi
if ! array_has_arg_or_equals_prefix "--campaign-directory-urls" "${signoff_passthrough[@]}"; then
  signoff_passthrough+=(--campaign-directory-urls "$campaign_directory_urls_effective")
fi
if ! array_has_arg_or_equals_prefix "--campaign-bootstrap-directory" "${signoff_passthrough[@]}"; then
  signoff_passthrough+=(--campaign-bootstrap-directory "$directory_a_url")
fi
if ! array_has_arg_or_equals_prefix "--refresh-campaign" "${signoff_passthrough[@]}"; then
  signoff_passthrough+=(--refresh-campaign 1)
fi
if ! array_has_arg_or_equals_prefix "--campaign-execution-mode" "${signoff_passthrough[@]}"; then
  signoff_passthrough+=(--campaign-execution-mode docker)
fi
if ! array_has_arg_or_equals_prefix "--campaign-start-local-stack" "${signoff_passthrough[@]}"; then
  signoff_passthrough+=(--campaign-start-local-stack 0)
fi
if ! array_has_arg_or_equals_prefix "--fail-on-no-go" "${signoff_passthrough[@]}"; then
  signoff_passthrough+=(--fail-on-no-go 0)
fi
if ! array_has_arg_or_equals_prefix "--campaign-timeout-sec" "${signoff_passthrough[@]}"; then
  signoff_passthrough+=(--campaign-timeout-sec "$campaign_timeout_default_sec")
fi
if ! array_has_arg_or_equals_prefix "--print-summary-json" "${signoff_passthrough[@]}"; then
  signoff_passthrough+=(--print-summary-json 0)
fi
campaign_timeout_effective="$(extract_flag_value --campaign-timeout-sec "${signoff_passthrough[@]}")"
campaign_timeout_effective="$(trim "$campaign_timeout_effective")"
if [[ -z "$campaign_timeout_effective" ]]; then
  echo "profile-default-gate-run failed: --campaign-timeout-sec requires a value"
  exit 2
fi
int_arg_or_die "--campaign-timeout-sec" "$campaign_timeout_effective"
if (( campaign_timeout_effective < 0 )); then
  echo "--campaign-timeout-sec must be >= 0"
  exit 2
fi

reports_dir_effective="$(extract_flag_value --reports-dir "${signoff_passthrough[@]}")"
reports_dir_effective="$(trim "$reports_dir_effective")"
if [[ -z "$reports_dir_effective" ]]; then
  reports_dir_effective="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
fi
reports_dir_effective="$(abs_path "$reports_dir_effective")"

summary_json_effective="$(extract_flag_value --summary-json "${signoff_passthrough[@]}")"
summary_json_effective="$(trim "$summary_json_effective")"
if [[ -n "$summary_json_effective" ]]; then
  summary_json_effective="$(abs_path "$summary_json_effective")"
else
  summary_json_effective="$reports_dir_effective/profile_compare_campaign_signoff_summary.json"
fi

echo "[profile-default-gate-run] $(timestamp_utc) start subject_source=$subject_source directory_urls=$campaign_directory_urls_effective campaign_timeout_sec=$campaign_timeout_effective"
echo "[profile-default-gate-run] $(timestamp_utc) summary_json=$summary_json_effective"

if ! wait_for_directory_endpoint "directory_a" "$directory_a_url"; then
  exit 1
fi
if [[ "$directory_b_url" == "$directory_a_url" ]]; then
  echo "[profile-default-gate-run] $(timestamp_utc) wait-skip label=directory_b reason=same_as_directory_a"
else
  if ! wait_for_directory_endpoint "directory_b" "$directory_b_url"; then
    exit 1
  fi
fi

echo "[profile-default-gate-run] $(timestamp_utc) campaign-visibility expected_duration_sec=$campaign_timeout_effective progress_reports_dir=$reports_dir_effective progress_summary_json=$summary_json_effective"
echo "[profile-default-gate-run] $(timestamp_utc) signoff-startup-hint campaign_timeout_sec=$campaign_timeout_effective summary_json=$summary_json_effective heartbeat_interval_sec=$heartbeat_interval_sec"
echo "[profile-default-gate-run] $(timestamp_utc) signoff-heartbeat interval_sec=$heartbeat_interval_sec"
echo "[profile-default-gate-run] $(timestamp_utc) invoking profile-compare-campaign-signoff"
signoff_start_epoch="$(date +%s)"
echo "[profile-default-gate-run] $(timestamp_utc) signoff-progress elapsed_sec=0 state=campaign_start_pending progress_reports_dir=$reports_dir_effective progress_summary_json=$summary_json_effective"
heartbeat_pid=""
(
  heartbeat_seq=0
  while true; do
    sleep "$heartbeat_interval_sec"
    heartbeat_seq=$((heartbeat_seq + 1))
    now_epoch="$(date +%s)"
    elapsed_sec=$((now_epoch - signoff_start_epoch))
    echo "[profile-default-gate-run] $(timestamp_utc) signoff-progress heartbeat_seq=$heartbeat_seq elapsed_sec=$elapsed_sec state=campaign_running progress_reports_dir=$reports_dir_effective progress_summary_json=$summary_json_effective"
  done
) &
heartbeat_pid="$!"
set +e
"$signoff_script" "${signoff_passthrough[@]}"
signoff_rc=$?
set -e
if [[ -n "$heartbeat_pid" ]]; then
  kill "$heartbeat_pid" >/dev/null 2>&1 || true
  wait "$heartbeat_pid" >/dev/null 2>&1 || true
fi
signoff_end_epoch="$(date +%s)"
signoff_elapsed_sec=$((signoff_end_epoch - signoff_start_epoch))
echo "[profile-default-gate-run] $(timestamp_utc) signoff-finish rc=$signoff_rc elapsed_sec=$signoff_elapsed_sec progress_summary_json=$summary_json_effective"

if [[ "$signoff_rc" -eq 0 ]]; then
  echo "[profile-default-gate-run] $(timestamp_utc) status=ok rc=0 summary_json=$summary_json_effective"
else
  echo "[profile-default-gate-run] $(timestamp_utc) status=fail rc=$signoff_rc summary_json=$summary_json_effective"
  echo "hint: inspect signoff summary/logs at $summary_json_effective"
  echo "hint: if campaign start timed out, increase --campaign-timeout-sec (current=$campaign_timeout_effective)"
fi

exit "$signoff_rc"
