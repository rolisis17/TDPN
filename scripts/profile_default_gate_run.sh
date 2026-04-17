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
    [--campaign-subject INVITE_KEY | --subject INVITE_KEY | --key INVITE_KEY | --invite-key INVITE_KEY] \
    [profile-compare-campaign-signoff args...]

Purpose:
  Run the final optional profile-default gate refresh/signoff with
  endpoint wait-retry preflight for A/B directory URLs.

Notes:
  - --host-a/--host-b are aliases for --directory-a/--directory-b.
  - --directory-a/--directory-b accept hostnames, host:port, or full http(s) URLs.
  - Host-style inputs are normalized to http://HOST:PORT (default port 8081).
  - This helper requires invite-key subject mode; passthrough anon-cred flags
    (--campaign-anon-cred/--anon-cred) are rejected.
  - --key/--invite-key are aliases for --subject.
  - Subject fallback order when CLI subject is omitted:
    CAMPAIGN_SUBJECT env, INVITE_KEY env, CAMPAIGN_SUBJECT file, INVITE_KEY file.
  - Env-file fallback default: $ROOT_DIR/deploy/.env.easy.client
    (override via PROFILE_DEFAULT_GATE_RUN_ENV_CLIENT_FILE).
  - Invite subject placeholders (for example literal INVITE_KEY) fail fast.
  - This wrapper defaults signoff refresh mode to roadmap docker defaults:
    --refresh-campaign 1
    --campaign-execution-mode docker
    --campaign-start-local-stack 0
    --fail-on-no-go 0
    --campaign-timeout-sec 1200
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

  printf 'http://%s' "$host_port"
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
  local err_file err_text

  probe_url="$(probe_url_for_directory "$directory_url")"
  start_epoch="$(date +%s)"
  deadline_epoch=$((start_epoch + endpoint_wait_timeout_sec))
  attempt=0

  echo "[profile-default-gate-run] $(timestamp_utc) wait-start label=$label url=$probe_url timeout_sec=$endpoint_wait_timeout_sec interval_sec=$endpoint_wait_interval_sec"

  while true; do
    attempt=$((attempt + 1))
    err_file="$(mktemp)"
    if curl --silent --show-error --fail --insecure \
      --noproxy '*' \
      --connect-timeout "$endpoint_connect_timeout_sec" \
      --max-time "$endpoint_connect_timeout_sec" \
      --output /dev/null \
      "$probe_url" > /dev/null 2>"$err_file"; then
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
    if (( endpoint_wait_timeout_sec == 0 || now_epoch >= deadline_epoch )); then
      echo "[profile-default-gate-run] $(timestamp_utc) wait-fail label=$label url=$probe_url attempt=$attempt error=$err_text"
      echo "[profile-default-gate-run] $(timestamp_utc) failure_kind=unreachable_directory_endpoint label=$label url=$probe_url"
      echo "profile-default-gate-run failed: unreachable directory endpoint ($label) url=$probe_url timeout_sec=$endpoint_wait_timeout_sec"
      echo "last_error: $err_text"
      return 1
    fi

    remaining_sec=$((deadline_epoch - now_epoch))
    echo "[profile-default-gate-run] $(timestamp_utc) wait-retry label=$label url=$probe_url attempt=$attempt remaining_sec=$remaining_sec error=$err_text"
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
env_client_file="${PROFILE_DEFAULT_GATE_RUN_ENV_CLIENT_FILE:-$ROOT_DIR/deploy/.env.easy.client}"
campaign_timeout_default_sec="${PROFILE_DEFAULT_GATE_RUN_CAMPAIGN_TIMEOUT_SEC:-1200}"
heartbeat_interval_sec_raw="${PROFILE_DEFAULT_GATE_RUN_HEARTBEAT_INTERVAL_SEC:-60}"

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
heartbeat_interval_sec="$(trim "$heartbeat_interval_sec_raw")"
if ! [[ "$heartbeat_interval_sec" =~ ^[0-9]+$ ]] || (( heartbeat_interval_sec < 1 )); then
  heartbeat_interval_sec=60
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
echo "[profile-default-gate-run] $(timestamp_utc) signoff-heartbeat interval_sec=$heartbeat_interval_sec"
echo "[profile-default-gate-run] $(timestamp_utc) invoking profile-compare-campaign-signoff"
signoff_start_epoch="$(date +%s)"
heartbeat_pid=""
(
  while true; do
    sleep "$heartbeat_interval_sec"
    now_epoch="$(date +%s)"
    elapsed_sec=$((now_epoch - signoff_start_epoch))
    echo "[profile-default-gate-run] $(timestamp_utc) signoff-progress elapsed_sec=$elapsed_sec progress_reports_dir=$reports_dir_effective progress_summary_json=$summary_json_effective"
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
fi

exit "$signoff_rc"
