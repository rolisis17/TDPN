#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/gpm_endpoint_posture_remediate.sh [options]

Description:
  Inspects endpoint/profile-default-gate posture and prints deterministic
  remediation commands for common misconfiguration classes.

Modes:
  --mode report|dry-run|apply   Default: report
  --report                      Alias for --mode report
  --dry-run                     Alias for --mode report
  --apply                       Alias for --mode apply

Input posture options:
  --host-a HOST|--directory-a HOST
  --host-b HOST|--directory-b HOST
  --campaign-subject INVITE_KEY
  --subject INVITE_KEY          Deprecated alias (reported as finding)
  --key INVITE_KEY              Deprecated alias (reported as finding)
  --invite-key INVITE_KEY       Deprecated alias (reported as finding)
  --campaign-timeout-sec N
  --summary-json PATH
  --summary-max-age-sec N       Default: 21600
  --minimum-campaign-timeout-sec N   Default: 900
  --signoff-arg ARG             Add one arg token to inspect (repeatable)
  --                            Remaining args are inspected as signoff args

Apply-mode optional setters (idempotent env-file upserts):
  --env-file PATH               Default: deploy/.env.easy.client
  --set-a-host HOST
  --set-b-host HOST
  --set-campaign-subject INVITE_KEY
  --set-campaign-timeout-sec N
  --remediation-script PATH     Default: .easy-node-logs/gpm_endpoint_posture_remediation.sh

Markers:
  - [gpm-endpoint-posture-remediate] finding id=...
  - [gpm-endpoint-posture-remediate] remediation_cmd id=...
  - [gpm-endpoint-posture-remediate] status=ok ...
USAGE
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path="$1"
  if [[ "$path" == /* ]]; then
    printf '%s\n' "$path"
  else
    printf '%s\n' "$ROOT_DIR/$path"
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

int_arg_or_die() {
  local label="$1"
  local value="${2:-}"
  if [[ -z "$value" || ! "$value" =~ ^[0-9]+$ ]]; then
    echo "$label must be a non-negative integer"
    exit 2
  fi
}

first_non_empty() {
  local candidate
  for candidate in "$@"; do
    candidate="$(trim "${candidate:-}")"
    if [[ -n "$candidate" ]]; then
      printf '%s\n' "$candidate"
      return 0
    fi
  done
  printf '\n'
}

read_env_key_from_file() {
  local env_file="$1"
  local key="$2"
  local raw line value

  if [[ ! -f "$env_file" ]]; then
    return 1
  fi

  while IFS= read -r raw || [[ -n "$raw" ]]; do
    line="$raw"
    line="${line%%#*}"
    line="$(trim "$line")"
    if [[ -z "$line" ]]; then
      continue
    fi
    if [[ "$line" == export[[:space:]]* ]]; then
      line="${line#export}"
      line="$(trim "$line")"
    fi
    if [[ "$line" != "$key="* ]]; then
      continue
    fi
    value="${line#*=}"
    value="$(trim "$value")"
    if [[ "$value" == \"*\" && "$value" == *\" && "${#value}" -ge 2 ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "$value" == \'*\' && "$value" == *\' && "${#value}" -ge 2 ]]; then
      value="${value:1:${#value}-2}"
    fi
    printf '%s\n' "$value"
    return 0
  done <"$env_file"

  return 1
}

env_value_literal() {
  local value="$1"
  if [[ "$value" =~ ^[A-Za-z0-9_./:@-]+$ ]]; then
    printf '%s' "$value"
  else
    printf "'%s'" "${value//\'/\'\\\'\'}"
  fi
}

upsert_env_key() {
  local env_file="$1"
  local key="$2"
  local value="$3"
  local tmp_file line parse_line found

  mkdir -p "$(dirname "$env_file")"
  if [[ ! -f "$env_file" ]]; then
    : >"$env_file"
  fi

  tmp_file="$(mktemp "${env_file}.tmp.XXXXXX")"
  found="0"

  while IFS= read -r line || [[ -n "$line" ]]; do
    parse_line="$line"
    parse_line="${parse_line%%#*}"
    parse_line="$(trim "$parse_line")"
    if [[ "$parse_line" == export[[:space:]]* ]]; then
      parse_line="${parse_line#export}"
      parse_line="$(trim "$parse_line")"
    fi
    if [[ "$parse_line" == "$key="* ]]; then
      if [[ "$found" == "0" ]]; then
        printf '%s=%s\n' "$key" "$(env_value_literal "$value")" >>"$tmp_file"
        found="1"
      fi
      continue
    fi
    printf '%s\n' "$line" >>"$tmp_file"
  done <"$env_file"

  if [[ "$found" == "0" ]]; then
    printf '%s=%s\n' "$key" "$(env_value_literal "$value")" >>"$tmp_file"
  fi

  mv -f "$tmp_file" "$env_file"
}

file_mtime_epoch() {
  local path="$1"
  if stat -c %Y "$path" >/dev/null 2>&1; then
    stat -c %Y "$path"
    return 0
  fi
  if stat -f %m "$path" >/dev/null 2>&1; then
    stat -f %m "$path"
    return 0
  fi
  return 1
}

log_marker() {
  printf '[gpm-endpoint-posture-remediate] %s\n' "$*"
}

log_remediation_cmd() {
  local finding_id="$1"
  local command_text="$2"
  printf '[gpm-endpoint-posture-remediate]\tremediation_cmd\t%s\t%s\n' "$finding_id" "$command_text"
}

array_contains_exact() {
  local needle="$1"
  shift || true
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

set_subject_value_or_die() {
  local flag="$1"
  local value="$2"
  local value_trimmed
  value_trimmed="$(trim "$value")"
  if [[ -z "$value_trimmed" ]]; then
    echo "$flag requires a value"
    exit 2
  fi
  if [[ -z "$CLI_SUBJECT" ]]; then
    CLI_SUBJECT="$value_trimmed"
    CLI_SUBJECT_SOURCE="$flag"
    return 0
  fi
  if [[ "$CLI_SUBJECT" != "$value_trimmed" ]]; then
    echo "conflicting subject values: $CLI_SUBJECT_SOURCE and $flag must match when both are provided"
    exit 2
  fi
}

MODE="report"
ENV_FILE="${GPM_ENDPOINT_POSTURE_ENV_FILE:-$ROOT_DIR/deploy/.env.easy.client}"
SUMMARY_JSON="${GPM_ENDPOINT_POSTURE_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/profile_compare_campaign_signoff_summary.json}"
SUMMARY_MAX_AGE_SEC="${GPM_ENDPOINT_POSTURE_SUMMARY_MAX_AGE_SEC:-21600}"
MINIMUM_CAMPAIGN_TIMEOUT_SEC="${GPM_ENDPOINT_POSTURE_MIN_CAMPAIGN_TIMEOUT_SEC:-900}"
REMEDIATION_SCRIPT="${GPM_ENDPOINT_POSTURE_REMEDIATION_SCRIPT:-$ROOT_DIR/.easy-node-logs/gpm_endpoint_posture_remediation.sh}"

CLI_HOST_A=""
CLI_HOST_B=""
CLI_SUBJECT=""
CLI_SUBJECT_SOURCE=""
CLI_CAMPAIGN_TIMEOUT_SEC=""
SUMMARY_JSON_SET_BY_FLAG="0"

SET_A_HOST=""
SET_B_HOST=""
SET_CAMPAIGN_SUBJECT=""
SET_CAMPAIGN_TIMEOUT_SEC=""

INSPECT_ARGS=()
DEPRECATED_FLAGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode)
      require_value_or_die "$1" "${2:-}"
      MODE="${2:-}"
      shift 2
      ;;
    --mode=*)
      MODE="${1#*=}"
      shift
      ;;
    --apply)
      MODE="apply"
      shift
      ;;
    --dry-run|--report)
      MODE="report"
      shift
      ;;
    --env-file)
      require_value_or_die "$1" "${2:-}"
      ENV_FILE="${2:-}"
      shift 2
      ;;
    --env-file=*)
      ENV_FILE="${1#*=}"
      shift
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      SUMMARY_JSON="${2:-}"
      SUMMARY_JSON_SET_BY_FLAG="1"
      shift 2
      ;;
    --summary-json=*)
      SUMMARY_JSON="${1#*=}"
      SUMMARY_JSON_SET_BY_FLAG="1"
      shift
      ;;
    --summary-max-age-sec)
      require_value_or_die "$1" "${2:-}"
      SUMMARY_MAX_AGE_SEC="${2:-}"
      shift 2
      ;;
    --summary-max-age-sec=*)
      SUMMARY_MAX_AGE_SEC="${1#*=}"
      shift
      ;;
    --minimum-campaign-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      MINIMUM_CAMPAIGN_TIMEOUT_SEC="${2:-}"
      shift 2
      ;;
    --minimum-campaign-timeout-sec=*)
      MINIMUM_CAMPAIGN_TIMEOUT_SEC="${1#*=}"
      shift
      ;;
    --remediation-script)
      require_value_or_die "$1" "${2:-}"
      REMEDIATION_SCRIPT="${2:-}"
      shift 2
      ;;
    --remediation-script=*)
      REMEDIATION_SCRIPT="${1#*=}"
      shift
      ;;
    --host-a|--directory-a)
      require_value_or_die "$1" "${2:-}"
      CLI_HOST_A="$(trim "${2:-}")"
      shift 2
      ;;
    --host-a=*|--directory-a=*)
      CLI_HOST_A="$(trim "${1#*=}")"
      shift
      ;;
    --host-b|--directory-b)
      require_value_or_die "$1" "${2:-}"
      CLI_HOST_B="$(trim "${2:-}")"
      shift 2
      ;;
    --host-b=*|--directory-b=*)
      CLI_HOST_B="$(trim "${1#*=}")"
      shift
      ;;
    --campaign-subject)
      require_value_or_die "$1" "${2:-}"
      set_subject_value_or_die "--campaign-subject" "${2:-}"
      shift 2
      ;;
    --campaign-subject=*)
      set_subject_value_or_die "--campaign-subject" "${1#*=}"
      shift
      ;;
    --subject|--key|--invite-key)
      require_value_or_die "$1" "${2:-}"
      DEPRECATED_FLAGS+=("$1")
      set_subject_value_or_die "$1" "${2:-}"
      shift 2
      ;;
    --subject=*|--key=*|--invite-key=*)
      DEPRECATED_FLAGS+=("${1%%=*}")
      set_subject_value_or_die "${1%%=*}" "${1#*=}"
      shift
      ;;
    --campaign-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      CLI_CAMPAIGN_TIMEOUT_SEC="${2:-}"
      shift 2
      ;;
    --campaign-timeout-sec=*)
      CLI_CAMPAIGN_TIMEOUT_SEC="${1#*=}"
      shift
      ;;
    --signoff-arg)
      if [[ $# -lt 2 ]]; then
        echo "--signoff-arg requires a value"
        exit 2
      fi
      if [[ -z "${2:-}" ]]; then
        echo "--signoff-arg requires a value"
        exit 2
      fi
      INSPECT_ARGS+=("${2:-}")
      shift 2
      ;;
    --signoff-arg=*)
      if [[ -z "${1#*=}" ]]; then
        echo "--signoff-arg requires a value"
        exit 2
      fi
      INSPECT_ARGS+=("${1#*=}")
      shift
      ;;
    --set-a-host)
      require_value_or_die "$1" "${2:-}"
      SET_A_HOST="$(trim "${2:-}")"
      shift 2
      ;;
    --set-a-host=*)
      SET_A_HOST="$(trim "${1#*=}")"
      shift
      ;;
    --set-b-host)
      require_value_or_die "$1" "${2:-}"
      SET_B_HOST="$(trim "${2:-}")"
      shift 2
      ;;
    --set-b-host=*)
      SET_B_HOST="$(trim "${1#*=}")"
      shift
      ;;
    --set-campaign-subject)
      require_value_or_die "$1" "${2:-}"
      SET_CAMPAIGN_SUBJECT="$(trim "${2:-}")"
      shift 2
      ;;
    --set-campaign-subject=*)
      SET_CAMPAIGN_SUBJECT="$(trim "${1#*=}")"
      shift
      ;;
    --set-campaign-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      SET_CAMPAIGN_TIMEOUT_SEC="${2:-}"
      shift 2
      ;;
    --set-campaign-timeout-sec=*)
      SET_CAMPAIGN_TIMEOUT_SEC="${1#*=}"
      shift
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        INSPECT_ARGS+=("$1")
        shift
      done
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

case "$MODE" in
  report|dry-run)
    MODE="report"
    ;;
  apply)
    ;;
  *)
    echo "--mode must be report|dry-run|apply"
    exit 2
    ;;
esac

int_arg_or_die "--summary-max-age-sec" "$SUMMARY_MAX_AGE_SEC"
int_arg_or_die "--minimum-campaign-timeout-sec" "$MINIMUM_CAMPAIGN_TIMEOUT_SEC"
if (( SUMMARY_MAX_AGE_SEC < 1 )); then
  echo "--summary-max-age-sec must be >= 1"
  exit 2
fi
if (( MINIMUM_CAMPAIGN_TIMEOUT_SEC < 1 )); then
  echo "--minimum-campaign-timeout-sec must be >= 1"
  exit 2
fi
if [[ -n "$SET_CAMPAIGN_TIMEOUT_SEC" ]]; then
  int_arg_or_die "--set-campaign-timeout-sec" "$SET_CAMPAIGN_TIMEOUT_SEC"
  if (( SET_CAMPAIGN_TIMEOUT_SEC < 1 )); then
    echo "--set-campaign-timeout-sec must be >= 1"
    exit 2
  fi
fi

if [[ -n "$CLI_CAMPAIGN_TIMEOUT_SEC" ]]; then
  int_arg_or_die "--campaign-timeout-sec" "$CLI_CAMPAIGN_TIMEOUT_SEC"
fi

INSPECT_TIMEOUT_SEC=""
INSPECT_SUMMARY_JSON=""
inspect_idx=0
while (( inspect_idx < ${#INSPECT_ARGS[@]} )); do
  token="${INSPECT_ARGS[$inspect_idx]}"
  case "$token" in
    --subject|--key|--invite-key)
      DEPRECATED_FLAGS+=("$token")
      if (( inspect_idx + 1 >= ${#INSPECT_ARGS[@]} )); then
        echo "$token in inspected args requires a value"
        exit 2
      fi
      next_token="${INSPECT_ARGS[$((inspect_idx + 1))]}"
      if [[ "$next_token" == --* ]]; then
        echo "$token in inspected args requires a value"
        exit 2
      fi
      inspect_idx=$((inspect_idx + 2))
      continue
      ;;
    --subject=*|--key=*|--invite-key=*)
      DEPRECATED_FLAGS+=("${token%%=*}")
      ;;
    --campaign-timeout-sec)
      if (( inspect_idx + 1 >= ${#INSPECT_ARGS[@]} )); then
        echo "--campaign-timeout-sec in inspected args requires a value"
        exit 2
      fi
      next_token="${INSPECT_ARGS[$((inspect_idx + 1))]}"
      if [[ "$next_token" == --* ]]; then
        echo "--campaign-timeout-sec in inspected args requires a value"
        exit 2
      fi
      INSPECT_TIMEOUT_SEC="$next_token"
      inspect_idx=$((inspect_idx + 2))
      continue
      ;;
    --campaign-timeout-sec=*)
      INSPECT_TIMEOUT_SEC="${token#*=}"
      ;;
    --summary-json)
      if (( inspect_idx + 1 >= ${#INSPECT_ARGS[@]} )); then
        echo "--summary-json in inspected args requires a value"
        exit 2
      fi
      next_token="${INSPECT_ARGS[$((inspect_idx + 1))]}"
      if [[ "$next_token" == --* ]]; then
        echo "--summary-json in inspected args requires a value"
        exit 2
      fi
      INSPECT_SUMMARY_JSON="$next_token"
      inspect_idx=$((inspect_idx + 2))
      continue
      ;;
    --summary-json=*)
      INSPECT_SUMMARY_JSON="${token#*=}"
      ;;
  esac
  inspect_idx=$((inspect_idx + 1))
done

if [[ -n "$INSPECT_TIMEOUT_SEC" ]]; then
  int_arg_or_die "--campaign-timeout-sec (inspected args)" "$INSPECT_TIMEOUT_SEC"
fi

if [[ "$SUMMARY_JSON_SET_BY_FLAG" == "0" && -n "$INSPECT_SUMMARY_JSON" ]]; then
  SUMMARY_JSON="$INSPECT_SUMMARY_JSON"
fi

ENV_FILE="$(abs_path "$ENV_FILE")"
SUMMARY_JSON="$(abs_path "$SUMMARY_JSON")"
REMEDIATION_SCRIPT="$(abs_path "$REMEDIATION_SCRIPT")"

ENV_HOST_A="$(trim "${A_HOST:-}")"
ENV_HOST_B="$(trim "${B_HOST:-}")"
ENV_CAMPAIGN_SUBJECT="$(trim "${CAMPAIGN_SUBJECT:-}")"
ENV_INVITE_KEY="$(trim "${INVITE_KEY:-}")"
ENV_SIGNOFF_TIMEOUT="$(trim "${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC:-}")"
ENV_GATE_TIMEOUT="$(trim "${PROFILE_DEFAULT_GATE_RUN_CAMPAIGN_TIMEOUT_SEC:-}")"

FILE_HOST_A="$(trim "$(read_env_key_from_file "$ENV_FILE" "A_HOST" || true)")"
FILE_HOST_B="$(trim "$(read_env_key_from_file "$ENV_FILE" "B_HOST" || true)")"
FILE_CAMPAIGN_SUBJECT="$(trim "$(read_env_key_from_file "$ENV_FILE" "CAMPAIGN_SUBJECT" || true)")"
FILE_INVITE_KEY="$(trim "$(read_env_key_from_file "$ENV_FILE" "INVITE_KEY" || true)")"
FILE_SIGNOFF_TIMEOUT="$(trim "$(read_env_key_from_file "$ENV_FILE" "PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC" || true)")"
FILE_GATE_TIMEOUT="$(trim "$(read_env_key_from_file "$ENV_FILE" "PROFILE_DEFAULT_GATE_RUN_CAMPAIGN_TIMEOUT_SEC" || true)")"

EFFECTIVE_HOST_A="$(first_non_empty "$CLI_HOST_A" "$ENV_HOST_A" "$FILE_HOST_A")"
EFFECTIVE_HOST_B="$(first_non_empty "$CLI_HOST_B" "$ENV_HOST_B" "$FILE_HOST_B")"
EFFECTIVE_SUBJECT="$(first_non_empty "$CLI_SUBJECT" "$ENV_CAMPAIGN_SUBJECT" "$ENV_INVITE_KEY" "$FILE_CAMPAIGN_SUBJECT" "$FILE_INVITE_KEY")"
EFFECTIVE_CAMPAIGN_TIMEOUT_SEC="$(first_non_empty "$CLI_CAMPAIGN_TIMEOUT_SEC" "$INSPECT_TIMEOUT_SEC" "$ENV_SIGNOFF_TIMEOUT" "$FILE_SIGNOFF_TIMEOUT" "$ENV_GATE_TIMEOUT" "$FILE_GATE_TIMEOUT")"

if [[ -n "$EFFECTIVE_CAMPAIGN_TIMEOUT_SEC" ]]; then
  int_arg_or_die "effective campaign timeout" "$EFFECTIVE_CAMPAIGN_TIMEOUT_SEC"
fi

declare -a FINDING_IDS=()
declare -a FINDING_MESSAGES=()
declare -a FINDING_COMMANDS=()

add_finding() {
  local finding_id="$1"
  local finding_message="$2"
  local remediation_command="$3"

  FINDING_IDS+=("$finding_id")
  FINDING_MESSAGES+=("$finding_message")
  FINDING_COMMANDS+=("$remediation_command")

  log_marker "finding id=$finding_id"
  log_marker "guidance id=$finding_id text=$finding_message"
  log_remediation_cmd "$finding_id" "$remediation_command"
}

log_marker "start mode=$MODE env_file=$ENV_FILE summary_json=$SUMMARY_JSON timestamp=$(timestamp_utc)"

if [[ -z "$EFFECTIVE_HOST_A" ]]; then
  host_a_cmd_value="$SET_A_HOST"
  if [[ -z "$host_a_cmd_value" ]]; then
    host_a_cmd_value="<authority-host-or-ip>"
  fi
  add_finding \
    "missing_a_host_env" \
    "A_HOST is missing for profile-default-gate-live endpoint wiring." \
    "export A_HOST=$(env_value_literal "$host_a_cmd_value")"
fi

if [[ -z "$EFFECTIVE_HOST_B" ]]; then
  host_b_cmd_value="$SET_B_HOST"
  if [[ -z "$host_b_cmd_value" ]]; then
    host_b_cmd_value="<provider-host-or-ip>"
  fi
  add_finding \
    "missing_b_host_env" \
    "B_HOST is missing for profile-default-gate-live endpoint wiring." \
    "export B_HOST=$(env_value_literal "$host_b_cmd_value")"
fi

if [[ -z "$EFFECTIVE_SUBJECT" ]]; then
  subject_cmd_value="$SET_CAMPAIGN_SUBJECT"
  if [[ -z "$subject_cmd_value" ]]; then
    subject_cmd_value="<invite-key>"
  fi
  add_finding \
    "missing_invite_subject_env" \
    "Invite subject is missing; profile/default gate live run requires CAMPAIGN_SUBJECT or INVITE_KEY." \
    "export INVITE_KEY=$(env_value_literal "$subject_cmd_value"); export CAMPAIGN_SUBJECT=\"\$INVITE_KEY\""
fi

if (( ${#DEPRECATED_FLAGS[@]} > 0 )); then
  unique_deprecated=()
  for deprecated_flag in "${DEPRECATED_FLAGS[@]}"; do
    if ! array_contains_exact "$deprecated_flag" "${unique_deprecated[@]}"; then
      unique_deprecated+=("$deprecated_flag")
    fi
  done
  deprecated_csv=""
  for deprecated_flag in "${unique_deprecated[@]}"; do
    if [[ -n "$deprecated_csv" ]]; then
      deprecated_csv+=","
    fi
    deprecated_csv+="$deprecated_flag"
  done
  add_finding \
    "deprecated_subject_alias" \
    "Deprecated subject aliases detected ($deprecated_csv). Prefer --campaign-subject for deterministic signoff wiring." \
    "./scripts/easy_node.sh profile-default-gate-live --host-a \"\${A_HOST}\" --host-b \"\${B_HOST}\" --campaign-subject \"\${INVITE_KEY}\""
fi

if [[ -n "$EFFECTIVE_CAMPAIGN_TIMEOUT_SEC" ]] && (( EFFECTIVE_CAMPAIGN_TIMEOUT_SEC > 0 )) && (( EFFECTIVE_CAMPAIGN_TIMEOUT_SEC < MINIMUM_CAMPAIGN_TIMEOUT_SEC )); then
  add_finding \
    "campaign_timeout_too_low" \
    "Campaign signoff timeout is too low (${EFFECTIVE_CAMPAIGN_TIMEOUT_SEC}s); recommended minimum is ${MINIMUM_CAMPAIGN_TIMEOUT_SEC}s." \
    "export PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC=${MINIMUM_CAMPAIGN_TIMEOUT_SEC}"
fi

if [[ ! -f "$SUMMARY_JSON" ]]; then
  add_finding \
    "summary_artifact_missing" \
    "Campaign signoff summary artifact is missing ($SUMMARY_JSON)." \
    "./scripts/easy_node.sh profile-compare-campaign-signoff --refresh-campaign 1 --campaign-timeout-sec ${MINIMUM_CAMPAIGN_TIMEOUT_SEC} --summary-json $(env_value_literal "$SUMMARY_JSON") --print-summary-json 1"
else
  summary_mtime_epoch="$(file_mtime_epoch "$SUMMARY_JSON" || true)"
  if [[ -z "$summary_mtime_epoch" || ! "$summary_mtime_epoch" =~ ^[0-9]+$ ]]; then
    add_finding \
      "summary_artifact_stale" \
      "Summary artifact exists but file timestamp could not be read ($SUMMARY_JSON)." \
      "./scripts/easy_node.sh profile-compare-campaign-signoff --refresh-campaign 1 --summary-json $(env_value_literal "$SUMMARY_JSON") --print-summary-json 1"
  else
    now_epoch="$(date +%s)"
    summary_age_sec=$((now_epoch - summary_mtime_epoch))
    if (( summary_age_sec < 0 )); then
      summary_age_sec=0
    fi
    if (( summary_age_sec > SUMMARY_MAX_AGE_SEC )); then
      add_finding \
        "summary_artifact_stale" \
        "Campaign signoff summary artifact is stale (${summary_age_sec}s old; max ${SUMMARY_MAX_AGE_SEC}s)." \
        "./scripts/easy_node.sh profile-compare-campaign-signoff --refresh-campaign 1 --summary-json $(env_value_literal "$SUMMARY_JSON") --print-summary-json 1"
    fi
  fi
fi

applied_count=0

if [[ "$MODE" == "apply" ]]; then
  if [[ -n "$SET_A_HOST" ]]; then
    upsert_env_key "$ENV_FILE" "A_HOST" "$SET_A_HOST"
    applied_count=$((applied_count + 1))
    log_marker "apply_env_upsert key=A_HOST env_file=$ENV_FILE"
  fi
  if [[ -n "$SET_B_HOST" ]]; then
    upsert_env_key "$ENV_FILE" "B_HOST" "$SET_B_HOST"
    applied_count=$((applied_count + 1))
    log_marker "apply_env_upsert key=B_HOST env_file=$ENV_FILE"
  fi
  if [[ -n "$SET_CAMPAIGN_SUBJECT" ]]; then
    upsert_env_key "$ENV_FILE" "CAMPAIGN_SUBJECT" "$SET_CAMPAIGN_SUBJECT"
    upsert_env_key "$ENV_FILE" "INVITE_KEY" "$SET_CAMPAIGN_SUBJECT"
    applied_count=$((applied_count + 2))
    log_marker "apply_env_upsert key=CAMPAIGN_SUBJECT env_file=$ENV_FILE"
    log_marker "apply_env_upsert key=INVITE_KEY env_file=$ENV_FILE"
  fi

  timeout_apply_value=""
  if [[ -n "$SET_CAMPAIGN_TIMEOUT_SEC" ]]; then
    timeout_apply_value="$SET_CAMPAIGN_TIMEOUT_SEC"
  elif [[ -n "$EFFECTIVE_CAMPAIGN_TIMEOUT_SEC" ]] && (( EFFECTIVE_CAMPAIGN_TIMEOUT_SEC > 0 )) && (( EFFECTIVE_CAMPAIGN_TIMEOUT_SEC < MINIMUM_CAMPAIGN_TIMEOUT_SEC )); then
    timeout_apply_value="$MINIMUM_CAMPAIGN_TIMEOUT_SEC"
  fi

  if [[ -n "$timeout_apply_value" ]]; then
    upsert_env_key "$ENV_FILE" "PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC" "$timeout_apply_value"
    applied_count=$((applied_count + 1))
    log_marker "apply_env_upsert key=PROFILE_COMPARE_CAMPAIGN_SIGNOFF_CAMPAIGN_TIMEOUT_SEC env_file=$ENV_FILE value=$timeout_apply_value"
  fi

  mkdir -p "$(dirname "$REMEDIATION_SCRIPT")"
  {
    printf '#!/usr/bin/env bash\n'
    printf 'set -euo pipefail\n\n'
    printf '# Generated by gpm_endpoint_posture_remediate.sh at %s\n' "$(timestamp_utc)"
    printf '# Review placeholders before execution.\n\n'
    idx=0
    while (( idx < ${#FINDING_COMMANDS[@]} )); do
      printf '%s\n' "${FINDING_COMMANDS[$idx]}"
      idx=$((idx + 1))
    done
  } >"$REMEDIATION_SCRIPT"
  chmod +x "$REMEDIATION_SCRIPT"
  log_marker "apply_written_remediation_script path=$REMEDIATION_SCRIPT command_count=${#FINDING_COMMANDS[@]}"
fi

if (( ${#FINDING_IDS[@]} == 0 )); then
  log_marker "no_findings"
fi

log_marker "status=ok mode=$MODE findings=${#FINDING_IDS[@]} applied=$applied_count"
exit 0
