#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

SIGNOFF_SCRIPT="${PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT:-$ROOT_DIR/scripts/profile_compare_campaign_signoff.sh}"
PROMOTION_CHECK_SCRIPT="${RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT:-$ROOT_DIR/scripts/runtime_actuation_promotion_check.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/runtime_actuation_promotion_cycle.sh \
    [--cycles N] \
    [--reports-dir DIR] \
    [--summary-list FILE | --signoff-summary-list FILE] \
    [--promotion-summary-json PATH | --promotion-check-summary-json PATH] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--show-json [0|1]] \
    [--print-summary-json [0|1]] \
    [profile_compare_campaign_signoff args...]

Purpose:
  Run repeated runtime-actuation evidence cycles by invoking
  profile_compare_campaign_signoff.sh with forced per-cycle artifact paths, then
  run runtime_actuation_promotion_check.sh over the produced cycle summary list.

Notes:
  - Signoff pass-through args are forwarded to each cycle invocation.
  - This orchestrator always forces per-cycle:
      --campaign-summary-json
      --campaign-report-md
      --campaign-check-summary-json
      --summary-json
    so artifacts are deterministic and non-colliding.
  - Stage scripts can be overridden with:
      PROFILE_COMPARE_CAMPAIGN_SIGNOFF_SCRIPT
      RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT
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

strip_optional_wrapping_quotes_01() {
  local value="${1:-}"
  local first_char=""
  local last_char=""
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

is_invite_subject_placeholder() {
  local value=""
  local normalized=""
  value="$(trim "${1:-}")"
  value="$(strip_optional_wrapping_quotes_01 "$value")"
  if [[ -z "$value" ]]; then
    return 1
  fi
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$normalized" in
    INVITE_KEY|\$\{INVITE_KEY\}|\$INVITE_KEY|"<INVITE_KEY>"|"{{INVITE_KEY}}"|YOUR_INVITE_KEY|REPLACE_WITH_INVITE_KEY|%INVITE_KEY%|\$\{INVITE_KEY:-*}|\$\{INVITE_KEY-*}|CAMPAIGN_SUBJECT|\$\{CAMPAIGN_SUBJECT\}|\$CAMPAIGN_SUBJECT|"<CAMPAIGN_SUBJECT>"|"{{CAMPAIGN_SUBJECT}}"|YOUR_CAMPAIGN_SUBJECT|REPLACE_WITH_CAMPAIGN_SUBJECT|%CAMPAIGN_SUBJECT%|\$\{CAMPAIGN_SUBJECT:-*}|\$\{CAMPAIGN_SUBJECT-*})
      return 0
      ;;
    *)
      return 1
      ;;
  esac
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
    echo "$name must be a non-negative integer"
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

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

normalize_decision() {
  local decision
  decision="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  case "$decision" in
    GO) printf '%s\n' "GO" ;;
    NO-GO|NOGO|NO_GO) printf '%s\n' "NO-GO" ;;
    *) printf '%s\n' "$decision" ;;
  esac
}

normalize_status() {
  local status
  status="$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
  case "$status" in
    pass|ok|success) printf '%s\n' "pass" ;;
    warn|warning) printf '%s\n' "warn" ;;
    fail|failed|error) printf '%s\n' "fail" ;;
    *) printf '%s\n' "$status" ;;
  esac
}

quote_cmd() {
  local arg
  for arg in "$@"; do
    printf '%q ' "$arg"
  done
  printf '\n'
}

json_file_valid_01() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '0'
    return
  fi
  if jq -e 'type == "object"' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

file_fingerprint_01() {
  local path="$1"
  if [[ -z "$path" || ! -f "$path" ]]; then
    printf '%s' ""
    return
  fi
  cksum "$path" 2>/dev/null | awk '{print $1 ":" $2}' || true
}

array_to_json() {
  if (($# == 0)); then
    printf '%s' '[]'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -s '.'
}

render_command_line_from_argv_01() {
  local arg=""
  local rendered=""
  for arg in "$@"; do
    rendered="${rendered}${rendered:+ }$(printf '%q' "$arg")"
  done
  printf '%s' "$rendered"
}

build_runtime_actuation_base_command_01() {
  local -a cmd=("./scripts/runtime_actuation_promotion_cycle.sh")
  cmd+=(--cycles "$cycles")
  cmd+=(--reports-dir "$reports_dir")
  if [[ -n "$signoff_summary_list" ]]; then
    cmd+=(--summary-list "$signoff_summary_list")
  fi
  if [[ -n "$promotion_summary_json" ]]; then
    cmd+=(--promotion-summary-json "$promotion_summary_json")
  fi
  if [[ -n "$summary_json" ]]; then
    cmd+=(--summary-json "$summary_json")
  fi
  cmd+=(--fail-on-no-go "$fail_on_no_go")
  cmd+=(--show-json "$show_json")
  cmd+=(--print-summary-json "$print_summary_json")

  render_command_line_from_argv_01 "${cmd[@]}"
}

build_runtime_actuation_subject_operator_command_01() {
  local -a cmd=()
  cmd=(./scripts/runtime_actuation_promotion_cycle.sh)
  cmd+=(--cycles "$cycles")
  cmd+=(--reports-dir "$reports_dir")
  if [[ -n "$signoff_summary_list" ]]; then
    cmd+=(--summary-list "$signoff_summary_list")
  fi
  if [[ -n "$promotion_summary_json" ]]; then
    cmd+=(--promotion-summary-json "$promotion_summary_json")
  fi
  if [[ -n "$summary_json" ]]; then
    cmd+=(--summary-json "$summary_json")
  fi
  cmd+=(--fail-on-no-go "$fail_on_no_go")
  cmd+=(--show-json "$show_json")
  cmd+=(--print-summary-json "$print_summary_json")
  cmd+=(--subject "REPLACE_WITH_INVITE_SUBJECT")

  render_command_line_from_argv_01 "${cmd[@]}"
}

build_runtime_actuation_subject_env_operator_command_01() {
  printf 'CAMPAIGN_SUBJECT=REPLACE_WITH_INVITE_SUBJECT %s' "$(build_runtime_actuation_base_command_01)"
}

write_alias_content_atomic() {
  local alias_path="$1"
  local label="$2"
  local tmp_alias=""

  mkdir -p "$(dirname "$alias_path")"
  tmp_alias="$(mktemp "${alias_path}.tmp.XXXXXX")"
  if ! cat >"$tmp_alias"; then
    rm -f "$tmp_alias" 2>/dev/null || true
    echo "failed to write $label temp file: $tmp_alias"
    return 1
  fi
  mv -f "$tmp_alias" "$alias_path"
}

refresh_alias_atomic() {
  local source_path="$1"
  local alias_path="$2"
  local label="$3"
  local tmp_alias=""

  if [[ "$source_path" == "$alias_path" ]]; then
    return 0
  fi
  if [[ -z "$source_path" || ! -f "$source_path" ]]; then
    echo "missing $label source for alias refresh: $source_path"
    return 1
  fi

  if ! cat "$source_path" | write_alias_content_atomic "$alias_path" "$label latest alias"; then
    return 1
  fi
}

invalidate_latest_aliases_fail_closed() {
  local run_id="$1"
  local invalidated_at_utc="$2"
  local reason_text="latest aliases invalidated for new runtime_actuation_promotion_cycle run; waiting for refreshed outputs"
  local signoff_failclosed_path="$reports_dir/runtime_actuation_promotion_cycle_latest_signoff_incomplete.json"

  # Clear previous aliases first so stale GO artifacts are not preserved if
  # this invalidation sequence fails part-way through.
  if ! rm -f "$latest_cycle_summary_alias" "$latest_promotion_summary_alias" "$latest_signoff_summary_list_alias" "$signoff_failclosed_path"; then
    echo "failed to clear one or more latest aliases before fail-closed invalidation"
    return 1
  fi

  if ! jq -n \
    --arg generated_at_utc "$invalidated_at_utc" \
    --arg reason "$reason_text" \
    --arg run_id "$run_id" \
    '{
      version: 1,
      schema: {
        id: "runtime_actuation_promotion_cycle_summary"
      },
      generated_at_utc: $generated_at_utc,
      status: "fail",
      rc: 1,
      decision: "NO-GO",
      failure_stage: "latest_alias_invalidation",
      failure_reason: $reason,
      run_id: $run_id,
      outcome: {
        should_promote: false,
        action: "hold_promotion_blocked"
      }
    }' | write_alias_content_atomic "$latest_cycle_summary_alias" "cycle orchestrator latest alias invalidation"; then
    return 1
  fi

  if ! jq -n \
    --arg generated_at_utc "$invalidated_at_utc" \
    --arg reason "$reason_text" \
    --arg run_id "$run_id" \
    '{
      version: 1,
      schema: {
        id: "runtime_actuation_promotion_check_summary"
      },
      generated_at_utc: $generated_at_utc,
      status: "fail",
      rc: 1,
      decision: "NO-GO",
      notes: $reason,
      run_id: $run_id,
      outcome: {
        should_promote: false,
        action: "hold_promotion_blocked",
        next_operator_action: "rerun runtime_actuation_promotion_cycle to refresh latest aliases"
      },
      errors: [
        "latest promotion summary alias invalidated before run completion"
      ],
      violations: []
    }' | write_alias_content_atomic "$latest_promotion_summary_alias" "promotion-check latest alias invalidation"; then
    return 1
  fi

  if ! jq -n \
    --arg generated_at_utc "$invalidated_at_utc" \
    --arg reason "$reason_text" \
    --arg run_id "$run_id" \
    '{
      version: 1,
      generated_at_utc: $generated_at_utc,
      status: "fail",
      final_rc: 1,
      decision: {
        decision: "NO-GO",
        next_operator_action: $reason
      },
      run_id: $run_id
    }' | write_alias_content_atomic "$signoff_failclosed_path" "signoff latest fail-closed sentinel"; then
    return 1
  fi

  if ! printf '%s\n' "$signoff_failclosed_path" | write_alias_content_atomic "$latest_signoff_summary_list_alias" "signoff summary-list latest alias invalidation"; then
    return 1
  fi
}

attempt_alias_refresh_nonfatal() {
  local source_path="$1"
  local alias_path="$2"
  local label="$3"

  if refresh_alias_atomic "$source_path" "$alias_path" "$label"; then
    echo "[runtime-actuation-promotion-cycle] latest-alias refreshed label=$label alias=$alias_path"
    return 0
  fi

  alias_refresh_failures=$((alias_refresh_failures + 1))
  alias_refresh_errors+=("$label: source=$source_path alias=$alias_path")
  echo "[runtime-actuation-promotion-cycle] warning: latest-alias refresh failed label=$label source=$source_path alias=$alias_path"
  return 0
}

need_cmd jq
need_cmd date
need_cmd bash
need_cmd mktemp
need_cmd mkdir
need_cmd cksum

cycles="${RUNTIME_ACTUATION_PROMOTION_CYCLE_CYCLES:-3}"
reports_dir="${RUNTIME_ACTUATION_PROMOTION_CYCLE_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
signoff_summary_list="${RUNTIME_ACTUATION_PROMOTION_CYCLE_SUMMARY_LIST:-}"
promotion_summary_json="${RUNTIME_ACTUATION_PROMOTION_CYCLE_PROMOTION_SUMMARY_JSON:-}"
summary_json="${RUNTIME_ACTUATION_PROMOTION_CYCLE_SUMMARY_JSON:-}"
fail_on_no_go="${RUNTIME_ACTUATION_PROMOTION_CYCLE_FAIL_ON_NO_GO:-${FAIL_ON_NO_GO:-1}}"
show_json="${RUNTIME_ACTUATION_PROMOTION_CYCLE_SHOW_JSON:-0}"
print_summary_json="${RUNTIME_ACTUATION_PROMOTION_CYCLE_PRINT_SUMMARY_JSON:-0}"

declare -a signoff_passthrough_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --cycles)
      require_value_or_die "$1" "$#"
      cycles="${2:-}"
      shift 2
      ;;
    --cycles=*)
      cycles="${1#*=}"
      shift
      ;;
    --reports-dir)
      require_value_or_die "$1" "$#"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --summary-list|--signoff-summary-list)
      require_value_or_die "$1" "$#"
      signoff_summary_list="${2:-}"
      shift 2
      ;;
    --summary-list=*|--signoff-summary-list=*)
      signoff_summary_list="${1#*=}"
      shift
      ;;
    --promotion-summary-json|--promotion-check-summary-json)
      require_value_or_die "$1" "$#"
      promotion_summary_json="${2:-}"
      shift 2
      ;;
    --promotion-summary-json=*|--promotion-check-summary-json=*)
      promotion_summary_json="${1#*=}"
      shift
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
    --fail-on-no-go=*)
      fail_on_no_go="${1#*=}"
      shift
      ;;
    --summary-json)
      require_value_or_die "$1" "$#"
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
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
    -h|--help|help)
      usage
      exit 0
      ;;
    --)
      shift
      while [[ $# -gt 0 ]]; do
        signoff_passthrough_args+=("$1")
        shift
      done
      ;;
    *)
      signoff_passthrough_args+=("$1")
      shift
      ;;
  esac
done

cycles="$(trim "$cycles")"
reports_dir="$(abs_path "$reports_dir")"
signoff_summary_list="$(abs_path "$signoff_summary_list")"
promotion_summary_json="$(abs_path "$promotion_summary_json")"
summary_json="$(abs_path "$summary_json")"
fail_on_no_go="$(trim "$fail_on_no_go")"
show_json="$(trim "$show_json")"
print_summary_json="$(trim "$print_summary_json")"
SIGNOFF_SCRIPT="$(abs_path "$SIGNOFF_SCRIPT")"
PROMOTION_CHECK_SCRIPT="$(abs_path "$PROMOTION_CHECK_SCRIPT")"

int_arg_or_die "--cycles" "$cycles"
if (( cycles < 1 )); then
  echo "--cycles must be >= 1"
  exit 2
fi
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--show-json" "$show_json"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

resolved_campaign_subject=""
resolved_campaign_subject_source=""
for subject_source in CAMPAIGN_SUBJECT INVITE_KEY; do
  subject_candidate="$(trim "${!subject_source:-}")"
  if [[ -z "$subject_candidate" ]]; then
    continue
  fi
  if is_invite_subject_placeholder "$subject_candidate"; then
    continue
  fi
  resolved_campaign_subject="$subject_candidate"
  resolved_campaign_subject_source="env:${subject_source}"
  break
done

signoff_has_subject_credential="false"
signoff_has_anon_credential="false"
campaign_subject_injected="false"
campaign_subject_placeholder_replaced="false"
campaign_subject_resolution_mode="none"

if ((${#signoff_passthrough_args[@]} > 0)); then
  declare -a normalized_signoff_passthrough_args=()
  idx=0
  while (( idx < ${#signoff_passthrough_args[@]} )); do
    token="${signoff_passthrough_args[$idx]}"
    case "$token" in
      --campaign-subject|--subject|--key|--invite-key)
        signoff_has_subject_credential="true"
        normalized_signoff_passthrough_args+=("$token")
        idx=$((idx + 1))
        if (( idx >= ${#signoff_passthrough_args[@]} )); then
          echo "runtime-actuation-promotion-cycle: $token requires a value in signoff passthrough args"
          echo "operator_next_action: $(build_runtime_actuation_subject_operator_command_01)"
          exit 2
        fi
        token_value="${signoff_passthrough_args[$idx]}"
        if [[ -z "$(trim "$token_value")" ]]; then
          echo "runtime-actuation-promotion-cycle: $token requires a non-empty value in signoff passthrough args"
          echo "operator_next_action: $(build_runtime_actuation_subject_operator_command_01)"
          exit 2
        fi
        if is_invite_subject_placeholder "$token_value"; then
          if [[ -n "$resolved_campaign_subject" ]]; then
            normalized_signoff_passthrough_args+=("$resolved_campaign_subject")
            campaign_subject_placeholder_replaced="true"
          else
            echo "runtime-actuation-promotion-cycle: placeholder invite subject in signoff passthrough ($token) cannot be resolved"
            echo "provide a real value via $token or set CAMPAIGN_SUBJECT/INVITE_KEY"
            echo "operator_next_action: $(build_runtime_actuation_subject_operator_command_01)"
            echo "operator_next_action: $(build_runtime_actuation_subject_env_operator_command_01)"
            exit 2
          fi
        else
          normalized_signoff_passthrough_args+=("$token_value")
        fi
        idx=$((idx + 1))
        ;;
      --campaign-subject=*|--subject=*|--key=*|--invite-key=*)
        signoff_has_subject_credential="true"
        token_key="${token%%=*}"
        token_value="${token#*=}"
        if [[ -z "$(trim "$token_value")" ]]; then
          echo "runtime-actuation-promotion-cycle: ${token_key}= requires a non-empty value in signoff passthrough args"
          echo "operator_next_action: $(build_runtime_actuation_subject_operator_command_01)"
          exit 2
        fi
        if is_invite_subject_placeholder "$token_value"; then
          if [[ -n "$resolved_campaign_subject" ]]; then
            normalized_signoff_passthrough_args+=("${token_key}=${resolved_campaign_subject}")
            campaign_subject_placeholder_replaced="true"
          else
            echo "runtime-actuation-promotion-cycle: placeholder invite subject in signoff passthrough (${token_key}=...) cannot be resolved"
            echo "provide a real value via $token_key or set CAMPAIGN_SUBJECT/INVITE_KEY"
            echo "operator_next_action: $(build_runtime_actuation_subject_operator_command_01)"
            echo "operator_next_action: $(build_runtime_actuation_subject_env_operator_command_01)"
            exit 2
          fi
        else
          normalized_signoff_passthrough_args+=("$token")
        fi
        idx=$((idx + 1))
        ;;
      --campaign-anon-cred|--anon-cred)
        signoff_has_anon_credential="true"
        normalized_signoff_passthrough_args+=("$token")
        idx=$((idx + 1))
        if (( idx >= ${#signoff_passthrough_args[@]} )); then
          echo "runtime-actuation-promotion-cycle: $token requires a value in signoff passthrough args"
          exit 2
        fi
        normalized_signoff_passthrough_args+=("${signoff_passthrough_args[$idx]}")
        idx=$((idx + 1))
        ;;
      --campaign-anon-cred=*|--anon-cred=*)
        signoff_has_anon_credential="true"
        normalized_signoff_passthrough_args+=("$token")
        idx=$((idx + 1))
        ;;
      *)
        normalized_signoff_passthrough_args+=("$token")
        idx=$((idx + 1))
        ;;
    esac
  done
  signoff_passthrough_args=("${normalized_signoff_passthrough_args[@]}")
fi

if [[ "$signoff_has_subject_credential" != "true" && "$signoff_has_anon_credential" != "true" && -n "$resolved_campaign_subject" ]]; then
  signoff_passthrough_args+=(--campaign-subject "$resolved_campaign_subject")
  signoff_has_subject_credential="true"
  campaign_subject_injected="true"
fi

if [[ "$campaign_subject_placeholder_replaced" == "true" ]]; then
  campaign_subject_resolution_mode="placeholder_replaced"
elif [[ "$campaign_subject_injected" == "true" ]]; then
  campaign_subject_resolution_mode="injected"
fi

if [[ "$campaign_subject_resolution_mode" != "none" ]]; then
  echo "[runtime-actuation-promotion-cycle] $(timestamp_utc) campaign-subject resolution mode=$campaign_subject_resolution_mode source=$resolved_campaign_subject_source"
fi

if [[ ! -f "$SIGNOFF_SCRIPT" ]]; then
  echo "campaign signoff script not found: $SIGNOFF_SCRIPT"
  exit 2
fi
if [[ ! -f "$PROMOTION_CHECK_SCRIPT" ]]; then
  echo "runtime actuation promotion check script not found: $PROMOTION_CHECK_SCRIPT"
  exit 2
fi

mkdir -p "$reports_dir"
run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$signoff_summary_list" ]]; then
  signoff_summary_list="$reports_dir/runtime_actuation_promotion_cycle_${run_stamp}_signoff_summaries.list"
fi
if [[ -z "$promotion_summary_json" ]]; then
  promotion_summary_json="$reports_dir/runtime_actuation_promotion_cycle_${run_stamp}_promotion_check_summary.json"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/runtime_actuation_promotion_cycle_${run_stamp}_summary.json"
fi

latest_cycle_summary_alias="$reports_dir/runtime_actuation_promotion_cycle_latest_summary.json"
latest_promotion_summary_alias="$reports_dir/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json"
latest_signoff_summary_list_alias="$reports_dir/runtime_actuation_promotion_cycle_latest_signoff_summaries.list"

mkdir -p "$(dirname "$signoff_summary_list")" "$(dirname "$promotion_summary_json")" "$(dirname "$summary_json")"
mkdir -p "$(dirname "$latest_cycle_summary_alias")" "$(dirname "$latest_promotion_summary_alias")" "$(dirname "$latest_signoff_summary_list_alias")"

if ! invalidate_latest_aliases_fail_closed "$run_stamp" "$(timestamp_utc)"; then
  echo "failed to invalidate latest aliases at run start"
  exit 1
fi

declare -a signoff_summary_paths=()
declare -a signoff_logs=()
declare -a cycle_stage_errors=()
cycles_entries_json='[]'
cycles_completed=0
cycles_passed=0
cycles_failed=0

for ((cycle_idx = 1; cycle_idx <= cycles; cycle_idx++)); do
  signoff_summary_path="$reports_dir/runtime_actuation_promotion_cycle_${run_stamp}_signoff_${cycle_idx}.json"
  campaign_check_summary_path="$reports_dir/runtime_actuation_promotion_cycle_${run_stamp}_campaign_check_${cycle_idx}.json"
  campaign_summary_path="$reports_dir/runtime_actuation_promotion_cycle_${run_stamp}_campaign_${cycle_idx}.json"
  campaign_report_path="$reports_dir/runtime_actuation_promotion_cycle_${run_stamp}_campaign_${cycle_idx}.md"
  signoff_log="$reports_dir/runtime_actuation_promotion_cycle_${run_stamp}_signoff_${cycle_idx}.log"

  signoff_summary_paths+=("$signoff_summary_path")
  signoff_logs+=("$signoff_log")

  pre_signoff_fingerprint="$(file_fingerprint_01 "$signoff_summary_path")"
  signoff_cmd=(
    bash "$SIGNOFF_SCRIPT"
    "${signoff_passthrough_args[@]}"
    --reports-dir "$reports_dir"
    --campaign-summary-json "$campaign_summary_path"
    --campaign-report-md "$campaign_report_path"
    --campaign-check-summary-json "$campaign_check_summary_path"
    --summary-json "$signoff_summary_path"
    --show-json 0
    --print-summary-json 0
  )
  signoff_command_display="$(quote_cmd "${signoff_cmd[@]}")"

  echo "[runtime-actuation-promotion-cycle] $(timestamp_utc) signoff-cycle start cycle=$cycle_idx/$cycles summary_json=$signoff_summary_path"
  set +e
  "${signoff_cmd[@]}" >"$signoff_log" 2>&1
  signoff_rc=$?
  set -e

  cycles_completed=$((cycles_completed + 1))

  signoff_summary_exists="false"
  signoff_summary_valid="false"
  signoff_summary_fresh="false"
  signoff_status=""
  signoff_status_normalized=""
  signoff_decision=""
  signoff_decision_usable="false"
  signoff_summary_rc_json="null"
  cycle_status="fail"
  cycle_error=""

  if [[ -f "$signoff_summary_path" ]]; then
    signoff_summary_exists="true"
  fi
  if [[ "$(json_file_valid_01 "$signoff_summary_path")" == "1" ]]; then
    signoff_summary_valid="true"
    post_signoff_fingerprint="$(file_fingerprint_01 "$signoff_summary_path")"
    if [[ -z "$pre_signoff_fingerprint" && -n "$post_signoff_fingerprint" ]]; then
      signoff_summary_fresh="true"
    elif [[ -n "$post_signoff_fingerprint" && "$post_signoff_fingerprint" != "$pre_signoff_fingerprint" ]]; then
      signoff_summary_fresh="true"
    fi
    signoff_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$signoff_summary_path" 2>/dev/null || printf '%s' "")"
    signoff_status_normalized="$(normalize_status "$signoff_status")"
    signoff_decision="$(jq -r '
      if (.decision.decision | type) == "string" then .decision.decision
      elif (.decision | type) == "string" then .decision
      else ""
      end
    ' "$signoff_summary_path" 2>/dev/null || printf '%s' "")"
    signoff_decision="$(normalize_decision "$signoff_decision")"
    if [[ "$signoff_decision" == "GO" || "$signoff_decision" == "NO-GO" ]]; then
      signoff_decision_usable="true"
    fi
    signoff_summary_rc_json="$(jq -r '
      if (.final_rc | type) == "number" then .final_rc
      elif (.rc | type) == "number" then .rc
      else "null"
      end
    ' "$signoff_summary_path" 2>/dev/null || printf '%s' "null")"
  fi

  if [[ "$signoff_rc" -ne 0 ]]; then
    cycle_error="signoff command failed (rc=$signoff_rc)"
  elif [[ "$signoff_summary_valid" != "true" ]]; then
    cycle_error="signoff summary is missing or invalid JSON"
  elif [[ "$signoff_summary_fresh" != "true" ]]; then
    cycle_error="signoff summary is stale (not refreshed by current cycle)"
  elif [[ "$signoff_decision_usable" != "true" ]]; then
    cycle_error="signoff summary is missing a usable decision"
  elif [[ "$signoff_summary_rc_json" != "0" ]]; then
    cycle_error="signoff summary rc indicates failure"
  elif [[ "$signoff_decision" != "GO" ]]; then
    cycle_error="signoff decision is ${signoff_decision:-unrecognized}"
  elif [[ "$signoff_status_normalized" != "pass" ]]; then
    cycle_error="signoff status is ${signoff_status_normalized:-unrecognized}"
  else
    cycle_status="pass"
  fi

  if [[ "$cycle_status" == "pass" ]]; then
    cycles_passed=$((cycles_passed + 1))
  else
    cycles_failed=$((cycles_failed + 1))
    cycle_stage_errors+=("cycle $cycle_idx: ${cycle_error:-unknown signoff cycle failure}")
  fi

  cycle_entry_json="$(jq -n \
    --argjson cycle_index "$cycle_idx" \
    --arg status "$cycle_status" \
    --argjson rc "$signoff_rc" \
    --arg error "$cycle_error" \
    --arg command "$signoff_command_display" \
    --arg log "$signoff_log" \
    --arg signoff_summary_json "$signoff_summary_path" \
    --arg campaign_check_summary_json "$campaign_check_summary_path" \
    --arg campaign_summary_json "$campaign_summary_path" \
    --arg campaign_report_md "$campaign_report_path" \
    --arg signoff_summary_exists "$signoff_summary_exists" \
    --arg signoff_summary_valid "$signoff_summary_valid" \
    --arg signoff_summary_fresh "$signoff_summary_fresh" \
    --arg signoff_status "$signoff_status" \
    --arg signoff_status_normalized "$signoff_status_normalized" \
    --arg signoff_decision "$signoff_decision" \
    --arg signoff_decision_usable "$signoff_decision_usable" \
    --argjson signoff_summary_rc "$signoff_summary_rc_json" \
    '{
      cycle_index: $cycle_index,
      status: $status,
      rc: $rc,
      error: (if $error == "" then null else $error end),
      command: $command,
      log: $log,
      summary: {
        signoff_summary_json: $signoff_summary_json,
        exists: ($signoff_summary_exists == "true"),
        valid_json: ($signoff_summary_valid == "true"),
        fresh: ($signoff_summary_fresh == "true"),
        status: (if $signoff_status == "" then null else $signoff_status end),
        status_normalized: (if $signoff_status_normalized == "" then null else $signoff_status_normalized end),
        decision: (if $signoff_decision == "" then null else $signoff_decision end),
        has_usable_decision: ($signoff_decision_usable == "true"),
        rc: $signoff_summary_rc
      },
      artifacts: {
        campaign_check_summary_json: $campaign_check_summary_json,
        campaign_summary_json: $campaign_summary_json,
        campaign_report_md: $campaign_report_md
      }
    }')"
  cycles_entries_json="$(jq -c --argjson entry "$cycle_entry_json" '. + [$entry]' <<<"$cycles_entries_json")"
done

summary_list_tmp="$(mktemp "${signoff_summary_list}.tmp.XXXXXX")"
if ((${#signoff_summary_paths[@]} > 0)); then
  printf '%s\n' "${signoff_summary_paths[@]}" >"$summary_list_tmp"
else
  # Keep non-empty to prevent downstream fallback glob expansion from hiding missing evidence.
  printf '%s\n' "$reports_dir/runtime_actuation_promotion_cycle_missing_summary.json" >"$summary_list_tmp"
fi
mv -f "$summary_list_tmp" "$signoff_summary_list"

promotion_log="$reports_dir/runtime_actuation_promotion_cycle_${run_stamp}_promotion_check.log"
promotion_cmd=(
  bash "$PROMOTION_CHECK_SCRIPT"
  --summary-list "$signoff_summary_list"
  --reports-dir "$reports_dir"
  --fail-on-no-go "$fail_on_no_go"
  --summary-json "$promotion_summary_json"
  --show-json 0
  --print-summary-json 0
)
promotion_command_display="$(quote_cmd "${promotion_cmd[@]}")"

echo "[runtime-actuation-promotion-cycle] $(timestamp_utc) promotion-check start summary_list=$signoff_summary_list"
pre_promotion_fingerprint="$(file_fingerprint_01 "$promotion_summary_json")"
set +e
"${promotion_cmd[@]}" >"$promotion_log" 2>&1
promotion_stage_rc=$?
set -e

promotion_stage_status="pass"
if [[ "$promotion_stage_rc" -ne 0 ]]; then
  promotion_stage_status="fail"
fi

promotion_summary_exists="false"
promotion_summary_valid="false"
promotion_summary_fresh="false"
promotion_decision=""
promotion_status=""
promotion_rc_json="null"
promotion_notes=""
promotion_outcome_action=""
promotion_next_operator_action=""
promotion_violations_json='[]'
promotion_errors_json='[]'

if [[ -f "$promotion_summary_json" ]]; then
  promotion_summary_exists="true"
fi
if [[ "$(json_file_valid_01 "$promotion_summary_json")" == "1" ]]; then
  promotion_summary_valid="true"
  post_promotion_fingerprint="$(file_fingerprint_01 "$promotion_summary_json")"
  if [[ -z "$pre_promotion_fingerprint" && -n "$post_promotion_fingerprint" ]]; then
    promotion_summary_fresh="true"
  elif [[ -n "$post_promotion_fingerprint" && "$post_promotion_fingerprint" != "$pre_promotion_fingerprint" ]]; then
    promotion_summary_fresh="true"
  fi
  promotion_decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_decision="$(normalize_decision "$promotion_decision")"
  promotion_status="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_rc_json="$(jq -r 'if (.rc | type) == "number" then .rc else "null" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "null")"
  promotion_notes="$(jq -r 'if (.notes | type) == "string" then .notes else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_outcome_action="$(jq -r 'if (.outcome.action | type) == "string" then .outcome.action else "" end' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_next_operator_action="$(jq -r '
    if (.outcome.next_operator_action | type) == "string" then .outcome.next_operator_action
    elif (.next_operator_action | type) == "string" then .next_operator_action
    else ""
    end
  ' "$promotion_summary_json" 2>/dev/null || printf '%s' "")"
  promotion_violations_json="$(jq -c 'if (.violations | type) == "array" then .violations else [] end' "$promotion_summary_json" 2>/dev/null || printf '%s' '[]')"
  promotion_errors_json="$(jq -c 'if (.errors | type) == "array" then .errors else [] end' "$promotion_summary_json" 2>/dev/null || printf '%s' '[]')"
fi

promotion_has_usable_decision="false"
if [[ "$promotion_decision" == "GO" || "$promotion_decision" == "NO-GO" ]]; then
  promotion_has_usable_decision="true"
fi

if [[ "$promotion_stage_rc" -eq 0 ]]; then
  if [[ "$promotion_summary_valid" != "true" ]]; then
    promotion_stage_status="fail"
  elif [[ "$promotion_summary_fresh" != "true" ]]; then
    promotion_stage_status="fail"
  elif [[ "$promotion_has_usable_decision" != "true" ]]; then
    promotion_stage_status="fail"
  elif [[ "$promotion_decision" == "GO" && ( "$promotion_status" == "ok" || "$promotion_status" == "pass" ) ]]; then
    promotion_stage_status="pass"
  else
    promotion_stage_status="fail"
  fi
fi

first_cycle_error=""
if ((${#cycle_stage_errors[@]} > 0)); then
  first_cycle_error="${cycle_stage_errors[0]}"
fi
first_promotion_error="$(jq -r '
  if (. | type) == "array" and (. | length) > 0 then
    if (.[0].message | type) == "string" then .[0].message
    elif (.[0] | type) == "string" then .[0]
    else ""
    end
  else
    ""
  end
' <<<"$promotion_violations_json" 2>/dev/null || printf '%s' "")"
if [[ -z "$first_promotion_error" ]]; then
  first_promotion_error="$(jq -r '
    if (. | type) == "array" and (. | length) > 0 and (.[0] | type) == "string" then .[0] else "" end
  ' <<<"$promotion_errors_json" 2>/dev/null || printf '%s' "")"
fi

decision="$promotion_decision"
status="fail"
final_rc=1
failure_stage=""
failure_reason=""

if [[ "$promotion_stage_rc" -ne 0 ]]; then
  decision="NO-GO"
  status="fail"
  final_rc="$promotion_stage_rc"
  if [[ "$final_rc" -eq 0 ]]; then
    final_rc=1
  fi
  failure_stage="promotion_check"
  if [[ -n "$first_promotion_error" ]]; then
    failure_reason="$first_promotion_error"
  else
    failure_reason="runtime_actuation_promotion_check failed (rc=$promotion_stage_rc)"
  fi
elif [[ "$promotion_summary_valid" != "true" ]]; then
  decision="NO-GO"
  status="fail"
  final_rc=1
  failure_stage="promotion_check"
  failure_reason="runtime actuation promotion summary is missing or invalid JSON"
elif [[ "$promotion_summary_fresh" != "true" ]]; then
  decision="NO-GO"
  status="fail"
  final_rc=1
  failure_stage="promotion_check"
  failure_reason="runtime actuation promotion summary is stale (not refreshed by current run)"
elif [[ "$promotion_has_usable_decision" != "true" ]]; then
  decision="NO-GO"
  status="fail"
  final_rc=1
  failure_stage="promotion_check"
  failure_reason="runtime actuation promotion summary is missing a usable decision"
elif [[ "$promotion_stage_rc" -eq 0 && "$promotion_rc_json" != "0" ]]; then
  decision="NO-GO"
  status="fail"
  final_rc=1
  failure_stage="promotion_check"
  failure_reason="runtime actuation promotion summary rc does not match command rc"
elif (( cycles_failed > 0 )); then
  decision="NO-GO"
  status="fail"
  final_rc=1
  failure_stage="cycles"
  if [[ -n "$first_cycle_error" ]]; then
    failure_reason="$first_cycle_error"
  else
    failure_reason="one or more signoff cycles failed to produce valid summaries"
  fi
elif [[ "$promotion_decision" == "GO" && ( "$promotion_status" == "ok" || "$promotion_status" == "pass" ) && "$promotion_rc_json" == "0" && "$promotion_stage_status" == "pass" ]]; then
  status="pass"
  final_rc=0
elif [[ "$promotion_decision" == "GO" ]]; then
  decision="NO-GO"
  status="fail"
  final_rc=1
  failure_stage="promotion_check"
  failure_reason="runtime actuation promotion GO decision failed contract validation"
elif [[ "$promotion_decision" == "NO-GO" ]]; then
  if [[ "$fail_on_no_go" == "1" ]]; then
    status="fail"
    final_rc=1
    failure_stage="promotion_check"
    if [[ -n "$first_promotion_error" ]]; then
      failure_reason="$first_promotion_error"
    else
      failure_reason="runtime actuation promotion decision is NO-GO"
    fi
  else
    status="warn"
    final_rc=0
  fi
else
  decision="NO-GO"
  status="fail"
  final_rc=1
  failure_stage="promotion_check"
  failure_reason="runtime actuation promotion decision is unrecognized"
fi

if [[ "$decision" != "GO" && -z "$promotion_next_operator_action" ]]; then
  if [[ -n "$failure_reason" ]]; then
    promotion_next_operator_action="$failure_reason"
  else
    promotion_next_operator_action="address runtime-actuation promotion blockers and rerun runtime_actuation_promotion_cycle"
  fi
fi

signoff_passthrough_args_json="$(array_to_json "${signoff_passthrough_args[@]}")"
signoff_summary_paths_json="$(array_to_json "${signoff_summary_paths[@]}")"
signoff_logs_json="$(array_to_json "${signoff_logs[@]}")"
cycle_stage_errors_json="$(array_to_json "${cycle_stage_errors[@]}")"

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg decision "$decision" \
  --arg failure_stage "$failure_stage" \
  --arg failure_reason "$failure_reason" \
  --arg reports_dir "$reports_dir" \
  --arg signoff_script "$SIGNOFF_SCRIPT" \
  --arg promotion_check_script "$PROMOTION_CHECK_SCRIPT" \
  --arg signoff_summary_list "$signoff_summary_list" \
  --arg latest_cycle_summary_alias "$latest_cycle_summary_alias" \
  --arg latest_promotion_summary_alias "$latest_promotion_summary_alias" \
  --arg latest_signoff_summary_list_alias "$latest_signoff_summary_list_alias" \
  --arg summary_json_path "$summary_json" \
  --arg promotion_summary_json "$promotion_summary_json" \
  --arg promotion_log "$promotion_log" \
  --arg promotion_command "$promotion_command_display" \
  --arg promotion_stage_status "$promotion_stage_status" \
  --arg promotion_summary_exists "$promotion_summary_exists" \
  --arg promotion_summary_valid "$promotion_summary_valid" \
  --arg promotion_summary_fresh "$promotion_summary_fresh" \
  --arg promotion_decision "$promotion_decision" \
  --arg promotion_status "$promotion_status" \
  --arg promotion_notes "$promotion_notes" \
  --arg promotion_outcome_action "$promotion_outcome_action" \
  --arg promotion_next_operator_action "$promotion_next_operator_action" \
  --arg promotion_has_usable_decision "$promotion_has_usable_decision" \
  --argjson rc "$final_rc" \
  --argjson cycles_requested "$cycles" \
  --argjson cycles_completed "$cycles_completed" \
  --argjson cycles_passed "$cycles_passed" \
  --argjson cycles_failed "$cycles_failed" \
  --argjson fail_on_no_go "$fail_on_no_go" \
  --argjson promotion_stage_rc "$promotion_stage_rc" \
  --argjson promotion_rc "$promotion_rc_json" \
  --argjson show_json "$show_json" \
  --argjson print_summary_json "$print_summary_json" \
  --arg campaign_subject_resolution_mode "$campaign_subject_resolution_mode" \
  --arg campaign_subject_resolution_source "$resolved_campaign_subject_source" \
  --arg signoff_has_subject_credential "$signoff_has_subject_credential" \
  --arg signoff_has_anon_credential "$signoff_has_anon_credential" \
  --argjson signoff_passthrough_args "$signoff_passthrough_args_json" \
  --argjson signoff_summary_paths "$signoff_summary_paths_json" \
  --argjson signoff_logs "$signoff_logs_json" \
  --argjson cycle_stage_errors "$cycle_stage_errors_json" \
  --argjson cycles_entries "$cycles_entries_json" \
  --argjson promotion_violations "$promotion_violations_json" \
  --argjson promotion_errors "$promotion_errors_json" \
  '{
    version: 1,
    schema: {
      id: "runtime_actuation_promotion_cycle_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: (if $decision == "" then null else $decision end),
    failure_stage: (if $failure_stage == "" then null else $failure_stage end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    inputs: {
      reports_dir: $reports_dir,
      cycles: $cycles_requested,
      fail_on_no_go: ($fail_on_no_go == 1),
      stage_scripts: {
        campaign_signoff_script: $signoff_script,
        runtime_actuation_promotion_check_script: $promotion_check_script
      },
      credential_resolution: {
        campaign_subject_mode: $campaign_subject_resolution_mode,
        campaign_subject_source: (if $campaign_subject_resolution_source == "" then null else $campaign_subject_resolution_source end),
        signoff_has_subject_credential: ($signoff_has_subject_credential == "true"),
        signoff_has_anon_credential: ($signoff_has_anon_credential == "true")
      },
      signoff_passthrough_args: $signoff_passthrough_args,
      show_json: ($show_json == 1),
      print_summary_json: ($print_summary_json == 1)
    },
    stages: {
      cycles: {
        attempted: true,
        requested: $cycles_requested,
        completed: $cycles_completed,
        passed: $cycles_passed,
        failed: $cycles_failed,
        all_passed: ($cycles_failed == 0),
        errors: $cycle_stage_errors,
        signoff_summary_list: $signoff_summary_list
      },
      promotion_check: {
        attempted: true,
        status: $promotion_stage_status,
        rc: $promotion_stage_rc,
        command: $promotion_command,
        log: $promotion_log,
        summary_json: $promotion_summary_json,
        summary_exists: ($promotion_summary_exists == "true"),
        summary_valid_json: ($promotion_summary_valid == "true"),
        summary_fresh: ($promotion_summary_fresh == "true"),
        has_usable_decision: ($promotion_has_usable_decision == "true")
      }
    },
    cycles: $cycles_entries,
    promotion_check: {
      decision: (if $promotion_decision == "" then null else $promotion_decision end),
      status: (if $promotion_status == "" then null else $promotion_status end),
      rc: $promotion_rc,
      notes: (if $promotion_notes == "" then null else $promotion_notes end),
      outcome_action: (if $promotion_outcome_action == "" then null else $promotion_outcome_action end),
      next_operator_action: (if $promotion_next_operator_action == "" then null else $promotion_next_operator_action end),
      violations: $promotion_violations,
      errors: $promotion_errors
    },
    enforcement: {
      fail_on_no_go: ($fail_on_no_go == 1),
      cycle_failures_present: ($cycles_failed > 0),
      promotion_no_go_detected: ($decision == "NO-GO"),
      promotion_no_go_enforced: ($decision == "NO-GO" and ($fail_on_no_go == 1))
    },
    outcome: {
      should_promote: ($status == "pass" and $decision == "GO" and $rc == 0),
      action: (
        if $status == "pass" and $decision == "GO" and $rc == 0 then "promote_allowed"
        elif $status == "fail" then "hold_promotion_blocked"
        elif $decision == "NO-GO" then "hold_promotion_warn_only"
        else "investigate_artifacts"
        end
      )
    },
    artifacts: {
      summary_json: $summary_json_path,
      signoff_summary_list: $signoff_summary_list,
      signoff_summary_paths: $signoff_summary_paths,
      signoff_logs: $signoff_logs,
      promotion_summary_json: $promotion_summary_json,
      promotion_log: $promotion_log,
      latest_aliases: {
        cycle_orchestrator_summary_json: $latest_cycle_summary_alias,
        promotion_check_summary_json: $latest_promotion_summary_alias,
        signoff_summary_list: $latest_signoff_summary_list_alias
      }
    }
  }' >"$summary_json"

alias_refresh_failures=0
declare -a alias_refresh_errors=()
attempt_alias_refresh_nonfatal "$summary_json" "$latest_cycle_summary_alias" "cycle orchestrator summary"
attempt_alias_refresh_nonfatal "$promotion_summary_json" "$latest_promotion_summary_alias" "promotion-check summary"
attempt_alias_refresh_nonfatal "$signoff_summary_list" "$latest_signoff_summary_list_alias" "signoff summary-list"
if (( alias_refresh_failures > 0 )); then
  echo "[runtime-actuation-promotion-cycle] warning: latest-alias refresh failures=$alias_refresh_failures (non-fatal, aliases remain fail-closed where refresh failed)"
fi

echo "[runtime-actuation-promotion-cycle] status=$status rc=$final_rc decision=${decision:-unset} summary_json=$summary_json"
if [[ -n "$failure_stage" ]]; then
  echo "[runtime-actuation-promotion-cycle] failure_stage=$failure_stage failure_reason=${failure_reason:-}"
fi
if [[ "$show_json" == "1" ]]; then
  echo "[runtime-actuation-promotion-cycle] summary_json_payload:"
  cat "$summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
