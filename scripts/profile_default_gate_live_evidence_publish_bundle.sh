#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

LIVE_GATE_SCRIPT="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_LIVE_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_run.sh}"
STABILITY_CYCLE_SCRIPT="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_STABILITY_CYCLE_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_cycle.sh}"
EVIDENCE_PACK_SCRIPT="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_EVIDENCE_PACK_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_evidence_pack.sh}"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_default_gate_live_evidence_publish_bundle.sh \
    --host-a HOST \
    --host-b HOST \
    [--campaign-subject INVITE_KEY | --subject INVITE_KEY] \
    [--reports-dir DIR] \
    [--fail-on-no-go [0|1]] \
    [--live-summary-json PATH] \
    [--stability-summary-json PATH] \
    [--stability-check-summary-json PATH] \
    [--stability-cycle-summary-json PATH | --cycle-summary-json PATH] \
    [--evidence-pack-summary-json PATH] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run the M2 live-evidence publish sequence end-to-end:
    1) profile-default live gate refresh/signoff
    2) profile-default stability cycle
    3) profile-default stability evidence-pack publish

Notes:
  - Stage scripts can be overridden with:
      PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_LIVE_SCRIPT
      PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_STABILITY_CYCLE_SCRIPT
      PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_EVIDENCE_PACK_SCRIPT
  - Operator-facing next commands reject unresolved placeholders and never
    include raw invite-subject values.
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
  value="${value//$'\r'/}"
  value="${value//$'\n'/}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

require_value_or_die() {
  local flag="$1"
  local argc="$2"
  if (( argc < 2 )); then
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

normalize_decision() {
  local decision
  decision="$(printf '%s' "${1:-}" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]')"
  case "$decision" in
    GO) printf '%s\n' "GO" ;;
    NO-GO|NOGO|NO_GO) printf '%s\n' "NO-GO" ;;
    *) printf '%s\n' "$decision" ;;
  esac
}

strip_optional_wrapping_quotes_01() {
  local value
  local first_char=""
  local last_char=""
  value="$(trim "${1:-}")"
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

host_placeholder_token_01() {
  local value=""
  value="$(trim "${1:-}")"
  value="$(strip_optional_wrapping_quotes_01 "$value")"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    return 1
  fi
  value="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$value" in
    HOST_A|A_HOST|HOST_B|B_HOST|\
    \$HOST_A|\$\{HOST_A\}|\$A_HOST|\$\{A_HOST\}|\
    \$HOST_B|\$\{HOST_B\}|\$B_HOST|\$\{B_HOST\}|\
    "<HOST_A>"|"<A_HOST>"|"<HOST_B>"|"<B_HOST>"|\
    "{{HOST_A}}"|"{{A_HOST}}"|"{{HOST_B}}"|"{{B_HOST}}"|\
    "%HOST_A%"|"%A_HOST%"|"%HOST_B%"|"%B_HOST%"|\
    YOUR_HOST_A|YOUR_A_HOST|YOUR_HOST_B|YOUR_B_HOST|\
    REPLACE_WITH_HOST_A|REPLACE_WITH_A_HOST|REPLACE_WITH_HOST_B|REPLACE_WITH_B_HOST|\
    \$\{HOST_A:-*}|\$\{HOST_A-*}|\$\{A_HOST:-*}|\$\{A_HOST-*}|\$\{HOST_B:-*}|\$\{HOST_B-*}|\$\{B_HOST:-*}|\$\{B_HOST-*})
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

subject_placeholder_token_01() {
  local value=""
  value="$(trim "${1:-}")"
  value="$(strip_optional_wrapping_quotes_01 "$value")"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    return 1
  fi
  value="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$value" in
    INVITE_KEY|\$\{INVITE_KEY\}|\$INVITE_KEY|"<INVITE_KEY>"|"{{INVITE_KEY}}"|\
    CAMPAIGN_SUBJECT|\$\{CAMPAIGN_SUBJECT\}|\$CAMPAIGN_SUBJECT|"<CAMPAIGN_SUBJECT>"|"{{CAMPAIGN_SUBJECT}}"|\
    YOUR_INVITE_KEY|YOUR_INVITE_SUBJECT|YOUR_CAMPAIGN_SUBJECT|\
    REPLACE_WITH_INVITE_KEY|REPLACE_WITH_INVITE_SUBJECT|REPLACE_WITH_CAMPAIGN_SUBJECT|\
    "<SET-REAL-INVITE-KEY>"|SET-REAL-INVITE-KEY|\
    %INVITE_KEY%|%CAMPAIGN_SUBJECT%|\
    \$\{INVITE_KEY:-*}|\$\{INVITE_KEY-*}|\$\{CAMPAIGN_SUBJECT:-*}|\$\{CAMPAIGN_SUBJECT-*}|\[REDACTED\]|REDACTED)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

render_command_line_from_argv_01() {
  local arg=""
  local rendered=""
  for arg in "$@"; do
    rendered="${rendered}${rendered:+ }$(printf '%q' "$arg")"
  done
  printf '%s' "$rendered"
}

redact_value_in_text_01() {
  local text="$1"
  local secret="$2"
  if [[ -z "$secret" ]]; then
    printf '%s' "$text"
    return
  fi
  printf '%s' "${text//"$secret"/[redacted]}"
}

redact_secret_in_file_01() {
  local file_path="$1"
  local secret="$2"
  local tmp_file=""
  local line=""
  if [[ -z "$file_path" || ! -f "$file_path" || -z "$secret" ]]; then
    return
  fi
  tmp_file="$(mktemp "${file_path}.redact.XXXXXX")"
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//"$secret"/[redacted]}"
    printf '%s\n' "$line" >>"$tmp_file"
  done <"$file_path"
  mv "$tmp_file" "$file_path"
}

json_array_from_lines() {
  local raw_line=""
  local normalized_line=""
  local -a normalized_lines=()
  if [[ $# -eq 0 ]]; then
    printf '[]'
    return
  fi
  for raw_line in "$@"; do
    normalized_line="$(trim "$raw_line")"
    if [[ -n "$normalized_line" ]]; then
      normalized_lines+=("$normalized_line")
    fi
  done
  if [[ "${#normalized_lines[@]}" -eq 0 ]]; then
    printf '[]'
    return
  fi
  printf '%s\n' "${normalized_lines[@]}" | jq -R . | jq -s .
}

build_bundle_rerun_command_without_subject_01() {
  local -a cmd=(
    "./scripts/profile_default_gate_live_evidence_publish_bundle.sh"
    "--host-a" "$host_a"
    "--host-b" "$host_b"
    "--reports-dir" "$reports_dir"
    "--fail-on-no-go" "$fail_on_no_go"
    "--live-summary-json" "$live_summary_json"
    "--stability-summary-json" "$stability_summary_json"
    "--stability-check-summary-json" "$stability_check_summary_json"
    "--stability-cycle-summary-json" "$stability_cycle_summary_json"
    "--evidence-pack-summary-json" "$evidence_pack_summary_json"
    "--summary-json" "$bundle_summary_json"
    "--report-md" "$bundle_report_md"
    "--print-summary-json" "1"
  )
  render_command_line_from_argv_01 "${cmd[@]}"
}

build_live_gate_rerun_command_without_subject_01() {
  local -a cmd=(
    "./scripts/profile_default_gate_run.sh"
    "--host-a" "$host_a"
    "--host-b" "$host_b"
    "--reports-dir" "$reports_dir"
    "--fail-on-no-go" "$fail_on_no_go"
    "--summary-json" "$live_summary_json"
    "--print-summary-json" "1"
  )
  render_command_line_from_argv_01 "${cmd[@]}"
}

build_stability_cycle_rerun_command_without_subject_01() {
  local -a cmd=(
    "./scripts/profile_default_gate_stability_cycle.sh"
    "--host-a" "$host_a"
    "--host-b" "$host_b"
    "--reports-dir" "$reports_dir"
    "--stability-summary-json" "$stability_summary_json"
    "--stability-check-summary-json" "$stability_check_summary_json"
    "--summary-json" "$stability_cycle_summary_json"
    "--fail-on-no-go" "$fail_on_no_go"
    "--print-summary-json" "1"
  )
  render_command_line_from_argv_01 "${cmd[@]}"
}

build_evidence_pack_rerun_command_01() {
  local -a cmd=(
    "./scripts/profile_default_gate_stability_evidence_pack.sh"
    "--reports-dir" "$reports_dir"
    "--stability-summary-json" "$stability_summary_json"
    "--stability-check-summary-json" "$stability_check_summary_json"
    "--cycle-summary-json" "$stability_cycle_summary_json"
    "--summary-json" "$evidence_pack_summary_json"
    "--fail-on-no-go" "$fail_on_no_go"
    "--print-summary-json" "1"
  )
  render_command_line_from_argv_01 "${cmd[@]}"
}

operator_command_placeholder_keys_json_01() {
  local cmd="$1"
  local cmd_upper=""
  local -a keys=()
  cmd_upper="$(printf '%s' "$cmd" | tr '[:lower:]' '[:upper:]')"
  if host_placeholder_token_01 "$host_a" || [[ "$cmd_upper" == *"HOST_A"* || "$cmd_upper" == *"A_HOST"* ]]; then
    keys+=("host_a")
  fi
  if host_placeholder_token_01 "$host_b" || [[ "$cmd_upper" == *"HOST_B"* || "$cmd_upper" == *"B_HOST"* ]]; then
    keys+=("host_b")
  fi
  if [[ "$cmd_upper" == *"INVITE_KEY"* || "$cmd_upper" == *"CAMPAIGN_SUBJECT"* || "$cmd_upper" == *"[REDACTED]"* ]]; then
    keys+=("campaign_subject")
  fi
  json_array_from_lines "${keys[@]:-}"
}

RUN_STAGE_JSON='{}'
RUN_STAGE_EFFECTIVE_RC=0

init_stage_json_01() {
  local stage_id="$1"
  local log_path="$2"
  local stage_summary_json="$3"
  jq -n \
    --arg stage_id "$stage_id" \
    --arg log_path "$log_path" \
    --arg stage_summary_json "$stage_summary_json" \
    '{
      id: $stage_id,
      attempted: false,
      status: "skip",
      command_rc: null,
      rc: 0,
      duration_sec: 0,
      log: $log_path,
      summary_json: $stage_summary_json,
      summary_valid_after_run: false,
      summary_fresh_after_run: false,
      command_redacted: null,
      failure_reason: null
    }'
}

run_stage_01() {
  local stage_id="$1"
  local stage_log="$2"
  local stage_summary_json="$3"
  local secret_for_redaction="$4"
  shift 4
  local -a cmd=( "$@" )
  local command_redacted=""
  local stage_start_epoch=0
  local stage_end_epoch=0
  local stage_duration_sec=0
  local stage_command_rc=0
  local stage_effective_rc=0
  local stage_status="pass"
  local stage_summary_valid="0"
  local stage_summary_pre_fingerprint=""
  local stage_summary_post_fingerprint=""
  local stage_summary_fresh="0"
  local stage_failure_reason=""

  stage_summary_pre_fingerprint="$(file_fingerprint_01 "$stage_summary_json")"
  stage_start_epoch="$(date -u +%s)"
  set +e
  "${cmd[@]}" >"$stage_log" 2>&1
  stage_command_rc=$?
  set -e
  redact_secret_in_file_01 "$stage_log" "$secret_for_redaction"
  stage_end_epoch="$(date -u +%s)"
  stage_duration_sec="$((stage_end_epoch - stage_start_epoch))"
  stage_summary_valid="$(json_file_valid_01 "$stage_summary_json")"
  if [[ "$stage_summary_valid" == "1" ]]; then
    stage_summary_post_fingerprint="$(file_fingerprint_01 "$stage_summary_json")"
    if [[ -z "$stage_summary_pre_fingerprint" && -n "$stage_summary_post_fingerprint" ]]; then
      stage_summary_fresh="1"
    elif [[ -n "$stage_summary_post_fingerprint" && "$stage_summary_post_fingerprint" != "$stage_summary_pre_fingerprint" ]]; then
      stage_summary_fresh="1"
    fi
  fi
  stage_effective_rc="$stage_command_rc"
  command_redacted="$(render_command_line_from_argv_01 "${cmd[@]}")"
  command_redacted="$(redact_value_in_text_01 "$command_redacted" "$secret_for_redaction")"

  if [[ "$stage_command_rc" -ne 0 ]]; then
    stage_status="fail"
    stage_failure_reason="stage command failed (rc=$stage_command_rc)"
  elif [[ "$stage_summary_valid" != "1" ]]; then
    stage_status="fail"
    stage_effective_rc=65
    stage_failure_reason="stage summary missing or invalid JSON: $stage_summary_json"
  elif [[ "$stage_summary_fresh" != "1" ]]; then
    stage_status="fail"
    stage_effective_rc=66
    stage_failure_reason="stage summary is stale/reused from a previous run: $stage_summary_json"
  fi

  RUN_STAGE_JSON="$(jq -n \
    --arg stage_id "$stage_id" \
    --arg stage_status "$stage_status" \
    --arg stage_log "$stage_log" \
    --arg stage_summary_json "$stage_summary_json" \
    --arg stage_summary_valid "$stage_summary_valid" \
    --arg stage_summary_fresh "$stage_summary_fresh" \
    --arg command_redacted "$command_redacted" \
    --arg stage_failure_reason "$stage_failure_reason" \
    --argjson stage_command_rc "$stage_command_rc" \
    --argjson stage_effective_rc "$stage_effective_rc" \
    --argjson stage_duration_sec "$stage_duration_sec" \
    '{
      id: $stage_id,
      attempted: true,
      status: $stage_status,
      command_rc: $stage_command_rc,
      rc: $stage_effective_rc,
      duration_sec: $stage_duration_sec,
      log: $stage_log,
      summary_json: $stage_summary_json,
      summary_valid_after_run: ($stage_summary_valid == "1"),
      summary_fresh_after_run: ($stage_summary_fresh == "1"),
      command_redacted: (if $command_redacted == "" then null else $command_redacted end),
      failure_reason: (if $stage_failure_reason == "" then null else $stage_failure_reason end)
    }')"
  RUN_STAGE_EFFECTIVE_RC="$stage_effective_rc"
}

need_cmd bash
need_cmd jq
need_cmd date
need_cmd mktemp
need_cmd cksum

host_a="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_HOST_A:-}"
host_b="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_HOST_B:-}"
campaign_subject_cli=""
subject_alias_cli=""
reports_dir="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_REPORTS_DIR:-${REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}}"
fail_on_no_go="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_FAIL_ON_NO_GO:-1}"
live_summary_json="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_LIVE_SUMMARY_JSON:-}"
stability_summary_json="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_STABILITY_SUMMARY_JSON:-}"
stability_check_summary_json="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_STABILITY_CHECK_SUMMARY_JSON:-}"
stability_cycle_summary_json="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_STABILITY_CYCLE_SUMMARY_JSON:-}"
evidence_pack_summary_json="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_EVIDENCE_PACK_SUMMARY_JSON:-}"
bundle_summary_json="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_SUMMARY_JSON:-}"
bundle_report_md="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_REPORT_MD:-}"
print_summary_json="${PROFILE_DEFAULT_GATE_LIVE_EVIDENCE_BUNDLE_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host-a)
      require_value_or_die "--host-a" "$#"
      host_a="${2:-}"
      shift 2
      ;;
    --host-a=*)
      host_a="${1#*=}"
      shift
      ;;
    --host-b)
      require_value_or_die "--host-b" "$#"
      host_b="${2:-}"
      shift 2
      ;;
    --host-b=*)
      host_b="${1#*=}"
      shift
      ;;
    --campaign-subject)
      require_value_or_die "--campaign-subject" "$#"
      campaign_subject_cli="${2:-}"
      shift 2
      ;;
    --campaign-subject=*)
      campaign_subject_cli="${1#*=}"
      shift
      ;;
    --subject)
      require_value_or_die "--subject" "$#"
      subject_alias_cli="${2:-}"
      shift 2
      ;;
    --subject=*)
      subject_alias_cli="${1#*=}"
      shift
      ;;
    --reports-dir)
      require_value_or_die "--reports-dir" "$#"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --fail-on-no-go)
      require_value_or_die "--fail-on-no-go" "$#"
      fail_on_no_go="${2:-}"
      shift 2
      ;;
    --fail-on-no-go=*)
      fail_on_no_go="${1#*=}"
      shift
      ;;
    --live-summary-json)
      require_value_or_die "--live-summary-json" "$#"
      live_summary_json="${2:-}"
      shift 2
      ;;
    --live-summary-json=*)
      live_summary_json="${1#*=}"
      shift
      ;;
    --stability-summary-json)
      require_value_or_die "--stability-summary-json" "$#"
      stability_summary_json="${2:-}"
      shift 2
      ;;
    --stability-summary-json=*)
      stability_summary_json="${1#*=}"
      shift
      ;;
    --stability-check-summary-json)
      require_value_or_die "--stability-check-summary-json" "$#"
      stability_check_summary_json="${2:-}"
      shift 2
      ;;
    --stability-check-summary-json=*)
      stability_check_summary_json="${1#*=}"
      shift
      ;;
    --stability-cycle-summary-json|--cycle-summary-json)
      require_value_or_die "$1" "$#"
      stability_cycle_summary_json="${2:-}"
      shift 2
      ;;
    --stability-cycle-summary-json=*|--cycle-summary-json=*)
      stability_cycle_summary_json="${1#*=}"
      shift
      ;;
    --evidence-pack-summary-json)
      require_value_or_die "--evidence-pack-summary-json" "$#"
      evidence_pack_summary_json="${2:-}"
      shift 2
      ;;
    --evidence-pack-summary-json=*)
      evidence_pack_summary_json="${1#*=}"
      shift
      ;;
    --summary-json)
      require_value_or_die "--summary-json" "$#"
      bundle_summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      bundle_summary_json="${1#*=}"
      shift
      ;;
    --report-md)
      require_value_or_die "--report-md" "$#"
      bundle_report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      bundle_report_md="${1#*=}"
      shift
      ;;
    --print-summary-json)
      if [[ "${2:-}" == "0" || "${2:-}" == "1" ]]; then
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

host_a="$(trim "$host_a")"
host_b="$(trim "$host_b")"
campaign_subject_cli="$(trim "$campaign_subject_cli")"
subject_alias_cli="$(trim "$subject_alias_cli")"
reports_dir="$(abs_path "$reports_dir")"
fail_on_no_go="$(trim "$fail_on_no_go")"
live_summary_json="$(trim "$live_summary_json")"
stability_summary_json="$(trim "$stability_summary_json")"
stability_check_summary_json="$(trim "$stability_check_summary_json")"
stability_cycle_summary_json="$(trim "$stability_cycle_summary_json")"
evidence_pack_summary_json="$(trim "$evidence_pack_summary_json")"
bundle_summary_json="$(trim "$bundle_summary_json")"
bundle_report_md="$(trim "$bundle_report_md")"
print_summary_json="$(trim "$print_summary_json")"

bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

if [[ -n "$campaign_subject_cli" && -n "$subject_alias_cli" && "$campaign_subject_cli" != "$subject_alias_cli" ]]; then
  echo "conflicting subject values: --campaign-subject and --subject must match when both are provided"
  exit 2
fi
campaign_subject_effective="$campaign_subject_cli"
subject_source="explicit:--campaign-subject"
if [[ -z "$campaign_subject_effective" && -n "$subject_alias_cli" ]]; then
  campaign_subject_effective="$subject_alias_cli"
  subject_source="explicit:--subject"
fi

if [[ -z "$live_summary_json" ]]; then
  live_summary_json="$reports_dir/profile_compare_campaign_signoff_summary.json"
fi
if [[ -z "$stability_summary_json" ]]; then
  stability_summary_json="$reports_dir/profile_default_gate_stability_summary.json"
fi
if [[ -z "$stability_check_summary_json" ]]; then
  stability_check_summary_json="$reports_dir/profile_default_gate_stability_check_summary.json"
fi
if [[ -z "$stability_cycle_summary_json" ]]; then
  stability_cycle_summary_json="$reports_dir/profile_default_gate_stability_cycle_summary.json"
fi
if [[ -z "$evidence_pack_summary_json" ]]; then
  evidence_pack_summary_json="$reports_dir/profile_default_gate_stability_evidence_pack_summary.json"
fi
if [[ -z "$bundle_summary_json" ]]; then
  bundle_summary_json="$reports_dir/profile_default_gate_live_evidence_publish_bundle_summary.json"
fi
if [[ -z "$bundle_report_md" ]]; then
  bundle_report_md="$reports_dir/profile_default_gate_live_evidence_publish_bundle_report.md"
fi

live_summary_json="$(abs_path "$live_summary_json")"
stability_summary_json="$(abs_path "$stability_summary_json")"
stability_check_summary_json="$(abs_path "$stability_check_summary_json")"
stability_cycle_summary_json="$(abs_path "$stability_cycle_summary_json")"
evidence_pack_summary_json="$(abs_path "$evidence_pack_summary_json")"
bundle_summary_json="$(abs_path "$bundle_summary_json")"
bundle_report_md="$(abs_path "$bundle_report_md")"

mkdir -p "$reports_dir"
mkdir -p "$(dirname "$bundle_summary_json")" "$(dirname "$bundle_report_md")"

run_id="$(date -u +%Y%m%d_%H%M%S)"
live_log="$reports_dir/profile_default_gate_live_evidence_publish_bundle_${run_id}_live_gate.log"
stability_log="$reports_dir/profile_default_gate_live_evidence_publish_bundle_${run_id}_stability_cycle.log"
publish_log="$reports_dir/profile_default_gate_live_evidence_publish_bundle_${run_id}_evidence_pack.log"

live_stage_json="$(init_stage_json_01 "live_gate" "$live_log" "$live_summary_json")"
stability_stage_json="$(init_stage_json_01 "stability_cycle" "$stability_log" "$stability_cycle_summary_json")"
publish_stage_json="$(init_stage_json_01 "evidence_pack_publish" "$publish_log" "$evidence_pack_summary_json")"

bundle_status="fail"
final_rc=1
failure_stage=""
failure_substep=""
failure_reason=""
next_command=""
next_command_reason=""
next_command_has_unresolved_placeholders="false"
next_command_unresolved_placeholder_keys_json='[]'
decision="NO-GO"

declare -a preflight_errors=()
if [[ ! -f "$LIVE_GATE_SCRIPT" || ! -r "$LIVE_GATE_SCRIPT" ]]; then
  preflight_errors+=("live gate script is missing or unreadable: $LIVE_GATE_SCRIPT")
fi
if [[ ! -f "$STABILITY_CYCLE_SCRIPT" || ! -r "$STABILITY_CYCLE_SCRIPT" ]]; then
  preflight_errors+=("stability cycle script is missing or unreadable: $STABILITY_CYCLE_SCRIPT")
fi
if [[ ! -f "$EVIDENCE_PACK_SCRIPT" || ! -r "$EVIDENCE_PACK_SCRIPT" ]]; then
  preflight_errors+=("evidence pack script is missing or unreadable: $EVIDENCE_PACK_SCRIPT")
fi
if [[ -z "$host_a" ]]; then
  preflight_errors+=("--host-a is required")
elif host_placeholder_token_01 "$host_a"; then
  preflight_errors+=("--host-a uses placeholder token; pass a concrete host")
fi
if [[ -z "$host_b" ]]; then
  preflight_errors+=("--host-b is required")
elif host_placeholder_token_01 "$host_b"; then
  preflight_errors+=("--host-b uses placeholder token; pass a concrete host")
fi
if [[ -z "$campaign_subject_effective" ]]; then
  preflight_errors+=("--campaign-subject/--subject is required")
elif subject_placeholder_token_01 "$campaign_subject_effective"; then
  preflight_errors+=("--campaign-subject/--subject uses placeholder token; pass a concrete invite subject")
fi

preflight_errors_json="$(json_array_from_lines "${preflight_errors[@]:-}")"
if [[ "$(jq -r 'length' <<<"$preflight_errors_json")" -gt 0 ]]; then
  failure_stage="preflight"
  failure_substep="preflight_validation_failed"
  final_rc=2
  failure_reason="$(jq -r '.[0]' <<<"$preflight_errors_json")"
  next_command="$(build_bundle_rerun_command_without_subject_01)"
  next_command_reason="$failure_reason; rerun bundle with concrete hosts and a real --campaign-subject/--subject value"
else
  live_cmd=(
    bash "$LIVE_GATE_SCRIPT"
    --host-a "$host_a"
    --host-b "$host_b"
    --campaign-subject "$campaign_subject_effective"
    --reports-dir "$reports_dir"
    --fail-on-no-go "$fail_on_no_go"
    --summary-json "$live_summary_json"
    --print-summary-json 0
  )
  run_stage_01 "live_gate" "$live_log" "$live_summary_json" "$campaign_subject_effective" "${live_cmd[@]}"
  live_stage_json="$RUN_STAGE_JSON"
  live_stage_rc="$RUN_STAGE_EFFECTIVE_RC"

  if [[ "$live_stage_rc" -ne 0 ]]; then
    failure_stage="live_gate"
    failure_substep="live_gate_stage_failed"
    final_rc="$live_stage_rc"
    failure_reason="$(jq -r '.failure_reason // "live gate stage failed"' <<<"$live_stage_json")"
    next_command="$(build_live_gate_rerun_command_without_subject_01)"
    next_command_reason="live gate stage failed; inspect live_gate log and rerun with a real --campaign-subject/--subject value"
  else
    stability_cmd=(
      bash "$STABILITY_CYCLE_SCRIPT"
      --host-a "$host_a"
      --host-b "$host_b"
      --campaign-subject "$campaign_subject_effective"
      --reports-dir "$reports_dir"
      --stability-summary-json "$stability_summary_json"
      --stability-check-summary-json "$stability_check_summary_json"
      --summary-json "$stability_cycle_summary_json"
      --fail-on-no-go "$fail_on_no_go"
      --print-summary-json 0
    )
    run_stage_01 "stability_cycle" "$stability_log" "$stability_cycle_summary_json" "$campaign_subject_effective" "${stability_cmd[@]}"
    stability_stage_json="$RUN_STAGE_JSON"
    stability_stage_rc="$RUN_STAGE_EFFECTIVE_RC"

    if [[ "$stability_stage_rc" -ne 0 ]]; then
      failure_stage="stability_cycle"
      failure_substep="stability_cycle_stage_failed"
      final_rc="$stability_stage_rc"
      failure_reason="$(jq -r '.failure_reason // "stability cycle stage failed"' <<<"$stability_stage_json")"
      next_command="$(build_stability_cycle_rerun_command_without_subject_01)"
      next_command_reason="stability cycle stage failed; inspect stability_cycle log and rerun with a real --campaign-subject/--subject value"
    else
      publish_cmd=(
        bash "$EVIDENCE_PACK_SCRIPT"
        --reports-dir "$reports_dir"
        --stability-summary-json "$stability_summary_json"
        --stability-check-summary-json "$stability_check_summary_json"
        --cycle-summary-json "$stability_cycle_summary_json"
        --summary-json "$evidence_pack_summary_json"
        --fail-on-no-go "$fail_on_no_go"
        --print-summary-json 0
      )
      run_stage_01 "evidence_pack_publish" "$publish_log" "$evidence_pack_summary_json" "$campaign_subject_effective" "${publish_cmd[@]}"
      publish_stage_json="$RUN_STAGE_JSON"
      publish_stage_rc="$RUN_STAGE_EFFECTIVE_RC"

      if [[ "$publish_stage_rc" -ne 0 ]]; then
        failure_stage="evidence_pack_publish"
        failure_substep="evidence_pack_publish_stage_failed"
        final_rc="$publish_stage_rc"
        failure_reason="$(jq -r '.failure_reason // "evidence pack publish stage failed"' <<<"$publish_stage_json")"
        next_command="$(build_evidence_pack_rerun_command_01)"
        next_command_reason="evidence-pack publish stage failed; inspect evidence_pack_publish log and rerun publish stage"
      else
        final_rc=0
        publish_status_norm="$(jq -r '.status // ""' "$evidence_pack_summary_json" 2>/dev/null || printf '%s' "")"
        decision="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$evidence_pack_summary_json" 2>/dev/null || printf '%s' "")"
        decision="$(normalize_decision "$decision")"
        if [[ "$decision" == "GO" ]] && [[ "$publish_status_norm" == "ok" || "$publish_status_norm" == "pass" ]]; then
          bundle_status="ok"
        else
          bundle_status="warn"
        fi
      fi
    fi
  fi
fi

if [[ "$final_rc" -ne 0 ]]; then
  bundle_status="fail"
  decision="NO-GO"
  if [[ -z "$failure_substep" ]]; then
    failure_substep="bundle_failed"
  fi
fi

if [[ -n "$next_command" ]]; then
  next_command_unresolved_placeholder_keys_json="$(operator_command_placeholder_keys_json_01 "$next_command")"
  if [[ "$(jq -r 'length' <<<"$next_command_unresolved_placeholder_keys_json")" -gt 0 ]]; then
    next_command_has_unresolved_placeholders="true"
    next_command=""
    placeholder_keys_csv="$(jq -r 'join(",")' <<<"$next_command_unresolved_placeholder_keys_json")"
    if [[ -n "$next_command_reason" ]]; then
      next_command_reason="${next_command_reason}; operator next command omitted because unresolved placeholders were detected (${placeholder_keys_csv})"
    else
      next_command_reason="operator next command omitted because unresolved placeholders were detected (${placeholder_keys_csv})"
    fi
  fi
fi

summary_payload="$(jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$bundle_status" \
  --arg decision "$decision" \
  --arg failure_stage "$failure_stage" \
  --arg failure_substep "$failure_substep" \
  --arg failure_reason "$failure_reason" \
  --arg host_a "$host_a" \
  --arg host_b "$host_b" \
  --arg subject_source "$subject_source" \
  --arg reports_dir "$reports_dir" \
  --arg fail_on_no_go "$fail_on_no_go" \
  --arg next_command "$next_command" \
  --arg next_command_reason "$next_command_reason" \
  --arg next_command_has_unresolved_placeholders "$next_command_has_unresolved_placeholders" \
  --arg live_summary_json "$live_summary_json" \
  --arg stability_summary_json "$stability_summary_json" \
  --arg stability_check_summary_json "$stability_check_summary_json" \
  --arg stability_cycle_summary_json "$stability_cycle_summary_json" \
  --arg evidence_pack_summary_json "$evidence_pack_summary_json" \
  --arg bundle_summary_json "$bundle_summary_json" \
  --arg bundle_report_md "$bundle_report_md" \
  --argjson rc "$final_rc" \
  --argjson preflight_errors "$preflight_errors_json" \
  --argjson live_stage "$live_stage_json" \
  --argjson stability_stage "$stability_stage_json" \
  --argjson publish_stage "$publish_stage_json" \
  --argjson next_command_unresolved_placeholder_keys "$next_command_unresolved_placeholder_keys_json" \
  '{
    version: 1,
    schema: {
      id: "profile_default_gate_live_evidence_publish_bundle_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: $decision,
    failure_stage: (if $failure_stage == "" then null else $failure_stage end),
    failure_substep: (if $failure_substep == "" then null else $failure_substep end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    inputs: {
      host_a: $host_a,
      host_b: $host_b,
      subject_source: (if $subject_source == "" then null else $subject_source end),
      subject_configured: (($subject_source // "") != ""),
      reports_dir: $reports_dir,
      fail_on_no_go: ($fail_on_no_go == "1")
    },
    preflight: {
      ok: (($preflight_errors | length) == 0),
      errors: $preflight_errors
    },
    stages: {
      live_gate: $live_stage,
      stability_cycle: $stability_stage,
      evidence_pack_publish: $publish_stage
    },
    next_action: {
      command: (if $next_command == "" then null else $next_command end),
      reason: (if $next_command_reason == "" then null else $next_command_reason end),
      command_has_unresolved_placeholders: ($next_command_has_unresolved_placeholders == "true"),
      command_unresolved_placeholder_keys: $next_command_unresolved_placeholder_keys
    },
    artifacts: {
      live_summary_json: $live_summary_json,
      stability_summary_json: $stability_summary_json,
      stability_check_summary_json: $stability_check_summary_json,
      stability_cycle_summary_json: $stability_cycle_summary_json,
      evidence_pack_summary_json: $evidence_pack_summary_json,
      summary_json: $bundle_summary_json,
      report_md: $bundle_report_md
    }
  }')"

printf '%s\n' "$summary_payload" >"$bundle_summary_json"

{
  echo "# Profile Default Gate Live Evidence Publish Bundle"
  echo
  echo "- Generated at (UTC): $(jq -r '.generated_at_utc' <<<"$summary_payload")"
  echo "- Status: $(jq -r '.status' <<<"$summary_payload")"
  echo "- RC: $(jq -r '.rc' <<<"$summary_payload")"
  echo "- Decision: $(jq -r '.decision' <<<"$summary_payload")"
  echo "- Failure stage: $(jq -r '.failure_stage // "none"' <<<"$summary_payload")"
  echo "- Failure substep: $(jq -r '.failure_substep // "none"' <<<"$summary_payload")"
  echo "- Failure reason: $(jq -r '.failure_reason // "none"' <<<"$summary_payload")"
  echo
  echo "## Stages"
  echo
  for stage_id in live_gate stability_cycle evidence_pack_publish; do
    echo "- ${stage_id}: status=$(jq -r ".stages.${stage_id}.status" <<<"$summary_payload"), rc=$(jq -r ".stages.${stage_id}.rc" <<<"$summary_payload"), duration_sec=$(jq -r ".stages.${stage_id}.duration_sec" <<<"$summary_payload"), log=$(jq -r ".stages.${stage_id}.log" <<<"$summary_payload")"
  done
  echo
  echo "## Next Action"
  echo
  echo "- Reason: $(jq -r '.next_action.reason // "none"' <<<"$summary_payload")"
  echo "- Command unresolved placeholders: $(jq -r '.next_action.command_has_unresolved_placeholders' <<<"$summary_payload")"
  echo "- Command unresolved placeholder keys: $(jq -r '.next_action.command_unresolved_placeholder_keys | if length == 0 then "none" else join(",") end' <<<"$summary_payload")"
  echo "- Command: $(jq -r '.next_action.command // "none"' <<<"$summary_payload")"
} >"$bundle_report_md"

echo "[profile-default-gate-live-evidence-publish-bundle] status=$bundle_status rc=$final_rc summary_json=$bundle_summary_json"
echo "[profile-default-gate-live-evidence-publish-bundle] report_md=$bundle_report_md"

if [[ "$print_summary_json" == "1" ]]; then
  echo "[profile-default-gate-live-evidence-publish-bundle] summary_json_payload:"
  cat "$bundle_summary_json"
fi

exit "$final_rc"
