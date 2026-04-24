#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_next_actions_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--roadmap-summary-json PATH] \
    [--roadmap-report-md PATH] \
    [--host-a HOST] \
    [--host-b HOST] \
    [--campaign-subject ID] \
    [--vm-command-source PATH] \
    [--action-timeout-sec N] \
    [--allow-unsafe-shell-commands [0|1]] \
    [--refresh-manual-validation [0|1]] \
    [--refresh-single-machine-readiness [0|1]] \
    [--parallel [0|1]] \
    [--max-actions N] \
    [--profile-default-gate-subject ID] \
    [--allow-profile-default-gate-unreachable [0|1]] \
    [--include-id ID] \
    [--exclude-id ID] \
    [--include-id-prefix PREFIX] \
    [--exclude-id-prefix PREFIX] \
    [--include-id-suffix SUFFIX] \
    [--exclude-id-suffix SUFFIX] \
    [--print-summary-json [0|1]]

Purpose:
  Resolve roadmap next_actions from roadmap_progress_report summary JSON,
  apply optional id-prefix/id/id-suffix filters, and execute selected commands in one
  deterministic wrapper run.

Defaults:
  --action-timeout-sec 0   (0 = no per-action timeout)
  --allow-unsafe-shell-commands 0
  --host-a ""   (precedence: CLI --host-a > ROADMAP_NEXT_ACTIONS_RUN_HOST_A > A_HOST > HOST_A > summary command values)
  --host-b ""   (precedence: CLI --host-b > ROADMAP_NEXT_ACTIONS_RUN_HOST_B > B_HOST > HOST_B > summary command values)
  --campaign-subject ""   (precedence: CLI --campaign-subject > --profile-default-gate-subject > ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_SUBJECT > ROADMAP_NEXT_ACTIONS_RUN_CAMPAIGN_SUBJECT > CAMPAIGN_SUBJECT > INVITE_KEY > summary command values)
  --vm-command-source ""   (precedence: CLI --vm-command-source > ROADMAP_NEXT_ACTIONS_RUN_VM_COMMAND_SOURCE > VM_COMMAND_SOURCE > summary command values)
  profile_default_gate default timeout sec: 2400
    (env ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC)
  --refresh-manual-validation 0
  --refresh-single-machine-readiness 0
  --parallel 0
  --max-actions 0   (0 = no limit)
  --profile-default-gate-subject ""   (disabled)
  --allow-profile-default-gate-unreachable 0
  --include-id ""   (disabled; repeatable)
  --exclude-id ""   (disabled; repeatable)
  --include-id-prefix ""   (disabled)
  --exclude-id-prefix ""   (disabled)
  --include-id-suffix ""   (disabled; repeatable)
  --exclude-id-suffix ""   (disabled; repeatable)
  ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_IDS ""   (optional comma-separated ids)
  ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_IDS ""   (optional comma-separated ids)
  ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_ID_SUFFIXES ""   (optional comma-separated suffixes)
  ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_ID_SUFFIXES ""   (optional comma-separated suffixes)
  --print-summary-json 1

Exit behavior:
  - Runs all selected commands (sequential by default, concurrent when --parallel=1).
  - Returns rc=0 only when all selected commands pass (or no actions selected).
  - Returns first failing action command rc otherwise.
  - Runtime inputs use deterministic precedence: CLI flags > env values > summary command values.
  - Fails closed (rc=3) when selected actions contain duplicate ids with
    conflicting commands after dedupe/filtering, to avoid stale ambiguous runs.
  - With --profile-default-gate-subject, profile_default_gate actions append
    --campaign-subject when no subject/anon override flag is already present.
  - profile_default_gate* placeholder subject tokens in commands
    (INVITE_KEY/CAMPAIGN_SUBJECT forms) are normalized using first available:
    --profile-default-gate-subject, CAMPAIGN_SUBJECT, INVITE_KEY.
  - profile_default_gate* placeholder subject tokens fail closed (rc=2) when no
    real subject value is available from the configured override/env fallback.
  - With global --action-timeout-sec=0, profile_default_gate gets a default
    per-action timeout from ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC.
  - With --allow-profile-default-gate-unreachable=1, profile_default_gate can
    soft-fail on unreachable endpoint logs or missing invite-subject precondition logs.
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

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "$flag requires a value"
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

json_array_from_args() {
  if [[ $# -eq 0 ]]; then
    printf '%s' "[]"
  else
    jq -cn '$ARGS.positional' --args "$@"
  fi
}

append_csv_values_to_id_filters() {
  local csv="${1:-}"
  local filter_kind="${2:-}"
  local raw=""
  local value=""
  local IFS=','
  local -a values=()
  read -r -a values <<<"$csv"
  for raw in "${values[@]}"; do
    value="$(trim "$raw")"
    [[ -n "$value" ]] || continue
    if [[ "$filter_kind" == "include" ]]; then
      include_ids+=("$value")
    elif [[ "$filter_kind" == "exclude" ]]; then
      exclude_ids+=("$value")
    fi
  done
}

append_csv_values_to_suffix_filters() {
  local csv="${1:-}"
  local filter_kind="${2:-}"
  local raw=""
  local value=""
  local IFS=','
  local -a values=()
  read -r -a values <<<"$csv"
  for raw in "${values[@]}"; do
    value="$(trim "$raw")"
    [[ -n "$value" ]] || continue
    if [[ "$filter_kind" == "include" ]]; then
      include_id_suffixes+=("$value")
    elif [[ "$filter_kind" == "exclude" ]]; then
      exclude_id_suffixes+=("$value")
    fi
  done
}

sanitize_id() {
  local value
  value="$(trim "${1:-}")"
  value="${value//[^a-zA-Z0-9._-]/_}"
  if [[ -z "$value" ]]; then
    value="action"
  fi
  printf '%s' "$value"
}

is_sensitive_secret_flag() {
  case "${1:-}" in
    --campaign-subject|--subject|--key|--invite-key|--campaign-anon-cred|--anon-cred|--token|--auth-token|--admin-token|--authorization|--bearer)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

render_log_token() {
  local token="${1:-}"
  if [[ "$token" == *[[:space:]]* ]]; then
    token="${token//\'/\'\"\'\"\'}"
    printf "'%s'" "$token"
  else
    printf '%s' "$token"
  fi
}

render_command_line_from_argv() {
  local arg=""
  local rendered=""
  for arg in "$@"; do
    rendered="${rendered}${rendered:+ }$(render_log_token "$arg")"
  done
  printf '%s' "$rendered"
}

build_profile_default_gate_subject_operator_command() {
  local -a cmd=("./scripts/roadmap_next_actions_run.sh")
  local filter_value=""

  if [[ -n "${reports_dir:-}" ]]; then
    cmd+=(--reports-dir "$reports_dir")
  fi
  if [[ -n "${summary_json:-}" ]]; then
    cmd+=(--summary-json "$summary_json")
  fi
  if [[ -n "${roadmap_summary_json:-}" ]]; then
    cmd+=(--roadmap-summary-json "$roadmap_summary_json")
  fi
  if [[ -n "${roadmap_report_md:-}" ]]; then
    cmd+=(--roadmap-report-md "$roadmap_report_md")
  fi
  if [[ "${refresh_manual_validation:-0}" == "1" ]]; then
    cmd+=(--refresh-manual-validation 1)
  fi
  if [[ "${refresh_single_machine_readiness:-0}" == "1" ]]; then
    cmd+=(--refresh-single-machine-readiness 1)
  fi
  if [[ "${parallel:-0}" == "1" ]]; then
    cmd+=(--parallel 1)
  fi
  if [[ "${max_actions:-0}" != "0" ]]; then
    cmd+=(--max-actions "$max_actions")
  fi
  if [[ "${action_timeout_sec:-0}" != "0" ]]; then
    cmd+=(--action-timeout-sec "$action_timeout_sec")
  fi
  if [[ "${allow_unsafe_shell_commands:-0}" == "1" ]]; then
    cmd+=(--allow-unsafe-shell-commands 1)
  fi
  if [[ "${allow_profile_default_gate_unreachable:-0}" == "1" ]]; then
    cmd+=(--allow-profile-default-gate-unreachable 1)
  fi
  if [[ -n "${runtime_host_a:-}" ]]; then
    cmd+=(--host-a "$runtime_host_a")
  fi
  if [[ -n "${runtime_host_b:-}" ]]; then
    cmd+=(--host-b "$runtime_host_b")
  fi
  if [[ -n "${runtime_vm_command_source:-}" ]]; then
    cmd+=(--vm-command-source "$runtime_vm_command_source")
  fi
  if [[ -n "${include_id_prefix:-}" ]]; then
    cmd+=(--include-id-prefix "$include_id_prefix")
  fi
  if [[ -n "${exclude_id_prefix:-}" ]]; then
    cmd+=(--exclude-id-prefix "$exclude_id_prefix")
  fi
  for filter_value in "${include_ids[@]:-}"; do
    if [[ -n "$filter_value" ]]; then
      cmd+=(--include-id "$filter_value")
    fi
  done
  for filter_value in "${exclude_ids[@]:-}"; do
    if [[ -n "$filter_value" ]]; then
      cmd+=(--exclude-id "$filter_value")
    fi
  done
  for filter_value in "${include_id_suffixes[@]:-}"; do
    if [[ -n "$filter_value" ]]; then
      cmd+=(--include-id-suffix "$filter_value")
    fi
  done
  for filter_value in "${exclude_id_suffixes[@]:-}"; do
    if [[ -n "$filter_value" ]]; then
      cmd+=(--exclude-id-suffix "$filter_value")
    fi
  done
  cmd+=(--print-summary-json "${print_summary_json:-1}")
  cmd+=(--campaign-subject "REPLACE_WITH_INVITE_SUBJECT")
  cmd+=(--profile-default-gate-subject "REPLACE_WITH_INVITE_SUBJECT")

  render_command_line_from_argv "${cmd[@]}"
}

command_has_profile_subject_or_anon_arg() {
  local command_text="${1:-}"
  [[ "$command_text" =~ (^|[[:space:]])--campaign-subject([[:space:]=]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--subject([[:space:]=]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--key([[:space:]=]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--invite-key([[:space:]=]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--campaign-anon-cred([[:space:]=]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--anon-cred([[:space:]=]|$) ]] && return 0
  return 1
}

action_id_is_profile_default_family() {
  local action_id
  action_id="$(trim "${1:-}")"
  [[ "$action_id" == profile_default_gate* ]]
}

action_id_is_multi_vm_stability_action_01() {
  local action_id
  action_id="$(trim "${1:-}")"
  [[ "$action_id" == "profile_compare_multi_vm_stability" || "$action_id" == "profile_compare_multi_vm_stability_promotion" ]]
}

strip_optional_wrapping_quotes() {
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

profile_subject_looks_placeholder() {
  local value normalized
  value="$(trim "${1:-}")"
  value="$(strip_optional_wrapping_quotes "$value")"
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$normalized" in
    INVITE_KEY|\$\{INVITE_KEY\}|\$INVITE_KEY|"<INVITE_KEY>"|"{{INVITE_KEY}}"|YOUR_INVITE_KEY|REPLACE_WITH_INVITE_KEY|%INVITE_KEY%|\$\{INVITE_KEY:-*}|\$\{INVITE_KEY-*}|CAMPAIGN_SUBJECT|\$\{CAMPAIGN_SUBJECT\}|\$CAMPAIGN_SUBJECT|"<CAMPAIGN_SUBJECT>"|"{{CAMPAIGN_SUBJECT}}"|YOUR_CAMPAIGN_SUBJECT|REPLACE_WITH_CAMPAIGN_SUBJECT|%CAMPAIGN_SUBJECT%|\$\{CAMPAIGN_SUBJECT:-*}|\$\{CAMPAIGN_SUBJECT-*})
      return 0
      ;;
  esac
  return 1
}

value_matches_placeholder_token_01() {
  local value token normalized
  value="$(trim "${1:-}")"
  token="$(trim "${2:-}")"
  if [[ -z "$value" || -z "$token" ]]; then
    return 1
  fi
  value="$(strip_optional_wrapping_quotes "$value")"
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  token="$(printf '%s' "$token" | tr '[:lower:]' '[:upper:]')"
  case "$normalized" in
    "$token"|\$\{"$token"\}|\$"$token"|"<$token>"|"{{$token}}"|YOUR_"$token"|REPLACE_WITH_"$token"|%$token%|\$\{"$token":-*}|\$\{"$token"-*})
      return 0
      ;;
  esac
  return 1
}

host_a_value_looks_placeholder_01() {
  local value
  value="$(trim "${1:-}")"
  for token in A_HOST HOST_A; do
    if value_matches_placeholder_token_01 "$value" "$token"; then
      return 0
    fi
  done
  return 1
}

host_b_value_looks_placeholder_01() {
  local value
  value="$(trim "${1:-}")"
  for token in B_HOST HOST_B; do
    if value_matches_placeholder_token_01 "$value" "$token"; then
      return 0
    fi
  done
  return 1
}

vm_command_source_value_looks_placeholder_01() {
  local value
  value="$(trim "${1:-}")"
  for token in VM_COMMAND_SOURCE VM_COMMAND_FILE VM_COMMAND; do
    if value_matches_placeholder_token_01 "$value" "$token"; then
      return 0
    fi
  done
  value="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$value" in
    "<VM-COMMAND>"|"<SET-VM-COMMAND-SOURCE>"|REPLACE_WITH_VM_COMMAND_SOURCE|REPLACE_WITH_VM_COMMAND_FILE)
      return 0
      ;;
  esac
  return 1
}

command_has_vm_command_source_placeholder_01() {
  local command_text normalized token key value idx token_count
  command_text="${1:-}"
  if [[ -z "$command_text" ]]; then
    return 1
  fi

  if command_string_to_argv "$command_text"; then
    token_count="${#COMMAND_STRING_ARGV[@]}"
    idx=0
    while (( idx < token_count )); do
      token="${COMMAND_STRING_ARGV[$idx]}"
      case "$token" in
        --vm-command-file|--vm-command-source)
          if (( idx + 1 >= token_count )); then
            return 0
          fi
          value="${COMMAND_STRING_ARGV[$((idx + 1))]}"
          if vm_command_source_value_looks_placeholder_01 "$value"; then
            return 0
          fi
          idx=$((idx + 2))
          continue
          ;;
        --vm-command-file=*|--vm-command-source=*)
          key="${token%%=*}"
          value="${token#*=}"
          if [[ -z "$value" ]] || vm_command_source_value_looks_placeholder_01 "$value"; then
            return 0
          fi
          idx=$((idx + 1))
          continue
          ;;
      esac
      if vm_command_source_value_looks_placeholder_01 "$token"; then
        return 0
      fi
      idx=$((idx + 1))
    done
    return 1
  fi

  normalized="$(printf '%s' "$command_text" | tr '[:lower:]' '[:upper:]')"
  if [[ "$normalized" =~ \$\{?(VM_COMMAND_SOURCE|VM_COMMAND_FILE|VM_COMMAND)\}? ]]; then
    return 0
  fi
  if [[ "$normalized" =~ (^|[^A-Z0-9_])(REPLACE_WITH_VM_COMMAND_SOURCE|REPLACE_WITH_VM_COMMAND_FILE|VM_COMMAND_SOURCE|VM_COMMAND_FILE|VM_COMMAND)([^A-Z0-9_]|$) ]]; then
    return 0
  fi
  if [[ "$normalized" == *"<VM-COMMAND>"* ]] \
     || [[ "$normalized" == *"<SET-VM-COMMAND-SOURCE>"* ]] \
     || [[ "$normalized" == *"REPLACE_WITH_VM_COMMAND_SOURCE"* ]] \
     || [[ "$normalized" == *"REPLACE_WITH_VM_COMMAND_FILE"* ]]; then
    return 0
  fi
  return 1
}

is_profile_subject_flag() {
  case "${1:-}" in
    --campaign-subject|--subject|--key|--invite-key)
      return 0
      ;;
  esac
  return 1
}

command_has_profile_subject_placeholder_invite_key() {
  local command_text="${1:-}"
  local token=""
  local key=""
  local value=""
  local idx=0
  local token_count=0

  if command_string_to_argv "$command_text"; then
    token_count="${#COMMAND_STRING_ARGV[@]}"
    while (( idx < token_count )); do
      token="${COMMAND_STRING_ARGV[$idx]}"
      if is_profile_subject_flag "$token"; then
        if (( idx + 1 < token_count )); then
          value="${COMMAND_STRING_ARGV[$((idx + 1))]}"
          if profile_subject_looks_placeholder "$value"; then
            return 0
          fi
          idx=$((idx + 2))
          continue
        fi
      elif [[ "$token" == --*=* ]]; then
        key="${token%%=*}"
        if is_profile_subject_flag "$key"; then
          value="${token#*=}"
          if profile_subject_looks_placeholder "$value"; then
            return 0
          fi
        fi
      fi
      idx=$((idx + 1))
    done
    return 1
  fi

  [[ "$command_text" =~ (^|[[:space:]])--campaign-subject([[:space:]=]+)(INVITE_KEY|CAMPAIGN_SUBJECT)([[:space:]]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--subject([[:space:]=]+)(INVITE_KEY|CAMPAIGN_SUBJECT)([[:space:]]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--key([[:space:]=]+)(INVITE_KEY|CAMPAIGN_SUBJECT)([[:space:]]|$) ]] && return 0
  [[ "$command_text" =~ (^|[[:space:]])--invite-key([[:space:]=]+)(INVITE_KEY|CAMPAIGN_SUBJECT)([[:space:]]|$) ]] && return 0
  return 1
}

COMMAND_PROFILE_SUBJECT_PLACEHOLDER_REPLACED="0"
command_replace_profile_subject_placeholder() {
  local command_text="${1:-}"
  local subject_value="${2:-}"
  local token=""
  local key=""
  local value=""
  local idx=0
  local token_count=0
  local replaced="0"
  local -a out_argv=()

  if ! command_string_to_argv "$command_text"; then
    COMMAND_PROFILE_SUBJECT_PLACEHOLDER_REPLACED="0"
    printf '%s' "$command_text"
    return
  fi

  token_count="${#COMMAND_STRING_ARGV[@]}"
  while (( idx < token_count )); do
    token="${COMMAND_STRING_ARGV[$idx]}"

    if is_profile_subject_flag "$token"; then
      out_argv+=("$token")
      if (( idx + 1 < token_count )); then
        value="${COMMAND_STRING_ARGV[$((idx + 1))]}"
        if profile_subject_looks_placeholder "$value"; then
          out_argv+=("$subject_value")
          replaced="1"
        else
          out_argv+=("$value")
        fi
        idx=$((idx + 2))
        continue
      fi
      idx=$((idx + 1))
      continue
    fi

    if [[ "$token" == --*=* ]]; then
      key="${token%%=*}"
      if is_profile_subject_flag "$key"; then
        value="${token#*=}"
        if profile_subject_looks_placeholder "$value"; then
          out_argv+=("${key}=${subject_value}")
          replaced="1"
        else
          out_argv+=("$token")
        fi
        idx=$((idx + 1))
        continue
      fi
    fi

    out_argv+=("$token")
    idx=$((idx + 1))
  done

  COMMAND_PROFILE_SUBJECT_PLACEHOLDER_REPLACED="$replaced"
  profile_default_gate_command_from_argv "${out_argv[@]}"
}

PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_VALUE=""
PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_SOURCE=""
PROFILE_DEFAULT_GATE_SUBJECT_RESOLVE_DETAIL=""
resolve_profile_default_gate_subject_value() {
  local candidate=""
  local detail=""

  PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_VALUE=""
  PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_SOURCE=""
  PROFILE_DEFAULT_GATE_SUBJECT_RESOLVE_DETAIL=""

  candidate="$(trim "${runtime_campaign_subject:-}")"
  if [[ -n "$candidate" ]]; then
    if profile_subject_looks_placeholder "$candidate"; then
      detail="runtime_campaign_subject=placeholder"
    else
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_VALUE="$candidate"
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_SOURCE="${runtime_campaign_subject_source:-runtime_campaign_subject}"
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVE_DETAIL="runtime_campaign_subject=resolved(${runtime_campaign_subject_source:-runtime_campaign_subject})"
      return 0
    fi
  else
    detail="runtime_campaign_subject=missing"
  fi

  candidate="$(trim "${profile_default_gate_subject:-}")"
  if [[ -n "$candidate" ]]; then
    if profile_subject_looks_placeholder "$candidate"; then
      detail="${detail},profile_default_gate_subject=placeholder"
    else
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_VALUE="$candidate"
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_SOURCE="profile_default_gate_subject"
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVE_DETAIL="${detail},profile_default_gate_subject=resolved"
      return 0
    fi
  else
    detail="${detail},profile_default_gate_subject=missing"
  fi

  candidate="$(trim "${CAMPAIGN_SUBJECT:-}")"
  if [[ -n "$candidate" ]]; then
    if profile_subject_looks_placeholder "$candidate"; then
      detail="${detail},CAMPAIGN_SUBJECT=placeholder"
    else
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_VALUE="$candidate"
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_SOURCE="CAMPAIGN_SUBJECT"
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVE_DETAIL="${detail},CAMPAIGN_SUBJECT=resolved"
      return 0
    fi
  else
    detail="${detail},CAMPAIGN_SUBJECT=missing"
  fi

  candidate="$(trim "${INVITE_KEY:-}")"
  if [[ -n "$candidate" ]]; then
    if profile_subject_looks_placeholder "$candidate"; then
      detail="${detail},INVITE_KEY=placeholder"
    else
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_VALUE="$candidate"
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_SOURCE="INVITE_KEY"
      PROFILE_DEFAULT_GATE_SUBJECT_RESOLVE_DETAIL="${detail},INVITE_KEY=resolved"
      return 0
    fi
  else
    detail="${detail},INVITE_KEY=missing"
  fi

  PROFILE_DEFAULT_GATE_SUBJECT_RESOLVE_DETAIL="$detail"
  return 1
}

write_profile_default_gate_subject_precondition_log() {
  local log_path="${1:-}"
  local command_redacted="${2:-}"
  local notes="${3:-}"
  local resolve_detail="${4:-}"
  local next_operator_action="${5:-}"

  if [[ -z "$log_path" ]]; then
    return
  fi
  if [[ -z "$next_operator_action" ]]; then
    next_operator_action="$(build_profile_default_gate_subject_operator_command)"
  fi

  {
    echo "failure_kind=missing_invite_subject_precondition"
    echo "profile_default_gate invite subject precondition failed before execution"
    if [[ -n "$notes" ]]; then
      echo "$notes"
    fi
    if [[ -n "$resolve_detail" ]]; then
      echo "resolve_detail=$resolve_detail"
    fi
    if [[ -n "$command_redacted" ]]; then
      echo "command=$command_redacted"
    fi
    echo "operator_next_action: $next_operator_action"
    echo "operator_next_action: CAMPAIGN_SUBJECT=REPLACE_WITH_INVITE_SUBJECT ./scripts/roadmap_next_actions_run.sh --reports-dir $reports_dir --summary-json $summary_json --print-summary-json ${print_summary_json:-1}"
    echo "operator_next_action: ./scripts/roadmap_next_actions_run.sh --reports-dir $reports_dir --summary-json $summary_json --profile-default-gate-subject REPLACE_WITH_INVITE_SUBJECT --campaign-subject REPLACE_WITH_INVITE_SUBJECT --print-summary-json ${print_summary_json:-1}"
  } >"$log_path"
}

build_multi_vm_stability_vm_command_source_operator_command_01() {
  local -a cmd=("./scripts/roadmap_next_actions_run.sh")

  if [[ -n "${reports_dir:-}" ]]; then
    cmd+=(--reports-dir "$reports_dir")
  fi
  if [[ -n "${summary_json:-}" ]]; then
    cmd+=(--summary-json "$summary_json")
  fi
  if [[ -n "${roadmap_summary_json:-}" ]]; then
    cmd+=(--roadmap-summary-json "$roadmap_summary_json")
  fi
  if [[ -n "${roadmap_report_md:-}" ]]; then
    cmd+=(--roadmap-report-md "$roadmap_report_md")
  fi
  if [[ -n "${runtime_host_a:-}" ]]; then
    cmd+=(--host-a "$runtime_host_a")
  fi
  if [[ -n "${runtime_host_b:-}" ]]; then
    cmd+=(--host-b "$runtime_host_b")
  fi
  if [[ -n "${runtime_campaign_subject:-}" ]]; then
    cmd+=(--campaign-subject "$runtime_campaign_subject")
  fi
  if [[ "${parallel:-0}" == "1" ]]; then
    cmd+=(--parallel 1)
  fi
  if [[ "${max_actions:-0}" != "0" ]]; then
    cmd+=(--max-actions "$max_actions")
  fi
  if [[ "${action_timeout_sec:-0}" != "0" ]]; then
    cmd+=(--action-timeout-sec "$action_timeout_sec")
  fi
  if [[ "${allow_unsafe_shell_commands:-0}" == "1" ]]; then
    cmd+=(--allow-unsafe-shell-commands 1)
  fi
  cmd+=(--include-id "profile_compare_multi_vm_stability")
  cmd+=(--include-id "profile_compare_multi_vm_stability_promotion")
  cmd+=(--vm-command-source "REPLACE_WITH_VM_COMMAND_SOURCE")
  cmd+=(--print-summary-json "${print_summary_json:-1}")
  render_command_line_from_argv "${cmd[@]}"
}

write_multi_vm_stability_vm_command_source_precondition_log_01() {
  local log_path="${1:-}"
  local command_redacted="${2:-}"
  local notes="${3:-}"
  local next_operator_action="${4:-}"

  if [[ -z "$log_path" ]]; then
    return
  fi
  if [[ -z "$next_operator_action" ]]; then
    next_operator_action="$(build_multi_vm_stability_vm_command_source_operator_command_01)"
  fi
  {
    echo "failure_kind=missing_vm_command_source_precondition"
    echo "multi-vm stability vm command source precondition failed before execution"
    if [[ -n "$notes" ]]; then
      echo "$notes"
    fi
    if [[ -n "$command_redacted" ]]; then
      echo "command=$command_redacted"
    fi
    echo "operator_next_action: $next_operator_action"
    echo "operator_next_action: VM_COMMAND_SOURCE=/absolute/path/to/vm_command.txt ./scripts/roadmap_next_actions_run.sh --reports-dir $reports_dir --summary-json $summary_json --include-id profile_compare_multi_vm_stability --vm-command-source /absolute/path/to/vm_command.txt --print-summary-json ${print_summary_json:-1}"
  } >"$log_path"
}

redact_command_secrets() {
  local line="${1:-}"
  local flag_regex='--campaign-subject|--subject|--key|--invite-key|--campaign-anon-cred|--anon-cred|--token|--auth-token|--admin-token|--authorization|--bearer'
  local token=""
  local key=""
  local rendered=""
  local idx=0
  local token_count=0

  if command_string_to_argv "$line"; then
    token_count="${#COMMAND_STRING_ARGV[@]}"
    while (( idx < token_count )); do
      token="${COMMAND_STRING_ARGV[$idx]}"
      if is_sensitive_secret_flag "$token"; then
        rendered="${rendered}${rendered:+ }$(render_log_token "$token")"
        if (( idx + 1 < token_count )); then
          rendered="${rendered}${rendered:+ }[redacted]"
          idx=$((idx + 2))
        else
          idx=$((idx + 1))
        fi
        continue
      fi

      if [[ "$token" == --*=* ]]; then
        key="${token%%=*}"
        if is_sensitive_secret_flag "$key"; then
          rendered="${rendered}${rendered:+ }${key}=[redacted]"
          idx=$((idx + 1))
          continue
        fi
      fi

      rendered="${rendered}${rendered:+ }$(render_log_token "$token")"
      idx=$((idx + 1))
    done
    printf '%s' "$rendered"
    return
  fi

  line="$(printf '%s' "$line" | sed -E \
    -e "s/(${flag_regex})([[:space:]]+)\"[^\"]*\"/\\1\\2[redacted]/g" \
    -e "s/(${flag_regex})([[:space:]]+)'[^']*'/\\1\\2[redacted]/g" \
    -e "s/(${flag_regex})([[:space:]]+)[^[:space:]]+/\\1\\2[redacted]/g" \
    -e "s/(${flag_regex})=[^[:space:]]+/\\1=[redacted]/g")"
  printf '%s' "$line"
}

profile_default_gate_extract_arg_value_from_cmd() {
  local cmd
  local opt
  local token
  local idx=0
  cmd="$(trim "${1:-}")"
  opt="${2:-}"
  if [[ -z "$cmd" || -z "$opt" ]]; then
    printf '%s' ""
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    printf '%s' ""
    return
  fi
  for token in "${COMMAND_STRING_ARGV[@]}"; do
    if [[ "$token" == "$opt" ]]; then
      if (( idx + 1 < ${#COMMAND_STRING_ARGV[@]} )); then
        printf '%s' "${COMMAND_STRING_ARGV[$((idx + 1))]}"
      else
        printf '%s' ""
      fi
      return
    fi
    if [[ "$token" == "$opt="* ]]; then
      printf '%s' "${token#"$opt="}"
      return
    fi
    idx=$((idx + 1))
  done
  printf '%s' ""
}

command_extract_first_flag_value_01() {
  local cmd="${1:-}"
  local token=""
  local key=""
  local idx=0
  local token_count=0
  local flag=""
  shift || true
  if [[ -z "$cmd" || $# -eq 0 ]]; then
    printf '%s' ""
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    printf '%s' ""
    return
  fi
  token_count="${#COMMAND_STRING_ARGV[@]}"
  while (( idx < token_count )); do
    token="${COMMAND_STRING_ARGV[$idx]}"
    for flag in "$@"; do
      if [[ "$token" == "$flag" ]]; then
        if (( idx + 1 < token_count )); then
          printf '%s' "${COMMAND_STRING_ARGV[$((idx + 1))]}"
        else
          printf '%s' ""
        fi
        return
      fi
      if [[ "$token" == "$flag="* ]]; then
        printf '%s' "${token#"$flag="}"
        return
      fi
    done
    if [[ "$token" == --*=* ]]; then
      key="${token%%=*}"
      for flag in "$@"; do
        if [[ "$key" == "$flag" ]]; then
          printf '%s' "${token#*=}"
          return
        fi
      done
    fi
    idx=$((idx + 1))
  done
  printf '%s' ""
}

extract_host_a_value_from_command_01() {
  local cmd value
  cmd="${1:-}"
  value="$(command_extract_first_flag_value_01 "$cmd" \
    --host-a --directory-a --host --host-a-url --directory-a-url \
    --bootstrap-directory --issuer-url --entry-url --exit-url)"
  value="$(trim "$value")"
  if [[ -n "$value" ]] && ! host_a_value_looks_placeholder_01 "$value"; then
    printf '%s' "$value"
  else
    printf '%s' ""
  fi
}

extract_host_b_value_from_command_01() {
  local cmd value
  cmd="${1:-}"
  value="$(command_extract_first_flag_value_01 "$cmd" --host-b --directory-b --host-b-url --directory-b-url)"
  value="$(trim "$value")"
  if [[ -n "$value" ]] && ! host_b_value_looks_placeholder_01 "$value"; then
    printf '%s' "$value"
  else
    printf '%s' ""
  fi
}

extract_campaign_subject_value_from_command_01() {
  local cmd value
  cmd="${1:-}"
  value="$(command_extract_first_flag_value_01 "$cmd" --campaign-subject --subject --key --invite-key)"
  value="$(trim "$value")"
  if [[ -n "$value" ]] && ! profile_subject_looks_placeholder "$value"; then
    printf '%s' "$value"
  else
    printf '%s' ""
  fi
}

extract_vm_command_source_value_from_command_01() {
  local cmd value
  cmd="${1:-}"
  value="$(command_extract_first_flag_value_01 "$cmd" --vm-command-source --vm-command-file)"
  value="$(trim "$value")"
  if [[ -n "$value" ]] && ! vm_command_source_value_looks_placeholder_01 "$value"; then
    printf '%s' "$value"
  else
    printf '%s' ""
  fi
}

extract_first_runtime_value_from_selected_actions_01() {
  local selected_actions_json="${1:-[]}"
  local extractor_fn="${2:-}"
  local action_json=""
  local action_command=""
  local value=""
  if [[ -z "$extractor_fn" ]]; then
    printf '%s' ""
    return
  fi
  while IFS= read -r action_json; do
    [[ -n "$action_json" ]] || continue
    action_command="$(printf '%s\n' "$action_json" | jq -r '.command // "" | tostring')"
    [[ -n "$action_command" ]] || continue
    value="$("$extractor_fn" "$action_command")"
    value="$(trim "$value")"
    if [[ -n "$value" ]]; then
      printf '%s' "$value"
      return
    fi
  done < <(printf '%s\n' "$selected_actions_json" | jq -c '.[]')
  printf '%s' ""
}

profile_default_gate_command_from_argv() {
  local token
  local out=""
  for token in "$@"; do
    out="${out}${out:+ }$(printf '%q' "$token")"
  done
  printf '%s' "$out"
}

profile_default_gate_command_is_localhost_profile_default_run_01() {
  local cmd
  local token
  local has_profile_default_gate_run="0"
  local directory_a=""
  local directory_b=""
  cmd="$(trim "${1:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' "0"
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    printf '%s' "0"
    return
  fi
  for token in "${COMMAND_STRING_ARGV[@]}"; do
    if [[ "$token" == "profile-default-gate-run" ]]; then
      has_profile_default_gate_run="1"
      break
    fi
  done
  if [[ "$has_profile_default_gate_run" != "1" ]]; then
    printf '%s' "0"
    return
  fi
  directory_a="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--directory-a")"
  directory_b="$(profile_default_gate_extract_arg_value_from_cmd "$cmd" "--directory-b")"
  if [[ "$directory_a" =~ ^https?://127\.0\.0\.1:[0-9]+$ \
     && "$directory_b" =~ ^https?://127\.0\.0\.1:[0-9]+$ ]]; then
    printf '%s' "1"
  else
    printf '%s' "0"
  fi
}

profile_default_gate_command_localhost_run_to_live_wrapper() {
  local cmd
  local host_a
  local host_b
  local token=""
  local -a in_argv=()
  local -a out_argv=()
  local idx=0
  local token_count=0
  local has_host_a="0"
  local has_host_b="0"
  cmd="$(trim "${1:-}")"
  host_a="$(trim "${2:-}")"
  host_b="$(trim "${3:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' ""
    return
  fi
  if [[ -z "$host_a" || -z "$host_b" ]]; then
    printf '%s' "$cmd"
    return
  fi
  if [[ "$(profile_default_gate_command_is_localhost_profile_default_run_01 "$cmd")" != "1" ]]; then
    printf '%s' "$cmd"
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    printf '%s' "$cmd"
    return
  fi
  in_argv=("${COMMAND_STRING_ARGV[@]}")
  token_count="${#in_argv[@]}"
  while (( idx < token_count )); do
    token="${in_argv[$idx]}"
    case "$token" in
      profile-default-gate-run)
        out_argv+=("profile-default-gate-live")
        ;;
      --directory-a)
        out_argv+=("--directory-a" "$host_a")
        if (( idx + 1 < token_count )); then
          idx=$((idx + 1))
        fi
        ;;
      --directory-a=*)
        out_argv+=("--directory-a=$host_a")
        ;;
      --directory-b)
        out_argv+=("--directory-b" "$host_b")
        if (( idx + 1 < token_count )); then
          idx=$((idx + 1))
        fi
        ;;
      --directory-b=*)
        out_argv+=("--directory-b=$host_b")
        ;;
      --host-a)
        has_host_a="1"
        out_argv+=("--host-a" "$host_a")
        if (( idx + 1 < token_count )); then
          idx=$((idx + 1))
        fi
        ;;
      --host-a=*)
        has_host_a="1"
        out_argv+=("--host-a=$host_a")
        ;;
      --host-b)
        has_host_b="1"
        out_argv+=("--host-b" "$host_b")
        if (( idx + 1 < token_count )); then
          idx=$((idx + 1))
        fi
        ;;
      --host-b=*)
        has_host_b="1"
        out_argv+=("--host-b=$host_b")
        ;;
      *)
        out_argv+=("$token")
        ;;
    esac
    idx=$((idx + 1))
  done
  if [[ "$has_host_a" != "1" ]]; then
    out_argv+=("--host-a" "$host_a")
  fi
  if [[ "$has_host_b" != "1" ]]; then
    out_argv+=("--host-b" "$host_b")
  fi
  profile_default_gate_command_from_argv "${out_argv[@]}"
}

profile_default_gate_command_apply_env_host_placeholders() {
  local cmd
  local host_a
  local host_b
  local token=""
  local idx=0
  local token_count=0
  local next_token=""
  local key=""
  local value=""
  local -a in_argv=()
  local -a out_argv=()

  cmd="$(trim "${1:-}")"
  host_a="$(trim "${2:-}")"
  host_b="$(trim "${3:-}")"
  if [[ -z "$cmd" ]]; then
    printf '%s' ""
    return
  fi
  if [[ -z "$host_a" && -z "$host_b" ]]; then
    printf '%s' "$cmd"
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    printf '%s' "$cmd"
    return
  fi

  in_argv=("${COMMAND_STRING_ARGV[@]}")
  token_count="${#in_argv[@]}"
  while (( idx < token_count )); do
    token="${in_argv[$idx]}"
    case "$token" in
      --host-a|--directory-a|--host|--host-a-url|--directory-a-url|--bootstrap-directory|--issuer-url|--entry-url|--exit-url)
        out_argv+=("$token")
        if (( idx + 1 < token_count )); then
          next_token="${in_argv[$((idx + 1))]}"
          if [[ -n "$host_a" ]]; then
            next_token="${next_token//HOST_A/$host_a}"
            next_token="${next_token//A_HOST/$host_a}"
          fi
          out_argv+=("$next_token")
          idx=$((idx + 2))
          continue
        fi
        idx=$((idx + 1))
        continue
        ;;
      --host-b|--directory-b|--host-b-url|--directory-b-url)
        out_argv+=("$token")
        if (( idx + 1 < token_count )); then
          next_token="${in_argv[$((idx + 1))]}"
          if [[ -n "$host_b" ]]; then
            next_token="${next_token//HOST_B/$host_b}"
            next_token="${next_token//B_HOST/$host_b}"
          fi
          out_argv+=("$next_token")
          idx=$((idx + 2))
          continue
        fi
        idx=$((idx + 1))
        continue
        ;;
      --*=*)
        key="${token%%=*}"
        value="${token#*=}"
        case "$key" in
          --host-a|--directory-a|--host|--host-a-url|--directory-a-url|--bootstrap-directory|--issuer-url|--entry-url|--exit-url)
            if [[ -n "$host_a" ]]; then
              value="${value//HOST_A/$host_a}"
              value="${value//A_HOST/$host_a}"
            fi
            out_argv+=("${key}=${value}")
            idx=$((idx + 1))
            continue
            ;;
          --host-b|--directory-b|--host-b-url|--directory-b-url)
            if [[ -n "$host_b" ]]; then
              value="${value//HOST_B/$host_b}"
              value="${value//B_HOST/$host_b}"
            fi
            out_argv+=("${key}=${value}")
            idx=$((idx + 1))
            continue
            ;;
        esac
        ;;
    esac

    if [[ -n "$host_a" ]]; then
      token="${token//HOST_A/$host_a}"
      token="${token//A_HOST/$host_a}"
    fi
    if [[ -n "$host_b" ]]; then
      token="${token//HOST_B/$host_b}"
      token="${token//B_HOST/$host_b}"
    fi
    out_argv+=("$token")
    idx=$((idx + 1))
  done

  profile_default_gate_command_from_argv "${out_argv[@]}"
}

profile_default_gate_command_apply_subject_override_01() {
  local cmd subject_value
  local token=""
  local key=""
  local value=""
  local idx=0
  local token_count=0
  local has_subject_arg="0"
  local has_anon_arg="0"
  local -a in_argv=()
  local -a out_argv=()

  cmd="$(trim "${1:-}")"
  subject_value="$(trim "${2:-}")"
  if [[ -z "$cmd" || -z "$subject_value" ]]; then
    printf '%s' "$cmd"
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    printf '%s' "$cmd"
    return
  fi

  in_argv=("${COMMAND_STRING_ARGV[@]}")
  token_count="${#in_argv[@]}"
  while (( idx < token_count )); do
    token="${in_argv[$idx]}"
    if is_profile_subject_flag "$token"; then
      has_subject_arg="1"
      out_argv+=("$token")
      if (( idx + 1 < token_count )); then
        out_argv+=("$subject_value")
        idx=$((idx + 2))
      else
        idx=$((idx + 1))
      fi
      continue
    fi
    case "$token" in
      --campaign-anon-cred|--anon-cred)
        has_anon_arg="1"
        out_argv+=("$token")
        if (( idx + 1 < token_count )); then
          out_argv+=("${in_argv[$((idx + 1))]}")
          idx=$((idx + 2))
        else
          idx=$((idx + 1))
        fi
        continue
        ;;
      --*=*)
        key="${token%%=*}"
        value="${token#*=}"
        if is_profile_subject_flag "$key"; then
          has_subject_arg="1"
          out_argv+=("${key}=${subject_value}")
          idx=$((idx + 1))
          continue
        fi
        if [[ "$key" == "--campaign-anon-cred" || "$key" == "--anon-cred" ]]; then
          has_anon_arg="1"
          out_argv+=("$token")
          idx=$((idx + 1))
          continue
        fi
        ;;
    esac
    out_argv+=("$token")
    idx=$((idx + 1))
  done
  if [[ "$has_subject_arg" != "1" && "$has_anon_arg" != "1" ]]; then
    out_argv+=("--campaign-subject" "$subject_value")
  fi
  profile_default_gate_command_from_argv "${out_argv[@]}"
}

multi_vm_stability_command_apply_vm_command_source_override_01() {
  local cmd vm_command_source
  local token=""
  local key=""
  local idx=0
  local token_count=0
  local has_vm_command_file="0"
  local has_vm_command="0"
  local -a in_argv=()
  local -a out_argv=()

  cmd="$(trim "${1:-}")"
  vm_command_source="$(trim "${2:-}")"
  if [[ -z "$cmd" || -z "$vm_command_source" ]]; then
    printf '%s' "$cmd"
    return
  fi
  if ! command_string_to_argv "$cmd"; then
    cmd="${cmd//VM_COMMAND_SOURCE/$vm_command_source}"
    cmd="${cmd//VM_COMMAND_FILE/$vm_command_source}"
    printf '%s' "$cmd"
    return
  fi

  in_argv=("${COMMAND_STRING_ARGV[@]}")
  token_count="${#in_argv[@]}"
  while (( idx < token_count )); do
    token="${in_argv[$idx]}"
    case "$token" in
      --vm-command-file)
        has_vm_command_file="1"
        out_argv+=("--vm-command-file")
        if (( idx + 1 < token_count )); then
          out_argv+=("$vm_command_source")
          idx=$((idx + 2))
        else
          out_argv+=("$vm_command_source")
          idx=$((idx + 1))
        fi
        continue
        ;;
      --vm-command-file=*)
        has_vm_command_file="1"
        out_argv+=("--vm-command-file=$vm_command_source")
        idx=$((idx + 1))
        continue
        ;;
      --vm-command)
        has_vm_command="1"
        out_argv+=("$token")
        if (( idx + 1 < token_count )); then
          out_argv+=("${in_argv[$((idx + 1))]}")
          idx=$((idx + 2))
        else
          idx=$((idx + 1))
        fi
        continue
        ;;
      --vm-command=*)
        has_vm_command="1"
        out_argv+=("$token")
        idx=$((idx + 1))
        continue
        ;;
      --*=*)
        key="${token%%=*}"
        if [[ "$key" == "--vm-command-file" ]]; then
          has_vm_command_file="1"
          out_argv+=("--vm-command-file=$vm_command_source")
          idx=$((idx + 1))
          continue
        fi
        if [[ "$key" == "--vm-command" ]]; then
          has_vm_command="1"
          out_argv+=("$token")
          idx=$((idx + 1))
          continue
        fi
        ;;
    esac

    token="${token//VM_COMMAND_SOURCE/$vm_command_source}"
    token="${token//VM_COMMAND_FILE/$vm_command_source}"
    out_argv+=("$token")
    idx=$((idx + 1))
  done

  if [[ "$has_vm_command_file" != "1" && "$has_vm_command" != "1" ]]; then
    out_argv+=("--vm-command-file" "$vm_command_source")
  fi
  profile_default_gate_command_from_argv "${out_argv[@]}"
}

log_has_failure_kind_marker() {
  local log_path="${1:-}"
  local marker="${2:-}"
  [[ -f "$log_path" ]] || return 1
  grep -E -q "failure_kind[=:]\"?${marker}\"?([[:space:],]|$)" "$log_path"
}

command_requires_shell_execution() {
  local command_text="${1:-}"
  if [[ -z "$command_text" ]]; then
    return 1
  fi
  if [[ "$command_text" == *$'\n'* || "$command_text" == *$'\r'* ]]; then
    return 0
  fi
  if [[ "$command_text" =~ [\;\|\&\<\>\`\$\(\)\{\}] ]]; then
    return 0
  fi
  return 1
}

command_string_to_argv() {
  local command_text="${1:-}"
  local length=0
  local idx=0
  local ch=""
  local token=""
  local quote_mode=""
  local escaped="0"
  local token_started="0"
  COMMAND_STRING_ARGV=()
  length="${#command_text}"

  while (( idx < length )); do
    ch="${command_text:idx:1}"

    if [[ "$quote_mode" == "single" ]]; then
      if [[ "$ch" == "'" ]]; then
        quote_mode=""
      else
        token+="$ch"
      fi
      token_started="1"
      idx=$((idx + 1))
      continue
    fi

    if [[ "$quote_mode" == "double" ]]; then
      if [[ "$escaped" == "1" ]]; then
        token+="$ch"
        escaped="0"
        token_started="1"
        idx=$((idx + 1))
        continue
      fi
      case "$ch" in
        "\\")
          escaped="1"
          ;;
        "\"")
          quote_mode=""
          ;;
        *)
          token+="$ch"
          token_started="1"
          ;;
      esac
      idx=$((idx + 1))
      continue
    fi

    if [[ "$escaped" == "1" ]]; then
      token+="$ch"
      escaped="0"
      token_started="1"
      idx=$((idx + 1))
      continue
    fi

    case "$ch" in
      [[:space:]])
        if [[ "$token_started" == "1" ]]; then
          COMMAND_STRING_ARGV+=("$token")
          token=""
          token_started="0"
        fi
        ;;
      "\\")
        escaped="1"
        token_started="1"
        ;;
      "'")
        quote_mode="single"
        token_started="1"
        ;;
      "\"")
        quote_mode="double"
        token_started="1"
        ;;
      *)
        token+="$ch"
        token_started="1"
        ;;
    esac
    idx=$((idx + 1))
  done

  if [[ "$escaped" == "1" || -n "$quote_mode" ]]; then
    COMMAND_STRING_ARGV=()
    return 1
  fi

  if [[ "$token_started" == "1" ]]; then
    COMMAND_STRING_ARGV+=("$token")
  fi

  [[ "${#COMMAND_STRING_ARGV[@]}" -gt 0 ]]
}

path_is_symlink_free_under_scripts_dir() {
  local candidate="${1:-}"
  local scripts_root="$ROOT_DIR/scripts"
  local current=""
  if [[ -z "$candidate" ]]; then
    return 1
  fi
  current="$candidate"
  while :; do
    if [[ -L "$current" ]]; then
      return 1
    fi
    if [[ "$current" == "$scripts_root" ]]; then
      return 0
    fi
    current="$(dirname "$current")"
    if [[ "$current" != "$scripts_root" && "$current" != "$scripts_root/"* ]]; then
      return 1
    fi
  done
}

canonical_existing_file_path() {
  local candidate="${1:-}"
  local parent_dir=""
  local base_name=""
  if [[ -z "$candidate" || ! -f "$candidate" ]]; then
    return 1
  fi
  parent_dir="$(dirname "$candidate")"
  base_name="$(basename "$candidate")"
  if ! parent_dir="$(cd -P "$parent_dir" 2>/dev/null && pwd)"; then
    return 1
  fi
  printf '%s/%s' "$parent_dir" "$base_name"
}

ACTION_COMMAND_VALIDATED_SCRIPT_PATH=""

action_command_argv_allowed() {
  local -a argv=("$@")
  local cmd
  local script_path
  local scripts_root="$ROOT_DIR/scripts"
  local scripts_root_canonical=""
  local canonical_script_path=""
  ACTION_COMMAND_VALIDATED_SCRIPT_PATH=""
  if [[ "${#argv[@]}" -eq 0 ]]; then
    return 1
  fi
  if ! scripts_root_canonical="$(cd -P "$scripts_root" 2>/dev/null && pwd)"; then
    return 1
  fi
  cmd="${argv[0]}"
  if [[ "$cmd" == "bash" ]]; then
    if [[ "${#argv[@]}" -lt 2 ]]; then
      return 1
    fi
    script_path="${argv[1]}"
    if [[ "$script_path" == -* ]]; then
      # Keep shell-evaluated modes blocked in argv-safe path mode.
      return 1
    fi
  else
    script_path="$cmd"
  fi
  case "$script_path" in
    "$scripts_root"/*)
      ;;
    scripts/*)
      script_path="$ROOT_DIR/$script_path"
      ;;
    ./scripts/*)
      script_path="$ROOT_DIR/${script_path#./}"
      ;;
    *)
      return 1
      ;;
  esac
  if [[ ! -f "$script_path" ]]; then
    return 1
  fi
  if ! path_is_symlink_free_under_scripts_dir "$script_path"; then
    return 1
  fi
  if ! canonical_script_path="$(canonical_existing_file_path "$script_path")"; then
    return 1
  fi
  if [[ "$canonical_script_path" != "$scripts_root_canonical/"* ]]; then
    return 1
  fi
  ACTION_COMMAND_VALIDATED_SCRIPT_PATH="$canonical_script_path"
  return 0
}

run_action_command_string() {
  local command_text="${1:-}"
  local log_path="${2:-}"
  local timeout_sec="${3:-0}"
  local redacted_command_text=""
  local -a command_argv=()
  local -a env_prefix=()
  local token
  local validated_script_path_initial=""
  local validated_script_path_pre_exec=""
  local pre_exec_revalidate_delay_sec="${ROADMAP_NEXT_ACTIONS_RUN_PRE_EXEC_REVALIDATE_DELAY_SEC:-0}"

  if [[ -z "$command_text" ]]; then
    return 4
  fi
  redacted_command_text="$(redact_command_secrets "$command_text")"

  if ! command_requires_shell_execution "$command_text" && command_string_to_argv "$command_text"; then
    for token in "${COMMAND_STRING_ARGV[@]}"; do
      if [[ "${#command_argv[@]}" -eq 0 && "$token" =~ ^[A-Za-z_][A-Za-z0-9_]*=.*$ ]]; then
        env_prefix+=("$token")
        continue
      fi
      command_argv+=("$token")
    done

    if [[ "${#command_argv[@]}" -gt 0 ]]; then
      if ! action_command_argv_allowed "${command_argv[@]}"; then
        {
          echo "refusing untrusted action command (outside scripts allowlist)"
          echo "command: $redacted_command_text"
        } >"$log_path"
        return 6
      fi
      validated_script_path_initial="$ACTION_COMMAND_VALIDATED_SCRIPT_PATH"
      if [[ "${#env_prefix[@]}" -gt 0 && "${allow_unsafe_shell_commands:-0}" != "1" ]]; then
        {
          echo "refusing env-prefixed action command (set --allow-unsafe-shell-commands 1 to override)"
          echo "command: $redacted_command_text"
        } >"$log_path"
        return 5
      fi
      if [[ "$pre_exec_revalidate_delay_sec" != "0" && "$pre_exec_revalidate_delay_sec" =~ ^[0-9]+([.][0-9]+)?$ ]]; then
        sleep "$pre_exec_revalidate_delay_sec"
      fi
      if ! action_command_argv_allowed "${command_argv[@]}"; then
        {
          echo "refusing untrusted action command (pre-exec validation mismatch)"
          echo "command: $redacted_command_text"
          if [[ -n "$validated_script_path_initial" ]]; then
            echo "validated_path_initial: $validated_script_path_initial"
          fi
        } >"$log_path"
        return 6
      fi
      validated_script_path_pre_exec="$ACTION_COMMAND_VALIDATED_SCRIPT_PATH"
      if [[ -n "$validated_script_path_initial" && "$validated_script_path_initial" != "$validated_script_path_pre_exec" ]]; then
        {
          echo "refusing untrusted action command (pre-exec validation mismatch)"
          echo "command: $redacted_command_text"
          echo "validated_path_initial: $validated_script_path_initial"
          echo "validated_path_pre_exec: $validated_script_path_pre_exec"
        } >"$log_path"
        return 6
      fi
      if (( timeout_sec > 0 )); then
        if [[ "${#env_prefix[@]}" -gt 0 ]]; then
          timeout --foreground "${timeout_sec}s" env "${env_prefix[@]}" "${command_argv[@]}" >"$log_path" 2>&1
        else
          timeout --foreground "${timeout_sec}s" "${command_argv[@]}" >"$log_path" 2>&1
        fi
      else
        if [[ "${#env_prefix[@]}" -gt 0 ]]; then
          env "${env_prefix[@]}" "${command_argv[@]}" >"$log_path" 2>&1
        else
          "${command_argv[@]}" >"$log_path" 2>&1
        fi
      fi
      return $?
    fi
  fi

  if (( timeout_sec > 0 )); then
    if [[ "${allow_unsafe_shell_commands:-0}" != "1" ]]; then
      {
        echo "refusing shell-evaluated action command (set --allow-unsafe-shell-commands 1 to override)"
        echo "command: $redacted_command_text"
      } >"$log_path"
      return 5
    fi
    timeout --foreground "${timeout_sec}s" bash -lc "$command_text" >"$log_path" 2>&1
  else
    if [[ "${allow_unsafe_shell_commands:-0}" != "1" ]]; then
      {
        echo "refusing shell-evaluated action command (set --allow-unsafe-shell-commands 1 to override)"
        echo "command: $redacted_command_text"
      } >"$log_path"
      return 5
    fi
    bash -lc "$command_text" >"$log_path" 2>&1
  fi
}

need_cmd jq
need_cmd bash
need_cmd date
need_cmd mktemp

reports_dir="${ROADMAP_NEXT_ACTIONS_RUN_REPORTS_DIR:-}"
summary_json="${ROADMAP_NEXT_ACTIONS_RUN_SUMMARY_JSON:-}"
roadmap_summary_json="${ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SUMMARY_JSON:-}"
roadmap_report_md="${ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_REPORT_MD:-}"
host_a_override_env="${ROADMAP_NEXT_ACTIONS_RUN_HOST_A:-}"
host_b_override_env="${ROADMAP_NEXT_ACTIONS_RUN_HOST_B:-}"
campaign_subject_override_env="${ROADMAP_NEXT_ACTIONS_RUN_CAMPAIGN_SUBJECT:-}"
vm_command_source_override_env="${ROADMAP_NEXT_ACTIONS_RUN_VM_COMMAND_SOURCE:-${VM_COMMAND_SOURCE:-}}"
refresh_manual_validation="${ROADMAP_NEXT_ACTIONS_RUN_REFRESH_MANUAL_VALIDATION:-0}"
refresh_single_machine_readiness="${ROADMAP_NEXT_ACTIONS_RUN_REFRESH_SINGLE_MACHINE_READINESS:-0}"
parallel="${ROADMAP_NEXT_ACTIONS_RUN_PARALLEL:-0}"
max_actions="${ROADMAP_NEXT_ACTIONS_RUN_MAX_ACTIONS:-0}"
profile_default_gate_subject_env="${ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_SUBJECT:-}"
profile_default_gate_subject="$profile_default_gate_subject_env"
profile_default_gate_subject_arg_provided="0"
allow_profile_default_gate_unreachable="${ROADMAP_NEXT_ACTIONS_RUN_ALLOW_PROFILE_DEFAULT_GATE_UNREACHABLE:-0}"
include_id_prefix="${ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_ID_PREFIX:-}"
exclude_id_prefix="${ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_ID_PREFIX:-}"
include_ids_csv="${ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_IDS:-}"
exclude_ids_csv="${ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_IDS:-}"
include_id_suffixes_csv="${ROADMAP_NEXT_ACTIONS_RUN_INCLUDE_ID_SUFFIXES:-}"
exclude_id_suffixes_csv="${ROADMAP_NEXT_ACTIONS_RUN_EXCLUDE_ID_SUFFIXES:-}"
print_summary_json="${ROADMAP_NEXT_ACTIONS_RUN_PRINT_SUMMARY_JSON:-1}"
action_timeout_sec="${ROADMAP_NEXT_ACTIONS_RUN_ACTION_TIMEOUT_SEC:-0}"
allow_unsafe_shell_commands="${ROADMAP_NEXT_ACTIONS_RUN_ALLOW_UNSAFE_SHELL_COMMANDS:-0}"
profile_default_gate_default_timeout_sec="${ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC:-2400}"
host_a_override_arg=""
host_b_override_arg=""
campaign_subject_override_arg=""
vm_command_source_override_arg=""
host_a_override_arg_provided="0"
host_b_override_arg_provided="0"
campaign_subject_override_arg_provided="0"
vm_command_source_override_arg_provided="0"
declare -a include_ids=()
declare -a exclude_ids=()
declare -a include_id_suffixes=()
declare -a exclude_id_suffixes=()
append_csv_values_to_id_filters "$include_ids_csv" "include"
append_csv_values_to_id_filters "$exclude_ids_csv" "exclude"
append_csv_values_to_suffix_filters "$include_id_suffixes_csv" "include"
append_csv_values_to_suffix_filters "$exclude_id_suffixes_csv" "exclude"

while [[ $# -gt 0 ]]; do
  case "$1" in
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
    --roadmap-summary-json)
      require_value_or_die "$1" "${2:-}"
      roadmap_summary_json="${2:-}"
      shift 2
      ;;
    --roadmap-report-md)
      require_value_or_die "$1" "${2:-}"
      roadmap_report_md="${2:-}"
      shift 2
      ;;
    --host-a)
      require_value_or_die "$1" "${2:-}"
      host_a_override_arg="${2:-}"
      host_a_override_arg_provided="1"
      shift 2
      ;;
    --host-b)
      require_value_or_die "$1" "${2:-}"
      host_b_override_arg="${2:-}"
      host_b_override_arg_provided="1"
      shift 2
      ;;
    --campaign-subject)
      require_value_or_die "$1" "${2:-}"
      campaign_subject_override_arg="${2:-}"
      campaign_subject_override_arg_provided="1"
      shift 2
      ;;
    --vm-command-source)
      require_value_or_die "$1" "${2:-}"
      vm_command_source_override_arg="${2:-}"
      vm_command_source_override_arg_provided="1"
      shift 2
      ;;
    --action-timeout-sec)
      require_value_or_die "$1" "${2:-}"
      action_timeout_sec="${2:-}"
      shift 2
      ;;
    --allow-unsafe-shell-commands)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_unsafe_shell_commands="${2:-}"
        shift 2
      else
        allow_unsafe_shell_commands="1"
        shift
      fi
      ;;
    --refresh-manual-validation)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_manual_validation="${2:-}"
        shift 2
      else
        refresh_manual_validation="1"
        shift
      fi
      ;;
    --refresh-single-machine-readiness)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_single_machine_readiness="${2:-}"
        shift 2
      else
        refresh_single_machine_readiness="1"
        shift
      fi
      ;;
    --parallel)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        parallel="${2:-}"
        shift 2
      else
        parallel="1"
        shift
      fi
      ;;
    --max-actions)
      require_value_or_die "$1" "${2:-}"
      max_actions="${2:-}"
      shift 2
      ;;
    --profile-default-gate-subject)
      require_value_or_die "$1" "${2:-}"
      profile_default_gate_subject="${2:-}"
      profile_default_gate_subject_arg_provided="1"
      shift 2
      ;;
    --allow-profile-default-gate-unreachable)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        allow_profile_default_gate_unreachable="${2:-}"
        shift 2
      else
        allow_profile_default_gate_unreachable="1"
        shift
      fi
      ;;
    --include-id-prefix)
      require_value_or_die "$1" "${2:-}"
      include_id_prefix="${2:-}"
      shift 2
      ;;
    --include-id)
      require_value_or_die "$1" "${2:-}"
      include_id_value="$(trim "${2:-}")"
      if [[ -z "$include_id_value" ]]; then
        echo "--include-id requires a non-empty value"
        exit 2
      fi
      include_ids+=("$include_id_value")
      shift 2
      ;;
    --exclude-id)
      require_value_or_die "$1" "${2:-}"
      exclude_id_value="$(trim "${2:-}")"
      if [[ -z "$exclude_id_value" ]]; then
        echo "--exclude-id requires a non-empty value"
        exit 2
      fi
      exclude_ids+=("$exclude_id_value")
      shift 2
      ;;
    --exclude-id-prefix)
      require_value_or_die "$1" "${2:-}"
      exclude_id_prefix="${2:-}"
      shift 2
      ;;
    --include-id-suffix)
      require_value_or_die "$1" "${2:-}"
      include_id_suffix_value="$(trim "${2:-}")"
      if [[ -z "$include_id_suffix_value" ]]; then
        echo "--include-id-suffix requires a non-empty value"
        exit 2
      fi
      include_id_suffixes+=("$include_id_suffix_value")
      shift 2
      ;;
    --exclude-id-suffix)
      require_value_or_die "$1" "${2:-}"
      exclude_id_suffix_value="$(trim "${2:-}")"
      if [[ -z "$exclude_id_suffix_value" ]]; then
        echo "--exclude-id-suffix requires a non-empty value"
        exit 2
      fi
      exclude_id_suffixes+=("$exclude_id_suffix_value")
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
      echo "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

bool_arg_or_die "--refresh-manual-validation" "$refresh_manual_validation"
bool_arg_or_die "--refresh-single-machine-readiness" "$refresh_single_machine_readiness"
bool_arg_or_die "--parallel" "$parallel"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--allow-profile-default-gate-unreachable" "$allow_profile_default_gate_unreachable"
bool_arg_or_die "--allow-unsafe-shell-commands" "$allow_unsafe_shell_commands"
int_arg_or_die "--max-actions" "$max_actions"
int_arg_or_die "--action-timeout-sec" "$action_timeout_sec"
int_arg_or_die "ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC" "$profile_default_gate_default_timeout_sec"
if (( profile_default_gate_default_timeout_sec < 1 )); then
  echo "ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_DEFAULT_TIMEOUT_SEC must be >= 1"
  exit 2
fi

runtime_host_a=""
runtime_host_a_source="summary_command"
runtime_host_a_configured="0"
runtime_host_b=""
runtime_host_b_source="summary_command"
runtime_host_b_configured="0"
runtime_campaign_subject=""
runtime_campaign_subject_source="summary_command"
runtime_campaign_subject_configured="0"
runtime_vm_command_source=""
runtime_vm_command_source_source="summary_command"
runtime_vm_command_source_configured="0"

runtime_value_candidate="$(trim "$host_a_override_arg")"
if [[ "$host_a_override_arg_provided" == "1" ]]; then
  if [[ -n "$runtime_value_candidate" ]] && ! host_a_value_looks_placeholder_01 "$runtime_value_candidate"; then
    runtime_host_a="$runtime_value_candidate"
    runtime_host_a_source="cli:--host-a"
    runtime_host_a_configured="1"
  else
    runtime_host_a_source="cli:--host-a=placeholder_or_empty"
  fi
elif [[ -n "$(trim "$host_a_override_env")" ]] && ! host_a_value_looks_placeholder_01 "$host_a_override_env"; then
  runtime_host_a="$(trim "$host_a_override_env")"
  runtime_host_a_source="env:ROADMAP_NEXT_ACTIONS_RUN_HOST_A"
  runtime_host_a_configured="1"
elif [[ -n "$(trim "${A_HOST:-}")" ]] && ! host_a_value_looks_placeholder_01 "${A_HOST:-}"; then
  runtime_host_a="$(trim "${A_HOST:-}")"
  runtime_host_a_source="env:A_HOST"
  runtime_host_a_configured="1"
elif [[ -n "$(trim "${HOST_A:-}")" ]] && ! host_a_value_looks_placeholder_01 "${HOST_A:-}"; then
  runtime_host_a="$(trim "${HOST_A:-}")"
  runtime_host_a_source="env:HOST_A"
  runtime_host_a_configured="1"
fi

runtime_value_candidate="$(trim "$host_b_override_arg")"
if [[ "$host_b_override_arg_provided" == "1" ]]; then
  if [[ -n "$runtime_value_candidate" ]] && ! host_b_value_looks_placeholder_01 "$runtime_value_candidate"; then
    runtime_host_b="$runtime_value_candidate"
    runtime_host_b_source="cli:--host-b"
    runtime_host_b_configured="1"
  else
    runtime_host_b_source="cli:--host-b=placeholder_or_empty"
  fi
elif [[ -n "$(trim "$host_b_override_env")" ]] && ! host_b_value_looks_placeholder_01 "$host_b_override_env"; then
  runtime_host_b="$(trim "$host_b_override_env")"
  runtime_host_b_source="env:ROADMAP_NEXT_ACTIONS_RUN_HOST_B"
  runtime_host_b_configured="1"
elif [[ -n "$(trim "${B_HOST:-}")" ]] && ! host_b_value_looks_placeholder_01 "${B_HOST:-}"; then
  runtime_host_b="$(trim "${B_HOST:-}")"
  runtime_host_b_source="env:B_HOST"
  runtime_host_b_configured="1"
elif [[ -n "$(trim "${HOST_B:-}")" ]] && ! host_b_value_looks_placeholder_01 "${HOST_B:-}"; then
  runtime_host_b="$(trim "${HOST_B:-}")"
  runtime_host_b_source="env:HOST_B"
  runtime_host_b_configured="1"
fi

runtime_value_candidate="$(trim "$campaign_subject_override_arg")"
if [[ "$campaign_subject_override_arg_provided" == "1" ]]; then
  if [[ -n "$runtime_value_candidate" ]] && ! profile_subject_looks_placeholder "$runtime_value_candidate"; then
    runtime_campaign_subject="$runtime_value_candidate"
    runtime_campaign_subject_source="cli:--campaign-subject"
    runtime_campaign_subject_configured="1"
  else
    runtime_campaign_subject_source="cli:--campaign-subject=placeholder_or_empty"
  fi
elif [[ "$profile_default_gate_subject_arg_provided" == "1" ]]; then
  runtime_value_candidate="$(trim "$profile_default_gate_subject")"
  if [[ -n "$runtime_value_candidate" ]] && ! profile_subject_looks_placeholder "$runtime_value_candidate"; then
    runtime_campaign_subject="$runtime_value_candidate"
    runtime_campaign_subject_source="cli:--profile-default-gate-subject"
    runtime_campaign_subject_configured="1"
  else
    runtime_campaign_subject_source="cli:--profile-default-gate-subject=placeholder_or_empty"
  fi
elif [[ -n "$(trim "$profile_default_gate_subject_env")" ]] && ! profile_subject_looks_placeholder "$profile_default_gate_subject_env"; then
  runtime_campaign_subject="$(trim "$profile_default_gate_subject_env")"
  runtime_campaign_subject_source="env:ROADMAP_NEXT_ACTIONS_RUN_PROFILE_DEFAULT_GATE_SUBJECT"
  runtime_campaign_subject_configured="1"
elif [[ -n "$(trim "$campaign_subject_override_env")" ]] && ! profile_subject_looks_placeholder "$campaign_subject_override_env"; then
  runtime_campaign_subject="$(trim "$campaign_subject_override_env")"
  runtime_campaign_subject_source="env:ROADMAP_NEXT_ACTIONS_RUN_CAMPAIGN_SUBJECT"
  runtime_campaign_subject_configured="1"
elif [[ -n "$(trim "${CAMPAIGN_SUBJECT:-}")" ]] && ! profile_subject_looks_placeholder "${CAMPAIGN_SUBJECT:-}"; then
  runtime_campaign_subject="$(trim "${CAMPAIGN_SUBJECT:-}")"
  runtime_campaign_subject_source="env:CAMPAIGN_SUBJECT"
  runtime_campaign_subject_configured="1"
elif [[ -n "$(trim "${INVITE_KEY:-}")" ]] && ! profile_subject_looks_placeholder "${INVITE_KEY:-}"; then
  runtime_campaign_subject="$(trim "${INVITE_KEY:-}")"
  runtime_campaign_subject_source="env:INVITE_KEY"
  runtime_campaign_subject_configured="1"
fi

runtime_value_candidate="$(trim "$vm_command_source_override_arg")"
if [[ "$vm_command_source_override_arg_provided" == "1" ]]; then
  if [[ -n "$runtime_value_candidate" ]] && ! vm_command_source_value_looks_placeholder_01 "$runtime_value_candidate"; then
    runtime_vm_command_source="$runtime_value_candidate"
    runtime_vm_command_source_source="cli:--vm-command-source"
    runtime_vm_command_source_configured="1"
  else
    runtime_vm_command_source_source="cli:--vm-command-source=placeholder_or_empty"
  fi
elif [[ -n "$(trim "$vm_command_source_override_env")" ]] && ! vm_command_source_value_looks_placeholder_01 "$vm_command_source_override_env"; then
  runtime_vm_command_source="$(trim "$vm_command_source_override_env")"
  runtime_vm_command_source_source="env:ROADMAP_NEXT_ACTIONS_RUN_VM_COMMAND_SOURCE"
  runtime_vm_command_source_configured="1"
fi

if (( action_timeout_sec > 0 )); then
  need_cmd timeout
fi

roadmap_paths_provided="1"
if [[ -z "$roadmap_summary_json" || -z "$roadmap_report_md" ]]; then
  roadmap_paths_provided="0"
fi

run_stamp="$(date -u +%Y%m%d_%H%M%S)"
if [[ -z "$reports_dir" ]]; then
  reports_dir="$ROOT_DIR/.easy-node-logs/roadmap_next_actions_run_${run_stamp}"
fi
reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$roadmap_summary_json" ]]; then
  roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
fi
if [[ -z "$roadmap_report_md" ]]; then
  roadmap_report_md="$reports_dir/roadmap_progress_report.md"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_next_actions_run_summary.json"
fi

roadmap_summary_json="$(abs_path "$roadmap_summary_json")"
roadmap_report_md="$(abs_path "$roadmap_report_md")"
summary_json="$(abs_path "$summary_json")"
roadmap_log="$reports_dir/roadmap_progress_report.log"

mkdir -p "$(dirname "$roadmap_summary_json")" "$(dirname "$roadmap_report_md")" "$(dirname "$summary_json")"

roadmap_script="${ROADMAP_NEXT_ACTIONS_RUN_ROADMAP_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"
ran_roadmap_report="0"

if [[ "$roadmap_paths_provided" != "1" ]]; then
  if [[ ! -f "$roadmap_script" ]]; then
    echo "missing roadmap script: $roadmap_script"
    exit 2
  fi
  if [[ ! -r "$roadmap_script" ]]; then
    echo "roadmap script is not readable: $roadmap_script"
    exit 2
  fi
  roadmap_cmd=(
    bash
    "$roadmap_script"
    --refresh-manual-validation "$refresh_manual_validation"
    --refresh-single-machine-readiness "$refresh_single_machine_readiness"
    --summary-json "$roadmap_summary_json"
    --report-md "$roadmap_report_md"
    --print-report 0
    --print-summary-json 0
  )
  echo "[roadmap-next-actions-run] stage=roadmap_progress_report status=running"
  set +e
  "${roadmap_cmd[@]}" >"$roadmap_log" 2>&1
  roadmap_rc=$?
  set -e
  if (( roadmap_rc != 0 )); then
    echo "[roadmap-next-actions-run] stage=roadmap_progress_report status=fail rc=$roadmap_rc"
    echo "roadmap_progress_report failed; see: $roadmap_log"
    exit "$roadmap_rc"
  fi
  ran_roadmap_report="1"
  echo "[roadmap-next-actions-run] stage=roadmap_progress_report status=pass rc=0"
fi

if [[ ! -f "$roadmap_summary_json" ]] || ! jq -e . "$roadmap_summary_json" >/dev/null 2>&1; then
  echo "roadmap summary JSON missing or invalid: $roadmap_summary_json"
  exit 3
fi
if [[ ! -f "$roadmap_report_md" ]]; then
  echo "roadmap report missing: $roadmap_report_md"
  exit 3
fi

include_id_suffixes_json="$(json_array_from_args "${include_id_suffixes[@]}")"
exclude_id_suffixes_json="$(json_array_from_args "${exclude_id_suffixes[@]}")"
include_ids_json="$(json_array_from_args "${include_ids[@]}")"
exclude_ids_json="$(json_array_from_args "${exclude_ids[@]}")"
selected_actions_json="$(jq -c '[ (.next_actions // [])[] | select(((.command // "") | tostring | length) > 0) ]' "$roadmap_summary_json")"
non_empty_command_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
if [[ -n "$include_id_prefix" ]]; then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --arg prefix "$include_id_prefix" '[.[] | select(((.id // "") | startswith($prefix)))]')"
fi
if [[ -n "$exclude_id_prefix" ]]; then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --arg prefix "$exclude_id_prefix" '[.[] | select(((.id // "") | startswith($prefix) | not))]')"
fi
after_prefix_filters_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
if (( ${#include_ids[@]} > 0 )); then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson ids "$include_ids_json" '[.[] | select((((.id // "") | tostring) as $id | any($ids[]; . == $id)))]')"
fi
after_include_id_filters_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
if (( ${#exclude_ids[@]} > 0 )); then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson ids "$exclude_ids_json" '[.[] | select(((((.id // "") | tostring) as $id | any($ids[]; . == $id)) | not))]')"
fi
after_exclude_id_filters_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
if (( ${#include_id_suffixes[@]} > 0 )); then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson suffixes "$include_id_suffixes_json" '[.[] | select((((.id // "") | tostring) as $id | any($suffixes[]; . as $suffix | ($id | endswith($suffix))))) ]')"
fi
after_include_suffix_filters_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
if (( ${#exclude_id_suffixes[@]} > 0 )); then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson suffixes "$exclude_id_suffixes_json" '[.[] | select(((((.id // "") | tostring) as $id | any($suffixes[]; . as $suffix | ($id | endswith($suffix)))) | not))]')"
fi
after_exclude_suffix_filters_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
before_dedupe_count="$after_exclude_suffix_filters_count"
deduped_actions_count=0
deduped_exact_duplicate_count=0
deduped_id_command_duplicate_count=0
dedupe_result_json="$(
  printf '%s\n' "$selected_actions_json" | jq -c '
    reduce .[] as $action (
      {
        actions: [],
        seen_exact: {},
        seen_id_command: {},
        deduped_exact_duplicate_count: 0,
        deduped_id_command_duplicate_count: 0
      };
      (
        ($action | tojson) as $exact_key
        | (($action.id // "") | tostring) as $id
        | (($action.command // "") | tostring) as $command
        | ($id + "\u0000" + $command) as $id_command_key
        | if (.seen_exact[$exact_key] // false) then
            .deduped_exact_duplicate_count += 1
          elif (.seen_id_command[$id_command_key] // false) then
            .deduped_id_command_duplicate_count += 1
          else
            .actions += [$action]
            | .seen_exact[$exact_key] = true
            | .seen_id_command[$id_command_key] = true
          end
      )
    )
    | .deduped_actions_count = (.deduped_exact_duplicate_count + .deduped_id_command_duplicate_count)
    | {
        actions,
        deduped_actions_count,
        deduped_exact_duplicate_count,
        deduped_id_command_duplicate_count
      }
  '
)"
selected_actions_json="$(printf '%s\n' "$dedupe_result_json" | jq -c '.actions')"
deduped_actions_count="$(printf '%s\n' "$dedupe_result_json" | jq -r '.deduped_actions_count // 0')"
deduped_exact_duplicate_count="$(printf '%s\n' "$dedupe_result_json" | jq -r '.deduped_exact_duplicate_count // 0')"
deduped_id_command_duplicate_count="$(printf '%s\n' "$dedupe_result_json" | jq -r '.deduped_id_command_duplicate_count // 0')"
after_dedupe_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
conflicting_ids_after_dedupe_json="$(
  printf '%s\n' "$selected_actions_json" | jq -c '
    group_by((.id // "") | tostring)
    | map(select(((.[0].id // "") | tostring | length) > 0 and length > 1))
    | map({
        id: ((.[0].id // "") | tostring),
        commands: (map((.command // "") | tostring))
      })
  '
)"
conflicting_ids_after_dedupe_count="$(printf '%s\n' "$conflicting_ids_after_dedupe_json" | jq -r 'length')"
if (( conflicting_ids_after_dedupe_count > 0 )); then
  conflicting_ids_after_dedupe_csv="$(printf '%s\n' "$conflicting_ids_after_dedupe_json" | jq -r 'map(.id) | join(",")')"
  echo "[roadmap-next-actions-run] fail-closed duplicate action ids with conflicting commands: $conflicting_ids_after_dedupe_csv"
  echo "roadmap next_actions contains stale/ambiguous duplicate ids; use include/exclude id filters or regenerate roadmap summary."
  exit 3
fi
before_batch_deconflict_count="$after_dedupe_count"
if printf '%s\n' "$selected_actions_json" | jq -e 'any(.[]; (.id // "") == "roadmap_live_evidence_cycle_batch_run")' >/dev/null; then
  selected_actions_json="$(
    printf '%s\n' "$selected_actions_json" | jq -c '
      [.[] | select(
        ((.id // "") != "roadmap_live_evidence_actionable_run")
        and ((.id // "") != "profile_default_gate")
        and ((.id // "") != "runtime_actuation_promotion")
        and ((.id // "") != "profile_compare_multi_vm_stability_promotion")
        and ((.id // "") != "profile_default_gate_stability_cycle")
        and ((.id // "") != "runtime_actuation_promotion_cycle")
        and ((.id // "") != "profile_compare_multi_vm_stability_promotion_cycle")
      )]
    '
  )"
fi
if printf '%s\n' "$selected_actions_json" | jq -e 'any(.[]; (.id // "") == "roadmap_live_and_pack_actionable_run")' >/dev/null; then
  selected_actions_json="$(
    printf '%s\n' "$selected_actions_json" | jq -c '
      [.[] | select(
        ((.id // "") != "roadmap_live_evidence_actionable_run")
        and ((.id // "") != "roadmap_live_evidence_cycle_batch_run")
        and ((.id // "") != "roadmap_evidence_pack_actionable_run")
        and ((.id // "") != "profile_default_gate")
        and ((.id // "") != "runtime_actuation_promotion")
        and ((.id // "") != "profile_compare_multi_vm_stability")
        and ((.id // "") != "profile_compare_multi_vm_stability_promotion")
        and ((.id // "") != "profile_default_gate_evidence_pack")
        and ((.id // "") != "runtime_actuation_promotion_evidence_pack")
        and ((.id // "") != "profile_compare_multi_vm_stability_promotion_evidence_pack")
      )]
    '
  )"
fi
if printf '%s\n' "$selected_actions_json" | jq -e 'any(.[]; (.id // "") == "profile_default_gate_evidence_pack" or (.id // "") == "runtime_actuation_promotion_evidence_pack" or (.id // "") == "profile_compare_multi_vm_stability_promotion_evidence_pack")' >/dev/null; then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c '[.[] | select((.id // "") != "roadmap_evidence_pack_actionable_run")]')"
fi
if printf '%s\n' "$selected_actions_json" | jq -e 'any(.[]; (.id // "") == "profile_default_gate" or (.id // "") == "runtime_actuation_promotion" or (.id // "") == "profile_compare_multi_vm_stability" or (.id // "") == "profile_compare_multi_vm_stability_promotion")' >/dev/null; then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c '[.[] | select((.id // "") != "roadmap_live_evidence_actionable_run")]')"
fi
after_batch_deconflict_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
if (( max_actions > 0 )); then
  selected_actions_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson max_actions "$max_actions" '.[:$max_actions]')"
fi
after_max_actions_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"

if [[ "$runtime_host_a_configured" != "1" ]]; then
  runtime_value_candidate="$(extract_first_runtime_value_from_selected_actions_01 "$selected_actions_json" extract_host_a_value_from_command_01)"
  if [[ -n "$runtime_value_candidate" ]]; then
    runtime_host_a="$runtime_value_candidate"
    runtime_host_a_source="summary_command:extracted_host_a"
    runtime_host_a_configured="1"
  fi
fi
if [[ "$runtime_host_b_configured" != "1" ]]; then
  runtime_value_candidate="$(extract_first_runtime_value_from_selected_actions_01 "$selected_actions_json" extract_host_b_value_from_command_01)"
  if [[ -n "$runtime_value_candidate" ]]; then
    runtime_host_b="$runtime_value_candidate"
    runtime_host_b_source="summary_command:extracted_host_b"
    runtime_host_b_configured="1"
  fi
fi
if [[ "$runtime_campaign_subject_configured" != "1" ]]; then
  runtime_value_candidate="$(extract_first_runtime_value_from_selected_actions_01 "$selected_actions_json" extract_campaign_subject_value_from_command_01)"
  if [[ -n "$runtime_value_candidate" ]]; then
    runtime_campaign_subject="$runtime_value_candidate"
    runtime_campaign_subject_source="summary_command:extracted_campaign_subject"
    runtime_campaign_subject_configured="1"
  fi
fi
if [[ "$runtime_vm_command_source_configured" != "1" ]]; then
  runtime_value_candidate="$(extract_first_runtime_value_from_selected_actions_01 "$selected_actions_json" extract_vm_command_source_value_from_command_01)"
  if [[ -n "$runtime_value_candidate" ]]; then
    runtime_vm_command_source="$runtime_value_candidate"
    runtime_vm_command_source_source="summary_command:extracted_vm_command_source"
    runtime_vm_command_source_configured="1"
  fi
fi

selected_has_profile_default_gate="$(printf '%s\n' "$selected_actions_json" | jq -r 'any(.[]; (.id // "") == "profile_default_gate")')"
if [[ "$selected_has_profile_default_gate" == "true" && "$action_timeout_sec" == "0" ]]; then
  need_cmd timeout
fi

actions_count="$(printf '%s\n' "$selected_actions_json" | jq -r 'length')"
selected_action_ids_json="$(printf '%s\n' "$selected_actions_json" | jq -c '[.[] | .id // "" | select(length > 0)]')"
selected_action_ids_csv="$(printf '%s\n' "$selected_action_ids_json" | jq -r 'join(",")')"
include_ids_csv_display="$(printf '%s\n' "$include_ids_json" | jq -r 'if length == 0 then "none" else join(",") end')"
exclude_ids_csv_display="$(printf '%s\n' "$exclude_ids_json" | jq -r 'if length == 0 then "none" else join(",") end')"
include_id_suffixes_csv_display="$(printf '%s\n' "$include_id_suffixes_json" | jq -r 'if length == 0 then "none" else join(",") end')"
exclude_id_suffixes_csv_display="$(printf '%s\n' "$exclude_id_suffixes_json" | jq -r 'if length == 0 then "none" else join(",") end')"
if [[ -z "$selected_action_ids_csv" ]]; then
  selected_action_ids_csv="none"
fi
echo "[roadmap-next-actions-run] selected_actions=$actions_count parallel=$parallel action_timeout_sec=$action_timeout_sec"
echo "[roadmap-next-actions-run] allow_unsafe_shell_commands=$allow_unsafe_shell_commands"
echo "[roadmap-next-actions-run] include_id_prefix=${include_id_prefix:-none} exclude_id_prefix=${exclude_id_prefix:-none}"
echo "[roadmap-next-actions-run] include_ids=$include_ids_csv_display exclude_ids=$exclude_ids_csv_display"
echo "[roadmap-next-actions-run] include_id_suffixes=$include_id_suffixes_csv_display exclude_id_suffixes=$exclude_id_suffixes_csv_display"
echo "[roadmap-next-actions-run] action_ids=$selected_action_ids_csv"
if (( actions_count == 0 )); then
  echo "[roadmap-next-actions-run] no actions selected; writing pass summary"
fi

actions_tmp="$(mktemp)"
actions_results_tmp_dir="$(mktemp -d)"
trap 'rm -f "$actions_tmp"; rm -rf "$actions_results_tmp_dir"' EXIT
: >"$actions_tmp"

declare -a action_result_files
declare -a action_pids
declare -a action_ids
declare -a action_labels
declare -a action_reasons
declare -a action_commands
declare -a action_commands_redacted
declare -a action_logs
declare -a action_timeout_secs

final_status="pass"
final_rc=0
executed_count=0
pass_count=0
fail_count=0
timed_out_count=0
soft_fail_count=0

for idx in $(seq 0 $(( actions_count - 1 )) 2>/dev/null || true); do
  action_json="$(printf '%s\n' "$selected_actions_json" | jq -c --argjson idx "$idx" '.[$idx]')"
  action_id="$(printf '%s\n' "$action_json" | jq -r '.id // ""')"
  action_label="$(printf '%s\n' "$action_json" | jq -r '.label // ""')"
  action_reason="$(printf '%s\n' "$action_json" | jq -r '.reason // ""')"
  action_command="$(printf '%s\n' "$action_json" | jq -r '.command // ""')"
  action_preflight_failure_kind=""
  action_preflight_notes=""
  action_profile_subject_resolve_detail=""
  action_preflight_next_operator_action=""
  action_has_subject_placeholder="0"
  action_resolved_subject_value=""
  action_timeout_sec_effective="$action_timeout_sec"
  if [[ "$action_id" == "profile_default_gate" && "$action_timeout_sec" == "0" ]]; then
    action_timeout_sec_effective="$profile_default_gate_default_timeout_sec"
  fi
  if action_id_is_profile_default_family "$action_id"; then
    action_command="$(
      profile_default_gate_command_apply_env_host_placeholders \
        "$action_command" \
        "$runtime_host_a" \
        "$runtime_host_b"
    )"
  fi
  if [[ "$action_id" == "profile_default_gate" ]]; then
    action_command="$(
      profile_default_gate_command_localhost_run_to_live_wrapper \
        "$action_command" \
        "$runtime_host_a" \
        "$runtime_host_b"
    )"
  fi
  if action_id_is_profile_default_family "$action_id" \
     && [[ -n "$action_command" ]] \
     && [[ "$runtime_campaign_subject_configured" == "1" ]]; then
    action_command="$(
      profile_default_gate_command_apply_subject_override_01 \
        "$action_command" \
        "$runtime_campaign_subject"
    )"
  fi
  if action_id_is_multi_vm_stability_action_01 "$action_id" \
     && [[ -n "$action_command" ]] \
     && [[ "$runtime_vm_command_source_configured" == "1" ]]; then
    action_command="$(
      multi_vm_stability_command_apply_vm_command_source_override_01 \
        "$action_command" \
        "$runtime_vm_command_source"
    )"
  fi
  if action_id_is_multi_vm_stability_action_01 "$action_id" \
     && [[ -n "$action_command" ]] \
     && command_has_vm_command_source_placeholder_01 "$action_command"; then
    action_preflight_failure_kind="missing_vm_command_source_precondition"
    action_preflight_notes="multi-vm stability vm command source placeholder token unresolved"
  fi
  if action_id_is_profile_default_family "$action_id" && [[ -n "$action_command" ]]; then
    if command_has_profile_subject_placeholder_invite_key "$action_command"; then
      action_has_subject_placeholder="1"
      if resolve_profile_default_gate_subject_value; then
        action_resolved_subject_value="$PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_VALUE"
        action_command="$(command_replace_profile_subject_placeholder "$action_command" "$action_resolved_subject_value")"
        if [[ "$COMMAND_PROFILE_SUBJECT_PLACEHOLDER_REPLACED" != "1" ]] \
           && command_has_profile_subject_placeholder_invite_key "$action_command"; then
          action_preflight_failure_kind="missing_invite_subject_precondition"
          action_preflight_notes="profile_default_gate subject placeholder token remains unresolved after normalization"
          action_profile_subject_resolve_detail="replacement_failed_resolved_source=${PROFILE_DEFAULT_GATE_SUBJECT_RESOLVED_SOURCE:-unknown}"
        fi
      else
        action_preflight_failure_kind="missing_invite_subject_precondition"
        action_preflight_notes="profile_default_gate subject placeholder token unresolved"
        action_profile_subject_resolve_detail="${PROFILE_DEFAULT_GATE_SUBJECT_RESOLVE_DETAIL:-}"
      fi
    fi
  fi
  action_id_safe="$(sanitize_id "$action_id")"
  action_log="$reports_dir/action_$((idx + 1))_${action_id_safe}.log"
  action_result_file="$actions_results_tmp_dir/action_$((idx + 1))_${action_id_safe}.json"
  action_command_redacted="$(redact_command_secrets "$action_command")"

  action_ids[$idx]="$action_id"
  action_labels[$idx]="$action_label"
  action_reasons[$idx]="$action_reason"
  action_commands[$idx]="$action_command"
  action_commands_redacted[$idx]="$action_command_redacted"
  action_logs[$idx]="$action_log"
  action_timeout_secs[$idx]="$action_timeout_sec_effective"
  action_result_files[$idx]="$action_result_file"

  if [[ -n "$action_preflight_failure_kind" ]]; then
    if [[ "$action_preflight_failure_kind" == "missing_vm_command_source_precondition" ]]; then
      action_preflight_next_operator_action="$(build_multi_vm_stability_vm_command_source_operator_command_01)"
      write_multi_vm_stability_vm_command_source_precondition_log_01 \
        "$action_log" \
        "$action_command_redacted" \
        "$action_preflight_notes" \
        "$action_preflight_next_operator_action"
    else
      action_preflight_next_operator_action="$(build_profile_default_gate_subject_operator_command)"
      write_profile_default_gate_subject_precondition_log \
        "$action_log" \
        "$action_command_redacted" \
        "$action_preflight_notes" \
        "$action_profile_subject_resolve_detail" \
        "$action_preflight_next_operator_action"
    fi
    jq -cn \
      --arg id "$action_id" \
      --arg label "$action_label" \
      --arg reason "$action_reason" \
      --arg command "$action_command_redacted" \
      --arg status "fail" \
      --arg notes "$action_preflight_notes" \
      --arg next_operator_action "$action_preflight_next_operator_action" \
      --arg log "$action_log" \
      --arg failure_kind "$action_preflight_failure_kind" \
      --argjson rc 2 \
      --argjson command_rc 2 \
      --argjson timed_out false \
      --argjson timeout_sec "$action_timeout_sec_effective" \
      '{
        id: $id,
        label: $label,
        reason: $reason,
        command: $command,
        status: $status,
        rc: $rc,
        command_rc: $command_rc,
        timed_out: $timed_out,
        timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
        failure_kind: $failure_kind,
        notes: (if $notes == "" then null else $notes end),
        next_operator_action: (if $next_operator_action == "" then null else $next_operator_action end),
        artifacts: { log: $log }
      }' >"$action_result_file"
  elif [[ -z "$action_command" ]]; then
    jq -cn \
      --arg id "$action_id" \
      --arg label "$action_label" \
      --arg reason "$action_reason" \
      --arg command "$action_command_redacted" \
      --arg status "fail" \
      --arg notes "missing command" \
      --arg log "$action_log" \
      --arg failure_kind "missing_command" \
      --argjson rc 4 \
      --argjson command_rc 4 \
      --argjson timed_out false \
      --argjson timeout_sec "$action_timeout_sec_effective" \
      '{
        id: $id,
        label: $label,
        reason: $reason,
        command: $command,
        status: $status,
        rc: $rc,
        command_rc: $command_rc,
        timed_out: $timed_out,
        timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
        failure_kind: $failure_kind,
        notes: (if $notes == "" then null else $notes end),
        artifacts: { log: $log }
      }' >"$action_result_file"
  else
    echo "[roadmap-next-actions-run] action=$action_id status=running"
    if [[ "$parallel" == "1" ]]; then
      (
        action_status="fail"
        action_rc=125
        command_rc=125
        action_timed_out="false"
        action_failure_kind="command_failed"
        action_notes="command failed"
        set +e
        run_action_command_string "$action_command" "$action_log" "$action_timeout_sec_effective"
        command_rc=$?
        set -e
        if (( command_rc == 0 )); then
          action_status="pass"
          action_rc=0
          action_notes=""
          action_failure_kind="none"
        else
          action_status="fail"
          action_rc="$command_rc"
          if (( command_rc == 124 )) && (( action_timeout_sec_effective > 0 )); then
            action_timed_out="true"
            action_failure_kind="timed_out"
            action_notes="action timed out after ${action_timeout_sec_effective}s"
          fi
        fi
        jq -cn \
          --arg id "$action_id" \
          --arg label "$action_label" \
          --arg reason "$action_reason" \
          --arg command "$action_command_redacted" \
          --arg status "$action_status" \
          --arg notes "$action_notes" \
          --arg log "$action_log" \
          --arg failure_kind "$action_failure_kind" \
          --argjson rc "$action_rc" \
          --argjson command_rc "$command_rc" \
          --argjson timed_out "$action_timed_out" \
          --argjson timeout_sec "$action_timeout_sec_effective" \
          '{
            id: $id,
            label: $label,
            reason: $reason,
            command: $command,
            status: $status,
            rc: $rc,
            command_rc: $command_rc,
            timed_out: $timed_out,
            timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
            failure_kind: $failure_kind,
            notes: (if $notes == "" then null else $notes end),
            artifacts: { log: $log }
          }' >"$action_result_file"
      ) &
      action_pids[$idx]=$!
    else
      action_status="fail"
      action_rc=125
      command_rc=125
      action_timed_out="false"
      action_failure_kind="command_failed"
      action_notes="command failed"
      set +e
      run_action_command_string "$action_command" "$action_log" "$action_timeout_sec_effective"
      command_rc=$?
      set -e
      if (( command_rc == 0 )); then
        action_status="pass"
        action_rc=0
        action_notes=""
        action_failure_kind="none"
      else
        action_status="fail"
        action_rc="$command_rc"
        if (( command_rc == 124 )) && (( action_timeout_sec_effective > 0 )); then
          action_timed_out="true"
          action_failure_kind="timed_out"
          action_notes="action timed out after ${action_timeout_sec_effective}s"
        fi
      fi
      jq -cn \
        --arg id "$action_id" \
        --arg label "$action_label" \
        --arg reason "$action_reason" \
        --arg command "$action_command_redacted" \
        --arg status "$action_status" \
        --arg notes "$action_notes" \
        --arg log "$action_log" \
        --arg failure_kind "$action_failure_kind" \
        --argjson rc "$action_rc" \
        --argjson command_rc "$command_rc" \
        --argjson timed_out "$action_timed_out" \
        --argjson timeout_sec "$action_timeout_sec_effective" \
        '{
          id: $id,
          label: $label,
          reason: $reason,
          command: $command,
          status: $status,
          rc: $rc,
          command_rc: $command_rc,
          timed_out: $timed_out,
          timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
          failure_kind: $failure_kind,
          notes: (if $notes == "" then null else $notes end),
          artifacts: { log: $log }
        }' >"$action_result_file"
    fi
  fi
done

if [[ "$parallel" == "1" ]]; then
  for idx in $(seq 0 $(( actions_count - 1 )) 2>/dev/null || true); do
    action_pid="${action_pids[$idx]:-}"
    if [[ -n "$action_pid" ]]; then
      set +e
      wait "$action_pid"
      wait_rc=$?
      set -e
      if (( wait_rc != 0 )); then
        action_id="${action_ids[$idx]}"
        action_label="${action_labels[$idx]}"
        action_reason="${action_reasons[$idx]}"
        action_command="${action_commands[$idx]}"
        action_command_redacted="${action_commands_redacted[$idx]}"
        action_log="${action_logs[$idx]}"
        action_timeout_sec_effective="${action_timeout_secs[$idx]:-$action_timeout_sec}"
        action_result_file="${action_result_files[$idx]}"
        jq -cn \
          --arg id "$action_id" \
          --arg label "$action_label" \
          --arg reason "$action_reason" \
          --arg command "$action_command_redacted" \
          --arg status "fail" \
          --arg notes "internal runner error (wait rc=$wait_rc)" \
          --arg log "$action_log" \
          --arg failure_kind "runner_error" \
          --argjson rc "$wait_rc" \
          --argjson command_rc "$wait_rc" \
          --argjson timed_out false \
          --argjson timeout_sec "$action_timeout_sec_effective" \
          '{
            id: $id,
            label: $label,
            reason: $reason,
            command: $command,
            status: $status,
            rc: $rc,
            command_rc: $command_rc,
            timed_out: $timed_out,
            timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
            failure_kind: $failure_kind,
            notes: (if $notes == "" then null else $notes end),
            artifacts: { log: $log }
          }' >"$action_result_file"
      fi
    fi
  done
fi

for idx in $(seq 0 $(( actions_count - 1 )) 2>/dev/null || true); do
  action_result_file="${action_result_files[$idx]}"
  action_id="${action_ids[$idx]}"
  action_label="${action_labels[$idx]}"
  action_reason="${action_reasons[$idx]}"
  action_command="${action_commands[$idx]}"
  action_command_redacted="${action_commands_redacted[$idx]}"
  action_log="${action_logs[$idx]}"
  action_timeout_sec_effective="${action_timeout_secs[$idx]:-$action_timeout_sec}"

  if [[ ! -s "$action_result_file" ]] || ! jq -e . "$action_result_file" >/dev/null 2>&1; then
    jq -cn \
      --arg id "$action_id" \
      --arg label "$action_label" \
      --arg reason "$action_reason" \
      --arg command "$action_command_redacted" \
      --arg status "fail" \
      --arg notes "internal runner error (missing or invalid action result)" \
      --arg log "$action_log" \
      --arg failure_kind "runner_error" \
      --argjson rc 125 \
      --argjson command_rc 125 \
      --argjson timed_out false \
      --argjson timeout_sec "$action_timeout_sec_effective" \
      '{
        id: $id,
        label: $label,
        reason: $reason,
        command: $command,
        status: $status,
        rc: $rc,
        command_rc: $command_rc,
        timed_out: $timed_out,
        timeout_sec: (if $timeout_sec > 0 then $timeout_sec else null end),
        failure_kind: $failure_kind,
        notes: (if $notes == "" then null else $notes end),
        artifacts: { log: $log }
      }' >"$action_result_file"
  fi

  action_status="$(jq -r '.status // "fail"' "$action_result_file")"
  action_rc="$(jq -r '.rc // .command_rc // 125' "$action_result_file")"
  action_timed_out="$(jq -r '.timed_out // false' "$action_result_file")"
  action_failure_kind="$(jq -r '.failure_kind // "command_failed"' "$action_result_file")"
  action_notes="$(jq -r '.notes // ""' "$action_result_file")"
  action_soft_failed="false"

  if [[ "$allow_profile_default_gate_unreachable" == "1" \
     && "$action_id" == "profile_default_gate" \
     && "$action_status" != "pass" ]]; then
    if log_has_failure_kind_marker "$action_log" "missing_invite_subject_precondition"; then
      action_status="pass"
      action_rc=0
      action_failure_kind="soft_failed_profile_default_gate_precondition"
      action_notes="soft-failed profile_default_gate missing invite-subject precondition (allow flag enabled)"
      action_soft_failed="true"
    elif log_has_failure_kind_marker "$action_log" "unreachable_directory_endpoint"; then
      action_status="pass"
      action_rc=0
      action_failure_kind="soft_failed_unreachable_profile_default_gate"
      action_notes="soft-failed unreachable profile_default_gate (allow flag enabled)"
      action_soft_failed="true"
    elif [[ -f "$action_log" ]] && grep -E -q 'profile-default-gate-run failed:[[:space:]]*missing invite key subject|provide[[:space:]]+--campaign-subject/--subject|profile-default-gate-live requires --campaign-subject INVITE_KEY|profile-default-gate-live requires invite subject' "$action_log"; then
      action_status="pass"
      action_rc=0
      action_failure_kind="soft_failed_profile_default_gate_precondition"
      action_notes="soft-failed profile_default_gate missing invite-subject precondition (allow flag enabled)"
      action_soft_failed="true"
    elif [[ -f "$action_log" ]] && grep -E -q 'profile-default-gate-run failed:[[:space:]]*unreachable directory endpoint|[[:space:]]wait-timeout[[:space:]]' "$action_log"; then
      action_status="pass"
      action_rc=0
      action_failure_kind="soft_failed_unreachable_profile_default_gate"
      action_notes="soft-failed unreachable profile_default_gate (allow flag enabled)"
      action_soft_failed="true"
    fi
  fi

  if [[ "$action_status" == "pass" && "$action_soft_failed" != "true" ]]; then
    echo "[roadmap-next-actions-run] action=$action_id status=pass rc=0"
  elif [[ "$action_status" == "pass" && "$action_soft_failed" == "true" ]]; then
    echo "[roadmap-next-actions-run] action=$action_id status=soft-fail rc=0 failure_kind=$action_failure_kind"
    echo "[roadmap-next-actions-run] action=$action_id notes=$action_notes"
    echo "[roadmap-next-actions-run] action=$action_id log=$action_log"
  else
    echo "[roadmap-next-actions-run] action=$action_id status=fail rc=$action_rc failure_kind=$action_failure_kind"
    if [[ -n "$action_notes" ]]; then
      echo "[roadmap-next-actions-run] action=$action_id notes=$action_notes"
    fi
    echo "[roadmap-next-actions-run] action=$action_id log=$action_log"
  fi

  executed_count=$((executed_count + 1))
  if [[ "$action_status" == "pass" ]]; then
    pass_count=$((pass_count + 1))
    if [[ "$action_soft_failed" == "true" ]]; then
      soft_fail_count=$((soft_fail_count + 1))
    fi
  else
    fail_count=$((fail_count + 1))
    final_status="fail"
    if (( final_rc == 0 )); then
      final_rc="$action_rc"
    fi
    if [[ "$action_timed_out" == "true" ]]; then
      timed_out_count=$((timed_out_count + 1))
    fi
  fi

  jq -c \
    --arg status "$action_status" \
    --arg failure_kind "$action_failure_kind" \
    --arg notes "$action_notes" \
    --argjson rc "$action_rc" \
    --argjson soft_failed "$action_soft_failed" \
    '.status = $status
     | .rc = $rc
     | .failure_kind = $failure_kind
     | .notes = (if $notes == "" then null else $notes end)
     | .soft_failed = $soft_failed' \
    "$action_result_file" >>"$actions_tmp"
done

actions_results_json="$(jq -s '.' "$actions_tmp")"
if (( actions_count == 0 )); then
  final_status="pass"
  final_rc=0
fi
summary_command_input="./scripts/roadmap_next_actions_run.sh"
for arg in "$@"; do
  summary_command_input="${summary_command_input} $(render_log_token "$arg")"
done
summary_command_redacted="$(redact_command_secrets "$summary_command_input")"
profile_default_gate_subject_configured="$runtime_campaign_subject_configured"
profile_default_gate_subject_redacted=""
runtime_campaign_subject_redacted=""
if [[ "$profile_default_gate_subject_configured" == "1" ]]; then
  profile_default_gate_subject_redacted="[redacted]"
  runtime_campaign_subject_redacted="[redacted]"
fi

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg command "$summary_command_redacted" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --arg roadmap_log "$roadmap_log" \
  --arg include_id_prefix "$include_id_prefix" \
  --arg exclude_id_prefix "$exclude_id_prefix" \
  --argjson include_ids "$include_ids_json" \
  --argjson exclude_ids "$exclude_ids_json" \
  --argjson include_id_suffixes "$include_id_suffixes_json" \
  --argjson exclude_id_suffixes "$exclude_id_suffixes_json" \
  --argjson non_empty_command_count "$non_empty_command_count" \
  --argjson after_prefix_filters_count "$after_prefix_filters_count" \
  --argjson after_include_id_filters_count "$after_include_id_filters_count" \
  --argjson after_exclude_id_filters_count "$after_exclude_id_filters_count" \
  --argjson after_include_suffix_filters_count "$after_include_suffix_filters_count" \
  --argjson after_exclude_suffix_filters_count "$after_exclude_suffix_filters_count" \
  --argjson before_dedupe_count "$before_dedupe_count" \
  --argjson deduped_actions_count "$deduped_actions_count" \
  --argjson deduped_exact_duplicate_count "$deduped_exact_duplicate_count" \
  --argjson deduped_id_command_duplicate_count "$deduped_id_command_duplicate_count" \
  --argjson after_dedupe_count "$after_dedupe_count" \
  --argjson after_batch_deconflict_count "$after_batch_deconflict_count" \
  --argjson after_max_actions_count "$after_max_actions_count" \
  --argjson ran_roadmap_report "$ran_roadmap_report" \
  --argjson refresh_manual_validation "$refresh_manual_validation" \
  --argjson refresh_single_machine_readiness "$refresh_single_machine_readiness" \
  --argjson parallel "$parallel" \
  --argjson max_actions "$max_actions" \
  --arg runtime_host_a "$runtime_host_a" \
  --arg runtime_host_a_source "$runtime_host_a_source" \
  --argjson runtime_host_a_configured "$runtime_host_a_configured" \
  --arg runtime_host_b "$runtime_host_b" \
  --arg runtime_host_b_source "$runtime_host_b_source" \
  --argjson runtime_host_b_configured "$runtime_host_b_configured" \
  --arg runtime_campaign_subject_redacted "$runtime_campaign_subject_redacted" \
  --arg runtime_campaign_subject_source "$runtime_campaign_subject_source" \
  --argjson runtime_campaign_subject_configured "$runtime_campaign_subject_configured" \
  --arg runtime_vm_command_source "$runtime_vm_command_source" \
  --arg runtime_vm_command_source_source "$runtime_vm_command_source_source" \
  --argjson runtime_vm_command_source_configured "$runtime_vm_command_source_configured" \
  --arg profile_default_gate_subject_redacted "$profile_default_gate_subject_redacted" \
  --argjson profile_default_gate_subject_configured "$profile_default_gate_subject_configured" \
  --argjson allow_profile_default_gate_unreachable "$allow_profile_default_gate_unreachable" \
  --argjson profile_default_gate_default_timeout_sec "$profile_default_gate_default_timeout_sec" \
  --argjson action_timeout_sec "$action_timeout_sec" \
  --argjson allow_unsafe_shell_commands "$allow_unsafe_shell_commands" \
  --argjson actions_count "$actions_count" \
  --argjson selected_action_ids "$selected_action_ids_json" \
  --argjson executed_count "$executed_count" \
  --argjson pass_count "$pass_count" \
  --argjson fail_count "$fail_count" \
  --argjson timed_out_count "$timed_out_count" \
  --argjson soft_fail_count "$soft_fail_count" \
  --argjson actions "$actions_results_json" \
  '{
    version: 1,
    schema: { id: "roadmap_next_actions_run_summary", major: 1, minor: 0 },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    command: $command,
    inputs: {
      refresh_manual_validation: ($refresh_manual_validation == 1),
      refresh_single_machine_readiness: ($refresh_single_machine_readiness == 1),
      parallel: ($parallel == 1),
      max_actions: $max_actions,
      action_timeout_sec: $action_timeout_sec,
      allow_unsafe_shell_commands: ($allow_unsafe_shell_commands == 1),
      runtime_input_precedence: "cli > env > summary_command",
      host_a: (if $runtime_host_a_configured == 1 then $runtime_host_a else null end),
      host_a_source: (if $runtime_host_a_source == "" then null else $runtime_host_a_source end),
      host_b: (if $runtime_host_b_configured == 1 then $runtime_host_b else null end),
      host_b_source: (if $runtime_host_b_source == "" then null else $runtime_host_b_source end),
      campaign_subject: (if $runtime_campaign_subject_configured == 1 then $runtime_campaign_subject_redacted else null end),
      campaign_subject_configured: ($runtime_campaign_subject_configured == 1),
      campaign_subject_source: (if $runtime_campaign_subject_source == "" then null else $runtime_campaign_subject_source end),
      vm_command_source: (if $runtime_vm_command_source_configured == 1 then $runtime_vm_command_source else null end),
      vm_command_source_configured: ($runtime_vm_command_source_configured == 1),
      vm_command_source_source: (if $runtime_vm_command_source_source == "" then null else $runtime_vm_command_source_source end),
      profile_default_gate_default_timeout_sec: $profile_default_gate_default_timeout_sec,
      profile_default_gate_subject: (if $profile_default_gate_subject_configured == 1 then $profile_default_gate_subject_redacted else null end),
      profile_default_gate_subject_configured: ($profile_default_gate_subject_configured == 1),
      allow_profile_default_gate_unreachable: ($allow_profile_default_gate_unreachable == 1),
      include_id_prefix: (if $include_id_prefix == "" then null else $include_id_prefix end),
      exclude_id_prefix: (if $exclude_id_prefix == "" then null else $exclude_id_prefix end),
      include_ids: (if ($include_ids | length) == 0 then null else $include_ids end),
      exclude_ids: (if ($exclude_ids | length) == 0 then null else $exclude_ids end),
      include_id_suffixes: (if ($include_id_suffixes | length) == 0 then null else $include_id_suffixes end),
      exclude_id_suffixes: (if ($exclude_id_suffixes | length) == 0 then null else $exclude_id_suffixes end)
    },
    roadmap: {
      generated_this_run: ($ran_roadmap_report == 1),
      actions_selected_count: $actions_count,
      selected_action_ids: $selected_action_ids,
      selection_accounting: {
        non_empty_command_count: $non_empty_command_count,
        after_prefix_filters_count: $after_prefix_filters_count,
        after_include_id_filters_count: $after_include_id_filters_count,
        after_exclude_id_filters_count: $after_exclude_id_filters_count,
        after_include_suffix_filters_count: $after_include_suffix_filters_count,
        after_exclude_suffix_filters_count: $after_exclude_suffix_filters_count,
        before_dedupe_count: $before_dedupe_count,
        deduped_actions_count: $deduped_actions_count,
        deduped_exact_duplicate_count: $deduped_exact_duplicate_count,
        deduped_id_command_duplicate_count: $deduped_id_command_duplicate_count,
        after_dedupe_count: $after_dedupe_count,
        after_batch_deconflict_count: $after_batch_deconflict_count,
        after_max_actions_count: $after_max_actions_count
      }
    },
    summary: {
      actions_executed: $executed_count,
      pass: $pass_count,
      fail: $fail_count,
      timed_out: $timed_out_count,
      soft_failed: $soft_fail_count
    },
    actions: $actions,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      roadmap_summary_json: $roadmap_summary_json,
      roadmap_report_md: $roadmap_report_md,
      roadmap_log: $roadmap_log
    }
  }' >"$summary_json"

echo "[roadmap-next-actions-run] status=$final_status rc=$final_rc selected=$actions_count executed=$executed_count pass=$pass_count fail=$fail_count"
echo "[roadmap-next-actions-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
