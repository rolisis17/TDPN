#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/runtime_actuation_promotion_evidence_pack.sh \
    [--reports-dir DIR] \
    [--promotion-cycle-summary-json PATH|--runtime-actuation-promotion-cycle-summary-json PATH] \
    [--fail-on-no-go [0|1]] \
    [--max-age-sec N] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]] \
    [--print-report [0|1]]

Purpose:
  Build a single-gate runtime-actuation promotion evidence pack from the latest
  runtime_actuation_promotion_cycle summary, failing closed when the source
  summary is missing, invalid, stale, or has unknown freshness.
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

invite_subject_placeholder_token_01() {
  local value=""
  local normalized=""
  value="$(trim "${1:-}")"
  value="$(strip_optional_wrapping_quotes_01 "$value")"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    return 1
  fi
  normalized="$(printf '%s' "$value" | tr '[:lower:]' '[:upper:]')"
  case "$normalized" in
    INVITE_KEY|\$\{INVITE_KEY\}|\$INVITE_KEY|"<INVITE_KEY>"|"{{INVITE_KEY}}"|YOUR_INVITE_KEY|YOUR_INVITE_SUBJECT|REPLACE_WITH_INVITE_KEY|REPLACE_WITH_INVITE_SUBJECT|"<SET-REAL-INVITE-KEY>"|SET-REAL-INVITE-KEY|%INVITE_KEY%|\$\{INVITE_KEY:-*}|\$\{INVITE_KEY-*}|CAMPAIGN_SUBJECT|\$\{CAMPAIGN_SUBJECT\}|\$CAMPAIGN_SUBJECT|"<CAMPAIGN_SUBJECT>"|"{{CAMPAIGN_SUBJECT}}"|YOUR_CAMPAIGN_SUBJECT|REPLACE_WITH_CAMPAIGN_SUBJECT|%CAMPAIGN_SUBJECT%|\$\{CAMPAIGN_SUBJECT:-*}|\$\{CAMPAIGN_SUBJECT-*}|"\[REDACTED\]"|"REDACTED")
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

text_has_invite_subject_issue_01() {
  local text=""
  local normalized=""
  local token=""
  local parsed=""
  text="$(trim "${1:-}")"
  text="$(strip_optional_wrapping_quotes_01 "$text")"
  text="$(trim "$text")"
  if [[ -z "$text" ]]; then
    return 1
  fi

  normalized="$(printf '%s' "$text" | tr '[:lower:]' '[:upper:]')"
  case "$normalized" in
    *"MISSING INVITE"*|*"INVITE SUBJECT"*|*"SUBJECT IS REQUIRED"*|*"CANNOT BE RESOLVED"*|*"REAL NON-PLACEHOLDER"*)
      return 0
      ;;
    *)
      ;;
  esac

  parsed="$(
    printf '%s\n' "$text" \
      | sed -E 's/["'"'"'`(),;=]/ /g'
  )"
  for token in $parsed; do
    if invite_subject_placeholder_token_01 "$token"; then
      return 0
    fi
    case "$token" in
      --subject|--campaign-subject|--invite-key|--key)
        return 0
        ;;
    esac
  done
  return 1
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

require_value_or_die() {
  local flag="$1"
  local argc="$2"
  if (( argc < 2 )); then
    echo "$flag requires a value"
    exit 2
  fi
}

is_non_negative_integer() {
  [[ "${1:-}" =~ ^[0-9]+$ ]]
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

file_mtime_epoch() {
  local path="$1"
  local raw=""
  if raw="$(stat -c %Y "$path" 2>/dev/null)"; then
    :
  elif raw="$(stat -f %m "$path" 2>/dev/null)"; then
    :
  else
    printf '%s' ""
    return
  fi
  if [[ "$raw" =~ ^[0-9]+$ ]]; then
    printf '%s' "$raw"
  else
    printf '%s' ""
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
    fail|error|failed) printf '%s\n' "fail" ;;
    warn|warning) printf '%s\n' "warn" ;;
    *) printf '%s\n' "$status" ;;
  esac
}

render_command() {
  local rendered=""
  local token=""
  for token in "$@"; do
    if [[ -n "$rendered" ]]; then
      rendered+=" "
    fi
    rendered+="$(printf '%q' "$token")"
  done
  printf '%s' "$rendered"
}

max_int_01() {
  local a="$1"
  local b="$2"
  if (( a >= b )); then
    printf '%s' "$a"
  else
    printf '%s' "$b"
  fi
}

build_runtime_actuation_cycle_rerun_command_01() {
  local reports_dir="$1"
  local cycles_override="${2:-}"
  local cycle_summary_json="$reports_dir/runtime_actuation_promotion_cycle_latest_summary.json"
  local promotion_summary_json="$reports_dir/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json"
  local -a cmd=(
    "./scripts/easy_node.sh"
    "runtime-actuation-promotion-cycle"
    "--reports-dir" "$reports_dir"
    "--promotion-summary-json" "$promotion_summary_json"
    "--summary-json" "$cycle_summary_json"
    "--fail-on-no-go" "1"
    "--print-summary-json" "1"
  )
  if [[ -n "$cycles_override" && "$cycles_override" =~ ^[0-9]+$ && "$cycles_override" -gt 0 ]]; then
    cmd+=(--cycles "$cycles_override")
  fi
  render_command "${cmd[@]}"
}

append_runtime_actuation_subject_guidance_reason_01() {
  local base_reason
  local normalized_reason=""
  local invite_subject_guidance=""
  base_reason="$(trim "${1:-}")"
  if text_has_invite_subject_issue_01 "$base_reason"; then
    normalized_reason="invite-subject input is missing, placeholder-like, or stale-like; rerun using a real invite key"
  else
    normalized_reason="$base_reason"
  fi
  invite_subject_guidance="if invite-subject auth is required, pass --subject <invite-key> (or --campaign-subject <invite-key>) or set CAMPAIGN_SUBJECT/INVITE_KEY to a real non-placeholder value"
  if [[ -n "$normalized_reason" ]]; then
    printf '%s; %s' "$normalized_reason" "$invite_subject_guidance"
  else
    printf '%s' "$invite_subject_guidance"
  fi
}

build_runtime_actuation_evidence_pack_rerun_command_01() {
  local reports_dir="$1"
  local promotion_cycle_summary_json="$2"
  local max_age_sec="$3"
  local summary_json="$4"
  local report_md="$5"
  render_command \
    "./scripts/easy_node.sh" \
    "runtime-actuation-promotion-evidence-pack" \
    "--reports-dir" "$reports_dir" \
    "--promotion-cycle-summary-json" "$promotion_cycle_summary_json" \
    "--fail-on-no-go" "1" \
    "--max-age-sec" "$max_age_sec" \
    "--summary-json" "$summary_json" \
    "--report-md" "$report_md" \
    "--print-summary-json" "1" \
    "--print-report" "1"
}

discover_latest_promotion_cycle_summary_path() {
  local reports_dir="$1"
  local preferred="$reports_dir/runtime_actuation_promotion_cycle_latest_summary.json"
  local discovered=""

  if [[ -f "$preferred" ]]; then
    printf '%s' "$preferred"
    return
  fi

  discovered="$(
    find "$reports_dir" -maxdepth 2 -type f \
      -name 'runtime_actuation_promotion_cycle_*_summary.json' \
      2>/dev/null \
      | while IFS= read -r candidate; do
          local candidate_name
          candidate_name="$(basename "$candidate")"
          case "$candidate_name" in
            runtime_actuation_promotion_cycle_latest_summary.json)
              # Preferred alias was already checked above; do not allow nested
              # alias copies to win fallback selection.
              continue
              ;;
            runtime_actuation_promotion_cycle_*_promotion_check_summary.json)
              # Promotion-check summaries are a different schema and should not
              # be selected as cycle summaries.
              continue
              ;;
            runtime_actuation_promotion_cycle_*_summary.json)
              ;;
            *)
              continue
              ;;
          esac
          [[ -f "$candidate" ]] || continue
          printf '%s\t%s\n' "$(file_mtime_epoch "$candidate")" "$candidate"
        done \
      | LC_ALL=C sort -k1,1n -k2,2 \
      | tail -n 1 \
      | cut -f2-
  )"
  if [[ -n "$discovered" ]]; then
    printf '%s' "$discovered"
    return
  fi

  printf '%s' "$preferred"
}

evaluate_promotion_cycle_summary_json() {
  local path="$1"
  local max_age_sec="$2"

  if [[ ! -f "$path" ]]; then
    jq -n --arg path "$path" --argjson max_age_sec "$max_age_sec" '{
      gate_id: "runtime_actuation_promotion_cycle",
      source_summary_json: $path,
      exists: false,
      summary_valid_json: false,
      schema_id: null,
      decision_raw: null,
      decision_normalized: null,
      status_raw: null,
      status_normalized: null,
      rc: null,
      freshness_known: false,
      freshness_ok: false,
      freshness_source: null,
      freshness_generated_at_utc: null,
      freshness_age_sec: null,
      freshness_max_age_sec: $max_age_sec,
      promotion_violation_codes: [],
      cycle_error_codes: [],
      promotion_policy_require_min_samples: null,
      promotion_policy_require_min_pass_samples: null,
      next_operator_action: null,
      failure_reason: null,
      reasons: ["summary_missing"],
      usable: false
    }'
    return
  fi

  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    jq -n --arg path "$path" --argjson max_age_sec "$max_age_sec" '{
      gate_id: "runtime_actuation_promotion_cycle",
      source_summary_json: $path,
      exists: true,
      summary_valid_json: false,
      schema_id: null,
      decision_raw: null,
      decision_normalized: null,
      status_raw: null,
      status_normalized: null,
      rc: null,
      freshness_known: false,
      freshness_ok: false,
      freshness_source: null,
      freshness_generated_at_utc: null,
      freshness_age_sec: null,
      freshness_max_age_sec: null,
      promotion_violation_codes: [],
      cycle_error_codes: [],
      promotion_policy_require_min_samples: null,
      promotion_policy_require_min_pass_samples: null,
      next_operator_action: null,
      failure_reason: null,
      reasons: ["summary_invalid_json"],
      usable: false
    }'
    return
  fi

  jq -c --arg path "$path" --argjson max_age_sec "$max_age_sec" '
    def norm_decision:
      if type == "string" then (ascii_upcase | gsub("[[:space:]_-]"; ""))
      else ""
      end;
    def canonical_decision:
      if norm_decision == "GO" then "GO"
      elif norm_decision == "NOGO" then "NO-GO"
      else null
      end;
    def norm_status:
      if type == "string" then (ascii_downcase | gsub("[[:space:]_-]"; ""))
      else ""
      end;
    def canonical_status:
      if norm_status == "pass" or norm_status == "ok" or norm_status == "success" then "pass"
      elif norm_status == "warn" or norm_status == "warning" then "warn"
      elif norm_status == "fail" or norm_status == "error" or norm_status == "failed" then "fail"
      else null
      end;
    def bool_freshness_signals:
      [
        (if (.stages.promotion_check.summary_fresh | type) == "boolean" then
          {source: "stages.promotion_check.summary_fresh", value: .stages.promotion_check.summary_fresh}
        else
          empty
        end),
        (if (.summary_fresh | type) == "boolean" then
          {source: "summary_fresh", value: .summary_fresh}
        else
          empty
        end),
        (if (.freshness.fresh | type) == "boolean" then
          {source: "freshness.fresh", value: .freshness.fresh}
        else
          empty
        end)
      ];
    def timestamp_freshness_signal:
      if (.generated_at_utc | type) == "string" then
        (try (.generated_at_utc | fromdateiso8601) catch null) as $generated_epoch
        | if $generated_epoch == null then
            {
              present: true,
              valid: false,
              source: "generated_at_utc",
              generated_at_utc: .generated_at_utc,
              age_sec: null,
              fresh: null
            }
          else
            {
              present: true,
              valid: true,
              source: "generated_at_utc",
              generated_at_utc: .generated_at_utc,
              age_sec: (now - $generated_epoch),
              fresh: (($generated_epoch <= now) and ((now - $generated_epoch) <= $max_age_sec))
            }
          end
      else
        {
          present: false,
          valid: false,
          source: null,
          generated_at_utc: null,
          age_sec: null,
          fresh: null
        }
      end;
    def freshness_value:
      (bool_freshness_signals) as $bool_signals
      | (timestamp_freshness_signal) as $time_signal
      | ($bool_signals | map(select(.value == false)) | length == 0) as $bool_all_fresh
      | ($bool_signals | map(.source)) as $bool_sources
      | ($bool_signals | length > 0) as $bool_known
      | ($time_signal.present and $time_signal.valid) as $time_known
      | ($time_signal.present and ($time_signal.valid | not)) as $time_invalid
      | {
          known: (if $time_invalid then false else ($bool_known or $time_known) end),
          fresh: (
            if $time_invalid then
              false
            else
              (if $bool_known then $bool_all_fresh else true end)
              and (if $time_known then ($time_signal.fresh == true) else true end)
            end
          ),
          source: (
            if $time_invalid then
              "generated_at_utc_invalid"
            elif $bool_known and $time_known then
              (([$time_signal.source] + $bool_sources) | join("+"))
            elif $time_known then
              $time_signal.source
            elif $bool_known then
              ($bool_sources | join("+"))
            else
              null
            end
          ),
          generated_at_utc: $time_signal.generated_at_utc,
          age_sec: $time_signal.age_sec
        };

    ((.schema // {}) | if (.id | type) == "string" then .id else "" end) as $schema_id
    | (.decision | canonical_decision) as $decision_norm
    | (.status | canonical_status) as $status_norm
    | (if (.rc | type) == "number" then .rc else null end) as $rc
    | (freshness_value) as $freshness
    | [
        (if $schema_id != "runtime_actuation_promotion_cycle_summary" then "schema_mismatch" else empty end),
        (if $decision_norm == null then "decision_missing_or_invalid" else empty end),
        (if $status_norm == null then "status_missing_or_invalid" else empty end),
        (if $rc == null then "rc_missing_or_invalid" else empty end),
        (if $freshness.source == "generated_at_utc_invalid" then "freshness_invalid_generated_at_utc" else empty end),
        (if $freshness.known == false then "freshness_unknown"
         elif $freshness.fresh == false then "freshness_stale"
         else empty
         end)
      ] as $reasons
    | {
        gate_id: "runtime_actuation_promotion_cycle",
        source_summary_json: $path,
        exists: true,
        summary_valid_json: true,
        schema_id: (if $schema_id == "" then null else $schema_id end),
        decision_raw: (if (.decision | type) == "string" then .decision else null end),
        decision_normalized: $decision_norm,
        status_raw: (if (.status | type) == "string" then .status else null end),
        status_normalized: $status_norm,
        rc: $rc,
        freshness_known: $freshness.known,
        freshness_ok: (if $freshness.known then ($freshness.fresh == true) else false end),
        freshness_source: $freshness.source,
        freshness_generated_at_utc: $freshness.generated_at_utc,
        freshness_age_sec: $freshness.age_sec,
        freshness_max_age_sec: $max_age_sec,
        promotion_violation_codes: (
          [
            (if (.promotion_check.violation_codes | type) == "array" then
              (.promotion_check.violation_codes[] | select(type == "string"))
            else
              empty
            end),
            (if (.promotion_check.violations | type) == "array" then
              (.promotion_check.violations[] | .code | select(type == "string"))
            else
              empty
            end)
          ]
          | map(select(length > 0))
          | unique
        ),
        cycle_error_codes: (
          if (.stages.cycles.error_codes | type) == "array" then
            [ .stages.cycles.error_codes[] | select(type == "string") | select(length > 0) ]
          else
            []
          end
        ),
        promotion_policy_require_min_samples: (
          if (.diagnostics.no_go.promotion_policy.require_min_samples | type) == "number" then .diagnostics.no_go.promotion_policy.require_min_samples
          elif (.promotion_check.inputs.policy.require_min_samples | type) == "number" then .promotion_check.inputs.policy.require_min_samples
          else null
          end
        ),
        promotion_policy_require_min_pass_samples: (
          if (.diagnostics.no_go.promotion_policy.require_min_pass_samples | type) == "number" then .diagnostics.no_go.promotion_policy.require_min_pass_samples
          elif (.promotion_check.inputs.policy.require_min_pass_samples | type) == "number" then .promotion_check.inputs.policy.require_min_pass_samples
          else null
          end
        ),
        next_operator_action: (
          if (.promotion_check.next_operator_action | type) == "string" and (.promotion_check.next_operator_action | length) > 0 then .promotion_check.next_operator_action
          elif (.outcome.next_operator_action | type) == "string" and (.outcome.next_operator_action | length) > 0 then .outcome.next_operator_action
          elif (.next_operator_action | type) == "string" and (.next_operator_action | length) > 0 then .next_operator_action
          else null
          end
        ),
        failure_reason: (
          if (.failure_reason | type) == "string" and (.failure_reason | length) > 0 then .failure_reason
          else null
          end
        ),
        reasons: $reasons,
        usable: (($reasons | length) == 0)
      }
  ' "$path"
}

sanitize_json_string_array() {
  jq -c '[ (. // [])[] | select(type == "string") | gsub("^\\s+|\\s+$"; "") | select(length > 0) ]'
}

need_cmd jq
need_cmd date
need_cmd find
need_cmd stat

reports_dir="${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_REPORTS_DIR:-${REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}}"
promotion_cycle_summary_json="${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_PROMOTION_CYCLE_SUMMARY_JSON:-${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_RUNTIME_ACTUATION_PROMOTION_CYCLE_SUMMARY_JSON:-}}"
summary_json="${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SUMMARY_JSON:-}"
report_md="${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_REPORT_MD:-}"
print_summary_json="${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_PRINT_SUMMARY_JSON:-0}"
print_report="${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_PRINT_REPORT:-1}"
fail_on_no_go_compat="${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_FAIL_ON_NO_GO:-1}"
max_age_sec="${RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_MAX_AGE_SEC:-86400}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      require_value_or_die "$1" "$#"
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --promotion-cycle-summary-json|--runtime-actuation-promotion-cycle-summary-json|--summary-source-json|--source-summary-json)
      require_value_or_die "$1" "$#"
      promotion_cycle_summary_json="${2:-}"
      shift 2
      ;;
    --promotion-cycle-summary-json=*|--runtime-actuation-promotion-cycle-summary-json=*|--summary-source-json=*|--source-summary-json=*)
      promotion_cycle_summary_json="${1#*=}"
      shift
      ;;
    --fail-on-no-go)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        fail_on_no_go_compat="${2:-}"
        shift 2
      else
        fail_on_no_go_compat="1"
        shift
      fi
      ;;
    --fail-on-no-go=*)
      fail_on_no_go_compat="${1#*=}"
      shift
      ;;
    --max-age-sec)
      require_value_or_die "$1" "$#"
      max_age_sec="${2:-}"
      shift 2
      ;;
    --max-age-sec=*)
      max_age_sec="${1#*=}"
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
    --report-md)
      require_value_or_die "$1" "$#"
      report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      report_md="${1#*=}"
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
    --print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_report="${2:-}"
        shift 2
      else
        print_report="1"
        shift
      fi
      ;;
    --print-report=*)
      print_report="${1#*=}"
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

reports_dir="$(abs_path "$reports_dir")"
promotion_cycle_summary_json="$(trim "$promotion_cycle_summary_json")"
summary_json="$(abs_path "$summary_json")"
report_md="$(abs_path "$report_md")"
print_summary_json="$(trim "$print_summary_json")"
print_report="$(trim "$print_report")"
fail_on_no_go_compat="$(trim "$fail_on_no_go_compat")"
max_age_sec="$(trim "$max_age_sec")"

bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go_compat"
if ! is_non_negative_integer "$max_age_sec"; then
  echo "--max-age-sec must be a non-negative integer"
  exit 2
fi

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/runtime_actuation_promotion_evidence_pack_summary.json"
fi
if [[ -z "$report_md" ]]; then
  report_md="$reports_dir/runtime_actuation_promotion_evidence_pack_report.md"
fi
summary_json="$(abs_path "$summary_json")"
report_md="$(abs_path "$report_md")"

if [[ -z "$promotion_cycle_summary_json" ]]; then
  promotion_cycle_summary_json="$(discover_latest_promotion_cycle_summary_path "$reports_dir")"
fi
if [[ -z "$promotion_cycle_summary_json" ]]; then
  promotion_cycle_summary_json="$reports_dir/runtime_actuation_promotion_cycle_latest_summary.json"
fi
promotion_cycle_summary_json="$(abs_path "$promotion_cycle_summary_json")"

mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
summary_tmp="$(mktemp "${summary_json}.tmp.XXXXXX")"
trap 'rm -f "$summary_tmp"' EXIT

source_eval_json="$(evaluate_promotion_cycle_summary_json "$promotion_cycle_summary_json" "$max_age_sec")"

source_usable="$(jq -r '.usable' <<<"$source_eval_json")"
source_decision="$(jq -r '.decision_normalized // ""' <<<"$source_eval_json")"
source_status="$(jq -r '.status_normalized // ""' <<<"$source_eval_json")"
source_rc="$(jq -r 'if (.rc | type) == "number" then .rc else null end' <<<"$source_eval_json")"
source_freshness_known="$(jq -r '.freshness_known | tostring' <<<"$source_eval_json")"
source_freshness_ok="$(jq -r '.freshness_ok | tostring' <<<"$source_eval_json")"
source_next_operator_action="$(jq -r '.next_operator_action // ""' <<<"$source_eval_json")"
source_failure_reason="$(jq -r '.failure_reason // ""' <<<"$source_eval_json")"
source_reasons_json="$(jq -c '.reasons // []' <<<"$source_eval_json")"
source_promotion_violation_codes_json="$(jq -c '.promotion_violation_codes // []' <<<"$source_eval_json")"
source_cycle_error_codes_json="$(jq -c '.cycle_error_codes // []' <<<"$source_eval_json")"
source_invite_subject_signal="false"
if text_has_invite_subject_issue_01 "$source_next_operator_action" || text_has_invite_subject_issue_01 "$source_failure_reason"; then
  source_invite_subject_signal="true"
fi
source_policy_require_min_samples="$(jq -r '
  if (.promotion_policy_require_min_samples | type) == "number" then (.promotion_policy_require_min_samples | floor | tostring)
  else "0"
  end
' <<<"$source_eval_json")"
source_policy_require_min_pass_samples="$(jq -r '
  if (.promotion_policy_require_min_pass_samples | type) == "number" then (.promotion_policy_require_min_pass_samples | floor | tostring)
  else "0"
  end
' <<<"$source_eval_json")"

declare -a reasons=()
if [[ "$source_usable" != "true" ]]; then
  while IFS= read -r reason_line; do
    [[ -n "$reason_line" ]] || continue
    reasons+=("runtime_actuation_promotion_cycle:$reason_line")
  done < <(jq -r '.reasons[]?' <<<"$source_eval_json")
fi

if [[ "$source_usable" == "true" ]]; then
  if [[ "$source_decision" != "GO" && "$source_decision" != "NO-GO" ]]; then
    reasons+=("runtime_actuation_promotion_cycle:decision missing/invalid")
  fi
  if [[ "$source_status" != "pass" && "$source_status" != "warn" && "$source_status" != "fail" ]]; then
    reasons+=("runtime_actuation_promotion_cycle:status missing/invalid")
  fi
  if [[ "$source_decision" == "GO" && "$source_status" != "pass" ]]; then
    reasons+=("runtime_actuation_promotion_cycle:go_status_not_pass")
  fi
  if [[ "$source_decision" == "GO" && "$source_rc" != "0" ]]; then
    reasons+=("runtime_actuation_promotion_cycle:go_rc_non_zero")
  fi
fi

fail_closed="true"
decision="NO-GO"
status="fail"
final_rc=1
notes="Fail-closed: runtime-actuation promotion-cycle evidence is missing, invalid, stale, or freshness-unknown."

if [[ "$source_usable" == "true" ]]; then
  decision="$source_decision"
  fail_closed="false"
  if [[ "$decision" == "GO" && "$source_status" == "pass" && "$source_rc" == "0" ]]; then
    status="pass"
    final_rc=0
    notes="Runtime-actuation promotion evidence is healthy."
  elif [[ "$decision" == "GO" ]]; then
    status="fail"
    final_rc=1
    fail_closed="true"
    notes="Fail-closed: runtime-actuation promotion-cycle decision is GO but source status/rc is degraded (status=${source_status:-unknown}, rc=${source_rc:-null})."
  elif [[ "$decision" == "NO-GO" ]]; then
    reasons+=("runtime_actuation_promotion_cycle:decision_no_go")
    if [[ "$fail_on_no_go_compat" == "1" ]]; then
      status="fail"
      final_rc=1
      notes="Evidence is usable and runtime-actuation promotion-cycle decision is NO-GO; fail-on-no-go enforcement is active."
    else
      status="warn"
      final_rc=0
      notes="Evidence is usable and runtime-actuation promotion-cycle decision is NO-GO; compatibility mode allows warn-only hold (fail-on-no-go=0)."
    fi
  else
    status="fail"
    final_rc=1
    fail_closed="true"
    notes="Fail-closed: runtime-actuation promotion-cycle decision is missing or invalid."
  fi
fi

next_operator_action="Refresh runtime-actuation promotion-cycle evidence and rerun runtime-actuation-promotion-evidence-pack."
if [[ "$source_usable" == "true" && "$decision" == "GO" && "$status" == "pass" ]]; then
  next_operator_action="No action required; runtime-actuation promotion evidence is healthy."
elif [[ -n "$source_next_operator_action" ]]; then
  next_operator_action="$source_next_operator_action"
elif [[ -n "$source_failure_reason" ]]; then
  next_operator_action="$source_failure_reason"
fi

needs_attention="true"
if [[ "$status" == "pass" && "$decision" == "GO" && "$final_rc" == "0" ]]; then
  needs_attention="false"
fi

stale_source_reason_count="$(jq -r '
  [ (. // [])[] | select(type == "string") | select(. == "freshness_stale" or . == "freshness_unknown" or . == "freshness_invalid_generated_at_utc") ]
  | length
' <<<"$source_reasons_json" 2>/dev/null || printf '%s' "0")"
threshold_violation_count="$(jq -r '
  [ (. // [])[] | select(type == "string")
    | select(
        . == "min_samples_not_met"
        or . == "min_pass_samples_not_met"
        or . == "max_fail_samples_exceeded"
        or . == "max_warn_samples_exceeded"
        or . == "ready_rate_below_threshold"
        or . == "modal_runtime_actuation_status_mismatch"
      )
  ] | length
' <<<"$source_promotion_violation_codes_json" 2>/dev/null || printf '%s' "0")"
signoff_context_violation_count="$(jq -r '
  [ (. // [])[] | select(type == "string")
    | select(
        . == "signoff_context_missing"
        or . == "runtime_actuation_diagnostics_missing"
        or . == "runtime_actuation_status_missing"
        or . == "runtime_actuation_ready_missing"
      )
  ] | length
' <<<"$source_promotion_violation_codes_json" 2>/dev/null || printf '%s' "0")"
signoff_context_cycle_error_count="$(jq -r '
  [ (. // [])[] | select(type == "string")
    | select(
        . == "signoff_decision_missing"
        or . == "signoff_summary_invalid_json"
      )
  ] | length
' <<<"$source_cycle_error_codes_json" 2>/dev/null || printf '%s' "0")"

no_go_reason_category="none"
no_go_reason_codes_json='[]'
if [[ "$needs_attention" == "true" ]]; then
  if (( stale_source_reason_count > 0 )); then
    no_go_reason_category="stale_evidence"
    no_go_reason_codes_json="$(jq -c '
      [ (. // [])[] | select(type == "string") | select(. == "freshness_stale" or . == "freshness_unknown" or . == "freshness_invalid_generated_at_utc") ]
    ' <<<"$source_reasons_json" 2>/dev/null || printf '%s' '[]')"
  elif [[ "$decision" == "NO-GO" && "$source_usable" == "true" && "$threshold_violation_count" -gt 0 ]]; then
    no_go_reason_category="pass_sample_thresholds"
    no_go_reason_codes_json="$(jq -c '
      [ (. // [])[] | select(type == "string")
        | select(
            . == "min_samples_not_met"
            or . == "min_pass_samples_not_met"
            or . == "max_fail_samples_exceeded"
            or . == "max_warn_samples_exceeded"
            or . == "ready_rate_below_threshold"
            or . == "modal_runtime_actuation_status_mismatch"
          )
      ]
    ' <<<"$source_promotion_violation_codes_json" 2>/dev/null || printf '%s' '[]')"
  elif [[ "$decision" == "NO-GO" && "$source_usable" == "true" && ( "$signoff_context_violation_count" -gt 0 || "$signoff_context_cycle_error_count" -gt 0 ) ]]; then
    no_go_reason_category="missing_signoff_context"
    no_go_reason_codes_json="$(jq -nc \
      --argjson violations "$source_promotion_violation_codes_json" \
      --argjson cycle_errors "$source_cycle_error_codes_json" \
      '[
        ($violations[]? | select(type == "string") | select(
          . == "signoff_context_missing"
          or . == "runtime_actuation_diagnostics_missing"
          or . == "runtime_actuation_status_missing"
          or . == "runtime_actuation_ready_missing"
        )),
        ($cycle_errors[]? | select(type == "string") | select(
          . == "signoff_decision_missing"
          or . == "signoff_summary_invalid_json"
        ))
      ] | unique' 2>/dev/null || printf '%s' '[]')"
  elif [[ "$source_invite_subject_signal" == "true" ]]; then
    no_go_reason_category="invite_subject_input"
    no_go_reason_codes_json='["invite_subject_input"]'
  elif [[ "$source_usable" == "false" && "$decision" == "NO-GO" ]]; then
    no_go_reason_category="missing_or_invalid_evidence"
    no_go_reason_codes_json="$source_reasons_json"
  else
    no_go_reason_category="policy_violation"
    if [[ "$source_usable" == "true" ]]; then
      no_go_reason_codes_json="$source_promotion_violation_codes_json"
    else
      no_go_reason_codes_json="$source_reasons_json"
    fi
  fi
fi

threshold_recommended_cycles=3
if [[ "$source_policy_require_min_samples" =~ ^[0-9]+$ ]]; then
  threshold_recommended_cycles="$(max_int_01 "$threshold_recommended_cycles" "$source_policy_require_min_samples")"
fi
if [[ "$source_policy_require_min_pass_samples" =~ ^[0-9]+$ ]]; then
  threshold_recommended_cycles="$(max_int_01 "$threshold_recommended_cycles" "$source_policy_require_min_pass_samples")"
fi

next_command=""
next_command_reason=""
if [[ "$needs_attention" == "true" ]]; then
  case "$no_go_reason_category" in
    pass_sample_thresholds)
      next_command="$(build_runtime_actuation_cycle_rerun_command_01 "$reports_dir" "$threshold_recommended_cycles")"
      next_command_reason="$(append_runtime_actuation_subject_guidance_reason_01 "collect enough pass-ready samples to satisfy promotion thresholds")"
      ;;
    stale_evidence)
      next_command="$(build_runtime_actuation_cycle_rerun_command_01 "$reports_dir" "")"
      next_command_reason="$(append_runtime_actuation_subject_guidance_reason_01 "refresh stale runtime-actuation promotion evidence")"
      ;;
    missing_signoff_context)
      next_command="$(build_runtime_actuation_cycle_rerun_command_01 "$reports_dir" "")"
      next_command_reason="$(append_runtime_actuation_subject_guidance_reason_01 "regenerate signoff evidence with campaign-check context")"
      ;;
    invite_subject_input)
      next_command="$(build_runtime_actuation_cycle_rerun_command_01 "$reports_dir" "")"
      next_command_reason="$(append_runtime_actuation_subject_guidance_reason_01 "provide a real invite-subject value and rerun runtime-actuation promotion evidence")"
      ;;
    missing_or_invalid_evidence)
      next_command="$(build_runtime_actuation_cycle_rerun_command_01 "$reports_dir" "")"
      next_command_reason="$(append_runtime_actuation_subject_guidance_reason_01 "recreate missing or invalid promotion-cycle evidence")"
      ;;
    *)
      next_command="$(build_runtime_actuation_cycle_rerun_command_01 "$reports_dir" "")"
      if [[ "${#reasons[@]}" -gt 0 ]]; then
        next_command_reason="$(append_runtime_actuation_subject_guidance_reason_01 "${reasons[0]}")"
      else
        next_command_reason="$(append_runtime_actuation_subject_guidance_reason_01 "$next_operator_action")"
      fi
      ;;
  esac
fi

reasons_json="$(printf '%s\n' "${reasons[@]:-}" | jq -R . | jq -s '.')"
reasons_json="$(sanitize_json_string_array <<<"$reasons_json")"
source_eval_output_json="$(jq -c '
  .reasons = (
    [ (.reasons // [])[] | select(type == "string") | gsub("^\\s+|\\s+$"; "") | select(length > 0) ]
  )
' <<<"$source_eval_json")"

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg decision "$decision" \
  --arg no_go_reason_category "$no_go_reason_category" \
  --arg notes "$notes" \
  --arg next_operator_action "$next_operator_action" \
  --arg next_command "$next_command" \
  --arg next_command_reason "$next_command_reason" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --arg source_summary_json "$promotion_cycle_summary_json" \
  --argjson rc "$final_rc" \
  --argjson fail_closed "$fail_closed" \
  --argjson needs_attention "$needs_attention" \
  --argjson fail_on_no_go "$fail_on_no_go_compat" \
  --argjson max_age_sec "$max_age_sec" \
  --argjson threshold_recommended_cycles "$threshold_recommended_cycles" \
  --argjson threshold_violation_count "$threshold_violation_count" \
  --argjson stale_source_reason_count "$stale_source_reason_count" \
  --argjson signoff_context_violation_count "$signoff_context_violation_count" \
  --argjson signoff_context_cycle_error_count "$signoff_context_cycle_error_count" \
  --argjson no_go_reason_codes "$no_go_reason_codes_json" \
  --argjson source_promotion_violation_codes "$source_promotion_violation_codes_json" \
  --argjson source_cycle_error_codes "$source_cycle_error_codes_json" \
  --argjson source_policy_require_min_samples "$source_policy_require_min_samples" \
  --argjson source_policy_require_min_pass_samples "$source_policy_require_min_pass_samples" \
  --argjson source_eval "$source_eval_output_json" \
  --argjson reasons "$reasons_json" \
  '{
    version: 1,
    schema: {
      id: "runtime_actuation_promotion_evidence_pack_summary"
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: $decision,
    available: ($source_eval.usable == true),
    helper_available: true,
    needs_attention: (if $status == "pass" and $decision == "GO" and $rc == 0 then false else true end),
    fail_closed: $fail_closed,
    reasons: $reasons,
    notes: $notes,
    next_operator_action: $next_operator_action,
    next_command: (if $next_command == "" then null else $next_command end),
    next_command_reason: (if $next_command_reason == "" then null else $next_command_reason end),
    inputs: {
      reports_dir: $reports_dir,
      fail_on_no_go: ($fail_on_no_go == 1),
      max_age_sec: $max_age_sec,
      promotion_cycle_summary_json: (if $source_summary_json == "" then null else $source_summary_json end)
    },
    source: {
      summary_json: (if $source_summary_json == "" then null else $source_summary_json end),
      exists: ($source_eval.exists == true),
      valid_json: ($source_eval.summary_valid_json == true),
      schema_id: $source_eval.schema_id,
      decision: $source_eval.decision_normalized,
      status: $source_eval.status_normalized,
      rc: $source_eval.rc,
      freshness: {
        known: $source_eval.freshness_known,
        fresh: $source_eval.freshness_ok,
        source: $source_eval.freshness_source,
        generated_at_utc: $source_eval.freshness_generated_at_utc,
        age_sec: $source_eval.freshness_age_sec,
        max_age_sec: $source_eval.freshness_max_age_sec
      },
      next_operator_action: $source_eval.next_operator_action,
      failure_reason: $source_eval.failure_reason,
      promotion_violation_codes: $source_eval.promotion_violation_codes,
      cycle_error_codes: $source_eval.cycle_error_codes,
      promotion_policy: {
        require_min_samples: $source_eval.promotion_policy_require_min_samples,
        require_min_pass_samples: $source_eval.promotion_policy_require_min_pass_samples
      },
      reasons: $source_eval.reasons,
      usable: ($source_eval.usable == true)
    },
    enforcement: {
      fail_on_no_go: ($fail_on_no_go == 1),
      fail_closed: $fail_closed,
      no_go_detected: ($decision == "NO-GO"),
      no_go_enforced: ($decision == "NO-GO" and ($fail_on_no_go == 1))
    },
    diagnostics: {
      no_go: {
        reason_category: (if $needs_attention then (if $no_go_reason_category == "" then null else $no_go_reason_category end) else null end),
        reason_codes: (if $needs_attention then $no_go_reason_codes else [] end),
        stale_source_reason_count: $stale_source_reason_count,
        threshold_violation_count: $threshold_violation_count,
        signoff_context_violation_count: $signoff_context_violation_count,
        signoff_context_cycle_error_count: $signoff_context_cycle_error_count,
        threshold_recommended_cycles: $threshold_recommended_cycles,
        source_promotion_violation_codes: $source_promotion_violation_codes,
        source_cycle_error_codes: $source_cycle_error_codes,
        source_policy: {
          require_min_samples: $source_policy_require_min_samples,
          require_min_pass_samples: $source_policy_require_min_pass_samples
        },
        remediation: {
          next_command: (if $next_command == "" then null else $next_command end),
          next_command_reason: (if $next_command_reason == "" then null else $next_command_reason end)
        }
      }
    },
    outcome: {
      should_promote: ($status == "pass" and $decision == "GO" and $rc == 0),
      action: (
        if $status == "pass" and $decision == "GO" and $rc == 0 then "promote_allowed"
        elif $status == "warn" then "hold_promotion_warn_only"
        else "hold_evidence_pack_blocked"
        end
      ),
      next_operator_action: $next_operator_action
    },
    artifacts: {
      summary_json: $summary_json,
      report_md: $report_md
    }
  }' >"$summary_tmp"

mv -f "$summary_tmp" "$summary_json"

{
  printf '# Runtime Actuation Promotion Evidence Pack\n\n'
  printf -- '- Generated at (UTC): %s\n' "$(jq -r '.generated_at_utc' "$summary_json")"
  printf -- '- Status: %s\n' "$(jq -r '.status' "$summary_json")"
  printf -- '- Decision: %s\n' "$(jq -r '.decision' "$summary_json")"
  printf -- '- RC: %s\n' "$(jq -r '.rc' "$summary_json")"
  printf -- '- Fail closed: %s\n' "$(jq -r '.fail_closed | tostring' "$summary_json")"
  printf -- '- Available: %s\n' "$(jq -r '.available | tostring' "$summary_json")"
  printf -- '- Needs attention: %s\n' "$(jq -r '.needs_attention | tostring' "$summary_json")"
  printf -- '- Next operator action: %s\n' "$(jq -r '.next_operator_action // "none"' "$summary_json")"
  printf '\n'
  printf '## Source Summary\n\n'
  printf -- '- Source summary: %s\n' "$(jq -r '.source.summary_json // "none"' "$summary_json")"
  printf -- '- Usable: %s\n' "$(jq -r '.source.usable | tostring' "$summary_json")"
  printf -- '- Decision/status/rc: %s / %s / %s\n' \
    "$(jq -r '.source.decision // "unknown"' "$summary_json")" \
    "$(jq -r '.source.status // "unknown"' "$summary_json")" \
    "$(jq -r '.source.rc // "null"' "$summary_json")"
  printf -- '- Freshness known: %s\n' "$(jq -r '.source.freshness.known | tostring' "$summary_json")"
  printf -- '- Freshness fresh: %s\n' "$(jq -r '.source.freshness.fresh | if . == null then "unknown" else tostring end' "$summary_json")"
  printf -- '- Freshness source: %s\n' "$(jq -r '.source.freshness.source // "unknown"' "$summary_json")"
  printf -- '- Reasons: %s\n' "$(jq -r '.source.reasons | if length == 0 then "none" else join("; ") end' "$summary_json")"
  printf '\n'
  printf '## Reasons\n\n'
  if [[ "$(jq -r '.reasons | length' "$summary_json")" -eq 0 ]]; then
    printf -- '- none\n'
  else
    jq -r '.reasons[]' "$summary_json" | while IFS= read -r reason_line; do
      printf -- '- %s\n' "$reason_line"
    done
  fi
  printf '\n'
  printf '## Next Action\n\n'
  printf -- '%s\n' "$(jq -r '.next_command // "none"' "$summary_json")"
} >"$report_md"

final_status="$(jq -r '.status' "$summary_json")"
final_rc="$(jq -r '.rc' "$summary_json")"
final_decision="$(jq -r '.decision' "$summary_json")"
echo "[runtime-actuation-promotion-evidence-pack] status=$final_status rc=$final_rc decision=${final_decision:-unset} summary_json=$summary_json report_md=$report_md"

if [[ "$print_report" == "1" ]]; then
  cat "$report_md"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
