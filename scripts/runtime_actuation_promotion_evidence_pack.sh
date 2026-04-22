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
    def freshness_value:
      if (.stages.promotion_check.summary_fresh | type) == "boolean" then
        {known: true, fresh: .stages.promotion_check.summary_fresh, source: "stages.promotion_check.summary_fresh", generated_at_utc: null, age_sec: null}
      elif (.summary_fresh | type) == "boolean" then
        {known: true, fresh: .summary_fresh, source: "summary_fresh", generated_at_utc: null, age_sec: null}
      elif (.freshness.fresh | type) == "boolean" then
        {known: true, fresh: .freshness.fresh, source: "freshness.fresh", generated_at_utc: (.freshness.generated_at_utc // null), age_sec: (.freshness.age_sec // null)}
      elif (.generated_at_utc | type) == "string" then
        (try (.generated_at_utc | fromdateiso8601) catch null) as $generated_epoch
        | if $generated_epoch == null then
            {known: false, fresh: null, source: null, generated_at_utc: .generated_at_utc, age_sec: null}
          else
            {known: true,
             fresh: (($generated_epoch <= now) and ((now - $generated_epoch) <= $max_age_sec)),
             source: "generated_at_utc",
             generated_at_utc: .generated_at_utc,
             age_sec: (now - $generated_epoch)}
          end
      else
        {known: false, fresh: null, source: null, generated_at_utc: null, age_sec: null}
      end;

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
  if [[ "$source_rc" != "0" && "$source_rc" != "1" && "$source_rc" != "2" && "$source_rc" != "3" && "$source_rc" != "4" && "$source_rc" != "5" && "$source_rc" != "6" && "$source_rc" != "7" && "$source_rc" != "8" && "$source_rc" != "9" ]]; then
    :
  fi
fi

fail_closed="false"
if [[ "$source_usable" != "true" ]]; then
  fail_closed="true"
fi

decision="NO-GO"
status="fail"
final_rc=1
notes="Fail-closed: runtime-actuation promotion-cycle evidence is missing, invalid, stale, or freshness-unknown."

if [[ "$source_usable" == "true" ]]; then
  decision="$source_decision"
  if [[ "$decision" == "GO" && "$source_status" == "pass" && "$source_rc" == "0" ]]; then
    status="pass"
    final_rc=0
    notes="Runtime-actuation promotion evidence is healthy."
  else
    if [[ "$fail_on_no_go_compat" == "1" ]]; then
      status="fail"
      final_rc=1
    else
      status="warn"
      final_rc=0
    fi
    notes="Evidence is usable but runtime-actuation promotion-cycle decision is NO-GO."
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

next_command=""
next_command_reason=""
if [[ "$needs_attention" == "true" ]]; then
  next_command="./scripts/easy_node.sh runtime-actuation-promotion-evidence-pack --reports-dir .easy-node-logs --fail-on-no-go 1 --summary-json .easy-node-logs/runtime_actuation_promotion_evidence_pack_summary.json --print-summary-json 1"
  if [[ "${#reasons[@]}" -gt 0 ]]; then
    next_command_reason="${reasons[0]}"
  else
    next_command_reason="$next_operator_action"
  fi
fi

reasons_json="$(printf '%s\n' "${reasons[@]:-}" | jq -R . | jq -s '.')"

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg decision "$decision" \
  --arg notes "$notes" \
  --arg next_operator_action "$next_operator_action" \
  --arg next_command "$next_command" \
  --arg next_command_reason "$next_command_reason" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --arg source_summary_json "$promotion_cycle_summary_json" \
  --argjson rc "$final_rc" \
  --argjson fail_on_no_go "$fail_on_no_go_compat" \
  --argjson max_age_sec "$max_age_sec" \
  --argjson source_eval "$source_eval_json" \
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
    fail_closed: (if $source_eval.usable == true then false else true end),
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
      reasons: $source_eval.reasons,
      usable: ($source_eval.usable == true)
    },
    enforcement: {
      fail_on_no_go: ($fail_on_no_go == 1),
      fail_closed: (if $source_eval.usable == true then false else true end),
      no_go_detected: ($decision == "NO-GO"),
      no_go_enforced: ($decision == "NO-GO" and ($fail_on_no_go == 1))
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
