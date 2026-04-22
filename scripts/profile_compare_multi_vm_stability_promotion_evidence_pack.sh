#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/profile_compare_multi_vm_stability_promotion_evidence_pack.sh \
    [--reports-dir DIR] \
    [--promotion-cycle-summary-json PATH] \
    [--fail-on-no-go [0|1]] \
    [--max-age-sec N] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Build one deterministic multi-VM stability promotion evidence pack from a
  single promotion-cycle summary, fail-closed when required evidence is
  missing, malformed, or freshness-unknown/stale.
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
  printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]'
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

iso8601_to_epoch() {
  local ts="$1"
  if [[ -z "$ts" ]]; then
    return 1
  fi
  jq -nr --arg ts "$ts" 'try ($ts | fromdateiso8601) catch empty'
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

json_array_from_lines() {
  if [[ $# -eq 0 ]]; then
    printf '[]'
    return
  fi
  printf '%s\n' "$@" | jq -R . | jq -s .
}

latest_matching_summary_json() {
  local reports_dir="$1"
  local prefix="$2"
  local best_path=""
  local best_mtime="-1"
  local candidate=""
  local mtime=""
  local found_any="0"

  shopt -s nullglob
  local candidates=(
    "$reports_dir"/"$prefix"*.json
    "$reports_dir"/"${prefix%_summary}"*/"$prefix".json
  )
  shopt -u nullglob

  for candidate in "${candidates[@]}"; do
    [[ -f "$candidate" ]] || continue
    found_any="1"
    mtime="$(file_mtime_epoch "$candidate")"
    if [[ "$mtime" =~ ^[0-9]+$ ]]; then
      if (( mtime > best_mtime )); then
        best_mtime="$mtime"
        best_path="$candidate"
      fi
    elif [[ -z "$best_path" ]]; then
      best_path="$candidate"
    fi
  done

  if [[ "$found_any" != "1" ]]; then
    printf '%s' ""
    return
  fi
  printf '%s' "$best_path"
}

discover_latest_promotion_cycle_summary_path() {
  local reports_dir="$1"
  local preferred="$reports_dir/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
  local discovered=""

  if [[ -f "$preferred" ]]; then
    printf '%s' "$preferred"
    return
  fi

  discovered="$(latest_matching_summary_json "$reports_dir" "profile_compare_multi_vm_stability_promotion_cycle_summary")"
  if [[ -n "$discovered" ]]; then
    printf '%s' "$discovered"
    return
  fi

  printf '%s' "$preferred"
}

collect_promotion_cycle_evidence() {
  local path="$1"
  local expected_schema_id="$2"
  local max_age_sec="$3"

  local exists="0"
  local valid_json="0"
  local schema_id=""
  local schema_valid="false"
  local status_value=""
  local status_normalized=""
  local status_valid="false"
  local rc_raw=""
  local rc_valid="false"
  local decision_value=""
  local decision_normalized=""
  local decision_valid="false"
  local generated_at_utc=""
  local freshness_known="false"
  local freshness_fresh=""
  local freshness_age_sec=""
  local next_operator_action=""
  local generated_epoch=""
  local now_epoch
  now_epoch="$(date -u +%s)"
  local -a errors=()

  if [[ -n "$path" && -f "$path" ]]; then
    exists="1"
  else
    errors+=("missing required evidence file: ${path:-unset}")
  fi

  if [[ "$exists" == "1" ]]; then
    valid_json="$(json_file_valid_01 "$path")"
    if [[ "$valid_json" != "1" ]]; then
      errors+=("invalid JSON object payload")
    fi
  fi

  if [[ "$exists" == "1" && "$valid_json" == "1" ]]; then
    schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "$path" 2>/dev/null || printf '%s' "")"
    if [[ "$schema_id" == "$expected_schema_id" ]]; then
      schema_valid="true"
    else
      errors+=("schema.id mismatch (expected=${expected_schema_id} actual=${schema_id:-unset})")
    fi

    status_value="$(jq -r 'if (.status | type) == "string" then .status else "" end' "$path" 2>/dev/null || printf '%s' "")"
    status_normalized="$(normalize_status "$status_value")"
    case "$status_normalized" in
      pass|warn|fail|ok)
        status_valid="true"
        ;;
      *)
        errors+=("status missing or invalid (actual=${status_value:-unset})")
        ;;
    esac

    rc_raw="$(jq -r '
      if (.rc | type) == "number" then (.rc | tostring)
      elif (.final_rc | type) == "number" then (.final_rc | tostring)
      else ""
      end
    ' "$path" 2>/dev/null || printf '%s' "")"
    if [[ "$rc_raw" =~ ^-?[0-9]+$ ]]; then
      rc_valid="true"
    else
      errors+=("rc missing or invalid (expected numeric rc/final_rc)")
    fi

    decision_value="$(jq -r 'if (.decision | type) == "string" then .decision else "" end' "$path" 2>/dev/null || printf '%s' "")"
    decision_normalized="$(normalize_decision "$decision_value")"
    if [[ "$decision_normalized" == "GO" || "$decision_normalized" == "NO-GO" ]]; then
      decision_valid="true"
    else
      errors+=("decision missing or invalid GO/NO-GO value (actual=${decision_value:-unset})")
    fi

    generated_at_utc="$(jq -r 'if (.generated_at_utc | type) == "string" then .generated_at_utc else "" end' "$path" 2>/dev/null || printf '%s' "")"
    if [[ -z "$generated_at_utc" ]]; then
      errors+=("generated_at_utc missing")
    else
      generated_epoch="$(iso8601_to_epoch "$generated_at_utc" 2>/dev/null || true)"
      if [[ "$generated_epoch" =~ ^[0-9]+$ ]]; then
        if (( generated_epoch <= now_epoch )); then
          freshness_known="true"
          freshness_age_sec="$((now_epoch - generated_epoch))"
          if (( freshness_age_sec <= max_age_sec )); then
            freshness_fresh="true"
          else
            freshness_fresh="false"
            errors+=("stale evidence (age_sec=${freshness_age_sec} max_age_sec=${max_age_sec})")
          fi
        else
          errors+=("generated_at_utc is in the future")
        fi
      else
        errors+=("generated_at_utc invalid ISO-8601 UTC timestamp")
      fi
    fi

    next_operator_action="$(jq -r '
      if (.next_operator_action | type) == "string" and (.next_operator_action | length) > 0 then .next_operator_action
      elif (.outcome.next_operator_action | type) == "string" and (.outcome.next_operator_action | length) > 0 then .outcome.next_operator_action
      else ""
      end
    ' "$path" 2>/dev/null || printf '%s' "")"
  fi

  local errors_json
  errors_json="$(json_array_from_lines "${errors[@]:-}")"

  local usable="false"
  if [[ "$exists" == "1" \
    && "$valid_json" == "1" \
    && "$schema_valid" == "true" \
    && "$status_valid" == "true" \
    && "$rc_valid" == "true" \
    && "$decision_valid" == "true" \
    && "$freshness_known" == "true" \
    && "$freshness_fresh" == "true" ]]; then
    usable="true"
  fi

  jq -n \
    --arg path "$path" \
    --arg expected_schema_id "$expected_schema_id" \
    --arg schema_id "$schema_id" \
    --arg schema_valid "$schema_valid" \
    --arg status_value "$status_value" \
    --arg status_normalized "$status_normalized" \
    --arg status_valid "$status_valid" \
    --arg rc_raw "$rc_raw" \
    --arg rc_valid "$rc_valid" \
    --arg decision_value "$decision_value" \
    --arg decision_normalized "$decision_normalized" \
    --arg decision_valid "$decision_valid" \
    --arg generated_at_utc "$generated_at_utc" \
    --arg freshness_known "$freshness_known" \
    --arg freshness_fresh "$freshness_fresh" \
    --arg freshness_age_sec "$freshness_age_sec" \
    --arg next_operator_action "$next_operator_action" \
    --arg exists "$exists" \
    --arg valid_json "$valid_json" \
    --arg usable "$usable" \
    --argjson max_age_sec "$max_age_sec" \
    --argjson errors "$errors_json" \
    '{
      path: (if $path == "" then null else $path end),
      exists: ($exists == "1"),
      valid_json: ($valid_json == "1"),
      schema: {
        expected_id: $expected_schema_id,
        observed_id: (if $schema_id == "" then null else $schema_id end),
        valid: ($schema_valid == "true")
      },
      status: {
        value: (if $status_value == "" then null else $status_value end),
        normalized: (if $status_normalized == "" then null else $status_normalized end),
        valid: ($status_valid == "true")
      },
      rc: {
        value: (if $rc_valid == "true" then ($rc_raw | tonumber) else null end),
        valid: ($rc_valid == "true")
      },
      decision: {
        value: (if $decision_value == "" then null else $decision_value end),
        normalized: (if $decision_normalized == "" then null else $decision_normalized end),
        valid: ($decision_valid == "true")
      },
      freshness: {
        generated_at_utc: (if $generated_at_utc == "" then null else $generated_at_utc end),
        known: ($freshness_known == "true"),
        fresh: (
          if $freshness_known != "true" then null
          elif $freshness_fresh == "true" then true
          elif $freshness_fresh == "false" then false
          else null
          end
        ),
        age_sec: (if $freshness_age_sec == "" then null else ($freshness_age_sec | tonumber) end),
        max_age_sec: $max_age_sec
      },
      next_operator_action: (if $next_operator_action == "" then null else $next_operator_action end),
      usable: ($usable == "true"),
      errors: $errors
    }'
}

need_cmd jq
need_cmd date
need_cmd stat
need_cmd find
need_cmd tail

reports_dir="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_REPORTS_DIR:-${REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}}"
promotion_cycle_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_PROMOTION_CYCLE_SUMMARY_JSON:-}"
fail_on_no_go_compat="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_FAIL_ON_NO_GO:-1}"
max_age_sec="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_MAX_AGE_SEC:-86400}"
summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_SUMMARY_JSON:-}"
report_md="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_REPORT_MD:-}"
print_summary_json="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_EVIDENCE_PACK_PRINT_SUMMARY_JSON:-0}"

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
    --promotion-cycle-summary-json)
      require_value_or_die "$1" "$#"
      promotion_cycle_summary_json="${2:-}"
      shift 2
      ;;
    --promotion-cycle-summary-json=*)
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

reports_dir="$(abs_path "$reports_dir")"
promotion_cycle_summary_json="$(trim "$promotion_cycle_summary_json")"
fail_on_no_go_compat="$(trim "$fail_on_no_go_compat")"
max_age_sec="$(trim "$max_age_sec")"
summary_json="$(trim "$summary_json")"
report_md="$(trim "$report_md")"
print_summary_json="$(trim "$print_summary_json")"

bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go_compat"
if ! is_non_negative_integer "$max_age_sec"; then
  echo "--max-age-sec must be a non-negative integer"
  exit 2
fi

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/profile_compare_multi_vm_stability_promotion_evidence_pack_summary.json"
fi
if [[ -z "$report_md" ]]; then
  report_md="$reports_dir/profile_compare_multi_vm_stability_promotion_evidence_pack_report.md"
fi

summary_json="$(abs_path "$summary_json")"
report_md="$(abs_path "$report_md")"

if [[ -z "$promotion_cycle_summary_json" ]]; then
  promotion_cycle_summary_json="$(discover_latest_promotion_cycle_summary_path "$reports_dir")"
fi
promotion_cycle_summary_json="$(abs_path "$promotion_cycle_summary_json")"

mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

promotion_cycle_evidence="$(collect_promotion_cycle_evidence "$promotion_cycle_summary_json" "profile_compare_multi_vm_stability_promotion_cycle_summary" "$max_age_sec")"

declare -a reasons=()
promotion_cycle_usable="$(jq -r '.usable' <<<"$promotion_cycle_evidence")"
if [[ "$promotion_cycle_usable" != "true" ]]; then
  while IFS= read -r err_line; do
    [[ -n "$err_line" ]] || continue
    reasons+=("promotion_cycle: $err_line")
  done < <(jq -r '.errors[]?' <<<"$promotion_cycle_evidence")
  if [[ "$(jq -r '.errors | length' <<<"$promotion_cycle_evidence")" == "0" ]]; then
    reasons+=("promotion_cycle: evidence unusable")
  fi
fi

promotion_cycle_decision="$(jq -r '.decision.normalized // ""' <<<"$promotion_cycle_evidence")"
promotion_cycle_status="$(jq -r '.status.normalized // ""' <<<"$promotion_cycle_evidence")"
if [[ "$promotion_cycle_decision" != "GO" && "$promotion_cycle_decision" != "NO-GO" ]]; then
  reasons+=("promotion_cycle: decision missing/invalid")
fi
if [[ "$promotion_cycle_status" != "pass" && "$promotion_cycle_status" != "warn" && "$promotion_cycle_status" != "fail" && "$promotion_cycle_status" != "ok" ]]; then
  reasons+=("promotion_cycle: status missing/invalid")
fi

input_next_operator_action="$(jq -r '.next_operator_action // ""' <<<"$promotion_cycle_evidence")"
operator_next_action_command="./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --reports-dir .easy-node-logs --summary-json .easy-node-logs/profile_compare_multi_vm_stability_promotion_cycle_summary.json --print-summary-json 1"

status="fail"
decision="NO-GO"
rc=1
failure_reason=""
next_operator_action=""

if [[ "${#reasons[@]}" -eq 0 ]]; then
  decision="$promotion_cycle_decision"
  if [[ "$decision" == "GO" ]]; then
    status="ok"
    rc=0
  elif [[ "$decision" == "NO-GO" ]]; then
    if [[ "$fail_on_no_go_compat" == "1" ]]; then
      status="fail"
      rc=1
      failure_reason="promotion-cycle decision is NO-GO"
    else
      status="warn"
      rc=0
    fi
  else
    status="fail"
    rc=1
    failure_reason="promotion-cycle decision is missing or invalid"
  fi
  if [[ -n "$input_next_operator_action" ]]; then
    next_operator_action="$input_next_operator_action"
  elif [[ "$decision" == "GO" ]]; then
    next_operator_action="Promotion may proceed. Continue monitoring multi-VM stability promotion cycles."
  else
    next_operator_action="Hold promotion. Resolve blockers and rerun profile_compare_multi_vm_stability_promotion_cycle.sh."
  fi
else
  failure_reason="${reasons[0]}"
  next_operator_action="Refresh profile_compare_multi_vm_stability_promotion_cycle_summary.json and rerun profile_compare_multi_vm_stability_promotion_evidence_pack.sh."
fi

reasons_json="$(json_array_from_lines "${reasons[@]:-}")"

summary_payload="$(jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg decision "$decision" \
  --arg failure_reason "$failure_reason" \
  --arg reports_dir "$reports_dir" \
  --arg promotion_cycle_summary_json "$promotion_cycle_summary_json" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --arg next_operator_action "$next_operator_action" \
  --arg operator_next_action_command "$operator_next_action_command" \
  --argjson rc "$rc" \
  --argjson fail_on_no_go "$fail_on_no_go_compat" \
  --argjson reasons "$reasons_json" \
  --argjson promotion_cycle_evidence "$promotion_cycle_evidence" \
  '{
    version: 1,
    schema: {
      id: "profile_compare_multi_vm_stability_promotion_evidence_pack_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    decision: $decision,
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    reasons: $reasons,
    inputs: {
      reports_dir: $reports_dir,
      fail_on_no_go: ($fail_on_no_go == 1)
    },
    evidence: {
      promotion_cycle: $promotion_cycle_evidence
    },
    next_operator_action: $next_operator_action,
    operator_next_action_command: $operator_next_action_command,
    outcome: {
      should_promote: ($status == "ok" and $decision == "GO" and $rc == 0),
      action: (
        if $status == "ok" and $decision == "GO" and $rc == 0 then "promote_allowed"
        elif $status == "warn" then "hold_promotion_warn_only"
        else "hold_evidence_pack_blocked"
        end
      ),
      next_operator_action: $next_operator_action
    },
    artifacts: {
      summary_json: $summary_json,
      report_md: $report_md,
      promotion_cycle_summary_json: $promotion_cycle_summary_json
    }
  }')"

printf '%s\n' "$summary_payload" >"$summary_json"

{
  echo "# Profile Compare Multi-VM Stability Promotion Evidence Pack"
  echo
  echo "- Generated at (UTC): $(jq -r '.generated_at_utc' <<<"$summary_payload")"
  echo "- Status: $(jq -r '.status' <<<"$summary_payload")"
  echo "- Decision: $(jq -r '.decision' <<<"$summary_payload")"
  echo "- RC: $(jq -r '.rc' <<<"$summary_payload")"
  echo "- Reports dir: $reports_dir"
  echo
  echo "## Evidence"
  echo
  echo "- Promotion cycle summary: $promotion_cycle_summary_json"
  echo "- Usable: $(jq -r '.evidence.promotion_cycle.usable | tostring' <<<"$summary_payload")"
  echo "- Freshness: $(jq -r '.evidence.promotion_cycle.freshness.fresh | if . == null then "unknown" else tostring end' <<<"$summary_payload")"
  echo "- Decision/status: $(jq -r '.evidence.promotion_cycle.decision.normalized // "unknown"' <<<"$summary_payload") / $(jq -r '.evidence.promotion_cycle.status.normalized // "unknown"' <<<"$summary_payload")"
  echo
  echo "## Reasons"
  if [[ "$(jq -r '.reasons | length' <<<"$summary_payload")" -eq 0 ]]; then
    echo
    echo "- none"
  else
    while IFS= read -r reason_line; do
      echo "- $reason_line"
    done < <(jq -r '.reasons[]' <<<"$summary_payload")
  fi
  echo
  echo "## Next Action"
  echo
  echo "$next_operator_action"
  echo
  echo "## Next Action Command"
  echo
  echo "\`$operator_next_action_command\`"
} >"$report_md"

echo "[profile-compare-multi-vm-stability-promotion-evidence-pack] status=$status rc=$rc decision=$decision summary_json=$summary_json"
echo "[profile-compare-multi-vm-stability-promotion-evidence-pack] report_md=$report_md"

if [[ "$print_summary_json" == "1" ]]; then
  echo "[profile-compare-multi-vm-stability-promotion-evidence-pack] summary_json_payload:"
  cat "$summary_json"
fi

exit "$rc"
