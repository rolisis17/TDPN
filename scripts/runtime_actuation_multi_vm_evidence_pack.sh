#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/runtime_actuation_multi_vm_evidence_pack.sh \
    [--reports-dir DIR] \
    [--runtime-actuation-promotion-cycle-summary-json PATH] \
    [--multi-vm-stability-promotion-cycle-summary-json PATH] \
    [--fail-on-no-go [0|1]] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]] \
    [--print-report [0|1]]

Purpose:
  Build one consolidated evidence pack from the latest:
    - runtime_actuation_promotion_cycle_summary
    - profile_compare_multi_vm_stability_promotion_cycle_summary

Fail-closed rules:
  - Missing summary
  - Invalid JSON object
  - Unexpected schema id
  - Freshness unknown (missing/non-boolean freshness field)
  - Freshness stale (freshness field is false)
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

json_file_valid_01() {
  local path="$1"
  if [[ -f "$path" ]] && jq -e 'type == "object"' "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

discover_latest_runtime_cycle_summary_path() {
  local reports_dir="$1"
  local preferred="$reports_dir/runtime_actuation_promotion_cycle_latest_summary.json"
  local discovered=""

  if [[ -f "$preferred" ]]; then
    printf '%s' "$preferred"
    return
  fi

  discovered="$(find "$reports_dir" -maxdepth 1 -type f -name 'runtime_actuation_promotion_cycle_*_summary.json' 2>/dev/null | LC_ALL=C sort | tail -n 1)"
  if [[ -n "$discovered" ]]; then
    printf '%s' "$discovered"
    return
  fi

  printf '%s' "$preferred"
}

discover_latest_multi_vm_cycle_summary_path() {
  local reports_dir="$1"
  local preferred="$reports_dir/profile_compare_multi_vm_stability_promotion_cycle_summary.json"
  local discovered=""

  if [[ -f "$preferred" ]]; then
    printf '%s' "$preferred"
    return
  fi

  discovered="$(
    find "$reports_dir" -maxdepth 2 -type f \
      -name 'profile_compare_multi_vm_stability_promotion_cycle_summary.json' \
      -path "$reports_dir/profile_compare_multi_vm_stability_promotion_cycle_*/profile_compare_multi_vm_stability_promotion_cycle_summary.json" \
      2>/dev/null \
      | LC_ALL=C sort \
      | tail -n 1
  )"
  if [[ -n "$discovered" ]]; then
    printf '%s' "$discovered"
    return
  fi

  printf '%s' "$preferred"
}

evaluate_runtime_cycle_summary_json() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    jq -n --arg path "$path" '{
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
      freshness_value: null,
      next_operator_action: null,
      failure_reason: null,
      reasons: ["summary_missing"],
      usable: false
    }'
    return
  fi

  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    jq -n --arg path "$path" '{
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
      freshness_value: null,
      next_operator_action: null,
      failure_reason: null,
      reasons: ["summary_invalid_json"],
      usable: false
    }'
    return
  fi

  jq -c --arg path "$path" '
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

    ((.schema // {}) | if (.id | type) == "string" then .id else "" end) as $schema_id
    | (.decision | canonical_decision) as $decision_norm
    | (.status | canonical_status) as $status_norm
    | (if (.rc | type) == "number" then .rc else null end) as $rc
    | ((.stages // {}) | (.promotion_check // {})) as $promotion_check_stage
    | (if ($promotion_check_stage.summary_fresh | type) == "boolean" then $promotion_check_stage.summary_fresh else null end) as $summary_fresh
    | [
        (if $schema_id != "runtime_actuation_promotion_cycle_summary" then "schema_mismatch" else empty end),
        (if $decision_norm == null then "decision_missing_or_invalid" else empty end),
        (if $status_norm == null then "status_missing_or_invalid" else empty end),
        (if $rc == null then "rc_missing_or_invalid" else empty end),
        (if $summary_fresh == null then "freshness_unknown"
         elif $summary_fresh == false then "freshness_stale"
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
        freshness_known: ($summary_fresh != null),
        freshness_ok: ($summary_fresh == true),
        freshness_value: $summary_fresh,
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

evaluate_multi_vm_cycle_summary_json() {
  local path="$1"
  if [[ ! -f "$path" ]]; then
    jq -n --arg path "$path" '{
      gate_id: "multi_vm_stability_promotion_cycle",
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
      freshness_value: null,
      next_operator_action: null,
      failure_reason: null,
      reasons: ["summary_missing"],
      usable: false
    }'
    return
  fi

  if [[ "$(json_file_valid_01 "$path")" != "1" ]]; then
    jq -n --arg path "$path" '{
      gate_id: "multi_vm_stability_promotion_cycle",
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
      freshness_value: null,
      next_operator_action: null,
      failure_reason: null,
      reasons: ["summary_invalid_json"],
      usable: false
    }'
    return
  fi

  jq -c --arg path "$path" '
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

    ((.schema // {}) | if (.id | type) == "string" then .id else "" end) as $schema_id
    | (.decision | canonical_decision) as $decision_norm
    | (.status | canonical_status) as $status_norm
    | (if (.rc | type) == "number" then .rc else null end) as $rc
    | ((.promotion // {})) as $promotion_stage
    | (if ($promotion_stage.summary_fresh | type) == "boolean" then $promotion_stage.summary_fresh else null end) as $summary_fresh
    | [
        (if $schema_id != "profile_compare_multi_vm_stability_promotion_cycle_summary" then "schema_mismatch" else empty end),
        (if $decision_norm == null then "decision_missing_or_invalid" else empty end),
        (if $status_norm == null then "status_missing_or_invalid" else empty end),
        (if $rc == null then "rc_missing_or_invalid" else empty end),
        (if $summary_fresh == null then "freshness_unknown"
         elif $summary_fresh == false then "freshness_stale"
         else empty
         end)
      ] as $reasons
    | {
        gate_id: "multi_vm_stability_promotion_cycle",
        source_summary_json: $path,
        exists: true,
        summary_valid_json: true,
        schema_id: (if $schema_id == "" then null else $schema_id end),
        decision_raw: (if (.decision | type) == "string" then .decision else null end),
        decision_normalized: $decision_norm,
        status_raw: (if (.status | type) == "string" then .status else null end),
        status_normalized: $status_norm,
        rc: $rc,
        freshness_known: ($summary_fresh != null),
        freshness_ok: ($summary_fresh == true),
        freshness_value: $summary_fresh,
        next_operator_action: (
          if (.next_operator_action | type) == "string" and (.next_operator_action | length) > 0 then .next_operator_action
          elif (.promotion.next_operator_action | type) == "string" and (.promotion.next_operator_action | length) > 0 then .promotion.next_operator_action
          elif (.outcome.next_operator_action | type) == "string" and (.outcome.next_operator_action | length) > 0 then .outcome.next_operator_action
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

reports_dir="${RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_REPORTS_DIR:-$ROOT_DIR/.easy-node-logs}"
runtime_actuation_input_summary_json="${RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_RUNTIME_ACTUATION_PROMOTION_CYCLE_SUMMARY_JSON:-}"
multi_vm_input_summary_json="${RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_MULTI_VM_STABILITY_PROMOTION_CYCLE_SUMMARY_JSON:-}"
summary_json="${RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_SUMMARY_JSON:-}"
report_md="${RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_REPORT_MD:-}"
print_summary_json="${RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_PRINT_SUMMARY_JSON:-0}"
print_report="${RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_PRINT_REPORT:-1}"
fail_on_no_go_compat="${RUNTIME_ACTUATION_MULTI_VM_EVIDENCE_PACK_FAIL_ON_NO_GO:-1}"

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
    --runtime-actuation-promotion-cycle-summary-json|--runtime-actuation-summary-json)
      require_value_or_die "$1" "$#"
      runtime_actuation_input_summary_json="${2:-}"
      shift 2
      ;;
    --runtime-actuation-promotion-cycle-summary-json=*|--runtime-actuation-summary-json=*)
      runtime_actuation_input_summary_json="${1#*=}"
      shift
      ;;
    --multi-vm-stability-promotion-cycle-summary-json|--multi-vm-summary-json)
      require_value_or_die "$1" "$#"
      multi_vm_input_summary_json="${2:-}"
      shift 2
      ;;
    --multi-vm-stability-promotion-cycle-summary-json=*|--multi-vm-summary-json=*)
      multi_vm_input_summary_json="${1#*=}"
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
runtime_actuation_input_summary_json="$(abs_path "$runtime_actuation_input_summary_json")"
multi_vm_input_summary_json="$(abs_path "$multi_vm_input_summary_json")"
summary_json="$(abs_path "$summary_json")"
report_md="$(abs_path "$report_md")"
print_summary_json="$(trim "$print_summary_json")"
print_report="$(trim "$print_report")"
fail_on_no_go_compat="$(trim "$fail_on_no_go_compat")"

bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--fail-on-no-go" "$fail_on_no_go_compat"

if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/runtime_actuation_multi_vm_evidence_pack_summary.json"
fi
if [[ -z "$report_md" ]]; then
  report_md="$reports_dir/runtime_actuation_multi_vm_evidence_pack_report.md"
fi

runtime_actuation_source_summary_json="$runtime_actuation_input_summary_json"
if [[ -z "$runtime_actuation_source_summary_json" ]]; then
  runtime_actuation_source_summary_json="$(discover_latest_runtime_cycle_summary_path "$reports_dir")"
fi

multi_vm_source_summary_json="$multi_vm_input_summary_json"
if [[ -z "$multi_vm_source_summary_json" ]]; then
  multi_vm_source_summary_json="$(discover_latest_multi_vm_cycle_summary_path "$reports_dir")"
fi

runtime_eval_json="$(evaluate_runtime_cycle_summary_json "$runtime_actuation_source_summary_json")"
multi_vm_eval_json="$(evaluate_multi_vm_cycle_summary_json "$multi_vm_source_summary_json")"

mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg reports_dir "$reports_dir" \
  --arg runtime_input_summary_json "$runtime_actuation_input_summary_json" \
  --arg multi_vm_input_summary_json "$multi_vm_input_summary_json" \
  --arg summary_json_path "$summary_json" \
  --arg report_md_path "$report_md" \
  --argjson fail_on_no_go "$fail_on_no_go_compat" \
  --argjson runtime "$runtime_eval_json" \
  --argjson multi_vm "$multi_vm_eval_json" \
  '
    def promote_ok($gate):
      ($gate.usable == true)
      and (($gate.decision_normalized // "") == "GO")
      and (($gate.status_normalized // "") == "pass")
      and (($gate.rc | type) == "number")
      and ($gate.rc == 0);

  (promote_ok($runtime) and promote_ok($multi_vm)) as $combined_go
  | (($runtime.usable == true) and ($multi_vm.usable == true) and (($runtime.decision_normalized // "") == "NO-GO" or ($multi_vm.decision_normalized // "") == "NO-GO")) as $usable_no_go
  | (($runtime.usable != true) or ($multi_vm.usable != true) or ($usable_no_go and ($fail_on_no_go == 1))) as $fail_closed
  | (
      ((if $runtime.usable != true then ($runtime.reasons // [] | map("runtime_actuation_promotion_cycle:" + .)) else [] end)
      + (if $multi_vm.usable != true then ($multi_vm.reasons // [] | map("multi_vm_stability_promotion_cycle:" + .)) else [] end)
      + (if $usable_no_go and ($fail_on_no_go == 1) then ["usable_no_go_detected"] else [] end))
    ) as $fail_closed_reasons
  | (
      if $combined_go then
        "Promotion evidence pack is healthy."
      elif $fail_closed then
        (
          if $usable_no_go and ($fail_on_no_go == 1) then
            [
              $runtime.next_operator_action,
              $multi_vm.next_operator_action,
              "Promotion evidence indicates NO-GO. Resolve blockers and rerun promotion cycles."
            ]
          else
            [
              $runtime.next_operator_action,
              $multi_vm.next_operator_action,
              "Refresh promotion-cycle artifacts and rerun runtime_actuation_multi_vm_evidence_pack.sh."
            ]
          end
          | map(select(type == "string" and length > 0))
          | .[0]
        )
      else
        (
          [
            $runtime.next_operator_action,
            $multi_vm.next_operator_action,
            "Promotion evidence indicates NO-GO. Resolve blockers and rerun promotion cycles."
          ]
          | map(select(type == "string" and length > 0))
          | .[0]
        )
      end
    ) as $next_operator_action
  | {
      version: 1,
      schema: {
        id: "runtime_actuation_multi_vm_evidence_pack_summary"
      },
      generated_at_utc: $generated_at_utc,
      status: (
        if $fail_closed then "fail"
        elif $combined_go then "pass"
        else "warn"
        end
      ),
      rc: (
        if $fail_closed then 1 else 0 end
      ),
      decision: (
        if $combined_go then "GO" else "NO-GO" end
      ),
      fail_closed: $fail_closed,
      reasons: (
        if $fail_closed then $fail_closed_reasons else [] end
      ),
      notes: (
        if $fail_closed then
          "Fail-closed: one or more promotion-cycle artifacts are missing, invalid, freshness-unknown/stale, or an enabled NO-GO decision must block promotion."
        elif $combined_go then
          "Runtime-actuation and multi-VM promotion evidence are both GO."
        else
          "Evidence is usable but at least one gate remains NO-GO/warn."
        end
      ),
      next_operator_action: $next_operator_action,
      inputs: {
        reports_dir: $reports_dir,
        runtime_actuation_promotion_cycle_summary_json: (
          if $runtime_input_summary_json == "" then null else $runtime_input_summary_json end
        ),
        multi_vm_stability_promotion_cycle_summary_json: (
          if $multi_vm_input_summary_json == "" then null else $multi_vm_input_summary_json end
        )
      },
      normalized: {
        runtime_actuation_decision: ($runtime.decision_normalized // null),
        multi_vm_decision: ($multi_vm.decision_normalized // null),
        combined_decision: (if $combined_go then "GO" else "NO-GO" end)
      },
      gates: {
        runtime_actuation_promotion_cycle: $runtime,
        multi_vm_stability_promotion_cycle: $multi_vm
      },
      outcome: {
        should_promote: $combined_go,
        action: (
          if $combined_go then "promote_allowed"
          elif $fail_closed then "hold_evidence_pack_blocked"
          else "hold_promotion_warn_only"
          end
        ),
        next_operator_action: $next_operator_action
      },
      artifacts: {
        summary_json: $summary_json_path,
        report_md: $report_md_path
      }
    }
  ' >"$summary_json"

{
  printf '# Runtime Actuation + Multi-VM Promotion Evidence Pack\n\n'
  printf -- '- Generated at (UTC): %s\n' "$(jq -r '.generated_at_utc' "$summary_json")"
  printf -- '- Status: %s\n' "$(jq -r '.status' "$summary_json")"
  printf -- '- Decision: %s\n' "$(jq -r '.decision' "$summary_json")"
  printf -- '- Fail closed: %s\n' "$(jq -r '.fail_closed | tostring' "$summary_json")"
  printf -- '- Next operator action: %s\n' "$(jq -r '.next_operator_action // "none"' "$summary_json")"
  printf '\n'
  printf '## Runtime Actuation Promotion Cycle\n\n'
  printf -- '- Source summary: %s\n' "$(jq -r '.gates.runtime_actuation_promotion_cycle.source_summary_json' "$summary_json")"
  printf -- '- Usable: %s\n' "$(jq -r '.gates.runtime_actuation_promotion_cycle.usable | tostring' "$summary_json")"
  printf -- '- Freshness: %s\n' "$(jq -r '.gates.runtime_actuation_promotion_cycle.freshness_value | if . == null then "unknown" else tostring end' "$summary_json")"
  printf -- '- Decision/status: %s / %s\n' \
    "$(jq -r '.gates.runtime_actuation_promotion_cycle.decision_normalized // "unknown"' "$summary_json")" \
    "$(jq -r '.gates.runtime_actuation_promotion_cycle.status_normalized // "unknown"' "$summary_json")"
  printf -- '- Next action: %s\n' "$(jq -r '.gates.runtime_actuation_promotion_cycle.next_operator_action // "none"' "$summary_json")"
  printf -- '- Reasons: %s\n' "$(jq -r '.gates.runtime_actuation_promotion_cycle.reasons | if length == 0 then "none" else join("; ") end' "$summary_json")"
  printf '\n'
  printf '## Multi-VM Stability Promotion Cycle\n\n'
  printf -- '- Source summary: %s\n' "$(jq -r '.gates.multi_vm_stability_promotion_cycle.source_summary_json' "$summary_json")"
  printf -- '- Usable: %s\n' "$(jq -r '.gates.multi_vm_stability_promotion_cycle.usable | tostring' "$summary_json")"
  printf -- '- Freshness: %s\n' "$(jq -r '.gates.multi_vm_stability_promotion_cycle.freshness_value | if . == null then "unknown" else tostring end' "$summary_json")"
  printf -- '- Decision/status: %s / %s\n' \
    "$(jq -r '.gates.multi_vm_stability_promotion_cycle.decision_normalized // "unknown"' "$summary_json")" \
    "$(jq -r '.gates.multi_vm_stability_promotion_cycle.status_normalized // "unknown"' "$summary_json")"
  printf -- '- Next action: %s\n' "$(jq -r '.gates.multi_vm_stability_promotion_cycle.next_operator_action // "none"' "$summary_json")"
  printf -- '- Reasons: %s\n' "$(jq -r '.gates.multi_vm_stability_promotion_cycle.reasons | if length == 0 then "none" else join("; ") end' "$summary_json")"
} >"$report_md"

final_status="$(jq -r '.status' "$summary_json")"
final_rc="$(jq -r '.rc' "$summary_json")"
final_decision="$(jq -r '.decision' "$summary_json")"
echo "[runtime-actuation-multi-vm-evidence-pack] status=$final_status rc=$final_rc decision=${final_decision:-unset} summary_json=$summary_json report_md=$report_md"

if [[ "$print_report" == "1" ]]; then
  cat "$report_md"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
