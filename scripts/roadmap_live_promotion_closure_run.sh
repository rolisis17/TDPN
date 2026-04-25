#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/roadmap_live_promotion_closure_run.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--host-a HOST] \
    [--host-b HOST] \
    [--campaign-subject ID] \
    [--print-summary-json [0|1]]

Purpose:
  Run the three live promotion closure helpers (M2/M4/M5) in deterministic,
  deconflict-safe sequence, then emit one consolidated machine-readable summary.

Helper order (fixed):
  1) profile_default_gate_stability_live_archive_and_pack.sh                     (M2)
  2) runtime_actuation_promotion_live_archive_and_pack.sh                        (M4)
  3) profile_compare_multi_vm_stability_promotion_live_archive_and_pack.sh       (M5)

Defaults:
  --reports-dir .easy-node-logs/roadmap_live_promotion_closure_run
  --summary-json <reports-dir>/roadmap_live_promotion_closure_run_summary.json
  --print-summary-json 1
  --host-a from ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_A (optional)
  --host-b from ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_B (optional)
  --campaign-subject from ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_CAMPAIGN_SUBJECT (optional)

Helper script override env vars:
  ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT
  ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT
  ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT

Fail-closed behavior:
  - If any required helper is missing or unreadable, no helper is executed.
  - Per-helper summary contract violations (missing/invalid summary JSON, invalid
    status/rc contract) are treated as failures.
  - Final rc is 0 only when all tracks pass.
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

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
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

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

render_invocation_command() {
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

need_cmd bash
need_cmd jq
need_cmd mktemp
need_cmd date

reports_dir="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_REPORTS_DIR:-.easy-node-logs/roadmap_live_promotion_closure_run}"
summary_json="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_SUMMARY_JSON:-}"
host_a="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_A:-}"
host_b="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_HOST_B:-}"
campaign_subject="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_CAMPAIGN_SUBJECT:-}"
print_summary_json="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_PRINT_SUMMARY_JSON:-1}"

m2_script="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M2_SCRIPT:-$ROOT_DIR/scripts/profile_default_gate_stability_live_archive_and_pack.sh}"
m4_script="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M4_SCRIPT:-$ROOT_DIR/scripts/runtime_actuation_promotion_live_archive_and_pack.sh}"
m5_script="${ROADMAP_LIVE_PROMOTION_CLOSURE_RUN_M5_SCRIPT:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_live_archive_and_pack.sh}"

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
    --host-a)
      require_value_or_die "$1" "${2:-}"
      host_a="${2:-}"
      shift 2
      ;;
    --host-b)
      require_value_or_die "$1" "${2:-}"
      host_b="${2:-}"
      shift 2
      ;;
    --campaign-subject|--subject)
      require_value_or_die "$1" "${2:-}"
      campaign_subject="${2:-}"
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
    --help|-h)
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

bool_arg_or_die "--print-summary-json" "$print_summary_json"

reports_dir="$(abs_path "$reports_dir")"
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/roadmap_live_promotion_closure_run_summary.json"
fi
summary_json="$(abs_path "$summary_json")"
m2_script="$(abs_path "$m2_script")"
m4_script="$(abs_path "$m4_script")"
m5_script="$(abs_path "$m5_script")"

mkdir -p "$reports_dir" "$(dirname "$summary_json")"
rm -f "$summary_json"

tmp_dir="$(mktemp -d "$reports_dir/.roadmap_live_promotion_closure_run.XXXXXX")"
tracks_jsonl="$tmp_dir/tracks.jsonl"
touch "$tracks_jsonl"
trap 'rm -rf "$tmp_dir"' EXIT

started_at="$(timestamp_utc)"

declare -a track_ids=(
  "m2_profile_default_gate_stability_live_archive_and_pack"
  "m4_runtime_actuation_promotion_live_archive_and_pack"
  "m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack"
)

declare -A track_label
declare -A track_script
declare -A track_reports_dir
declare -A track_summary_json
declare -A track_log
declare -A track_helper_available
declare -A track_helper_readable
declare -A track_status
declare -A track_rc
declare -A track_notes
declare -A track_started_at
declare -A track_completed_at
declare -A track_executed
declare -A track_summary_valid
declare -A track_contract_valid
declare -A track_contract_failure_reason
declare -A track_observed_status
declare -A track_observed_rc
declare -A track_run_rc
declare -A track_command
declare -A track_expected_schema_id
declare -A track_observed_schema_id
declare -A track_schema_valid

track_label["m2_profile_default_gate_stability_live_archive_and_pack"]="M2 profile-default live archive+pack"
track_label["m4_runtime_actuation_promotion_live_archive_and_pack"]="M4 runtime-actuation live archive+pack"
track_label["m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack"]="M5 multi-vm promotion live archive+pack"

track_script["m2_profile_default_gate_stability_live_archive_and_pack"]="$m2_script"
track_script["m4_runtime_actuation_promotion_live_archive_and_pack"]="$m4_script"
track_script["m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack"]="$m5_script"

track_expected_schema_id["m2_profile_default_gate_stability_live_archive_and_pack"]="profile_default_gate_stability_live_archive_and_pack_summary"
track_expected_schema_id["m4_runtime_actuation_promotion_live_archive_and_pack"]="runtime_actuation_promotion_live_archive_and_pack_summary"
track_expected_schema_id["m5_profile_compare_multi_vm_stability_promotion_live_archive_and_pack"]="profile_compare_multi_vm_stability_promotion_live_archive_and_pack_summary"

preflight_failed="0"
missing_or_unreadable_helper_count=0
preflight_failure_reason=""

for track_id in "${track_ids[@]}"; do
  track_reports_dir["$track_id"]="$reports_dir/$track_id"
  track_summary_json["$track_id"]="$reports_dir/$track_id/${track_id}_summary.json"
  track_log["$track_id"]="$reports_dir/$track_id/${track_id}.log"
  track_helper_available["$track_id"]="1"
  track_helper_readable["$track_id"]="1"
  track_status["$track_id"]="pending"
  track_rc["$track_id"]="null"
  track_notes["$track_id"]=""
  track_started_at["$track_id"]=""
  track_completed_at["$track_id"]=""
  track_executed["$track_id"]="0"
  track_summary_valid["$track_id"]="0"
  track_contract_valid["$track_id"]="0"
  track_contract_failure_reason["$track_id"]=""
  track_observed_status["$track_id"]=""
  track_observed_rc["$track_id"]="null"
  track_run_rc["$track_id"]="null"
  track_observed_schema_id["$track_id"]=""
  track_schema_valid["$track_id"]="0"
  track_command["$track_id"]=""

  helper_path="${track_script[$track_id]}"
  if [[ ! -f "$helper_path" ]]; then
    track_helper_available["$track_id"]="0"
    track_helper_readable["$track_id"]="0"
    track_status["$track_id"]="fail"
    track_rc["$track_id"]="2"
    track_notes["$track_id"]="missing_helper_script"
    preflight_failed="1"
    missing_or_unreadable_helper_count=$((missing_or_unreadable_helper_count + 1))
    if [[ -z "$preflight_failure_reason" ]]; then
      preflight_failure_reason="missing helper script: $helper_path"
    fi
  elif [[ ! -r "$helper_path" ]]; then
    track_helper_available["$track_id"]="1"
    track_helper_readable["$track_id"]="0"
    track_status["$track_id"]="fail"
    track_rc["$track_id"]="2"
    track_notes["$track_id"]="unreadable_helper_script"
    preflight_failed="1"
    missing_or_unreadable_helper_count=$((missing_or_unreadable_helper_count + 1))
    if [[ -z "$preflight_failure_reason" ]]; then
      preflight_failure_reason="unreadable helper script: $helper_path"
    fi
  fi
done

if [[ "$preflight_failed" == "1" ]]; then
  for track_id in "${track_ids[@]}"; do
    if [[ "${track_status[$track_id]}" == "pending" ]]; then
      track_status["$track_id"]="skipped"
      track_rc["$track_id"]="null"
      track_notes["$track_id"]="preflight_aborted_due_to_missing_or_unreadable_helper"
    fi
  done
else
  for track_id in "${track_ids[@]}"; do
    mkdir -p "${track_reports_dir[$track_id]}"
    rm -f "${track_summary_json[$track_id]}" "${track_log[$track_id]}"

    track_started_at["$track_id"]="$(timestamp_utc)"

    declare -a cmd=()
    cmd=(
      bash "${track_script[$track_id]}"
      --reports-dir "${track_reports_dir[$track_id]}"
      --summary-json "${track_summary_json[$track_id]}"
      --fail-on-no-go 1
      --print-summary-json 0
    )

    if [[ "$track_id" == "m2_profile_default_gate_stability_live_archive_and_pack" ]]; then
      if [[ -n "$(trim "$host_a")" ]]; then
        cmd+=(--host-a "$host_a")
      fi
      if [[ -n "$(trim "$host_b")" ]]; then
        cmd+=(--host-b "$host_b")
      fi
      if [[ -n "$(trim "$campaign_subject")" ]]; then
        cmd+=(--campaign-subject "$campaign_subject")
      fi
    fi

    track_command["$track_id"]="$(render_invocation_command "${cmd[@]}")"

    echo "[roadmap-live-promotion-closure-run] stage=track status=running track_id=$track_id helper=${track_script[$track_id]}"
    set +e
    "${cmd[@]}" >"${track_log[$track_id]}" 2>&1
    run_rc=$?
    set -e
    track_run_rc["$track_id"]="$run_rc"
    track_completed_at["$track_id"]="$(timestamp_utc)"
    track_executed["$track_id"]="1"

    summary_valid="0"
    observed_status=""
    observed_rc="null"
    observed_schema_id=""
    schema_valid="0"
    if [[ -f "${track_summary_json[$track_id]}" ]] && jq -e 'type == "object"' "${track_summary_json[$track_id]}" >/dev/null 2>&1; then
      summary_valid="1"
      observed_status="$(jq -r '.status // "" | tostring | ascii_downcase' "${track_summary_json[$track_id]}")"
      observed_rc_raw="$(jq -r '.rc // empty | tostring' "${track_summary_json[$track_id]}")"
      observed_schema_id="$(jq -r 'if (.schema.id | type) == "string" then .schema.id else "" end' "${track_summary_json[$track_id]}")"
      if [[ "$observed_schema_id" == "${track_expected_schema_id[$track_id]}" ]]; then
        schema_valid="1"
      fi
      if [[ "$observed_rc_raw" =~ ^-?[0-9]+$ ]]; then
        observed_rc="$observed_rc_raw"
      fi
    fi
    track_summary_valid["$track_id"]="$summary_valid"
    track_observed_status["$track_id"]="$observed_status"
    track_observed_rc["$track_id"]="$observed_rc"
    track_observed_schema_id["$track_id"]="$observed_schema_id"
    track_schema_valid["$track_id"]="$schema_valid"

    contract_valid="0"
    contract_failure_reason=""
    effective_status="fail"
    effective_rc="$run_rc"

    if [[ "$run_rc" -ne 0 ]]; then
      contract_failure_reason="helper process exited non-zero (run_rc=$run_rc)"
    elif [[ "$summary_valid" != "1" ]]; then
      contract_failure_reason="summary missing or invalid JSON object"
    elif [[ "$schema_valid" != "1" ]]; then
      contract_failure_reason="summary schema.id mismatch (expected ${track_expected_schema_id[$track_id]})"
    elif [[ "$observed_status" != "pass" && "$observed_status" != "fail" ]]; then
      contract_failure_reason="summary status must be pass or fail"
    elif [[ "$observed_rc" == "null" ]]; then
      contract_failure_reason="summary rc must be an integer"
    elif [[ "$observed_rc" == "0" && "$observed_status" != "pass" ]]; then
      contract_failure_reason="summary contract mismatch: rc=0 requires status=pass"
    elif [[ "$observed_rc" != "0" && "$observed_status" != "fail" ]]; then
      contract_failure_reason="summary contract mismatch: rc!=0 requires status=fail"
    elif [[ "$observed_rc" != "$run_rc" ]]; then
      contract_failure_reason="summary rc mismatch: observed_rc=$observed_rc run_rc=$run_rc"
    else
      contract_valid="1"
      effective_status="$observed_status"
      effective_rc="$observed_rc"
    fi

    if [[ "$contract_valid" != "1" ]]; then
      effective_status="fail"
      if [[ "$run_rc" == "0" ]]; then
        effective_rc="125"
      else
        effective_rc="$run_rc"
      fi
    fi

    track_contract_valid["$track_id"]="$contract_valid"
    track_contract_failure_reason["$track_id"]="$contract_failure_reason"
    track_status["$track_id"]="$effective_status"
    track_rc["$track_id"]="$effective_rc"
    if [[ "$effective_status" == "pass" ]]; then
      track_notes["$track_id"]=""
      echo "[roadmap-live-promotion-closure-run] stage=track status=pass track_id=$track_id rc=0"
    else
      if [[ -n "$contract_failure_reason" ]]; then
        track_notes["$track_id"]="helper_failed_or_summary_contract_violation"
      else
        track_notes["$track_id"]="helper_failed"
      fi
      echo "[roadmap-live-promotion-closure-run] stage=track status=fail track_id=$track_id rc=$effective_rc"
    fi
  done
fi

total_tracks="${#track_ids[@]}"
executed_tracks=0
pass_tracks=0
fail_tracks=0
skipped_tracks=0
first_failure_track_id=""
first_failure_rc="1"

for track_id in "${track_ids[@]}"; do
  status="${track_status[$track_id]}"
  if [[ "${track_executed[$track_id]}" == "1" ]]; then
    executed_tracks=$((executed_tracks + 1))
  fi
  case "$status" in
    pass)
      pass_tracks=$((pass_tracks + 1))
      ;;
    fail)
      fail_tracks=$((fail_tracks + 1))
      if [[ -z "$first_failure_track_id" ]]; then
        first_failure_track_id="$track_id"
        if [[ "${track_rc[$track_id]}" =~ ^-?[0-9]+$ ]]; then
          first_failure_rc="${track_rc[$track_id]}"
        else
          first_failure_rc="1"
        fi
      fi
      ;;
    *)
      skipped_tracks=$((skipped_tracks + 1))
      ;;
  esac
done

final_status="pass"
final_rc="0"
failure_substep=""
failure_reason=""

if [[ "$preflight_failed" == "1" ]]; then
  final_status="fail"
  final_rc="2"
  failure_substep="preflight:helpers_missing_or_unreadable"
  failure_reason="${preflight_failure_reason:-missing or unreadable helper script}"
elif (( fail_tracks > 0 )); then
  final_status="fail"
  final_rc="$first_failure_rc"
  failure_substep="track:${first_failure_track_id}"
  failure_reason="first failing track in deterministic M2/M4/M5 order"
fi

preflight_ok="1"
if [[ "$preflight_failed" == "1" ]]; then
  preflight_ok="0"
fi

for track_id in "${track_ids[@]}"; do
  track_rc_json="${track_rc[$track_id]}"
  if [[ "$track_rc_json" != "null" && ! "$track_rc_json" =~ ^-?[0-9]+$ ]]; then
    track_rc_json="null"
  fi
  observed_rc_json="${track_observed_rc[$track_id]}"
  if [[ "$observed_rc_json" != "null" && ! "$observed_rc_json" =~ ^-?[0-9]+$ ]]; then
    observed_rc_json="null"
  fi
  run_rc_json="${track_run_rc[$track_id]}"
  if [[ "$run_rc_json" != "null" && ! "$run_rc_json" =~ ^-?[0-9]+$ ]]; then
    run_rc_json="null"
  fi

  jq -n \
    --arg track_id "$track_id" \
    --arg label "${track_label[$track_id]}" \
    --arg status "${track_status[$track_id]}" \
    --argjson rc "$track_rc_json" \
    --arg script_path "${track_script[$track_id]}" \
    --arg reports_dir "${track_reports_dir[$track_id]}" \
    --arg summary_json "${track_summary_json[$track_id]}" \
    --arg log "${track_log[$track_id]}" \
    --arg command "${track_command[$track_id]}" \
    --arg started_at "${track_started_at[$track_id]}" \
    --arg completed_at "${track_completed_at[$track_id]}" \
    --arg notes "${track_notes[$track_id]}" \
    --arg observed_status "${track_observed_status[$track_id]}" \
    --arg observed_schema_id "${track_observed_schema_id[$track_id]}" \
    --arg expected_schema_id "${track_expected_schema_id[$track_id]}" \
    --arg contract_failure_reason "${track_contract_failure_reason[$track_id]}" \
    --argjson run_rc "$run_rc_json" \
    --argjson observed_rc "$observed_rc_json" \
    --argjson helper_available "${track_helper_available[$track_id]}" \
    --argjson helper_readable "${track_helper_readable[$track_id]}" \
    --argjson executed "${track_executed[$track_id]}" \
    --argjson summary_valid "${track_summary_valid[$track_id]}" \
    --argjson schema_valid "${track_schema_valid[$track_id]}" \
    --argjson contract_valid "${track_contract_valid[$track_id]}" \
    '{
      track_id: $track_id,
      label: $label,
      status: $status,
      rc: $rc,
      executed: ($executed == 1),
      helper: {
        script_path: $script_path,
        available: ($helper_available == 1),
        readable: ($helper_readable == 1)
      },
      contract: {
        summary_valid: ($summary_valid == 1),
        expected_schema_id: $expected_schema_id,
        observed_schema_id: (if $observed_schema_id == "" then null else $observed_schema_id end),
        schema_valid: ($schema_valid == 1),
        valid: ($contract_valid == 1),
        failure_reason: (if $contract_failure_reason == "" then null else $contract_failure_reason end),
        run_rc: $run_rc,
        observed_status: (if $observed_status == "" then null else $observed_status end),
        observed_rc: $observed_rc
      },
      artifacts: {
        reports_dir: $reports_dir,
        summary_json: $summary_json,
        log: $log
      },
      command: (if $command == "" then null else $command end),
      started_at: (if $started_at == "" then null else $started_at end),
      completed_at: (if $completed_at == "" then null else $completed_at end),
      notes: (if $notes == "" then null else $notes end)
    }' >>"$tracks_jsonl"
done

tracks_json="$(jq -s '.' "$tracks_jsonl")"

host_a_provided="0"
host_b_provided="0"
campaign_subject_provided="0"
if [[ -n "$(trim "$host_a")" ]]; then
  host_a_provided="1"
fi
if [[ -n "$(trim "$host_b")" ]]; then
  host_b_provided="1"
fi
if [[ -n "$(trim "$campaign_subject")" ]]; then
  campaign_subject_provided="1"
fi

completed_at="$(timestamp_utc)"

jq -n \
  --arg started_at "$started_at" \
  --arg completed_at "$completed_at" \
  --arg status "$final_status" \
  --argjson rc "$final_rc" \
  --arg failure_substep "$failure_substep" \
  --arg failure_reason "$failure_reason" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg m2_script "$m2_script" \
  --arg m4_script "$m4_script" \
  --arg m5_script "$m5_script" \
  --arg first_failure_track_id "$first_failure_track_id" \
  --argjson host_a_provided "$host_a_provided" \
  --argjson host_b_provided "$host_b_provided" \
  --argjson campaign_subject_provided "$campaign_subject_provided" \
  --argjson print_summary_json "$print_summary_json" \
  --argjson preflight_ok "$preflight_ok" \
  --argjson missing_or_unreadable_helper_count "$missing_or_unreadable_helper_count" \
  --argjson total_tracks "$total_tracks" \
  --argjson executed_tracks "$executed_tracks" \
  --argjson pass_tracks "$pass_tracks" \
  --argjson fail_tracks "$fail_tracks" \
  --argjson skipped_tracks "$skipped_tracks" \
  --argjson tracks "$tracks_json" \
  '{
    version: 1,
    schema: { id: "roadmap_live_promotion_closure_run_summary", major: 1, minor: 0 },
    status: $status,
    rc: $rc,
    failure_substep: (if $failure_substep == "" then null else $failure_substep end),
    failure_reason: (if $failure_reason == "" then null else $failure_reason end),
    timestamps: {
      started_at: $started_at,
      completed_at: $completed_at
    },
    inputs: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      host_a_provided: ($host_a_provided == 1),
      host_b_provided: ($host_b_provided == 1),
      campaign_subject_provided: ($campaign_subject_provided == 1),
      print_summary_json: ($print_summary_json == 1)
    },
    helper_scripts: {
      m2: $m2_script,
      m4: $m4_script,
      m5: $m5_script
    },
    summary: {
      total_tracks: $total_tracks,
      executed_tracks: $executed_tracks,
      pass_tracks: $pass_tracks,
      fail_tracks: $fail_tracks,
      skipped_tracks: $skipped_tracks,
      preflight_ok: ($preflight_ok == 1),
      missing_or_unreadable_helper_count: $missing_or_unreadable_helper_count,
      first_failure_track_id: (if $first_failure_track_id == "" then null else $first_failure_track_id end)
    },
    tracks: $tracks,
    artifacts: {
      summary_json: $summary_json
    }
  }' >"$summary_json"

echo "[roadmap-live-promotion-closure-run] status=$final_status rc=$final_rc executed_tracks=$executed_tracks pass_tracks=$pass_tracks fail_tracks=$fail_tracks skipped_tracks=$skipped_tracks"
echo "[roadmap-live-promotion-closure-run] summary_json=$summary_json"

if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$final_rc"
