#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/manual_validation_status.sh \
    [--base-port N] \
    [--client-iface IFACE] \
    [--exit-iface IFACE] \
    [--vpn-iface IFACE] \
    [--runtime-doctor-timeout-sec N] \
    [--profile-compare-signoff-summary-json PATH] \
    [--overlay-check-id CHECK_ID] \
    [--overlay-status pass|fail|warn|pending|skip] \
    [--overlay-notes TEXT] \
    [--overlay-command TEXT] \
    [--overlay-artifact PATH]... \
    [--show-json [0|1]]

Purpose:
  Show the current real-host production-readiness checklist status.

What it combines:
  - live runtime-doctor status
  - recorded manual validation receipts
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

abs_path() {
  local path="$1"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

manual_validation_state_dir() {
  if [[ -n "${EASY_NODE_MANUAL_VALIDATION_STATE_DIR:-}" ]]; then
    printf '%s\n' "${EASY_NODE_MANUAL_VALIDATION_STATE_DIR}"
    return
  fi

  local home_dir=""
  local state_home=""
  if [[ -n "${SUDO_USER:-}" && "${SUDO_USER:-}" != "root" ]]; then
    home_dir="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)"
    if [[ -z "$home_dir" ]]; then
      home_dir="$(eval echo "~$SUDO_USER" 2>/dev/null || true)"
    fi
    if [[ -n "$home_dir" && "$home_dir" != "~$SUDO_USER" ]]; then
      state_home="$home_dir/.local/state"
    fi
  fi
  if [[ -z "$state_home" ]]; then
    if [[ -n "${XDG_STATE_HOME:-}" ]]; then
      state_home="${XDG_STATE_HOME}"
    elif [[ -n "${HOME:-}" ]]; then
      state_home="${HOME}/.local/state"
    else
      state_home="${ROOT_DIR}/.easy-node-logs"
    fi
  fi
  printf '%s\n' "${state_home}/privacynode/manual_validation"
}

extract_json_payload() {
  local log_file="$1"
  awk '/^\[runtime-doctor\] summary_json_payload:/{flag=1; next} flag{print}' "$log_file"
}

path_exists_01() {
  local path="$1"
  if [[ -n "$path" && -e "$path" ]]; then
    printf '1'
  else
    printf '0'
  fi
}

json_file_valid_01() {
  local path="$1"
  if [[ -n "$path" && -f "$path" ]] && jq -e . "$path" >/dev/null 2>&1; then
    printf '1'
  else
    printf '0'
  fi
}

extract_attachment_record() {
  local manifest_file="$1"
  local kind="$2"
  [[ -f "$manifest_file" ]] || return 0
  awk -F'\t' -v kind="$kind" '
    function source_matches(kind, source_path, stored_path, source_base) {
      if (kind == "readiness_report_summary") {
        return source_base == "manual_validation_readiness_summary.json" || stored_path ~ /manual_validation_readiness_summary\.json$/
      }
      if (kind == "readiness_report_md") {
        return source_base == "manual_validation_readiness_report.md" || stored_path ~ /manual_validation_readiness_report\.md$/
      }
      if (kind == "readiness_report_log") {
        return source_base ~ /manual_validation_report\.log$/ || stored_path ~ /manual_validation_report\.log$/
      }
      return 0
    }
    {
      stored_path = $1
      source_path = (NF >= 3 ? $3 : (NF == 2 ? $2 : ""))
      if (stored_path == "" || source_path == "") {
        next
      }
      source_base = source_path
      sub(/^.*\//, "", source_base)
      if (source_matches(kind, source_path, stored_path, source_base)) {
        print stored_path "\t" source_path
        exit
      }
    }
  ' "$manifest_file"
}

build_attachment_pointer_json() {
  local manifest_file="$1"
  local bundle_dir="$2"
  local kind="$3"
  local record=""
  local stored_path=""
  local source_path=""
  local bundle_path=""
  local bundle_exists="0"
  local source_exists="0"
  local bundle_valid_json="0"

  record="$(extract_attachment_record "$manifest_file" "$kind")"
  if [[ -n "$record" ]]; then
    IFS=$'\t' read -r stored_path source_path <<<"$record"
    if [[ -n "$bundle_dir" && -n "$stored_path" ]]; then
      bundle_path="$bundle_dir/$stored_path"
    fi
    bundle_exists="$(path_exists_01 "$bundle_path")"
    source_exists="$(path_exists_01 "$source_path")"
    bundle_valid_json="$(json_file_valid_01 "$bundle_path")"
  fi

  jq -n \
    --arg source_path "$source_path" \
    --arg stored_path "$stored_path" \
    --arg bundle_path "$bundle_path" \
    --argjson source_exists "$source_exists" \
    --argjson bundle_exists "$bundle_exists" \
    --argjson bundle_valid_json "$bundle_valid_json" \
    '{
      source_path: $source_path,
      source_exists: ($source_exists == 1),
      stored_path: $stored_path,
      bundle_path: $bundle_path,
      exists: ($bundle_exists == 1),
      valid_json: ($bundle_valid_json == 1)
    }'
}

find_incident_source_summary_json() {
  local artifacts_json="$1"
  local artifact=""
  while IFS= read -r artifact; do
    artifact="$(trim "$artifact")"
    if [[ -z "$artifact" || ! -f "$artifact" ]]; then
      continue
    fi
    if jq -e '.incident_snapshot? != null and .status? != null' "$artifact" >/dev/null 2>&1; then
      printf '%s\n' "$artifact"
      return 0
    fi
  done < <(printf '%s\n' "$artifacts_json" | jq -r '.[]?')
  printf '%s\n' ""
}

build_incident_handoff_json() {
  local source_summary_json="$1"
  local receipt_json="$2"
  local enabled="0"
  local status=""
  local bundle_dir=""
  local bundle_tar=""
  local summary_json=""
  local report_md=""
  local attachment_manifest=""
  local attachment_skipped=""
  local attachment_count="0"
  local incident_log=""
  local readiness_report_summary_attachment_json='{"source_path":"","source_exists":false,"stored_path":"","bundle_path":"","exists":false,"valid_json":false}'
  local readiness_report_md_attachment_json='{"source_path":"","source_exists":false,"stored_path":"","bundle_path":"","exists":false,"valid_json":false}'
  local readiness_report_log_attachment_json='{"source_path":"","source_exists":false,"stored_path":"","bundle_path":"","exists":false,"valid_json":false}'
  local source_exists="0"
  local source_valid="0"
  local receipt_exists="0"
  local receipt_valid="0"
  local bundle_dir_exists="0"
  local bundle_tar_exists="0"
  local summary_exists="0"
  local summary_valid="0"
  local report_exists="0"
  local attachment_manifest_exists="0"
  local attachment_skipped_exists="0"
  local incident_log_exists="0"

  source_exists="$(path_exists_01 "$source_summary_json")"
  source_valid="$(json_file_valid_01 "$source_summary_json")"
  receipt_exists="$(path_exists_01 "$receipt_json")"
  receipt_valid="$(json_file_valid_01 "$receipt_json")"

  if [[ "$source_valid" == "1" ]]; then
    enabled="$(jq -r '(.incident_snapshot.enabled // .incident_snapshot.enabled_on_fail // false) | if . then 1 else 0 end' "$source_summary_json" 2>/dev/null || echo 0)"
    status="$(jq -r '.incident_snapshot.status // ""' "$source_summary_json" 2>/dev/null || true)"
    bundle_dir="$(jq -r '.incident_snapshot.bundle_dir // ""' "$source_summary_json" 2>/dev/null || true)"
    bundle_tar="$(jq -r '.incident_snapshot.bundle_tar // ""' "$source_summary_json" 2>/dev/null || true)"
    summary_json="$(jq -r '.incident_snapshot.summary_json // ""' "$source_summary_json" 2>/dev/null || true)"
    report_md="$(jq -r '.incident_snapshot.report_md // ""' "$source_summary_json" 2>/dev/null || true)"
    attachment_manifest="$(jq -r '.incident_snapshot.attachment_manifest // ""' "$source_summary_json" 2>/dev/null || true)"
    attachment_skipped="$(jq -r '.incident_snapshot.attachment_skipped // ""' "$source_summary_json" 2>/dev/null || true)"
    attachment_count="$(jq -r '.incident_snapshot.attachment_count // 0' "$source_summary_json" 2>/dev/null || echo 0)"
    incident_log="$(jq -r '.incident_snapshot.log // ""' "$source_summary_json" 2>/dev/null || true)"
  fi

  bundle_dir_exists="$(path_exists_01 "$bundle_dir")"
  bundle_tar_exists="$(path_exists_01 "$bundle_tar")"
  summary_exists="$(path_exists_01 "$summary_json")"
  summary_valid="$(json_file_valid_01 "$summary_json")"
  report_exists="$(path_exists_01 "$report_md")"
  attachment_manifest_exists="$(path_exists_01 "$attachment_manifest")"
  attachment_skipped_exists="$(path_exists_01 "$attachment_skipped")"
  incident_log_exists="$(path_exists_01 "$incident_log")"
  if [[ "$attachment_manifest_exists" == "1" ]]; then
    readiness_report_summary_attachment_json="$(build_attachment_pointer_json "$attachment_manifest" "$bundle_dir" "readiness_report_summary")"
    readiness_report_md_attachment_json="$(build_attachment_pointer_json "$attachment_manifest" "$bundle_dir" "readiness_report_md")"
    readiness_report_log_attachment_json="$(build_attachment_pointer_json "$attachment_manifest" "$bundle_dir" "readiness_report_log")"
  fi

  jq -n \
    --arg status "$status" \
    --arg source_summary_json "$source_summary_json" \
    --arg receipt_json "$receipt_json" \
    --arg bundle_dir "$bundle_dir" \
    --arg bundle_tar "$bundle_tar" \
    --arg summary_json "$summary_json" \
    --arg report_md "$report_md" \
    --arg attachment_manifest "$attachment_manifest" \
    --arg attachment_skipped "$attachment_skipped" \
    --arg attachment_count "$attachment_count" \
    --arg incident_log "$incident_log" \
    --argjson enabled "$enabled" \
    --argjson source_exists "$source_exists" \
    --argjson source_valid "$source_valid" \
    --argjson receipt_exists "$receipt_exists" \
    --argjson receipt_valid "$receipt_valid" \
    --argjson bundle_dir_exists "$bundle_dir_exists" \
    --argjson bundle_tar_exists "$bundle_tar_exists" \
    --argjson summary_exists "$summary_exists" \
    --argjson summary_valid "$summary_valid" \
    --argjson report_exists "$report_exists" \
    --argjson attachment_manifest_exists "$attachment_manifest_exists" \
    --argjson attachment_skipped_exists "$attachment_skipped_exists" \
    --argjson incident_log_exists "$incident_log_exists" \
    --argjson readiness_report_summary_attachment "$readiness_report_summary_attachment_json" \
    --argjson readiness_report_md_attachment "$readiness_report_md_attachment_json" \
    --argjson readiness_report_log_attachment "$readiness_report_log_attachment_json" \
    '{
      available: (($status | length) > 0 or ($summary_json | length) > 0 or ($report_md | length) > 0 or ($bundle_dir | length) > 0),
      enabled: ($enabled == 1),
      status: $status,
      source_summary_json: {
        path: $source_summary_json,
        exists: ($source_exists == 1),
        valid_json: ($source_valid == 1)
      },
      receipt_json: {
        path: $receipt_json,
        exists: ($receipt_exists == 1),
        valid_json: ($receipt_valid == 1)
      },
      bundle_dir: {
        path: $bundle_dir,
        exists: ($bundle_dir_exists == 1)
      },
      bundle_tar: {
        path: $bundle_tar,
        exists: ($bundle_tar_exists == 1)
      },
      summary_json: {
        path: $summary_json,
        exists: ($summary_exists == 1),
        valid_json: ($summary_valid == 1)
      },
      report_md: {
        path: $report_md,
        exists: ($report_exists == 1)
      },
      attachment_manifest: {
        path: $attachment_manifest,
        exists: ($attachment_manifest_exists == 1)
      },
      attachment_skipped: {
        path: $attachment_skipped,
        exists: ($attachment_skipped_exists == 1)
      },
      attachment_count: ($attachment_count | tonumber),
      readiness_report_summary_attachment: $readiness_report_summary_attachment,
      readiness_report_md_attachment: $readiness_report_md_attachment,
      readiness_report_log_attachment: $readiness_report_log_attachment,
      log: {
        path: $incident_log,
        exists: ($incident_log_exists == 1)
      }
    }'
}

build_recorded_check_json() {
  local check_id="$1"
  local check_label="$2"
  local default_command="$3"
  local check_json=""
  local check_status=""
  local check_notes=""
  local check_command=""
  local check_recorded_at=""
  local check_receipt_json=""
  local check_artifacts_json=""
  local source_summary_json=""
  local incident_handoff_json=""

  check_json="$(printf '%s\n' "$recorded_json" | jq -c --arg id "$check_id" '.checks[$id] // {
    status: "pending",
    notes: "",
    command: "",
    artifacts: [],
    recorded_at_utc: "",
    receipt_json: ""
  }')"
  check_status="$(jq -r '.status // "pending"' <<<"$check_json")"
  check_notes="$(jq -r '.notes // ""' <<<"$check_json")"
  check_command="$(jq -r '.command // ""' <<<"$check_json")"
  if [[ -z "$check_command" ]]; then
    check_command="$default_command"
  fi
  check_recorded_at="$(jq -r '.recorded_at_utc // ""' <<<"$check_json")"
  check_receipt_json="$(jq -r '.receipt_json // ""' <<<"$check_json")"
  check_artifacts_json="$(jq -c '.artifacts // []' <<<"$check_json")"
  source_summary_json="$(find_incident_source_summary_json "$check_artifacts_json")"
  incident_handoff_json="$(build_incident_handoff_json "$source_summary_json" "$check_receipt_json")"

  jq -n \
    --arg check_id "$check_id" \
    --arg check_label "$check_label" \
    --arg status "$check_status" \
    --arg notes "$check_notes" \
    --arg command "$check_command" \
    --arg recorded_at_utc "$check_recorded_at" \
    --arg receipt_json "$check_receipt_json" \
    --argjson artifacts "$check_artifacts_json" \
    --argjson incident_handoff "$incident_handoff_json" \
    '{
      "check_id": $check_id,
      "label": $check_label,
      "status": $status,
      "notes": $notes,
      "command": $command,
      "artifacts": $artifacts,
      "recorded_at_utc": $recorded_at_utc,
      "receipt_json": $receipt_json,
      "incident_handoff": $incident_handoff
    }'
}

build_runtime_hygiene_check_json() {
  local runtime_check_json=""
  local runtime_recorded_json=""
  local runtime_recorded_notes=""
  local runtime_recorded_command=""
  local runtime_recorded_at=""
  local runtime_receipt_json=""
  local runtime_artifacts_json=""
  local runtime_incident_source_summary_json=""
  local runtime_incident_handoff_json=""
  local runtime_combined_notes=""
  local runtime_recorded_note_suffix=""

  runtime_recorded_json="$(printf '%s\n' "$recorded_json" | jq -c '.checks["runtime_hygiene"] // {
    notes: "",
    command: "",
    artifacts: [],
    recorded_at_utc: "",
    receipt_json: ""
  }')"
  runtime_recorded_notes="$(jq -r '.notes // ""' <<<"$runtime_recorded_json")"
  runtime_recorded_command="$(jq -r '.command // ""' <<<"$runtime_recorded_json")"
  runtime_recorded_at="$(jq -r '.recorded_at_utc // ""' <<<"$runtime_recorded_json")"
  runtime_receipt_json="$(jq -r '.receipt_json // ""' <<<"$runtime_recorded_json")"
  runtime_artifacts_json="$(jq -c '.artifacts // []' <<<"$runtime_recorded_json")"
  runtime_incident_source_summary_json="$(find_incident_source_summary_json "$runtime_artifacts_json")"
  runtime_incident_handoff_json="$(build_incident_handoff_json "$runtime_incident_source_summary_json" "$runtime_receipt_json")"

  if [[ -z "$runtime_recorded_at" ]]; then
    runtime_recorded_at="$(printf '%s\n' "$runtime_doctor_json" | jq -r '.generated_at_utc // ""')"
  fi
  if [[ -n "$runtime_recorded_notes" ]]; then
    runtime_recorded_note_suffix="last recorded: $runtime_recorded_notes"
  fi
  runtime_combined_notes="$(
    jq -rn \
      --arg runtime_summary "$runtime_summary" \
      --arg runtime_notes "$runtime_notes" \
      --arg recorded_notes "$runtime_recorded_note_suffix" \
      '[ $runtime_summary, $runtime_notes, $recorded_notes ] | map(select(length > 0)) | join("; ")'
  )"
  if [[ -z "$runtime_recorded_command" ]]; then
    runtime_recorded_command="./scripts/easy_node.sh runtime-doctor --show-json 1"
  fi

  runtime_check_json="$(
    jq -n \
      --arg runtime_status "$runtime_check_status" \
      --arg runtime_notes "$runtime_combined_notes" \
      --arg runtime_command "$runtime_recorded_command" \
      --arg runtime_remediation_command "$runtime_fix_record_command" \
      --arg runtime_recorded_at "$runtime_recorded_at" \
      --arg runtime_receipt_json "$runtime_receipt_json" \
      --argjson runtime_artifacts "$runtime_artifacts_json" \
      --argjson runtime_remediations "$runtime_remediations_json" \
      --argjson runtime_incident_handoff "$runtime_incident_handoff_json" \
      '{
        check_id: "runtime_hygiene",
        label: "Runtime hygiene doctor",
        status: $runtime_status,
        notes: $runtime_notes,
        command: $runtime_command,
        remediation_command: (if $runtime_status == "pass" then "" else $runtime_remediation_command end),
        remediations: $runtime_remediations,
        artifacts: $runtime_artifacts,
        recorded_at_utc: $runtime_recorded_at,
        receipt_json: $runtime_receipt_json,
        incident_handoff: $runtime_incident_handoff
      }'
  )"

  printf '%s\n' "$runtime_check_json"
}

profile_signoff_non_root_refresh_blocked_01() {
  local signoff_summary_json="$1"
  local failure_stage=""
  local refresh_campaign="0"
  local campaign_log=""
  local root_required_msg="--start-local-stack=1 requires root"
  local campaign_line=""
  local run_log=""

  if [[ ! -f "$signoff_summary_json" ]] || ! jq -e . "$signoff_summary_json" >/dev/null 2>&1; then
    printf '0'
    return
  fi

  failure_stage="$(jq -r '.failure_stage // ""' "$signoff_summary_json" 2>/dev/null || true)"
  refresh_campaign="$(jq -r '(.inputs.refresh_campaign // false) | if . then "1" else "0" end' "$signoff_summary_json" 2>/dev/null || echo 0)"
  campaign_log="$(jq -r '.stages.campaign.log // ""' "$signoff_summary_json" 2>/dev/null || true)"
  if [[ "$failure_stage" != "campaign" || "$refresh_campaign" != "1" || -z "$campaign_log" || ! -f "$campaign_log" ]]; then
    printf '0'
    return
  fi

  if grep -F -- "$root_required_msg" "$campaign_log" >/dev/null 2>&1; then
    printf '1'
    return
  fi

  while IFS= read -r campaign_line; do
    run_log="${campaign_line##* log=}"
    if [[ "$run_log" == "$campaign_line" ]]; then
      continue
    fi
    if [[ -n "$run_log" && -f "$run_log" ]] && grep -F -- "$root_required_msg" "$run_log" >/dev/null 2>&1; then
      printf '1'
      return
    fi
  done <"$campaign_log"

  printf '0'
}

build_profile_default_gate_json() {
  local signoff_summary_json="$1"
  local default_signoff_summary_json="$ROOT_DIR/.easy-node-logs/profile_compare_campaign_signoff_summary.json"
  local reports_dir=""
  local reports_dir_arg=""
  local summary_json_arg=""
  local next_command=""
  local next_command_sudo=""
  local available="0"
  local valid_json="0"
  local status="pending"
  local notes="profile compare campaign signoff has not been recorded yet"
  local decision=""
  local recommended_profile=""
  local trend_source=""
  local final_rc="0"
  local campaign_summary_json=""
  local campaign_report_md=""
  local campaign_check_summary_json=""
  local failure_stage=""
  local non_root_refresh_blocked="0"
  local stale_non_refreshed="0"
  local refresh_campaign="0"
  local signoff_status=""
  local decision_normalized=""
  local decision_is_no_go="0"

  reports_dir="$(dirname "$signoff_summary_json")"
  if [[ "$signoff_summary_json" == "$default_signoff_summary_json" ]]; then
    reports_dir_arg=".easy-node-logs"
    summary_json_arg=".easy-node-logs/profile_compare_campaign_signoff_summary.json"
  else
    printf -v reports_dir_arg '%q' "$reports_dir"
    printf -v summary_json_arg '%q' "$signoff_summary_json"
  fi
  next_command="./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir $reports_dir_arg --refresh-campaign 1 --fail-on-no-go 1 --summary-json $summary_json_arg --print-summary-json 1"
  next_command_sudo="sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir $reports_dir_arg --refresh-campaign 1 --fail-on-no-go 1 --summary-json $summary_json_arg --print-summary-json 1"

  if [[ -f "$signoff_summary_json" ]]; then
    available="1"
  fi
  if [[ "$available" == "1" ]] && jq -e . "$signoff_summary_json" >/dev/null 2>&1; then
    valid_json="1"
  fi
  if [[ "$available" == "1" && "$valid_json" != "1" ]]; then
    status="pending"
    notes="profile compare campaign signoff summary JSON is invalid; rerun with refresh-campaign=1"
    next_command="$next_command_sudo"
  fi

  if [[ "$valid_json" == "1" ]]; then
    signoff_status="$(jq -r '.status // ""' "$signoff_summary_json")"
    decision="$(jq -r '.decision.decision // ""' "$signoff_summary_json")"
    decision_normalized="$(printf '%s' "$decision" | tr '[:lower:]' '[:upper:]' | tr -d '[:space:]_-')"
    if [[ "$decision_normalized" == "NOGO" ]]; then
      decision_is_no_go="1"
    fi
    recommended_profile="$(jq -r '.decision.recommended_profile // ""' "$signoff_summary_json")"
    trend_source="$(jq -r '.decision.trend_source // ""' "$signoff_summary_json")"
    final_rc="$(jq -r '.final_rc // 0' "$signoff_summary_json")"
    refresh_campaign="$(jq -r '(.inputs.refresh_campaign // false) | if . then "1" else "0" end' "$signoff_summary_json")"
    campaign_summary_json="$(jq -r '.artifacts.campaign_summary_json // ""' "$signoff_summary_json")"
    campaign_report_md="$(jq -r '.artifacts.campaign_report_md // ""' "$signoff_summary_json")"
    campaign_check_summary_json="$(jq -r '.artifacts.campaign_check_summary_json // ""' "$signoff_summary_json")"
    failure_stage="$(jq -r '.failure_stage // ""' "$signoff_summary_json")"
    non_root_refresh_blocked="$(profile_signoff_non_root_refresh_blocked_01 "$signoff_summary_json")"
    if ! [[ "$final_rc" =~ ^-?[0-9]+$ ]]; then
      final_rc="0"
    fi
    case "$signoff_status" in
      ok)
        if [[ "$decision" == "GO" ]]; then
          status="pass"
          notes="profile compare campaign signoff decision is GO"
        elif [[ "$decision" == "NO-GO" || "$decision" == "NO_GO" || "$decision" == "NOGO" ]]; then
          status="warn"
          notes="profile compare campaign signoff decision is NO-GO"
        else
          status="warn"
          notes="profile compare campaign signoff status is ok but decision is ${decision:-unknown}"
        fi
        ;;
      fail)
        if [[ "$refresh_campaign" != "1" ]]; then
          status="pending"
          stale_non_refreshed="1"
          notes="profile compare campaign signoff summary is stale (refresh-campaign=0); rerun with refresh-campaign=1"
          next_command="$next_command_sudo"
        elif [[ "$non_root_refresh_blocked" == "1" ]]; then
          status="pending"
          notes="profile compare campaign signoff refresh needs root for local stack (non-root host)"
          next_command="$next_command_sudo"
        elif [[ "$decision_is_no_go" == "1" ]]; then
          status="warn"
          notes="profile compare campaign signoff decision is NO-GO"
        else
          status="fail"
          notes="profile compare campaign signoff failed (final_rc=${final_rc})"
        fi
        ;;
      *)
        status="warn"
        notes="profile compare campaign signoff status is ${signoff_status:-unknown}"
        ;;
    esac
  fi

  jq -n \
    --arg summary_json "$signoff_summary_json" \
    --arg next_command "$next_command" \
    --arg status "$status" \
    --arg notes "$notes" \
    --arg decision "$decision" \
    --arg recommended_profile "$recommended_profile" \
    --arg trend_source "$trend_source" \
    --arg final_rc "$final_rc" \
    --arg failure_stage "$failure_stage" \
    --arg non_root_refresh_blocked "$non_root_refresh_blocked" \
    --arg stale_non_refreshed "$stale_non_refreshed" \
    --arg refresh_campaign "$refresh_campaign" \
    --arg campaign_summary_json "$campaign_summary_json" \
    --arg campaign_report_md "$campaign_report_md" \
    --arg campaign_check_summary_json "$campaign_check_summary_json" \
    --argjson available "$available" \
    --argjson valid_json "$valid_json" \
    '{
      enabled: true,
      summary_json: $summary_json,
      available: ($available == 1),
      valid_json: ($valid_json == 1),
      status: $status,
      notes: $notes,
      decision: $decision,
      recommended_profile: $recommended_profile,
      trend_source: $trend_source,
      final_rc: ($final_rc | tonumber),
      failure_stage: $failure_stage,
      non_root_refresh_blocked: ($non_root_refresh_blocked == "1"),
      stale_non_refreshed: ($stale_non_refreshed == "1"),
      refresh_campaign: ($refresh_campaign == "1"),
      next_command: $next_command,
      artifacts: {
        campaign_summary_json: $campaign_summary_json,
        campaign_report_md: $campaign_report_md,
        campaign_check_summary_json: $campaign_check_summary_json
      }
    }'
}

show_json="0"
base_port="${EASY_NODE_DOCTOR_WG_ONLY_BASE_PORT:-19280}"
client_iface="${EASY_NODE_DOCTOR_CLIENT_IFACE:-wgcstack0}"
exit_iface="${EASY_NODE_DOCTOR_EXIT_IFACE:-wgestack0}"
vpn_iface="${EASY_NODE_DOCTOR_VPN_IFACE:-wgvpn0}"
runtime_doctor_timeout_sec="${MANUAL_VALIDATION_RUNTIME_DOCTOR_TIMEOUT_SEC:-120}"
profile_compare_signoff_summary_json="${MANUAL_VALIDATION_PROFILE_COMPARE_SIGNOFF_SUMMARY_JSON:-$ROOT_DIR/.easy-node-logs/profile_compare_campaign_signoff_summary.json}"
overlay_check_id=""
overlay_status=""
overlay_notes=""
overlay_command=""
declare -a overlay_artifacts=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-port)
      base_port="${2:-}"
      shift 2
      ;;
    --client-iface)
      client_iface="${2:-}"
      shift 2
      ;;
    --exit-iface)
      exit_iface="${2:-}"
      shift 2
      ;;
    --vpn-iface)
      vpn_iface="${2:-}"
      shift 2
      ;;
    --runtime-doctor-timeout-sec)
      runtime_doctor_timeout_sec="${2:-}"
      shift 2
      ;;
    --profile-compare-signoff-summary-json)
      profile_compare_signoff_summary_json="${2:-}"
      shift 2
      ;;
    --overlay-check-id)
      overlay_check_id="${2:-}"
      shift 2
      ;;
    --overlay-status)
      overlay_status="${2:-}"
      shift 2
      ;;
    --overlay-notes)
      overlay_notes="${2:-}"
      shift 2
      ;;
    --overlay-command)
      overlay_command="${2:-}"
      shift 2
      ;;
    --overlay-artifact)
      overlay_artifacts+=("$(abs_path "${2:-}")")
      shift 2
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

bool_arg_or_die "--show-json" "$show_json"
for cmd in jq awk date mktemp; do
  need_cmd "$cmd"
done
if ! [[ "$base_port" =~ ^[0-9]+$ ]]; then
  echo "--base-port must be an integer"
  exit 2
fi
if [[ -z "$client_iface" || -z "$exit_iface" || -z "$vpn_iface" ]]; then
  echo "--client-iface, --exit-iface, and --vpn-iface must be non-empty"
  exit 2
fi
if ! [[ "$runtime_doctor_timeout_sec" =~ ^[0-9]+$ ]]; then
  echo "--runtime-doctor-timeout-sec must be an integer >= 0"
  exit 2
fi
profile_compare_signoff_summary_json="$(abs_path "$profile_compare_signoff_summary_json")"
if [[ -z "$profile_compare_signoff_summary_json" ]]; then
  echo "--profile-compare-signoff-summary-json must be non-empty"
  exit 2
fi
overlay_check_id="$(trim "$overlay_check_id")"
overlay_status="$(trim "$overlay_status")"
overlay_notes="$(trim "$overlay_notes")"
overlay_command="$(trim "$overlay_command")"
if [[ -n "$overlay_check_id" ]]; then
  if [[ ! "$overlay_check_id" =~ ^[a-z0-9_]+$ ]]; then
    echo "--overlay-check-id must match ^[a-z0-9_]+$"
    exit 2
  fi
  case "$overlay_status" in
    pass|fail|warn|pending|skip)
      ;;
    *)
      echo "--overlay-status must be one of: pass fail warn pending skip"
      exit 2
      ;;
  esac
fi

runtime_doctor_script="${RUNTIME_DOCTOR_SCRIPT:-$ROOT_DIR/scripts/runtime_doctor.sh}"
if [[ ! -x "$runtime_doctor_script" ]]; then
  echo "missing runtime doctor script: $runtime_doctor_script"
  exit 2
fi

run_with_optional_timeout() {
  local timeout_sec="$1"
  shift
  if [[ "$timeout_sec" -gt 0 ]] && command -v timeout >/dev/null 2>&1; then
    timeout "${timeout_sec}s" "$@"
  else
    "$@"
  fi
}

doctor_log="$(mktemp)"
runtime_doctor_rc=0
runtime_doctor_timed_out="0"
runtime_doctor_timeout_guard_available="0"
if command -v timeout >/dev/null 2>&1; then
  runtime_doctor_timeout_guard_available="1"
fi
if [[ "$runtime_doctor_timeout_sec" -gt 0 && "$runtime_doctor_timeout_guard_available" != "1" ]]; then
  echo "[manual-validation-status] warn=timeout command not found; running runtime-doctor without timeout guard"
fi
if run_with_optional_timeout "$runtime_doctor_timeout_sec" "$runtime_doctor_script" \
  --base-port "$base_port" \
  --client-iface "$client_iface" \
  --exit-iface "$exit_iface" \
  --vpn-iface "$vpn_iface" \
  --show-json 1 >"$doctor_log" 2>&1; then
  runtime_doctor_rc=0
else
  runtime_doctor_rc=$?
fi
if [[ "$runtime_doctor_rc" -eq 124 ]]; then
  runtime_doctor_timed_out="1"
fi
runtime_doctor_json="$(extract_json_payload "$doctor_log")"
if [[ -z "$runtime_doctor_json" ]]; then
  if [[ "$runtime_doctor_timed_out" == "1" ]]; then
    runtime_doctor_json="$(
      jq -n \
        --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson timeout_sec "$runtime_doctor_timeout_sec" \
        '{
          version: 1,
          generated_at_utc: $generated_at_utc,
          status: "FAIL",
          summary: {
            findings_total: 1,
            warnings_total: 0,
            failures_total: 1
          },
          findings: [
            {
              severity: "FAIL",
              code: "runtime_doctor_timeout",
              message: ("runtime-doctor timed out after " + ($timeout_sec | tostring) + " seconds"),
              remediation: "rerun runtime-fix-record and runtime-doctor after checking host load"
            }
          ]
        }'
    )"
  else
    echo "manual-validation-status failed: runtime-doctor did not emit JSON summary"
    cat "$doctor_log"
    rm -f "$doctor_log"
    exit 1
  fi
fi
if ! printf '%s\n' "$runtime_doctor_json" | jq -e . >/dev/null 2>&1; then
  if [[ "$runtime_doctor_timed_out" == "1" ]]; then
    runtime_doctor_json="$(
      jq -n \
        --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --argjson timeout_sec "$runtime_doctor_timeout_sec" \
        '{
          version: 1,
          generated_at_utc: $generated_at_utc,
          status: "FAIL",
          summary: {
            findings_total: 1,
            warnings_total: 0,
            failures_total: 1
          },
          findings: [
            {
              severity: "FAIL",
              code: "runtime_doctor_timeout_invalid_json",
              message: ("runtime-doctor timed out after " + ($timeout_sec | tostring) + " seconds and emitted invalid/partial JSON"),
              remediation: "rerun runtime-fix-record and runtime-doctor after checking host load"
            }
          ]
        }'
    )"
  else
    echo "manual-validation-status failed: runtime-doctor emitted invalid JSON summary"
    cat "$doctor_log"
    rm -f "$doctor_log"
    exit 1
  fi
fi
rm -f "$doctor_log"

state_dir="$(manual_validation_state_dir)"
status_json="${state_dir}/status.json"
recorded_status_file_present="0"
recorded_status_json_valid="1"
recorded_status_json_warning=""
if [[ -f "$status_json" ]]; then
  recorded_status_file_present="1"
  if jq -e . "$status_json" >/dev/null 2>&1; then
    recorded_json="$(cat "$status_json")"
  else
    recorded_status_json_valid="0"
    recorded_status_json_warning="manual-validation status file is invalid JSON; falling back to empty checks: $status_json"
    recorded_json='{"version":1,"checks":{}}'
    echo "[manual-validation-status] warn=$recorded_status_json_warning"
  fi
else
  recorded_json='{"version":1,"checks":{}}'
fi
if [[ -n "$overlay_check_id" ]]; then
  overlay_recorded_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  overlay_artifacts_json="$(printf '%s\n' "${overlay_artifacts[@]:-}" | jq -Rsc 'split("\n") | map(select(length > 0))')"
  recorded_json="$(
    printf '%s\n' "$recorded_json" | jq \
      --arg check_id "$overlay_check_id" \
      --arg status "$overlay_status" \
      --arg notes "$overlay_notes" \
      --arg command "$overlay_command" \
      --arg recorded_at_utc "$overlay_recorded_at_utc" \
      --argjson artifacts "$overlay_artifacts_json" \
      '
        .version = 1
        | .checks = (.checks // {})
        | .checks[$check_id] = {
            status: $status,
            notes: $notes,
            command: $command,
            artifacts: $artifacts,
            recorded_at_utc: $recorded_at_utc,
            receipt_json: ""
          }
      '
  )"
fi

runtime_status="$(printf '%s\n' "$runtime_doctor_json" | jq -r '.status // "UNKNOWN"')"
case "$runtime_status" in
  OK) runtime_check_status="pass" ;;
  WARN) runtime_check_status="warn" ;;
  FAIL) runtime_check_status="fail" ;;
  *) runtime_check_status="pending" ;;
esac
runtime_findings_total="$(printf '%s\n' "$runtime_doctor_json" | jq -r '.summary.findings_total // 0')"
runtime_notes="$(printf '%s\n' "$runtime_doctor_json" | jq -r '[.findings[].code] | join(", ")')"
runtime_remediations_json="$(printf '%s\n' "$runtime_doctor_json" | jq -c '[.findings[]?.remediation | select(type == "string" and length > 0)] | unique')"
runtime_summary="runtime-doctor findings=${runtime_findings_total}"
if [[ "$runtime_doctor_timed_out" == "1" ]]; then
  runtime_summary="${runtime_summary}; runtime-doctor timeout=${runtime_doctor_timeout_sec}s"
fi
runtime_fix_record_command="sudo ./scripts/easy_node.sh runtime-fix-record --prune-wg-only-dir 1 --print-summary-json 1"
runtime_hygiene_check_json="$(build_runtime_hygiene_check_json)"
wg_only_check_json="$(build_recorded_check_json "wg_only_stack_selftest" "WG-only stack selftest" "sudo ./scripts/easy_node.sh wg-only-stack-selftest-record --strict-beta 1 --base-port 19280 --client-iface wgcstack0 --exit-iface wgestack0 --print-summary-json 1")"
docker_rehearsal_check_json="$(build_recorded_check_json "three_machine_docker_readiness" "One-host docker 3-machine rehearsal" "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1")"
real_wg_privileged_check_json="$(build_recorded_check_json "real_wg_privileged_matrix" "Linux root real-WG privileged matrix" "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1")"
machine_c_check_json="$(build_recorded_check_json "machine_c_vpn_smoke" "Machine C VPN smoke test" "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country")"
three_machine_check_json="$(build_recorded_check_json "three_machine_prod_signoff" "True 3-machine production signoff" "sudo ./scripts/easy_node.sh three-machine-prod-signoff --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --pre-real-host-readiness 1 --runtime-fix 1 --print-summary-json 1")"
profile_default_gate_json="$(build_profile_default_gate_json "$profile_compare_signoff_summary_json")"
real_wg_host_linux="0"
real_wg_host_root="0"
real_wg_host_has_wg="0"
real_wg_host_has_ip="0"
real_wg_host_eligible="0"
real_wg_host_hint="requires Linux root host with wg/ip tools"
if [[ "$(uname -s)" == "Linux" ]]; then
  real_wg_host_linux="1"
fi
if [[ "$(id -u)" -eq 0 ]]; then
  real_wg_host_root="1"
fi
if command -v wg >/dev/null 2>&1; then
  real_wg_host_has_wg="1"
fi
if command -v ip >/dev/null 2>&1; then
  real_wg_host_has_ip="1"
fi
if [[ "$real_wg_host_linux" == "1" && "$real_wg_host_root" == "1" && "$real_wg_host_has_wg" == "1" && "$real_wg_host_has_ip" == "1" ]]; then
  real_wg_host_eligible="1"
  real_wg_host_hint="host eligible"
elif [[ "$real_wg_host_linux" != "1" ]]; then
  real_wg_host_hint="requires Linux host"
elif [[ "$real_wg_host_root" != "1" ]]; then
  real_wg_host_hint="requires root (run with sudo)"
elif [[ "$real_wg_host_has_wg" != "1" || "$real_wg_host_has_ip" != "1" ]]; then
  real_wg_host_hint="requires wg and ip commands on host"
fi

combined_json="$(
  jq -n \
    --arg state_dir "$state_dir" \
    --arg status_json "$status_json" \
    --arg recorded_status_json_warning "$recorded_status_json_warning" \
    --argjson recorded_status_file_present "$recorded_status_file_present" \
    --argjson recorded_status_json_valid "$recorded_status_json_valid" \
    --argjson runtime_doctor_timeout_sec "$runtime_doctor_timeout_sec" \
    --arg runtime_doctor_timed_out "$runtime_doctor_timed_out" \
    --arg runtime_doctor_timeout_guard_available "$runtime_doctor_timeout_guard_available" \
    --arg runtime_doctor_json_rc "$runtime_doctor_rc" \
    --argjson recorded "$recorded_json" \
    --argjson runtime_doctor "$runtime_doctor_json" \
    --argjson runtime_hygiene_check "$runtime_hygiene_check_json" \
    --argjson wg_only_check "$wg_only_check_json" \
    --argjson docker_rehearsal_check "$docker_rehearsal_check_json" \
    --argjson real_wg_privileged_check "$real_wg_privileged_check_json" \
    --argjson machine_c_check "$machine_c_check_json" \
    --argjson three_machine_check "$three_machine_check_json" \
    --argjson profile_default_gate "$profile_default_gate_json" \
    --arg real_wg_host_linux "$real_wg_host_linux" \
    --arg real_wg_host_root "$real_wg_host_root" \
    --arg real_wg_host_has_wg "$real_wg_host_has_wg" \
    --arg real_wg_host_has_ip "$real_wg_host_has_ip" \
    --arg real_wg_host_eligible "$real_wg_host_eligible" \
    --arg real_wg_host_hint "$real_wg_host_hint" \
    '
      {
        version: 1,
        generated_at_utc: (now | todateiso8601),
        state_dir: $state_dir,
        status_json: $status_json,
        recorded_status: {
          file_exists: ($recorded_status_file_present == 1),
          valid_json: ($recorded_status_json_valid == 1),
          fallback_used: ($recorded_status_file_present == 1 and ($recorded_status_json_valid != 1)),
          warning: $recorded_status_json_warning
        },
        runtime_doctor_invocation: {
          timeout_sec: $runtime_doctor_timeout_sec,
          timed_out: ($runtime_doctor_timed_out == "1"),
          timeout_guard_available: ($runtime_doctor_timeout_guard_available == "1")
        },
        runtime_doctor_exit_code: ($runtime_doctor_json_rc | tonumber),
        runtime_doctor: $runtime_doctor,
        checks: [
          $runtime_hygiene_check,
          $wg_only_check,
          $docker_rehearsal_check,
          $real_wg_privileged_check,
          $machine_c_check,
          $three_machine_check
        ]
      }
      | .summary = {
          total_checks: (.checks | length),
          pass_checks: ([.checks[] | select(.status == "pass")] | length),
          warn_checks: ([.checks[] | select(.status == "warn")] | length),
          fail_checks: ([.checks[] | select(.status == "fail")] | length),
          pending_checks: ([.checks[] | select(.status == "pending")] | length),
          optional_check_ids: ["three_machine_docker_readiness", "real_wg_privileged_matrix"],
          blocking_check_ids: ["runtime_hygiene", "wg_only_stack_selftest", "machine_c_vpn_smoke", "three_machine_prod_signoff"],
          next_action_check_id: (([.checks[] | select(.check_id != "three_machine_docker_readiness" and .check_id != "real_wg_privileged_matrix" and .status != "pass" and .status != "skip") | .check_id][0]) // ""),
          next_action_label: (([.checks[] | select(.check_id != "three_machine_docker_readiness" and .check_id != "real_wg_privileged_matrix" and .status != "pass" and .status != "skip") | .label][0]) // ""),
          next_action_command: (([
            .checks[]
            | select(.check_id != "three_machine_docker_readiness" and .check_id != "real_wg_privileged_matrix" and .status != "pass" and .status != "skip")
            | (.remediation_command // .command // "")
            | select(length > 0)
          ][0]) // ""),
          next_action_remediations: (([
            .checks[]
            | select(.check_id != "three_machine_docker_readiness" and .check_id != "real_wg_privileged_matrix" and .status != "pass" and .status != "skip")
            | (.remediations // [])
          ][0]) // []),
          latest_failed_incident: (([
            .checks[]
            | select(.status == "fail" and (.incident_handoff.available // false))
            | {
                "check_id": .check_id,
                "label": .label,
                "recorded_at_utc": .recorded_at_utc,
                "source_summary_json": .incident_handoff.source_summary_json,
                "summary_json": .incident_handoff.summary_json,
                "report_md": .incident_handoff.report_md,
                "bundle_dir": .incident_handoff.bundle_dir,
                "bundle_tar": .incident_handoff.bundle_tar,
                "attachment_manifest": .incident_handoff.attachment_manifest,
                "attachment_skipped": .incident_handoff.attachment_skipped,
                "attachment_count": .incident_handoff.attachment_count,
                "readiness_report_summary_attachment": .incident_handoff.readiness_report_summary_attachment,
                "readiness_report_md_attachment": .incident_handoff.readiness_report_md_attachment,
                "readiness_report_log_attachment": .incident_handoff.readiness_report_log_attachment,
                "log": .incident_handoff.log
              }
          ] | sort_by(.recorded_at_utc // "") | reverse | .[0]) // null)
        }
      | .summary.pre_machine_c_gate = (
          {
            blockers: (
              [
                .checks[]
                | select((.check_id == "runtime_hygiene" or .check_id == "wg_only_stack_selftest") and (.status != "pass" and .status != "skip"))
                | .check_id
              ]
            ),
            next_check_id: "machine_c_vpn_smoke",
            next_label: (([.checks[] | select(.check_id == "machine_c_vpn_smoke") | .label][0]) // ""),
            next_command: (([.checks[] | select(.check_id == "machine_c_vpn_smoke") | .command][0]) // "")
          }
          | .ready = ((.blockers | length) == 0)
        )
      | .summary.local_gate = (
          {
            check_ids: ["runtime_hygiene", "wg_only_stack_selftest"],
            blockers: (.summary.pre_machine_c_gate.blockers // []),
            next_check_id: (
              if ((.summary.pre_machine_c_gate.blockers // []) | length) > 0 then
                (((.summary.pre_machine_c_gate.blockers // [])[0]) // "")
              else
                ""
              end
            )
          }
          | .ready = ((.blockers | length) == 0)
        )
      | .summary.real_host_gate = (
          {
            check_ids: ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
            blockers: (
              [
                .checks[]
                | select((.check_id == "machine_c_vpn_smoke" or .check_id == "three_machine_prod_signoff") and (.status != "pass" and .status != "skip"))
                | .check_id
              ]
            ),
            next_check_id: (
              ([
                .checks[]
                | select((.check_id == "machine_c_vpn_smoke" or .check_id == "three_machine_prod_signoff") and (.status != "pass" and .status != "skip"))
                | .check_id
              ][0]) // ""
            ),
            next_label: (
              ([
                .checks[]
                | select((.check_id == "machine_c_vpn_smoke" or .check_id == "three_machine_prod_signoff") and (.status != "pass" and .status != "skip"))
                | .label
              ][0]) // ""
            ),
            next_command: (
              ([
                .checks[]
                | select((.check_id == "machine_c_vpn_smoke" or .check_id == "three_machine_prod_signoff") and (.status != "pass" and .status != "skip"))
                | .command
              ][0]) // ""
            )
          }
          | .ready = ((.blockers | length) == 0)
        )
      | .summary.profile_default_gate = $profile_default_gate
      | .summary.profile_default_ready = ((.summary.profile_default_gate.status // "") == "pass")
      | .summary.docker_rehearsal_gate = (
          {
            check_id: "three_machine_docker_readiness",
            status: (([.checks[] | select(.check_id == "three_machine_docker_readiness") | .status][0]) // "pending"),
            notes: (([.checks[] | select(.check_id == "three_machine_docker_readiness") | .notes][0]) // ""),
            command: (([.checks[] | select(.check_id == "three_machine_docker_readiness") | .command][0]) // "")
          }
          | .next_command = (if .status == "pass" or .status == "skip" then "" else .command end)
          | .ready = (.status == "pass" or .status == "skip")
        )
      | .summary.real_wg_privileged_gate = (
          {
            check_id: "real_wg_privileged_matrix",
            status: (([.checks[] | select(.check_id == "real_wg_privileged_matrix") | .status][0]) // "pending"),
            notes: (([.checks[] | select(.check_id == "real_wg_privileged_matrix") | .notes][0]) // ""),
            command: (([.checks[] | select(.check_id == "real_wg_privileged_matrix") | .command][0]) // ""),
            host: {
              linux: ($real_wg_host_linux == "1"),
              root: ($real_wg_host_root == "1"),
              has_wg: ($real_wg_host_has_wg == "1"),
              has_ip: ($real_wg_host_has_ip == "1"),
              eligible: ($real_wg_host_eligible == "1"),
              hint: $real_wg_host_hint
            }
          }
          | .next_command = (if .status == "pass" or .status == "skip" then "" else .command end)
          | .notes = (
              if (.notes | length) > 0 then
                .notes
              elif .status == "pending" and (.host.eligible | not) then
                .host.hint
              else
                .notes
              end
            )
          | .ready = (.status == "pass" or .status == "skip")
        )
      | .summary.single_machine_ready = (.summary.local_gate.ready // false)
      | .summary.roadmap_stage = (
          if (.summary.local_gate.ready // false) | not then
            "BLOCKED_LOCAL"
          elif (.summary.real_host_gate.ready // false) then
            "PRODUCTION_SIGNOFF_COMPLETE"
          elif ((.summary.real_host_gate.blockers // []) | index("machine_c_vpn_smoke")) != null then
            "READY_FOR_MACHINE_C_SMOKE"
          elif ((.summary.real_host_gate.blockers // []) | index("three_machine_prod_signoff")) != null then
            "READY_FOR_3_MACHINE_PROD_SIGNOFF"
          else
            "IN_PROGRESS"
          end
        )
    '
)"

echo "[manual-validation-status] state_dir=$state_dir"
printf '%s\n' "$combined_json" | jq -r '
  .checks[]
  | "[manual-validation-status] \(.check_id)=\(.status | ascii_upcase) label=\"\(.label)\" recorded_at=\(.recorded_at_utc // "")"
' 
printf '%s\n' "$combined_json" | jq -r '
  .checks[]
  | select((.notes // "") | length > 0)
  | "  note: \(.notes)"
'
printf '%s\n' "$combined_json" | jq -r '
  .checks[]
  | select((.artifacts // []) | length > 0)
  | "  artifacts: \((.artifacts // []) | join(" "))"
'
printf '%s\n' "$combined_json" | jq -r '
  .checks[]
  | select((.incident_handoff.available // false) == true)
  | "  incident_handoff source_summary_json=\(.incident_handoff.source_summary_json.path // "") receipt_json=\(.incident_handoff.receipt_json.path // "") summary_json=\(.incident_handoff.summary_json.path // "") report_md=\(.incident_handoff.report_md.path // "") bundle_dir=\(.incident_handoff.bundle_dir.path // "") bundle_tar=\(.incident_handoff.bundle_tar.path // "") attachment_manifest=\(.incident_handoff.attachment_manifest.path // "") readiness_report_summary_attachment=\(.incident_handoff.readiness_report_summary_attachment.bundle_path // "") readiness_report_md_attachment=\(.incident_handoff.readiness_report_md_attachment.bundle_path // "")"
'
next_action_check_id="$(printf '%s\n' "$combined_json" | jq -r '.summary.next_action_check_id // ""')"
next_action_command="$(printf '%s\n' "$combined_json" | jq -r '.summary.next_action_command // ""')"
next_action_remediations_json="$(printf '%s\n' "$combined_json" | jq -c '.summary.next_action_remediations // []')"
if [[ -n "$next_action_check_id" ]]; then
  echo "[manual-validation-status] next_action_check_id=$next_action_check_id"
fi
if [[ -n "$next_action_command" ]]; then
  echo "[manual-validation-status] next_action_command=$next_action_command"
fi
printf '%s\n' "$next_action_remediations_json" | jq -r '.[]? | "[manual-validation-status] next_action_remediation=\(.)"'
machine_c_smoke_ready="$(printf '%s\n' "$combined_json" | jq -r '.summary.pre_machine_c_gate.ready // false')"
machine_c_smoke_blockers="$(printf '%s\n' "$combined_json" | jq -r '(.summary.pre_machine_c_gate.blockers // []) | if length == 0 then "none" else join(",") end')"
machine_c_smoke_next_command="$(printf '%s\n' "$combined_json" | jq -r '.summary.pre_machine_c_gate.next_command // ""')"
single_machine_ready="$(printf '%s\n' "$combined_json" | jq -r '.summary.single_machine_ready // false')"
roadmap_stage="$(printf '%s\n' "$combined_json" | jq -r '.summary.roadmap_stage // ""')"
real_host_gate_ready="$(printf '%s\n' "$combined_json" | jq -r '.summary.real_host_gate.ready // false')"
real_host_gate_blockers="$(printf '%s\n' "$combined_json" | jq -r '(.summary.real_host_gate.blockers // []) | if length == 0 then "none" else join(",") end')"
real_host_gate_next_command="$(printf '%s\n' "$combined_json" | jq -r '.summary.real_host_gate.next_command // ""')"
profile_default_gate_status="$(printf '%s\n' "$combined_json" | jq -r '.summary.profile_default_gate.status // ""')"
profile_default_gate_available="$(printf '%s\n' "$combined_json" | jq -r '.summary.profile_default_gate.available // false')"
profile_default_gate_decision="$(printf '%s\n' "$combined_json" | jq -r '.summary.profile_default_gate.decision // ""')"
profile_default_gate_recommended_profile="$(printf '%s\n' "$combined_json" | jq -r '.summary.profile_default_gate.recommended_profile // ""')"
profile_default_gate_summary_json="$(printf '%s\n' "$combined_json" | jq -r '.summary.profile_default_gate.summary_json // ""')"
profile_default_gate_next_command="$(printf '%s\n' "$combined_json" | jq -r '.summary.profile_default_gate.next_command // ""')"
docker_rehearsal_status="$(printf '%s\n' "$combined_json" | jq -r '.summary.docker_rehearsal_gate.status // ""')"
docker_rehearsal_ready="$(printf '%s\n' "$combined_json" | jq -r '.summary.docker_rehearsal_gate.ready // false')"
docker_rehearsal_command="$(printf '%s\n' "$combined_json" | jq -r '.summary.docker_rehearsal_gate.command // ""')"
real_wg_privileged_status="$(printf '%s\n' "$combined_json" | jq -r '.summary.real_wg_privileged_gate.status // ""')"
real_wg_privileged_ready="$(printf '%s\n' "$combined_json" | jq -r '.summary.real_wg_privileged_gate.ready // false')"
real_wg_privileged_command="$(printf '%s\n' "$combined_json" | jq -r '.summary.real_wg_privileged_gate.command // ""')"
echo "[manual-validation-status] machine_c_smoke_ready=$machine_c_smoke_ready"
echo "[manual-validation-status] machine_c_smoke_blockers=$machine_c_smoke_blockers"
if [[ -n "$machine_c_smoke_next_command" ]]; then
  echo "[manual-validation-status] machine_c_smoke_next_command=$machine_c_smoke_next_command"
fi
echo "[manual-validation-status] single_machine_ready=$single_machine_ready"
if [[ -n "$roadmap_stage" ]]; then
  echo "[manual-validation-status] roadmap_stage=$roadmap_stage"
fi
echo "[manual-validation-status] real_host_gate_ready=$real_host_gate_ready"
echo "[manual-validation-status] real_host_gate_blockers=$real_host_gate_blockers"
if [[ -n "$real_host_gate_next_command" ]]; then
  echo "[manual-validation-status] real_host_gate_next_command=$real_host_gate_next_command"
fi
if [[ -n "$profile_default_gate_status" ]]; then
  echo "[manual-validation-status] profile_default_gate_status=$profile_default_gate_status"
fi
echo "[manual-validation-status] profile_default_gate_available=$profile_default_gate_available"
if [[ -n "$profile_default_gate_decision" ]]; then
  echo "[manual-validation-status] profile_default_gate_decision=$profile_default_gate_decision"
fi
if [[ -n "$profile_default_gate_recommended_profile" ]]; then
  echo "[manual-validation-status] profile_default_gate_recommended_profile=$profile_default_gate_recommended_profile"
fi
if [[ -n "$profile_default_gate_summary_json" ]]; then
  echo "[manual-validation-status] profile_default_gate_summary_json=$profile_default_gate_summary_json"
fi
if [[ -n "$profile_default_gate_next_command" ]]; then
  echo "[manual-validation-status] profile_default_gate_next_command=$profile_default_gate_next_command"
fi
if [[ -n "$docker_rehearsal_status" ]]; then
  echo "[manual-validation-status] docker_rehearsal_status=$docker_rehearsal_status"
fi
echo "[manual-validation-status] docker_rehearsal_ready=$docker_rehearsal_ready"
if [[ -n "$docker_rehearsal_command" ]]; then
  echo "[manual-validation-status] docker_rehearsal_command=$docker_rehearsal_command"
fi
if [[ -n "$real_wg_privileged_status" ]]; then
  echo "[manual-validation-status] real_wg_privileged_status=$real_wg_privileged_status"
fi
echo "[manual-validation-status] real_wg_privileged_ready=$real_wg_privileged_ready"
if [[ -n "$real_wg_privileged_command" ]]; then
  echo "[manual-validation-status] real_wg_privileged_command=$real_wg_privileged_command"
fi
latest_failed_incident_check_id="$(printf '%s\n' "$combined_json" | jq -r '.summary.latest_failed_incident.check_id // ""')"
latest_failed_incident_summary_json="$(printf '%s\n' "$combined_json" | jq -r '.summary.latest_failed_incident.summary_json.path // ""')"
latest_failed_incident_report_md="$(printf '%s\n' "$combined_json" | jq -r '.summary.latest_failed_incident.report_md.path // ""')"
latest_failed_incident_bundle_dir="$(printf '%s\n' "$combined_json" | jq -r '.summary.latest_failed_incident.bundle_dir.path // ""')"
latest_failed_incident_readiness_report_summary_attachment="$(printf '%s\n' "$combined_json" | jq -r '.summary.latest_failed_incident.readiness_report_summary_attachment.bundle_path // ""')"
latest_failed_incident_readiness_report_md_attachment="$(printf '%s\n' "$combined_json" | jq -r '.summary.latest_failed_incident.readiness_report_md_attachment.bundle_path // ""')"
if [[ -n "$latest_failed_incident_check_id" ]]; then
  echo "[manual-validation-status] latest_failed_incident_check_id=$latest_failed_incident_check_id"
fi
if [[ -n "$latest_failed_incident_summary_json" ]]; then
  echo "[manual-validation-status] latest_failed_incident_summary_json=$latest_failed_incident_summary_json"
fi
if [[ -n "$latest_failed_incident_report_md" ]]; then
  echo "[manual-validation-status] latest_failed_incident_report_md=$latest_failed_incident_report_md"
fi
if [[ -n "$latest_failed_incident_bundle_dir" ]]; then
  echo "[manual-validation-status] latest_failed_incident_bundle_dir=$latest_failed_incident_bundle_dir"
fi
if [[ -n "$latest_failed_incident_readiness_report_summary_attachment" ]]; then
  echo "[manual-validation-status] latest_failed_incident_readiness_report_summary_attachment=$latest_failed_incident_readiness_report_summary_attachment"
fi
if [[ -n "$latest_failed_incident_readiness_report_md_attachment" ]]; then
  echo "[manual-validation-status] latest_failed_incident_readiness_report_md_attachment=$latest_failed_incident_readiness_report_md_attachment"
fi

if [[ "$show_json" == "1" ]]; then
  echo "[manual-validation-status] summary_json_payload:"
  printf '%s\n' "$combined_json"
fi
