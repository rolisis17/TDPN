#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod cp touch; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

REPORT_SCRIPT_SOURCE="$ROOT_DIR/scripts/roadmap_progress_report.sh"
if [[ ! -f "$REPORT_SCRIPT_SOURCE" ]]; then
  echo "missing report script: $REPORT_SCRIPT_SOURCE"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

WORKSPACE="$TMP_DIR/workspace"
mkdir -p "$WORKSPACE/scripts" "$WORKSPACE/.easy-node-logs"
cp "$REPORT_SCRIPT_SOURCE" "$WORKSPACE/scripts/roadmap_progress_report.sh"
chmod +x "$WORKSPACE/scripts/roadmap_progress_report.sh"

MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_summary.json"
MANUAL_REPORT_MD="$TMP_DIR/manual_validation_report.md"
cat >"$MANUAL_SUMMARY_JSON" <<'EOF_MANUAL'
{
  "version": 1,
  "summary": {
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_MANUAL

CHECK_SUMMARY_JSON="$TMP_DIR/phase2_linux_prod_candidate_check_summary.json"
RUN_SUMMARY_JSON="$TMP_DIR/phase2_linux_prod_candidate_run_summary.json"
NEWER_CHECK_SUMMARY_JSON="$TMP_DIR/phase2_linux_prod_candidate_check_summary_newer.json"
DRY_RUN_CHECK_SUMMARY_JSON="$TMP_DIR/phase2_linux_prod_candidate_check_summary_dry_run_newer.json"
INCOMPLETE_CHECK_SUMMARY_JSON="$TMP_DIR/phase2_linux_prod_candidate_check_summary_incomplete_newer.json"
INVALID_SUMMARY_JSON="$TMP_DIR/phase2_linux_prod_candidate_invalid_summary.json"

cat >"$CHECK_SUMMARY_JSON" <<EOF_CHECK
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "release_integrity_ok": true,
    "release_policy_ok": false,
    "operator_lifecycle_ok": true,
    "pilot_signoff_ok": false
  },
  "stages": {
    "release_integrity": {
      "status": "pass",
      "ok": true
    },
    "release_policy": {
      "status": "fail",
      "ok": false
    },
    "operator_lifecycle": {
      "status": "pass",
      "ok": true
    },
    "pilot_signoff": {
      "status": "fail",
      "ok": false
    }
  }
}
EOF_CHECK

cat >"$RUN_SUMMARY_JSON" <<EOF_RUN
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "artifacts": {
    "check_summary_json": "$CHECK_SUMMARY_JSON"
  },
  "steps": {
    "phase2_linux_prod_candidate_check": {
      "artifacts": {
        "summary_json": "$CHECK_SUMMARY_JSON"
      }
    }
  }
}
EOF_RUN

cat >"$NEWER_CHECK_SUMMARY_JSON" <<'EOF_NEWER_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "warn",
  "rc": 7,
  "signals": {
    "release_integrity_ok": false,
    "release_policy_ok": true,
    "operator_lifecycle_ok": false,
    "pilot_signoff_ok": true
  },
  "stages": {
    "release_integrity": {
      "status": "fail",
      "ok": false
    },
    "release_policy": {
      "status": "pass",
      "ok": true
    },
    "operator_lifecycle": {
      "status": "fail",
      "ok": false
    },
    "pilot_signoff": {
      "status": "pass",
      "ok": true
    }
  }
}
EOF_NEWER_CHECK

cat >"$DRY_RUN_CHECK_SUMMARY_JSON" <<'EOF_DRY_RUN_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "warn",
  "rc": 11,
  "inputs": {
    "dry_run": true
  },
  "signals": {
    "release_integrity_ok": false,
    "release_policy_ok": true,
    "operator_lifecycle_ok": false,
    "pilot_signoff_ok": true
  },
  "stages": {
    "release_integrity": {
      "status": "fail",
      "ok": false
    },
    "release_policy": {
      "status": "pass",
      "ok": true
    },
    "operator_lifecycle": {
      "status": "fail",
      "ok": false
    },
    "pilot_signoff": {
      "status": "pass",
      "ok": true
    }
  }
}
EOF_DRY_RUN_CHECK

cat >"$INCOMPLETE_CHECK_SUMMARY_JSON" <<'EOF_INCOMPLETE_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "warn",
  "rc": 9,
  "signals": {
    "release_integrity_ok": null,
    "release_policy_ok": null,
    "operator_lifecycle_ok": null,
    "pilot_signoff_ok": null
  },
  "stages": {
    "release_integrity": {
      "status": "unknown"
    },
    "release_policy": {
      "status": "unknown"
    },
    "operator_lifecycle": {
      "status": "unknown"
    },
    "pilot_signoff": {
      "status": "unknown"
    }
  }
}
EOF_INCOMPLETE_CHECK

cat >"$INVALID_SUMMARY_JSON" <<'EOF_INVALID'
{"version":1
EOF_INVALID

run_report() {
  local summary_json="$1"
  local report_md="$2"
  shift 2
  bash "$WORKSPACE/scripts/roadmap_progress_report.sh" \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
    --manual-validation-report-md "$MANUAL_REPORT_MD" \
    --summary-json "$summary_json" \
    --report-md "$report_md" \
    --print-report 0 \
    --print-summary-json 0 \
    "$@"
}

assert_phase2_block() {
  local summary_json="$1"
  local input_json="$2"
  local source_json="$3"
  local source_kind="$4"
  jq -e \
    --arg input_json "$input_json" \
    --arg source_json "$source_json" \
    --arg source_kind "$source_kind" \
    '
      .vpn_track.phase2_linux_prod_candidate_handoff.available == true
      and .vpn_track.phase2_linux_prod_candidate_handoff.input_summary_json == $input_json
      and .vpn_track.phase2_linux_prod_candidate_handoff.source_summary_json == $source_json
      and .vpn_track.phase2_linux_prod_candidate_handoff.source_summary_kind == $source_kind
      and .vpn_track.phase2_linux_prod_candidate_handoff.status == "pass"
      and .vpn_track.phase2_linux_prod_candidate_handoff.rc == 0
      and .vpn_track.phase2_linux_prod_candidate_handoff.release_integrity_ok == true
      and .vpn_track.phase2_linux_prod_candidate_handoff.release_policy_ok == false
      and .vpn_track.phase2_linux_prod_candidate_handoff.operator_lifecycle_ok == true
      and .vpn_track.phase2_linux_prod_candidate_handoff.pilot_signoff_ok == false
      and .artifacts.phase2_linux_prod_candidate_summary_json == $input_json
    ' "$summary_json" >/dev/null
}

assert_phase2_missing_block() {
  local summary_json="$1"
  jq -e '
    .vpn_track.phase2_linux_prod_candidate_handoff.available == false
    and .vpn_track.phase2_linux_prod_candidate_handoff.input_summary_json == null
    and .vpn_track.phase2_linux_prod_candidate_handoff.source_summary_json == null
    and .vpn_track.phase2_linux_prod_candidate_handoff.source_summary_kind == null
    and .vpn_track.phase2_linux_prod_candidate_handoff.status == "missing"
    and .vpn_track.phase2_linux_prod_candidate_handoff.rc == null
    and .vpn_track.phase2_linux_prod_candidate_handoff.release_integrity_ok == null
    and .vpn_track.phase2_linux_prod_candidate_handoff.release_policy_ok == null
    and .vpn_track.phase2_linux_prod_candidate_handoff.operator_lifecycle_ok == null
    and .vpn_track.phase2_linux_prod_candidate_handoff.pilot_signoff_ok == null
    and .artifacts.phase2_linux_prod_candidate_summary_json == null
  ' "$summary_json" >/dev/null
}

echo "[roadmap-progress-phase2-handoff] explicit check summary path"
EXPLICIT_CHECK_SUMMARY_JSON="$TMP_DIR/roadmap_progress_explicit_check.json"
EXPLICIT_CHECK_REPORT_MD="$TMP_DIR/roadmap_progress_explicit_check.md"
run_report "$EXPLICIT_CHECK_SUMMARY_JSON" "$EXPLICIT_CHECK_REPORT_MD" \
  --phase2-linux-prod-candidate-summary-json "$CHECK_SUMMARY_JSON"
assert_phase2_block "$EXPLICIT_CHECK_SUMMARY_JSON" "$CHECK_SUMMARY_JSON" "$CHECK_SUMMARY_JSON" "check"

echo "[roadmap-progress-phase2-handoff] explicit run summary path"
EXPLICIT_RUN_SUMMARY_JSON="$TMP_DIR/roadmap_progress_explicit_run.json"
EXPLICIT_RUN_REPORT_MD="$TMP_DIR/roadmap_progress_explicit_run.md"
run_report "$EXPLICIT_RUN_SUMMARY_JSON" "$EXPLICIT_RUN_REPORT_MD" \
  --phase2-linux-prod-candidate-summary-json "$RUN_SUMMARY_JSON"
assert_phase2_block "$EXPLICIT_RUN_SUMMARY_JSON" "$RUN_SUMMARY_JSON" "$CHECK_SUMMARY_JSON" "check"

echo "[roadmap-progress-phase2-handoff] missing-input fail-soft path"
MISSING_SUMMARY_JSON="$TMP_DIR/roadmap_progress_missing_phase2.json"
MISSING_REPORT_MD="$TMP_DIR/roadmap_progress_missing_phase2.md"
run_report "$MISSING_SUMMARY_JSON" "$MISSING_REPORT_MD"
assert_phase2_missing_block "$MISSING_SUMMARY_JSON"

echo "[roadmap-progress-phase2-handoff] .easy-node-logs fallback path"
PHASE2_OLD_DIR="$WORKSPACE/.easy-node-logs/zzz_old_valid"
PHASE2_NEW_DIR="$WORKSPACE/.easy-node-logs/aaa_new_valid"
PHASE2_INVALID_DIR="$WORKSPACE/.easy-node-logs/yyy_invalid_newest"
mkdir -p "$PHASE2_OLD_DIR" "$PHASE2_NEW_DIR" "$PHASE2_INVALID_DIR"
PHASE2_OLD_JSON="$PHASE2_OLD_DIR/phase2_linux_prod_candidate_check_summary.json"
PHASE2_NEW_JSON="$PHASE2_NEW_DIR/phase2_linux_prod_candidate_check_summary.json"
PHASE2_INVALID_JSON="$PHASE2_INVALID_DIR/phase2_linux_prod_candidate_run_summary.json"
cp "$CHECK_SUMMARY_JSON" "$PHASE2_OLD_JSON"
cp "$NEWER_CHECK_SUMMARY_JSON" "$PHASE2_NEW_JSON"
cp "$INVALID_SUMMARY_JSON" "$PHASE2_INVALID_JSON"
touch -t 202601010101 "$PHASE2_OLD_JSON"
touch -t 202601020202 "$PHASE2_NEW_JSON"
touch -t 202601030303 "$PHASE2_INVALID_JSON"
FALLBACK_SUMMARY_JSON="$TMP_DIR/roadmap_progress_fallback_phase2.json"
FALLBACK_REPORT_MD="$TMP_DIR/roadmap_progress_fallback_phase2.md"
run_report "$FALLBACK_SUMMARY_JSON" "$FALLBACK_REPORT_MD"
jq -e \
  --arg new_json "$PHASE2_NEW_JSON" \
  '
    .vpn_track.phase2_linux_prod_candidate_handoff.available == true
    and .vpn_track.phase2_linux_prod_candidate_handoff.input_summary_json == $new_json
    and .vpn_track.phase2_linux_prod_candidate_handoff.source_summary_json == $new_json
    and .vpn_track.phase2_linux_prod_candidate_handoff.source_summary_kind == "check"
    and .vpn_track.phase2_linux_prod_candidate_handoff.status == "warn"
    and .vpn_track.phase2_linux_prod_candidate_handoff.rc == 7
    and .vpn_track.phase2_linux_prod_candidate_handoff.release_integrity_ok == false
    and .vpn_track.phase2_linux_prod_candidate_handoff.release_policy_ok == true
    and .vpn_track.phase2_linux_prod_candidate_handoff.operator_lifecycle_ok == false
    and .vpn_track.phase2_linux_prod_candidate_handoff.pilot_signoff_ok == true
    and .artifacts.phase2_linux_prod_candidate_summary_json == $new_json
  ' "$FALLBACK_SUMMARY_JSON" >/dev/null

echo "[roadmap-progress-phase2-handoff] .easy-node-logs fallback prefers complete summary over newer incomplete summary"
PHASE2_COMPLETE_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/bbb_complete_older"
PHASE2_INCOMPLETE_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/ccc_incomplete_newer"
mkdir -p "$PHASE2_COMPLETE_FALLBACK_DIR" "$PHASE2_INCOMPLETE_FALLBACK_DIR"
PHASE2_COMPLETE_FALLBACK_JSON="$PHASE2_COMPLETE_FALLBACK_DIR/phase2_linux_prod_candidate_check_summary.json"
PHASE2_INCOMPLETE_FALLBACK_JSON="$PHASE2_INCOMPLETE_FALLBACK_DIR/phase2_linux_prod_candidate_check_summary.json"
cp "$CHECK_SUMMARY_JSON" "$PHASE2_COMPLETE_FALLBACK_JSON"
cp "$INCOMPLETE_CHECK_SUMMARY_JSON" "$PHASE2_INCOMPLETE_FALLBACK_JSON"
touch -t 202601040101 "$PHASE2_COMPLETE_FALLBACK_JSON"
touch -t 202601040202 "$PHASE2_INCOMPLETE_FALLBACK_JSON"
FALLBACK_COMPLETE_PREFERRED_SUMMARY_JSON="$TMP_DIR/roadmap_progress_fallback_phase2_complete_preferred.json"
FALLBACK_COMPLETE_PREFERRED_REPORT_MD="$TMP_DIR/roadmap_progress_fallback_phase2_complete_preferred.md"
run_report "$FALLBACK_COMPLETE_PREFERRED_SUMMARY_JSON" "$FALLBACK_COMPLETE_PREFERRED_REPORT_MD"
assert_phase2_block "$FALLBACK_COMPLETE_PREFERRED_SUMMARY_JSON" "$PHASE2_COMPLETE_FALLBACK_JSON" "$PHASE2_COMPLETE_FALLBACK_JSON" "check"

echo "[roadmap-progress-phase2-handoff] .easy-node-logs fallback prefers non-dry source over newer dry-run candidate"
PHASE2_NON_DRY_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/ddd_non_dry_older"
PHASE2_DRY_RUN_FALLBACK_DIR="$WORKSPACE/.easy-node-logs/eee_dry_run_newer"
mkdir -p "$PHASE2_NON_DRY_FALLBACK_DIR" "$PHASE2_DRY_RUN_FALLBACK_DIR"
PHASE2_NON_DRY_FALLBACK_JSON="$PHASE2_NON_DRY_FALLBACK_DIR/phase2_linux_prod_candidate_check_summary.json"
PHASE2_DRY_RUN_FALLBACK_JSON="$PHASE2_DRY_RUN_FALLBACK_DIR/phase2_linux_prod_candidate_check_summary.json"
cp "$CHECK_SUMMARY_JSON" "$PHASE2_NON_DRY_FALLBACK_JSON"
cp "$DRY_RUN_CHECK_SUMMARY_JSON" "$PHASE2_DRY_RUN_FALLBACK_JSON"
touch -t 202601040301 "$PHASE2_NON_DRY_FALLBACK_JSON"
touch -t 202601040302 "$PHASE2_DRY_RUN_FALLBACK_JSON"
FALLBACK_NON_DRY_PREFERRED_SUMMARY_JSON="$TMP_DIR/roadmap_progress_fallback_phase2_non_dry_preferred.json"
FALLBACK_NON_DRY_PREFERRED_REPORT_MD="$TMP_DIR/roadmap_progress_fallback_phase2_non_dry_preferred.md"
run_report "$FALLBACK_NON_DRY_PREFERRED_SUMMARY_JSON" "$FALLBACK_NON_DRY_PREFERRED_REPORT_MD"
assert_phase2_block "$FALLBACK_NON_DRY_PREFERRED_SUMMARY_JSON" "$PHASE2_NON_DRY_FALLBACK_JSON" "$PHASE2_NON_DRY_FALLBACK_JSON" "check"

echo "[roadmap-progress-phase2-handoff] .easy-node-logs equal-mtime tie-break uses deterministic path"
PHASE2_TIE_LOW_DIR="$WORKSPACE/.easy-node-logs/aaa_tie_low"
PHASE2_TIE_HIGH_DIR="$WORKSPACE/.easy-node-logs/zzz_tie_high"
mkdir -p "$PHASE2_TIE_LOW_DIR" "$PHASE2_TIE_HIGH_DIR"
PHASE2_TIE_LOW_JSON="$PHASE2_TIE_LOW_DIR/phase2_linux_prod_candidate_check_summary.json"
PHASE2_TIE_HIGH_JSON="$PHASE2_TIE_HIGH_DIR/phase2_linux_prod_candidate_check_summary.json"
cp "$CHECK_SUMMARY_JSON" "$PHASE2_TIE_LOW_JSON"
cp "$NEWER_CHECK_SUMMARY_JSON" "$PHASE2_TIE_HIGH_JSON"
touch -t 202601040404 "$PHASE2_TIE_LOW_JSON"
touch -t 202601040404 "$PHASE2_TIE_HIGH_JSON"
TIE_BREAK_SUMMARY_JSON="$TMP_DIR/roadmap_progress_fallback_phase2_tie_break.json"
TIE_BREAK_REPORT_MD="$TMP_DIR/roadmap_progress_fallback_phase2_tie_break.md"
run_report "$TIE_BREAK_SUMMARY_JSON" "$TIE_BREAK_REPORT_MD"
jq -e \
  --arg high_json "$PHASE2_TIE_HIGH_JSON" \
  '
    .vpn_track.phase2_linux_prod_candidate_handoff.available == true
    and .vpn_track.phase2_linux_prod_candidate_handoff.input_summary_json == $high_json
    and .vpn_track.phase2_linux_prod_candidate_handoff.source_summary_json == $high_json
    and .vpn_track.phase2_linux_prod_candidate_handoff.source_summary_kind == "check"
    and .vpn_track.phase2_linux_prod_candidate_handoff.status == "warn"
    and .vpn_track.phase2_linux_prod_candidate_handoff.rc == 7
    and .vpn_track.phase2_linux_prod_candidate_handoff.release_integrity_ok == false
    and .vpn_track.phase2_linux_prod_candidate_handoff.release_policy_ok == true
    and .vpn_track.phase2_linux_prod_candidate_handoff.operator_lifecycle_ok == false
    and .vpn_track.phase2_linux_prod_candidate_handoff.pilot_signoff_ok == true
    and .artifacts.phase2_linux_prod_candidate_summary_json == $high_json
  ' "$TIE_BREAK_SUMMARY_JSON" >/dev/null

echo "roadmap progress phase2 handoff integration ok"
