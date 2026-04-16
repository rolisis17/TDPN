#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp chmod mkdir touch cp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
MISSING_SUMMARY="$TMP_DIR/does_not_exist.json"

MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_summary.json"
cat >"$MANUAL_SUMMARY_JSON" <<'EOF_MANUAL_SUMMARY'
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
EOF_MANUAL_SUMMARY

echo "[roadmap-progress-resilience] missing resilience artifact remains backward compatible"
SUMMARY_MISSING_JSON="$TMP_DIR/roadmap_progress_missing_resilience.json"
REPORT_MISSING_MD="$TMP_DIR/roadmap_progress_missing_resilience.md"
ROADMAP_PROGRESS_VPN_RC_RESILIENCE_SUMMARY_JSON="$TMP_DIR/does_not_exist.json" \
./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$MISSING_SUMMARY" \
  --summary-json "$SUMMARY_MISSING_JSON" \
  --report-md "$REPORT_MISSING_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_missing.log 2>&1

if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .vpn_track.resilience_handoff.available == false
  and .vpn_track.resilience_handoff.source_summary_json == null
  and .vpn_track.resilience_handoff.profile_matrix_stable == null
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == null
  and .vpn_track.resilience_handoff.session_churn_guard_ok == null
  and .artifacts.vpn_rc_resilience_summary_json == null
' "$SUMMARY_MISSING_JSON" >/dev/null; then
  echo "missing-artifact path summary JSON mismatch"
  cat "$SUMMARY_MISSING_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] explicit resilience artifact booleans"
RESILIENCE_DIRECT_JSON="$TMP_DIR/vpn_rc_resilience_direct.json"
cat >"$RESILIENCE_DIRECT_JSON" <<'EOF_RESILIENCE_DIRECT'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": false,
  "session_churn_guard_ok": true
}
EOF_RESILIENCE_DIRECT

SUMMARY_DIRECT_JSON="$TMP_DIR/roadmap_progress_direct_resilience.json"
REPORT_DIRECT_MD="$TMP_DIR/roadmap_progress_direct_resilience.md"
./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$MISSING_SUMMARY" \
  --vpn-rc-resilience-summary-json "$RESILIENCE_DIRECT_JSON" \
  --summary-json "$SUMMARY_DIRECT_JSON" \
  --report-md "$REPORT_DIRECT_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_direct.log 2>&1

if ! jq -e --arg src "$RESILIENCE_DIRECT_JSON" '
  .vpn_track.resilience_handoff.available == true
  and .vpn_track.resilience_handoff.source_summary_json == $src
  and .vpn_track.resilience_handoff.profile_matrix_stable == true
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == false
  and .vpn_track.resilience_handoff.session_churn_guard_ok == true
  and .artifacts.vpn_rc_resilience_summary_json == $src
' "$SUMMARY_DIRECT_JSON" >/dev/null; then
  echo "explicit-artifact path summary JSON mismatch"
  cat "$SUMMARY_DIRECT_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] legacy resilience artifact fallback derivation"
RESILIENCE_LEGACY_JSON="$TMP_DIR/vpn_rc_resilience_legacy.json"
cat >"$RESILIENCE_LEGACY_JSON" <<'EOF_RESILIENCE_LEGACY'
{
  "version": 1,
  "steps": {
    "three_machine_docker_profile_matrix": {
      "status": "pass"
    },
    "vpn_rc_matrix_path": {
      "status": "fail"
    }
  }
}
EOF_RESILIENCE_LEGACY

SUMMARY_LEGACY_JSON="$TMP_DIR/roadmap_progress_legacy_resilience.json"
REPORT_LEGACY_MD="$TMP_DIR/roadmap_progress_legacy_resilience.md"
./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$MISSING_SUMMARY" \
  --vpn-rc-resilience-summary-json "$RESILIENCE_LEGACY_JSON" \
  --summary-json "$SUMMARY_LEGACY_JSON" \
  --report-md "$REPORT_LEGACY_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_legacy.log 2>&1

if ! jq -e --arg src "$RESILIENCE_LEGACY_JSON" '
  .vpn_track.resilience_handoff.available == true
  and .vpn_track.resilience_handoff.source_summary_json == $src
  and .vpn_track.resilience_handoff.profile_matrix_stable == true
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == false
  and .vpn_track.resilience_handoff.session_churn_guard_ok == false
  and .artifacts.vpn_rc_resilience_summary_json == $src
' "$SUMMARY_LEGACY_JSON" >/dev/null; then
  echo "legacy-artifact fallback summary JSON mismatch"
  cat "$SUMMARY_LEGACY_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] auto-discovery prefers freshest valid summary by mtime"
RESILIENCE_LOGS_ROOT="$TMP_DIR/resilience_logs_root"
RESILIENCE_OLD_DIR="$RESILIENCE_LOGS_ROOT/zzz_old_path"
RESILIENCE_NEW_DIR="$RESILIENCE_LOGS_ROOT/aaa_new_path"
RESILIENCE_INVALID_DIR="$RESILIENCE_LOGS_ROOT/yyy_invalid_newest"
mkdir -p "$RESILIENCE_OLD_DIR" "$RESILIENCE_NEW_DIR" "$RESILIENCE_INVALID_DIR"

RESILIENCE_OLD_JSON="$RESILIENCE_OLD_DIR/vpn_rc_resilience_path_summary.json"
cat >"$RESILIENCE_OLD_JSON" <<'EOF_RESILIENCE_OLD'
{
  "version": 1,
  "profile_matrix_stable": false,
  "peer_loss_recovery_ok": false,
  "session_churn_guard_ok": false
}
EOF_RESILIENCE_OLD
touch -t 202601010101 "$RESILIENCE_OLD_JSON"

RESILIENCE_NEW_JSON="$RESILIENCE_NEW_DIR/vpn_rc_resilience_path_summary.json"
cat >"$RESILIENCE_NEW_JSON" <<'EOF_RESILIENCE_NEW'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": true
}
EOF_RESILIENCE_NEW
touch -t 202601020202 "$RESILIENCE_NEW_JSON"

RESILIENCE_INVALID_JSON="$RESILIENCE_INVALID_DIR/vpn_rc_resilience_path_summary.json"
printf '{"version": 1, "profile_matrix_stable": true' >"$RESILIENCE_INVALID_JSON"
touch -t 202601030303 "$RESILIENCE_INVALID_JSON"

SUMMARY_AUTO_RESILIENCE_JSON="$TMP_DIR/roadmap_progress_auto_resilience_source.json"
REPORT_AUTO_RESILIENCE_MD="$TMP_DIR/roadmap_progress_auto_resilience_source.md"
ROADMAP_PROGRESS_LOGS_ROOT="$RESILIENCE_LOGS_ROOT" \
./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$MISSING_SUMMARY" \
  --summary-json "$SUMMARY_AUTO_RESILIENCE_JSON" \
  --report-md "$REPORT_AUTO_RESILIENCE_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_auto_source.log 2>&1

if ! jq -e --arg src "$RESILIENCE_NEW_JSON" '
  .vpn_track.resilience_handoff.available == true
  and .vpn_track.resilience_handoff.source_summary_json == $src
  and .vpn_track.resilience_handoff.profile_matrix_stable == true
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.resilience_handoff.session_churn_guard_ok == true
  and .artifacts.vpn_rc_resilience_summary_json == $src
' "$SUMMARY_AUTO_RESILIENCE_JSON" >/dev/null; then
  echo "auto-source freshness summary JSON mismatch"
  cat "$SUMMARY_AUTO_RESILIENCE_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1-linked resilience summary takes precedence over newer global auto-discovery"
PHASE1_LINKED_PREF_WORKSPACE="$TMP_DIR/phase1_linked_resilience_precedence_workspace"
mkdir -p "$PHASE1_LINKED_PREF_WORKSPACE/scripts" "$PHASE1_LINKED_PREF_WORKSPACE/.easy-node-logs"
cp "$ROOT_DIR/scripts/roadmap_progress_report.sh" "$PHASE1_LINKED_PREF_WORKSPACE/scripts/roadmap_progress_report.sh"
chmod +x "$PHASE1_LINKED_PREF_WORKSPACE/scripts/roadmap_progress_report.sh"

PHASE1_LINKED_PREF_LOGS_ROOT="$PHASE1_LINKED_PREF_WORKSPACE/.easy-node-logs"
PHASE1_LINKED_PREF_PHASE1_DIR="$PHASE1_LINKED_PREF_LOGS_ROOT/phase1_source"
PHASE1_LINKED_PREF_GLOBAL_DIR="$PHASE1_LINKED_PREF_LOGS_ROOT/global_newer"
mkdir -p "$PHASE1_LINKED_PREF_PHASE1_DIR" "$PHASE1_LINKED_PREF_GLOBAL_DIR"

PHASE1_LINKED_PREF_RESILIENCE_JSON="$PHASE1_LINKED_PREF_PHASE1_DIR/vpn_rc_resilience_linked.json"
cat >"$PHASE1_LINKED_PREF_RESILIENCE_JSON" <<'EOF_PHASE1_LINKED_PREF_RESILIENCE'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": false,
  "session_churn_guard_ok": true
}
EOF_PHASE1_LINKED_PREF_RESILIENCE
touch -t 202602010101 "$PHASE1_LINKED_PREF_RESILIENCE_JSON"

PHASE1_LINKED_PREF_CI_JSON="$PHASE1_LINKED_PREF_PHASE1_DIR/ci_phase1_resilience_summary.json"
cat >"$PHASE1_LINKED_PREF_CI_JSON" <<'EOF_PHASE1_LINKED_PREF_CI'
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "vpn_rc_resilience_path": {
      "artifacts": {
        "summary_json": "vpn_rc_resilience_linked.json"
      }
    }
  }
}
EOF_PHASE1_LINKED_PREF_CI
touch -t 202602010102 "$PHASE1_LINKED_PREF_CI_JSON"

PHASE1_LINKED_PREF_HANDOFF_JSON="$PHASE1_LINKED_PREF_PHASE1_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_LINKED_PREF_HANDOFF_JSON" <<'EOF_PHASE1_LINKED_PREF_HANDOFF'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "ci_phase1_summary_json": "ci_phase1_resilience_summary.json"
  },
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": false,
    "session_churn_guard_ok": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_LINKED_PREF_HANDOFF
touch -t 202602010103 "$PHASE1_LINKED_PREF_HANDOFF_JSON"

PHASE1_LINKED_PREF_RUN_JSON="$PHASE1_LINKED_PREF_PHASE1_DIR/phase1_resilience_handoff_run_summary.json"
cat >"$PHASE1_LINKED_PREF_RUN_JSON" <<'EOF_PHASE1_LINKED_PREF_RUN'
{
  "schema": {
    "id": "phase1_resilience_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  },
  "artifacts": {
    "handoff_summary_json": "phase1_resilience_handoff_check_summary.json",
    "ci_summary_json": "ci_phase1_resilience_summary.json"
  },
  "steps": {
    "phase1_resilience_handoff_check": {
      "artifacts": {
        "summary_json": "phase1_resilience_handoff_check_summary.json"
      }
    },
    "ci_phase1_resilience": {
      "artifacts": {
        "summary_json": "ci_phase1_resilience_summary.json"
      }
    }
  }
}
EOF_PHASE1_LINKED_PREF_RUN
touch -t 202602010104 "$PHASE1_LINKED_PREF_RUN_JSON"

PHASE1_LINKED_PREF_GLOBAL_JSON="$PHASE1_LINKED_PREF_GLOBAL_DIR/vpn_rc_resilience_path_summary.json"
cat >"$PHASE1_LINKED_PREF_GLOBAL_JSON" <<'EOF_PHASE1_LINKED_PREF_GLOBAL'
{
  "version": 1,
  "profile_matrix_stable": false,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": false
}
EOF_PHASE1_LINKED_PREF_GLOBAL
touch -t 202602020202 "$PHASE1_LINKED_PREF_GLOBAL_JSON"

SUMMARY_PHASE1_LINKED_PREF_JSON="$TMP_DIR/roadmap_progress_phase1_linked_resilience_precedence.json"
REPORT_PHASE1_LINKED_PREF_MD="$TMP_DIR/roadmap_progress_phase1_linked_resilience_precedence.md"
ROADMAP_PROGRESS_LOGS_ROOT="$PHASE1_LINKED_PREF_LOGS_ROOT" \
bash "$PHASE1_LINKED_PREF_WORKSPACE/scripts/roadmap_progress_report.sh" \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$PHASE1_LINKED_PREF_RUN_JSON" \
  --summary-json "$SUMMARY_PHASE1_LINKED_PREF_JSON" \
  --report-md "$REPORT_PHASE1_LINKED_PREF_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1_linked_precedence.log 2>&1

if ! jq -e \
  --arg phase1_src "$PHASE1_LINKED_PREF_RUN_JSON" \
  --arg linked_src "$PHASE1_LINKED_PREF_RESILIENCE_JSON" \
  --arg global_src "$PHASE1_LINKED_PREF_GLOBAL_JSON" \
  '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $phase1_src
  and .vpn_track.resilience_handoff.available == true
  and .vpn_track.resilience_handoff.source_summary_json == $linked_src
  and .vpn_track.resilience_handoff.profile_matrix_stable == true
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == false
  and .vpn_track.resilience_handoff.session_churn_guard_ok == true
  and .artifacts.vpn_rc_resilience_summary_json == $linked_src
  and (.vpn_track.resilience_handoff.source_summary_json != $global_src)
' "$SUMMARY_PHASE1_LINKED_PREF_JSON" >/dev/null; then
  echo "phase1-linked resilience precedence mismatch"
  cat "$SUMMARY_PHASE1_LINKED_PREF_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1-linked resilience conflict resolves to phase1 handoff source"
PHASE1_CONFLICT_WORKSPACE="$TMP_DIR/phase1_linked_resilience_conflict_workspace"
mkdir -p "$PHASE1_CONFLICT_WORKSPACE/scripts" "$PHASE1_CONFLICT_WORKSPACE/.easy-node-logs"
cp "$ROOT_DIR/scripts/roadmap_progress_report.sh" "$PHASE1_CONFLICT_WORKSPACE/scripts/roadmap_progress_report.sh"
chmod +x "$PHASE1_CONFLICT_WORKSPACE/scripts/roadmap_progress_report.sh"

PHASE1_CONFLICT_LOGS_ROOT="$PHASE1_CONFLICT_WORKSPACE/.easy-node-logs"
PHASE1_CONFLICT_PHASE1_DIR="$PHASE1_CONFLICT_LOGS_ROOT/phase1_source"
PHASE1_CONFLICT_GLOBAL_DIR="$PHASE1_CONFLICT_LOGS_ROOT/global_newer"
mkdir -p "$PHASE1_CONFLICT_PHASE1_DIR" "$PHASE1_CONFLICT_GLOBAL_DIR"

PHASE1_CONFLICT_LINKED_JSON="$PHASE1_CONFLICT_PHASE1_DIR/vpn_rc_resilience_linked_conflict.json"
cat >"$PHASE1_CONFLICT_LINKED_JSON" <<'EOF_PHASE1_CONFLICT_LINKED'
{
  "version": 1,
  "profile_matrix_stable": false,
  "peer_loss_recovery_ok": false,
  "session_churn_guard_ok": false
}
EOF_PHASE1_CONFLICT_LINKED
touch -t 202602050101 "$PHASE1_CONFLICT_LINKED_JSON"

PHASE1_CONFLICT_CI_JSON="$PHASE1_CONFLICT_PHASE1_DIR/ci_phase1_resilience_summary.json"
cat >"$PHASE1_CONFLICT_CI_JSON" <<'EOF_PHASE1_CONFLICT_CI'
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "vpn_rc_resilience_path": {
      "artifacts": {
        "summary_json": "vpn_rc_resilience_linked_conflict.json"
      }
    }
  }
}
EOF_PHASE1_CONFLICT_CI
touch -t 202602050102 "$PHASE1_CONFLICT_CI_JSON"

PHASE1_CONFLICT_HANDOFF_JSON="$PHASE1_CONFLICT_PHASE1_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_CONFLICT_HANDOFF_JSON" <<'EOF_PHASE1_CONFLICT_HANDOFF'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "ci_phase1_summary_json": "ci_phase1_resilience_summary.json"
  },
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_CONFLICT_HANDOFF
touch -t 202602050103 "$PHASE1_CONFLICT_HANDOFF_JSON"

PHASE1_CONFLICT_RUN_JSON="$PHASE1_CONFLICT_PHASE1_DIR/phase1_resilience_handoff_run_summary.json"
cat >"$PHASE1_CONFLICT_RUN_JSON" <<'EOF_PHASE1_CONFLICT_RUN'
{
  "schema": {
    "id": "phase1_resilience_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  },
  "artifacts": {
    "handoff_summary_json": "phase1_resilience_handoff_check_summary.json",
    "ci_summary_json": "ci_phase1_resilience_summary.json"
  },
  "steps": {
    "phase1_resilience_handoff_check": {
      "artifacts": {
        "summary_json": "phase1_resilience_handoff_check_summary.json"
      }
    },
    "ci_phase1_resilience": {
      "artifacts": {
        "summary_json": "ci_phase1_resilience_summary.json"
      }
    }
  }
}
EOF_PHASE1_CONFLICT_RUN
touch -t 202602050104 "$PHASE1_CONFLICT_RUN_JSON"

PHASE1_CONFLICT_GLOBAL_JSON="$PHASE1_CONFLICT_GLOBAL_DIR/vpn_rc_resilience_path_summary.json"
cat >"$PHASE1_CONFLICT_GLOBAL_JSON" <<'EOF_PHASE1_CONFLICT_GLOBAL'
{
  "version": 1,
  "profile_matrix_stable": false,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": false
}
EOF_PHASE1_CONFLICT_GLOBAL
touch -t 202602060202 "$PHASE1_CONFLICT_GLOBAL_JSON"

SUMMARY_PHASE1_CONFLICT_JSON="$TMP_DIR/roadmap_progress_phase1_linked_resilience_conflict.json"
REPORT_PHASE1_CONFLICT_MD="$TMP_DIR/roadmap_progress_phase1_linked_resilience_conflict.md"
ROADMAP_PROGRESS_LOGS_ROOT="$PHASE1_CONFLICT_LOGS_ROOT" \
bash "$PHASE1_CONFLICT_WORKSPACE/scripts/roadmap_progress_report.sh" \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$PHASE1_CONFLICT_RUN_JSON" \
  --summary-json "$SUMMARY_PHASE1_CONFLICT_JSON" \
  --report-md "$REPORT_PHASE1_CONFLICT_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1_conflict.log 2>&1

if ! jq -e \
  --arg phase1_src "$PHASE1_CONFLICT_RUN_JSON" \
  --arg linked_src "$PHASE1_CONFLICT_LINKED_JSON" \
  --arg global_src "$PHASE1_CONFLICT_GLOBAL_JSON" \
  '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $phase1_src
  and .vpn_track.phase1_resilience_handoff.profile_matrix_stable == true
  and .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.phase1_resilience_handoff.session_churn_guard_ok == true
  and .vpn_track.resilience_handoff.available == true
  and .vpn_track.resilience_handoff.source_summary_json == $phase1_src
  and .vpn_track.resilience_handoff.profile_matrix_stable == true
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.resilience_handoff.session_churn_guard_ok == true
  and (.vpn_track.resilience_handoff.source_summary_json != $linked_src)
  and (.vpn_track.resilience_handoff.source_summary_json != $global_src)
  and .artifacts.vpn_rc_resilience_summary_json == $phase1_src
' "$SUMMARY_PHASE1_CONFLICT_JSON" >/dev/null; then
  echo "phase1-linked resilience conflict resolution mismatch"
  cat "$SUMMARY_PHASE1_CONFLICT_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1-linked resilience falls back to global auto-discovery when linked artifact is invalid"
PHASE1_LINKED_FALLBACK_WORKSPACE="$TMP_DIR/phase1_linked_resilience_fallback_workspace"
mkdir -p "$PHASE1_LINKED_FALLBACK_WORKSPACE/scripts" "$PHASE1_LINKED_FALLBACK_WORKSPACE/.easy-node-logs"
cp "$ROOT_DIR/scripts/roadmap_progress_report.sh" "$PHASE1_LINKED_FALLBACK_WORKSPACE/scripts/roadmap_progress_report.sh"
chmod +x "$PHASE1_LINKED_FALLBACK_WORKSPACE/scripts/roadmap_progress_report.sh"

PHASE1_LINKED_FALLBACK_LOGS_ROOT="$PHASE1_LINKED_FALLBACK_WORKSPACE/.easy-node-logs"
PHASE1_LINKED_FALLBACK_PHASE1_DIR="$PHASE1_LINKED_FALLBACK_LOGS_ROOT/phase1_source"
PHASE1_LINKED_FALLBACK_GLOBAL_DIR="$PHASE1_LINKED_FALLBACK_LOGS_ROOT/global_valid"
mkdir -p "$PHASE1_LINKED_FALLBACK_PHASE1_DIR" "$PHASE1_LINKED_FALLBACK_GLOBAL_DIR"

PHASE1_LINKED_FALLBACK_CI_JSON="$PHASE1_LINKED_FALLBACK_PHASE1_DIR/ci_phase1_resilience_summary.json"
cat >"$PHASE1_LINKED_FALLBACK_CI_JSON" <<'EOF_PHASE1_LINKED_FALLBACK_CI'
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "vpn_rc_resilience_path": {
      "artifacts": {
        "summary_json": "missing_vpn_rc_resilience_summary.json"
      }
    }
  }
}
EOF_PHASE1_LINKED_FALLBACK_CI
touch -t 202602030101 "$PHASE1_LINKED_FALLBACK_CI_JSON"

PHASE1_LINKED_FALLBACK_HANDOFF_JSON="$PHASE1_LINKED_FALLBACK_PHASE1_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_LINKED_FALLBACK_HANDOFF_JSON" <<'EOF_PHASE1_LINKED_FALLBACK_HANDOFF'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "ci_phase1_summary_json": "ci_phase1_resilience_summary.json"
  },
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_LINKED_FALLBACK_HANDOFF
touch -t 202602030102 "$PHASE1_LINKED_FALLBACK_HANDOFF_JSON"

PHASE1_LINKED_FALLBACK_RUN_JSON="$PHASE1_LINKED_FALLBACK_PHASE1_DIR/phase1_resilience_handoff_run_summary.json"
cat >"$PHASE1_LINKED_FALLBACK_RUN_JSON" <<'EOF_PHASE1_LINKED_FALLBACK_RUN'
{
  "schema": {
    "id": "phase1_resilience_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  },
  "artifacts": {
    "handoff_summary_json": "phase1_resilience_handoff_check_summary.json",
    "ci_summary_json": "ci_phase1_resilience_summary.json"
  },
  "steps": {
    "phase1_resilience_handoff_check": {
      "artifacts": {
        "summary_json": "phase1_resilience_handoff_check_summary.json"
      }
    },
    "ci_phase1_resilience": {
      "artifacts": {
        "summary_json": "ci_phase1_resilience_summary.json"
      }
    }
  }
}
EOF_PHASE1_LINKED_FALLBACK_RUN
touch -t 202602030103 "$PHASE1_LINKED_FALLBACK_RUN_JSON"

PHASE1_LINKED_FALLBACK_GLOBAL_JSON="$PHASE1_LINKED_FALLBACK_GLOBAL_DIR/vpn_rc_resilience_path_summary.json"
cat >"$PHASE1_LINKED_FALLBACK_GLOBAL_JSON" <<'EOF_PHASE1_LINKED_FALLBACK_GLOBAL'
{
  "version": 1,
  "profile_matrix_stable": false,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": false
}
EOF_PHASE1_LINKED_FALLBACK_GLOBAL
touch -t 202602040404 "$PHASE1_LINKED_FALLBACK_GLOBAL_JSON"

SUMMARY_PHASE1_LINKED_FALLBACK_JSON="$TMP_DIR/roadmap_progress_phase1_linked_resilience_fallback.json"
REPORT_PHASE1_LINKED_FALLBACK_MD="$TMP_DIR/roadmap_progress_phase1_linked_resilience_fallback.md"
ROADMAP_PROGRESS_LOGS_ROOT="$PHASE1_LINKED_FALLBACK_LOGS_ROOT" \
bash "$PHASE1_LINKED_FALLBACK_WORKSPACE/scripts/roadmap_progress_report.sh" \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$PHASE1_LINKED_FALLBACK_RUN_JSON" \
  --summary-json "$SUMMARY_PHASE1_LINKED_FALLBACK_JSON" \
  --report-md "$REPORT_PHASE1_LINKED_FALLBACK_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1_linked_fallback.log 2>&1

if ! jq -e \
  --arg phase1_src "$PHASE1_LINKED_FALLBACK_RUN_JSON" \
  --arg global_src "$PHASE1_LINKED_FALLBACK_GLOBAL_JSON" \
  '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $phase1_src
  and .vpn_track.resilience_handoff.available == true
  and .vpn_track.resilience_handoff.source_summary_json == $global_src
  and .vpn_track.resilience_handoff.profile_matrix_stable == false
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.resilience_handoff.session_churn_guard_ok == false
  and .artifacts.vpn_rc_resilience_summary_json == $global_src
' "$SUMMARY_PHASE1_LINKED_FALLBACK_JSON" >/dev/null; then
  echo "phase1-linked resilience fallback mismatch"
  cat "$SUMMARY_PHASE1_LINKED_FALLBACK_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1 handoff ingestion + non-sudo actionable gates"
PHASE1_HANDOFF_JSON="$TMP_DIR/phase1_handoff_summary.json"
cat >"$PHASE1_HANDOFF_JSON" <<'EOF_PHASE1_HANDOFF'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_HANDOFF

SUMMARY_PHASE1_JSON="$TMP_DIR/roadmap_progress_phase1_handoff.json"
REPORT_PHASE1_MD="$TMP_DIR/roadmap_progress_phase1_handoff.md"
./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$PHASE1_HANDOFF_JSON" \
  --vpn-rc-resilience-summary-json "$MISSING_SUMMARY" \
  --summary-json "$SUMMARY_PHASE1_JSON" \
  --report-md "$REPORT_PHASE1_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1.log 2>&1

if ! jq -e --arg src "$PHASE1_HANDOFF_JSON" '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $src
  and .vpn_track.phase1_resilience_handoff.status == "pass"
  and .vpn_track.phase1_resilience_handoff.rc == 0
  and .vpn_track.phase1_resilience_handoff.profile_matrix_stable == true
  and .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.phase1_resilience_handoff.session_churn_guard_ok == true
  and .vpn_track.phase1_resilience_handoff.automatable_without_sudo_or_github == true
  and .artifacts.phase1_resilience_handoff_summary_json == $src
  and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github | length) >= 1)
  and (((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | any(.id == "phase1_resilience_handoff_run_dry")) | not)
' "$SUMMARY_PHASE1_JSON" >/dev/null; then
  echo "phase1 handoff ingestion/actionable summary JSON mismatch"
  cat "$SUMMARY_PHASE1_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1 handoff failure semantics propagation"
PHASE1_HANDOFF_FAILURE_JSON="$TMP_DIR/phase1_handoff_failure_summary.json"
cat >"$PHASE1_HANDOFF_FAILURE_JSON" <<'EOF_PHASE1_HANDOFF_FAILURE'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 1,
  "handoff": {
    "profile_matrix_stable": false,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": false
  },
  "failure": {
    "kind": "policy_no_go",
    "policy_no_go": true,
    "execution_failure": false,
    "timeout": false
  },
  "policy_outcome": {
    "decision": "NO-GO",
    "fail_closed_no_go": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_HANDOFF_FAILURE

SUMMARY_PHASE1_FAILURE_JSON="$TMP_DIR/roadmap_progress_phase1_handoff_failure.json"
REPORT_PHASE1_FAILURE_MD="$TMP_DIR/roadmap_progress_phase1_handoff_failure.md"
./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$PHASE1_HANDOFF_FAILURE_JSON" \
  --vpn-rc-resilience-summary-json "$MISSING_SUMMARY" \
  --summary-json "$SUMMARY_PHASE1_FAILURE_JSON" \
  --report-md "$REPORT_PHASE1_FAILURE_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1_failure.log 2>&1

if ! jq -e --arg src "$PHASE1_HANDOFF_FAILURE_JSON" '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $src
  and .vpn_track.phase1_resilience_handoff.status == "fail"
  and .vpn_track.phase1_resilience_handoff.rc == 1
  and .vpn_track.phase1_resilience_handoff.profile_matrix_stable == false
  and .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.phase1_resilience_handoff.session_churn_guard_ok == false
  and ((.vpn_track.phase1_resilience_handoff.failure.kind // "") == "policy_no_go")
  and ((.vpn_track.phase1_resilience_handoff.policy_outcome.decision // "") == "NO-GO")
  and ((.vpn_track.phase1_resilience_handoff.policy_outcome.fail_closed_no_go // false) == true)
  and .artifacts.phase1_resilience_handoff_summary_json == $src
' "$SUMMARY_PHASE1_FAILURE_JSON" >/dev/null; then
  echo "phase1 handoff failure semantics propagation mismatch"
  cat "$SUMMARY_PHASE1_FAILURE_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1 handoff legacy summaries remain backward compatible"
PHASE1_HANDOFF_LEGACY_JSON="$TMP_DIR/phase1_handoff_legacy_summary.json"
cat >"$PHASE1_HANDOFF_LEGACY_JSON" <<'EOF_PHASE1_HANDOFF_LEGACY'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_HANDOFF_LEGACY

SUMMARY_PHASE1_LEGACY_JSON="$TMP_DIR/roadmap_progress_phase1_handoff_legacy.json"
REPORT_PHASE1_LEGACY_MD="$TMP_DIR/roadmap_progress_phase1_handoff_legacy.md"
./scripts/roadmap_progress_report.sh \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$PHASE1_HANDOFF_LEGACY_JSON" \
  --vpn-rc-resilience-summary-json "$MISSING_SUMMARY" \
  --summary-json "$SUMMARY_PHASE1_LEGACY_JSON" \
  --report-md "$REPORT_PHASE1_LEGACY_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1_legacy.log 2>&1

if ! jq -e --arg src "$PHASE1_HANDOFF_LEGACY_JSON" '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $src
  and .vpn_track.phase1_resilience_handoff.status == "pass"
  and .vpn_track.phase1_resilience_handoff.rc == 0
  and .vpn_track.phase1_resilience_handoff.profile_matrix_stable == true
  and .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.phase1_resilience_handoff.session_churn_guard_ok == true
  and (
    .vpn_track.phase1_resilience_handoff.failure == null
    or (
      (.vpn_track.phase1_resilience_handoff.failure | type) == "object"
      and ((.vpn_track.phase1_resilience_handoff.failure.kind // "none") == "none")
    )
  )
  and (
    .vpn_track.phase1_resilience_handoff.policy_outcome == null
    or (
      (.vpn_track.phase1_resilience_handoff.policy_outcome | type) == "object"
      and ((.vpn_track.phase1_resilience_handoff.policy_outcome.decision // "GO") == "GO")
    )
  )
  and .artifacts.phase1_resilience_handoff_summary_json == $src
' "$SUMMARY_PHASE1_LEGACY_JSON" >/dev/null; then
  echo "phase1 legacy-summary compatibility mismatch"
  cat "$SUMMARY_PHASE1_LEGACY_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1 auto-source prefers newer run summary over stale check artifact"
PHASE1_AUTO_WORKSPACE="$TMP_DIR/phase1_auto_workspace"
mkdir -p "$PHASE1_AUTO_WORKSPACE/scripts" "$PHASE1_AUTO_WORKSPACE/.easy-node-logs"
cp "$ROOT_DIR/scripts/roadmap_progress_report.sh" "$PHASE1_AUTO_WORKSPACE/scripts/roadmap_progress_report.sh"
chmod +x "$PHASE1_AUTO_WORKSPACE/scripts/roadmap_progress_report.sh"

PHASE1_AUTO_LOGS_ROOT="$PHASE1_AUTO_WORKSPACE/.easy-node-logs"
PHASE1_AUTO_CHECK_DIR="$PHASE1_AUTO_LOGS_ROOT/zzz_old_check"
PHASE1_AUTO_RUN_DIR="$PHASE1_AUTO_LOGS_ROOT/aaa_new_run"
mkdir -p "$PHASE1_AUTO_CHECK_DIR" "$PHASE1_AUTO_RUN_DIR"

PHASE1_AUTO_CHECK_JSON="$PHASE1_AUTO_CHECK_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_AUTO_CHECK_JSON" <<'EOF_PHASE1_AUTO_CHECK'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 9,
  "handoff": {
    "profile_matrix_stable": false,
    "peer_loss_recovery_ok": false,
    "session_churn_guard_ok": false
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_AUTO_CHECK
touch -t 202601010101 "$PHASE1_AUTO_CHECK_JSON"

PHASE1_AUTO_CI_JSON="$PHASE1_AUTO_RUN_DIR/ci_phase1_resilience_summary.json"
PHASE1_AUTO_RESILIENCE_JSON="$PHASE1_AUTO_RUN_DIR/vpn_rc_resilience_path_summary.json"
cat >"$PHASE1_AUTO_RESILIENCE_JSON" <<'EOF_PHASE1_AUTO_RESILIENCE'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": true
}
EOF_PHASE1_AUTO_RESILIENCE
touch -t 202601020201 "$PHASE1_AUTO_RESILIENCE_JSON"

cat >"$PHASE1_AUTO_CI_JSON" <<EOF_PHASE1_AUTO_CI
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "vpn_rc_resilience_path": {
      "artifacts": {
        "summary_json": "$PHASE1_AUTO_RESILIENCE_JSON"
      }
    }
  }
}
EOF_PHASE1_AUTO_CI
touch -t 202601020202 "$PHASE1_AUTO_CI_JSON"

PHASE1_AUTO_RUN_JSON="$PHASE1_AUTO_RUN_DIR/phase1_resilience_handoff_run_summary.json"
cat >"$PHASE1_AUTO_RUN_JSON" <<EOF_PHASE1_AUTO_RUN
{
  "schema": {
    "id": "phase1_resilience_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  },
  "artifacts": {
    "handoff_summary_json": "$PHASE1_AUTO_CHECK_JSON",
    "ci_summary_json": "$PHASE1_AUTO_CI_JSON"
  },
  "steps": {
    "phase1_resilience_handoff_check": {
      "artifacts": {
        "summary_json": "$PHASE1_AUTO_CHECK_JSON"
      }
    },
    "ci_phase1_resilience": {
      "artifacts": {
        "summary_json": "$PHASE1_AUTO_CI_JSON"
      }
    }
  }
}
EOF_PHASE1_AUTO_RUN
touch -t 202601020303 "$PHASE1_AUTO_RUN_JSON"

SUMMARY_PHASE1_AUTO_SOURCE_JSON="$TMP_DIR/roadmap_progress_phase1_auto_source.json"
REPORT_PHASE1_AUTO_SOURCE_MD="$TMP_DIR/roadmap_progress_phase1_auto_source.md"
bash "$PHASE1_AUTO_WORKSPACE/scripts/roadmap_progress_report.sh" \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --vpn-rc-resilience-summary-json "$MISSING_SUMMARY" \
  --summary-json "$SUMMARY_PHASE1_AUTO_SOURCE_JSON" \
  --report-md "$REPORT_PHASE1_AUTO_SOURCE_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1_auto_source.log 2>&1

if ! jq -e \
  --arg run_src "$PHASE1_AUTO_RUN_JSON" \
  --arg stale_src "$PHASE1_AUTO_CHECK_JSON" \
  '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.input_summary_json == $run_src
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $run_src
  and .vpn_track.phase1_resilience_handoff.source_summary_kind == "run"
  and .vpn_track.phase1_resilience_handoff.status == "pass"
  and .vpn_track.phase1_resilience_handoff.rc == 0
  and .vpn_track.phase1_resilience_handoff.profile_matrix_stable == true
  and .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.phase1_resilience_handoff.session_churn_guard_ok == true
  and .vpn_track.phase1_resilience_handoff.automatable_without_sudo_or_github == true
  and .artifacts.phase1_resilience_handoff_summary_json == $run_src
  and (.vpn_track.phase1_resilience_handoff.source_summary_json != $stale_src)
' "$SUMMARY_PHASE1_AUTO_SOURCE_JSON" >/dev/null; then
  echo "phase1 auto-source run-summary preference mismatch"
  cat "$SUMMARY_PHASE1_AUTO_SOURCE_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1 auto-source prefers non-dry source over newer dry-run source"
PHASE1_DRY_PREF_WORKSPACE="$TMP_DIR/phase1_dry_preference_workspace"
mkdir -p "$PHASE1_DRY_PREF_WORKSPACE/scripts" "$PHASE1_DRY_PREF_WORKSPACE/.easy-node-logs"
cp "$ROOT_DIR/scripts/roadmap_progress_report.sh" "$PHASE1_DRY_PREF_WORKSPACE/scripts/roadmap_progress_report.sh"
chmod +x "$PHASE1_DRY_PREF_WORKSPACE/scripts/roadmap_progress_report.sh"

PHASE1_DRY_PREF_LOGS_ROOT="$PHASE1_DRY_PREF_WORKSPACE/.easy-node-logs"
PHASE1_NON_DRY_DIR="$PHASE1_DRY_PREF_LOGS_ROOT/aaa_non_dry"
PHASE1_DRY_DIR="$PHASE1_DRY_PREF_LOGS_ROOT/zzz_dry_newer"
mkdir -p "$PHASE1_NON_DRY_DIR" "$PHASE1_DRY_DIR"

PHASE1_NON_DRY_CHECK_JSON="$PHASE1_NON_DRY_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_NON_DRY_CHECK_JSON" <<'EOF_PHASE1_NON_DRY_CHECK'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_NON_DRY_CHECK
touch -t 202601050100 "$PHASE1_NON_DRY_CHECK_JSON"

PHASE1_NON_DRY_RUN_JSON="$PHASE1_NON_DRY_DIR/phase1_resilience_handoff_run_summary.json"
cat >"$PHASE1_NON_DRY_RUN_JSON" <<EOF_PHASE1_NON_DRY_RUN
{
  "schema": {
    "id": "phase1_resilience_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "dry_run": false
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  },
  "artifacts": {
    "handoff_summary_json": "$PHASE1_NON_DRY_CHECK_JSON"
  },
  "steps": {
    "phase1_resilience_handoff_check": {
      "artifacts": {
        "summary_json": "$PHASE1_NON_DRY_CHECK_JSON"
      }
    }
  }
}
EOF_PHASE1_NON_DRY_RUN
touch -t 202601050101 "$PHASE1_NON_DRY_RUN_JSON"

PHASE1_DRY_CHECK_JSON="$PHASE1_DRY_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_DRY_CHECK_JSON" <<'EOF_PHASE1_DRY_CHECK'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_DRY_CHECK
touch -t 202601050200 "$PHASE1_DRY_CHECK_JSON"

PHASE1_DRY_RUN_JSON="$PHASE1_DRY_DIR/phase1_resilience_handoff_run_summary.json"
cat >"$PHASE1_DRY_RUN_JSON" <<EOF_PHASE1_DRY_RUN
{
  "schema": {
    "id": "phase1_resilience_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "dry_run": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  },
  "artifacts": {
    "handoff_summary_json": "$PHASE1_DRY_CHECK_JSON"
  },
  "steps": {
    "phase1_resilience_handoff_check": {
      "artifacts": {
        "summary_json": "$PHASE1_DRY_CHECK_JSON"
      }
    }
  }
}
EOF_PHASE1_DRY_RUN
touch -t 202601050201 "$PHASE1_DRY_RUN_JSON"

SUMMARY_PHASE1_DRY_PREF_JSON="$TMP_DIR/roadmap_progress_phase1_dry_pref.json"
REPORT_PHASE1_DRY_PREF_MD="$TMP_DIR/roadmap_progress_phase1_dry_pref.md"
bash "$PHASE1_DRY_PREF_WORKSPACE/scripts/roadmap_progress_report.sh" \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --vpn-rc-resilience-summary-json "$MISSING_SUMMARY" \
  --summary-json "$SUMMARY_PHASE1_DRY_PREF_JSON" \
  --report-md "$REPORT_PHASE1_DRY_PREF_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1_dry_pref.log 2>&1

if ! jq -e \
  --arg non_dry_src "$PHASE1_NON_DRY_RUN_JSON" \
  --arg dry_src "$PHASE1_DRY_RUN_JSON" \
  '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.input_summary_json == $non_dry_src
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $non_dry_src
  and .vpn_track.phase1_resilience_handoff.source_summary_kind == "run"
  and .vpn_track.phase1_resilience_handoff.status == "pass"
  and .vpn_track.phase1_resilience_handoff.rc == 0
  and .vpn_track.phase1_resilience_handoff.profile_matrix_stable == true
  and .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.phase1_resilience_handoff.session_churn_guard_ok == true
  and .vpn_track.phase1_resilience_handoff.automatable_without_sudo_or_github == true
  and .artifacts.phase1_resilience_handoff_summary_json == $non_dry_src
  and (.vpn_track.phase1_resilience_handoff.source_summary_json != $dry_src)
' "$SUMMARY_PHASE1_DRY_PREF_JSON" >/dev/null; then
  echo "phase1 auto-source non-dry preference mismatch"
  cat "$SUMMARY_PHASE1_DRY_PREF_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1 auto-source prefers richer dry-run semantics over older weak non-dry source"
PHASE1_RICH_DRY_WORKSPACE="$TMP_DIR/phase1_richer_dry_workspace"
mkdir -p "$PHASE1_RICH_DRY_WORKSPACE/scripts" "$PHASE1_RICH_DRY_WORKSPACE/.easy-node-logs"
cp "$ROOT_DIR/scripts/roadmap_progress_report.sh" "$PHASE1_RICH_DRY_WORKSPACE/scripts/roadmap_progress_report.sh"
chmod +x "$PHASE1_RICH_DRY_WORKSPACE/scripts/roadmap_progress_report.sh"

PHASE1_RICH_DRY_LOGS_ROOT="$PHASE1_RICH_DRY_WORKSPACE/.easy-node-logs"
PHASE1_RICH_DRY_NON_DRY_DIR="$PHASE1_RICH_DRY_LOGS_ROOT/aaa_non_dry_older_weak"
PHASE1_RICH_DRY_DRY_DIR="$PHASE1_RICH_DRY_LOGS_ROOT/zzz_dry_richer"
mkdir -p "$PHASE1_RICH_DRY_NON_DRY_DIR" "$PHASE1_RICH_DRY_DRY_DIR"

PHASE1_RICH_DRY_NON_DRY_CHECK_JSON="$PHASE1_RICH_DRY_NON_DRY_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_RICH_DRY_NON_DRY_CHECK_JSON" <<'EOF_PHASE1_RICH_DRY_NON_DRY_CHECK'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "profile_matrix_stable": true
  }
}
EOF_PHASE1_RICH_DRY_NON_DRY_CHECK
touch -t 202601070100 "$PHASE1_RICH_DRY_NON_DRY_CHECK_JSON"

PHASE1_RICH_DRY_NON_DRY_RUN_JSON="$PHASE1_RICH_DRY_NON_DRY_DIR/phase1_resilience_handoff_run_summary.json"
cat >"$PHASE1_RICH_DRY_NON_DRY_RUN_JSON" <<EOF_PHASE1_RICH_DRY_NON_DRY_RUN
{
  "schema": {
    "id": "phase1_resilience_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "dry_run": false
  },
  "artifacts": {
    "handoff_summary_json": "$PHASE1_RICH_DRY_NON_DRY_CHECK_JSON"
  },
  "steps": {
    "phase1_resilience_handoff_check": {
      "artifacts": {
        "summary_json": "$PHASE1_RICH_DRY_NON_DRY_CHECK_JSON"
      }
    }
  }
}
EOF_PHASE1_RICH_DRY_NON_DRY_RUN
touch -t 202601070101 "$PHASE1_RICH_DRY_NON_DRY_RUN_JSON"

PHASE1_RICH_DRY_CHECK_JSON="$PHASE1_RICH_DRY_DRY_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_RICH_DRY_CHECK_JSON" <<'EOF_PHASE1_RICH_DRY_CHECK'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 7,
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": false,
    "session_churn_guard_ok": false
  },
  "failure": {
    "kind": "execution_failure"
  },
  "policy_outcome": {
    "decision": "NO-GO",
    "fail_closed_no_go": false
  },
  "failure_semantics": {
    "profile_matrix_stable": {
      "kind": "none"
    },
    "peer_loss_recovery_ok": {
      "kind": "execution_failure"
    },
    "session_churn_guard_ok": {
      "kind": "execution_failure"
    }
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_RICH_DRY_CHECK
touch -t 202601070200 "$PHASE1_RICH_DRY_CHECK_JSON"

PHASE1_RICH_DRY_RUN_JSON="$PHASE1_RICH_DRY_DRY_DIR/phase1_resilience_handoff_run_summary.json"
cat >"$PHASE1_RICH_DRY_RUN_JSON" <<EOF_PHASE1_RICH_DRY_RUN
{
  "schema": {
    "id": "phase1_resilience_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 7,
  "inputs": {
    "dry_run": true
  },
  "artifacts": {
    "handoff_summary_json": "$PHASE1_RICH_DRY_CHECK_JSON"
  },
  "steps": {
    "phase1_resilience_handoff_check": {
      "artifacts": {
        "summary_json": "$PHASE1_RICH_DRY_CHECK_JSON"
      }
    }
  }
}
EOF_PHASE1_RICH_DRY_RUN
touch -t 202601070201 "$PHASE1_RICH_DRY_RUN_JSON"

SUMMARY_PHASE1_RICH_DRY_JSON="$TMP_DIR/roadmap_progress_phase1_richer_dry_pref.json"
REPORT_PHASE1_RICH_DRY_MD="$TMP_DIR/roadmap_progress_phase1_richer_dry_pref.md"
bash "$PHASE1_RICH_DRY_WORKSPACE/scripts/roadmap_progress_report.sh" \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --vpn-rc-resilience-summary-json "$MISSING_SUMMARY" \
  --summary-json "$SUMMARY_PHASE1_RICH_DRY_JSON" \
  --report-md "$REPORT_PHASE1_RICH_DRY_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1_richer_dry_pref.log 2>&1

if ! jq -e \
  --arg non_dry_src "$PHASE1_RICH_DRY_NON_DRY_RUN_JSON" \
  --arg dry_src "$PHASE1_RICH_DRY_RUN_JSON" \
  '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.input_summary_json == $dry_src
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $dry_src
  and .vpn_track.phase1_resilience_handoff.source_summary_kind == "run"
  and .vpn_track.phase1_resilience_handoff.profile_matrix_stable == true
  and .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok == false
  and .vpn_track.phase1_resilience_handoff.session_churn_guard_ok == false
  and ((.vpn_track.phase1_resilience_handoff.failure.kind // "") == "execution_failure")
  and ((.vpn_track.phase1_resilience_handoff.policy_outcome.decision // "") == "NO-GO")
  and ((.vpn_track.phase1_resilience_handoff.failure_semantics.peer_loss_recovery_ok.kind // "") == "execution_failure")
  and ((.vpn_track.phase1_resilience_handoff.failure_semantics.session_churn_guard_ok.kind // "") == "execution_failure")
  and (.vpn_track.phase1_resilience_handoff.source_summary_json != $non_dry_src)
' "$SUMMARY_PHASE1_RICH_DRY_JSON" >/dev/null; then
  echo "phase1 auto-source richer dry-run semantics preference mismatch"
  cat "$SUMMARY_PHASE1_RICH_DRY_JSON"
  exit 1
fi

echo "[roadmap-progress-resilience] phase1 check-only auto-source inherits dry-run signal from linked ci summary"
PHASE1_CHECK_ONLY_WORKSPACE="$TMP_DIR/phase1_check_only_dry_workspace"
mkdir -p "$PHASE1_CHECK_ONLY_WORKSPACE/scripts" "$PHASE1_CHECK_ONLY_WORKSPACE/.easy-node-logs"
cp "$ROOT_DIR/scripts/roadmap_progress_report.sh" "$PHASE1_CHECK_ONLY_WORKSPACE/scripts/roadmap_progress_report.sh"
chmod +x "$PHASE1_CHECK_ONLY_WORKSPACE/scripts/roadmap_progress_report.sh"

PHASE1_CHECK_ONLY_LOGS_ROOT="$PHASE1_CHECK_ONLY_WORKSPACE/.easy-node-logs"
PHASE1_CHECK_ONLY_NON_DRY_DIR="$PHASE1_CHECK_ONLY_LOGS_ROOT/aaa_non_dry_check_only"
PHASE1_CHECK_ONLY_DRY_DIR="$PHASE1_CHECK_ONLY_LOGS_ROOT/zzz_dry_check_only_newer"
mkdir -p "$PHASE1_CHECK_ONLY_NON_DRY_DIR" "$PHASE1_CHECK_ONLY_DRY_DIR"

PHASE1_CHECK_ONLY_NON_DRY_CI_JSON="$PHASE1_CHECK_ONLY_NON_DRY_DIR/ci_phase1_resilience_summary.json"
cat >"$PHASE1_CHECK_ONLY_NON_DRY_CI_JSON" <<'EOF_PHASE1_CHECK_ONLY_NON_DRY_CI'
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "dry_run": false
  },
  "steps": {
    "three_machine_docker_profile_matrix": {
      "status": "pass"
    },
    "vpn_rc_resilience_path": {
      "status": "pass"
    },
    "session_churn_guard": {
      "status": "pass"
    }
  }
}
EOF_PHASE1_CHECK_ONLY_NON_DRY_CI

PHASE1_CHECK_ONLY_NON_DRY_JSON="$PHASE1_CHECK_ONLY_NON_DRY_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_CHECK_ONLY_NON_DRY_JSON" <<EOF_PHASE1_CHECK_ONLY_NON_DRY
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "ci_phase1_summary_json": "$PHASE1_CHECK_ONLY_NON_DRY_CI_JSON",
    "requirements": {
      "profile_matrix_stable": true,
      "peer_loss_recovery_ok": true,
      "session_churn_guard_ok": true
    }
  },
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": true
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_CHECK_ONLY_NON_DRY
touch -t 202601060100 "$PHASE1_CHECK_ONLY_NON_DRY_CI_JSON"
touch -t 202601060101 "$PHASE1_CHECK_ONLY_NON_DRY_JSON"

PHASE1_CHECK_ONLY_DRY_CI_JSON="$PHASE1_CHECK_ONLY_DRY_DIR/ci_phase1_resilience_summary.json"
cat >"$PHASE1_CHECK_ONLY_DRY_CI_JSON" <<'EOF_PHASE1_CHECK_ONLY_DRY_CI'
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "dry_run": true
  },
  "steps": {
    "three_machine_docker_profile_matrix": {
      "status": "pass"
    },
    "vpn_rc_resilience_path": {
      "status": "pass"
    },
    "session_churn_guard": {
      "status": "skip"
    }
  }
}
EOF_PHASE1_CHECK_ONLY_DRY_CI

PHASE1_CHECK_ONLY_DRY_JSON="$PHASE1_CHECK_ONLY_DRY_DIR/phase1_resilience_handoff_check_summary.json"
cat >"$PHASE1_CHECK_ONLY_DRY_JSON" <<EOF_PHASE1_CHECK_ONLY_DRY
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "inputs": {
    "ci_phase1_summary_json": "$PHASE1_CHECK_ONLY_DRY_CI_JSON",
    "requirements": {
      "profile_matrix_stable": true,
      "peer_loss_recovery_ok": true,
      "session_churn_guard_ok": false
    }
  },
  "handoff": {
    "profile_matrix_stable": true,
    "peer_loss_recovery_ok": true,
    "session_churn_guard_ok": false
  },
  "automation": {
    "track": "non_blockchain",
    "requires_sudo": false,
    "requires_github": false,
    "automatable_without_sudo_or_github": true
  }
}
EOF_PHASE1_CHECK_ONLY_DRY
touch -t 202601060200 "$PHASE1_CHECK_ONLY_DRY_CI_JSON"
touch -t 202601060201 "$PHASE1_CHECK_ONLY_DRY_JSON"

SUMMARY_PHASE1_CHECK_ONLY_JSON="$TMP_DIR/roadmap_progress_phase1_check_only_dry_pref.json"
REPORT_PHASE1_CHECK_ONLY_MD="$TMP_DIR/roadmap_progress_phase1_check_only_dry_pref.md"
bash "$PHASE1_CHECK_ONLY_WORKSPACE/scripts/roadmap_progress_report.sh" \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MANUAL_SUMMARY_JSON" \
  --vpn-rc-resilience-summary-json "$MISSING_SUMMARY" \
  --summary-json "$SUMMARY_PHASE1_CHECK_ONLY_JSON" \
  --report-md "$REPORT_PHASE1_CHECK_ONLY_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_resilience_phase1_check_only_dry_pref.log 2>&1

if ! jq -e \
  --arg non_dry_src "$PHASE1_CHECK_ONLY_NON_DRY_JSON" \
  --arg dry_src "$PHASE1_CHECK_ONLY_DRY_JSON" \
  '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.input_summary_json == $non_dry_src
  and .vpn_track.phase1_resilience_handoff.source_summary_json == $non_dry_src
  and .vpn_track.phase1_resilience_handoff.source_summary_kind == "check"
  and .vpn_track.phase1_resilience_handoff.status == "pass"
  and .vpn_track.phase1_resilience_handoff.rc == 0
  and .vpn_track.phase1_resilience_handoff.profile_matrix_stable == true
  and .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.phase1_resilience_handoff.session_churn_guard_ok == true
  and .vpn_track.phase1_resilience_handoff.automatable_without_sudo_or_github == true
  and .artifacts.phase1_resilience_handoff_summary_json == $non_dry_src
  and (.vpn_track.phase1_resilience_handoff.source_summary_json != $dry_src)
' "$SUMMARY_PHASE1_CHECK_ONLY_JSON" >/dev/null; then
  echo "phase1 check-only auto-source dry inheritance mismatch"
  cat "$SUMMARY_PHASE1_CHECK_ONLY_JSON"
  exit 1
fi

echo "roadmap progress resilience handoff integration check ok"
