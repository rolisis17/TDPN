#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_handoff_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SIGNOFF="$TMP_DIR/signoff_pass.json"
PASS_ROADMAP="$TMP_DIR/roadmap_pass.json"
PASS_OUTPUT="$TMP_DIR/pass_output.json"
PASS_LOG="$TMP_DIR/pass.log"

FALLBACK_SIGNOFF="$TMP_DIR/signoff_fallback.json"
FALLBACK_RUN="$TMP_DIR/run_fallback.json"
FALLBACK_CHECK="$TMP_DIR/check_fallback.json"
FALLBACK_ROADMAP="$TMP_DIR/roadmap_fallback.json"
FALLBACK_OUTPUT="$TMP_DIR/fallback_output.json"
FALLBACK_LOG="$TMP_DIR/fallback.log"
UNRESOLVED_SIGNOFF="$TMP_DIR/signoff_unresolved.json"
UNRESOLVED_OUTPUT="$TMP_DIR/unresolved_output.json"
UNRESOLVED_LOG="$TMP_DIR/unresolved.log"

FAIL_SIGNOFF="$TMP_DIR/signoff_fail.json"
FAIL_ROADMAP="$TMP_DIR/roadmap_fail.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
FAIL_LOG="$TMP_DIR/fail.log"

MISSING_OUTPUT="$TMP_DIR/missing_output.json"
MISSING_LOG="$TMP_DIR/missing.log"

cat >"$PASS_ROADMAP" <<'EOF_PASS_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase2_linux_prod_candidate_handoff": {
      "release_integrity_ok": true,
      "release_policy_ok": true,
      "operator_lifecycle_ok": true,
      "pilot_signoff_ok": true
    }
  }
}
EOF_PASS_ROADMAP

cat >"$PASS_SIGNOFF" <<EOF_PASS_SIGNOFF
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_signoff_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "phase2_linux_prod_candidate_run": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$FALLBACK_RUN"
      }
    },
    "roadmap_progress_report": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$PASS_ROADMAP"
      }
    }
  },
  "artifacts": {
    "run_summary_json": "$FALLBACK_RUN",
    "roadmap_summary_json": "$PASS_ROADMAP"
  }
}
EOF_PASS_SIGNOFF

cat >"$FALLBACK_RUN" <<EOF_FALLBACK_RUN
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "phase2_linux_prod_candidate_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$FALLBACK_CHECK"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$FALLBACK_CHECK"
  }
}
EOF_FALLBACK_RUN

cat >"$FALLBACK_CHECK" <<'EOF_FALLBACK_CHECK'
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
    "release_policy_ok": true,
    "operator_lifecycle_ok": true,
    "pilot_signoff_ok": true
  }
}
EOF_FALLBACK_CHECK

cat >"$FALLBACK_ROADMAP" <<'EOF_FALLBACK_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase2_linux_prod_candidate_handoff": {
      "note": "missing booleans on purpose"
    }
  }
}
EOF_FALLBACK_ROADMAP

echo "[phase2-linux-prod-candidate-handoff-check] primary roadmap pass path"
"$SCRIPT_UNDER_TEST" \
  --phase2-signoff-summary-json "$PASS_SIGNOFF" \
  --roadmap-summary-json "$PASS_ROADMAP" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
  .version == 1
  and .schema.id == "phase2_linux_prod_candidate_handoff_check_summary"
  and .status == "pass"
  and .rc == 0
  and .fail_closed == true
  and .inputs.usable.phase2_signoff_summary_json == true
  and .inputs.usable.roadmap_summary_json == true
  and .handoff.signoff_pipeline_ok == true
  and .handoff.release_integrity_ok == true
  and .handoff.release_policy_ok == true
  and .handoff.operator_lifecycle_ok == true
  and .handoff.pilot_signoff_ok == true
  and .handoff.sources.release_integrity_ok == "roadmap_progress_summary.vpn_track.phase2_linux_prod_candidate_handoff.release_integrity_ok"
  and (.decision.reason_details | length) == 0
  and (.decision.warnings | length) == 0
  and (.decision.warning_details | length) == 0
' "$PASS_OUTPUT" >/dev/null; then
  echo "primary pass-path summary mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase2-linux-prod-candidate-handoff-check] nested check fallback path"
"$SCRIPT_UNDER_TEST" \
  --phase2-signoff-summary-json "$PASS_SIGNOFF" \
  --roadmap-summary-json "$FALLBACK_ROADMAP" \
  --summary-json "$FALLBACK_OUTPUT" \
  --show-json 0 >"$FALLBACK_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.release_integrity_ok == true
  and .handoff.release_policy_ok == true
  and .handoff.operator_lifecycle_ok == true
  and .handoff.pilot_signoff_ok == true
  and .handoff.sources.release_integrity_ok == "phase2_linux_prod_candidate_check_summary.release_integrity_ok"
  and .handoff.sources.release_policy_ok == "phase2_linux_prod_candidate_check_summary.release_policy_ok"
  and .handoff.sources.operator_lifecycle_ok == "phase2_linux_prod_candidate_check_summary.operator_lifecycle_ok"
  and .handoff.sources.pilot_signoff_ok == "phase2_linux_prod_candidate_check_summary.pilot_signoff_ok"
  and (.decision.reason_details | length) == 0
  and (.decision.warnings | length) == 0
' "$FALLBACK_OUTPUT" >/dev/null; then
  echo "fallback-path summary mismatch"
  cat "$FALLBACK_OUTPUT"
  cat "$FALLBACK_LOG"
  exit 1
fi

cat >"$UNRESOLVED_SIGNOFF" <<'EOF_UNRESOLVED_SIGNOFF'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_signoff_summary",
    "major": 1,
    "minor": 0
  },
  "status": "warn",
  "rc": 0,
  "steps": {
    "phase2_linux_prod_candidate_run": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/tmp/does-not-exist-run-summary.json"
      }
    },
    "roadmap_progress_report": {
      "status": "warn",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/tmp/does-not-exist-roadmap-summary.json"
      }
    }
  }
}
EOF_UNRESOLVED_SIGNOFF

echo "[phase2-linux-prod-candidate-handoff-check] unresolved booleans with relaxed requirements"
"$SCRIPT_UNDER_TEST" \
  --phase2-signoff-summary-json "$UNRESOLVED_SIGNOFF" \
  --roadmap-summary-json "$FALLBACK_ROADMAP" \
  --summary-json "$UNRESOLVED_OUTPUT" \
  --require-signoff-pipeline-ok 0 \
  --require-release-integrity-ok 0 \
  --require-release-policy-ok 0 \
  --require-operator-lifecycle-ok 0 \
  --require-pilot-signoff-ok 0 \
  --show-json 0 >"$UNRESOLVED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.signoff_pipeline_ok == true
  and .handoff.release_integrity_ok == null
  and .handoff.release_policy_ok == null
  and .handoff.operator_lifecycle_ok == null
  and .handoff.pilot_signoff_ok == null
  and ((.decision.warnings // []) | length) >= 4
  and ((.decision.warning_details // []) | map(select(.code == "optional_signal_not_ready")) | length) >= 4
  and ((.decision.warning_codes // []) | index("optional_signal_not_ready") != null)
' "$UNRESOLVED_OUTPUT" >/dev/null; then
  echo "unresolved relaxed summary mismatch"
  cat "$UNRESOLVED_OUTPUT"
  cat "$UNRESOLVED_LOG"
  exit 1
fi

cat >"$FAIL_SIGNOFF" <<'EOF_FAIL_SIGNOFF'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_signoff_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 27,
  "steps": {
    "phase2_linux_prod_candidate_run": {
      "status": "fail",
      "rc": 27,
      "command_rc": 27,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/tmp/run_fail.json"
      }
    },
    "roadmap_progress_report": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/tmp/roadmap_fail.json"
      }
    }
  }
}
EOF_FAIL_SIGNOFF

cat >"$FAIL_ROADMAP" <<'EOF_FAIL_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase2_linux_prod_candidate_handoff": {
      "release_integrity_ok": true,
      "release_policy_ok": true,
      "operator_lifecycle_ok": true,
      "pilot_signoff_ok": true
    }
  }
}
EOF_FAIL_ROADMAP

echo "[phase2-linux-prod-candidate-handoff-check] signoff pipeline failure is fail-closed"
set +e
"$SCRIPT_UNDER_TEST" \
  --phase2-signoff-summary-json "$FAIL_SIGNOFF" \
  --roadmap-summary-json "$FAIL_ROADMAP" \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for signoff pipeline failure, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .handoff.signoff_pipeline_ok == false
  and ((.decision.reasons // []) | any(test("signoff_pipeline_ok is false|signoff_pipeline_ok unresolved")))
  and ((.decision.reason_details // []) | any(.signal == "signoff_pipeline_ok"))
  and ((.decision.reason_codes // []) | index("required_signal_false") != null or index("signal_unresolved") != null)
' "$FAIL_OUTPUT" >/dev/null; then
  echo "signoff pipeline failure summary mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase2-linux-prod-candidate-handoff-check] missing signoff summary contract fail-close"
set +e
"$SCRIPT_UNDER_TEST" \
  --phase2-signoff-summary-json "$TMP_DIR/missing_signoff.json" \
  --roadmap-summary-json "$PASS_ROADMAP" \
  --summary-json "$MISSING_OUTPUT" \
  --show-json 1 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 1 ]]; then
  echo "expected rc=1 for missing signoff summary fail-close, got rc=$missing_rc"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .inputs.usable.phase2_signoff_summary_json == false
  and ((.decision.reasons // []) | any(test("phase2 signoff summary file not found or invalid JSON")))
  and ((.decision.reason_details // []) | any(.code == "signoff_summary_unusable"))
  and ((.decision.reason_codes // []) | index("signoff_summary_unusable") != null)
' "$MISSING_OUTPUT" >/dev/null; then
  echo "missing-signoff summary mismatch"
  cat "$MISSING_OUTPUT"
  cat "$MISSING_LOG"
  exit 1
fi
if ! grep -q '"schema"' "$MISSING_LOG"; then
  echo "--show-json 1 did not print summary payload"
  cat "$MISSING_LOG"
  exit 1
fi

echo "phase2 linux prod candidate handoff check integration ok"
