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

SCRIPT_UNDER_TEST="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase4_windows_full_parity_handoff_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_RUN="$TMP_DIR/run_pass.json"
PASS_ROADMAP="$TMP_DIR/roadmap_pass.json"
PASS_CHECK="$TMP_DIR/check_pass.json"
PASS_OUTPUT="$TMP_DIR/pass_output.json"
PASS_LOG="$TMP_DIR/pass.log"

FALLBACK_RUN="$TMP_DIR/run_fallback.json"
FALLBACK_CHECK="$TMP_DIR/check_fallback.json"
FALLBACK_ROADMAP="$TMP_DIR/roadmap_fallback.json"
FALLBACK_OUTPUT="$TMP_DIR/fallback_output.json"
FALLBACK_LOG="$TMP_DIR/fallback.log"

UNRESOLVED_RUN="$TMP_DIR/run_unresolved.json"
UNRESOLVED_ROADMAP="$TMP_DIR/roadmap_unresolved.json"
UNRESOLVED_OUTPUT="$TMP_DIR/unresolved_output.json"
UNRESOLVED_LOG="$TMP_DIR/unresolved.log"

FAIL_RUN="$TMP_DIR/run_fail.json"
FAIL_ROADMAP="$TMP_DIR/roadmap_fail.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
FAIL_LOG="$TMP_DIR/fail.log"

UNRESOLVED_STRICT_OUTPUT="$TMP_DIR/unresolved_strict_output.json"
UNRESOLVED_STRICT_LOG="$TMP_DIR/unresolved_strict.log"

MISSING_OUTPUT="$TMP_DIR/missing_output.json"
MISSING_LOG="$TMP_DIR/missing.log"

cat >"$PASS_ROADMAP" <<'EOF_PASS_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase4_windows_full_parity_handoff": {
      "windows_server_packaging_ok": true,
      "windows_role_runbooks_ok": true,
      "cross_platform_interop_ok": true,
      "role_combination_validation_ok": true
    }
  }
}
EOF_PASS_ROADMAP

cat >"$PASS_CHECK" <<'EOF_PASS_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "windows_server_packaging_ok": true,
    "windows_role_runbooks_ok": true,
    "cross_platform_interop_ok": true,
    "role_combination_validation_ok": true
  }
}
EOF_PASS_CHECK

cat >"$PASS_RUN" <<EOF_PASS_RUN
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase4_windows_full_parity": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase4_windows_full_parity_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$PASS_CHECK"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$PASS_CHECK"
  }
}
EOF_PASS_RUN

echo "[phase4-windows-full-parity-handoff-check] primary roadmap pass path"
"$SCRIPT_UNDER_TEST" \
  --phase4-run-summary-json "$PASS_RUN" \
  --roadmap-summary-json "$PASS_ROADMAP" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
  .version == 1
  and .schema.id == "phase4_windows_full_parity_handoff_check_summary"
  and .status == "pass"
  and .rc == 0
  and .fail_closed == true
  and .inputs.usable.phase4_run_summary_json == true
  and .inputs.usable.roadmap_summary_json == true
  and .handoff.run_pipeline_ok == true
  and .handoff.windows_server_packaging_ok == true
  and .handoff.windows_role_runbooks_ok == true
  and .handoff.cross_platform_interop_ok == true
  and .handoff.role_combination_validation_ok == true
  and .handoff.sources.windows_server_packaging_ok == "roadmap_progress_summary.vpn_track.phase4_windows_full_parity_handoff.windows_server_packaging_ok"
  and .decision.failure_kind == "none"
  and ((.decision.reason_codes // []) | length) == 0
  and .failure.kind == "none"
  and .handoff_semantics.run_pipeline_ok.failure_kind == "ok"
  and .handoff_semantics.windows_server_packaging_ok.failure_kind == "ok"
  and .handoff_semantics.windows_role_runbooks_ok.failure_kind == "ok"
  and .handoff_semantics.cross_platform_interop_ok.failure_kind == "ok"
  and .handoff_semantics.role_combination_validation_ok.failure_kind == "ok"
' "$PASS_OUTPUT" >/dev/null; then
  echo "primary pass-path summary mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi

cat >"$FALLBACK_CHECK" <<'EOF_FALLBACK_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "windows_server_packaging_ok": true,
    "windows_role_runbooks_ok": true,
    "cross_platform_interop_ok": true,
    "role_combination_validation_ok": true
  }
}
EOF_FALLBACK_CHECK

cat >"$FALLBACK_RUN" <<EOF_FALLBACK_RUN
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase4_windows_full_parity": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase4_windows_full_parity_check": {
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

cat >"$FALLBACK_ROADMAP" <<'EOF_FALLBACK_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase4_windows_full_parity_handoff": {
      "note": "missing booleans on purpose"
    }
  }
}
EOF_FALLBACK_ROADMAP

echo "[phase4-windows-full-parity-handoff-check] nested check fallback path"
"$SCRIPT_UNDER_TEST" \
  --phase4-run-summary-json "$FALLBACK_RUN" \
  --roadmap-summary-json "$FALLBACK_ROADMAP" \
  --summary-json "$FALLBACK_OUTPUT" \
  --show-json 0 >"$FALLBACK_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.windows_server_packaging_ok == true
  and .handoff.windows_role_runbooks_ok == true
  and .handoff.cross_platform_interop_ok == true
  and .handoff.role_combination_validation_ok == true
  and .handoff.sources.windows_server_packaging_ok == "phase4_windows_full_parity_check_summary.windows_server_packaging_ok"
  and .handoff.sources.windows_role_runbooks_ok == "phase4_windows_full_parity_check_summary.windows_role_runbooks_ok"
  and .handoff.sources.cross_platform_interop_ok == "phase4_windows_full_parity_check_summary.cross_platform_interop_ok"
  and .handoff.sources.role_combination_validation_ok == "phase4_windows_full_parity_check_summary.role_combination_validation_ok"
  and .decision.failure_kind == "none"
  and ((.decision.reason_codes // []) | length) == 0
  and .handoff_semantics.windows_server_packaging_ok.source == "phase4_windows_full_parity_check_summary.windows_server_packaging_ok"
' "$FALLBACK_OUTPUT" >/dev/null; then
  echo "fallback-path summary mismatch"
  cat "$FALLBACK_OUTPUT"
  cat "$FALLBACK_LOG"
  exit 1
fi

cat >"$UNRESOLVED_RUN" <<'EOF_UNRESOLVED_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase4_windows_full_parity": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase4_windows_full_parity_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/tmp/does-not-exist-check-summary.json"
      }
    }
  }
}
EOF_UNRESOLVED_RUN

cat >"$UNRESOLVED_ROADMAP" <<'EOF_UNRESOLVED_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase4_windows_full_parity_handoff": {
      "note": "intentionally unresolved"
    }
  }
}
EOF_UNRESOLVED_ROADMAP

echo "[phase4-windows-full-parity-handoff-check] unresolved booleans with relaxed requirements"
"$SCRIPT_UNDER_TEST" \
  --phase4-run-summary-json "$UNRESOLVED_RUN" \
  --roadmap-summary-json "$UNRESOLVED_ROADMAP" \
  --summary-json "$UNRESOLVED_OUTPUT" \
  --require-run-pipeline-ok 0 \
  --require-windows-server-packaging-ok 0 \
  --require-windows-role-runbooks-ok 0 \
  --require-cross-platform-interop-ok 0 \
  --require-role-combination-validation-ok 0 \
  --show-json 0 >"$UNRESOLVED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.run_pipeline_ok == true
  and .handoff.windows_server_packaging_ok == null
  and .handoff.windows_role_runbooks_ok == null
  and .handoff.cross_platform_interop_ok == null
  and .handoff.role_combination_validation_ok == null
  and .handoff_semantics.run_pipeline_ok.failure_kind == "not_required"
  and .handoff_semantics.windows_server_packaging_ok.failure_kind == "not_required"
  and .handoff_semantics.windows_role_runbooks_ok.failure_kind == "not_required"
  and .handoff_semantics.cross_platform_interop_ok.failure_kind == "not_required"
  and .handoff_semantics.role_combination_validation_ok.failure_kind == "not_required"
  and ((.decision.reason_codes // []) | length) == 0
' "$UNRESOLVED_OUTPUT" >/dev/null; then
  echo "unresolved relaxed summary mismatch"
  cat "$UNRESOLVED_OUTPUT"
  cat "$UNRESOLVED_LOG"
  exit 1
fi

echo "[phase4-windows-full-parity-handoff-check] unresolved required handoff signals are fail-closed"
set +e
"$SCRIPT_UNDER_TEST" \
  --phase4-run-summary-json "$UNRESOLVED_RUN" \
  --roadmap-summary-json "$UNRESOLVED_ROADMAP" \
  --summary-json "$UNRESOLVED_STRICT_OUTPUT" \
  --show-json 0 >"$UNRESOLVED_STRICT_LOG" 2>&1
unresolved_strict_rc=$?
set -e
if [[ "$unresolved_strict_rc" -ne 1 ]]; then
  echo "expected rc=1 for unresolved strict fail-close, got rc=$unresolved_strict_rc"
  cat "$UNRESOLVED_STRICT_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .handoff.run_pipeline_ok == true
  and .handoff.windows_server_packaging_ok == null
  and .handoff.windows_server_packaging_resolved == false
  and .handoff.cross_platform_interop_ok == null
  and .handoff.cross_platform_interop_resolved == false
  and .handoff.sources.windows_server_packaging_ok == "unresolved"
  and .handoff.sources.cross_platform_interop_ok == "unresolved"
  and .handoff_semantics.windows_server_packaging_ok.failure_kind == "unresolved"
  and .handoff_semantics.cross_platform_interop_ok.failure_kind == "unresolved"
  and .decision.failure_kind == "policy_no_go"
  and .failure.kind == "policy_no_go"
  and ((.decision.reason_codes // []) | any(. == "windows_server_packaging_ok_unresolved"))
  and ((.decision.reason_codes // []) | any(. == "cross_platform_interop_ok_unresolved"))
  and ((.decision.reason_details // []) | any(.code == "windows_server_packaging_ok_unresolved" and .kind == "unresolved" and .source == "unresolved"))
  and ((.decision.reason_details // []) | any(.code == "cross_platform_interop_ok_unresolved" and .kind == "unresolved" and .source == "unresolved"))
  and ((.decision.reasons // []) | any(test("windows_server_packaging_ok unresolved from provided artifacts")))
  and ((.decision.reasons // []) | any(test("cross_platform_interop_ok unresolved from provided artifacts")))
' "$UNRESOLVED_STRICT_OUTPUT" >/dev/null; then
  echo "unresolved strict summary mismatch"
  cat "$UNRESOLVED_STRICT_OUTPUT"
  cat "$UNRESOLVED_STRICT_LOG"
  exit 1
fi

cat >"$FAIL_RUN" <<'EOF_FAIL_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 27,
  "steps": {
    "ci_phase4_windows_full_parity": {
      "status": "fail",
      "rc": 27,
      "command_rc": 27,
      "contract_valid": true
    },
    "phase4_windows_full_parity_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/tmp/check_fail.json"
      }
    }
  }
}
EOF_FAIL_RUN

cat >"$FAIL_ROADMAP" <<'EOF_FAIL_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase4_windows_full_parity_handoff": {
      "windows_server_packaging_ok": true,
      "windows_role_runbooks_ok": true,
      "cross_platform_interop_ok": true,
      "role_combination_validation_ok": true
    }
  }
}
EOF_FAIL_ROADMAP

echo "[phase4-windows-full-parity-handoff-check] run pipeline failure is fail-closed"
set +e
"$SCRIPT_UNDER_TEST" \
  --phase4-run-summary-json "$FAIL_RUN" \
  --roadmap-summary-json "$FAIL_ROADMAP" \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for run pipeline failure, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .handoff.run_pipeline_ok == false
  and ((.decision.reasons // []) | any(test("run_pipeline_ok is false|run_pipeline_ok unresolved")))
  and .handoff_semantics.run_pipeline_ok.failure_kind == "false"
  and ((.decision.reason_codes // []) | any(. == "run_pipeline_ok_false"))
  and .decision.failure_kind == "policy_no_go"
  and .failure.kind == "policy_no_go"
' "$FAIL_OUTPUT" >/dev/null; then
  echo "run pipeline failure summary mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase4-windows-full-parity-handoff-check] missing run summary contract fail-close"
set +e
"$SCRIPT_UNDER_TEST" \
  --phase4-run-summary-json "$TMP_DIR/missing_run.json" \
  --roadmap-summary-json "$PASS_ROADMAP" \
  --summary-json "$MISSING_OUTPUT" \
  --show-json 1 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 1 ]]; then
  echo "expected rc=1 for missing run summary fail-close, got rc=$missing_rc"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .inputs.usable.phase4_run_summary_json == false
  and ((.decision.reasons // []) | any(test("phase4 run summary file not found or invalid JSON")))
  and .handoff_semantics.run_pipeline_ok.failure_kind == "unresolved"
  and ((.decision.reason_codes // []) | any(. == "phase4_run_summary_unusable"))
  and ((.decision.reason_codes // []) | any(. == "run_pipeline_ok_unresolved"))
' "$MISSING_OUTPUT" >/dev/null; then
  echo "missing-run summary mismatch"
  cat "$MISSING_OUTPUT"
  cat "$MISSING_LOG"
  exit 1
fi
if ! grep -q '"schema"' "$MISSING_LOG"; then
  echo "--show-json 1 did not print summary payload"
  cat "$MISSING_LOG"
  exit 1
fi

echo "phase4 windows full parity handoff check integration ok"
