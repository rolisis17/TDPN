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

RUNNER="${PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase4_windows_full_parity_handoff_run.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
PASS_STDOUT="$TMP_DIR/pass.stdout"
DRY_STDOUT="$TMP_DIR/dry.stdout"
FAIL_STDOUT="$TMP_DIR/fail.stdout"
RUN_CONTRACT_FAIL_STDOUT="$TMP_DIR/run_contract_fail.stdout"
HANDOFF_CONTRACT_FAIL_STDOUT="$TMP_DIR/handoff_contract_fail.stdout"
RESUME_STDOUT="$TMP_DIR/resume.stdout"
RESUME_RUN_FALLBACK_STDOUT="$TMP_DIR/resume_run_fallback.stdout"
RESUME_HANDOFF_FALLBACK_STDOUT="$TMP_DIR/resume_handoff_fallback.stdout"

FAKE_RUN="$TMP_DIR/fake_phase4_windows_full_parity_run.sh"
cat >"$FAKE_RUN" <<'EOF_FAKE_RUN'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE4_HANDOFF_RUN_CAPTURE_FILE:?}"
printf 'run\t%s\n' "$*" >>"$capture"

reports_dir=""
summary_json=""
dry_run="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --dry-run)
      dry_run="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

status="pass"
rc=0
if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_RUN_FAIL_RC:-31}"
fi

check_summary="${FAKE_RUN_CHECK_SUMMARY:-${reports_dir}/phase4_windows_full_parity_check_summary.json}"
roadmap_summary="${FAKE_RUN_ROADMAP_SUMMARY:-${reports_dir}/roadmap_progress_summary.json}"
mkdir -p "$(dirname "$check_summary")" "$(dirname "$roadmap_summary")"

windows_native_bootstrap_guardrails_ok="${FAKE_RUN_WINDOWS_NATIVE_BOOTSTRAP_GUARDRAILS_OK:-1}"

cat >"$check_summary" <<'EOF_CHECK'
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
    "role_combination_validation_ok": true,
    "windows_native_bootstrap_guardrails_ok": true
  }
}
EOF_CHECK

cat >"$roadmap_summary" <<'EOF_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase4_windows_full_parity_handoff": {
      "windows_server_packaging_ok": true,
      "windows_role_runbooks_ok": true,
      "cross_platform_interop_ok": true,
      "role_combination_validation_ok": true,
      "windows_native_bootstrap_guardrails_ok": true
    }
  }
}
EOF_ROADMAP

if [[ -n "$summary_json" && "${FAKE_RUN_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "steps": {
    "ci_phase4_windows_full_parity": {
      "status": "$status",
      "rc": $rc,
      "command_rc": $rc,
      "contract_valid": true
    },
    "phase4_windows_full_parity_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$check_summary",
        "roadmap_summary_json": "$roadmap_summary"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$check_summary",
    "roadmap_summary_json": "$roadmap_summary"
  }
}
EOF_SUMMARY
fi

if [[ "${FAKE_RUN_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_RUN
chmod +x "$FAKE_RUN"

FAKE_HANDOFF="$TMP_DIR/fake_phase4_windows_full_parity_handoff_check.sh"
cat >"$FAKE_HANDOFF" <<'EOF_FAKE_HANDOFF'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE4_HANDOFF_RUN_CAPTURE_FILE:?}"
printf 'handoff\t%s\n' "$*" >>"$capture"

summary_json=""
require_windows_native_bootstrap_guardrails_ok="0"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --require-windows-native-bootstrap-guardrails-ok)
      require_windows_native_bootstrap_guardrails_ok="${2:-1}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

status="pass"
rc=0
if [[ "${FAKE_HANDOFF_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_HANDOFF_FAIL_RC:-19}"
fi

if [[ -n "$summary_json" && "${FAKE_HANDOFF_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "fail_closed": true,
  "handoff": {
    "run_pipeline_ok": true,
    "windows_server_packaging_ok": true,
    "windows_role_runbooks_ok": true,
    "cross_platform_interop_ok": true,
    "role_combination_validation_ok": true,
    "windows_native_bootstrap_guardrails_ok": true
  },
  "sources": {
    "windows_native_bootstrap_guardrails_ok": "roadmap_progress_summary.vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok"
  },
  "decision": {
    "pass": true,
    "reasons": [],
    "warnings": []
  }
}
EOF_SUMMARY
fi

if [[ "${FAKE_HANDOFF_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_HANDOFF
chmod +x "$FAKE_HANDOFF"

echo "[phase4-windows-full-parity-handoff-run] pass path"
: >"$CAPTURE"
PASS_WRAPPER_SUMMARY="$TMP_DIR/pass_wrapper.json"
PHASE4_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_pass" \
  --run-summary-json "$TMP_DIR/pass_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/pass_handoff_summary.json" \
  --summary-json "$PASS_WRAPPER_SUMMARY" \
  --print-summary-json 0 \
  --run-gamma 7 \
  --handoff-require-run-pipeline-ok 1 >"$PASS_STDOUT" 2>&1

run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$run_line" != *"--reports-dir $TMP_DIR/reports_pass"* || "$run_line" != *"--summary-json $TMP_DIR/pass_run_summary.json"* ]]; then
  echo "run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$run_line" != *"--gamma 7"* ]]; then
  echo "run passthrough mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_line" != *"--phase4-run-summary-json $TMP_DIR/pass_run_summary.json"* || "$handoff_line" != *"--roadmap-summary-json $TMP_DIR/reports_pass/roadmap_progress_summary.json"* ]]; then
  echo "handoff forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-run-pipeline-ok 1"* || "$handoff_line" != *"--show-json 0"* ]]; then
  echo "handoff default forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi

if ! jq -e --arg run_summary "$TMP_DIR/pass_run_summary.json" --arg handoff_summary "$TMP_DIR/pass_handoff_summary.json" '
  .version == 1
  and .schema.id == "phase4_windows_full_parity_handoff_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == false
  and .steps.phase4_windows_full_parity_run.status == "pass"
  and .steps.phase4_windows_full_parity_run.rc == 0
  and .steps.phase4_windows_full_parity_run.command_rc == 0
  and .steps.phase4_windows_full_parity_run.contract_valid == true
  and .steps.phase4_windows_full_parity_run.failure_kind == "none"
  and .steps.phase4_windows_full_parity_run.artifacts.summary_json == $run_summary
  and .steps.phase4_windows_full_parity_handoff_check.status == "pass"
  and .steps.phase4_windows_full_parity_handoff_check.rc == 0
  and .steps.phase4_windows_full_parity_handoff_check.command_rc == 0
  and .steps.phase4_windows_full_parity_handoff_check.contract_valid == true
  and .steps.phase4_windows_full_parity_handoff_check.failure_kind == "none"
  and .steps.phase4_windows_full_parity_handoff_check.artifacts.summary_json == $handoff_summary
  and .decision.pass == true
  and .decision.failure_stage == null
  and .decision.failure_kind == "none"
  and ((.decision.reason_codes // []) | length) == 0
  and .failure.kind == "none"
' "$PASS_WRAPPER_SUMMARY" >/dev/null; then
  echo "pass-path combined summary mismatch"
  cat "$PASS_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase4-windows-full-parity-handoff-run] dry-run forwarding and relax behavior"
: >"$CAPTURE"
DRY_WRAPPER_SUMMARY="$TMP_DIR/dry_wrapper.json"
PHASE4_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --run-summary-json "$TMP_DIR/dry_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/dry_handoff_summary.json" \
  --summary-json "$DRY_WRAPPER_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --run-theta 9 \
  --handoff-require-windows-role-runbooks-ok 1 \
  --handoff-require-role-combination-validation-ok 1 \
  --handoff-require-windows-native-bootstrap-guardrails-ok 1 >"$DRY_STDOUT" 2>&1

run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$run_line" != *"--dry-run 1"* || "$run_line" != *"--theta 9"* ]]; then
  echo "dry-run run forwarding mismatch"
  echo "$run_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-run-pipeline-ok 0"* || "$handoff_line" != *"--require-windows-server-packaging-ok 0"* || "$handoff_line" != *"--require-windows-role-runbooks-ok 1"* || "$handoff_line" != *"--require-cross-platform-interop-ok 0"* || "$handoff_line" != *"--require-role-combination-validation-ok 1"* ]]; then
  echo "dry-run handoff relax/override mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-windows-native-bootstrap-guardrails-ok 1"* ]]; then
  echo "dry-run handoff guardrail passthrough mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--dry-run 1"* ]]; then
  echo "dry-run should not leak to handoff checker"
  echo "$handoff_line"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.phase4_windows_full_parity_run.contract_valid == true
  and .steps.phase4_windows_full_parity_handoff_check.contract_valid == true
  and .steps.phase4_windows_full_parity_run.failure_kind == "none"
  and .steps.phase4_windows_full_parity_handoff_check.failure_kind == "none"
  and .decision.failure_kind == "none"
  and ((.decision.reason_codes // []) | length) == 0
' "$DRY_WRAPPER_SUMMARY" >/dev/null; then
  echo "dry-run wrapper summary mismatch"
  cat "$DRY_WRAPPER_SUMMARY"
  exit 1
fi
if ! jq -e '
  .handoff.windows_native_bootstrap_guardrails_ok == true
  and .sources.windows_native_bootstrap_guardrails_ok == "roadmap_progress_summary.vpn_track.phase4_windows_full_parity_handoff.windows_native_bootstrap_guardrails_ok"
' "$TMP_DIR/dry_handoff_summary.json" >/dev/null; then
  echo "dry-run handoff summary missing windows native bootstrap guardrails contract fields"
  cat "$TMP_DIR/dry_handoff_summary.json"
  exit 1
fi

echo "[phase4-windows-full-parity-handoff-run] resume mode reuses pass summaries"
: >"$CAPTURE"
RESUME_WRAPPER_SUMMARY="$TMP_DIR/resume_wrapper.json"
RESUME_RUN_SUMMARY="$TMP_DIR/resume_run_summary.json"
RESUME_HANDOFF_SUMMARY="$TMP_DIR/resume_handoff_summary.json"
cat >"$RESUME_RUN_SUMMARY" <<'EOF_RESUME_RUN'
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
      "contract_valid": true
    }
  }
}
EOF_RESUME_RUN
cat >"$RESUME_HANDOFF_SUMMARY" <<'EOF_RESUME_HANDOFF'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "run_pipeline_ok": true
  },
  "decision": {
    "pass": true
  }
}
EOF_RESUME_HANDOFF

PHASE4_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --resume 1 \
  --reports-dir "$TMP_DIR/reports_resume" \
  --run-summary-json "$RESUME_RUN_SUMMARY" \
  --handoff-summary-json "$RESUME_HANDOFF_SUMMARY" \
  --summary-json "$RESUME_WRAPPER_SUMMARY" \
  --print-summary-json 0 >"$RESUME_STDOUT" 2>&1

if [[ -s "$CAPTURE" ]]; then
  echo "resume mode should skip stage execution when pass summaries exist"
  cat "$CAPTURE"
  cat "$RESUME_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.resume == true
  and .steps.phase4_windows_full_parity_run.status == "pass"
  and .steps.phase4_windows_full_parity_run.rc == 0
  and .steps.phase4_windows_full_parity_run.command_rc == 0
  and .steps.phase4_windows_full_parity_run.contract_valid == true
  and .steps.phase4_windows_full_parity_run.reused_artifact == true
  and .steps.phase4_windows_full_parity_run.failure_kind == "none"
  and .steps.phase4_windows_full_parity_handoff_check.status == "pass"
  and .steps.phase4_windows_full_parity_handoff_check.rc == 0
  and .steps.phase4_windows_full_parity_handoff_check.command_rc == 0
  and .steps.phase4_windows_full_parity_handoff_check.contract_valid == true
  and .steps.phase4_windows_full_parity_handoff_check.reused_artifact == true
  and .steps.phase4_windows_full_parity_handoff_check.failure_kind == "none"
  and .decision.failure_kind == "none"
  and ((.decision.reason_codes // []) | length) == 0
' "$RESUME_WRAPPER_SUMMARY" >/dev/null; then
  echo "resume reuse summary mismatch"
  cat "$RESUME_WRAPPER_SUMMARY"
  exit 1
fi
if ! grep -q '\[phase4-windows-full-parity-handoff-run\] stage=phase4_windows_full_parity_run status=pass rc=0 reason=resume-artifact-pass' "$RESUME_STDOUT"; then
  echo "resume log missing run-stage artifact reuse signal"
  cat "$RESUME_STDOUT"
  exit 1
fi
if ! grep -q '\[phase4-windows-full-parity-handoff-run\] stage=phase4_windows_full_parity_handoff_check status=pass rc=0 reason=resume-artifact-pass' "$RESUME_STDOUT"; then
  echo "resume log missing handoff-stage artifact reuse signal"
  cat "$RESUME_STDOUT"
  exit 1
fi

echo "[phase4-windows-full-parity-handoff-run] resume fallback reruns non-pass run summary"
: >"$CAPTURE"
RESUME_RUN_FALLBACK_SUMMARY="$TMP_DIR/resume_run_fallback_wrapper.json"
RESUME_RUN_FALLBACK_INPUT="$TMP_DIR/resume_run_fallback_input.json"
cat >"$RESUME_RUN_FALLBACK_INPUT" <<'EOF_RESUME_RUN_FALLBACK'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 9,
  "steps": {
    "ci_phase4_windows_full_parity": {
      "status": "fail",
      "rc": 9,
      "command_rc": 9,
      "contract_valid": true
    },
    "phase4_windows_full_parity_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    }
  }
}
EOF_RESUME_RUN_FALLBACK

PHASE4_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --resume 1 \
  --reports-dir "$TMP_DIR/reports_resume_run_fallback" \
  --run-summary-json "$RESUME_RUN_FALLBACK_INPUT" \
  --handoff-summary-json "$TMP_DIR/resume_run_fallback_handoff.json" \
  --summary-json "$RESUME_RUN_FALLBACK_SUMMARY" \
  --run-phase4-windows-full-parity-handoff-check 0 \
  --print-summary-json 0 >"$RESUME_RUN_FALLBACK_STDOUT" 2>&1

if ! grep -q '^run	' "$CAPTURE"; then
  echo "resume fallback should rerun run stage when run summary is non-pass"
  cat "$CAPTURE"
  cat "$RESUME_RUN_FALLBACK_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.resume == true
  and .steps.phase4_windows_full_parity_run.status == "pass"
  and .steps.phase4_windows_full_parity_run.reused_artifact == false
  and .steps.phase4_windows_full_parity_handoff_check.enabled == false
  and .steps.phase4_windows_full_parity_run.failure_kind == "none"
  and .decision.failure_kind == "none"
' "$RESUME_RUN_FALLBACK_SUMMARY" >/dev/null; then
  echo "resume run fallback summary mismatch"
  cat "$RESUME_RUN_FALLBACK_SUMMARY"
  exit 1
fi

echo "[phase4-windows-full-parity-handoff-run] resume fallback reruns non-pass handoff summary"
: >"$CAPTURE"
RESUME_HANDOFF_FALLBACK_SUMMARY="$TMP_DIR/resume_handoff_fallback_wrapper.json"
RESUME_HANDOFF_FALLBACK_INPUT="$TMP_DIR/resume_handoff_fallback_input.json"
cat >"$RESUME_HANDOFF_FALLBACK_INPUT" <<'EOF_RESUME_HANDOFF_FALLBACK'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 8,
  "handoff": {
    "run_pipeline_ok": true
  },
  "decision": {
    "pass": false
  }
}
EOF_RESUME_HANDOFF_FALLBACK

PHASE4_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --resume 1 \
  --reports-dir "$TMP_DIR/reports_resume_handoff_fallback" \
  --run-summary-json "$RESUME_RUN_SUMMARY" \
  --handoff-summary-json "$RESUME_HANDOFF_FALLBACK_INPUT" \
  --summary-json "$RESUME_HANDOFF_FALLBACK_SUMMARY" \
  --run-phase4-windows-full-parity-run 0 \
  --print-summary-json 0 >"$RESUME_HANDOFF_FALLBACK_STDOUT" 2>&1

if ! grep -q '^handoff	' "$CAPTURE"; then
  echo "resume fallback should rerun handoff stage when handoff summary is non-pass"
  cat "$CAPTURE"
  cat "$RESUME_HANDOFF_FALLBACK_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.resume == true
  and .steps.phase4_windows_full_parity_run.enabled == false
  and .steps.phase4_windows_full_parity_handoff_check.status == "pass"
  and .steps.phase4_windows_full_parity_handoff_check.reused_artifact == false
  and .steps.phase4_windows_full_parity_handoff_check.failure_kind == "none"
  and .decision.failure_kind == "none"
' "$RESUME_HANDOFF_FALLBACK_SUMMARY" >/dev/null; then
  echo "resume handoff fallback summary mismatch"
  cat "$RESUME_HANDOFF_FALLBACK_SUMMARY"
  exit 1
fi

echo "[phase4-windows-full-parity-handoff-run] run failure still runs handoff check"
: >"$CAPTURE"
FAIL_WRAPPER_SUMMARY="$TMP_DIR/fail_wrapper.json"
set +e
PHASE4_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
FAKE_RUN_FAIL=1 \
FAKE_RUN_FAIL_RC=27 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_fail" \
  --run-summary-json "$TMP_DIR/fail_run_summary.json" \
  --handoff-summary-json "$TMP_DIR/fail_handoff_summary.json" \
  --summary-json "$FAIL_WRAPPER_SUMMARY" \
  --print-summary-json 0 >"$FAIL_STDOUT" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 27 ]]; then
  echo "expected wrapper rc=27, got rc=$fail_rc"
  cat "$FAIL_STDOUT"
  exit 1
fi
run_line="$(grep '^run	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$run_line" || -z "$handoff_line" ]]; then
  echo "expected both stages to run in run-failure path"
  cat "$CAPTURE"
  cat "$FAIL_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 27
  and .steps.phase4_windows_full_parity_run.status == "fail"
  and .steps.phase4_windows_full_parity_run.rc == 27
  and .steps.phase4_windows_full_parity_run.command_rc == 27
  and .steps.phase4_windows_full_parity_run.contract_valid == true
  and .steps.phase4_windows_full_parity_run.failure_kind == "command_failed"
  and .steps.phase4_windows_full_parity_handoff_check.status == "pass"
  and .steps.phase4_windows_full_parity_handoff_check.rc == 0
  and .steps.phase4_windows_full_parity_handoff_check.command_rc == 0
  and .steps.phase4_windows_full_parity_handoff_check.contract_valid == true
  and .decision.failure_stage == "phase4_windows_full_parity_run"
  and .decision.failure_kind == "command_failed"
  and ((.decision.reason_codes // []) | any(. == "phase4_windows_full_parity_run_stage_failed"))
  and .failure.kind == "stage_failed"
' "$FAIL_WRAPPER_SUMMARY" >/dev/null; then
  echo "run-failure summary mismatch"
  cat "$FAIL_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase4-windows-full-parity-handoff-run] run contract fail-close"
: >"$CAPTURE"
RUN_CONTRACT_FAIL_SUMMARY="$TMP_DIR/run_contract_fail.json"
set +e
PHASE4_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
FAKE_RUN_OMIT_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_run_contract_fail" \
  --run-summary-json "$TMP_DIR/run_contract_fail_summary.json" \
  --handoff-summary-json "$TMP_DIR/run_contract_fail_handoff.json" \
  --summary-json "$RUN_CONTRACT_FAIL_SUMMARY" \
  --print-summary-json 0 >"$RUN_CONTRACT_FAIL_STDOUT" 2>&1
run_contract_fail_rc=$?
set -e
if [[ "$run_contract_fail_rc" -ne 3 ]]; then
  echo "expected wrapper rc=3 for run contract failure, got rc=$run_contract_fail_rc"
  cat "$RUN_CONTRACT_FAIL_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.phase4_windows_full_parity_run.status == "fail"
  and .steps.phase4_windows_full_parity_run.contract_valid == false
  and .steps.phase4_windows_full_parity_run.failure_kind == "contract_invalid"
  and .steps.phase4_windows_full_parity_run.rc == 3
  and .steps.phase4_windows_full_parity_handoff_check.status == "pass"
  and .decision.failure_stage == "phase4_windows_full_parity_run"
  and .decision.failure_kind == "contract_invalid"
  and ((.decision.reason_codes // []) | any(. == "phase4_windows_full_parity_run_contract_invalid"))
  and .failure.kind == "contract_invalid"
' "$RUN_CONTRACT_FAIL_SUMMARY" >/dev/null; then
  echo "run contract-fail summary mismatch"
  cat "$RUN_CONTRACT_FAIL_SUMMARY"
  exit 1
fi

echo "[phase4-windows-full-parity-handoff-run] handoff contract fail-close"
: >"$CAPTURE"
HANDOFF_CONTRACT_FAIL_SUMMARY="$TMP_DIR/handoff_contract_fail.json"
set +e
PHASE4_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_RUN_SCRIPT="$FAKE_RUN" \
PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
FAKE_HANDOFF_OMIT_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_handoff_contract_fail" \
  --run-summary-json "$TMP_DIR/handoff_contract_fail_run.json" \
  --handoff-summary-json "$TMP_DIR/handoff_contract_fail_summary.json" \
  --summary-json "$HANDOFF_CONTRACT_FAIL_SUMMARY" \
  --print-summary-json 0 >"$HANDOFF_CONTRACT_FAIL_STDOUT" 2>&1
handoff_contract_fail_rc=$?
set -e
if [[ "$handoff_contract_fail_rc" -ne 3 ]]; then
  echo "expected wrapper rc=3 for handoff contract failure, got rc=$handoff_contract_fail_rc"
  cat "$HANDOFF_CONTRACT_FAIL_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.phase4_windows_full_parity_run.status == "pass"
  and .steps.phase4_windows_full_parity_run.contract_valid == true
  and .steps.phase4_windows_full_parity_handoff_check.status == "fail"
  and .steps.phase4_windows_full_parity_handoff_check.contract_valid == false
  and .steps.phase4_windows_full_parity_handoff_check.failure_kind == "contract_invalid"
  and .steps.phase4_windows_full_parity_handoff_check.rc == 3
  and .decision.failure_stage == "phase4_windows_full_parity_handoff_check"
  and .decision.failure_kind == "contract_invalid"
  and ((.decision.reason_codes // []) | any(. == "phase4_windows_full_parity_handoff_check_contract_invalid"))
  and .failure.kind == "contract_invalid"
' "$HANDOFF_CONTRACT_FAIL_SUMMARY" >/dev/null; then
  echo "handoff contract-fail summary mismatch"
  cat "$HANDOFF_CONTRACT_FAIL_SUMMARY"
  exit 1
fi

echo "phase4 windows full parity handoff run integration ok"
