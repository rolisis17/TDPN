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

RUNNER="${PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_handoff_run.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
PASS_STDOUT="$TMP_DIR/pass.stdout"
DRY_STDOUT="$TMP_DIR/dry.stdout"
RESUME_STDOUT="$TMP_DIR/resume.stdout"
RESUME_FALLBACK_STDOUT="$TMP_DIR/resume_fallback.stdout"
FAIL_STDOUT="$TMP_DIR/fail.stdout"
SIGNOFF_CONTRACT_FAIL_STDOUT="$TMP_DIR/signoff_contract_fail.stdout"
HANDOFF_CONTRACT_FAIL_STDOUT="$TMP_DIR/handoff_contract_fail.stdout"

FAKE_SIGNOFF="$TMP_DIR/fake_phase2_linux_prod_candidate_signoff.sh"
cat >"$FAKE_SIGNOFF" <<'EOF_FAKE_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE2_HANDFOFF_RUN_CAPTURE_FILE:?}"
printf 'signoff\t%s\n' "$*" >>"$capture"

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
if [[ "${FAKE_SIGNOFF_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="${FAKE_SIGNOFF_FAIL_RC:-31}"
elif [[ "${FAKE_SIGNOFF_WARN:-0}" == "1" ]]; then
  status="warn"
  rc=0
fi

roadmap_summary="${FAKE_SIGNOFF_ROADMAP_SUMMARY:-${reports_dir}/roadmap_progress_summary.json}"
run_summary="${FAKE_SIGNOFF_RUN_SUMMARY:-${reports_dir}/phase2_linux_prod_candidate_run_summary.json}"
check_summary="${FAKE_SIGNOFF_CHECK_SUMMARY:-${reports_dir}/phase2_linux_prod_candidate_check_summary.json}"

mkdir -p "$(dirname "$run_summary")" "$(dirname "$check_summary")" "$(dirname "$roadmap_summary")"

cat >"$run_summary" <<EOF_RUN
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
        "summary_json": "$check_summary"
      }
    }
  },
  "artifacts": {
    "check_summary_json": "$check_summary"
  }
}
EOF_RUN

cat >"$check_summary" <<'EOF_CHECK'
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
EOF_CHECK

if [[ "${FAKE_SIGNOFF_ROADMAP_MODE:-explicit}" == "explicit" ]]; then
  cat >"$roadmap_summary" <<'EOF_ROADMAP'
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
EOF_ROADMAP
else
  cat >"$roadmap_summary" <<'EOF_ROADMAP_MIN'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase2_linux_prod_candidate_handoff": {
      "note": "intentionally missing booleans"
    }
  }
}
EOF_ROADMAP_MIN
fi

if [[ -n "$summary_json" && "${FAKE_SIGNOFF_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_signoff_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "steps": {
    "phase2_linux_prod_candidate_run": {
      "status": "$status",
      "rc": $rc,
      "command_rc": $rc,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$run_summary"
      }
    },
    "roadmap_progress_report": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$roadmap_summary"
      }
    }
  },
  "artifacts": {
    "run_summary_json": "$run_summary",
    "roadmap_summary_json": "$roadmap_summary"
  }
}
EOF_SUMMARY
fi

if [[ "${FAKE_SIGNOFF_FAIL:-0}" == "1" ]]; then
  exit "$rc"
fi
exit 0
EOF_FAKE_SIGNOFF
chmod +x "$FAKE_SIGNOFF"

FAKE_HANDFOFF="$TMP_DIR/fake_phase2_linux_prod_candidate_handoff_check.sh"
cat >"$FAKE_HANDFOFF" <<'EOF_FAKE_HANDOFF'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE2_HANDFOFF_RUN_CAPTURE_FILE:?}"
printf 'handoff\t%s\n' "$*" >>"$capture"

summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
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
  cat >"$summary_json" <<'EOF_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "fail_closed": true,
  "inputs": {
    "phase2_signoff_summary_json": "/fake/signoff.json",
    "roadmap_summary_json": "/fake/roadmap.json"
  },
  "handoff": {
    "signoff_pipeline_ok": true,
    "signoff_pipeline_status": "pass",
    "signoff_pipeline_resolved": true,
    "signoff_pipeline_contract_valid": true,
    "release_integrity_ok": true,
    "release_integrity_status": "pass",
    "release_integrity_resolved": true,
    "release_policy_ok": true,
    "release_policy_status": "pass",
    "release_policy_resolved": true,
    "operator_lifecycle_ok": true,
    "operator_lifecycle_status": "pass",
    "operator_lifecycle_resolved": true,
    "pilot_signoff_ok": true,
    "pilot_signoff_status": "pass",
    "pilot_signoff_resolved": true,
    "sources": {
      "signoff_pipeline_ok": "phase2_signoff_summary",
      "release_integrity_ok": "roadmap_progress_summary.vpn_track.phase2_linux_prod_candidate_handoff.release_integrity_ok",
      "release_policy_ok": "roadmap_progress_summary.vpn_track.phase2_linux_prod_candidate_handoff.release_policy_ok",
      "operator_lifecycle_ok": "roadmap_progress_summary.vpn_track.phase2_linux_prod_candidate_handoff.operator_lifecycle_ok",
      "pilot_signoff_ok": "roadmap_progress_summary.vpn_track.phase2_linux_prod_candidate_handoff.pilot_signoff_ok"
    }
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
chmod +x "$FAKE_HANDFOFF"

echo "[phase2-linux-prod-candidate-handoff-run] pass path"
: >"$CAPTURE"
PASS_WRAPPER_SUMMARY="$TMP_DIR/pass_wrapper.json"
PHASE2_HANDFOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDFOFF" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_pass" \
  --signoff-summary-json "$TMP_DIR/pass_signoff_summary.json" \
  --handoff-summary-json "$TMP_DIR/pass_handoff_summary.json" \
  --summary-json "$PASS_WRAPPER_SUMMARY" \
  --print-summary-json 0 \
  --signoff-run-pass-through 7 \
  --handoff-require-signoff-pipeline-ok 1 >"$PASS_STDOUT" 2>&1

signoff_line="$(grep '^signoff	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$signoff_line" != *"--reports-dir $TMP_DIR/reports_pass"* || "$signoff_line" != *"--summary-json $TMP_DIR/pass_signoff_summary.json"* ]]; then
  echo "signoff forwarding mismatch"
  echo "$signoff_line"
  exit 1
fi
if [[ "$signoff_line" != *"--run-pass-through 7"* ]]; then
  echo "signoff passthrough mismatch"
  echo "$signoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--phase2-signoff-summary-json $TMP_DIR/pass_signoff_summary.json"* || "$handoff_line" != *"--roadmap-summary-json $TMP_DIR/reports_pass/roadmap_progress_summary.json"* ]]; then
  echo "handoff forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-signoff-pipeline-ok 1"* || "$handoff_line" != *"--show-json 0"* ]]; then
  echo "handoff default forwarding mismatch"
  echo "$handoff_line"
  exit 1
fi

if ! jq -e --arg signoff_summary "$TMP_DIR/pass_signoff_summary.json" --arg handoff_summary "$TMP_DIR/pass_handoff_summary.json" '
  .version == 1
  and .schema.id == "phase2_linux_prod_candidate_handoff_run_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.dry_run == false
  and .steps.phase2_linux_prod_candidate_signoff.status == "pass"
  and .steps.phase2_linux_prod_candidate_signoff.rc == 0
  and .steps.phase2_linux_prod_candidate_signoff.command_rc == 0
  and .steps.phase2_linux_prod_candidate_signoff.contract_valid == true
  and .steps.phase2_linux_prod_candidate_signoff.artifacts.summary_json == $signoff_summary
  and .steps.phase2_linux_prod_candidate_handoff_check.status == "pass"
  and .steps.phase2_linux_prod_candidate_handoff_check.rc == 0
  and .steps.phase2_linux_prod_candidate_handoff_check.command_rc == 0
  and .steps.phase2_linux_prod_candidate_handoff_check.contract_valid == true
  and .steps.phase2_linux_prod_candidate_handoff_check.artifacts.summary_json == $handoff_summary
  and .decision.pass == true
  and (.decision.reason_details | length) == 0
  and (.decision.warnings | length) == 0
' "$PASS_WRAPPER_SUMMARY" >/dev/null; then
  echo "pass-path combined summary mismatch"
  cat "$PASS_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase2-linux-prod-candidate-handoff-run] dry-run forwarding and relax behavior"
: >"$CAPTURE"
DRY_WRAPPER_SUMMARY="$TMP_DIR/dry_wrapper.json"
PHASE2_HANDFOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDFOFF" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --signoff-summary-json "$TMP_DIR/dry_signoff_summary.json" \
  --handoff-summary-json "$TMP_DIR/dry_handoff_summary.json" \
  --summary-json "$DRY_WRAPPER_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --signoff-gamma 9 \
  --handoff-require-release-policy-ok 1 \
  --handoff-require-pilot-signoff-ok 1 >"$DRY_STDOUT" 2>&1

signoff_line="$(grep '^signoff	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ "$signoff_line" != *"--dry-run 1"* || "$signoff_line" != *"--gamma 9"* ]]; then
  echo "dry-run signoff forwarding mismatch"
  echo "$signoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-signoff-pipeline-ok 0"* || "$handoff_line" != *"--require-release-integrity-ok 0"* || "$handoff_line" != *"--require-release-policy-ok 1"* || "$handoff_line" != *"--require-operator-lifecycle-ok 0"* || "$handoff_line" != *"--require-pilot-signoff-ok 1"* ]]; then
  echo "dry-run handoff relax/override mismatch"
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
  and .steps.phase2_linux_prod_candidate_signoff.contract_valid == true
  and .steps.phase2_linux_prod_candidate_handoff_check.contract_valid == true
  and .decision.pass == true
  and (.decision.reason_details | length) == 0
' "$DRY_WRAPPER_SUMMARY" >/dev/null; then
  echo "dry-run wrapper summary mismatch"
  cat "$DRY_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase2-linux-prod-candidate-handoff-run] resume mode reuses pass summaries"
: >"$CAPTURE"
RESUME_WRAPPER_SUMMARY="$TMP_DIR/resume_wrapper.json"
RESUME_SIGNOFF_SUMMARY="$TMP_DIR/resume_signoff_summary.json"
RESUME_HANDOFF_SUMMARY="$TMP_DIR/resume_handoff_summary.json"
RESUME_ROADMAP_SUMMARY="$TMP_DIR/resume_roadmap_progress_summary.json"
cat >"$RESUME_SIGNOFF_SUMMARY" <<EOF_RESUME_SIGNOFF
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
        "summary_json": "$TMP_DIR/resume_phase2_run_summary.json"
      }
    },
    "roadmap_progress_report": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "$RESUME_ROADMAP_SUMMARY"
      }
    }
  },
  "artifacts": {
    "run_summary_json": "$TMP_DIR/resume_phase2_run_summary.json",
    "roadmap_summary_json": "$RESUME_ROADMAP_SUMMARY"
  }
}
EOF_RESUME_SIGNOFF
cat >"$RESUME_HANDOFF_SUMMARY" <<'EOF_RESUME_HANDOFF'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "signoff_pipeline_ok": true
  },
  "decision": {
    "pass": true
  }
}
EOF_RESUME_HANDOFF
cat >"$RESUME_ROADMAP_SUMMARY" <<'EOF_RESUME_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0
}
EOF_RESUME_ROADMAP

PHASE2_HANDFOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDFOFF" \
bash "$RUNNER" \
  --resume 1 \
  --reports-dir "$TMP_DIR/reports_resume" \
  --signoff-summary-json "$RESUME_SIGNOFF_SUMMARY" \
  --handoff-summary-json "$RESUME_HANDOFF_SUMMARY" \
  --summary-json "$RESUME_WRAPPER_SUMMARY" \
  --print-summary-json 0 >"$RESUME_STDOUT" 2>&1

if [[ -s "$CAPTURE" ]]; then
  echo "resume mode should skip signoff/handoff commands when pass summaries exist"
  cat "$CAPTURE"
  cat "$RESUME_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.resume == true
  and .steps.phase2_linux_prod_candidate_signoff.status == "pass"
  and .steps.phase2_linux_prod_candidate_signoff.rc == 0
  and .steps.phase2_linux_prod_candidate_signoff.command_rc == 0
  and .steps.phase2_linux_prod_candidate_signoff.contract_valid == true
  and .steps.phase2_linux_prod_candidate_signoff.reused_artifact == true
  and .steps.phase2_linux_prod_candidate_handoff_check.status == "pass"
  and .steps.phase2_linux_prod_candidate_handoff_check.rc == 0
  and .steps.phase2_linux_prod_candidate_handoff_check.command_rc == 0
  and .steps.phase2_linux_prod_candidate_handoff_check.contract_valid == true
  and .steps.phase2_linux_prod_candidate_handoff_check.reused_artifact == true
  and .decision.pass == true
  and (.decision.reason_details | length) == 0
' "$RESUME_WRAPPER_SUMMARY" >/dev/null; then
  echo "resume wrapper summary mismatch"
  cat "$RESUME_WRAPPER_SUMMARY"
  exit 1
fi
if ! grep -q '\[phase2-linux-prod-candidate-handoff-run\] stage=phase2_linux_prod_candidate_signoff status=pass rc=0 reason=resume-artifact-pass' "$RESUME_STDOUT"; then
  echo "resume stdout missing signoff reuse signal"
  cat "$RESUME_STDOUT"
  exit 1
fi
if ! grep -q '\[phase2-linux-prod-candidate-handoff-run\] stage=phase2_linux_prod_candidate_handoff_check status=pass rc=0 reason=resume-artifact-pass' "$RESUME_STDOUT"; then
  echo "resume stdout missing handoff reuse signal"
  cat "$RESUME_STDOUT"
  exit 1
fi

echo "[phase2-linux-prod-candidate-handoff-run] resume fallback reruns non-pass summaries"
: >"$CAPTURE"
RESUME_FALLBACK_WRAPPER_SUMMARY="$TMP_DIR/resume_fallback_wrapper.json"
RESUME_FALLBACK_SIGNOFF_SUMMARY="$TMP_DIR/resume_fallback_signoff_summary.json"
RESUME_FALLBACK_HANDOFF_SUMMARY="$TMP_DIR/resume_fallback_handoff_summary.json"
cat >"$RESUME_FALLBACK_SIGNOFF_SUMMARY" <<'EOF_RESUME_FALLBACK_SIGNOFF'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_signoff_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 9,
  "steps": {
    "phase2_linux_prod_candidate_run": {
      "status": "fail",
      "rc": 9,
      "command_rc": 9,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/fake/nonpass_run_summary.json"
      }
    },
    "roadmap_progress_report": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "artifacts": {
        "summary_json": "/fake/nonpass_roadmap_summary.json"
      }
    }
  }
}
EOF_RESUME_FALLBACK_SIGNOFF
cat >"$RESUME_FALLBACK_HANDOFF_SUMMARY" <<'EOF_RESUME_FALLBACK_HANDOFF'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 7,
  "handoff": {
    "signoff_pipeline_ok": false
  },
  "decision": {
    "pass": false
  }
}
EOF_RESUME_FALLBACK_HANDOFF

PHASE2_HANDFOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDFOFF" \
bash "$RUNNER" \
  --resume 1 \
  --reports-dir "$TMP_DIR/reports_resume_fallback" \
  --signoff-summary-json "$RESUME_FALLBACK_SIGNOFF_SUMMARY" \
  --handoff-summary-json "$RESUME_FALLBACK_HANDOFF_SUMMARY" \
  --summary-json "$RESUME_FALLBACK_WRAPPER_SUMMARY" \
  --print-summary-json 0 >"$RESUME_FALLBACK_STDOUT" 2>&1

if ! grep -q '^signoff	' "$CAPTURE" || ! grep -q '^handoff	' "$CAPTURE"; then
  echo "resume fallback should rerun both stages when summaries are non-pass"
  cat "$CAPTURE"
  cat "$RESUME_FALLBACK_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.resume == true
  and .steps.phase2_linux_prod_candidate_signoff.status == "pass"
  and .steps.phase2_linux_prod_candidate_signoff.reused_artifact == false
  and .steps.phase2_linux_prod_candidate_handoff_check.status == "pass"
  and .steps.phase2_linux_prod_candidate_handoff_check.reused_artifact == false
  and .decision.pass == true
' "$RESUME_FALLBACK_WRAPPER_SUMMARY" >/dev/null; then
  echo "resume fallback summary mismatch"
  cat "$RESUME_FALLBACK_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase2-linux-prod-candidate-handoff-run] signoff failure still runs handoff check"
: >"$CAPTURE"
FAIL_WRAPPER_SUMMARY="$TMP_DIR/fail_wrapper.json"
set +e
PHASE2_HANDFOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDFOFF" \
FAKE_SIGNOFF_FAIL=1 \
FAKE_SIGNOFF_FAIL_RC=27 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_fail" \
  --signoff-summary-json "$TMP_DIR/fail_signoff_summary.json" \
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
signoff_line="$(grep '^signoff	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$signoff_line" || -z "$handoff_line" ]]; then
  echo "expected both stages to run in signoff-failure path"
  cat "$CAPTURE"
  cat "$FAIL_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 27
  and .steps.phase2_linux_prod_candidate_signoff.status == "fail"
  and .steps.phase2_linux_prod_candidate_signoff.rc == 27
  and .steps.phase2_linux_prod_candidate_signoff.command_rc == 27
  and .steps.phase2_linux_prod_candidate_signoff.contract_valid == true
  and .steps.phase2_linux_prod_candidate_handoff_check.status == "pass"
  and .steps.phase2_linux_prod_candidate_handoff_check.rc == 0
  and .steps.phase2_linux_prod_candidate_handoff_check.command_rc == 0
  and .steps.phase2_linux_prod_candidate_handoff_check.contract_valid == true
  and .decision.pass == false
  and ((.decision.reason_details // []) | any(.code == "signoff_step_not_pass"))
  and ((.decision.reason_codes // []) | index("signoff_step_not_pass") != null)
' "$FAIL_WRAPPER_SUMMARY" >/dev/null; then
  echo "signoff-failure summary mismatch"
  cat "$FAIL_WRAPPER_SUMMARY"
  exit 1
fi

echo "[phase2-linux-prod-candidate-handoff-run] signoff contract fail-close"
: >"$CAPTURE"
SIGNOFF_CONTRACT_FAIL_SUMMARY="$TMP_DIR/signoff_contract_fail.json"
set +e
PHASE2_HANDFOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDFOFF" \
FAKE_SIGNOFF_OMIT_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_signoff_contract_fail" \
  --signoff-summary-json "$TMP_DIR/signoff_contract_fail_summary.json" \
  --handoff-summary-json "$TMP_DIR/signoff_contract_fail_handoff.json" \
  --summary-json "$SIGNOFF_CONTRACT_FAIL_SUMMARY" \
  --print-summary-json 0 >"$SIGNOFF_CONTRACT_FAIL_STDOUT" 2>&1
signoff_contract_fail_rc=$?
set -e
if [[ "$signoff_contract_fail_rc" -ne 3 ]]; then
  echo "expected wrapper rc=3 for signoff contract failure, got rc=$signoff_contract_fail_rc"
  cat "$SIGNOFF_CONTRACT_FAIL_STDOUT"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.phase2_linux_prod_candidate_signoff.status == "fail"
  and .steps.phase2_linux_prod_candidate_signoff.contract_valid == false
  and .steps.phase2_linux_prod_candidate_signoff.rc == 3
  and .steps.phase2_linux_prod_candidate_handoff_check.status == "pass"
  and .decision.pass == false
  and ((.decision.reason_details // []) | any(.code == "signoff_summary_contract_invalid"))
  and ((.decision.reason_codes // []) | index("signoff_summary_contract_invalid") != null)
' "$SIGNOFF_CONTRACT_FAIL_SUMMARY" >/dev/null; then
  echo "signoff contract-fail summary mismatch"
  cat "$SIGNOFF_CONTRACT_FAIL_SUMMARY"
  exit 1
fi

echo "[phase2-linux-prod-candidate-handoff-run] handoff contract fail-close"
: >"$CAPTURE"
HANDOFF_CONTRACT_FAIL_SUMMARY="$TMP_DIR/handoff_contract_fail.json"
set +e
PHASE2_HANDFOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDFOFF" \
FAKE_HANDOFF_OMIT_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_handoff_contract_fail" \
  --signoff-summary-json "$TMP_DIR/handoff_contract_fail_signoff.json" \
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
  and .steps.phase2_linux_prod_candidate_signoff.status == "pass"
  and .steps.phase2_linux_prod_candidate_signoff.contract_valid == true
  and .steps.phase2_linux_prod_candidate_handoff_check.status == "fail"
  and .steps.phase2_linux_prod_candidate_handoff_check.contract_valid == false
  and .steps.phase2_linux_prod_candidate_handoff_check.rc == 3
  and .decision.pass == false
  and ((.decision.reason_details // []) | any(.code == "handoff_summary_contract_invalid"))
  and ((.decision.reason_codes // []) | index("handoff_summary_contract_invalid") != null)
' "$HANDOFF_CONTRACT_FAIL_SUMMARY" >/dev/null; then
  echo "handoff contract-fail summary mismatch"
  cat "$HANDOFF_CONTRACT_FAIL_SUMMARY"
  exit 1
fi

echo "phase2 linux prod candidate handoff run integration ok"
