#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp chmod grep sed cat bash; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

RUNNER="$ROOT_DIR/scripts/phase1_resilience_handoff_run.sh"
if [[ ! -f "$RUNNER" ]]; then
  echo "missing script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_capture.tsv"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"
RESUME_LOG="$TMP_DIR/resume.log"
RESUME_FALLBACK_LOG="$TMP_DIR/resume_fallback.log"
REFRESH_LOG="$TMP_DIR/refresh.log"
FAIL_LOG="$TMP_DIR/fail.log"
CONTRACT_FAIL_LOG="$TMP_DIR/contract_fail.log"

FAKE_CI="$TMP_DIR/fake_ci_phase1_resilience.sh"
cat >"$FAKE_CI" <<'EOF_FAKE_CI'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE1_HANDOFF_RUN_CAPTURE_FILE:?}"
printf 'ci\t%s\n' "$*" >>"$capture"

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

fail_rc="${FAKE_CI_FAIL_RC:-17}"
status="pass"
rc=0
if [[ "${FAKE_CI_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="$fail_rc"
fi

if [[ -n "$summary_json" && "${FAKE_CI_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_CI_SUMMARY
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc
}
EOF_CI_SUMMARY
fi

if [[ "${FAKE_CI_FAIL:-0}" == "1" ]]; then
  exit "$fail_rc"
fi
exit 0
EOF_FAKE_CI
chmod +x "$FAKE_CI"

FAKE_HANDOFF="$TMP_DIR/fake_phase1_resilience_handoff_check.sh"
cat >"$FAKE_HANDOFF" <<'EOF_FAKE_HANDOFF'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE1_HANDOFF_RUN_CAPTURE_FILE:?}"
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

fail_rc="${FAKE_HANDOFF_FAIL_RC:-23}"
status="pass"
rc=0
if [[ "${FAKE_HANDOFF_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="$fail_rc"
fi

if [[ -n "$summary_json" && "${FAKE_HANDOFF_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_HANDOFF_SUMMARY
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc
}
EOF_HANDOFF_SUMMARY
fi

if [[ "${FAKE_HANDOFF_FAIL:-0}" == "1" ]]; then
  exit "$fail_rc"
fi
exit 0
EOF_FAKE_HANDOFF
chmod +x "$FAKE_HANDOFF"

echo "[phase1-resilience-handoff-run] dry-run contract path"
: >"$CAPTURE"
DRY_RUN_SUMMARY_JSON="$TMP_DIR/phase1_handoff_run_dry.json"
PHASE1_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE1_RESILIENCE_HANDOFF_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE1_RESILIENCE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --ci-summary-json "$TMP_DIR/ci_dry_summary.json" \
  --handoff-summary-json "$TMP_DIR/handoff_dry_summary.json" \
  --summary-json "$DRY_RUN_SUMMARY_JSON" \
  --allow-policy-no-go 1 \
  --dry-run 1 \
  --print-summary-json 0 \
  --ci-run-session-churn-guard 0 \
  --ci-run-3hop-runtime-integration 1 \
  --handoff-require-ci-pass 1 >"$DRY_RUN_LOG" 2>&1

ci_line="$(grep '^ci	' "$CAPTURE" | tail -n 1 || true)"
handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$ci_line" || -z "$handoff_line" ]]; then
  echo "expected both stages to run in dry-run path"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if [[ "$ci_line" != *"--dry-run 1"* || "$ci_line" != *"--print-summary-json 0"* ]]; then
  echo "dry-run ci forwarding contract mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$ci_line" != *"--allow-policy-no-go 1"* ]]; then
  echo "ci forwarding missing --allow-policy-no-go 1"
  echo "$ci_line"
  exit 1
fi
if [[ "$ci_line" != *"--run-session-churn-guard 0"* || "$ci_line" != *"--run-3hop-runtime-integration 1"* ]]; then
  echo "ci passthrough contract mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$handoff_line" != *"--ci-phase1-summary-json $TMP_DIR/ci_dry_summary.json"* ]]; then
  echo "dry-run handoff forwarding missing ci summary path"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--show-json 0"* ]]; then
  echo "dry-run handoff forwarding missing --show-json 0"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" == *"--dry-run 1"* || "$handoff_line" == *"--print-summary-json 0"* ]]; then
  echo "dry-run handoff forwarding should not pass unsupported flags"
  echo "$handoff_line"
  exit 1
fi
if [[ "$handoff_line" != *"--require-ci-pass 1"* ]]; then
  echo "handoff passthrough contract mismatch"
  echo "$handoff_line"
  exit 1
fi

if [[ ! -f "$DRY_RUN_SUMMARY_JSON" ]]; then
  echo "missing dry-run combined summary JSON: $DRY_RUN_SUMMARY_JSON"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .schema.id == "phase1_resilience_handoff_run_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .automation.track == "non_blockchain"
  and .automation.requires_sudo == false
  and .automation.requires_github == false
  and .automation.automatable_without_sudo_or_github == true
  and .inputs.allow_policy_no_go == true
  and .inputs.dry_run == true
  and .steps.ci_phase1_resilience.status == "pass"
  and .steps.ci_phase1_resilience.rc == 0
  and .steps.ci_phase1_resilience.command_rc == 0
  and .steps.ci_phase1_resilience.contract_valid == true
  and .steps.phase1_resilience_handoff_check.status == "pass"
  and .steps.phase1_resilience_handoff_check.rc == 0
  and .steps.phase1_resilience_handoff_check.command_rc == 0
  and .steps.phase1_resilience_handoff_check.contract_valid == true
  and .steps.ci_phase1_resilience.artifacts.summary_exists == true
  and .steps.phase1_resilience_handoff_check.artifacts.summary_exists == true
' "$DRY_RUN_SUMMARY_JSON" >/dev/null; then
  echo "dry-run combined summary contract mismatch"
  cat "$DRY_RUN_SUMMARY_JSON"
  exit 1
fi

echo "[phase1-resilience-handoff-run] resume mode reuses pass summaries"
: >"$CAPTURE"
RESUME_SUMMARY_JSON="$TMP_DIR/phase1_handoff_run_resume.json"
RESUME_REPORTS_DIR="$TMP_DIR/reports_resume"
RESUME_CI_SUMMARY_JSON="$TMP_DIR/ci_resume_summary.json"
RESUME_HANDOFF_SUMMARY_JSON="$TMP_DIR/handoff_resume_summary.json"
mkdir -p "$RESUME_REPORTS_DIR"
cat >"$RESUME_CI_SUMMARY_JSON" <<'EOF_RESUME_CI_SUMMARY'
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_RESUME_CI_SUMMARY
cat >"$RESUME_HANDOFF_SUMMARY_JSON" <<'EOF_RESUME_HANDOFF_SUMMARY'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_RESUME_HANDOFF_SUMMARY

PHASE1_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE1_RESILIENCE_HANDOFF_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE1_RESILIENCE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --resume 1 \
  --reports-dir "$RESUME_REPORTS_DIR" \
  --ci-summary-json "$RESUME_CI_SUMMARY_JSON" \
  --handoff-summary-json "$RESUME_HANDOFF_SUMMARY_JSON" \
  --summary-json "$RESUME_SUMMARY_JSON" \
  --print-summary-json 0 >"$RESUME_LOG" 2>&1

if [[ -s "$CAPTURE" ]]; then
  echo "resume mode should skip ci/handoff executions when pass summaries exist"
  cat "$CAPTURE"
  cat "$RESUME_LOG"
  exit 1
fi
if [[ ! -f "$RESUME_SUMMARY_JSON" ]]; then
  echo "missing resume summary JSON: $RESUME_SUMMARY_JSON"
  cat "$RESUME_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.resume == true
  and .steps.ci_phase1_resilience.status == "pass"
  and .steps.ci_phase1_resilience.rc == 0
  and .steps.ci_phase1_resilience.command_rc == 0
  and .steps.ci_phase1_resilience.contract_valid == true
  and .steps.ci_phase1_resilience.reused_artifact == true
  and .steps.phase1_resilience_handoff_check.status == "pass"
  and .steps.phase1_resilience_handoff_check.rc == 0
  and .steps.phase1_resilience_handoff_check.command_rc == 0
  and .steps.phase1_resilience_handoff_check.contract_valid == true
  and .steps.phase1_resilience_handoff_check.reused_artifact == true
' "$RESUME_SUMMARY_JSON" >/dev/null; then
  echo "resume summary missing expected artifact-reuse fields"
  cat "$RESUME_SUMMARY_JSON"
  exit 1
fi
if ! grep -q '\[phase1-resilience-handoff-run\] step=ci_phase1_resilience status=pass rc=0 reason=resume-artifact-pass' "$RESUME_LOG"; then
  echo "resume log missing ci artifact reuse signal"
  cat "$RESUME_LOG"
  exit 1
fi
if ! grep -q '\[phase1-resilience-handoff-run\] step=phase1_resilience_handoff_check status=pass rc=0 reason=resume-artifact-pass' "$RESUME_LOG"; then
  echo "resume log missing handoff artifact reuse signal"
  cat "$RESUME_LOG"
  exit 1
fi

echo "[phase1-resilience-handoff-run] resume mode reruns when summary is non-pass"
: >"$CAPTURE"
RESUME_FALLBACK_SUMMARY_JSON="$TMP_DIR/phase1_handoff_run_resume_fallback.json"
RESUME_FALLBACK_REPORTS_DIR="$TMP_DIR/reports_resume_fallback"
RESUME_FALLBACK_CI_SUMMARY_JSON="$TMP_DIR/ci_resume_fallback_summary.json"
mkdir -p "$RESUME_FALLBACK_REPORTS_DIR"
cat >"$RESUME_FALLBACK_CI_SUMMARY_JSON" <<'EOF_RESUME_FALLBACK_CI_SUMMARY'
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 9
}
EOF_RESUME_FALLBACK_CI_SUMMARY

PHASE1_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE1_RESILIENCE_HANDOFF_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE1_RESILIENCE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --resume 1 \
  --reports-dir "$RESUME_FALLBACK_REPORTS_DIR" \
  --ci-summary-json "$RESUME_FALLBACK_CI_SUMMARY_JSON" \
  --handoff-summary-json "$TMP_DIR/handoff_resume_fallback_summary.json" \
  --summary-json "$RESUME_FALLBACK_SUMMARY_JSON" \
  --run-phase1-resilience-handoff-check 0 \
  --print-summary-json 0 >"$RESUME_FALLBACK_LOG" 2>&1

if ! grep -q '^ci	' "$CAPTURE"; then
  echo "resume fallback should rerun ci stage when summary is non-pass"
  cat "$CAPTURE"
  cat "$RESUME_FALLBACK_LOG"
  exit 1
fi
if [[ ! -f "$RESUME_FALLBACK_SUMMARY_JSON" ]]; then
  echo "missing resume fallback summary JSON: $RESUME_FALLBACK_SUMMARY_JSON"
  cat "$RESUME_FALLBACK_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.resume == true
  and .steps.ci_phase1_resilience.status == "pass"
  and .steps.ci_phase1_resilience.reused_artifact == false
  and .steps.phase1_resilience_handoff_check.enabled == false
' "$RESUME_FALLBACK_SUMMARY_JSON" >/dev/null; then
  echo "resume fallback summary mismatch"
  cat "$RESUME_FALLBACK_SUMMARY_JSON"
  exit 1
fi

echo "[phase1-resilience-handoff-run] refresh-from-ci-summary runs handoff-only against existing ci artifact"
: >"$CAPTURE"
REFRESH_SUMMARY_JSON="$TMP_DIR/phase1_handoff_run_refresh.json"
REFRESH_REPORTS_DIR="$TMP_DIR/reports_refresh"
REFRESH_CI_SUMMARY_JSON="$TMP_DIR/ci_refresh_summary.json"
REFRESH_HANDOFF_SUMMARY_JSON="$TMP_DIR/handoff_refresh_summary.json"
mkdir -p "$REFRESH_REPORTS_DIR"
cat >"$REFRESH_CI_SUMMARY_JSON" <<'EOF_REFRESH_CI_SUMMARY'
{
  "schema": {
    "id": "ci_phase1_resilience_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_REFRESH_CI_SUMMARY
cat >"$REFRESH_HANDOFF_SUMMARY_JSON" <<'EOF_REFRESH_HANDOFF_SUMMARY'
{
  "schema": {
    "id": "phase1_resilience_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_REFRESH_HANDOFF_SUMMARY

PHASE1_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE1_RESILIENCE_HANDOFF_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE1_RESILIENCE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
bash "$RUNNER" \
  --refresh-from-ci-summary 1 \
  --resume 1 \
  --reports-dir "$REFRESH_REPORTS_DIR" \
  --ci-summary-json "$REFRESH_CI_SUMMARY_JSON" \
  --handoff-summary-json "$REFRESH_HANDOFF_SUMMARY_JSON" \
  --summary-json "$REFRESH_SUMMARY_JSON" \
  --print-summary-json 0 >"$REFRESH_LOG" 2>&1

if grep -q '^ci	' "$CAPTURE"; then
  echo "refresh-from-ci-summary should skip ci stage execution"
  cat "$CAPTURE"
  cat "$REFRESH_LOG"
  exit 1
fi
refresh_handoff_line="$(grep '^handoff	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$refresh_handoff_line" ]]; then
  echo "refresh-from-ci-summary should execute handoff stage"
  cat "$CAPTURE"
  cat "$REFRESH_LOG"
  exit 1
fi
if [[ "$refresh_handoff_line" != *"--ci-phase1-summary-json $REFRESH_CI_SUMMARY_JSON"* ]]; then
  echo "refresh-from-ci-summary handoff forwarding missing ci summary path"
  echo "$refresh_handoff_line"
  exit 1
fi
if [[ ! -f "$REFRESH_SUMMARY_JSON" ]]; then
  echo "missing refresh summary JSON: $REFRESH_SUMMARY_JSON"
  cat "$REFRESH_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.refresh_from_ci_summary == true
  and .inputs.resume == true
  and .inputs.run_ci_phase1_resilience == false
  and .inputs.run_phase1_resilience_handoff_check == true
  and .steps.ci_phase1_resilience.enabled == false
  and .steps.ci_phase1_resilience.status == "skip"
  and .steps.phase1_resilience_handoff_check.enabled == true
  and .steps.phase1_resilience_handoff_check.status == "pass"
  and .steps.phase1_resilience_handoff_check.command_rc == 0
  and .steps.phase1_resilience_handoff_check.reused_artifact == false
  and .steps.phase1_resilience_handoff_check.contract_valid == true
' "$REFRESH_SUMMARY_JSON" >/dev/null; then
  echo "refresh-from-ci-summary summary mismatch"
  cat "$REFRESH_SUMMARY_JSON"
  exit 1
fi
if ! grep -q '\[phase1-resilience-handoff-run\] step=ci_phase1_resilience status=skip reason=refresh-from-ci-summary' "$REFRESH_LOG"; then
  echo "refresh-from-ci-summary log missing ci skip reason"
  cat "$REFRESH_LOG"
  exit 1
fi
if ! grep -q '\[phase1-resilience-handoff-run\] refresh-from-ci-summary enabled; ignoring resume for handoff-check stage' "$REFRESH_LOG"; then
  echo "refresh-from-ci-summary log missing resume-ignore signal"
  cat "$REFRESH_LOG"
  exit 1
fi

echo "[phase1-resilience-handoff-run] ci failure keeps handoff stage execution"
: >"$CAPTURE"
FAIL_SUMMARY_JSON="$TMP_DIR/phase1_handoff_run_fail.json"
set +e
PHASE1_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE1_RESILIENCE_HANDOFF_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE1_RESILIENCE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
FAKE_CI_FAIL=1 \
FAKE_CI_FAIL_RC=27 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_fail" \
  --ci-summary-json "$TMP_DIR/ci_fail_summary.json" \
  --handoff-summary-json "$TMP_DIR/handoff_fail_summary.json" \
  --summary-json "$FAIL_SUMMARY_JSON" \
  --print-summary-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 27 ]]; then
  echo "expected wrapper fail rc=27, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! grep -q '^ci	' "$CAPTURE" || ! grep -q '^handoff	' "$CAPTURE"; then
  echo "expected both stages to run in ci-failure path"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
if [[ ! -f "$FAIL_SUMMARY_JSON" ]]; then
  echo "missing fail-path combined summary JSON: $FAIL_SUMMARY_JSON"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 27
  and .automation.track == "non_blockchain"
  and .automation.requires_sudo == false
  and .automation.requires_github == false
  and .automation.automatable_without_sudo_or_github == true
  and .steps.ci_phase1_resilience.status == "fail"
  and .steps.ci_phase1_resilience.rc == 27
  and .steps.ci_phase1_resilience.command_rc == 27
  and .steps.ci_phase1_resilience.contract_valid == true
  and .steps.phase1_resilience_handoff_check.status == "pass"
  and .steps.phase1_resilience_handoff_check.rc == 0
  and .steps.phase1_resilience_handoff_check.command_rc == 0
  and .steps.phase1_resilience_handoff_check.contract_valid == true
' "$FAIL_SUMMARY_JSON" >/dev/null; then
  echo "ci-failure combined summary contract mismatch"
  cat "$FAIL_SUMMARY_JSON"
  exit 1
fi

echo "[phase1-resilience-handoff-run] dry-run contract fail-close when handoff summary missing"
: >"$CAPTURE"
CONTRACT_FAIL_SUMMARY_JSON="$TMP_DIR/phase1_handoff_run_contract_fail.json"
set +e
PHASE1_HANDOFF_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE1_RESILIENCE_HANDOFF_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE1_RESILIENCE_HANDOFF_RUN_HANDOFF_CHECK_SCRIPT="$FAKE_HANDOFF" \
FAKE_HANDOFF_OMIT_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_contract_fail" \
  --ci-summary-json "$TMP_DIR/ci_contract_fail_summary.json" \
  --handoff-summary-json "$TMP_DIR/handoff_contract_fail_summary.json" \
  --summary-json "$CONTRACT_FAIL_SUMMARY_JSON" \
  --dry-run 1 \
  --print-summary-json 0 >"$CONTRACT_FAIL_LOG" 2>&1
contract_fail_rc=$?
set -e
if [[ "$contract_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when handoff summary contract is missing"
  cat "$CONTRACT_FAIL_LOG"
  exit 1
fi
if [[ ! -f "$CONTRACT_FAIL_SUMMARY_JSON" ]]; then
  echo "missing contract-fail combined summary JSON: $CONTRACT_FAIL_SUMMARY_JSON"
  cat "$CONTRACT_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .steps.ci_phase1_resilience.status == "pass"
  and .steps.ci_phase1_resilience.contract_valid == true
  and .steps.phase1_resilience_handoff_check.status == "fail"
  and .steps.phase1_resilience_handoff_check.command_rc == 0
  and .steps.phase1_resilience_handoff_check.contract_valid == false
  and .steps.phase1_resilience_handoff_check.contract_error != null
  and .steps.phase1_resilience_handoff_check.rc == 3
' "$CONTRACT_FAIL_SUMMARY_JSON" >/dev/null; then
  echo "contract-fail combined summary mismatch"
  cat "$CONTRACT_FAIL_SUMMARY_JSON"
  exit 1
fi

echo "phase1 resilience handoff run integration check ok"
