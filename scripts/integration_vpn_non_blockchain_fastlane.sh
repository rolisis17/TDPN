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

RUNNER="${VPN_NON_BLOCKCHAIN_FASTLANE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/vpn_non_blockchain_fastlane.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

if grep -Eq 'phase5|cosmos' "$RUNNER"; then
  echo "runner contains forbidden chain-stage references (phase5/cosmos)"
  exit 1
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
SUCCESS_LOG="$TMP_DIR/success.log"
DRY_LOG="$TMP_DIR/dry.log"
FAIL_LOG="$TMP_DIR/fail.log"

FAKE_RUNTIME="$TMP_DIR/fake_runtime_fix_record.sh"
cat >"$FAKE_RUNTIME" <<'EOF_FAKE_RUNTIME'
#!/usr/bin/env bash
set -euo pipefail

capture="${FASTLANE_CAPTURE_FILE:?}"
capture_line="runtime"
for arg in "$@"; do
  capture_line+=$'\t'"$arg"
done
if command -v flock >/dev/null 2>&1; then
  {
    flock -x 9
    printf '%s\n' "$capture_line" >&9
  } 9>>"$capture"
else
  printf '%s\n' "$capture_line" >>"$capture"
fi

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

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_RUNTIME_SUMMARY'
{
  "version": 1,
  "status": "pass",
  "rc": 0
}
EOF_RUNTIME_SUMMARY
fi

if [[ "${FASTLANE_FAIL_STAGE:-}" == "runtime" ]]; then
  exit "${FASTLANE_FAIL_RC:-41}"
fi
exit 0
EOF_FAKE_RUNTIME
chmod +x "$FAKE_RUNTIME"

FAKE_PHASE1="$TMP_DIR/fake_phase1.sh"
cat >"$FAKE_PHASE1" <<'EOF_FAKE_PHASE1'
#!/usr/bin/env bash
set -euo pipefail

capture="${FASTLANE_CAPTURE_FILE:?}"
capture_line="phase1"
for arg in "$@"; do
  capture_line+=$'\t'"$arg"
done
if command -v flock >/dev/null 2>&1; then
  {
    flock -x 9
    printf '%s\n' "$capture_line" >&9
  } 9>>"$capture"
else
  printf '%s\n' "$capture_line" >>"$capture"
fi

summary_json=""
reports_dir=""
ci_summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -n "$reports_dir" ]]; then
  ci_summary_json="$reports_dir/ci_phase1_resilience/ci_phase1_resilience_summary.json"
  resilience_summary_json="$reports_dir/ci_phase1_resilience/vpn_rc_resilience_path/vpn_rc_resilience_path_summary.json"
  mkdir -p "$(dirname "$resilience_summary_json")"
  cat >"$resilience_summary_json" <<'EOF_PHASE1_RESILIENCE_SUMMARY'
{
  "status": "pass",
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": true
}
EOF_PHASE1_RESILIENCE_SUMMARY
  mkdir -p "$(dirname "$ci_summary_json")"
  cat >"$ci_summary_json" <<EOF_PHASE1_CI_SUMMARY
{
  "steps": {
    "vpn_rc_resilience_path": {
      "artifacts": {
        "summary_json": "$resilience_summary_json"
      }
    }
  }
}
EOF_PHASE1_CI_SUMMARY
fi

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_PHASE1_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase1_resilience_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "artifacts": {
    "ci_summary_json": "$ci_summary_json"
  }
}
EOF_PHASE1_SUMMARY
fi

if [[ "${FASTLANE_FAIL_STAGE:-}" == "phase1" ]]; then
  exit "${FASTLANE_FAIL_RC:-42}"
fi
exit 0
EOF_FAKE_PHASE1
chmod +x "$FAKE_PHASE1"

FAKE_PHASE2="$TMP_DIR/fake_phase2.sh"
cat >"$FAKE_PHASE2" <<'EOF_FAKE_PHASE2'
#!/usr/bin/env bash
set -euo pipefail

capture="${FASTLANE_CAPTURE_FILE:?}"
capture_line="phase2"
for arg in "$@"; do
  capture_line+=$'\t'"$arg"
done
if command -v flock >/dev/null 2>&1; then
  {
    flock -x 9
    printf '%s\n' "$capture_line" >&9
  } 9>>"$capture"
else
  printf '%s\n' "$capture_line" >>"$capture"
fi

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

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_PHASE2_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase2_linux_prod_candidate_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_PHASE2_SUMMARY
fi

if [[ "${FASTLANE_FAIL_STAGE:-}" == "phase2" ]]; then
  exit "${FASTLANE_FAIL_RC:-43}"
fi
exit 0
EOF_FAKE_PHASE2
chmod +x "$FAKE_PHASE2"

FAKE_PHASE3="$TMP_DIR/fake_phase3.sh"
cat >"$FAKE_PHASE3" <<'EOF_FAKE_PHASE3'
#!/usr/bin/env bash
set -euo pipefail

capture="${FASTLANE_CAPTURE_FILE:?}"
capture_line="phase3"
for arg in "$@"; do
  capture_line+=$'\t'"$arg"
done
if command -v flock >/dev/null 2>&1; then
  {
    flock -x 9
    printf '%s\n' "$capture_line" >&9
  } 9>>"$capture"
else
  printf '%s\n' "$capture_line" >>"$capture"
fi

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

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_PHASE3_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase3_windows_client_beta_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_PHASE3_SUMMARY
fi

if [[ "${FASTLANE_FAIL_STAGE:-}" == "phase3" ]]; then
  exit "${FASTLANE_FAIL_RC:-44}"
fi
exit 0
EOF_FAKE_PHASE3
chmod +x "$FAKE_PHASE3"

FAKE_PHASE4="$TMP_DIR/fake_phase4.sh"
cat >"$FAKE_PHASE4" <<'EOF_FAKE_PHASE4'
#!/usr/bin/env bash
set -euo pipefail

capture="${FASTLANE_CAPTURE_FILE:?}"
capture_line="phase4"
for arg in "$@"; do
  capture_line+=$'\t'"$arg"
done
if command -v flock >/dev/null 2>&1; then
  {
    flock -x 9
    printf '%s\n' "$capture_line" >&9
  } 9>>"$capture"
else
  printf '%s\n' "$capture_line" >>"$capture"
fi

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

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_PHASE4_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase4_windows_full_parity_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0
}
EOF_PHASE4_SUMMARY
fi

if [[ "${FASTLANE_FAIL_STAGE:-}" == "phase4" ]]; then
  exit "${FASTLANE_FAIL_RC:-45}"
fi
exit 0
EOF_FAKE_PHASE4
chmod +x "$FAKE_PHASE4"

FAKE_ROADMAP="$TMP_DIR/fake_roadmap.sh"
cat >"$FAKE_ROADMAP" <<'EOF_FAKE_ROADMAP'
#!/usr/bin/env bash
set -euo pipefail

capture="${FASTLANE_CAPTURE_FILE:?}"
capture_line="roadmap"
for arg in "$@"; do
  capture_line+=$'\t'"$arg"
done
if command -v flock >/dev/null 2>&1; then
  {
    flock -x 9
    printf '%s\n' "$capture_line" >&9
  } 9>>"$capture"
else
  printf '%s\n' "$capture_line" >>"$capture"
fi

summary_json=""
report_md=""
phase1_semantics_mode="${FASTLANE_ROADMAP_PHASE1_SEMANTICS_MODE:-default}"
phase1_failure_kind="${FASTLANE_ROADMAP_PHASE1_FAILURE_KIND:-policy_no_go}"
phase1_policy_decision="${FASTLANE_ROADMAP_PHASE1_POLICY_DECISION:-NO-GO}"
phase1_fail_closed_no_go="${FASTLANE_ROADMAP_PHASE1_FAIL_CLOSED_NO_GO:-true}"
if [[ "$phase1_fail_closed_no_go" != "true" && "$phase1_fail_closed_no_go" != "false" ]]; then
  phase1_fail_closed_no_go="false"
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --phase1-resilience-handoff-summary-json)
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  case "$phase1_semantics_mode" in
    with_failure)
      jq -n \
        --arg failure_kind "$phase1_failure_kind" \
        --arg policy_decision "$phase1_policy_decision" \
        --argjson fail_closed_no_go "$phase1_fail_closed_no_go" \
        '{
          version: 1,
          status: "warn",
          rc: 0,
          vpn_track: {
            roadmap_stage: "READY_FOR_MACHINE_C_SMOKE",
            readiness_status: "NOT_READY",
            phase1_resilience_handoff: {
              available: true,
              status: "fail",
              failure: {
                kind: $failure_kind
              },
              policy_outcome: {
                decision: $policy_decision,
                fail_closed_no_go: $fail_closed_no_go
              }
            },
            non_blockchain_recommended_gate_id: "phase1_resilience_handoff_run_dry",
            non_blockchain_actionable_no_sudo_or_github: [
              {
                id: "phase1_resilience_handoff_run_dry",
                command: "bash ./scripts/phase1_resilience_handoff_run.sh --dry-run 1 --print-summary-json 1",
                reason: ("phase1_resilience_handoff status=fail failure.kind=" + $failure_kind + " policy_outcome.decision=" + $policy_decision)
              }
            ]
          },
          artifacts: {
            summary_json: "/tmp/fake-roadmap-summary.json",
            report_md: "/tmp/fake-roadmap-report.md"
          }
        }' >"$summary_json"
      ;;
    legacy_actionable)
      jq -n '
        {
          version: 1,
          status: "warn",
          rc: 0,
          vpn_track: {
            roadmap_stage: "READY_FOR_MACHINE_C_SMOKE",
            readiness_status: "NOT_READY",
            phase1_resilience_handoff: {
              available: true,
              status: "fail"
            },
            non_blockchain_recommended_gate_id: "phase1_resilience_handoff_run_dry",
            non_blockchain_actionable_no_sudo_or_github: [
              {
                id: "phase1_resilience_handoff_run_dry",
                command: "bash ./scripts/phase1_resilience_handoff_run.sh --dry-run 1 --print-summary-json 1",
                reason: "phase1_resilience_handoff status=fail"
              }
            ]
          },
          artifacts: {
            summary_json: "/tmp/fake-roadmap-summary.json",
            report_md: "/tmp/fake-roadmap-report.md"
          }
        }' >"$summary_json"
      ;;
    *)
      cat >"$summary_json" <<'EOF_ROADMAP_SUMMARY'
{
  "version": 1,
  "status": "warn",
  "rc": 0,
  "vpn_track": {
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "readiness_status": "NOT_READY"
  },
  "artifacts": {
    "summary_json": "/tmp/fake-roadmap-summary.json",
    "report_md": "/tmp/fake-roadmap-report.md"
  }
}
EOF_ROADMAP_SUMMARY
      ;;
  esac
fi

if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake roadmap report\n' >"$report_md"
fi

if [[ "${FASTLANE_FAIL_STAGE:-}" == "roadmap" ]]; then
  exit "${FASTLANE_FAIL_RC:-46}"
fi
exit 0
EOF_FAKE_ROADMAP
chmod +x "$FAKE_ROADMAP"

echo "[vpn-non-blockchain-fastlane] success path"
: >"$CAPTURE"
SUCCESS_SUMMARY="$TMP_DIR/success_wrapper.json"
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_success" \
  --summary-json "$SUCCESS_SUMMARY" \
  --runtime-fix-record-summary-json "$TMP_DIR/runtime_success.json" \
  --phase1-resilience-handoff-run-summary-json "$TMP_DIR/phase1_success.json" \
  --phase2-linux-prod-candidate-handoff-run-summary-json "$TMP_DIR/phase2_success.json" \
  --phase3-windows-client-beta-handoff-run-summary-json "$TMP_DIR/phase3_success.json" \
  --phase4-windows-full-parity-handoff-run-summary-json "$TMP_DIR/phase4_success.json" \
  --roadmap-progress-summary-json "$TMP_DIR/roadmap_success.json" \
  --roadmap-progress-report-md "$TMP_DIR/roadmap_success.md" \
  --print-summary-json 0 \
  --runtime-foo A \
  --phase1-alpha 1 \
  --phase2-beta 2 \
  --phase3-gamma 3 \
  --phase4-delta 4 \
  --roadmap-epsilon 5 >"$SUCCESS_LOG" 2>&1

runtime_line="$(grep '^runtime' "$CAPTURE" | tail -n 1 || true)"
phase1_line="$(grep '^phase1' "$CAPTURE" | tail -n 1 || true)"
phase2_line="$(grep '^phase2' "$CAPTURE" | tail -n 1 || true)"
phase3_line="$(grep '^phase3' "$CAPTURE" | tail -n 1 || true)"
phase4_line="$(grep '^phase4' "$CAPTURE" | tail -n 1 || true)"
roadmap_line="$(grep '^roadmap' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$runtime_line" || -z "$phase1_line" || -z "$phase2_line" || -z "$phase3_line" || -z "$phase4_line" || -z "$roadmap_line" ]]; then
  echo "missing expected stage invocations in success path"
  cat "$CAPTURE"
  cat "$SUCCESS_LOG"
  exit 1
fi

runtime_line_sp="${runtime_line//$'\t'/ }"
phase1_line_sp="${phase1_line//$'\t'/ }"
phase2_line_sp="${phase2_line//$'\t'/ }"
phase3_line_sp="${phase3_line//$'\t'/ }"
phase4_line_sp="${phase4_line//$'\t'/ }"
roadmap_line_sp="${roadmap_line//$'\t'/ }"
expected_success_resilience="$TMP_DIR/reports_success/ci_phase1_resilience/vpn_rc_resilience_path/vpn_rc_resilience_path_summary.json"

if [[ "$runtime_line_sp" != *"--summary-json $TMP_DIR/runtime_success.json"* || "$runtime_line_sp" != *"--print-summary-json 0"* || "$runtime_line_sp" != *"--foo A"* ]]; then
  echo "runtime forwarding mismatch"
  echo "$runtime_line_sp"
  exit 1
fi
if [[ "$phase1_line_sp" != *"--reports-dir $TMP_DIR/reports_success"* || "$phase1_line_sp" != *"--summary-json $TMP_DIR/phase1_success.json"* || "$phase1_line_sp" != *"--print-summary-json 0"* || "$phase1_line_sp" != *"--resume 1"* || "$phase1_line_sp" != *"--alpha 1"* ]]; then
  echo "phase1 forwarding mismatch"
  echo "$phase1_line_sp"
  exit 1
fi
if [[ "$phase1_line_sp" == *"--allow-policy-no-go"* ]]; then
  echo "phase1 default forwarding should not include --allow-policy-no-go when top-level flag is unset"
  echo "$phase1_line_sp"
  exit 1
fi
if [[ "$phase2_line_sp" != *"--summary-json $TMP_DIR/phase2_success.json"* || "$phase2_line_sp" != *"--resume 1"* || "$phase2_line_sp" != *"--beta 2"* ]]; then
  echo "phase2 forwarding mismatch"
  echo "$phase2_line_sp"
  exit 1
fi
if [[ "$phase3_line_sp" != *"--summary-json $TMP_DIR/phase3_success.json"* || "$phase3_line_sp" != *"--resume 1"* || "$phase3_line_sp" != *"--gamma 3"* ]]; then
  echo "phase3 forwarding mismatch"
  echo "$phase3_line_sp"
  exit 1
fi
if [[ "$phase4_line_sp" != *"--summary-json $TMP_DIR/phase4_success.json"* || "$phase4_line_sp" != *"--resume 1"* || "$phase4_line_sp" != *"--delta 4"* ]]; then
  echo "phase4 forwarding mismatch"
  echo "$phase4_line_sp"
  exit 1
fi
if [[ "$roadmap_line_sp" != *"--phase2-linux-prod-candidate-summary-json $TMP_DIR/phase2_success.json"* || "$roadmap_line_sp" != *"--phase3-windows-client-beta-summary-json $TMP_DIR/phase3_success.json"* || "$roadmap_line_sp" != *"--phase4-windows-full-parity-summary-json $TMP_DIR/phase4_success.json"* || "$roadmap_line_sp" != *"--vpn-rc-resilience-summary-json $expected_success_resilience"* || "$roadmap_line_sp" != *"--summary-json $TMP_DIR/roadmap_success.json"* || "$roadmap_line_sp" != *"--report-md $TMP_DIR/roadmap_success.md"* || "$roadmap_line_sp" != *"--print-report 0"* || "$roadmap_line_sp" != *"--print-summary-json 0"* || "$roadmap_line_sp" != *"--epsilon 5"* ]]; then
  echo "roadmap forwarding mismatch"
  echo "$roadmap_line_sp"
  exit 1
fi
if [[ "$roadmap_line_sp" != *"--phase1-resilience-handoff-summary-json $TMP_DIR/phase1_success.json"* ]]; then
  echo "roadmap forwarding missing phase1 handoff summary"
  echo "$roadmap_line_sp"
  exit 1
fi
if [[ "$roadmap_line_sp" == *"phase5"* || "$roadmap_line_sp" == *"cosmos"* ]]; then
  echo "forbidden chain references observed in roadmap invocation"
  echo "$roadmap_line_sp"
  exit 1
fi
if [[ "$roadmap_line_sp" == *"$ROOT_DIR/.easy-node-logs"* ]]; then
  echo "roadmap invocation should not depend on global .easy-node-logs summaries"
  echo "$roadmap_line_sp"
  exit 1
fi
if ! grep -q '\[vpn-non-blockchain-fastlane\] stage=runtime_fix_record status=running mode=parallel' "$SUCCESS_LOG"; then
  echo "expected parallel launch log line in success path"
  cat "$SUCCESS_LOG"
  exit 1
fi

if ! jq -e '
  .version == 1
  and .schema.id == "vpn_non_blockchain_fastlane_summary"
  and .status == "pass"
  and .rc == 0
  and .non_blockchain_only == true
  and .execution.mode == "parallel"
  and .execution.parallel_enabled == true
  and .inputs.dry_run == false
  and .inputs.parallel == true
  and .inputs.allow_policy_no_go == false
  and .steps.runtime_fix_record.status == "pass"
  and .steps.phase1_resilience_handoff_run.status == "pass"
  and .steps.phase2_linux_prod_candidate_handoff_run.status == "pass"
  and .steps.phase3_windows_client_beta_handoff_run.status == "pass"
  and .steps.phase4_windows_full_parity_handoff_run.status == "pass"
  and .steps.roadmap_progress_report.status == "pass"
  and .steps.runtime_fix_record.contract_valid == true
  and .steps.phase1_resilience_handoff_run.contract_valid == true
  and .steps.phase2_linux_prod_candidate_handoff_run.contract_valid == true
  and .steps.phase3_windows_client_beta_handoff_run.contract_valid == true
  and .steps.phase4_windows_full_parity_handoff_run.contract_valid == true
  and .steps.roadmap_progress_report.contract_valid == true
  and ((.steps | has("phase5_settlement_layer")) | not)
' "$SUCCESS_SUMMARY" >/dev/null; then
  echo "success summary contract mismatch"
  cat "$SUCCESS_SUMMARY"
  exit 1
fi

echo "[vpn-non-blockchain-fastlane] allow-policy-no-go top-level forwarding"
: >"$CAPTURE"
ALLOW_LOG="$TMP_DIR/allow_policy.log"
ALLOW_SUMMARY="$TMP_DIR/allow_policy_wrapper.json"
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_allow_policy" \
  --summary-json "$ALLOW_SUMMARY" \
  --allow-policy-no-go 1 \
  --print-summary-json 0 >"$ALLOW_LOG" 2>&1

allow_phase1_line_sp="$(grep '^phase1' "$CAPTURE" | tail -n 1 | tr '\t' ' ')"
if [[ -z "$allow_phase1_line_sp" || "$allow_phase1_line_sp" != *"--allow-policy-no-go 1"* ]]; then
  echo "allow-policy-no-go top-level forwarding missing on phase1 invocation"
  cat "$CAPTURE"
  cat "$ALLOW_LOG"
  exit 1
fi
if ! jq -e '.status == "pass" and .rc == 0 and .inputs.allow_policy_no_go == true' "$ALLOW_SUMMARY" >/dev/null; then
  echo "allow-policy-no-go top-level summary input mismatch"
  cat "$ALLOW_SUMMARY"
  exit 1
fi

echo "[vpn-non-blockchain-fastlane] allow-policy-no-go explicit phase1 override precedence"
: >"$CAPTURE"
ALLOW_OVERRIDE_LOG="$TMP_DIR/allow_policy_override.log"
ALLOW_OVERRIDE_SUMMARY="$TMP_DIR/allow_policy_override_wrapper.json"
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_allow_policy_override" \
  --summary-json "$ALLOW_OVERRIDE_SUMMARY" \
  --allow-policy-no-go 1 \
  --phase1-allow-policy-no-go 0 \
  --print-summary-json 0 >"$ALLOW_OVERRIDE_LOG" 2>&1

allow_override_phase1_line_sp="$(grep '^phase1' "$CAPTURE" | tail -n 1 | tr '\t' ' ')"
if [[ -z "$allow_override_phase1_line_sp" || "$allow_override_phase1_line_sp" != *"--allow-policy-no-go 0"* || "$allow_override_phase1_line_sp" == *"--allow-policy-no-go 1"* ]]; then
  echo "explicit phase1 allow-policy-no-go override precedence mismatch"
  cat "$CAPTURE"
  cat "$ALLOW_OVERRIDE_LOG"
  exit 1
fi
if ! jq -e '.status == "pass" and .rc == 0 and .inputs.allow_policy_no_go == true' "$ALLOW_OVERRIDE_SUMMARY" >/dev/null; then
  echo "allow-policy-no-go override summary input mismatch"
  cat "$ALLOW_OVERRIDE_SUMMARY"
  exit 1
fi

echo "[vpn-non-blockchain-fastlane] allow-policy-no-go explicit phase1 equals-form override precedence"
: >"$CAPTURE"
ALLOW_EQUALS_OVERRIDE_LOG="$TMP_DIR/allow_policy_equals_override.log"
ALLOW_EQUALS_OVERRIDE_SUMMARY="$TMP_DIR/allow_policy_equals_override_wrapper.json"
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_allow_policy_equals_override" \
  --summary-json "$ALLOW_EQUALS_OVERRIDE_SUMMARY" \
  --allow-policy-no-go 1 \
  --phase1-allow-policy-no-go=0 \
  --print-summary-json 0 >"$ALLOW_EQUALS_OVERRIDE_LOG" 2>&1

allow_equals_override_phase1_line_sp="$(grep '^phase1' "$CAPTURE" | tail -n 1 | tr '\t' ' ')"
if [[ -z "$allow_equals_override_phase1_line_sp" || "$allow_equals_override_phase1_line_sp" != *"--allow-policy-no-go=0"* || "$allow_equals_override_phase1_line_sp" == *"--allow-policy-no-go 1"* ]]; then
  echo "explicit phase1 equals-form allow-policy-no-go override precedence mismatch"
  cat "$CAPTURE"
  cat "$ALLOW_EQUALS_OVERRIDE_LOG"
  exit 1
fi
if ! jq -e '.status == "pass" and .rc == 0 and .inputs.allow_policy_no_go == true' "$ALLOW_EQUALS_OVERRIDE_SUMMARY" >/dev/null; then
  echo "allow-policy-no-go equals-form override summary input mismatch"
  cat "$ALLOW_EQUALS_OVERRIDE_SUMMARY"
  exit 1
fi

echo "[vpn-non-blockchain-fastlane] phase1 failure semantics propagation"
: >"$CAPTURE"
PHASE1_SEMANTICS_LOG="$TMP_DIR/phase1_semantics.log"
PHASE1_SEMANTICS_SUMMARY="$TMP_DIR/phase1_semantics_wrapper.json"
PHASE1_SEMANTICS_ROADMAP_SUMMARY="$TMP_DIR/roadmap_phase1_semantics.json"
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
FASTLANE_ROADMAP_PHASE1_SEMANTICS_MODE="with_failure" \
FASTLANE_ROADMAP_PHASE1_FAILURE_KIND="policy_no_go" \
FASTLANE_ROADMAP_PHASE1_POLICY_DECISION="NO-GO" \
FASTLANE_ROADMAP_PHASE1_FAIL_CLOSED_NO_GO="true" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_phase1_semantics" \
  --summary-json "$PHASE1_SEMANTICS_SUMMARY" \
  --roadmap-progress-summary-json "$PHASE1_SEMANTICS_ROADMAP_SUMMARY" \
  --roadmap-progress-report-md "$TMP_DIR/roadmap_phase1_semantics.md" \
  --print-summary-json 0 >"$PHASE1_SEMANTICS_LOG" 2>&1

if ! jq -e '
  .vpn_track.phase1_resilience_handoff.failure.kind == "policy_no_go"
  and .vpn_track.phase1_resilience_handoff.policy_outcome.decision == "NO-GO"
  and .vpn_track.phase1_resilience_handoff.policy_outcome.fail_closed_no_go == true
  and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | any(
      .id == "phase1_resilience_handoff_run_dry"
      and ((.reason // "") | contains("failure.kind=policy_no_go"))
      and ((.reason // "") | contains("policy_outcome.decision=NO-GO"))
  ))
' "$PHASE1_SEMANTICS_ROADMAP_SUMMARY" >/dev/null; then
  echo "phase1 failure semantics propagation mismatch in roadmap summary"
  cat "$PHASE1_SEMANTICS_ROADMAP_SUMMARY"
  cat "$PHASE1_SEMANTICS_LOG"
  exit 1
fi
if ! jq -e --arg roadmap_summary "$PHASE1_SEMANTICS_ROADMAP_SUMMARY" '
  .status == "pass"
  and .rc == 0
  and .steps.roadmap_progress_report.status == "pass"
  and .artifacts.roadmap_progress_summary_json == $roadmap_summary
' "$PHASE1_SEMANTICS_SUMMARY" >/dev/null; then
  echo "phase1 semantics wrapper summary contract mismatch"
  cat "$PHASE1_SEMANTICS_SUMMARY"
  cat "$PHASE1_SEMANTICS_LOG"
  exit 1
fi

echo "[vpn-non-blockchain-fastlane] phase1 actionable backward compatibility"
: >"$CAPTURE"
PHASE1_LEGACY_LOG="$TMP_DIR/phase1_legacy.log"
PHASE1_LEGACY_SUMMARY="$TMP_DIR/phase1_legacy_wrapper.json"
PHASE1_LEGACY_ROADMAP_SUMMARY="$TMP_DIR/roadmap_phase1_legacy.json"
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
FASTLANE_ROADMAP_PHASE1_SEMANTICS_MODE="legacy_actionable" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_phase1_legacy" \
  --summary-json "$PHASE1_LEGACY_SUMMARY" \
  --roadmap-progress-summary-json "$PHASE1_LEGACY_ROADMAP_SUMMARY" \
  --roadmap-progress-report-md "$TMP_DIR/roadmap_phase1_legacy.md" \
  --print-summary-json 0 >"$PHASE1_LEGACY_LOG" 2>&1

if ! jq -e '
  .vpn_track.phase1_resilience_handoff.available == true
  and .vpn_track.phase1_resilience_handoff.status == "fail"
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
  and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | any(
      .id == "phase1_resilience_handoff_run_dry"
      and ((.command // "") == "bash ./scripts/phase1_resilience_handoff_run.sh --dry-run 1 --print-summary-json 1")
      and ((.reason // "") | contains("status=fail"))
  ))
' "$PHASE1_LEGACY_ROADMAP_SUMMARY" >/dev/null; then
  echo "phase1 legacy actionable compatibility mismatch"
  cat "$PHASE1_LEGACY_ROADMAP_SUMMARY"
  cat "$PHASE1_LEGACY_LOG"
  exit 1
fi
if ! jq -e --arg roadmap_summary "$PHASE1_LEGACY_ROADMAP_SUMMARY" '
  .status == "pass"
  and .rc == 0
  and .steps.roadmap_progress_report.status == "pass"
  and .artifacts.roadmap_progress_summary_json == $roadmap_summary
' "$PHASE1_LEGACY_SUMMARY" >/dev/null; then
  echo "phase1 legacy wrapper summary contract mismatch"
  cat "$PHASE1_LEGACY_SUMMARY"
  cat "$PHASE1_LEGACY_LOG"
  exit 1
fi

echo "[vpn-non-blockchain-fastlane] run-local roadmap artifact isolation"
: >"$CAPTURE"
LOCAL_LOG="$TMP_DIR/local.log"
LOCAL_SUMMARY="$TMP_DIR/local_wrapper.json"
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_local" \
  --summary-json "$LOCAL_SUMMARY" \
  --print-summary-json 0 >"$LOCAL_LOG" 2>&1

local_roadmap_line="$(grep '^roadmap' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$local_roadmap_line" ]]; then
  echo "missing roadmap invocation in run-local isolation path"
  cat "$CAPTURE"
  cat "$LOCAL_LOG"
  exit 1
fi
local_roadmap_line_sp="${local_roadmap_line//$'\t'/ }"
expected_local_phase1="$TMP_DIR/reports_local/phase1_resilience_handoff_run_summary.json"
expected_local_phase2="$TMP_DIR/reports_local/phase2_linux_prod_candidate_handoff_run_summary.json"
expected_local_phase3="$TMP_DIR/reports_local/phase3_windows_client_beta_handoff_run_summary.json"
expected_local_phase4="$TMP_DIR/reports_local/phase4_windows_full_parity_handoff_run_summary.json"
expected_local_resilience="$TMP_DIR/reports_local/ci_phase1_resilience/vpn_rc_resilience_path/vpn_rc_resilience_path_summary.json"
if [[ "$local_roadmap_line_sp" != *"--phase1-resilience-handoff-summary-json $expected_local_phase1"* || "$local_roadmap_line_sp" != *"--phase2-linux-prod-candidate-summary-json $expected_local_phase2"* || "$local_roadmap_line_sp" != *"--phase3-windows-client-beta-summary-json $expected_local_phase3"* || "$local_roadmap_line_sp" != *"--phase4-windows-full-parity-summary-json $expected_local_phase4"* || "$local_roadmap_line_sp" != *"--vpn-rc-resilience-summary-json $expected_local_resilience"* ]]; then
  echo "run-local roadmap summary forwarding mismatch"
  echo "$local_roadmap_line_sp"
  exit 1
fi
if [[ "$local_roadmap_line_sp" == *"$ROOT_DIR/.easy-node-logs"* ]]; then
  echo "run-local roadmap invocation should not reference global .easy-node-logs paths"
  echo "$local_roadmap_line_sp"
  exit 1
fi
if ! jq -e \
  --arg p1 "$expected_local_phase1" \
  --arg p2 "$expected_local_phase2" \
  --arg p3 "$expected_local_phase3" \
  --arg p4 "$expected_local_phase4" \
  --arg pr "$expected_local_resilience" \
  '
  .artifacts.phase1_resilience_handoff_run_summary_json == $p1
  and .artifacts.phase2_linux_prod_candidate_handoff_run_summary_json == $p2
  and .artifacts.phase3_windows_client_beta_handoff_run_summary_json == $p3
  and .artifacts.phase4_windows_full_parity_handoff_run_summary_json == $p4
  and .artifacts.vpn_rc_resilience_summary_json == $pr
' "$LOCAL_SUMMARY" >/dev/null; then
  echo "run-local summary contract missing expected artifact paths"
  cat "$LOCAL_SUMMARY"
  exit 1
fi

echo "[vpn-non-blockchain-fastlane] dry-run forwarding"
: >"$CAPTURE"
DRY_SUMMARY="$TMP_DIR/dry_wrapper.json"
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --summary-json "$DRY_SUMMARY" \
  --runtime-fix-record-summary-json "$TMP_DIR/runtime_dry.json" \
  --phase1-resilience-handoff-run-summary-json "$TMP_DIR/phase1_dry.json" \
  --phase2-linux-prod-candidate-handoff-run-summary-json "$TMP_DIR/phase2_dry.json" \
  --phase3-windows-client-beta-handoff-run-summary-json "$TMP_DIR/phase3_dry.json" \
  --phase4-windows-full-parity-handoff-run-summary-json "$TMP_DIR/phase4_dry.json" \
  --roadmap-progress-summary-json "$TMP_DIR/roadmap_dry.json" \
  --roadmap-progress-report-md "$TMP_DIR/roadmap_dry.md" \
  --dry-run 1 \
  --print-summary-json 0 >"$DRY_LOG" 2>&1

runtime_line_sp="$(grep '^runtime' "$CAPTURE" | tail -n 1 | tr '\t' ' ')"
phase1_line_sp="$(grep '^phase1' "$CAPTURE" | tail -n 1 | tr '\t' ' ')"
phase2_line_sp="$(grep '^phase2' "$CAPTURE" | tail -n 1 | tr '\t' ' ')"
phase3_line_sp="$(grep '^phase3' "$CAPTURE" | tail -n 1 | tr '\t' ' ')"
phase4_line_sp="$(grep '^phase4' "$CAPTURE" | tail -n 1 | tr '\t' ' ')"
roadmap_line_sp="$(grep '^roadmap' "$CAPTURE" | tail -n 1 | tr '\t' ' ')"
if [[ "$phase1_line_sp" != *"--resume 1"* || "$phase1_line_sp" != *"--dry-run 1"* || "$phase2_line_sp" != *"--resume 1"* || "$phase2_line_sp" != *"--dry-run 1"* || "$phase3_line_sp" != *"--resume 1"* || "$phase3_line_sp" != *"--dry-run 1"* || "$phase4_line_sp" != *"--resume 1"* || "$phase4_line_sp" != *"--dry-run 1"* ]]; then
  echo "expected resume + dry-run forwarding to phase1/2/3/4 stages"
  cat "$CAPTURE"
  exit 1
fi
if [[ "$runtime_line_sp" == *"--dry-run 1"* || "$roadmap_line_sp" == *"--dry-run 1"* ]]; then
  echo "dry-run should not be forwarded to runtime/roadmap stages"
  cat "$CAPTURE"
  exit 1
fi
expected_dry_resilience="$TMP_DIR/reports_dry/ci_phase1_resilience/vpn_rc_resilience_path/vpn_rc_resilience_path_summary.json"
if [[ "$roadmap_line_sp" != *"--vpn-rc-resilience-summary-json $expected_dry_resilience"* ]]; then
  echo "dry-run roadmap invocation missing run-local resilience summary path"
  echo "$roadmap_line_sp"
  exit 1
fi
if [[ "$roadmap_line_sp" == *"$ROOT_DIR/.easy-node-logs"* ]]; then
  echo "dry-run roadmap invocation should not depend on global .easy-node-logs summaries"
  echo "$roadmap_line_sp"
  exit 1
fi
if ! jq -e '.status == "pass" and .rc == 0 and .inputs.dry_run == true' "$DRY_SUMMARY" >/dev/null; then
  echo "dry summary contract mismatch"
  cat "$DRY_SUMMARY"
  exit 1
fi
if ! jq -e '.execution.mode == "parallel" and .inputs.parallel == true' "$DRY_SUMMARY" >/dev/null; then
  echo "dry summary missing parallel mode contract fields"
  cat "$DRY_SUMMARY"
  exit 1
fi

echo "[vpn-non-blockchain-fastlane] sequential fallback mode"
: >"$CAPTURE"
SEQUENTIAL_SUMMARY="$TMP_DIR/sequential_wrapper.json"
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_sequential" \
  --summary-json "$SEQUENTIAL_SUMMARY" \
  --runtime-fix-record-summary-json "$TMP_DIR/runtime_sequential.json" \
  --phase1-resilience-handoff-run-summary-json "$TMP_DIR/phase1_sequential.json" \
  --phase2-linux-prod-candidate-handoff-run-summary-json "$TMP_DIR/phase2_sequential.json" \
  --phase3-windows-client-beta-handoff-run-summary-json "$TMP_DIR/phase3_sequential.json" \
  --phase4-windows-full-parity-handoff-run-summary-json "$TMP_DIR/phase4_sequential.json" \
  --roadmap-progress-summary-json "$TMP_DIR/roadmap_sequential.json" \
  --roadmap-progress-report-md "$TMP_DIR/roadmap_sequential.md" \
  --parallel 0 \
  --print-summary-json 0 >/tmp/integration_vpn_non_blockchain_fastlane_sequential.log 2>&1

if ! jq -e '.status == "pass" and .rc == 0 and .execution.mode == "sequential" and .execution.parallel_enabled == false and .inputs.parallel == false' "$SEQUENTIAL_SUMMARY" >/dev/null; then
  echo "sequential fallback summary contract mismatch"
  cat "$SEQUENTIAL_SUMMARY"
  cat /tmp/integration_vpn_non_blockchain_fastlane_sequential.log
  exit 1
fi
if grep -q 'mode=parallel' /tmp/integration_vpn_non_blockchain_fastlane_sequential.log; then
  echo "sequential mode should not emit parallel launch logs"
  cat /tmp/integration_vpn_non_blockchain_fastlane_sequential.log
  exit 1
fi

echo "[vpn-non-blockchain-fastlane] failure path continues later stages"
: >"$CAPTURE"
FAIL_SUMMARY="$TMP_DIR/fail_wrapper.json"
set +e
FASTLANE_CAPTURE_FILE="$CAPTURE" \
VPN_NON_BLOCKCHAIN_FASTLANE_RUNTIME_FIX_RECORD_SCRIPT="$FAKE_RUNTIME" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE1_RESILIENCE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE1" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE2_LINUX_PROD_CANDIDATE_HANDOFF_RUN_SCRIPT="$FAKE_PHASE2" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE3_WINDOWS_CLIENT_BETA_HANDOFF_RUN_SCRIPT="$FAKE_PHASE3" \
VPN_NON_BLOCKCHAIN_FASTLANE_PHASE4_WINDOWS_FULL_PARITY_HANDOFF_RUN_SCRIPT="$FAKE_PHASE4" \
VPN_NON_BLOCKCHAIN_FASTLANE_ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_ROADMAP" \
FASTLANE_FAIL_STAGE="phase2" \
FASTLANE_FAIL_RC=29 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_fail" \
  --summary-json "$FAIL_SUMMARY" \
  --runtime-fix-record-summary-json "$TMP_DIR/runtime_fail.json" \
  --phase1-resilience-handoff-run-summary-json "$TMP_DIR/phase1_fail.json" \
  --phase2-linux-prod-candidate-handoff-run-summary-json "$TMP_DIR/phase2_fail.json" \
  --phase3-windows-client-beta-handoff-run-summary-json "$TMP_DIR/phase3_fail.json" \
  --phase4-windows-full-parity-handoff-run-summary-json "$TMP_DIR/phase4_fail.json" \
  --roadmap-progress-summary-json "$TMP_DIR/roadmap_fail.json" \
  --roadmap-progress-report-md "$TMP_DIR/roadmap_fail.md" \
  --print-summary-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 29 ]]; then
  echo "expected wrapper rc=29 on phase2 failure, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! grep -q '^phase3' "$CAPTURE" || ! grep -q '^phase4' "$CAPTURE" || ! grep -q '^roadmap' "$CAPTURE"; then
  echo "expected later stages to run after phase2 failure"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 29
  and .steps.phase2_linux_prod_candidate_handoff_run.status == "fail"
  and .steps.phase2_linux_prod_candidate_handoff_run.rc == 29
  and .steps.phase3_windows_client_beta_handoff_run.status == "pass"
  and .steps.phase4_windows_full_parity_handoff_run.status == "pass"
  and .steps.roadmap_progress_report.status == "pass"
' "$FAIL_SUMMARY" >/dev/null; then
  echo "fail summary contract mismatch"
  cat "$FAIL_SUMMARY"
  exit 1
fi

echo "vpn non-blockchain fastlane integration check ok"
