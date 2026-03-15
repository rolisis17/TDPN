#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

PASS_GATE="$TMP_DIR/prod_gate_ok.json"
PASS_RUN_REPORT="$TMP_DIR/prod_bundle_run_report_ok.json"
INCIDENT_BUNDLE_DIR="$TMP_DIR/incident_bundle"
INCIDENT_BUNDLE_TAR="$TMP_DIR/incident_bundle.tar.gz"
INCIDENT_SUMMARY_JSON="$TMP_DIR/incident_summary.json"
INCIDENT_REPORT_MD="$TMP_DIR/incident_report.md"
INCIDENT_ATTACH_DIR="$INCIDENT_BUNDLE_DIR/attachments"
INCIDENT_ATTACH_MANIFEST="$INCIDENT_ATTACH_DIR/manifest.tsv"
INCIDENT_ATTACH_SKIPPED="$INCIDENT_ATTACH_DIR/skipped.tsv"

mkdir -p "$INCIDENT_BUNDLE_DIR"
mkdir -p "$INCIDENT_ATTACH_DIR"
touch "$INCIDENT_BUNDLE_TAR"
cat >"$INCIDENT_SUMMARY_JSON" <<'EOF_INCIDENT_SUMMARY'
{
  "status": "ok"
}
EOF_INCIDENT_SUMMARY
cat >"$INCIDENT_REPORT_MD" <<'EOF_INCIDENT_REPORT'
# Incident Report
EOF_INCIDENT_REPORT
printf 'attachments/01_runtime_doctor_before.json\tfile\t/tmp/runtime_doctor_before.json\n' >"$INCIDENT_ATTACH_MANIFEST"
printf '/tmp/runtime_fix.json\tmissing\n' >"$INCIDENT_ATTACH_SKIPPED"

cat >"$PASS_GATE" <<'EOF_PASS_GATE'
{
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  },
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_status": "ok",
  "wg_soak_rounds_passed": 12,
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_PASS_GATE

cat >"$PASS_RUN_REPORT" <<EOF_PASS_RUN_REPORT
{
  "status": "ok",
  "final_rc": 0,
  "bundle_dir": "$TMP_DIR/prod_bundle_dir",
  "gate_summary_json": "$PASS_GATE",
  "preflight": {
    "enabled": true,
    "status": "ok",
    "rc": 0
  },
  "bundle": {
    "status": "ok",
    "rc": 0
  },
  "integrity_verify": {
    "enabled": true,
    "status": "ok",
    "rc": 0
  },
  "signoff": {
    "enabled": true,
    "rc": 0
  },
  "incident_snapshot": {
    "enabled_on_fail": true,
    "status": "skipped",
    "rc": -1,
    "bundle_dir": "",
    "bundle_tar": ""
  }
}
EOF_PASS_RUN_REPORT

echo "[prod-gate-slo-summary] pass baseline"
./scripts/prod_gate_slo_summary.sh \
  --run-report-json "$PASS_RUN_REPORT" \
  --require-preflight-ok 1 \
  --require-bundle-ok 1 \
  --require-integrity-ok 1 \
  --require-signoff-ok 1 \
  --fail-on-no-go 1 \
  --show-json 0 >/tmp/integration_prod_gate_slo_summary_pass.log 2>&1

if ! rg -q '\[prod-gate-slo\] decision=GO' /tmp/integration_prod_gate_slo_summary_pass.log; then
  echo "expected GO decision in pass baseline"
  cat /tmp/integration_prod_gate_slo_summary_pass.log
  exit 1
fi

echo "[prod-gate-slo-summary] no-go decision without fail-close"
FAIL_GATE_SOAK_BUDGET="$TMP_DIR/prod_gate_fail_soak_budget.json"
cat >"$FAIL_GATE_SOAK_BUDGET" <<'EOF_FAIL_GATE_SOAK'
{
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  },
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_status": "ok",
  "wg_soak_rounds_passed": 9,
  "wg_soak_rounds_failed": 2,
  "wg_soak_top_failure_class": "timeout",
  "wg_soak_top_failure_count": 2
}
EOF_FAIL_GATE_SOAK

./scripts/prod_gate_slo_summary.sh \
  --gate-summary-json "$FAIL_GATE_SOAK_BUDGET" \
  --max-wg-soak-failed-rounds 1 \
  --show-json 0 >/tmp/integration_prod_gate_slo_summary_no_go_relaxed.log 2>&1

if ! rg -q '\[prod-gate-slo\] decision=NO-GO' /tmp/integration_prod_gate_slo_summary_no_go_relaxed.log; then
  echo "expected NO-GO decision for soak budget failure"
  cat /tmp/integration_prod_gate_slo_summary_no_go_relaxed.log
  exit 1
fi
if ! rg -q 'wg_soak_rounds_failed exceeds limit' /tmp/integration_prod_gate_slo_summary_no_go_relaxed.log; then
  echo "expected soak-budget no-go reason not found"
  cat /tmp/integration_prod_gate_slo_summary_no_go_relaxed.log
  exit 1
fi

echo "[prod-gate-slo-summary] no-go fail-close"
set +e
./scripts/prod_gate_slo_summary.sh \
  --gate-summary-json "$FAIL_GATE_SOAK_BUDGET" \
  --max-wg-soak-failed-rounds 1 \
  --fail-on-no-go 1 >/tmp/integration_prod_gate_slo_summary_no_go_fail_close.log 2>&1
no_go_rc=$?
set -e
if [[ "$no_go_rc" -eq 0 ]]; then
  echo "expected non-zero rc when NO-GO and --fail-on-no-go=1"
  cat /tmp/integration_prod_gate_slo_summary_no_go_fail_close.log
  exit 1
fi
if ! rg -q '\[prod-gate-slo\] decision=NO-GO' /tmp/integration_prod_gate_slo_summary_no_go_fail_close.log; then
  echo "expected NO-GO decision in fail-close output"
  cat /tmp/integration_prod_gate_slo_summary_no_go_fail_close.log
  exit 1
fi

echo "[prod-gate-slo-summary] run-report preflight policy failure"
RUN_REPORT_PREFLIGHT_FAIL="$TMP_DIR/prod_bundle_run_report_preflight_fail.json"
cat >"$RUN_REPORT_PREFLIGHT_FAIL" <<EOF_PREFLIGHT_FAIL
{
  "status": "fail",
  "final_rc": 1,
  "bundle_dir": "$TMP_DIR/prod_bundle_dir",
  "gate_summary_json": "$PASS_GATE",
  "preflight": {
    "enabled": true,
    "status": "fail",
    "rc": 1
  },
  "bundle": {
    "status": "ok",
    "rc": 0
  },
  "integrity_verify": {
    "enabled": true,
    "status": "ok",
    "rc": 0
  },
  "signoff": {
    "enabled": true,
    "rc": 0
  }
}
EOF_PREFLIGHT_FAIL

set +e
./scripts/prod_gate_slo_summary.sh \
  --run-report-json "$RUN_REPORT_PREFLIGHT_FAIL" \
  --require-preflight-ok 1 \
  --fail-on-no-go 1 >/tmp/integration_prod_gate_slo_summary_preflight_fail.log 2>&1
preflight_fail_rc=$?
set -e
if [[ "$preflight_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when preflight policy is required and preflight failed"
  cat /tmp/integration_prod_gate_slo_summary_preflight_fail.log
  exit 1
fi
if ! rg -q 'preflight is not ok' /tmp/integration_prod_gate_slo_summary_preflight_fail.log; then
  echo "expected preflight-policy no-go reason not found"
  cat /tmp/integration_prod_gate_slo_summary_preflight_fail.log
  exit 1
fi

echo "[prod-gate-slo-summary] run-report incident snapshot policy failure"
RUN_REPORT_INCIDENT_FAIL="$TMP_DIR/prod_bundle_run_report_incident_fail.json"
cat >"$RUN_REPORT_INCIDENT_FAIL" <<EOF_INCIDENT_FAIL
{
  "status": "fail",
  "final_rc": 1,
  "bundle_dir": "$TMP_DIR/prod_bundle_dir",
  "gate_summary_json": "$PASS_GATE",
  "preflight": {
    "enabled": true,
    "status": "ok",
    "rc": 0
  },
  "bundle": {
    "status": "ok",
    "rc": 0
  },
  "integrity_verify": {
    "enabled": true,
    "status": "ok",
    "rc": 0
  },
  "signoff": {
    "enabled": true,
    "rc": 0
  },
  "incident_snapshot": {
    "enabled_on_fail": false,
    "status": "skipped",
    "rc": -1,
    "bundle_dir": "",
    "bundle_tar": ""
  }
}
EOF_INCIDENT_FAIL

set +e
./scripts/prod_gate_slo_summary.sh \
  --run-report-json "$RUN_REPORT_INCIDENT_FAIL" \
  --require-incident-snapshot-on-fail 1 \
  --fail-on-no-go 1 >/tmp/integration_prod_gate_slo_summary_incident_fail.log 2>&1
incident_fail_rc=$?
set -e
if [[ "$incident_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when incident snapshot policy is required and incident snapshot did not run"
  cat /tmp/integration_prod_gate_slo_summary_incident_fail.log
  exit 1
fi
if ! rg -q 'incident snapshot is not enabled on fail' /tmp/integration_prod_gate_slo_summary_incident_fail.log; then
  echo "expected incident-snapshot policy no-go reason not found"
  cat /tmp/integration_prod_gate_slo_summary_incident_fail.log
  exit 1
fi

echo "[prod-gate-slo-summary] incident snapshot artifact validation"
RUN_REPORT_INCIDENT_ARTIFACTS="$TMP_DIR/prod_bundle_run_report_incident_artifacts.json"
cat >"$RUN_REPORT_INCIDENT_ARTIFACTS" <<EOF_INCIDENT_ARTIFACTS
{
  "status": "fail",
  "final_rc": 1,
  "bundle_dir": "$TMP_DIR/prod_bundle_dir",
  "gate_summary_json": "$PASS_GATE",
  "preflight": {
    "enabled": true,
    "status": "ok",
    "rc": 0
  },
  "bundle": {
    "status": "ok",
    "rc": 0
  },
  "integrity_verify": {
    "enabled": true,
    "status": "ok",
    "rc": 0
  },
  "signoff": {
    "enabled": true,
    "rc": 0
  },
  "incident_snapshot": {
    "enabled_on_fail": true,
    "status": "ok",
    "rc": 0,
    "bundle_dir": "$INCIDENT_BUNDLE_DIR",
    "bundle_tar": "$INCIDENT_BUNDLE_TAR",
    "summary_json": "$INCIDENT_SUMMARY_JSON",
    "report_md": "$INCIDENT_REPORT_MD",
    "attachment_manifest": "$INCIDENT_ATTACH_MANIFEST",
    "attachment_skipped": "$INCIDENT_ATTACH_SKIPPED",
    "attachment_count": 1
  }
}
EOF_INCIDENT_ARTIFACTS

./scripts/prod_gate_slo_summary.sh \
  --run-report-json "$RUN_REPORT_INCIDENT_ARTIFACTS" \
  --require-incident-snapshot-artifacts 1 \
  --fail-on-no-go 1 >/tmp/integration_prod_gate_slo_summary_incident_artifacts_pass.log 2>&1

if ! rg -q '\[prod-gate-slo\] incident_handoff source_summary_json=' /tmp/integration_prod_gate_slo_summary_incident_artifacts_pass.log; then
  echo "expected normalized incident handoff line not found"
  cat /tmp/integration_prod_gate_slo_summary_incident_artifacts_pass.log
  exit 1
fi
if ! rg -q "attachment_manifest=${INCIDENT_ATTACH_MANIFEST}" /tmp/integration_prod_gate_slo_summary_incident_artifacts_pass.log; then
  echo "expected incident attachment manifest not surfaced in prod-gate-slo-summary output"
  cat /tmp/integration_prod_gate_slo_summary_incident_artifacts_pass.log
  exit 1
fi

INVALID_INCIDENT_SUMMARY_JSON="$TMP_DIR/incident_summary_invalid.json"
printf '%s\n' '{invalid-json' >"$INVALID_INCIDENT_SUMMARY_JSON"
RUN_REPORT_INCIDENT_ARTIFACTS_INVALID="$TMP_DIR/prod_bundle_run_report_incident_artifacts_invalid.json"
cat >"$RUN_REPORT_INCIDENT_ARTIFACTS_INVALID" <<EOF_INCIDENT_ARTIFACTS_INVALID
{
  "status": "fail",
  "final_rc": 1,
  "bundle_dir": "$TMP_DIR/prod_bundle_dir",
  "gate_summary_json": "$PASS_GATE",
  "incident_snapshot": {
    "enabled_on_fail": true,
    "status": "ok",
    "rc": 0,
    "bundle_dir": "$INCIDENT_BUNDLE_DIR",
    "bundle_tar": "$INCIDENT_BUNDLE_TAR",
    "summary_json": "$INVALID_INCIDENT_SUMMARY_JSON",
    "report_md": "$INCIDENT_REPORT_MD"
  }
}
EOF_INCIDENT_ARTIFACTS_INVALID

set +e
./scripts/prod_gate_slo_summary.sh \
  --run-report-json "$RUN_REPORT_INCIDENT_ARTIFACTS_INVALID" \
  --require-incident-snapshot-artifacts 1 \
  --fail-on-no-go 1 >/tmp/integration_prod_gate_slo_summary_incident_artifacts_fail.log 2>&1
incident_artifacts_fail_rc=$?
set -e
if [[ "$incident_artifacts_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when incident summary JSON is invalid"
  cat /tmp/integration_prod_gate_slo_summary_incident_artifacts_fail.log
  exit 1
fi
if ! rg -q 'incident snapshot summary_json is invalid JSON' /tmp/integration_prod_gate_slo_summary_incident_artifacts_fail.log; then
  echo "expected invalid incident summary JSON reason not found"
  cat /tmp/integration_prod_gate_slo_summary_incident_artifacts_fail.log
  exit 1
fi

echo "[prod-gate-slo-summary] wg evidence policy checks"
WG_VALIDATE_SUMMARY="$TMP_DIR/wg_validate_summary.json"
WG_SOAK_SUMMARY="$TMP_DIR/wg_soak_summary.json"
cat >"$WG_VALIDATE_SUMMARY" <<'EOF_WG_VALIDATE'
{
  "client_inner_source": "udp",
  "strict_distinct": true
}
EOF_WG_VALIDATE
cat >"$WG_SOAK_SUMMARY" <<'EOF_WG_SOAK'
{
  "selection_lines_total": 8,
  "selection_entry_operators": 2,
  "selection_exit_operators": 2,
  "selection_cross_operator_pairs": 1,
  "selection_diversity_failed": 0
}
EOF_WG_SOAK

./scripts/prod_gate_slo_summary.sh \
  --gate-summary-json "$PASS_GATE" \
  --wg-validate-summary-json "$WG_VALIDATE_SUMMARY" \
  --wg-soak-summary-json "$WG_SOAK_SUMMARY" \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 8 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 1 \
  --show-json 0 >/tmp/integration_prod_gate_slo_summary_wg_policy_pass.log 2>&1

if ! rg -q '\[prod-gate-slo\] decision=GO' /tmp/integration_prod_gate_slo_summary_wg_policy_pass.log; then
  echo "expected GO with WG evidence policy satisfied"
  cat /tmp/integration_prod_gate_slo_summary_wg_policy_pass.log
  exit 1
fi

set +e
./scripts/prod_gate_slo_summary.sh \
  --gate-summary-json "$PASS_GATE" \
  --wg-validate-summary-json "$WG_VALIDATE_SUMMARY" \
  --wg-soak-summary-json "$WG_SOAK_SUMMARY" \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 9 \
  --fail-on-no-go 1 >/tmp/integration_prod_gate_slo_summary_wg_policy_fail.log 2>&1
wg_policy_fail_rc=$?
set -e
if [[ "$wg_policy_fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when WG soak selection floor is not met"
  cat /tmp/integration_prod_gate_slo_summary_wg_policy_fail.log
  exit 1
fi
if ! rg -q 'selection_lines_total below floor' /tmp/integration_prod_gate_slo_summary_wg_policy_fail.log; then
  echo "expected WG soak selection floor no-go reason not found"
  cat /tmp/integration_prod_gate_slo_summary_wg_policy_fail.log
  exit 1
fi

echo "[prod-gate-slo-summary] easy_node forwarding"
FAKE_SLO_SUMMARY="$TMP_DIR/fake_prod_gate_slo_summary.sh"
CAPTURE="$TMP_DIR/prod_gate_slo_summary_args.log"
cat >"$FAKE_SLO_SUMMARY" <<'EOF_FAKE_SLO'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
exit 0
EOF_FAKE_SLO
chmod +x "$FAKE_SLO_SUMMARY"

CAPTURE_FILE="$CAPTURE" \
PROD_GATE_SLO_SUMMARY_SCRIPT="$FAKE_SLO_SUMMARY" \
./scripts/easy_node.sh prod-gate-slo-summary \
  --run-report-json /tmp/prod_bundle/prod_bundle_run_report.json \
  --require-full-sequence 1 \
  --require-wg-validate-ok 1 \
  --require-wg-soak-ok 1 \
  --max-wg-soak-failed-rounds 0 \
  --require-preflight-ok 1 \
  --require-bundle-ok 1 \
  --require-integrity-ok 1 \
  --require-signoff-ok 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 8 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 1 \
  --fail-on-no-go 1 \
  --show-json 1 >/tmp/integration_prod_gate_slo_summary_easy_node.log 2>&1

if ! rg -q -- '--run-report-json /tmp/prod_bundle/prod_bundle_run_report.json' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --run-report-json"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-signoff-ok 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --require-signoff-ok"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --require-incident-snapshot-on-fail"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --require-incident-snapshot-artifacts"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-udp-source 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --require-wg-validate-udp-source"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-strict-distinct 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --require-wg-validate-strict-distinct"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-diversity-pass 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --require-wg-soak-diversity-pass"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-selection-lines 8' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --min-wg-soak-selection-lines"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-entry-operators 2' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --min-wg-soak-entry-operators"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-exit-operators 2' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --min-wg-soak-exit-operators"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-cross-operator-pairs 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --min-wg-soak-cross-operator-pairs"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--fail-on-no-go 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --fail-on-no-go"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$CAPTURE"; then
  echo "easy_node prod-gate-slo-summary forwarding failed: missing --show-json"
  cat "$CAPTURE"
  exit 1
fi

echo "prod gate slo summary integration ok"
