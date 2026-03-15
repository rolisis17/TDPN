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
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

PASS_WG_VALIDATE="$TMP_DIR/wg_validate_ok.json"
PASS_WG_SOAK="$TMP_DIR/wg_soak_ok.json"
PASS_GATE="$TMP_DIR/prod_gate_ok.json"
PASS_RUN_REPORT="$TMP_DIR/prod_bundle_run_report_ok.json"

cat >"$PASS_WG_VALIDATE" <<'EOF_WG_VALIDATE_OK'
{
  "status": "ok",
  "failed_step": "",
  "client_inner_source": "udp",
  "strict_distinct": 1
}
EOF_WG_VALIDATE_OK

cat >"$PASS_WG_SOAK" <<'EOF_WG_SOAK_OK'
{
  "status": "ok",
  "rounds_failed": 0,
  "failure_classes": {},
  "selection_lines_total": 16,
  "selection_entry_operators": 2,
  "selection_exit_operators": 2,
  "selection_cross_operator_pairs": 3,
  "selection_diversity_failed": 0
}
EOF_WG_SOAK_OK

cat >"$PASS_GATE" <<EOF_GATE_OK
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
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "ok",
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_GATE_OK

cat >"$PASS_RUN_REPORT" <<EOF_RUN_REPORT_OK
{
  "status": "ok",
  "final_rc": 0,
  "bundle_dir": "$TMP_DIR/prod_bundle_dir",
  "gate_summary_json": "$PASS_GATE",
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "preflight": {
    "enabled": true,
    "status": "ok",
    "rc": 0
  },
  "bundle": {
    "status": "ok",
    "rc": 0,
    "tar_exists": true,
    "manifest_exists": true
  },
  "integrity_verify": {
    "enabled": true,
    "status": "ok",
    "rc": 0
  },
  "incident_snapshot": {
    "enabled_on_fail": true,
    "status": "skipped",
    "rc": -1,
    "bundle_dir": "",
    "bundle_tar": ""
  },
  "signoff": {
    "enabled": true,
    "rc": 0
  }
}
EOF_RUN_REPORT_OK

echo "[prod-gate-check] pass baseline"
./scripts/prod_gate_check.sh --gate-summary-json "$PASS_GATE" --show-json 0 >/tmp/integration_prod_gate_check_pass.log 2>&1
./scripts/prod_gate_check.sh --run-report-json "$PASS_RUN_REPORT" --show-json 0 >/tmp/integration_prod_gate_check_pass_run_report.log 2>&1

echo "[prod-gate-check] wg validate evidence checks"
BAD_VALIDATE_SOURCE="$TMP_DIR/wg_validate_bad_source.json"
cat >"$BAD_VALIDATE_SOURCE" <<'EOF_WG_VALIDATE_BAD_SOURCE'
{
  "status": "ok",
  "failed_step": "",
  "client_inner_source": "synthetic",
  "strict_distinct": 1
}
EOF_WG_VALIDATE_BAD_SOURCE
BAD_VALIDATE_SOURCE_GATE="$TMP_DIR/prod_gate_bad_validate_source.json"
cat >"$BAD_VALIDATE_SOURCE_GATE" <<EOF_GATE_BAD_VALIDATE_SOURCE
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
  "wg_validate_summary_json": "$BAD_VALIDATE_SOURCE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "ok",
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_GATE_BAD_VALIDATE_SOURCE
set +e
./scripts/prod_gate_check.sh \
  --gate-summary-json "$BAD_VALIDATE_SOURCE_GATE" \
  --require-wg-validate-udp-source 1 \
  --show-json 0 >/tmp/integration_prod_gate_check_validate_source_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc for non-udp validate source policy"
  cat /tmp/integration_prod_gate_check_validate_source_fail.log
  exit 1
fi
if ! rg -q 'does not show UDP inner source' /tmp/integration_prod_gate_check_validate_source_fail.log; then
  echo "expected non-udp validate source message not found"
  cat /tmp/integration_prod_gate_check_validate_source_fail.log
  exit 1
fi

BAD_VALIDATE_DISTINCT="$TMP_DIR/wg_validate_bad_distinct.json"
cat >"$BAD_VALIDATE_DISTINCT" <<'EOF_WG_VALIDATE_BAD_DISTINCT'
{
  "status": "ok",
  "failed_step": "",
  "client_inner_source": "udp",
  "strict_distinct": 0
}
EOF_WG_VALIDATE_BAD_DISTINCT
BAD_VALIDATE_DISTINCT_GATE="$TMP_DIR/prod_gate_bad_validate_distinct.json"
cat >"$BAD_VALIDATE_DISTINCT_GATE" <<EOF_GATE_BAD_VALIDATE_DISTINCT
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
  "wg_validate_summary_json": "$BAD_VALIDATE_DISTINCT",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "ok",
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_GATE_BAD_VALIDATE_DISTINCT
set +e
./scripts/prod_gate_check.sh \
  --gate-summary-json "$BAD_VALIDATE_DISTINCT_GATE" \
  --require-wg-validate-strict-distinct 1 \
  --show-json 0 >/tmp/integration_prod_gate_check_validate_distinct_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc for non-strict-distinct validate policy"
  cat /tmp/integration_prod_gate_check_validate_distinct_fail.log
  exit 1
fi
if ! rg -q 'does not show strict distinct mode enabled' /tmp/integration_prod_gate_check_validate_distinct_fail.log; then
  echo "expected strict-distinct validate message not found"
  cat /tmp/integration_prod_gate_check_validate_distinct_fail.log
  exit 1
fi

echo "[prod-gate-check] wg soak diversity floor checks"
BAD_SOAK_DIVERSITY="$TMP_DIR/wg_soak_bad_diversity.json"
cat >"$BAD_SOAK_DIVERSITY" <<'EOF_WG_SOAK_BAD_DIVERSITY'
{
  "status": "ok",
  "rounds_failed": 0,
  "failure_classes": {},
  "selection_lines_total": 5,
  "selection_entry_operators": 1,
  "selection_exit_operators": 1,
  "selection_cross_operator_pairs": 1,
  "selection_diversity_failed": 1
}
EOF_WG_SOAK_BAD_DIVERSITY
BAD_SOAK_DIVERSITY_GATE="$TMP_DIR/prod_gate_bad_soak_diversity.json"
cat >"$BAD_SOAK_DIVERSITY_GATE" <<EOF_GATE_BAD_SOAK_DIVERSITY
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
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$BAD_SOAK_DIVERSITY",
  "wg_soak_status": "ok",
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_GATE_BAD_SOAK_DIVERSITY
set +e
./scripts/prod_gate_check.sh \
  --gate-summary-json "$BAD_SOAK_DIVERSITY_GATE" \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 12 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 2 \
  --show-json 0 >/tmp/integration_prod_gate_check_soak_diversity_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc for soak diversity policy"
  cat /tmp/integration_prod_gate_check_soak_diversity_fail.log
  exit 1
fi
if ! rg -q 'selection_diversity_failed' /tmp/integration_prod_gate_check_soak_diversity_fail.log; then
  echo "expected soak diversity failure message not found"
  cat /tmp/integration_prod_gate_check_soak_diversity_fail.log
  exit 1
fi
if ! rg -q 'selection_lines_total below floor' /tmp/integration_prod_gate_check_soak_diversity_fail.log; then
  echo "expected soak diversity floor message not found"
  cat /tmp/integration_prod_gate_check_soak_diversity_fail.log
  exit 1
fi

./scripts/prod_gate_check.sh \
  --gate-summary-json "$PASS_GATE" \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 12 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 2 \
  --show-json 0 >/tmp/integration_prod_gate_check_diversity_pass.log 2>&1

echo "[prod-gate-check] run-report stage policy checks"
./scripts/prod_gate_check.sh \
  --run-report-json "$PASS_RUN_REPORT" \
  --require-preflight-ok 1 \
  --require-bundle-ok 1 \
  --require-integrity-ok 1 \
  --require-signoff-ok 1 \
  --show-json 0 >/tmp/integration_prod_gate_check_run_report_policy.log 2>&1

echo "[prod-gate-check] incident snapshot policy (fail path)"
INCIDENT_FAIL_RUN_REPORT="$TMP_DIR/prod_bundle_run_report_incident_fail.json"
cat >"$INCIDENT_FAIL_RUN_REPORT" <<EOF_RUN_REPORT_INCIDENT_FAIL
{
  "status": "fail",
  "final_rc": 1,
  "bundle_dir": "$TMP_DIR/prod_bundle_dir",
  "gate_summary_json": "$PASS_GATE",
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "incident_snapshot": {
    "enabled_on_fail": true,
    "status": "fail",
    "rc": 2,
    "bundle_dir": "",
    "bundle_tar": ""
  }
}
EOF_RUN_REPORT_INCIDENT_FAIL
set +e
./scripts/prod_gate_check.sh \
  --run-report-json "$INCIDENT_FAIL_RUN_REPORT" \
  --require-full-sequence 0 \
  --require-wg-validate-ok 0 \
  --require-wg-soak-ok 0 \
  --require-incident-snapshot-on-fail 1 \
  --show-json 0 >/tmp/integration_prod_gate_check_incident_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc for incident snapshot fail-on-failure policy"
  cat /tmp/integration_prod_gate_check_incident_fail.log
  exit 1
fi
if ! rg -q 'incident snapshot status is not ok' /tmp/integration_prod_gate_check_incident_fail.log; then
  echo "expected incident snapshot fail-on-failure message not found"
  cat /tmp/integration_prod_gate_check_incident_fail.log
  exit 1
fi

echo "[prod-gate-check] incident snapshot artifacts policy"
INCIDENT_ARTIFACTS_SUMMARY_JSON="$TMP_DIR/incident_bundle/incident_summary.json"
INCIDENT_ARTIFACTS_REPORT_MD="$TMP_DIR/incident_bundle/incident_report.md"
INCIDENT_ARTIFACTS_RUN_REPORT="$TMP_DIR/prod_bundle_run_report_incident_artifacts.json"
cat >"$INCIDENT_ARTIFACTS_RUN_REPORT" <<EOF_RUN_REPORT_INCIDENT_ARTIFACTS
{
  "status": "fail",
  "final_rc": 1,
  "bundle_dir": "$TMP_DIR/prod_bundle_dir",
  "gate_summary_json": "$PASS_GATE",
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "incident_snapshot": {
    "enabled_on_fail": true,
    "status": "ok",
    "rc": 0,
    "bundle_dir": "$TMP_DIR/missing_incident_bundle_dir",
    "bundle_tar": "$TMP_DIR/missing_incident_bundle.tar.gz",
    "summary_json": "$TMP_DIR/missing_incident_bundle_dir/incident_summary.json",
    "report_md": "$TMP_DIR/missing_incident_bundle_dir/incident_report.md"
  }
}
EOF_RUN_REPORT_INCIDENT_ARTIFACTS
set +e
./scripts/prod_gate_check.sh \
  --run-report-json "$INCIDENT_ARTIFACTS_RUN_REPORT" \
  --require-full-sequence 0 \
  --require-wg-validate-ok 0 \
  --require-wg-soak-ok 0 \
  --require-incident-snapshot-artifacts 1 \
  --show-json 0 >/tmp/integration_prod_gate_check_incident_artifacts_fail.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc for missing incident snapshot artifacts"
  cat /tmp/integration_prod_gate_check_incident_artifacts_fail.log
  exit 1
fi
if ! rg -q 'incident snapshot bundle_dir not found' /tmp/integration_prod_gate_check_incident_artifacts_fail.log; then
  echo "expected incident snapshot artifact failure message not found"
  cat /tmp/integration_prod_gate_check_incident_artifacts_fail.log
  exit 1
fi

INCIDENT_ARTIFACTS_DIR="$TMP_DIR/incident_bundle"
INCIDENT_ARTIFACTS_TAR="$TMP_DIR/incident_bundle.tar.gz"
INCIDENT_ARTIFACTS_ATTACH_DIR="$INCIDENT_ARTIFACTS_DIR/attachments"
INCIDENT_ARTIFACTS_ATTACH_MANIFEST="$INCIDENT_ARTIFACTS_ATTACH_DIR/manifest.tsv"
INCIDENT_ARTIFACTS_ATTACH_SKIPPED="$INCIDENT_ARTIFACTS_ATTACH_DIR/skipped.tsv"
mkdir -p "$INCIDENT_ARTIFACTS_DIR"
mkdir -p "$INCIDENT_ARTIFACTS_ATTACH_DIR"
printf 'incident snapshot tar placeholder\n' >"$INCIDENT_ARTIFACTS_TAR"
cat >"$INCIDENT_ARTIFACTS_SUMMARY_JSON" <<'EOF_INCIDENT_SUMMARY'
{"status":"ok","findings":[]}
EOF_INCIDENT_SUMMARY
cat >"$INCIDENT_ARTIFACTS_REPORT_MD" <<'EOF_INCIDENT_REPORT'
# Incident Snapshot Summary
EOF_INCIDENT_REPORT
printf 'attachments/01_runtime_doctor_before.json\tfile\t/tmp/runtime_doctor_before.json\n' >"$INCIDENT_ARTIFACTS_ATTACH_MANIFEST"
printf '/tmp/runtime_fix.json\tmissing\n' >"$INCIDENT_ARTIFACTS_ATTACH_SKIPPED"
INCIDENT_ARTIFACTS_PASS_RUN_REPORT="$TMP_DIR/prod_bundle_run_report_incident_artifacts_pass.json"
cat >"$INCIDENT_ARTIFACTS_PASS_RUN_REPORT" <<EOF_RUN_REPORT_INCIDENT_ARTIFACTS_PASS
{
  "status": "fail",
  "final_rc": 1,
  "bundle_dir": "$TMP_DIR/prod_bundle_dir",
  "gate_summary_json": "$PASS_GATE",
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "incident_snapshot": {
    "enabled_on_fail": true,
    "status": "ok",
    "rc": 0,
    "bundle_dir": "$INCIDENT_ARTIFACTS_DIR",
    "bundle_tar": "$INCIDENT_ARTIFACTS_TAR",
    "summary_json": "$INCIDENT_ARTIFACTS_SUMMARY_JSON",
    "report_md": "$INCIDENT_ARTIFACTS_REPORT_MD",
    "attachment_manifest": "$INCIDENT_ARTIFACTS_ATTACH_MANIFEST",
    "attachment_skipped": "$INCIDENT_ARTIFACTS_ATTACH_SKIPPED",
    "attachment_count": 1
  }
}
EOF_RUN_REPORT_INCIDENT_ARTIFACTS_PASS
./scripts/prod_gate_check.sh \
  --run-report-json "$INCIDENT_ARTIFACTS_PASS_RUN_REPORT" \
  --require-full-sequence 0 \
  --require-wg-validate-ok 0 \
  --require-wg-soak-ok 0 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --show-json 0 >/tmp/integration_prod_gate_check_incident_artifacts_pass.log 2>&1
if ! rg -q 'incident_handoff source_run_report=' /tmp/integration_prod_gate_check_incident_artifacts_pass.log; then
  echo "expected incident handoff summary/report line not found in prod-gate-check output"
  cat /tmp/integration_prod_gate_check_incident_artifacts_pass.log
  exit 1
fi
if ! rg -q "attachment_manifest=${INCIDENT_ARTIFACTS_ATTACH_MANIFEST}" /tmp/integration_prod_gate_check_incident_artifacts_pass.log; then
  echo "expected incident attachment manifest not surfaced in prod-gate-check output"
  cat /tmp/integration_prod_gate_check_incident_artifacts_pass.log
  exit 1
fi

echo "[prod-gate-check] run-report missing file"
set +e
./scripts/prod_gate_check.sh --run-report-json "$TMP_DIR/does_not_exist.json" >/tmp/integration_prod_gate_check_missing_run_report.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc for missing run report JSON"
  cat /tmp/integration_prod_gate_check_missing_run_report.log
  exit 1
fi
if ! rg -q 'run report JSON file not found' /tmp/integration_prod_gate_check_missing_run_report.log; then
  echo "expected run report missing-file message not found"
  cat /tmp/integration_prod_gate_check_missing_run_report.log
  exit 1
fi

echo "[prod-gate-check] fail on gate status"
FAIL_GATE_STATUS="$TMP_DIR/prod_gate_fail_status.json"
cat >"$FAIL_GATE_STATUS" <<EOF_GATE_FAIL_STATUS
{
  "status": "fail",
  "failed_step": "prod_wg_soak",
  "failed_rc": 1,
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "failed"
  },
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "fail",
  "wg_soak_rounds_failed": 2,
  "wg_soak_top_failure_class": "timeout",
  "wg_soak_top_failure_count": 2
}
EOF_GATE_FAIL_STATUS
set +e
./scripts/prod_gate_check.sh --gate-summary-json "$FAIL_GATE_STATUS" >/tmp/integration_prod_gate_check_fail_status.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc for failing gate status"
  cat /tmp/integration_prod_gate_check_fail_status.log
  exit 1
fi
if ! rg -q 'gate status is not ok' /tmp/integration_prod_gate_check_fail_status.log; then
  echo "expected gate-status failure message not found"
  cat /tmp/integration_prod_gate_check_fail_status.log
  exit 1
fi

echo "[prod-gate-check] full-sequence override"
SKIP_GATE="$TMP_DIR/prod_gate_skip_control_soak.json"
cat >"$SKIP_GATE" <<EOF_GATE_SKIP
{
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
  "steps": {
    "control_validate": "ok",
    "control_soak": "skipped",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  },
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "ok",
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_GATE_SKIP
set +e
./scripts/prod_gate_check.sh --gate-summary-json "$SKIP_GATE" --require-full-sequence 1 >/tmp/integration_prod_gate_check_skip_strict.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc when full sequence is required and a step is skipped"
  cat /tmp/integration_prod_gate_check_skip_strict.log
  exit 1
fi
./scripts/prod_gate_check.sh --gate-summary-json "$SKIP_GATE" --require-full-sequence 0 >/tmp/integration_prod_gate_check_skip_relaxed.log 2>&1

echo "[prod-gate-check] soak failed-round budget"
SOAK_FAILED_GATE="$TMP_DIR/prod_gate_soak_failed_rounds.json"
cat >"$SOAK_FAILED_GATE" <<EOF_GATE_SOAK_FAILED
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
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "ok",
  "wg_soak_rounds_failed": 2,
  "wg_soak_top_failure_class": "timeout",
  "wg_soak_top_failure_count": 2
}
EOF_GATE_SOAK_FAILED
set +e
./scripts/prod_gate_check.sh --gate-summary-json "$SOAK_FAILED_GATE" --max-wg-soak-failed-rounds 1 >/tmp/integration_prod_gate_check_soak_budget.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc when wg_soak_rounds_failed exceeds budget"
  cat /tmp/integration_prod_gate_check_soak_budget.log
  exit 1
fi
if ! rg -q 'wg_soak_rounds_failed exceeds limit' /tmp/integration_prod_gate_check_soak_budget.log; then
  echo "expected soak budget failure message not found"
  cat /tmp/integration_prod_gate_check_soak_budget.log
  exit 1
fi
./scripts/prod_gate_check.sh --gate-summary-json "$SOAK_FAILED_GATE" --max-wg-soak-failed-rounds 2 >/tmp/integration_prod_gate_check_soak_budget_ok.log 2>&1

echo "[prod-gate-check] easy_node forwarding"
FAKE_CHECK="$TMP_DIR/fake_prod_gate_check.sh"
CAPTURE="$TMP_DIR/easy_node_prod_gate_check_args.log"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
exit 0
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

CAPTURE_FILE="$CAPTURE" \
THREE_MACHINE_PROD_GATE_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/easy_node.sh prod-gate-check \
  --bundle-dir /tmp/prod_bundle \
  --run-report-json /tmp/prod_bundle/prod_bundle_run_report.json \
  --require-preflight-ok 1 \
  --require-bundle-ok 1 \
  --require-integrity-ok 1 \
  --require-signoff-ok 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 12 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 2 \
  --max-wg-soak-failed-rounds 1 \
  --show-json 1 >/tmp/integration_prod_gate_check_easy_node.log 2>&1

if ! rg -q -- '--bundle-dir /tmp/prod_bundle' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --bundle-dir"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--run-report-json /tmp/prod_bundle/prod_bundle_run_report.json' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --run-report-json"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-wg-soak-failed-rounds 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --max-wg-soak-failed-rounds"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-preflight-ok 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --require-preflight-ok"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-bundle-ok 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --require-bundle-ok"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-integrity-ok 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --require-integrity-ok"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-signoff-ok 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --require-signoff-ok"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --require-incident-snapshot-on-fail"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --require-incident-snapshot-artifacts"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-udp-source 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --require-wg-validate-udp-source"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-strict-distinct 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --require-wg-validate-strict-distinct"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-diversity-pass 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --require-wg-soak-diversity-pass"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-selection-lines 12' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --min-wg-soak-selection-lines"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-entry-operators 2' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --min-wg-soak-entry-operators"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-exit-operators 2' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --min-wg-soak-exit-operators"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-cross-operator-pairs 2' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --min-wg-soak-cross-operator-pairs"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --show-json"
  cat "$CAPTURE"
  exit 1
fi

echo "[prod-gate-check] easy_node prod-gate-signoff forwarding"
FAKE_VERIFY="$TMP_DIR/fake_prod_gate_verify.sh"
VERIFY_CAPTURE="$TMP_DIR/easy_node_prod_gate_signoff_verify_args.log"
CHECK_CAPTURE="$TMP_DIR/easy_node_prod_gate_signoff_check_args.log"
cat >"$FAKE_VERIFY" <<'EOF_FAKE_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${VERIFY_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_VERIFY
chmod +x "$FAKE_VERIFY"

cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CHECK_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_CHECK_SIGNOFF
chmod +x "$FAKE_CHECK"

VERIFY_CAPTURE_FILE="$VERIFY_CAPTURE" \
CHECK_CAPTURE_FILE="$CHECK_CAPTURE" \
THREE_MACHINE_PROD_GATE_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
THREE_MACHINE_PROD_GATE_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/easy_node.sh prod-gate-signoff \
  --run-report-json /tmp/prod_bundle/prod_bundle_run_report.json \
  --bundle-dir /tmp/prod_bundle \
  --bundle-tar /tmp/prod_bundle.tar.gz \
  --check-tar-sha256 1 \
  --check-manifest 1 \
  --show-integrity-details 1 \
  --require-full-sequence 1 \
  --require-wg-validate-ok 1 \
  --require-wg-soak-ok 1 \
  --require-preflight-ok 1 \
  --require-bundle-ok 1 \
  --require-integrity-ok 1 \
  --require-signoff-ok 1 \
  --require-incident-snapshot-on-fail 1 \
  --require-incident-snapshot-artifacts 1 \
  --require-wg-validate-udp-source 1 \
  --require-wg-validate-strict-distinct 1 \
  --require-wg-soak-diversity-pass 1 \
  --min-wg-soak-selection-lines 12 \
  --min-wg-soak-entry-operators 2 \
  --min-wg-soak-exit-operators 2 \
  --min-wg-soak-cross-operator-pairs 2 \
  --max-wg-soak-failed-rounds 0 \
  --show-json 1 >/tmp/integration_prod_gate_signoff_easy_node.log 2>&1

if ! rg -q -- '--run-report-json /tmp/prod_bundle/prod_bundle_run_report.json' "$VERIFY_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: verify missing --run-report-json"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-tar /tmp/prod_bundle.tar.gz' "$VERIFY_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: verify missing --bundle-tar"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-details 1' "$VERIFY_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: verify missing --show-details"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--run-report-json /tmp/prod_bundle/prod_bundle_run_report.json' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --run-report-json"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-ok 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-wg-soak-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-wg-soak-failed-rounds 0' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing max failed rounds"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-preflight-ok 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-preflight-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-bundle-ok 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-bundle-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-integrity-ok 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-integrity-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-signoff-ok 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-signoff-ok"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-on-fail 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-incident-snapshot-on-fail"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-incident-snapshot-artifacts 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-incident-snapshot-artifacts"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-udp-source 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-wg-validate-udp-source"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-validate-strict-distinct 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-wg-validate-strict-distinct"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-wg-soak-diversity-pass 1' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --require-wg-soak-diversity-pass"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-selection-lines 12' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --min-wg-soak-selection-lines"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-entry-operators 2' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --min-wg-soak-entry-operators"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-exit-operators 2' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --min-wg-soak-exit-operators"
  cat "$CHECK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--min-wg-soak-cross-operator-pairs 2' "$CHECK_CAPTURE"; then
  echo "easy_node prod-gate-signoff forwarding failed: check missing --min-wg-soak-cross-operator-pairs"
  cat "$CHECK_CAPTURE"
  exit 1
fi

echo "prod gate check integration ok"
