#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg chmod mkdir touch; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.log"
SINGLE_MACHINE_SUMMARY_JSON="$TMP_DIR/single_machine_prod_readiness_latest.json"
ROADMAP_PROGRESS_TEST_LOGS_ROOT="$TMP_DIR/roadmap_progress_logs"
mkdir -p "$ROADMAP_PROGRESS_TEST_LOGS_ROOT"
export ROADMAP_PROGRESS_LOGS_ROOT="$ROADMAP_PROGRESS_TEST_LOGS_ROOT"

ROADMAP_PROGRESS_MISSING_PHASE0_SUMMARY_JSON="$TMP_DIR/missing_phase0_summary.json"
ROADMAP_PROGRESS_MISSING_PHASE1_SUMMARY_JSON="$TMP_DIR/missing_phase1_summary.json"
ROADMAP_PROGRESS_MISSING_PHASE2_SUMMARY_JSON="$TMP_DIR/missing_phase2_summary.json"
ROADMAP_PROGRESS_MISSING_PHASE3_SUMMARY_JSON="$TMP_DIR/missing_phase3_summary.json"
ROADMAP_PROGRESS_MISSING_PHASE4_SUMMARY_JSON="$TMP_DIR/missing_phase4_summary.json"
ROADMAP_PROGRESS_MISSING_PHASE5_SUMMARY_JSON="$TMP_DIR/missing_phase5_summary.json"
ROADMAP_PROGRESS_MISSING_PHASE6_SUMMARY_JSON="$TMP_DIR/missing_phase6_summary.json"

run_roadmap_progress_report() {
  ./scripts/roadmap_progress_report.sh \
    --phase0-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE0_SUMMARY_JSON" \
    --phase1-resilience-handoff-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE1_SUMMARY_JSON" \
    --phase2-linux-prod-candidate-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE2_SUMMARY_JSON" \
    --phase3-windows-client-beta-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE3_SUMMARY_JSON" \
    --phase4-windows-full-parity-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE4_SUMMARY_JSON" \
    --phase5-settlement-layer-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE5_SUMMARY_JSON" \
    --phase6-cosmos-l1-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE6_SUMMARY_JSON" \
    "$@"
}

FAKE_MANUAL="$TMP_DIR/fake_manual_validation_report.sh"
cat >"$FAKE_MANUAL" <<'EOF_FAKE_MANUAL'
#!/usr/bin/env bash
set -euo pipefail
printf 'manual-validation-report %s\n' "$*" >>"${FAKE_ROADMAP_CAPTURE_FILE:?}"
summary_json=""
report_md=""
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
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" || -z "$report_md" ]]; then
  echo "missing summary/report args" >&2
  exit 1
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

cat >"$summary_json" <<'EOF_SUMMARY'
{
  "version": 1,
  "checks": [
    {
      "check_id": "runtime_hygiene",
      "label": "Runtime hygiene",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh runtime-doctor --show-json 1"
    },
    {
      "check_id": "wg_only_stack_selftest",
      "label": "WG-only stack selftest",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh wg-only-stack-selftest-record --strict-beta 1 --print-summary-json 1"
    },
    {
      "check_id": "three_machine_docker_readiness",
      "label": "One-host docker 3-machine rehearsal",
      "status": "skip",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    {
      "check_id": "real_wg_privileged_matrix",
      "label": "Linux root real-WG privileged matrix",
      "status": "skip",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    },
    {
      "check_id": "machine_c_vpn_smoke",
      "label": "Machine C VPN smoke test",
      "status": "pending",
      "command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    {
      "check_id": "three_machine_prod_signoff",
      "label": "True 3-machine production signoff",
      "status": "pending",
      "command": "sudo ./scripts/easy_node.sh three-machine-prod-signoff --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --pre-real-host-readiness 1 --runtime-fix 1 --print-summary-json 1"
    }
  ],
  "summary": {
    "total_checks": 6,
    "pass_checks": 2,
    "warn_checks": 0,
    "fail_checks": 0,
    "pending_checks": 2,
    "next_action_check_id": "machine_c_vpn_smoke",
    "next_action_label": "Machine C VPN smoke test",
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country",
    "blocking_check_ids": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
    "optional_check_ids": ["three_machine_docker_readiness", "real_wg_privileged_matrix"],
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "pre_machine_c_gate": {
      "ready": true,
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    "real_host_gate": {
      "ready": false,
      "blockers": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    "profile_default_gate": {
      "status": "pending",
      "next_command": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1"
    },
    "docker_rehearsal_gate": {
      "status": "skip",
      "next_command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "skip",
      "next_command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY",
    "ready": false
  }
}
EOF_SUMMARY

printf '# fake manual validation report\n' >"$report_md"
EOF_FAKE_MANUAL
chmod +x "$FAKE_MANUAL"

FAKE_MANUAL_INVALID="$TMP_DIR/fake_manual_validation_report_invalid.sh"
cat >"$FAKE_MANUAL_INVALID" <<'EOF_FAKE_MANUAL_INVALID'
#!/usr/bin/env bash
set -euo pipefail
printf 'manual-validation-report-invalid %s\n' "$*" >>"${FAKE_ROADMAP_CAPTURE_FILE:?}"
summary_json=""
report_md=""
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
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" || -z "$report_md" ]]; then
  echo "missing summary/report args" >&2
  exit 1
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

printf '{"version":1,' >"$summary_json"
printf '# fake invalid manual validation report\n' >"$report_md"
exit 1
EOF_FAKE_MANUAL_INVALID
chmod +x "$FAKE_MANUAL_INVALID"

FAKE_MANUAL_PARTIAL="$TMP_DIR/fake_manual_validation_report_partial.sh"
cat >"$FAKE_MANUAL_PARTIAL" <<'EOF_FAKE_MANUAL_PARTIAL'
#!/usr/bin/env bash
set -euo pipefail
printf 'manual-validation-report-partial %s\n' "$*" >>"${FAKE_ROADMAP_CAPTURE_FILE:?}"
summary_json=""
report_md=""
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
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" || -z "$report_md" ]]; then
  echo "missing summary/report args" >&2
  exit 1
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

cat >"$summary_json" <<'EOF_SUMMARY_PARTIAL'
{"version":1,"summary":{"next_action_check_id":"machine_c_vpn_smoke"}}
EOF_SUMMARY_PARTIAL
printf '# fake partial manual validation report\n' >"$report_md"
exit 1
EOF_FAKE_MANUAL_PARTIAL
chmod +x "$FAKE_MANUAL_PARTIAL"

FAKE_SINGLE="$TMP_DIR/fake_single_machine_prod_readiness.sh"
cat >"$FAKE_SINGLE" <<'EOF_FAKE_SINGLE'
#!/usr/bin/env bash
set -euo pipefail
printf 'single-machine-prod-readiness %s\n' "$*" >>"${FAKE_ROADMAP_CAPTURE_FILE:?}"
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
  if [[ -n "${FAKE_SINGLE_SUMMARY_PAYLOAD:-}" ]]; then
    printf '%s\n' "${FAKE_SINGLE_SUMMARY_PAYLOAD}" >"$summary_json"
  else
    printf '{"status":"warn"}\n' >"$summary_json"
  fi
fi
if [[ "${FAKE_SINGLE_TRANSIENT_LOG:-0}" == "1" ]]; then
  echo 'failed to do request: Head "https://registry-1.docker.io/v2/library/alpine/manifests/3.20": dial tcp: lookup registry-1.docker.io on 127.0.0.53:53: server misbehaving' >&2
fi
if [[ "${FAKE_SINGLE_SLEEP_SEC:-0}" =~ ^[0-9]+$ ]] && [[ "${FAKE_SINGLE_SLEEP_SEC:-0}" -gt 0 ]]; then
  sleep "${FAKE_SINGLE_SLEEP_SEC}"
fi
if [[ "${FAKE_SINGLE_FAIL:-0}" == "1" ]]; then
  exit 1
fi
exit 0
EOF_FAKE_SINGLE
chmod +x "$FAKE_SINGLE"

echo "[roadmap-progress-report] success path"
SUMMARY_JSON="$TMP_DIR/roadmap_progress_summary.json"
REPORT_MD="$TMP_DIR/roadmap_progress_report.md"
PHASE5_SETTLEMENT_LAYER_SUMMARY_JSON="$TMP_DIR/phase5_settlement_layer_handoff_check_summary.json"
PHASE6_COSMOS_L1_SUMMARY_JSON="$TMP_DIR/phase6_cosmos_l1_build_testnet_handoff_check_summary.json"
PHASE0_SUMMARY_JSON="$TMP_DIR/ci_phase0_summary.json"
cat >"$PHASE5_SETTLEMENT_LAYER_SUMMARY_JSON" <<'EOF_PHASE5_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    }
  }
}
EOF_PHASE5_SUMMARY
cat >"$PHASE6_COSMOS_L1_SUMMARY_JSON" <<'EOF_PHASE6_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase6_cosmos_l1_build_testnet_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "run_pipeline_ok": true,
    "module_tx_surface_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true
  },
  "signals": {
    "module_tx_surface_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true
  },
  "artifacts": {
    "summary_json": "phase6_cosmos_l1_build_testnet_handoff_check_summary.json"
  }
}
EOF_PHASE6_SUMMARY
cat >"$PHASE0_SUMMARY_JSON" <<'EOF_PHASE0_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "ci_phase0_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "dry_run": false,
  "steps": {
    "launcher_wiring": {"status": "pass", "rc": 0},
    "launcher_runtime": {"status": "pass", "rc": 0},
    "prompt_budget": {"status": "pass", "rc": 0},
    "config_v1": {"status": "pass", "rc": 0},
    "local_control_api": {"status": "pass", "rc": 0}
  },
  "summary": {
    "contract_ok": true,
    "all_required_steps_ok": true
  }
}
EOF_PHASE0_SUMMARY
FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL" \
ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
run_roadmap_progress_report \
  --refresh-manual-validation 1 \
  --refresh-single-machine-readiness 0 \
  --phase0-summary-json "$PHASE0_SUMMARY_JSON" \
  --phase5-settlement-layer-summary-json "$PHASE5_SETTLEMENT_LAYER_SUMMARY_JSON" \
  --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_ok.log 2>&1

if ! rg -q '\[roadmap-progress-report\] status=warn rc=0' /tmp/integration_roadmap_progress_report_ok.log; then
  echo "expected warn status in success path"
  cat /tmp/integration_roadmap_progress_report_ok.log
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "expected roadmap progress artifacts missing"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .vpn_track.readiness_status == "NOT_READY"
  and .vpn_track.roadmap_stage == "READY_FOR_MACHINE_C_SMOKE"
  and .vpn_track.vpn_rc_done_for_phase == true
  and .vpn_track.phase0_product_surface.available == true
  and .vpn_track.phase0_product_surface.status == "pass"
  and .vpn_track.phase0_product_surface.contract_ok == true
  and .vpn_track.phase0_product_surface.all_required_steps_ok == true
  and .vpn_track.phase0_product_surface.launcher_wiring_ok == true
  and .vpn_track.phase0_product_surface.launcher_runtime_ok == true
  and .vpn_track.phase0_product_surface.prompt_budget_ok == true
  and .vpn_track.phase0_product_surface.config_v1_ok == true
  and .vpn_track.phase0_product_surface.local_control_api_ok == true
  and (.vpn_track.pending_real_host_checks | length) == 2
  and .vpn_track.pending_real_host_checks[0].check_id == "machine_c_vpn_smoke"
  and .vpn_track.pending_real_host_checks[1].check_id == "three_machine_prod_signoff"
  and .blockchain_track.status == "parallel-cosmos-build"
  and .blockchain_track.policy == "canonical execution plan: docs/full-execution-plan-2026-2027.md"
  and (.blockchain_track.recommendation | contains("Cosmos-first blockchain track"))
  and (.next_actions | length) >= 1
  and (.next_actions[0].id // "") == "machine_c_vpn_smoke"
  and (.next_actions[1].id // "") == "profile_default_gate"
  and (((.next_actions // []) | any(.id == "three_machine_docker_readiness")) | not)
  and (((.next_actions // []) | any(.id == "real_wg_privileged_matrix")) | not)
  and .refresh.manual_validation_report.status == "pass"
  and .refresh.manual_validation_report.timed_out == false
  and .refresh.manual_validation_report.summary_valid_after_run == true
  and .refresh.manual_validation_report.summary_restored_from_snapshot == false
  and (.refresh.manual_validation_report.duration_sec >= 0)
  and .refresh.single_machine_prod_readiness.status == "skip"
  and .refresh.single_machine_prod_readiness.timed_out == false
  and (.refresh.single_machine_prod_readiness.duration_sec >= 0)
  and .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok == true
  and .artifacts.phase0_summary_json == "'"$PHASE0_SUMMARY_JSON"'"
' "$SUMMARY_JSON" >/dev/null; then
  echo "summary JSON missing expected fields"
  cat "$SUMMARY_JSON"
  exit 1
fi
PHASE6_OUTPUT_PRESENT=0
if jq -e '.blockchain_track.phase6_cosmos_l1_handoff.available == true' "$SUMMARY_JSON" >/dev/null 2>&1; then
  PHASE6_OUTPUT_PRESENT=1
fi
if [[ "$PHASE6_OUTPUT_PRESENT" == "1" ]]; then
  if ! jq -e '
    .blockchain_track.phase6_cosmos_l1_handoff.available == true
    and .blockchain_track.phase6_cosmos_l1_handoff.status == "pass"
    and .blockchain_track.phase6_cosmos_l1_handoff.rc == 0
    and .blockchain_track.phase6_cosmos_l1_handoff.run_pipeline_ok == true
    and .blockchain_track.phase6_cosmos_l1_handoff.module_tx_surface_ok == true
    and .blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_runtime_smoke_ok == true
    and .blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_live_smoke_ok == true
    and .blockchain_track.phase6_cosmos_l1_handoff.tdpnd_grpc_auth_live_smoke_ok == true
    and .artifacts.phase6_cosmos_l1_summary_json == "'"$PHASE6_COSMOS_L1_SUMMARY_JSON"'"
  ' "$SUMMARY_JSON" >/dev/null; then
    echo "summary JSON missing expected phase6 fields"
    cat "$SUMMARY_JSON"
    exit 1
  fi
fi
if ! rg -q '\[roadmap-progress-report\] refresh_step=manual_validation_report status=running' /tmp/integration_roadmap_progress_report_ok.log; then
  echo "expected manual refresh running heartbeat line"
  cat /tmp/integration_roadmap_progress_report_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] refresh_step=manual_validation_report status=pass rc=0 timed_out=false' /tmp/integration_roadmap_progress_report_ok.log; then
  echo "expected manual refresh completion heartbeat line"
  cat /tmp/integration_roadmap_progress_report_ok.log
  exit 1
fi
if ! rg -q 'manual-validation-report --profile-compare-signoff-summary-json' "$CAPTURE"; then
  echo "expected manual-validation-report refresh call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^## Pending Real-Host Checks$' "$REPORT_MD"; then
  echo "report markdown missing pending real-host checks section"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q '^- Phase-0 product surface available: true$' "$REPORT_MD"; then
  echo "report markdown missing phase-0 product surface line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'VPN RC done for phase: `true`' "$REPORT_MD"; then
  echo "report markdown missing VPN RC done signal"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Pending real-host checks: machine_c_vpn_smoke,three_machine_prod_signoff' "$REPORT_MD"; then
  echo "report markdown missing pending real-host check list"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 issuer_sponsor_api_live_smoke_status: pass' "$REPORT_MD"; then
  echo "report markdown missing phase5 issuer_sponsor_api_live_smoke_status line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 issuer_sponsor_api_live_smoke_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase5 issuer_sponsor_api_live_smoke_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if [[ "$PHASE6_OUTPUT_PRESENT" == "1" ]]; then
  if ! rg -q 'Phase-6|phase6_cosmos_l1' "$REPORT_MD"; then
    echo "report markdown missing phase6 line"
    cat "$REPORT_MD"
    exit 1
  fi
fi
if ! rg -q '\[roadmap-progress-report\] phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status=pass issuer_sponsor_api_live_smoke_ok=true' /tmp/integration_roadmap_progress_report_ok.log; then
  echo "expected phase5 issuer sponsor debug line in success path"
  cat /tmp/integration_roadmap_progress_report_ok.log
  exit 1
fi
if [[ "$PHASE6_OUTPUT_PRESENT" == "1" ]]; then
  if ! rg -q '\[roadmap-progress-report\].*phase6' /tmp/integration_roadmap_progress_report_ok.log; then
    echo "expected phase6 debug line in success path"
    cat /tmp/integration_roadmap_progress_report_ok.log
    exit 1
  fi
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] partial manual summary schema path"
MINIMAL_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_minimal_summary.json"
cat >"$MINIMAL_MANUAL_SUMMARY_JSON" <<'EOF_MINIMAL_SUMMARY'
{"version":1,"summary":{"next_action_check_id":"machine_c_vpn_smoke"},"report":{"readiness_status":"NOT_READY"}}
EOF_MINIMAL_SUMMARY
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_minimal_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_minimal_report.md" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_minimal.log 2>&1; then
  echo "expected success when manual-validation summary has partial schema"
  cat /tmp/integration_roadmap_progress_report_minimal.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .vpn_track.readiness_status == "NOT_READY"
  and (.vpn_track.pending_real_host_checks | length) == 0
  and (.vpn_track.blocking_check_ids | length) == 0
' "$TMP_DIR/roadmap_progress_minimal_summary.json" >/dev/null; then
  echo "minimal-schema summary JSON missing expected fallback fields"
  cat "$TMP_DIR/roadmap_progress_minimal_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] incompatible manual summary schema path"
INCOMPATIBLE_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_incompatible_schema_summary.json"
cat >"$INCOMPATIBLE_MANUAL_SUMMARY_JSON" <<'EOF_INCOMPATIBLE_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "unexpected_schema",
    "major": 1,
    "minor": 0
  },
  "summary": {
    "next_action_check_id": "machine_c_vpn_smoke"
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_INCOMPATIBLE_SUMMARY
if run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$INCOMPATIBLE_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_incompatible_schema_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_incompatible_schema_report.md" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_incompatible_schema.log 2>&1; then
  echo "expected failure when manual-validation summary schema is incompatible"
  cat /tmp/integration_roadmap_progress_report_incompatible_schema.log
  exit 1
fi
if ! rg -q 'manual-validation summary JSON is missing required fields or uses an incompatible schema' /tmp/integration_roadmap_progress_report_incompatible_schema.log; then
  echo "incompatible schema path missing expected fail-close message"
  cat /tmp/integration_roadmap_progress_report_incompatible_schema.log
  exit 1
fi

echo "[roadmap-progress-report] next action fallback from checks path"
FALLBACK_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_fallback_summary.json"
cat >"$FALLBACK_MANUAL_SUMMARY_JSON" <<'EOF_FALLBACK_SUMMARY'
{
  "version": 1,
  "checks": [
    {
      "check_id": "machine_c_vpn_smoke",
      "label": "Machine C VPN smoke test",
      "status": "pending",
      "command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    }
  ],
  "summary": {
    "next_action_check_id": "machine_c_vpn_smoke",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": ["machine_c_vpn_smoke"],
    "optional_check_ids": []
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_FALLBACK_SUMMARY
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$FALLBACK_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_fallback_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_fallback_report.md" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_fallback.log 2>&1; then
  echo "expected success when next_action_command is inferred from checks"
  cat /tmp/integration_roadmap_progress_report_fallback.log
  exit 1
fi
if ! jq -e '
  .vpn_track.next_action.check_id == "machine_c_vpn_smoke"
  and .vpn_track.next_action.command == "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
  and ((.next_actions // []) | any(.id == "machine_c_vpn_smoke"))
' "$TMP_DIR/roadmap_progress_fallback_summary.json" >/dev/null; then
  echo "fallback summary JSON missing inferred next action command"
  cat "$TMP_DIR/roadmap_progress_fallback_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] real-host + docker gate fallback from summary path"
SUMMARY_GATE_FALLBACK_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_summary_gate_fallback.json"
cat >"$SUMMARY_GATE_FALLBACK_MANUAL_SUMMARY_JSON" <<'EOF_SUMMARY_GATE_FALLBACK'
{
  "version": 1,
  "summary": {
    "next_action_check_id": "machine_c_vpn_smoke",
    "next_action_label": "Machine C VPN smoke test",
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
    "optional_check_ids": ["three_machine_docker_readiness", "real_wg_privileged_matrix"],
    "real_host_gate": {
      "ready": false,
      "blockers": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
      "next_check_id": "machine_c_vpn_smoke",
      "next_label": "Machine C VPN smoke test",
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    "docker_rehearsal_gate": {
      "status": "pass"
    },
    "profile_default_gate": {
      "status": "pending",
      "next_command": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "skip"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_SUMMARY_GATE_FALLBACK
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$SUMMARY_GATE_FALLBACK_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_summary_gate_fallback_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_summary_gate_fallback_report.md" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_summary_gate_fallback.log 2>&1; then
  echo "expected success when real-host/docker gates are inferred from summary fields"
  cat /tmp/integration_roadmap_progress_report_summary_gate_fallback.log
  exit 1
fi
if ! jq -e '
  .vpn_track.vpn_rc_done_for_phase == true
  and (.vpn_track.pending_real_host_checks | length) == 2
  and ((.vpn_track.pending_real_host_checks | map(.check_id) | sort) == ["machine_c_vpn_smoke","three_machine_prod_signoff"])
  and (.vpn_track.next_action.check_id == "machine_c_vpn_smoke")
  and ((.next_actions // []) | any(.id == "machine_c_vpn_smoke"))
  and (((.next_actions // []) | any(.id == "three_machine_docker_readiness")) | not)
  and (((.next_actions // []) | any(.id == "real_wg_privileged_matrix")) | not)
' "$TMP_DIR/roadmap_progress_summary_gate_fallback_summary.json" >/dev/null; then
  echo "summary-gate fallback JSON missing expected inferred readiness fields"
  cat "$TMP_DIR/roadmap_progress_summary_gate_fallback_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] optional gate command fallback path"
OPTIONAL_FALLBACK_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_optional_gate_fallback_summary.json"
cat >"$OPTIONAL_FALLBACK_MANUAL_SUMMARY_JSON" <<'EOF_OPTIONAL_FALLBACK_SUMMARY'
{
  "version": 1,
  "checks": [
    {
      "check_id": "runtime_hygiene",
      "label": "Runtime hygiene doctor",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh runtime-doctor --show-json 1"
    },
    {
      "check_id": "wg_only_stack_selftest",
      "label": "WG-only stack selftest",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh wg-only-stack-selftest-record --strict-beta 1 --print-summary-json 1"
    }
  ],
  "summary": {
    "next_action_check_id": "",
    "next_action_command": "",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": [],
    "optional_check_ids": ["three_machine_docker_readiness", "real_wg_privileged_matrix"],
    "docker_rehearsal_gate": {
      "status": "pending",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pending",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_OPTIONAL_FALLBACK_SUMMARY
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$OPTIONAL_FALLBACK_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_optional_fallback_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_optional_fallback_report.md" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_optional_fallback.log 2>&1; then
  echo "expected success when optional gate next commands are inferred from command fields"
  cat /tmp/integration_roadmap_progress_report_optional_fallback.log
  exit 1
fi
if ! jq -e '
  ((.next_actions // []) | any(.id == "three_machine_docker_readiness" and .command == "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"))
  and ((.next_actions // []) | any(.id == "real_wg_privileged_matrix" and .command == "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"))
' "$TMP_DIR/roadmap_progress_optional_fallback_summary.json" >/dev/null; then
  echo "optional gate command fallback summary JSON missing expected commands"
  cat "$TMP_DIR/roadmap_progress_optional_fallback_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] manual refresh invalid summary restore path"
RESTORE_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_restore_target.json"
RESTORE_MANUAL_REPORT_MD="$TMP_DIR/manual_validation_restore_target.md"
cat >"$RESTORE_MANUAL_SUMMARY_JSON" <<'EOF_RESTORE_SUMMARY'
{
  "version": 1,
  "checks": [
    {
      "check_id": "machine_c_vpn_smoke",
      "label": "Machine C VPN smoke test",
      "status": "pending",
      "command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    {
      "check_id": "three_machine_prod_signoff",
      "label": "True 3-machine production signoff",
      "status": "pending",
      "command": "sudo ./scripts/easy_node.sh three-machine-prod-signoff --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --pre-real-host-readiness 1 --runtime-fix 1 --print-summary-json 1"
    }
  ],
  "summary": {
    "next_action_check_id": "machine_c_vpn_smoke",
    "next_action_label": "Machine C VPN smoke test",
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country",
    "blocking_check_ids": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
    "optional_check_ids": [],
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "pre_machine_c_gate": {
      "ready": true,
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    "real_host_gate": {
      "ready": false,
      "blockers": ["machine_c_vpn_smoke", "three_machine_prod_signoff"],
      "next_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    "profile_default_gate": {
      "status": "pending",
      "next_command": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1"
    },
    "docker_rehearsal_gate": {
      "status": "pending",
      "next_command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pending",
      "next_command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY",
    "ready": false
  }
}
EOF_RESTORE_SUMMARY
printf '# existing manual validation report\n' >"$RESTORE_MANUAL_REPORT_MD"
if FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
  ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_INVALID" \
  ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
  run_roadmap_progress_report \
    --refresh-manual-validation 1 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$RESTORE_MANUAL_SUMMARY_JSON" \
    --manual-validation-report-md "$RESTORE_MANUAL_REPORT_MD" \
    --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_manual_restore_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_manual_restore_report.md" \
    --print-report 0 \
    --print-summary-json 0 >/tmp/integration_roadmap_progress_report_manual_restore.log 2>&1; then
  echo "expected failure when manual refresh emits invalid summary"
  cat /tmp/integration_roadmap_progress_report_manual_restore.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] status=fail rc=1' /tmp/integration_roadmap_progress_report_manual_restore.log; then
  echo "manual restore path missing fail status line"
  cat /tmp/integration_roadmap_progress_report_manual_restore.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .refresh.manual_validation_report.status == "fail"
  and .refresh.manual_validation_report.summary_valid_after_run == true
  and .refresh.manual_validation_report.summary_restored_from_snapshot == true
  and .vpn_track.next_action.check_id == "machine_c_vpn_smoke"
' "$TMP_DIR/roadmap_progress_manual_restore_summary.json" >/dev/null; then
  echo "manual restore summary missing expected restored snapshot fields"
  cat "$TMP_DIR/roadmap_progress_manual_restore_summary.json"
  exit 1
fi
if ! jq -e '
  .summary.next_action_check_id == "machine_c_vpn_smoke"
  and .report.readiness_status == "NOT_READY"
' "$RESTORE_MANUAL_SUMMARY_JSON" >/dev/null; then
  echo "manual restore path did not keep manual validation summary JSON valid"
  cat "$RESTORE_MANUAL_SUMMARY_JSON"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] manual refresh partial summary restore path"
if FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
  ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL_PARTIAL" \
  ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
  run_roadmap_progress_report \
    --refresh-manual-validation 1 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$RESTORE_MANUAL_SUMMARY_JSON" \
    --manual-validation-report-md "$RESTORE_MANUAL_REPORT_MD" \
    --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_manual_partial_restore_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_manual_partial_restore_report.md" \
    --print-report 0 \
    --print-summary-json 0 >/tmp/integration_roadmap_progress_report_manual_partial_restore.log 2>&1; then
  echo "expected failure when manual refresh emits partial summary schema"
  cat /tmp/integration_roadmap_progress_report_manual_partial_restore.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] status=fail rc=1' /tmp/integration_roadmap_progress_report_manual_partial_restore.log; then
  echo "manual partial restore path missing fail status line"
  cat /tmp/integration_roadmap_progress_report_manual_partial_restore.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .refresh.manual_validation_report.status == "fail"
  and .refresh.manual_validation_report.summary_valid_after_run == true
  and .refresh.manual_validation_report.summary_restored_from_snapshot == true
  and .vpn_track.next_action.check_id == "machine_c_vpn_smoke"
' "$TMP_DIR/roadmap_progress_manual_partial_restore_summary.json" >/dev/null; then
  echo "manual partial restore summary missing expected restored snapshot fields"
  cat "$TMP_DIR/roadmap_progress_manual_partial_restore_summary.json"
  exit 1
fi
if ! jq -e '
  .summary.next_action_check_id == "machine_c_vpn_smoke"
  and .report.readiness_status == "NOT_READY"
' "$RESTORE_MANUAL_SUMMARY_JSON" >/dev/null; then
  echo "manual partial restore path did not keep manual validation summary JSON usable"
  cat "$RESTORE_MANUAL_SUMMARY_JSON"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] single-machine refresh failure path"
cat >"$SINGLE_MACHINE_SUMMARY_JSON" <<'EOF_SINGLE_MACHINE_SNAPSHOT'
{
  "status": "ok",
  "summary": {
    "single_machine_ready": true
  }
}
EOF_SINGLE_MACHINE_SNAPSHOT
if FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
  FAKE_SINGLE_FAIL=1 \
  ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL" \
  ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
  run_roadmap_progress_report \
    --refresh-manual-validation 1 \
    --refresh-single-machine-readiness 1 \
    --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_fail_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_fail_report.md" \
    --print-report 0 \
    --print-summary-json 0 >/tmp/integration_roadmap_progress_report_fail.log 2>&1; then
  echo "expected failure when single-machine refresh fails"
  cat /tmp/integration_roadmap_progress_report_fail.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] status=fail rc=1' /tmp/integration_roadmap_progress_report_fail.log; then
  echo "expected fail status when single-machine refresh fails"
  cat /tmp/integration_roadmap_progress_report_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .refresh.single_machine_prod_readiness.status == "fail"
  and .refresh.single_machine_prod_readiness.rc == 1
  and .refresh.single_machine_prod_readiness.timed_out == false
  and .refresh.single_machine_prod_readiness.summary_valid_after_run == true
  and .refresh.single_machine_prod_readiness.summary_restored_from_snapshot == true
' "$TMP_DIR/roadmap_progress_fail_summary.json" >/dev/null; then
  echo "failure summary JSON missing expected fields"
  cat "$TMP_DIR/roadmap_progress_fail_summary.json"
  exit 1
fi
if ! jq -e '.summary.single_machine_ready == true' "$SINGLE_MACHINE_SUMMARY_JSON" >/dev/null 2>&1; then
  echo "single-machine refresh failure path did not restore latest summary snapshot"
  cat "$SINGLE_MACHINE_SUMMARY_JSON"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] single-machine refresh transient non-blocking warning path"
if ! FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
  FAKE_SINGLE_FAIL=1 \
  FAKE_SINGLE_TRANSIENT_LOG=1 \
  FAKE_SINGLE_SUMMARY_PAYLOAD='{"status":"fail","summary":{"critical_failed_steps":[{"step_id":"three_machine_docker_readiness"}],"pending_local_checks":[],"three_machine_docker_readiness":{"status":"fail"}}}' \
  ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL" \
  ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
  run_roadmap_progress_report \
    --refresh-manual-validation 1 \
    --refresh-single-machine-readiness 1 \
    --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_transient_warn_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_transient_warn_report.md" \
    --print-report 0 \
    --print-summary-json 0 >/tmp/integration_roadmap_progress_report_transient_warn.log 2>&1; then
  echo "expected success with warn status when single-machine refresh hits transient docker registry failure"
  cat /tmp/integration_roadmap_progress_report_transient_warn.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] status=warn rc=0' /tmp/integration_roadmap_progress_report_transient_warn.log; then
  echo "transient warning path missing warn status line"
  cat /tmp/integration_roadmap_progress_report_transient_warn.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] refresh_step=single_machine_prod_readiness status=warn rc=1 timed_out=false' /tmp/integration_roadmap_progress_report_transient_warn.log; then
  echo "transient warning path missing single-machine warn heartbeat line"
  cat /tmp/integration_roadmap_progress_report_transient_warn.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .notes == "One or more requested refresh steps reported non-blocking transient warnings; latest usable summaries were retained."
  and .refresh.single_machine_prod_readiness.status == "warn"
  and .refresh.single_machine_prod_readiness.rc == 1
  and .refresh.single_machine_prod_readiness.timed_out == false
  and .refresh.single_machine_prod_readiness.non_blocking_transient == true
  and (.refresh.single_machine_prod_readiness.non_blocking_reason | contains("Transient docker registry/network failure"))
' "$TMP_DIR/roadmap_progress_transient_warn_summary.json" >/dev/null; then
  echo "transient warning summary JSON missing expected fields"
  cat "$TMP_DIR/roadmap_progress_transient_warn_summary.json"
  exit 1
fi

: >"$CAPTURE"

if command -v timeout >/dev/null 2>&1; then
  echo "[roadmap-progress-report] single-machine refresh timeout path"
  if FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
    FAKE_SINGLE_SLEEP_SEC=2 \
    ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL" \
    ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
    run_roadmap_progress_report \
      --refresh-manual-validation 0 \
      --refresh-single-machine-readiness 1 \
      --single-machine-refresh-timeout-sec 1 \
      --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
      --summary-json "$TMP_DIR/roadmap_progress_timeout_summary.json" \
      --report-md "$TMP_DIR/roadmap_progress_timeout_report.md" \
      --print-report 0 \
      --print-summary-json 0 >/tmp/integration_roadmap_progress_report_timeout.log 2>&1; then
    echo "expected failure when single-machine refresh times out"
    cat /tmp/integration_roadmap_progress_report_timeout.log
    exit 1
  fi
  if ! rg -q '\[roadmap-progress-report\] refresh_step=single_machine_prod_readiness status=running timeout_sec=1' /tmp/integration_roadmap_progress_report_timeout.log; then
    echo "timeout path missing running heartbeat line"
    cat /tmp/integration_roadmap_progress_report_timeout.log
    exit 1
  fi
  if ! rg -q '\[roadmap-progress-report\] refresh_step=single_machine_prod_readiness status=fail rc=124 timed_out=true' /tmp/integration_roadmap_progress_report_timeout.log; then
    echo "timeout path missing timeout completion heartbeat line"
    cat /tmp/integration_roadmap_progress_report_timeout.log
    exit 1
  fi
  if ! jq -e '
    .status == "fail"
    and .rc == 1
    and .notes == "One or more requested refresh steps timed out; inspect refresh logs."
    and .refresh.single_machine_prod_readiness.status == "fail"
    and .refresh.single_machine_prod_readiness.rc == 124
    and .refresh.single_machine_prod_readiness.timed_out == true
    and .refresh.single_machine_prod_readiness.timeout_sec == 1
    and (.refresh.single_machine_prod_readiness.duration_sec >= 1)
  ' "$TMP_DIR/roadmap_progress_timeout_summary.json" >/dev/null; then
    echo "timeout summary JSON missing expected timeout fields"
    cat "$TMP_DIR/roadmap_progress_timeout_summary.json"
    exit 1
  fi
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] phase1 handoff actionable gate contract"
build_phase1_handoff_fixture() {
  local output_path="$1"
  local failure_kind="$2"
  local policy_decision="$3"
  local fail_closed_no_go="$4"

  jq -n \
    --arg failure_kind "$failure_kind" \
    --arg policy_decision "$policy_decision" \
    --argjson fail_closed_no_go "$fail_closed_no_go" \
    '{
      schema: {
        id: "phase1_resilience_handoff_check_summary",
        major: 1,
        minor: 0
      },
      status: "fail",
      rc: 1,
      handoff: {
        profile_matrix_stable: true,
        peer_loss_recovery_ok: false,
        session_churn_guard_ok: true,
        failure_semantics: {
          profile_matrix_stable: {
            kind: "none",
            policy_no_go: false,
            execution_failure: false,
            timeout: false
          },
          peer_loss_recovery_ok: {
            kind: $failure_kind,
            policy_no_go: ($failure_kind == "policy_no_go"),
            execution_failure: ($failure_kind == "execution_failure"),
            timeout: ($failure_kind == "timeout")
          },
          session_churn_guard_ok: {
            kind: "none",
            policy_no_go: false,
            execution_failure: false,
            timeout: false
          }
        }
      },
      failure: {
        kind: $failure_kind,
        policy_no_go: ($failure_kind == "policy_no_go"),
        execution_failure: ($failure_kind == "execution_failure"),
        timeout: ($failure_kind == "timeout")
      },
      policy_outcome: {
        decision: $policy_decision,
        fail_closed_no_go: $fail_closed_no_go
      },
      automation: {
        track: "non_blockchain",
        requires_sudo: false,
        requires_github: false,
        automatable_without_sudo_or_github: true
      }
    }' >"$output_path"
}

assert_phase1_actionable_contract_case() {
  local case_id="$1"
  local handoff_summary_json="$2"
  local expected_failure_kind="$3"
  local expected_policy_decision="$4"
  local expected_fail_closed_no_go="$5"
  local phase1_summary_json="$TMP_DIR/roadmap_progress_phase1_actionable_${case_id}_summary.json"
  local phase1_report_md="$TMP_DIR/roadmap_progress_phase1_actionable_${case_id}_report.md"
  local phase1_log="/tmp/integration_roadmap_progress_report_phase1_actionable_${case_id}.log"

  if ! run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
    --phase0-summary-json "$PHASE0_SUMMARY_JSON" \
    --phase1-resilience-handoff-summary-json "$handoff_summary_json" \
    --vpn-rc-resilience-summary-json "$TMP_DIR/missing_resilience_for_phase1_contract_${case_id}.json" \
    --summary-json "$phase1_summary_json" \
    --report-md "$phase1_report_md" \
    --print-report 0 \
    --print-summary-json 0 >"$phase1_log" 2>&1; then
    echo "expected success for phase1 actionable-gate contract path ($case_id)"
    cat "$phase1_log"
    exit 1
  fi

  if ! jq -e \
    --arg src "$handoff_summary_json" \
    --arg failure_kind "$expected_failure_kind" \
    --arg policy_decision "$expected_policy_decision" \
    --argjson fail_closed_no_go "$expected_fail_closed_no_go" '
      .status == "warn"
      and .rc == 0
      and .vpn_track.phase1_resilience_handoff.available == true
      and .vpn_track.phase1_resilience_handoff.source_summary_json == $src
      and .vpn_track.phase1_resilience_handoff.status == "fail"
      and .vpn_track.phase1_resilience_handoff.rc == 1
      and .vpn_track.phase1_resilience_handoff.profile_matrix_stable == true
      and .vpn_track.phase1_resilience_handoff.peer_loss_recovery_ok == false
      and .vpn_track.phase1_resilience_handoff.session_churn_guard_ok == true
      and .vpn_track.phase1_resilience_handoff.automatable_without_sudo_or_github == true
      and .vpn_track.phase1_resilience_handoff.failure.kind == $failure_kind
      and .vpn_track.phase1_resilience_handoff.policy_outcome.decision == $policy_decision
      and .vpn_track.phase1_resilience_handoff.policy_outcome.fail_closed_no_go == $fail_closed_no_go
      and .vpn_track.non_blockchain_recommended_gate_id == "phase1_resilience_handoff_run_dry"
      and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | length) >= 1
      and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | any(
            .id == "phase1_resilience_handoff_run_dry"
            and (.command // "") == "bash ./scripts/phase1_resilience_handoff_run.sh --dry-run 1 --print-summary-json 1"
            and ((.reason // "") | contains("status=fail"))
            and ((.reason // "") | contains($failure_kind))
          ))
      and .artifacts.phase1_resilience_handoff_summary_json == $src
    ' "$phase1_summary_json" >/dev/null; then
    echo "phase1 actionable-gate contract summary mismatch ($case_id)"
    cat "$phase1_summary_json"
    exit 1
  fi

  if ! rg -q '^## Non-Blockchain Actionable Gates \(No sudo/GitHub\)$' "$phase1_report_md"; then
    echo "phase1 actionable report missing non-blockchain gate section ($case_id)"
    cat "$phase1_report_md"
    exit 1
  fi
  if ! rg -q 'phase1_resilience_handoff_run.sh --dry-run 1 --print-summary-json 1' "$phase1_report_md"; then
    echo "phase1 actionable report missing recommended dry-run command ($case_id)"
    cat "$phase1_report_md"
    exit 1
  fi
}

PHASE1_HANDOFF_FAIL_SUMMARY_JSON="$TMP_DIR/phase1_handoff_fail_policy_no_go_summary.json"
build_phase1_handoff_fixture "$PHASE1_HANDOFF_FAIL_SUMMARY_JSON" "policy_no_go" "NO-GO" true

: >"$CAPTURE"

echo "[roadmap-progress-report] phase0 actionable gate precedence when product surface is incomplete"
PHASE0_ACTIONABLE_MISSING_SUMMARY_JSON="$TMP_DIR/missing_phase0_summary_for_actionable.json"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase0-summary-json "$PHASE0_ACTIONABLE_MISSING_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$PHASE1_HANDOFF_FAIL_SUMMARY_JSON" \
  --vpn-rc-resilience-summary-json "$TMP_DIR/missing_resilience_for_phase0_actionable_contract.json" \
  --summary-json "$TMP_DIR/roadmap_progress_phase0_actionable_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_phase0_actionable_report.md" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_phase0_actionable.log 2>&1; then
  echo "expected success for phase0 actionable-gate precedence path"
  cat /tmp/integration_roadmap_progress_report_phase0_actionable.log
  exit 1
fi
if ! jq -e '
  .status == "warn"
  and .rc == 0
  and .vpn_track.phase0_product_surface.available == false
  and .vpn_track.phase0_product_surface.status == "missing"
  and .vpn_track.non_blockchain_recommended_gate_id == "phase0_product_surface_gate"
  and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | length) >= 2
  and (.vpn_track.non_blockchain_actionable_no_sudo_or_github[0].id // "") == "phase0_product_surface_gate"
  and (.vpn_track.non_blockchain_actionable_no_sudo_or_github[0].command // "") == "bash ./scripts/ci_phase0.sh --print-summary-json 1"
  and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | any(.id == "phase1_resilience_handoff_run_dry"))
  and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | all(((.command // "") | contains("sudo") | not)))
  and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | all(((.command // "") | contains("github") | not)))
' "$TMP_DIR/roadmap_progress_phase0_actionable_summary.json" >/dev/null; then
  echo "phase0 actionable-gate precedence summary mismatch"
  cat "$TMP_DIR/roadmap_progress_phase0_actionable_summary.json"
  exit 1
fi
if ! rg -q 'ci_phase0.sh --print-summary-json 1' "$TMP_DIR/roadmap_progress_phase0_actionable_report.md"; then
  echo "phase0 actionable report missing ci_phase0 gate command"
  cat "$TMP_DIR/roadmap_progress_phase0_actionable_report.md"
  exit 1
fi

assert_phase1_actionable_contract_case "policy_no_go" "$PHASE1_HANDOFF_FAIL_SUMMARY_JSON" "policy_no_go" "NO-GO" true

PHASE1_HANDOFF_EXECUTION_FAILURE_SUMMARY_JSON="$TMP_DIR/phase1_handoff_fail_execution_failure_summary.json"
build_phase1_handoff_fixture "$PHASE1_HANDOFF_EXECUTION_FAILURE_SUMMARY_JSON" "execution_failure" "ERROR" false
assert_phase1_actionable_contract_case "execution_failure" "$PHASE1_HANDOFF_EXECUTION_FAILURE_SUMMARY_JSON" "execution_failure" "ERROR" false

PHASE1_HANDOFF_TIMEOUT_SUMMARY_JSON="$TMP_DIR/phase1_handoff_fail_timeout_summary.json"
build_phase1_handoff_fixture "$PHASE1_HANDOFF_TIMEOUT_SUMMARY_JSON" "timeout" "ERROR" false
assert_phase1_actionable_contract_case "timeout" "$PHASE1_HANDOFF_TIMEOUT_SUMMARY_JSON" "timeout" "ERROR" false

: >"$CAPTURE"

echo "[roadmap-progress-report] phase2 actionable gate progression when phase1 is pass"
PHASE1_HANDOFF_PASS_SUMMARY_JSON="$TMP_DIR/phase1_handoff_pass_summary.json"
cat >"$PHASE1_HANDOFF_PASS_SUMMARY_JSON" <<'EOF_PHASE1_HANDOFF_PASS'
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
EOF_PHASE1_HANDOFF_PASS
PHASE2_HANDOFF_FAIL_SUMMARY_JSON="$TMP_DIR/phase2_handoff_fail_summary.json"
cat >"$PHASE2_HANDOFF_FAIL_SUMMARY_JSON" <<'EOF_PHASE2_HANDOFF_FAIL'
{
  "schema": {
    "id": "phase2_linux_prod_candidate_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 1,
  "signals": {
    "release_integrity_ok": false,
    "release_policy_ok": true,
    "operator_lifecycle_ok": true,
    "pilot_signoff_ok": true
  }
}
EOF_PHASE2_HANDOFF_FAIL
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase0-summary-json "$PHASE0_SUMMARY_JSON" \
  --phase1-resilience-handoff-summary-json "$PHASE1_HANDOFF_PASS_SUMMARY_JSON" \
  --phase2-linux-prod-candidate-summary-json "$PHASE2_HANDOFF_FAIL_SUMMARY_JSON" \
  --vpn-rc-resilience-summary-json "$TMP_DIR/missing_resilience_for_phase2_actionable_contract.json" \
  --summary-json "$TMP_DIR/roadmap_progress_phase2_actionable_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_phase2_actionable_report.md" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_roadmap_progress_report_phase2_actionable.log 2>&1; then
  echo "expected success for phase2 actionable-gate progression path"
  cat /tmp/integration_roadmap_progress_report_phase2_actionable.log
  exit 1
fi
if ! jq -e --arg p2src "$PHASE2_HANDOFF_FAIL_SUMMARY_JSON" '
  .status == "warn"
  and .rc == 0
  and .vpn_track.phase1_resilience_handoff.status == "pass"
  and .vpn_track.phase2_linux_prod_candidate_handoff.available == true
  and .vpn_track.phase2_linux_prod_candidate_handoff.source_summary_json == $p2src
  and .vpn_track.phase2_linux_prod_candidate_handoff.status == "fail"
  and .vpn_track.non_blockchain_recommended_gate_id == "phase2_linux_prod_candidate_handoff_run_dry"
  and ((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | any(
        .id == "phase2_linux_prod_candidate_handoff_run_dry"
        and (.command // "") == "bash ./scripts/phase2_linux_prod_candidate_handoff_run.sh --dry-run 1 --print-summary-json 1"
      ))
  and (((.vpn_track.non_blockchain_actionable_no_sudo_or_github // []) | any(.id == "phase1_resilience_handoff_run_dry")) | not)
' "$TMP_DIR/roadmap_progress_phase2_actionable_summary.json" >/dev/null; then
  echo "phase2 actionable-gate progression summary mismatch"
  cat "$TMP_DIR/roadmap_progress_phase2_actionable_summary.json"
  exit 1
fi
if ! rg -q 'phase2_linux_prod_candidate_handoff_run.sh --dry-run 1 --print-summary-json 1' "$TMP_DIR/roadmap_progress_phase2_actionable_report.md"; then
  echo "phase2 actionable report missing recommended dry-run command"
  cat "$TMP_DIR/roadmap_progress_phase2_actionable_report.md"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] resilience auto-source selection uses freshest valid summary"
AUTO_RESILIENCE_LOGS_ROOT="$TMP_DIR/auto_resilience_logs_root"
AUTO_RESILIENCE_OLD_DIR="$AUTO_RESILIENCE_LOGS_ROOT/zzz_old_path"
AUTO_RESILIENCE_NEW_DIR="$AUTO_RESILIENCE_LOGS_ROOT/aaa_new_path"
AUTO_RESILIENCE_INVALID_DIR="$AUTO_RESILIENCE_LOGS_ROOT/yyy_invalid_newest"
mkdir -p "$AUTO_RESILIENCE_OLD_DIR" "$AUTO_RESILIENCE_NEW_DIR" "$AUTO_RESILIENCE_INVALID_DIR"

AUTO_RESILIENCE_OLD_JSON="$AUTO_RESILIENCE_OLD_DIR/vpn_rc_resilience_path_summary.json"
cat >"$AUTO_RESILIENCE_OLD_JSON" <<'EOF_AUTO_RESILIENCE_OLD'
{
  "version": 1,
  "profile_matrix_stable": false,
  "peer_loss_recovery_ok": false,
  "session_churn_guard_ok": false
}
EOF_AUTO_RESILIENCE_OLD
touch -t 202601010101 "$AUTO_RESILIENCE_OLD_JSON"

AUTO_RESILIENCE_NEW_JSON="$AUTO_RESILIENCE_NEW_DIR/vpn_rc_resilience_path_summary.json"
cat >"$AUTO_RESILIENCE_NEW_JSON" <<'EOF_AUTO_RESILIENCE_NEW'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": true
}
EOF_AUTO_RESILIENCE_NEW
touch -t 202601020202 "$AUTO_RESILIENCE_NEW_JSON"

AUTO_RESILIENCE_INVALID_JSON="$AUTO_RESILIENCE_INVALID_DIR/vpn_rc_resilience_path_summary.json"
printf '{"version": 1, "profile_matrix_stable": true' >"$AUTO_RESILIENCE_INVALID_JSON"
touch -t 202601030303 "$AUTO_RESILIENCE_INVALID_JSON"

if ! ROADMAP_PROGRESS_LOGS_ROOT="$AUTO_RESILIENCE_LOGS_ROOT" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
    --phase1-resilience-handoff-summary-json "$TMP_DIR/missing_phase1_for_auto_resilience.json" \
    --summary-json "$TMP_DIR/roadmap_progress_auto_resilience_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_auto_resilience_report.md" \
    --print-report 0 \
    --print-summary-json 0 >/tmp/integration_roadmap_progress_report_auto_resilience.log 2>&1; then
  echo "expected success for auto resilience source selection path"
  cat /tmp/integration_roadmap_progress_report_auto_resilience.log
  exit 1
fi
if ! jq -e --arg src "$AUTO_RESILIENCE_NEW_JSON" '
  .status == "warn"
  and .rc == 0
  and .vpn_track.resilience_handoff.available == true
  and .vpn_track.resilience_handoff.source_summary_json == $src
  and .vpn_track.resilience_handoff.profile_matrix_stable == true
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.resilience_handoff.session_churn_guard_ok == true
  and .artifacts.vpn_rc_resilience_summary_json == $src
' "$TMP_DIR/roadmap_progress_auto_resilience_summary.json" >/dev/null; then
  echo "auto resilience source selection summary mismatch"
  cat "$TMP_DIR/roadmap_progress_auto_resilience_summary.json"
  exit 1
fi

: >"$CAPTURE"

FAKE_FORWARD="$TMP_DIR/fake_roadmap_progress_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FAKE_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'roadmap-progress-report %s\n' "$*" >>"${FORWARD_CAPTURE_FILE:?}"
EOF_FAKE_FORWARD
chmod +x "$FAKE_FORWARD"

echo "[roadmap-progress-report] easy_node forwarding"
FORWARD_CAPTURE_FILE="$CAPTURE" \
ROADMAP_PROGRESS_REPORT_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh roadmap-progress-report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 1 \
  --summary-json /tmp/roadmap_progress.json \
  --print-summary-json 1 >/tmp/integration_roadmap_progress_report_forward.log 2>&1

forward_line="$(rg '^roadmap-progress-report ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing roadmap-progress-report forward capture"
  cat "$CAPTURE"
  exit 1
fi
for expected in '--refresh-manual-validation 0' '--refresh-single-machine-readiness 1' '--summary-json /tmp/roadmap_progress.json' '--print-summary-json 1'; do
  if [[ "$forward_line" != *"$expected"* ]]; then
    echo "forwarded command missing expected fragment: $expected"
    echo "$forward_line"
    exit 1
  fi
done

echo "roadmap progress report integration check ok"
