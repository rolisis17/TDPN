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
INTEGRATION_STDOUT_LOG_DIR="$TMP_DIR/stdout-logs"
mkdir -p "$INTEGRATION_STDOUT_LOG_DIR"
ROADMAP_PROGRESS_REPORT_LOG_PREFIX="$INTEGRATION_STDOUT_LOG_DIR/integration_roadmap_progress_report"
ROADMAP_PROGRESS_FORWARD_SUMMARY_JSON="$TMP_DIR/roadmap_progress_forward_summary.json"

cleanup_integration_artifacts() {
  rm -rf "$TMP_DIR"
}
trap 'cleanup_integration_artifacts' EXIT

TEST_LOG_DIR="$TMP_DIR/easy-node-logs"
TEST_STATE_DIR="$TMP_DIR/manual-validation-state"
mkdir -p "$TEST_LOG_DIR" "$TEST_STATE_DIR"
export EASY_NODE_LOG_DIR="$TEST_LOG_DIR"
export EASY_NODE_MANUAL_VALIDATION_STATE_DIR="$TEST_STATE_DIR"

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
ROADMAP_PROGRESS_MISSING_PHASE7_SUMMARY_JSON="$TMP_DIR/missing_phase7_summary.json"
ROADMAP_PROGRESS_MISSING_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON="$TMP_DIR/missing_blockchain_mainnet_activation_gate_summary.json"
ROADMAP_PROGRESS_MISSING_BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON="$TMP_DIR/missing_blockchain_bootstrap_governance_graduation_gate_summary.json"

run_roadmap_progress_report() {
  ./scripts/roadmap_progress_report.sh \
    --phase0-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE0_SUMMARY_JSON" \
    --phase1-resilience-handoff-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE1_SUMMARY_JSON" \
    --phase2-linux-prod-candidate-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE2_SUMMARY_JSON" \
    --phase3-windows-client-beta-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE3_SUMMARY_JSON" \
    --phase4-windows-full-parity-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE4_SUMMARY_JSON" \
    --phase5-settlement-layer-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE5_SUMMARY_JSON" \
    --phase6-cosmos-l1-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE6_SUMMARY_JSON" \
    --phase7-mainnet-cutover-summary-json "$ROADMAP_PROGRESS_MISSING_PHASE7_SUMMARY_JSON" \
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
PHASE7_MAINNET_CUTOVER_LOG_DIR="$ROADMAP_PROGRESS_TEST_LOGS_ROOT/phase7_mainnet_cutover_20260416_000001"
mkdir -p "$PHASE7_MAINNET_CUTOVER_LOG_DIR"
PHASE7_MAINNET_CUTOVER_CHECK_SUMMARY_JSON="$PHASE7_MAINNET_CUTOVER_LOG_DIR/phase7_mainnet_cutover_check_summary.json"
PHASE7_MAINNET_CUTOVER_RUN_SUMMARY_JSON="$PHASE7_MAINNET_CUTOVER_LOG_DIR/phase7_mainnet_cutover_run_summary.json"
PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_SUMMARY_JSON="$PHASE7_MAINNET_CUTOVER_LOG_DIR/phase7_mainnet_cutover_handoff_check_summary.json"
PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_SUMMARY_JSON="$PHASE7_MAINNET_CUTOVER_LOG_DIR/phase7_mainnet_cutover_handoff_run_summary.json"
PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON="$PHASE7_MAINNET_CUTOVER_LOG_DIR/phase7_mainnet_cutover_summary_report.json"
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
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    },
    "issuer_settlement_status_live_smoke": {
      "status": "pass"
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "pass"
    },
    "exit_settlement_status_live_smoke": {
      "status": "pass"
    }
  },
  "settlement_dual_asset_parity_status": "pass",
  "settlement_dual_asset_parity_ok": true,
  "settlement_adapter_signed_tx_roundtrip_status": "pass",
  "settlement_adapter_signed_tx_roundtrip_ok": true,
  "settlement_shadow_env_status": "pass",
  "settlement_shadow_env_ok": true,
  "settlement_shadow_status_surface_status": "pass",
  "settlement_shadow_status_surface_ok": true,
  "issuer_admin_blockchain_handlers_coverage_status": "pass",
  "issuer_admin_blockchain_handlers_coverage_ok": true
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
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true
  },
  "signals": {
    "module_tx_surface_ok": true,
    "tdpnd_grpc_runtime_smoke_ok": true,
    "tdpnd_grpc_live_smoke_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true
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
cat >"$PHASE7_MAINNET_CUTOVER_CHECK_SUMMARY_JSON" <<'EOF_PHASE7_CHECK_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "check": true,
    "run": true,
    "handoff_check": true,
    "handoff_run": true,
    "mainnet_activation_gate_go": true,
    "bootstrap_governance_graduation_gate_go": true
  },
  "handoff": {
    "check": true,
    "run": true,
    "handoff_check": true,
    "handoff_run": true,
    "mainnet_activation_gate_go": true,
    "bootstrap_governance_graduation_gate_go": true
  }
}
EOF_PHASE7_CHECK_SUMMARY
cat >"$PHASE7_MAINNET_CUTOVER_RUN_SUMMARY_JSON" <<'EOF_PHASE7_RUN_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "phase7_mainnet_cutover_check": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true,
      "signal_snapshot": {
        "check": true,
        "run": true,
        "handoff_check": true,
        "handoff_run": true,
        "mainnet_activation_gate_go": true,
        "bootstrap_governance_graduation_gate_go": true
      }
    }
  },
  "signals": {
    "check": true,
    "run": true,
    "handoff_check": true,
    "handoff_run": true,
    "mainnet_activation_gate_go": true,
    "bootstrap_governance_graduation_gate_go": true
  },
  "handoff": {
    "check": true,
    "run": true,
    "handoff_check": true,
    "handoff_run": true,
    "mainnet_activation_gate_go": true,
    "bootstrap_governance_graduation_gate_go": true
  }
}
EOF_PHASE7_RUN_SUMMARY
cat >"$PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_SUMMARY_JSON" <<'EOF_PHASE7_HANDOFF_CHECK_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "handoff": {
    "check": true,
    "run": true,
    "handoff_check": true,
    "handoff_run": true,
    "mainnet_activation_gate_go": true,
    "bootstrap_governance_graduation_gate_go": true
  },
  "signals": {
    "check": true,
    "run": true,
    "handoff_check": true,
    "handoff_run": true,
    "mainnet_activation_gate_go": true,
    "bootstrap_governance_graduation_gate_go": true
  },
  "decision": {
    "pass": true,
    "reasons": [],
    "warnings": []
  }
}
EOF_PHASE7_HANDOFF_CHECK_SUMMARY
cat >"$PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_SUMMARY_JSON" <<'EOF_PHASE7_HANDOFF_RUN_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_handoff_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "mainnet_activation_gate_go_ok": true,
    "bootstrap_governance_graduation_gate_go_ok": true,
    "cosmos_module_coverage_floor_ok": true,
    "cosmos_keeper_coverage_floor_ok": true,
    "cosmos_app_coverage_floor_ok": true,
    "dual_write_parity_ok": true
  },
  "summaries": {
    "check": {
      "status": "pass",
      "rc": 0
    },
    "run": {
      "status": "pass",
      "rc": 0
    },
    "handoff_check": {
      "status": "pass",
      "rc": 0
    },
    "handoff_run": {
      "status": "pass",
      "rc": 0
    }
  }
}
EOF_PHASE7_HANDOFF_RUN_SUMMARY
cat >"$PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON" <<'EOF_PHASE7_SUMMARY_REPORT'
{
  "version": 1,
  "schema": {
    "id": "phase7_mainnet_cutover_summary_report",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "tdpnd_grpc_live_smoke_ok": true,
    "module_tx_surface_ok": true,
    "tdpnd_grpc_auth_live_smoke_ok": true,
    "tdpnd_comet_runtime_smoke_ok": true,
    "bootstrap_governance_graduation_gate_go_ok": true
  },
  "summaries": {
    "check": {
      "configured": true,
      "exists": true,
      "valid_json": true,
      "schema_id": "phase7_mainnet_cutover_check_summary",
      "schema_valid": true,
      "raw_status": "pass",
      "raw_rc": 0,
      "signal_snapshot": {
        "mainnet_activation_gate_go": true,
        "bootstrap_governance_graduation_gate_go": true,
        "tdpnd_grpc_live_smoke_ok": true,
        "module_tx_surface_ok": true,
        "tdpnd_grpc_auth_live_smoke_ok": true,
        "tdpnd_comet_runtime_smoke_ok": true,
        "cosmos_module_coverage_floor_ok": true,
        "cosmos_keeper_coverage_floor_ok": true,
        "cosmos_app_coverage_floor_ok": true,
        "dual_write_parity_ok": true
      },
      "status": "pass"
    },
    "run": {
      "configured": true,
      "exists": true,
      "valid_json": true,
      "schema_id": "phase7_mainnet_cutover_run_summary",
      "schema_valid": true,
      "raw_status": "pass",
      "raw_rc": 0,
      "signal_snapshot": {
        "mainnet_activation_gate_go": true,
        "bootstrap_governance_graduation_gate_go": true,
        "tdpnd_grpc_live_smoke_ok": true,
        "module_tx_surface_ok": true,
        "tdpnd_grpc_auth_live_smoke_ok": true,
        "tdpnd_comet_runtime_smoke_ok": true,
        "cosmos_module_coverage_floor_ok": true,
        "cosmos_keeper_coverage_floor_ok": true,
        "cosmos_app_coverage_floor_ok": true,
        "dual_write_parity_ok": true
      },
      "status": "pass"
    },
    "handoff_check": {
      "configured": true,
      "exists": true,
      "valid_json": true,
      "schema_id": "phase7_mainnet_cutover_handoff_check_summary",
      "schema_valid": true,
      "raw_status": "pass",
      "raw_rc": 0,
      "signal_snapshot": {
        "mainnet_activation_gate_go": true,
        "bootstrap_governance_graduation_gate_go": true,
        "tdpnd_grpc_live_smoke_ok": true,
        "module_tx_surface_ok": true,
        "tdpnd_grpc_auth_live_smoke_ok": true,
        "tdpnd_comet_runtime_smoke_ok": true,
        "cosmos_module_coverage_floor_ok": true,
        "cosmos_keeper_coverage_floor_ok": true,
        "cosmos_app_coverage_floor_ok": true,
        "dual_write_parity_ok": true
      },
      "status": "pass"
    },
    "handoff_run": {
      "configured": true,
      "exists": true,
      "valid_json": true,
      "schema_id": "phase7_mainnet_cutover_handoff_run_summary",
      "schema_valid": true,
      "raw_status": "pass",
      "raw_rc": 0,
      "signal_snapshot": {
        "mainnet_activation_gate_go": true,
        "bootstrap_governance_graduation_gate_go": true,
        "tdpnd_grpc_live_smoke_ok": true,
        "module_tx_surface_ok": true,
        "tdpnd_grpc_auth_live_smoke_ok": true,
        "tdpnd_comet_runtime_smoke_ok": true,
        "cosmos_module_coverage_floor_ok": true,
        "cosmos_keeper_coverage_floor_ok": true,
        "cosmos_app_coverage_floor_ok": true,
        "dual_write_parity_ok": true
      },
      "status": "pass"
    }
  }
}
EOF_PHASE7_SUMMARY_REPORT
cp "$PHASE7_MAINNET_CUTOVER_CHECK_SUMMARY_JSON" "$ROADMAP_PROGRESS_TEST_LOGS_ROOT/phase7_mainnet_cutover_check_summary.json"
cp "$PHASE7_MAINNET_CUTOVER_RUN_SUMMARY_JSON" "$ROADMAP_PROGRESS_TEST_LOGS_ROOT/phase7_mainnet_cutover_run_summary.json"
cp "$PHASE7_MAINNET_CUTOVER_HANDOFF_CHECK_SUMMARY_JSON" "$ROADMAP_PROGRESS_TEST_LOGS_ROOT/phase7_mainnet_cutover_handoff_check_summary.json"
cp "$PHASE7_MAINNET_CUTOVER_HANDOFF_RUN_SUMMARY_JSON" "$ROADMAP_PROGRESS_TEST_LOGS_ROOT/phase7_mainnet_cutover_handoff_run_summary.json"
cp "$PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON" "$ROADMAP_PROGRESS_TEST_LOGS_ROOT/phase7_mainnet_cutover_summary_report.json"

BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON="$TMP_DIR/blockchain_mainnet_activation_gate_summary.json"
cat >"$BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON" <<'EOF_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "NO-GO",
  "decision": {
    "pass": false,
    "go": false,
    "no_go": true,
    "reasons": [
      "12-week measurement window is still in progress",
      "validator and economics thresholds remain below go/no-go policy"
    ]
  },
  "reasons": [
    "12-week measurement window is still in progress",
    "validator and economics thresholds remain below go/no-go policy"
  ],
  "source_paths": [
    "./artifacts/blockchain/mainnet-activation-metrics/metrics.json"
  ]
}
EOF_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY

BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON="$TMP_DIR/blockchain_bootstrap_governance_graduation_gate_summary.json"
cat >"$BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON" <<'EOF_BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "bootstrap_governance_graduation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "GO",
  "decision": {
    "pass": true,
    "go": true,
    "no_go": false,
    "reasons": [
      "bootstrap governance graduation readiness met"
    ]
  },
  "source_paths": [
    "./artifacts/blockchain/bootstrap-governance-graduation/summary.json"
  ]
}
EOF_BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY

BLOCKCHAIN_MAINNET_ACTIVATION_GATE_INVALID_SUMMARY_JSON="$TMP_DIR/blockchain_mainnet_activation_gate_invalid_summary.json"
printf '{"version":1,' >"$BLOCKCHAIN_MAINNET_ACTIVATION_GATE_INVALID_SUMMARY_JSON"
BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_INVALID_SUMMARY_JSON="$TMP_DIR/blockchain_bootstrap_governance_graduation_gate_invalid_summary.json"
printf '{"version":1,' >"$BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_INVALID_SUMMARY_JSON"
PHASE7_MAINNET_CUTOVER_INVALID_SUMMARY_REPORT_JSON="$TMP_DIR/phase7_mainnet_cutover_invalid_summary_report.json"
printf '{"version":1,' >"$PHASE7_MAINNET_CUTOVER_INVALID_SUMMARY_REPORT_JSON"

FAKE_ROADMAP_CAPTURE_FILE="$CAPTURE" \
ROADMAP_PROGRESS_MANUAL_VALIDATION_REPORT_SCRIPT="$FAKE_MANUAL" \
ROADMAP_PROGRESS_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
run_roadmap_progress_report \
  --refresh-manual-validation 1 \
  --refresh-single-machine-readiness 0 \
  --phase0-summary-json "$PHASE0_SUMMARY_JSON" \
  --phase5-settlement-layer-summary-json "$PHASE5_SETTLEMENT_LAYER_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "$PHASE7_MAINNET_CUTOVER_SUMMARY_REPORT_JSON" \
  --blockchain-mainnet-activation-gate-summary-json "$BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON" \
  --blockchain-bootstrap-governance-graduation-gate-summary-json "$BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON" \
  --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log 2>&1

if ! rg -q '\[roadmap-progress-report\] status=warn rc=0' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected warn status in success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
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
  and .vpn_track.vpn_rc_done_for_phase == false
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
  and .blockchain_track.mainnet_activation_missing_metrics_action.available == false
  and .blockchain_track.mainnet_activation_missing_metrics_action.id == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.reason == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.normalize_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.rerun_bundle_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.checklist_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.missing_input_template_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.template_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.prefill_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.cycle_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.seeded_cycle_command == null
  and (.blockchain_track.mainnet_activation_missing_metrics_action.real_evidence_run_command // null) == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.available == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.status == "pass"
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok == false
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok_source == "dedicated-mainnet-activation-gate-summary"
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok_source == "dedicated-bootstrap-governance-graduation-gate-summary"
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_live_smoke_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.module_tx_surface_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_auth_live_smoke_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_comet_runtime_smoke_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_module_coverage_floor_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_keeper_coverage_floor_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_app_coverage_floor_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.dual_write_parity_ok == true
  and (.next_actions | length) >= 1
  and (.next_actions[0].id // "") == "machine_c_vpn_smoke"
  and (.next_actions[1].id // "") == "profile_default_gate"
  and (((.next_actions // []) | any(.id == "three_machine_docker_readiness")) | not)
  and (((.next_actions // []) | any(.id == "real_wg_privileged_matrix")) | not)
  and (((.next_actions // []) | any(.id == "blockchain_mainnet_activation_missing_metrics")) | not)
  and (.vpn_track.profile_default_gate | has("selection_policy_evidence_present"))
  and (.vpn_track.profile_default_gate | has("selection_policy_evidence_valid"))
  and (.vpn_track.profile_default_gate | has("micro_relay_evidence_available"))
  and (.vpn_track.profile_default_gate | has("micro_relay_quality_status_pass"))
  and (.vpn_track.profile_default_gate | has("micro_relay_demotion_policy_present"))
  and (.vpn_track.profile_default_gate | has("micro_relay_promotion_policy_present"))
  and (.vpn_track.profile_default_gate | has("trust_tier_port_unlock_policy_present"))
  and (.vpn_track.profile_default_gate | has("micro_relay_evidence_note"))
  and (
    (.vpn_track.profile_default_gate.selection_policy_evidence_present == null)
    or ((.vpn_track.profile_default_gate.selection_policy_evidence_present | type) == "boolean")
  )
  and (
    (.vpn_track.profile_default_gate.selection_policy_evidence_valid == null)
    or ((.vpn_track.profile_default_gate.selection_policy_evidence_valid | type) == "boolean")
  )
  and ((.vpn_track.profile_default_gate.micro_relay_evidence_available | type) == "boolean")
  and (
    (.vpn_track.profile_default_gate.micro_relay_quality_status_pass == null)
    or ((.vpn_track.profile_default_gate.micro_relay_quality_status_pass | type) == "boolean")
  )
  and ((.vpn_track.profile_default_gate.micro_relay_demotion_policy_present | type) == "boolean")
  and ((.vpn_track.profile_default_gate.micro_relay_promotion_policy_present | type) == "boolean")
  and ((.vpn_track.profile_default_gate.trust_tier_port_unlock_policy_present | type) == "boolean")
  and (
    (.vpn_track.profile_default_gate.micro_relay_evidence_note == null)
    or ((.vpn_track.profile_default_gate.micro_relay_evidence_note | type) == "string")
  )
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
  and .vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_ok == true
  and .artifacts.phase0_summary_json == "'"$PHASE0_SUMMARY_JSON"'"
  and .artifacts.manual_validation_summary_json == "'"$TEST_LOG_DIR/manual_validation_readiness_summary.json"'"
  and .artifacts.manual_validation_report_md == "'"$TEST_LOG_DIR/manual_validation_readiness_report.md"'"
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
    and .blockchain_track.phase6_cosmos_l1_handoff.tdpnd_comet_runtime_smoke_ok == true
    and .artifacts.phase6_cosmos_l1_summary_json == "'"$PHASE6_COSMOS_L1_SUMMARY_JSON"'"
  ' "$SUMMARY_JSON" >/dev/null; then
    echo "summary JSON missing expected phase6 fields"
    cat "$SUMMARY_JSON"
    exit 1
  fi
fi
PHASE7_OUTPUT_PRESENT=0
if jq -e '.blockchain_track.phase7_mainnet_cutover.available == true' "$SUMMARY_JSON" >/dev/null 2>&1; then
  PHASE7_OUTPUT_PRESENT=1
fi
if [[ "$PHASE7_OUTPUT_PRESENT" == "1" ]]; then
  if ! jq -e '
    .blockchain_track.phase7_mainnet_cutover.available == true
    and .blockchain_track.phase7_mainnet_cutover.status == "pass"
    and .blockchain_track.phase7_mainnet_cutover.rc == 0
    and .blockchain_track.phase7_mainnet_cutover.check == true
    and .blockchain_track.phase7_mainnet_cutover.run == true
    and .blockchain_track.phase7_mainnet_cutover.handoff_check == true
    and .blockchain_track.phase7_mainnet_cutover.handoff_run == true
  ' "$SUMMARY_JSON" >/dev/null; then
    echo "summary JSON missing expected phase7 fields"
    cat "$SUMMARY_JSON"
    exit 1
  fi
fi
if ! jq -e '
  .blockchain_track.mainnet_activation_gate.available == true
  and .blockchain_track.mainnet_activation_gate.status == "NO-GO"
   and .blockchain_track.mainnet_activation_gate.decision == "NO-GO"
   and .blockchain_track.mainnet_activation_gate.go == false
   and .blockchain_track.mainnet_activation_gate.no_go == true
   and (.blockchain_track.mainnet_activation_gate.reasons | length) == 2
   and (.blockchain_track.mainnet_activation_gate.source_paths | length) == 1
   and ((.blockchain_track.mainnet_activation_gate.source_paths // []) | index("./artifacts/blockchain/mainnet-activation-metrics/metrics.json")) != null
   and .blockchain_track.mainnet_activation_gate.source_summary_json == "'"$BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON"'"
   and .blockchain_track.mainnet_activation_gate.source_summary_kind == "mainnet-activation-gate-summary"
 ' "$SUMMARY_JSON" >/dev/null; then
  echo "summary JSON missing expected mainnet activation gate fields"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! jq -e '
  .blockchain_track.bootstrap_governance_graduation_gate.available == true
  and .blockchain_track.bootstrap_governance_graduation_gate.status == "GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.decision == "GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.go == true
  and .blockchain_track.bootstrap_governance_graduation_gate.no_go == false
  and (.blockchain_track.bootstrap_governance_graduation_gate.reasons | length) == 1
  and ((.blockchain_track.bootstrap_governance_graduation_gate.source_paths // []) | index("./artifacts/blockchain/bootstrap-governance-graduation/summary.json")) != null
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_json == "'"$BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON"'"
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_kind == "bootstrap-governance-graduation-gate-summary"
' "$SUMMARY_JSON" >/dev/null; then
  echo "summary JSON missing expected bootstrap governance graduation gate fields"
  cat "$SUMMARY_JSON"
  exit 1
fi

echo "[roadmap-progress-report] blockchain freshness fresh-vs-stale go behavior"
MINIMAL_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_minimal_summary_for_gate_tests.json"
cat >"$MINIMAL_MANUAL_SUMMARY_JSON" <<'EOF_MINIMAL_SUMMARY_GATE'
{"version":1,"summary":{"next_action_check_id":"machine_c_vpn_smoke"},"report":{"readiness_status":"NOT_READY"}}
EOF_MINIMAL_SUMMARY_GATE
FRESH_MAINNET_GATE_SUMMARY_JSON="$TMP_DIR/blockchain_mainnet_activation_gate_fresh_summary.json"
FRESH_BOOTSTRAP_GATE_SUMMARY_JSON="$TMP_DIR/blockchain_bootstrap_governance_graduation_gate_fresh_summary.json"
STALE_MAINNET_GATE_SUMMARY_JSON="$TMP_DIR/blockchain_mainnet_activation_gate_stale_summary.json"
current_epoch="$(date -u +%s)"
fresh_epoch=$((current_epoch - 3600))
stale_epoch=$((current_epoch - 172800))
fresh_iso="$(date -u -d "@$fresh_epoch" +%Y-%m-%dT%H:%M:%SZ)"

cat >"$FRESH_MAINNET_GATE_SUMMARY_JSON" <<EOF_FRESH_MAINNET
{
  "version": 1,
  "schema": {
    "id": "mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "generated_at": "$fresh_iso",
  "status": "GO",
  "decision": {
    "pass": true,
    "go": true,
    "no_go": false,
    "reasons": [
      "fresh activation evidence"
    ]
  },
  "reasons": [
    "fresh activation evidence"
  ],
  "source_paths": [
    "./artifacts/blockchain/mainnet-activation-metrics/metrics.json"
  ]
}
EOF_FRESH_MAINNET

cat >"$FRESH_BOOTSTRAP_GATE_SUMMARY_JSON" <<EOF_FRESH_BOOTSTRAP
{
  "version": 1,
  "schema": {
    "id": "bootstrap_governance_graduation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "generated_at": "$fresh_iso",
  "status": "GO",
  "decision": {
    "pass": true,
    "go": true,
    "no_go": false,
    "reasons": [
      "fresh bootstrap governance evidence"
    ]
  },
  "source_paths": [
    "./artifacts/blockchain/bootstrap-governance-graduation/summary.json"
  ]
}
EOF_FRESH_BOOTSTRAP

cat >"$STALE_MAINNET_GATE_SUMMARY_JSON" <<'EOF_STALE_MAINNET'
{
  "version": 1,
  "schema": {
    "id": "mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "GO",
  "decision": {
    "pass": true,
    "go": true,
    "no_go": false,
    "reasons": [
      "stale activation evidence"
    ]
  },
  "reasons": [
    "stale activation evidence"
  ],
  "source_paths": [
    "./artifacts/blockchain/mainnet-activation-metrics/metrics.json"
  ]
}
EOF_STALE_MAINNET
touch -d "@$stale_epoch" "$STALE_MAINNET_GATE_SUMMARY_JSON"

FRESH_SUMMARY_JSON="$TMP_DIR/roadmap_progress_mainnet_activation_gate_fresh_summary.json"
FRESH_REPORT_MD="$TMP_DIR/roadmap_progress_mainnet_activation_gate_fresh_report.md"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase0-summary-json "$PHASE0_SUMMARY_JSON" \
  --phase5-settlement-layer-summary-json "$PHASE5_SETTLEMENT_LAYER_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --blockchain-mainnet-activation-gate-summary-json "$FRESH_MAINNET_GATE_SUMMARY_JSON" \
  --blockchain-bootstrap-governance-graduation-gate-summary-json "$FRESH_BOOTSTRAP_GATE_SUMMARY_JSON" \
  --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
  --summary-json "$FRESH_SUMMARY_JSON" \
  --report-md "$FRESH_REPORT_MD" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_fresh.log 2>&1; then
  echo "expected success for fresh blockchain freshness summary"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_fresh.log
  exit 1
fi
if ! jq -e --arg fresh_iso "$fresh_iso" '
  .blockchain_track.mainnet_activation_gate.available == true
  and .blockchain_track.mainnet_activation_gate.status == "GO"
  and .blockchain_track.mainnet_activation_gate.decision == "GO"
  and .blockchain_track.mainnet_activation_gate.go == true
  and .blockchain_track.mainnet_activation_gate.no_go == false
  and .blockchain_track.mainnet_activation_gate.summary_generated_at == $fresh_iso
  and (.blockchain_track.mainnet_activation_gate.summary_age_sec | tonumber) >= 3500
  and (.blockchain_track.mainnet_activation_gate.summary_age_sec | tonumber) <= 3705
  and .blockchain_track.mainnet_activation_gate.summary_stale == false
  and .blockchain_track.mainnet_activation_gate.summary_max_age_sec == 86400
  and .blockchain_track.bootstrap_governance_graduation_gate.summary_generated_at == $fresh_iso
  and (.blockchain_track.bootstrap_governance_graduation_gate.summary_age_sec | tonumber) >= 3500
  and (.blockchain_track.bootstrap_governance_graduation_gate.summary_age_sec | tonumber) <= 3705
  and .blockchain_track.bootstrap_governance_graduation_gate.summary_stale == false
  and .blockchain_track.bootstrap_governance_graduation_gate.summary_max_age_sec == 86400
  and .blockchain_track.mainnet_activation_stale_evidence.status == "fresh"
  and .blockchain_track.mainnet_activation_stale_evidence.action_required == false
  and .blockchain_track.mainnet_activation_stale_evidence.reason == null
  and .blockchain_track.mainnet_activation_stale_evidence.refresh_command == null
  and .blockchain_track.mainnet_activation_refresh_evidence_action.available == false
  and .blockchain_track.mainnet_activation_refresh_evidence_action.id == null
  and .blockchain_track.mainnet_activation_refresh_evidence_action.reason == null
  and .blockchain_track.mainnet_activation_refresh_evidence_action.command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.id == null
  and .blockchain_track.recommended_gate_id == null
  and .blockchain_track.recommended_gate_reason == null
  and .blockchain_track.recommended_gate_command == null
  and (((.next_actions // []) | any(.id == "blockchain_mainnet_activation_refresh_evidence")) | not)
' "$FRESH_SUMMARY_JSON" >/dev/null; then
  echo "fresh blockchain freshness summary missing expected fields"
  cat "$FRESH_SUMMARY_JSON"
  exit 1
fi

STALE_SUMMARY_JSON="$TMP_DIR/roadmap_progress_mainnet_activation_gate_stale_summary.json"
STALE_REPORT_MD="$TMP_DIR/roadmap_progress_mainnet_activation_gate_stale_report.md"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase0-summary-json "$PHASE0_SUMMARY_JSON" \
  --phase5-settlement-layer-summary-json "$PHASE5_SETTLEMENT_LAYER_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --blockchain-mainnet-activation-gate-summary-json "$STALE_MAINNET_GATE_SUMMARY_JSON" \
  --blockchain-bootstrap-governance-graduation-gate-summary-json "$FRESH_BOOTSTRAP_GATE_SUMMARY_JSON" \
  --single-machine-summary-json "$SINGLE_MACHINE_SUMMARY_JSON" \
  --summary-json "$STALE_SUMMARY_JSON" \
  --report-md "$STALE_REPORT_MD" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_stale.log 2>&1; then
  echo "expected success for stale blockchain freshness summary"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_stale.log
  exit 1
fi
if ! jq -e --arg stale_reason "stale activation evidence" '
  .blockchain_track.mainnet_activation_gate.available == true
  and .blockchain_track.mainnet_activation_gate.status == "GO"
  and .blockchain_track.mainnet_activation_gate.decision == "GO"
  and .blockchain_track.mainnet_activation_gate.go == true
  and .blockchain_track.mainnet_activation_gate.no_go == false
  and .blockchain_track.mainnet_activation_gate.summary_generated_at == null
  and (.blockchain_track.mainnet_activation_gate.summary_age_sec | tonumber) >= 172800
  and .blockchain_track.mainnet_activation_gate.summary_stale == true
  and .blockchain_track.mainnet_activation_gate.summary_max_age_sec == 86400
  and .blockchain_track.bootstrap_governance_graduation_gate.summary_stale == false
  and .blockchain_track.mainnet_activation_stale_evidence.status == "stale"
  and .blockchain_track.mainnet_activation_stale_evidence.action_required == true
  and ((.blockchain_track.mainnet_activation_stale_evidence.reason // "") | contains($stale_reason))
  and .blockchain_track.mainnet_activation_stale_evidence.refresh_command == "./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run --input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json --reports-dir .easy-node-logs/blockchain_mainnet_activation_real_evidence_run --summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_latest_summary.json --canonical-summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_summary.json --refresh-roadmap 1 --print-summary-json 1"
  and .blockchain_track.mainnet_activation_refresh_evidence_action.available == true
  and .blockchain_track.mainnet_activation_refresh_evidence_action.id == "blockchain_mainnet_activation_refresh_evidence"
  and ((.blockchain_track.mainnet_activation_refresh_evidence_action.reason // "") | contains($stale_reason))
  and (.blockchain_track.mainnet_activation_refresh_evidence_action.command // "") == "./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run --input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json --reports-dir .easy-node-logs/blockchain_mainnet_activation_real_evidence_run --summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_latest_summary.json --canonical-summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_summary.json --refresh-roadmap 1 --print-summary-json 1"
  and .blockchain_track.mainnet_activation_missing_metrics_action.available == false
  and .blockchain_track.mainnet_activation_missing_metrics_action.id == "blockchain_mainnet_activation_refresh_evidence"
  and .blockchain_track.recommended_gate_id == "blockchain_mainnet_activation_refresh_evidence"
  and ((.blockchain_track.recommended_gate_reason // "") | contains($stale_reason))
  and .blockchain_track.recommended_gate_command == "./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run --input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json --reports-dir .easy-node-logs/blockchain_mainnet_activation_real_evidence_run --summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_latest_summary.json --canonical-summary-json .easy-node-logs/blockchain_mainnet_activation_real_evidence_run_summary.json --refresh-roadmap 1 --print-summary-json 1"
  and ((.next_actions // []) | any(.id == "blockchain_mainnet_activation_refresh_evidence" and ((.reason // "") | contains($stale_reason))))
' "$STALE_SUMMARY_JSON" >/dev/null; then
  echo "stale blockchain freshness summary missing expected refresh action"
  cat "$STALE_SUMMARY_JSON"
  exit 1
fi
if ! rg -q 'Blockchain recommended actionable gate id: blockchain_mainnet_activation_refresh_evidence' "$STALE_REPORT_MD"; then
  echo "stale blockchain report missing recommended actionable gate id line"
  cat "$STALE_REPORT_MD"
  exit 1
fi
if ! rg -q 'Mainnet activation stale evidence action required: true' "$STALE_REPORT_MD"; then
  echo "stale blockchain report missing stale evidence action-required line"
  cat "$STALE_REPORT_MD"
  exit 1
fi
if ! rg -q 'Mainnet activation stale evidence refresh command: ./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run ' "$STALE_REPORT_MD"; then
  echo "stale blockchain report missing stale evidence refresh command line"
  cat "$STALE_REPORT_MD"
  exit 1
fi
if ! rg -q 'mainnet_activation_stale_evidence_status=stale action_required=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_stale.log; then
  echo "stale blockchain freshness log missing stale evidence operator-action line"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_stale.log
  exit 1
fi
if ! rg -q 'blockchain_recommended_gate_id=blockchain_mainnet_activation_refresh_evidence' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_stale.log; then
  echo "stale blockchain freshness log missing recommended gate line"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_stale.log
  exit 1
fi

if ! rg -q '\[roadmap-progress-report\] refresh_step=manual_validation_report status=running' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected manual refresh running heartbeat line"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] refresh_step=manual_validation_report status=pass rc=0 timed_out=false' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected manual refresh completion heartbeat line"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q 'phase7_mainnet_cutover_summary_status=.*mainnet_activation_gate_go_ok=false.*mainnet_activation_gate_go_ok_source=dedicated-mainnet-activation-gate-summary.*bootstrap_governance_graduation_gate_go_ok=true.*bootstrap_governance_graduation_gate_go_ok_source=dedicated-bootstrap-governance-graduation-gate-summary' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected phase7 heartbeat log line to include dedicated gate-aligned signals"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q 'blockchain_mainnet_activation_missing_metrics_action_available=false' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected neutral blockchain missing-metrics actionable log line in default success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
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
if ! rg -q 'VPN RC done for phase: `false`' "$REPORT_MD"; then
  echo "report markdown missing VPN RC done signal"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Pending real-host checks: machine_c_vpn_smoke,three_machine_prod_signoff' "$REPORT_MD"; then
  echo "report markdown missing pending real-host check list"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Profile gate selection-policy evidence present: null' "$REPORT_MD"; then
  echo "report markdown missing profile gate selection-policy evidence present line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Profile gate selection-policy evidence note: selection-policy evidence unavailable' "$REPORT_MD"; then
  echo "report markdown missing profile gate selection-policy evidence guidance note"
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
if ! rg -q 'Phase-5 issuer_settlement_status_live_smoke_status: pass' "$REPORT_MD"; then
  echo "report markdown missing phase5 issuer_settlement_status_live_smoke_status line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 issuer_settlement_status_live_smoke_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase5 issuer_settlement_status_live_smoke_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 issuer_admin_blockchain_handlers_coverage_status: pass' "$REPORT_MD"; then
  echo "report markdown missing phase5 issuer_admin_blockchain_handlers_coverage_status line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 issuer_admin_blockchain_handlers_coverage_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase5 issuer_admin_blockchain_handlers_coverage_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 settlement_dual_asset_parity_status: pass' "$REPORT_MD"; then
  echo "report markdown missing phase5 settlement_dual_asset_parity_status line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 settlement_dual_asset_parity_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase5 settlement_dual_asset_parity_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 settlement_adapter_signed_tx_roundtrip_status: pass' "$REPORT_MD"; then
  echo "report markdown missing phase5 settlement_adapter_signed_tx_roundtrip_status line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 settlement_adapter_signed_tx_roundtrip_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase5 settlement_adapter_signed_tx_roundtrip_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 settlement_shadow_env_status: pass' "$REPORT_MD"; then
  echo "report markdown missing phase5 settlement_shadow_env_status line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 settlement_shadow_env_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase5 settlement_shadow_env_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 settlement_shadow_status_surface_status: pass' "$REPORT_MD"; then
  echo "report markdown missing phase5 settlement_shadow_status_surface_status line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 settlement_shadow_status_surface_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase5 settlement_shadow_status_surface_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 exit_settlement_status_live_smoke_status: pass' "$REPORT_MD"; then
  echo "report markdown missing phase5 exit_settlement_status_live_smoke_status line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-5 exit_settlement_status_live_smoke_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase5 exit_settlement_status_live_smoke_ok line"
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
if [[ "$PHASE7_OUTPUT_PRESENT" == "1" ]]; then
  if ! rg -q 'Phase-7|phase7_mainnet_cutover' "$REPORT_MD"; then
    echo "report markdown missing phase7 line"
    cat "$REPORT_MD"
    exit 1
  fi
fi
if ! rg -q 'Phase-7 mainnet cutover mainnet_activation_gate_go_ok: false' "$REPORT_MD"; then
  echo "report markdown missing phase7 mainnet_activation_gate_go_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover mainnet_activation_gate_go_ok source: dedicated-mainnet-activation-gate-summary' "$REPORT_MD"; then
  echo "report markdown missing phase7 mainnet_activation_gate_go_ok source line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover bootstrap_governance_graduation_gate_go_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase7 bootstrap_governance_graduation_gate_go_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover bootstrap_governance_graduation_gate_go_ok source: dedicated-bootstrap-governance-graduation-gate-summary' "$REPORT_MD"; then
  echo "report markdown missing phase7 bootstrap_governance_graduation_gate_go_ok source line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover tdpnd_grpc_live_smoke_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase7 tdpnd_grpc_live_smoke_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover module_tx_surface_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase7 module_tx_surface_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover tdpnd_grpc_auth_live_smoke_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase7 tdpnd_grpc_auth_live_smoke_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover tdpnd_comet_runtime_smoke_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase7 tdpnd_comet_runtime_smoke_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover cosmos_module_coverage_floor_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase7 cosmos_module_coverage_floor_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover cosmos_keeper_coverage_floor_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase7 cosmos_keeper_coverage_floor_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover cosmos_app_coverage_floor_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase7 cosmos_app_coverage_floor_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Phase-7 mainnet cutover dual_write_parity_ok: true' "$REPORT_MD"; then
  echo "report markdown missing phase7 dual_write_parity_ok line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Mainnet activation gate|mainnet_activation_gate' "$REPORT_MD"; then
  echo "report markdown missing mainnet activation gate line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Mainnet activation missing-metrics action available: false' "$REPORT_MD"; then
  echo "report markdown missing neutral mainnet activation missing-metrics actionable line"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Bootstrap governance graduation gate|bootstrap_governance_graduation_gate' "$REPORT_MD"; then
  echo "report markdown missing bootstrap governance graduation gate line"
  cat "$REPORT_MD"
  exit 1
fi

echo "[roadmap-progress-report] blockchain mainnet activation gate missing summary path"
MINIMAL_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_minimal_summary_for_gate_tests.json"
cat >"$MINIMAL_MANUAL_SUMMARY_JSON" <<'EOF_MINIMAL_SUMMARY_GATE'
{"version":1,"summary":{"next_action_check_id":"machine_c_vpn_smoke"},"report":{"readiness_status":"NOT_READY"}}
EOF_MINIMAL_SUMMARY_GATE
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --blockchain-mainnet-activation-gate-summary-json "$ROADMAP_PROGRESS_MISSING_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_mainnet_activation_gate_missing_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_mainnet_activation_gate_missing_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_missing.log 2>&1; then
  echo "expected success when mainnet activation gate summary is missing"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_missing.log
  exit 1
fi
if ! jq -e '
  .blockchain_track.phase7_mainnet_cutover_summary_report.available == false
  and .blockchain_track.phase7_mainnet_cutover_summary_report.status == "missing"
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok_source == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok_source == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_live_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.module_tx_surface_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_auth_live_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_comet_runtime_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_module_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_keeper_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_app_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.dual_write_parity_ok == null
  and
  .blockchain_track.mainnet_activation_gate.available == false
  and .blockchain_track.mainnet_activation_gate.status == "missing"
  and .blockchain_track.mainnet_activation_gate.decision == null
  and .blockchain_track.mainnet_activation_gate.go == null
  and .blockchain_track.mainnet_activation_gate.no_go == null
  and (.blockchain_track.mainnet_activation_gate.reasons | length) == 0
  and (.blockchain_track.mainnet_activation_gate.source_paths | length) == 0
  and .blockchain_track.mainnet_activation_gate.input_summary_json == "'"$ROADMAP_PROGRESS_MISSING_BLOCKCHAIN_MAINNET_ACTIVATION_GATE_SUMMARY_JSON"'"
  and .blockchain_track.mainnet_activation_gate.source_summary_json == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.available == false
  and .blockchain_track.mainnet_activation_missing_metrics_action.id == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.reason == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.normalize_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.rerun_bundle_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.checklist_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.missing_input_template_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.template_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.prefill_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.cycle_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.seeded_cycle_command == null
  and (.blockchain_track.mainnet_activation_missing_metrics_action.real_evidence_run_command // null) == null
' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_missing_summary.json" >/dev/null; then
  echo "missing gate summary JSON missing expected fallback fields"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_missing_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain bootstrap governance graduation gate missing summary path"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --blockchain-bootstrap-governance-graduation-gate-summary-json "$ROADMAP_PROGRESS_MISSING_BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_missing_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_missing_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_bootstrap_governance_graduation_gate_missing.log 2>&1; then
  echo "expected success when bootstrap governance graduation gate summary is missing"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_bootstrap_governance_graduation_gate_missing.log
  exit 1
fi
if ! jq -e '
  .blockchain_track.bootstrap_governance_graduation_gate.available == false
  and .blockchain_track.bootstrap_governance_graduation_gate.status == "missing"
  and .blockchain_track.bootstrap_governance_graduation_gate.decision == null
  and .blockchain_track.bootstrap_governance_graduation_gate.go == null
  and .blockchain_track.bootstrap_governance_graduation_gate.no_go == null
  and (.blockchain_track.bootstrap_governance_graduation_gate.reasons | length) == 0
  and (.blockchain_track.bootstrap_governance_graduation_gate.source_paths | length) == 0
  and .blockchain_track.bootstrap_governance_graduation_gate.input_summary_json == "'"$ROADMAP_PROGRESS_MISSING_BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON"'"
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_json == null
' "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_missing_summary.json" >/dev/null; then
  echo "missing bootstrap governance graduation gate summary JSON missing expected fallback fields"
  cat "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_missing_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain mainnet activation gate phase7 signal fallback path"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "$PHASE7_MAINNET_CUTOVER_CHECK_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_mainnet_activation_gate_phase7_signal_fallback_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_mainnet_activation_gate_phase7_signal_fallback_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_phase7_signal_fallback.log 2>&1; then
  echo "expected success when mainnet activation gate is derived from phase7 signal"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_phase7_signal_fallback.log
  exit 1
fi
if ! jq -e --arg src "$PHASE7_MAINNET_CUTOVER_CHECK_SUMMARY_JSON" '
  .blockchain_track.phase7_mainnet_cutover_summary_report.available == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok_source == "phase7-mainnet-cutover-summary-signal"
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok_source == "phase7-mainnet-cutover-summary-signal"
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_live_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.module_tx_surface_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_auth_live_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_comet_runtime_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_module_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_keeper_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_app_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.dual_write_parity_ok == null
  and .blockchain_track.mainnet_activation_gate.available == true
  and .blockchain_track.mainnet_activation_gate.status == "go"
  and .blockchain_track.mainnet_activation_gate.decision == "GO"
  and .blockchain_track.mainnet_activation_gate.go == true
  and .blockchain_track.mainnet_activation_gate.no_go == false
  and (.blockchain_track.mainnet_activation_gate.reasons | length) == 0
  and .blockchain_track.mainnet_activation_gate.input_summary_json == $src
  and .blockchain_track.mainnet_activation_gate.source_summary_json == $src
  and .blockchain_track.mainnet_activation_gate.source_summary_kind == "phase7-mainnet-cutover-signal"
  and ((.blockchain_track.mainnet_activation_gate.source_paths // []) | index($src)) != null
  and .blockchain_track.mainnet_activation_missing_metrics_action.available == false
  and .blockchain_track.mainnet_activation_missing_metrics_action.id == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.reason == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.normalize_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.rerun_bundle_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.checklist_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.missing_input_template_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.template_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.prefill_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command == null
    and .blockchain_track.mainnet_activation_missing_metrics_action.cycle_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.seeded_cycle_command == null
  and (.blockchain_track.mainnet_activation_missing_metrics_action.real_evidence_run_command // null) == null
  and .blockchain_track.bootstrap_governance_graduation_gate.available == true
  and .blockchain_track.bootstrap_governance_graduation_gate.status == "GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.decision == "GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.go == true
  and .blockchain_track.bootstrap_governance_graduation_gate.no_go == false
  and (.blockchain_track.bootstrap_governance_graduation_gate.reasons | length) == 0
  and .blockchain_track.bootstrap_governance_graduation_gate.input_summary_json == $src
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_json == $src
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_kind == "phase7-mainnet-cutover-signal"
  and ((.blockchain_track.bootstrap_governance_graduation_gate.source_paths // []) | index($src)) != null
' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_phase7_signal_fallback_summary.json" >/dev/null; then
  echo "phase7-signal fallback gate summary missing expected fields"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_phase7_signal_fallback_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain mainnet activation gate phase7 NO-GO signal fallback path"
PHASE7_MAINNET_CUTOVER_CHECK_NO_GO_SUMMARY_JSON="$TMP_DIR/phase7_mainnet_cutover_check_no_go_summary.json"
jq '
  .signals.mainnet_activation_gate_go = false
  | .signals.mainnet_activation_gate_go_ok = false
  | .signals.bootstrap_governance_graduation_gate_go = false
  | .signals.bootstrap_governance_graduation_gate_go_ok = false
  | .handoff.mainnet_activation_gate_go = false
  | .handoff.mainnet_activation_gate_go_ok = false
  | .handoff.bootstrap_governance_graduation_gate_go = false
  | .handoff.bootstrap_governance_graduation_gate_go_ok = false
  | .mainnet_activation_gate_go = false
  | .mainnet_activation_gate_go_ok = false
  | .bootstrap_governance_graduation_gate_go = false
  | .bootstrap_governance_graduation_gate_go_ok = false
' "$PHASE7_MAINNET_CUTOVER_CHECK_SUMMARY_JSON" >"$PHASE7_MAINNET_CUTOVER_CHECK_NO_GO_SUMMARY_JSON"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "$PHASE7_MAINNET_CUTOVER_CHECK_NO_GO_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_mainnet_activation_gate_phase7_signal_no_go_fallback_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_mainnet_activation_gate_phase7_signal_no_go_fallback_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_phase7_signal_no_go_fallback.log 2>&1; then
  echo "expected success when mainnet activation gate NO-GO is derived from phase7 signal"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_phase7_signal_no_go_fallback.log
  exit 1
fi
if ! jq -e --arg src "$PHASE7_MAINNET_CUTOVER_CHECK_NO_GO_SUMMARY_JSON" '
  .blockchain_track.phase7_mainnet_cutover_summary_report.available == true
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok == false
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok_source == "phase7-mainnet-cutover-summary-signal"
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok == false
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok_source == "phase7-mainnet-cutover-summary-signal"
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_live_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.module_tx_surface_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_auth_live_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_comet_runtime_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_module_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_keeper_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_app_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.dual_write_parity_ok == null
  and .blockchain_track.mainnet_activation_gate.available == true
  and .blockchain_track.mainnet_activation_gate.status == "no-go"
  and .blockchain_track.mainnet_activation_gate.decision == "NO-GO"
  and .blockchain_track.mainnet_activation_gate.go == false
  and .blockchain_track.mainnet_activation_gate.no_go == true
  and ((.blockchain_track.mainnet_activation_gate.reasons // []) | index("derived from phase7 mainnet_activation_gate_go signal=false")) != null
  and .blockchain_track.mainnet_activation_gate.input_summary_json == $src
  and .blockchain_track.mainnet_activation_gate.source_summary_json == $src
  and .blockchain_track.mainnet_activation_gate.source_summary_kind == "phase7-mainnet-cutover-signal"
  and ((.blockchain_track.mainnet_activation_gate.source_paths // []) | index($src)) != null
  and .blockchain_track.mainnet_activation_missing_metrics_action.available == false
  and .blockchain_track.mainnet_activation_missing_metrics_action.id == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.reason == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.normalize_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.rerun_bundle_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.checklist_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.missing_input_template_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.template_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.cycle_command == null
  and .blockchain_track.mainnet_activation_missing_metrics_action.seeded_cycle_command == null
  and (.blockchain_track.mainnet_activation_missing_metrics_action.real_evidence_run_command // null) == null
  and .blockchain_track.bootstrap_governance_graduation_gate.available == true
  and .blockchain_track.bootstrap_governance_graduation_gate.status == "NO-GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.decision == "NO-GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.go == false
  and .blockchain_track.bootstrap_governance_graduation_gate.no_go == true
  and ((.blockchain_track.bootstrap_governance_graduation_gate.reasons // []) | index("derived from phase7 bootstrap_governance_graduation_gate_go signal=false")) != null
  and .blockchain_track.bootstrap_governance_graduation_gate.input_summary_json == $src
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_json == $src
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_kind == "phase7-mainnet-cutover-signal"
  and ((.blockchain_track.bootstrap_governance_graduation_gate.source_paths // []) | index($src)) != null
' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_phase7_signal_no_go_fallback_summary.json" >/dev/null; then
  echo "phase7 NO-GO signal fallback gate summary missing expected fields"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_phase7_signal_no_go_fallback_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain mainnet activation gate invalid summary path"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "$PHASE7_MAINNET_CUTOVER_INVALID_SUMMARY_REPORT_JSON" \
  --blockchain-mainnet-activation-gate-summary-json "$BLOCKCHAIN_MAINNET_ACTIVATION_GATE_INVALID_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_mainnet_activation_gate_invalid_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_mainnet_activation_gate_invalid_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_invalid.log 2>&1; then
  echo "expected success when mainnet activation gate summary is invalid"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_invalid.log
  exit 1
fi
if ! jq -e '
  .blockchain_track.phase7_mainnet_cutover_summary_report.available == false
  and .blockchain_track.phase7_mainnet_cutover_summary_report.status == "invalid"
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.mainnet_activation_gate_go_ok_source == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.bootstrap_governance_graduation_gate_go_ok_source == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_live_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.module_tx_surface_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_grpc_auth_live_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.tdpnd_comet_runtime_smoke_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_module_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_keeper_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.cosmos_app_coverage_floor_ok == null
  and .blockchain_track.phase7_mainnet_cutover_summary_report.dual_write_parity_ok == null
  and
  .blockchain_track.mainnet_activation_gate.available == false
  and .blockchain_track.mainnet_activation_gate.status == "invalid"
  and .blockchain_track.mainnet_activation_gate.decision == null
  and .blockchain_track.mainnet_activation_gate.go == null
  and .blockchain_track.mainnet_activation_gate.no_go == null
  and (.blockchain_track.mainnet_activation_gate.reasons | length) == 0
  and (.blockchain_track.mainnet_activation_gate.source_paths | length) == 0
  and .blockchain_track.mainnet_activation_gate.input_summary_json == "'"$BLOCKCHAIN_MAINNET_ACTIVATION_GATE_INVALID_SUMMARY_JSON"'"
  and .blockchain_track.mainnet_activation_gate.source_summary_json == null
' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_invalid_summary.json" >/dev/null; then
  echo "invalid gate summary JSON missing expected fallback fields"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_invalid_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain bootstrap governance graduation gate invalid summary path"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --blockchain-bootstrap-governance-graduation-gate-summary-json "$BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_INVALID_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_invalid_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_invalid_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_bootstrap_governance_graduation_gate_invalid.log 2>&1; then
  echo "expected success when bootstrap governance graduation gate summary is invalid"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_bootstrap_governance_graduation_gate_invalid.log
  exit 1
fi
if ! jq -e '
  .blockchain_track.bootstrap_governance_graduation_gate.available == false
  and .blockchain_track.bootstrap_governance_graduation_gate.status == "invalid"
  and .blockchain_track.bootstrap_governance_graduation_gate.decision == null
  and .blockchain_track.bootstrap_governance_graduation_gate.go == null
  and .blockchain_track.bootstrap_governance_graduation_gate.no_go == null
  and (.blockchain_track.bootstrap_governance_graduation_gate.reasons | length) == 0
  and (.blockchain_track.bootstrap_governance_graduation_gate.source_paths | length) == 0
  and .blockchain_track.bootstrap_governance_graduation_gate.input_summary_json == "'"$BLOCKCHAIN_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_INVALID_SUMMARY_JSON"'"
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_json == null
' "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_invalid_summary.json" >/dev/null; then
  echo "invalid bootstrap governance graduation gate summary JSON missing expected fallback fields"
  cat "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_invalid_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain mainnet activation gate auto-discovery path"
AUTO_MAINNET_GATE_SUMMARY_JSON="$ROADMAP_PROGRESS_TEST_LOGS_ROOT/blockchain_mainnet_activation_gate_summary.json"
cat >"$AUTO_MAINNET_GATE_SUMMARY_JSON" <<'EOF_AUTO_MAINNET_GATE'
{
  "version": 1,
  "schema": {
    "id": "blockchain_mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "no-go",
  "decision": "NO-GO",
  "go": false,
  "no_go": true,
  "reasons": [
    "missing or invalid metric: paying_users_3mo_min",
    "missing or invalid metric: measurement_window_weeks"
  ],
  "source_paths": [
    "metrics_input"
  ]
}
EOF_AUTO_MAINNET_GATE
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --summary-json "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log 2>&1; then
  echo "expected success when mainnet activation gate summary is auto-discovered"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
  if ! jq -e --arg src "$AUTO_MAINNET_GATE_SUMMARY_JSON" '
    (.blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command // "") as $operator_pack_command
    | (.blockchain_track.mainnet_activation_missing_metrics_action.prefill_command // "") as $prefill_command
    | (.blockchain_track.mainnet_activation_missing_metrics_action.real_evidence_run_command // "") as $real_evidence_run_command
    | (if $real_evidence_run_command != "" then $real_evidence_run_command else $operator_pack_command end) as $preferred_missing_metrics_command
  | (.blockchain_track.mainnet_activation_missing_metrics_action.reason // "") as $missing_metrics_reason
  | .blockchain_track.mainnet_activation_gate.available == true
  and .blockchain_track.mainnet_activation_gate.status == "no-go"
  and .blockchain_track.mainnet_activation_gate.decision == "NO-GO"
  and .blockchain_track.mainnet_activation_gate.go == false
  and .blockchain_track.mainnet_activation_gate.no_go == true
  and .blockchain_track.mainnet_activation_gate.input_summary_json == $src
  and .blockchain_track.mainnet_activation_gate.source_summary_json == $src
  and ((.blockchain_track.mainnet_activation_gate.reasons // []) | index("missing or invalid metric: paying_users_3mo_min")) != null
  and ((.blockchain_track.mainnet_activation_gate.reasons // []) | index("missing or invalid metric: measurement_window_weeks")) != null
  and ((.blockchain_track.mainnet_activation_gate.source_paths // []) | index("metrics_input")) != null
  and .blockchain_track.mainnet_activation_missing_metrics_action.available == true
  and .blockchain_track.mainnet_activation_missing_metrics_action.id == "blockchain_mainnet_activation_missing_metrics"
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.reason // "") | contains("required metrics evidence is missing/invalid"))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.normalize_command // "") | startswith("./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input "))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.normalize_command // "") | contains("--input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json"))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.rerun_bundle_command // "") | startswith("./scripts/easy_node.sh blockchain-gate-bundle "))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.rerun_bundle_command // "") | contains("--blockchain-mainnet-activation-metrics-input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json"))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.checklist_command // "") | startswith("./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-checklist "))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.checklist_command // "") | contains("--metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json"))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.checklist_command // "") | contains("--print-summary-json 1"))
  and (((.blockchain_track.mainnet_activation_missing_metrics_action.checklist_command // "") | contains("--print-output-json")) | not)
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.missing_input_template_command // "") | startswith("./scripts/easy_node.sh blockchain-mainnet-activation-metrics-missing-input-template "))
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.missing_input_template_command // "") | contains("--metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json"))
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.missing_input_template_command // "") | contains("--print-summary-json 1"))
    and (((.blockchain_track.mainnet_activation_missing_metrics_action.missing_input_template_command // "") | contains("--print-output-json")) | not)
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.template_command // "") | startswith("./scripts/easy_node.sh blockchain-mainnet-activation-metrics-input-template "))
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.template_command // "") | contains("--output-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.template.json"))
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.template_command // "") | contains("--print-summary-json 1"))
    and (((.blockchain_track.mainnet_activation_missing_metrics_action.template_command // "") | contains("--print-output-json")) | not)
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.prefill_command // "") | startswith("./scripts/easy_node.sh blockchain-mainnet-activation-metrics-prefill "))
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.prefill_command // "") | contains("--output-json .easy-node-logs/blockchain_mainnet_activation_metrics_prefill.json"))
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.prefill_command // "") | contains("--print-summary-json 1"))
    and (((.blockchain_track.mainnet_activation_missing_metrics_action.prefill_command // "") | contains("--print-output-json")) | not)
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command // "") | startswith("./scripts/easy_node.sh blockchain-mainnet-activation-operator-pack "))
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command // "") | contains("--metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json"))
    and ((.blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command // "") | contains("--template-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.template.json"))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command // "") | contains("--missing-input-template-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.json"))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.operator_pack_command // "") | contains("--missing-input-template-canonical-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.canonical.json"))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.cycle_command // "") | startswith("./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle "))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.cycle_command // "") | contains("--input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json"))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.seeded_cycle_command // "") | startswith("./scripts/easy_node.sh blockchain-mainnet-activation-gate-cycle-seeded "))
  and ((.blockchain_track.mainnet_activation_missing_metrics_action.seeded_cycle_command // "") | contains("--refresh-roadmap 1"))
    and ($real_evidence_run_command | startswith("./scripts/easy_node.sh blockchain-mainnet-activation-real-evidence-run "))
    and ($real_evidence_run_command | contains("--input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json"))
    and ($real_evidence_run_command | contains("--refresh-roadmap 1"))
    and ((.next_actions // []) | any(
      .id == "blockchain_mainnet_activation_missing_metrics_prefill"
      and .command == $prefill_command
      and .reason == $missing_metrics_reason
    ))
    and ((.next_actions // []) | any(
      .id == "blockchain_mainnet_activation_missing_metrics"
      and ((.label // "") | test("^Blockchain missing-metrics"))
    and .command == $preferred_missing_metrics_command
    and .reason == $missing_metrics_reason
  ))
' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_summary.json" >/dev/null; then
  echo "auto-discovered gate summary JSON missing expected fields"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_summary.json"
  exit 1
fi
if ! rg -q 'Mainnet activation missing-metrics action available: true' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing blockchain missing-metrics actionable availability line"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'Mainnet activation missing-metrics prefill command:' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing blockchain missing-metrics prefill command line"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-metrics-input --input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing metrics-input normalization command"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-gate-bundle --blockchain-mainnet-activation-metrics-input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing gate-bundle rerun command"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-metrics-missing-checklist --metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing missing-checklist command"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-metrics-missing-input-template --metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing missing-input-template command"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-metrics-input-template --output-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.template.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing metrics-input template command"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-operator-pack --metrics-summary-json .easy-node-logs/blockchain_gate_bundle_summary.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing operator-pack one-step command"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-operator-pack .* --missing-input-template-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing operator-pack missing-input-template output-json"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-operator-pack .* --missing-input-template-canonical-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.canonical.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing operator-pack missing-input-template canonical-output-json"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-gate-cycle --input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing one-command gate cycle command"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-gate-cycle-seeded --reports-dir .easy-node-logs/blockchain_mainnet_activation_gate_cycle_seeded' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing seeded one-command gate cycle command"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain-mainnet-activation-real-evidence-run --input-json .easy-node-logs/blockchain_mainnet_activation_metrics_input.operator.json' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"; then
  echo "auto-discovered report missing preferred real-evidence one-command run command"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_report.md"
  exit 1
fi
if ! rg -q 'blockchain_mainnet_activation_missing_metrics_action_available=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing blockchain missing-metrics actionable line"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'blockchain_mainnet_activation_missing_metrics_action_template_command=.*blockchain-mainnet-activation-metrics-input-template ' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing template actionable command"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'prefill_command=.*blockchain-mainnet-activation-metrics-prefill ' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing prefill actionable command"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'blockchain_mainnet_activation_missing_metrics_action_missing_input_template_command=.*blockchain-mainnet-activation-metrics-missing-input-template ' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing missing-input-template actionable command"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'operator_pack_command=.*blockchain-mainnet-activation-operator-pack ' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing operator-pack actionable command"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'cycle_command=.*blockchain-mainnet-activation-gate-cycle ' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing cycle actionable command"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'operator_pack_command=.*--missing-input-template-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.json' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing operator-pack missing-input-template output-json"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'operator_pack_command=.*--missing-input-template-canonical-output-json .easy-node-logs/blockchain_mainnet_activation_metrics_missing_input_template.canonical.json' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing operator-pack missing-input-template canonical-output-json"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'blockchain_mainnet_activation_missing_metrics_action_checklist_command=.*blockchain-mainnet-activation-metrics-missing-checklist ' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing checklist actionable command"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'blockchain_mainnet_activation_missing_metrics_action_seeded_cycle_command=.*blockchain-mainnet-activation-gate-cycle-seeded ' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing seeded cycle actionable command"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi
if ! rg -q 'real_evidence_run_command=.*blockchain-mainnet-activation-real-evidence-run ' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log; then
  echo "auto-discovered log missing preferred real-evidence actionable command"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto.log
  exit 1
fi

echo "[roadmap-progress-report] blockchain mainnet activation gate auto-discovery ignores seeded artifacts"
AUTO_MAINNET_GATE_SEEDED_SUMMARY_JSON="$ROADMAP_PROGRESS_TEST_LOGS_ROOT/blockchain_mainnet_activation_gate_cycle_seeded/blockchain_mainnet_activation_gate_summary.json"
mkdir -p "$(dirname "$AUTO_MAINNET_GATE_SEEDED_SUMMARY_JSON")"
cat >"$AUTO_MAINNET_GATE_SEEDED_SUMMARY_JSON" <<'EOF_AUTO_MAINNET_GATE_SEEDED'
{
  "version": 1,
  "schema": {
    "id": "blockchain_mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "go",
  "decision": "GO",
  "go": true,
  "no_go": false,
  "reasons": [
    "seeded example path should be ignored"
  ],
  "inputs": {
    "seed_example_input": true
  },
  "source_paths": [
    "seeded_metrics_input"
  ]
}
EOF_AUTO_MAINNET_GATE_SEEDED
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --summary-json "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_seeded_ignored_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_seeded_ignored_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto_seeded_ignored.log 2>&1; then
  echo "expected success when seeded mainnet activation gate summary exists"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_auto_seeded_ignored.log
  exit 1
fi
if ! jq -e --arg preferred_src "$AUTO_MAINNET_GATE_SUMMARY_JSON" --arg seeded_src "$AUTO_MAINNET_GATE_SEEDED_SUMMARY_JSON" '
  .blockchain_track.mainnet_activation_gate.available == true
  and .blockchain_track.mainnet_activation_gate.status == "no-go"
  and .blockchain_track.mainnet_activation_gate.decision == "NO-GO"
  and .blockchain_track.mainnet_activation_gate.go == false
  and .blockchain_track.mainnet_activation_gate.no_go == true
  and .blockchain_track.mainnet_activation_gate.input_summary_json == $preferred_src
  and .blockchain_track.mainnet_activation_gate.source_summary_json == $preferred_src
  and .blockchain_track.mainnet_activation_gate.source_summary_json != $seeded_src
' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_seeded_ignored_summary.json" >/dev/null; then
  echo "auto-discovered mainnet gate did not ignore seeded summary artifact"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_auto_seeded_ignored_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain bootstrap governance graduation gate auto-discovery path"
AUTO_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON="$ROADMAP_PROGRESS_TEST_LOGS_ROOT/blockchain_bootstrap_governance_graduation_gate_summary.json"
cat >"$AUTO_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON" <<'EOF_AUTO_BOOTSTRAP_GATE'
{
  "version": 1,
  "schema": {
    "id": "blockchain_bootstrap_governance_graduation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "GO",
  "decision": "GO",
  "go": true,
  "no_go": false,
  "reasons": [
    "bootstrap governance graduation readiness met"
  ],
  "source_paths": [
    "bootstrap_metrics_input"
  ]
}
EOF_AUTO_BOOTSTRAP_GATE
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --summary-json "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_auto_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_auto_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_bootstrap_governance_graduation_gate_auto.log 2>&1; then
  echo "expected success when bootstrap governance graduation gate summary is auto-discovered"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_bootstrap_governance_graduation_gate_auto.log
  exit 1
fi
if ! jq -e --arg src "$AUTO_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON" '
  .blockchain_track.bootstrap_governance_graduation_gate.available == true
  and .blockchain_track.bootstrap_governance_graduation_gate.status == "GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.decision == "GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.go == true
  and .blockchain_track.bootstrap_governance_graduation_gate.no_go == false
  and .blockchain_track.bootstrap_governance_graduation_gate.input_summary_json == $src
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_json == $src
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_kind == "bootstrap-governance-graduation-gate-summary"
  and ((.blockchain_track.bootstrap_governance_graduation_gate.reasons // []) | index("bootstrap governance graduation readiness met")) != null
  and ((.blockchain_track.bootstrap_governance_graduation_gate.source_paths // []) | index("bootstrap_metrics_input")) != null
' "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_auto_summary.json" >/dev/null; then
  echo "auto-discovered bootstrap governance graduation gate summary JSON missing expected fields"
  cat "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_auto_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain bootstrap governance graduation gate auto-discovery ignores seeded artifacts"
AUTO_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SEEDED_SUMMARY_JSON="$ROADMAP_PROGRESS_TEST_LOGS_ROOT/blockchain_mainnet_activation_gate_cycle_seeded/blockchain_bootstrap_governance_graduation_gate_summary.json"
mkdir -p "$(dirname "$AUTO_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SEEDED_SUMMARY_JSON")"
cat >"$AUTO_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SEEDED_SUMMARY_JSON" <<'EOF_AUTO_BOOTSTRAP_GATE_SEEDED'
{
  "version": 1,
  "schema": {
    "id": "blockchain_bootstrap_governance_graduation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "NO-GO",
  "decision": "NO-GO",
  "go": false,
  "no_go": true,
  "reasons": [
    "seeded bootstrap path should be ignored"
  ],
  "inputs": {
    "seed_example_input": true
  },
  "source_paths": [
    "seeded_bootstrap_metrics_input"
  ]
}
EOF_AUTO_BOOTSTRAP_GATE_SEEDED
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --summary-json "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_auto_seeded_ignored_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_auto_seeded_ignored_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_bootstrap_governance_graduation_gate_auto_seeded_ignored.log 2>&1; then
  echo "expected success when seeded bootstrap governance graduation gate summary exists"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_bootstrap_governance_graduation_gate_auto_seeded_ignored.log
  exit 1
fi
if ! jq -e --arg preferred_src "$AUTO_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SUMMARY_JSON" --arg seeded_src "$AUTO_BOOTSTRAP_GOVERNANCE_GRADUATION_GATE_SEEDED_SUMMARY_JSON" '
  .blockchain_track.bootstrap_governance_graduation_gate.available == true
  and .blockchain_track.bootstrap_governance_graduation_gate.status == "GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.decision == "GO"
  and .blockchain_track.bootstrap_governance_graduation_gate.go == true
  and .blockchain_track.bootstrap_governance_graduation_gate.no_go == false
  and .blockchain_track.bootstrap_governance_graduation_gate.input_summary_json == $preferred_src
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_json == $preferred_src
  and .blockchain_track.bootstrap_governance_graduation_gate.source_summary_json != $seeded_src
' "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_auto_seeded_ignored_summary.json" >/dev/null; then
  echo "auto-discovered bootstrap governance graduation gate did not ignore seeded summary artifact"
  cat "$TMP_DIR/roadmap_progress_bootstrap_governance_graduation_gate_auto_seeded_ignored_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain mainnet activation gate failed_reasons-only fallback path"
FAILED_REASONS_ONLY_MAINNET_GATE_SUMMARY_JSON="$TMP_DIR/blockchain_mainnet_activation_gate_failed_reasons_only_summary.json"
cat >"$FAILED_REASONS_ONLY_MAINNET_GATE_SUMMARY_JSON" <<'EOF_FAILED_REASONS_ONLY_MAINNET_GATE'
{
  "version": 1,
  "schema": {
    "id": "blockchain_mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "no-go",
  "decision": "NO-GO",
  "go": false,
  "no_go": true,
  "failed_gate_ids": [
    "validator_candidate_depth"
  ],
  "failed_reasons": [
    "validator candidate depth below threshold"
  ],
  "input": {
    "metrics_json": "./artifacts/blockchain/mainnet_activation_metrics_snapshot.json"
  },
  "artifacts": {
    "metrics_json": "./artifacts/blockchain/mainnet_activation_metrics_snapshot.json"
  }
}
EOF_FAILED_REASONS_ONLY_MAINNET_GATE
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --blockchain-mainnet-activation-gate-summary-json "$FAILED_REASONS_ONLY_MAINNET_GATE_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_mainnet_activation_gate_failed_reasons_only_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_mainnet_activation_gate_failed_reasons_only_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_failed_reasons_only.log 2>&1; then
  echo "expected success when mainnet activation gate summary has only failed_reasons"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_failed_reasons_only.log
  exit 1
fi
if ! jq -e '
  .blockchain_track.mainnet_activation_gate.available == true
  and .blockchain_track.mainnet_activation_gate.status == "no-go"
  and .blockchain_track.mainnet_activation_gate.decision == "NO-GO"
  and ((.blockchain_track.mainnet_activation_gate.reasons // []) | length) > 0
  and ((.blockchain_track.mainnet_activation_gate.reasons // []) | index("validator candidate depth below threshold")) != null
  and ((.blockchain_track.mainnet_activation_gate.source_paths // []) | index("./artifacts/blockchain/mainnet_activation_metrics_snapshot.json")) != null
' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_failed_reasons_only_summary.json" >/dev/null; then
  echo "failed_reasons-only gate summary JSON missing expected reason/source-path fallbacks"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_failed_reasons_only_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] blockchain mainnet activation gate failed_gate_ids-only fallback path"
FAILED_GATE_IDS_ONLY_MAINNET_GATE_SUMMARY_JSON="$TMP_DIR/blockchain_mainnet_activation_gate_failed_gate_ids_only_summary.json"
cat >"$FAILED_GATE_IDS_ONLY_MAINNET_GATE_SUMMARY_JSON" <<'EOF_FAILED_GATE_IDS_ONLY_MAINNET_GATE'
{
  "version": 1,
  "schema": {
    "id": "blockchain_mainnet_activation_gate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "no-go",
  "decision": "NO-GO",
  "go": false,
  "no_go": true,
  "failed_gate_ids": [
    "validator_candidate_depth",
    "subsidy_sustainability"
  ],
  "input": {
    "metrics_json": "./artifacts/blockchain/mainnet_activation_metrics_snapshot_failed_gate_ids.json"
  },
  "artifacts": {
    "metrics_json": "./artifacts/blockchain/mainnet_activation_metrics_snapshot_failed_gate_ids.json"
  }
}
EOF_FAILED_GATE_IDS_ONLY_MAINNET_GATE
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
  --phase7-mainnet-cutover-summary-json "" \
  --blockchain-mainnet-activation-gate-summary-json "$FAILED_GATE_IDS_ONLY_MAINNET_GATE_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_mainnet_activation_gate_failed_gate_ids_only_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_mainnet_activation_gate_failed_gate_ids_only_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_failed_gate_ids_only.log 2>&1; then
  echo "expected success when mainnet activation gate summary has only failed_gate_ids"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_mainnet_activation_gate_failed_gate_ids_only.log
  exit 1
fi
if ! jq -e '
  .blockchain_track.mainnet_activation_gate.available == true
  and .blockchain_track.mainnet_activation_gate.status == "no-go"
  and .blockchain_track.mainnet_activation_gate.decision == "NO-GO"
  and ((.blockchain_track.mainnet_activation_gate.reasons // []) | length) > 0
  and ((.blockchain_track.mainnet_activation_gate.reasons // []) | index("validator_candidate_depth")) != null
  and ((.blockchain_track.mainnet_activation_gate.reasons // []) | index("subsidy_sustainability")) != null
  and ((.blockchain_track.mainnet_activation_gate.source_paths // []) | index("./artifacts/blockchain/mainnet_activation_metrics_snapshot_failed_gate_ids.json")) != null
' "$TMP_DIR/roadmap_progress_mainnet_activation_gate_failed_gate_ids_only_summary.json" >/dev/null; then
  echo "failed_gate_ids-only gate summary JSON missing expected reason/source-path fallbacks"
  cat "$TMP_DIR/roadmap_progress_mainnet_activation_gate_failed_gate_ids_only_summary.json"
  exit 1
fi

if ! rg -q '\[roadmap-progress-report\] phase5_settlement_layer_handoff_issuer_sponsor_api_live_smoke_status=pass issuer_sponsor_api_live_smoke_ok=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected phase5 issuer sponsor debug line in success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] phase5_settlement_layer_handoff_issuer_settlement_status_live_smoke_status=pass issuer_settlement_status_live_smoke_ok=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected phase5 issuer settlement status debug line in success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] phase5_settlement_layer_handoff_issuer_admin_blockchain_handlers_coverage_status=pass issuer_admin_blockchain_handlers_coverage_ok=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected phase5 issuer admin blockchain handlers coverage debug line in success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] phase5_settlement_layer_handoff_settlement_dual_asset_parity_status=pass settlement_dual_asset_parity_ok=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected phase5 settlement dual asset parity debug line in success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] phase5_settlement_layer_handoff_settlement_adapter_signed_tx_roundtrip_status=pass settlement_adapter_signed_tx_roundtrip_ok=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected phase5 settlement adapter signed tx roundtrip debug line in success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] phase5_settlement_layer_handoff_settlement_shadow_env_status=pass settlement_shadow_env_ok=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected phase5 settlement shadow env debug line in success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] phase5_settlement_layer_handoff_settlement_shadow_status_surface_status=pass settlement_shadow_status_surface_ok=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected phase5 settlement shadow status surface debug line in success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] phase5_settlement_layer_handoff_exit_settlement_status_live_smoke_status=pass exit_settlement_status_live_smoke_ok=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
  echo "expected phase5 exit settlement status debug line in success path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
  exit 1
fi
if [[ "$PHASE6_OUTPUT_PRESENT" == "1" ]]; then
  if ! rg -q '\[roadmap-progress-report\].*phase6' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
    echo "expected phase6 debug line in success path"
    cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
    exit 1
  fi
fi
if [[ "$PHASE7_OUTPUT_PRESENT" == "1" ]]; then
  if ! rg -q '\[roadmap-progress-report\].*phase7' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log; then
    echo "expected phase7 debug line in success path"
    cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ok.log
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
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_minimal.log 2>&1; then
  echo "expected success when manual-validation summary has partial schema"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_minimal.log
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
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_incompatible_schema.log 2>&1; then
  echo "expected failure when manual-validation summary schema is incompatible"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_incompatible_schema.log
  exit 1
fi
if ! rg -q 'manual-validation summary JSON is missing required fields or uses an incompatible schema' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_incompatible_schema.log; then
  echo "incompatible schema path missing expected fail-close message"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_incompatible_schema.log
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
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_fallback.log 2>&1; then
  echo "expected success when next_action_command is inferred from checks"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_fallback.log
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
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_summary_gate_fallback.log 2>&1; then
  echo "expected success when real-host/docker gates are inferred from summary fields"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_summary_gate_fallback.log
  exit 1
fi
if ! jq -e '
  .vpn_track.vpn_rc_done_for_phase == false
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

echo "[roadmap-progress-report] vpn_rc_done_for_phase follows resilience criteria (fail-closed)"
READY_SIGNOFF_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_ready_signoff_summary.json"
cat >"$READY_SIGNOFF_MANUAL_SUMMARY_JSON" <<'EOF_READY_SIGNOFF_MANUAL_SUMMARY'
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
    },
    {
      "check_id": "three_machine_docker_readiness",
      "label": "One-host docker 3-machine rehearsal",
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    {
      "check_id": "real_wg_privileged_matrix",
      "label": "Linux root real-WG privileged matrix",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    },
    {
      "check_id": "machine_c_vpn_smoke",
      "label": "Machine C VPN smoke test",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
    },
    {
      "check_id": "three_machine_prod_signoff",
      "label": "True 3-machine production signoff",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh three-machine-prod-signoff --bundle-dir .easy-node-logs/prod_gate_bundle --directory-a https://A_HOST:8081 --directory-b https://B_HOST:8081 --issuer-url https://A_HOST:8082 --entry-url https://A_HOST:8083 --exit-url https://A_HOST:8084 --pre-real-host-readiness 1 --runtime-fix 1 --print-summary-json 1"
    }
  ],
  "summary": {
    "next_action_check_id": "",
    "next_action_label": "",
    "next_action_command": "",
    "roadmap_stage": "PRODUCTION_SIGNOFF_COMPLETE",
    "single_machine_ready": true,
    "blocking_check_ids": [],
    "optional_check_ids": ["three_machine_docker_readiness", "real_wg_privileged_matrix"],
    "pre_machine_c_gate": {
      "ready": true
    },
    "real_host_gate": {
      "ready": true,
      "blockers": []
    },
    "docker_rehearsal_gate": {
      "status": "pass"
    },
    "profile_default_gate": {
      "status": "pass"
    },
    "real_wg_privileged_gate": {
      "status": "pass"
    }
  },
  "report": {
    "readiness_status": "READY",
    "ready": true
  }
}
EOF_READY_SIGNOFF_MANUAL_SUMMARY

READY_SIGNOFF_RESILIENCE_PASS_JSON="$TMP_DIR/ready_signoff_resilience_pass_summary.json"
cat >"$READY_SIGNOFF_RESILIENCE_PASS_JSON" <<'EOF_READY_SIGNOFF_RESILIENCE_PASS'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": true,
  "session_churn_guard_ok": true
}
EOF_READY_SIGNOFF_RESILIENCE_PASS

READY_SIGNOFF_RESILIENCE_FAIL_JSON="$TMP_DIR/ready_signoff_resilience_fail_summary.json"
cat >"$READY_SIGNOFF_RESILIENCE_FAIL_JSON" <<'EOF_READY_SIGNOFF_RESILIENCE_FAIL'
{
  "version": 1,
  "profile_matrix_stable": true,
  "peer_loss_recovery_ok": false,
  "session_churn_guard_ok": true
}
EOF_READY_SIGNOFF_RESILIENCE_FAIL

READY_SIGNOFF_EMPTY_LOGS_ROOT="$TMP_DIR/ready_signoff_empty_logs"
mkdir -p "$READY_SIGNOFF_EMPTY_LOGS_ROOT"
MISSING_READY_SIGNOFF_PHASE1_SUMMARY_JSON="$TMP_DIR/missing_ready_signoff_phase1_summary.json"
MISSING_READY_SIGNOFF_RESILIENCE_SUMMARY_JSON="$TMP_DIR/missing_ready_signoff_resilience_summary.json"

READY_SIGNOFF_PASS_SUMMARY_JSON="$TMP_DIR/roadmap_progress_ready_signoff_resilience_pass_summary.json"
if ! ROADMAP_PROGRESS_LOGS_ROOT="$READY_SIGNOFF_EMPTY_LOGS_ROOT" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$READY_SIGNOFF_MANUAL_SUMMARY_JSON" \
    --phase0-summary-json "$PHASE0_SUMMARY_JSON" \
    --phase1-resilience-handoff-summary-json "$MISSING_READY_SIGNOFF_PHASE1_SUMMARY_JSON" \
    --vpn-rc-resilience-summary-json "$READY_SIGNOFF_RESILIENCE_PASS_JSON" \
    --summary-json "$READY_SIGNOFF_PASS_SUMMARY_JSON" \
    --report-md "$TMP_DIR/roadmap_progress_ready_signoff_resilience_pass_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ready_signoff_resilience_pass.log 2>&1; then
  echo "expected success for READY signoff resilience-pass path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ready_signoff_resilience_pass.log
  exit 1
fi
if ! jq -e '
  .status == "ok"
  and .rc == 0
  and .vpn_track.readiness_status == "READY"
  and .vpn_track.roadmap_stage == "PRODUCTION_SIGNOFF_COMPLETE"
  and .vpn_track.vpn_rc_done_for_phase == true
  and .vpn_track.resilience_handoff.available == true
  and .vpn_track.resilience_handoff.profile_matrix_stable == true
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == true
  and .vpn_track.resilience_handoff.session_churn_guard_ok == true
' "$READY_SIGNOFF_PASS_SUMMARY_JSON" >/dev/null; then
  echo "READY signoff resilience-pass summary missing expected vpn_rc_done_for_phase=true contract"
  cat "$READY_SIGNOFF_PASS_SUMMARY_JSON"
  exit 1
fi

READY_SIGNOFF_FAIL_SUMMARY_JSON="$TMP_DIR/roadmap_progress_ready_signoff_resilience_fail_summary.json"
if ! ROADMAP_PROGRESS_LOGS_ROOT="$READY_SIGNOFF_EMPTY_LOGS_ROOT" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$READY_SIGNOFF_MANUAL_SUMMARY_JSON" \
    --phase0-summary-json "$PHASE0_SUMMARY_JSON" \
    --phase1-resilience-handoff-summary-json "$MISSING_READY_SIGNOFF_PHASE1_SUMMARY_JSON" \
    --vpn-rc-resilience-summary-json "$READY_SIGNOFF_RESILIENCE_FAIL_JSON" \
    --summary-json "$READY_SIGNOFF_FAIL_SUMMARY_JSON" \
    --report-md "$TMP_DIR/roadmap_progress_ready_signoff_resilience_fail_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ready_signoff_resilience_fail.log 2>&1; then
  echo "expected success for READY signoff resilience-fail path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ready_signoff_resilience_fail.log
  exit 1
fi
if ! jq -e '
  .status == "ok"
  and .rc == 0
  and .vpn_track.readiness_status == "READY"
  and .vpn_track.roadmap_stage == "PRODUCTION_SIGNOFF_COMPLETE"
  and .vpn_track.vpn_rc_done_for_phase == false
  and .vpn_track.resilience_handoff.available == true
  and .vpn_track.resilience_handoff.profile_matrix_stable == true
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == false
  and .vpn_track.resilience_handoff.session_churn_guard_ok == true
' "$READY_SIGNOFF_FAIL_SUMMARY_JSON" >/dev/null; then
  echo "READY signoff resilience-fail summary missing expected fail-closed vpn_rc_done_for_phase=false contract"
  cat "$READY_SIGNOFF_FAIL_SUMMARY_JSON"
  exit 1
fi

READY_SIGNOFF_MISSING_SUMMARY_JSON="$TMP_DIR/roadmap_progress_ready_signoff_resilience_missing_summary.json"
if ! ROADMAP_PROGRESS_LOGS_ROOT="$READY_SIGNOFF_EMPTY_LOGS_ROOT" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$READY_SIGNOFF_MANUAL_SUMMARY_JSON" \
    --phase0-summary-json "$PHASE0_SUMMARY_JSON" \
    --phase1-resilience-handoff-summary-json "$MISSING_READY_SIGNOFF_PHASE1_SUMMARY_JSON" \
    --vpn-rc-resilience-summary-json "$MISSING_READY_SIGNOFF_RESILIENCE_SUMMARY_JSON" \
    --summary-json "$READY_SIGNOFF_MISSING_SUMMARY_JSON" \
    --report-md "$TMP_DIR/roadmap_progress_ready_signoff_resilience_missing_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ready_signoff_resilience_missing.log 2>&1; then
  echo "expected success for READY signoff resilience-missing path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_ready_signoff_resilience_missing.log
  exit 1
fi
if ! jq -e '
  .status == "ok"
  and .rc == 0
  and .vpn_track.readiness_status == "READY"
  and .vpn_track.roadmap_stage == "PRODUCTION_SIGNOFF_COMPLETE"
  and .vpn_track.vpn_rc_done_for_phase == false
  and .vpn_track.resilience_handoff.available == false
  and .vpn_track.resilience_handoff.profile_matrix_stable == null
  and .vpn_track.resilience_handoff.peer_loss_recovery_ok == null
  and .vpn_track.resilience_handoff.session_churn_guard_ok == null
' "$READY_SIGNOFF_MISSING_SUMMARY_JSON" >/dev/null; then
  echo "READY signoff resilience-missing summary missing expected fail-closed vpn_rc_done_for_phase=false contract"
  cat "$READY_SIGNOFF_MISSING_SUMMARY_JSON"
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
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_optional_fallback.log 2>&1; then
  echo "expected success when optional gate next commands are inferred from command fields"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_optional_fallback.log
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

echo "[roadmap-progress-report] profile default gate exposes no-sudo primary command with sudo fallback"
OPTIONAL_PROFILE_HINT_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_optional_profile_hint_summary.json"
cat >"$OPTIONAL_PROFILE_HINT_MANUAL_SUMMARY_JSON" <<'EOF_OPTIONAL_PROFILE_HINT_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "profile compare campaign signoff decision is NO-GO but campaign-check evidence is insufficient/unstable; rerun with refresh-campaign=1",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --subject INVITE_KEY --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --subject INVITE_KEY --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "docker_rehearsal_artifacts",
      "docker_rehearsal_hint_available": true,
      "docker_rehearsal_hint_source": "docker_rehearsal_artifacts",
      "artifacts": {
        "campaign_check_summary_json_resolved": "/tmp/profile_compare_campaign_check_summary_insufficient.json",
        "docker_rehearsal_matrix_summary_json": "/tmp/three_machine_docker_profile_matrix_record_hint_matrix.json",
        "docker_rehearsal_profile_summary_json": "/tmp/three_machine_docker_readiness_hint_2hop.json"
      }
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_OPTIONAL_PROFILE_HINT_SUMMARY

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$OPTIONAL_PROFILE_HINT_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_optional_profile_hint_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_optional_profile_hint_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_optional_profile_hint.log 2>&1; then
  echo "expected success when profile default gate includes docker no-sudo guidance"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_optional_profile_hint.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh (profile-default-gate-run|profile-compare-campaign-signoff)( |$)"));
  def is_profile_gate_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh (profile-default-gate-run|profile-compare-campaign-signoff)( |$)"));
  ((.next_actions // []) | any(.id == "profile_default_gate" and is_profile_gate_non_sudo_cmd(.command)))
  and (.vpn_track.optional_gate_status.profile_default_gate == "pending")
  and is_profile_gate_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and ((.vpn_track.profile_default_gate.next_command_source // "") | test("docker"))
  and (.vpn_track.profile_default_gate.docker_hint_available == true)
' "$TMP_DIR/roadmap_progress_optional_profile_hint_summary.json" >/dev/null; then
  echo "optional profile-hint summary JSON missing expected profile_default_gate guidance fields"
  cat "$TMP_DIR/roadmap_progress_optional_profile_hint_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate appends subject placeholder when credential args are missing"
PROFILE_DEFAULT_GATE_SUBJECT_PLACEHOLDER_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_subject_placeholder_summary.json"
cat >"$PROFILE_DEFAULT_GATE_SUBJECT_PLACEHOLDER_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_SUBJECT_PLACEHOLDER_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "profile compare campaign signoff decision is NO-GO but campaign-check evidence is insufficient/unstable; rerun with refresh-campaign=1",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "docker_rehearsal_artifacts",
      "docker_rehearsal_hint_available": true
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_SUBJECT_PLACEHOLDER_SUMMARY

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_SUBJECT_PLACEHOLDER_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_subject_placeholder_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_subject_placeholder_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_subject_placeholder.log 2>&1; then
  echo "expected success when profile default gate command requires subject placeholder normalization"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_subject_placeholder.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh (profile-default-gate-run|profile-compare-campaign-signoff)( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  ((.next_actions // []) | any(.id == "profile_default_gate" and is_profile_gate_non_sudo_cmd(.command) and has_subject_placeholder(.command)))
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command_sudo)
' "$TMP_DIR/roadmap_progress_profile_default_subject_placeholder_summary.json" >/dev/null; then
  echo "profile default subject placeholder summary JSON missing expected INVITE_KEY placeholder command normalization"
  cat "$TMP_DIR/roadmap_progress_profile_default_subject_placeholder_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] profile default gate live wrapper appends subject placeholder when key is missing"
PROFILE_DEFAULT_GATE_LIVE_PLACEHOLDER_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_live_placeholder_summary.json"
cat >"$PROFILE_DEFAULT_GATE_LIVE_PLACEHOLDER_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_LIVE_PLACEHOLDER_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "live wrapper command should gain subject placeholder when missing",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-default-gate-live --host-a 100.113.245.61 --host-b 100.64.244.24 --reports-dir .easy-node-logs --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-default-gate-live --host-a 100.113.245.61 --host-b 100.64.244.24 --reports-dir .easy-node-logs --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "default_non_sudo",
      "docker_rehearsal_hint_available": false
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_LIVE_PLACEHOLDER_SUMMARY

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_LIVE_PLACEHOLDER_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_live_placeholder_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_live_placeholder_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_live_placeholder.log 2>&1; then
  echo "expected success when profile default live wrapper command requires subject placeholder normalization"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_live_placeholder.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_live_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def is_profile_gate_live_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  ((.next_actions // []) | any(.id == "profile_default_gate" and is_profile_gate_live_non_sudo_cmd(.command) and has_subject_placeholder(.command)))
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command_sudo)
  and is_profile_gate_live_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
' "$TMP_DIR/roadmap_progress_profile_default_live_placeholder_summary.json" >/dev/null; then
  echo "profile default live wrapper summary JSON missing expected INVITE_KEY placeholder command normalization"
  cat "$TMP_DIR/roadmap_progress_profile_default_live_placeholder_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] profile default gate live wrapper preserves explicit --key credentials without adding --subject"
PROFILE_DEFAULT_GATE_LIVE_KEYED_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_live_keyed_summary.json"
cat >"$PROFILE_DEFAULT_GATE_LIVE_KEYED_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_LIVE_KEYED_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "live wrapper command should keep explicit --key credential",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-default-gate-live --host-a 100.113.245.61 --host-b 100.64.244.24 --key INVITE_KEY --reports-dir .easy-node-logs --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-default-gate-live --host-a 100.113.245.61 --host-b 100.64.244.24 --key INVITE_KEY --reports-dir .easy-node-logs --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "default_non_sudo",
      "docker_rehearsal_hint_available": false
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_LIVE_KEYED_SUMMARY

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_LIVE_KEYED_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_live_keyed_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_live_keyed_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_live_keyed.log 2>&1; then
  echo "expected success when profile default live wrapper command already includes --key credential"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_live_keyed.log
  exit 1
fi
if ! jq -e '
  def has_key_placeholder($cmd):
    (($cmd // "") | test("(^| )--key INVITE_KEY( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  has_key_placeholder(.vpn_track.profile_default_gate.next_command)
  and has_key_placeholder(.vpn_track.profile_default_gate.next_command_sudo)
  and ((has_subject_placeholder(.vpn_track.profile_default_gate.next_command)) | not)
  and ((has_subject_placeholder(.vpn_track.profile_default_gate.next_command_sudo)) | not)
' "$TMP_DIR/roadmap_progress_profile_default_live_keyed_summary.json" >/dev/null; then
  echo "profile default live wrapper keyed summary JSON unexpectedly rewrote --key credentials"
  cat "$TMP_DIR/roadmap_progress_profile_default_live_keyed_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default anon-cred commands remain run-mode and redact credential values"
PROFILE_DEFAULT_GATE_LIVE_ANON_CRED_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_live_anon_cred_summary.json"
cat >"$PROFILE_DEFAULT_GATE_LIVE_ANON_CRED_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_LIVE_ANON_CRED_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "live-wrapper rewrite should preserve anon credential flags while retaining existing key behavior",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --campaign-anon-cred CAMPAIGN_ANON_TOKEN --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --key INVITE_KEY --anon-cred ANON_TOKEN --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "docker_rehearsal_artifacts",
      "docker_rehearsal_hint_available": true
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_LIVE_ANON_CRED_SUMMARY

if ! A_HOST="100.113.245.61" B_HOST="100.64.244.24" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_LIVE_ANON_CRED_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_profile_default_live_anon_cred_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_profile_default_live_anon_cred_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_live_anon_cred.log 2>&1; then
  echo "expected success when profile default anon-cred commands stay in run-mode with redacted credentials"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_live_anon_cred.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_run_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-default-gate-run( |$)"));
  def is_profile_gate_run_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-default-gate-run( |$)"));
  def is_profile_gate_live_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def is_profile_gate_live_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def has_campaign_anon_cred_redacted($cmd):
    (($cmd // "") | test("(^| )--campaign-anon-cred ANON_CRED( |$)"));
  def has_anon_cred_redacted($cmd):
    (($cmd // "") | test("(^| )--anon-cred ANON_CRED( |$)"));
  def has_key_placeholder($cmd):
    (($cmd // "") | test("(^| )--key INVITE_KEY( |$)"));
  def has_raw_anon_tokens($cmd):
    (($cmd // "") | test("CAMPAIGN_ANON_TOKEN|ANON_TOKEN"));
  ((.next_actions // []) | any(
    .id == "profile_default_gate"
    and is_profile_gate_run_non_sudo_cmd(.command)
    and has_campaign_anon_cred_redacted(.command)
    and ((is_profile_gate_live_non_sudo_cmd(.command)) | not)
    and ((has_raw_anon_tokens(.command)) | not)
  ))
  and is_profile_gate_run_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_run_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and ((is_profile_gate_live_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)) | not)
  and ((is_profile_gate_live_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)) | not)
  and has_campaign_anon_cred_redacted(.vpn_track.profile_default_gate.next_command)
  and has_key_placeholder(.vpn_track.profile_default_gate.next_command_sudo)
  and has_anon_cred_redacted(.vpn_track.profile_default_gate.next_command_sudo)
  and ((has_raw_anon_tokens(.vpn_track.profile_default_gate.next_command)) | not)
  and ((has_raw_anon_tokens(.vpn_track.profile_default_gate.next_command_sudo)) | not)
' "$TMP_DIR/roadmap_progress_profile_default_live_anon_cred_summary.json" >/dev/null; then
  echo "profile default anon-cred summary JSON missing expected run-mode redaction fields"
  cat "$TMP_DIR/roadmap_progress_profile_default_live_anon_cred_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] malformed anon-cred flags remain signoff-mode and never inject subject placeholders"
PROFILE_DEFAULT_GATE_MALFORMED_ANON_FLAG_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_malformed_anon_flag_summary.json"
cat >"$PROFILE_DEFAULT_GATE_MALFORMED_ANON_FLAG_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_MALFORMED_ANON_FLAG_SUMMARY'
{
  "version": 1,
  "checks": [
    {
      "check_id": "runtime_hygiene",
      "label": "Runtime hygiene doctor",
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh runtime-doctor --show-json 1"
    }
  ],
  "summary": {
    "next_action_check_id": "",
    "next_action_command": "",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": [],
    "optional_check_ids": ["three_machine_docker_readiness"],
    "profile_default_gate": {
      "status": "pending",
      "notes": "malformed anon-cred must stay signoff-mode",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --campaign-directory-urls 'https://198.51.100.31:8081,https://198.51.100.32:8081' --anon-cred --oops --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --campaign-directory-urls 'https://198.51.100.31:8081,https://198.51.100.32:8081' --anon-cred --oops --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "signoff+docker_rehearsal_artifacts",
      "docker_hint_available": true,
      "docker_hint_source": "signoff+docker_rehearsal_artifacts"
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_MALFORMED_ANON_FLAG_SUMMARY

if ! A_HOST="100.113.245.61" B_HOST="100.64.244.24" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_MALFORMED_ANON_FLAG_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_profile_default_malformed_anon_flag_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_profile_default_malformed_anon_flag_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_malformed_anon_flag.log 2>&1; then
  echo "expected success when malformed anon-cred flags preserve signoff-mode"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_malformed_anon_flag.log
  exit 1
fi
if ! jq -e '
  def is_signoff_cmd($cmd):
    (($cmd // "") | test("^(sudo )?\\./scripts/easy_node\\.sh profile-compare-campaign-signoff( |$)"));
  def is_live_wrapper_cmd($cmd):
    (($cmd // "") | test("^(sudo )?\\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def has_anon_flag($cmd):
    (($cmd // "") | test("(^| )--anon-cred( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  ((.next_actions // []) | any(
    .id == "profile_default_gate"
    and is_signoff_cmd(.command)
    and has_anon_flag(.command)
    and ((is_live_wrapper_cmd(.command)) | not)
    and ((has_subject_placeholder(.command)) | not)
  ))
  and is_signoff_cmd(.vpn_track.profile_default_gate.next_command)
  and is_signoff_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and has_anon_flag(.vpn_track.profile_default_gate.next_command)
  and has_anon_flag(.vpn_track.profile_default_gate.next_command_sudo)
  and ((is_live_wrapper_cmd(.vpn_track.profile_default_gate.next_command)) | not)
  and ((is_live_wrapper_cmd(.vpn_track.profile_default_gate.next_command_sudo)) | not)
  and ((has_subject_placeholder(.vpn_track.profile_default_gate.next_command)) | not)
  and ((has_subject_placeholder(.vpn_track.profile_default_gate.next_command_sudo)) | not)
' "$TMP_DIR/roadmap_progress_profile_default_malformed_anon_flag_summary.json" >/dev/null; then
  echo "malformed anon-cred summary JSON unexpectedly rewrote command mode or injected subject placeholder"
  cat "$TMP_DIR/roadmap_progress_profile_default_malformed_anon_flag_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default credential redaction fails closed when command parsing fails"
PROFILE_DEFAULT_GATE_PARSE_FAIL_CRED_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_parse_fail_cred_summary.json"
cat >"$PROFILE_DEFAULT_GATE_PARSE_FAIL_CRED_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_PARSE_FAIL_CRED_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "parse-failure credential values must not leak",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --subject 'LEAKY MULTI TOKEN VALUE --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --anon-cred 'ANON LEAK MULTI TOKEN --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "default_non_sudo",
      "docker_rehearsal_hint_available": false
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_PARSE_FAIL_CRED_SUMMARY

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_PARSE_FAIL_CRED_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_parse_fail_cred_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_parse_fail_cred_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_parse_fail_cred.log 2>&1; then
  echo "expected success when profile default commands contain unparseable quoted credential values"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_parse_fail_cred.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_signoff_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-compare-campaign-signoff( |$)"));
  def is_profile_gate_signoff_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-compare-campaign-signoff( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  def has_anon_cred_redacted($cmd):
    (($cmd // "") | test("(^| )--anon-cred ANON_CRED( |$)"));
  def has_raw_leaked_values($cmd):
    (($cmd // "") | test("LEAKY MULTI TOKEN VALUE|ANON LEAK MULTI TOKEN"));
  ((.next_actions // []) | any(
    .id == "profile_default_gate"
    and is_profile_gate_signoff_non_sudo_cmd(.command)
    and has_subject_placeholder(.command)
    and ((has_raw_leaked_values(.command)) | not)
  ))
  and is_profile_gate_signoff_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_signoff_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command)
  and has_anon_cred_redacted(.vpn_track.profile_default_gate.next_command_sudo)
  and ((has_raw_leaked_values(.vpn_track.profile_default_gate.next_command)) | not)
  and ((has_raw_leaked_values(.vpn_track.profile_default_gate.next_command_sudo)) | not)
' "$TMP_DIR/roadmap_progress_profile_default_parse_fail_cred_summary.json" >/dev/null; then
  echo "profile default parse-failure credential redaction summary JSON leaked raw credential text"
  cat "$TMP_DIR/roadmap_progress_profile_default_parse_fail_cred_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate preserves sudo-required command-source from manual summary"
PROFILE_DEFAULT_GATE_MANUAL_SUDO_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_sudo_source_summary.json"
cat >"$PROFILE_DEFAULT_GATE_MANUAL_SUDO_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_MANUAL_SUDO_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "profile compare campaign signoff decision is NO-GO but campaign-check evidence is insufficient/unstable; rerun with refresh-campaign=1; operator action: Use a fresh invite key from active issuer and rerun signoff",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "decision_next_operator_action": "Use a fresh invite key from active issuer and rerun signoff",
      "diagnostics_root_required": true,
      "next_command": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "sudo_required_diagnostics_root_required",
      "next_command_sudo_only_reason": "diagnostics_root_required",
      "docker_rehearsal_hint_available": false
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_MANUAL_SUDO_SUMMARY

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_MANUAL_SUDO_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_sudo_source_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_sudo_source_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_sudo_source.log 2>&1; then
  echo "expected success when profile default gate uses sudo-required diagnostics command source"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_sudo_source.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh (profile-default-gate-run|profile-compare-campaign-signoff)( |$)"));
  ((.next_actions // []) | any(.id == "profile_default_gate" and is_profile_gate_sudo_cmd(.command)))
  and (.vpn_track.optional_gate_status.profile_default_gate == "pending")
  and ((.vpn_track.profile_default_gate.next_command_source // "") == "sudo_required_diagnostics_root_required")
  and is_profile_gate_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and (.vpn_track.profile_default_gate.docker_hint_available == false)
' "$TMP_DIR/roadmap_progress_profile_default_sudo_source_summary.json" >/dev/null; then
  echo "profile default sudo-source summary JSON missing expected command-source passthrough fields"
  cat "$TMP_DIR/roadmap_progress_profile_default_sudo_source_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate preserves docker-hint command-source with safe start_local_stack"
PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_docker_source_summary.json"
cat >"$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "profile compare campaign signoff decision is NO-GO but campaign-check evidence is insufficient/unstable; rerun with refresh-campaign=1",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --subject INVITE_KEY --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --subject INVITE_KEY --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "docker_rehearsal_artifacts",
      "docker_rehearsal_hint_available": true
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SUMMARY

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_docker_source_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_docker_source_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_source.log 2>&1; then
  echo "expected success when profile default gate uses docker command source with safe start_local_stack"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_source.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh (profile-default-gate-run|profile-compare-campaign-signoff)( |$)"));
  def is_profile_gate_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh (profile-default-gate-run|profile-compare-campaign-signoff)( |$)"));
  ((.next_actions // []) | any(.id == "profile_default_gate" and is_profile_gate_non_sudo_cmd(.command)))
  and (.vpn_track.optional_gate_status.profile_default_gate == "pending")
  and ((.vpn_track.profile_default_gate.next_command_source // "") == "docker_rehearsal_artifacts")
  and is_profile_gate_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and (.vpn_track.profile_default_gate.docker_hint_available == true)
' "$TMP_DIR/roadmap_progress_profile_default_docker_source_summary.json" >/dev/null; then
  echo "profile default docker-source summary JSON missing expected command-source passthrough fields"
  cat "$TMP_DIR/roadmap_progress_profile_default_docker_source_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default docker source prefers live wrapper when A_HOST/B_HOST are set"
if ! A_HOST="100.113.245.61" B_HOST="100.64.244.24" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_profile_default_docker_source_live_wrapper_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_profile_default_docker_source_live_wrapper_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_source_live_wrapper.log 2>&1; then
  echo "expected success when docker profile-default hint is converted to live wrapper under A_HOST/B_HOST"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_source_live_wrapper.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_live_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def is_profile_gate_live_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def has_hosts($cmd):
    (($cmd // "") | test("(^| )--host-a 100\\.113\\.245\\.61( |$)"))
    and (($cmd // "") | test("(^| )--host-b 100\\.64\\.244\\.24( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  ((.next_actions // []) | any(.id == "profile_default_gate" and is_profile_gate_live_non_sudo_cmd(.command) and has_hosts(.command)))
  and (.vpn_track.optional_gate_status.profile_default_gate == "pending")
  and ((.vpn_track.profile_default_gate.next_command_source // "") == "docker_rehearsal_artifacts")
  and is_profile_gate_live_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_live_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and has_hosts(.vpn_track.profile_default_gate.next_command)
  and has_hosts(.vpn_track.profile_default_gate.next_command_sudo)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command_sudo)
' "$TMP_DIR/roadmap_progress_profile_default_docker_source_live_wrapper_summary.json" >/dev/null; then
  echo "profile default docker-source live-wrapper summary JSON missing expected host-aware conversion fields"
  cat "$TMP_DIR/roadmap_progress_profile_default_docker_source_live_wrapper_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default docker source live wrapper preserves quoted arg values"
PROFILE_DEFAULT_GATE_MANUAL_DOCKER_QUOTED_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_docker_quoted_summary.json"
cat >"$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_QUOTED_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_QUOTED_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "docker source localhost run should preserve quoted reports-dir/summary-json values through live-wrapper rewrite",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-default-gate-run --reports-dir './quoted reports dir' --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --subject INVITE_KEY --summary-json './quoted summary dir/profile compare campaign signoff summary.json' --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-default-gate-run --reports-dir './quoted reports dir' --directory-a http://127.0.0.1:18081 --directory-b http://127.0.0.1:28081 --campaign-issuer-url http://127.0.0.1:18082 --campaign-entry-url http://127.0.0.1:18083 --campaign-exit-url http://127.0.0.1:18084 --subject INVITE_KEY --summary-json './quoted summary dir/profile compare campaign signoff summary.json' --print-summary-json 1",
      "next_command_source": "docker_rehearsal_artifacts",
      "docker_rehearsal_hint_available": true
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_QUOTED_SUMMARY

if ! A_HOST="100.113.245.61" B_HOST="100.64.244.24" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_QUOTED_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_profile_default_docker_quoted_live_wrapper_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_profile_default_docker_quoted_live_wrapper_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_quoted_live_wrapper.log 2>&1; then
  echo "expected success when docker localhost profile-default command with quoted args is converted to live wrapper"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_quoted_live_wrapper.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_live_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def is_profile_gate_live_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def has_hosts($cmd):
    (($cmd // "") | test("(^| )--host-a 100\\.113\\.245\\.61( |$)"))
    and (($cmd // "") | test("(^| )--host-b 100\\.64\\.244\\.24( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  def has_quoted_reports($cmd):
    (($cmd // "") | contains("--reports-dir ./quoted\\ reports\\ dir"));
  def has_quoted_summary($cmd):
    (($cmd // "") | contains("--summary-json ./quoted\\ summary\\ dir/profile\\ compare\\ campaign\\ signoff\\ summary.json"));
  ((.next_actions // []) | any(
    .id == "profile_default_gate"
    and is_profile_gate_live_non_sudo_cmd(.command)
    and has_hosts(.command)
    and has_subject_placeholder(.command)
    and has_quoted_reports(.command)
    and has_quoted_summary(.command)
  ))
  and (.vpn_track.optional_gate_status.profile_default_gate == "pending")
  and ((.vpn_track.profile_default_gate.next_command_source // "") == "docker_rehearsal_artifacts")
  and is_profile_gate_live_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_live_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and has_hosts(.vpn_track.profile_default_gate.next_command)
  and has_hosts(.vpn_track.profile_default_gate.next_command_sudo)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command_sudo)
  and has_quoted_reports(.vpn_track.profile_default_gate.next_command)
  and has_quoted_reports(.vpn_track.profile_default_gate.next_command_sudo)
  and has_quoted_summary(.vpn_track.profile_default_gate.next_command)
  and has_quoted_summary(.vpn_track.profile_default_gate.next_command_sudo)
' "$TMP_DIR/roadmap_progress_profile_default_docker_quoted_live_wrapper_summary.json" >/dev/null; then
  echo "profile default docker localhost quoted live-wrapper summary JSON missing expected quoted-arg preservation"
  cat "$TMP_DIR/roadmap_progress_profile_default_docker_quoted_live_wrapper_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default docker source prefers live wrapper for real-host run command when A_HOST/B_HOST are set"
PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_docker_run_real_host_summary.json"
cat >"$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "docker source should prefer live wrapper even when profile-default-gate-run already points at real-host URLs",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a https://100.113.245.61:8081 --directory-b https://100.64.244.24:8081 --campaign-issuer-url https://100.113.245.61:8082 --campaign-entry-url https://100.113.245.61:8083 --campaign-exit-url https://100.113.245.61:8084 --subject INVITE_KEY --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec 901 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a https://100.113.245.61:8081 --directory-b https://100.64.244.24:8081 --campaign-issuer-url https://100.113.245.61:8082 --campaign-entry-url https://100.113.245.61:8083 --campaign-exit-url https://100.113.245.61:8084 --subject INVITE_KEY --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec 901 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "docker_rehearsal_artifacts",
      "docker_rehearsal_hint_available": true
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_SUMMARY

if ! A_HOST="100.113.245.61" B_HOST="100.64.244.24" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_profile_default_docker_run_real_host_live_wrapper_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_profile_default_docker_run_real_host_live_wrapper_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_run_real_host_live_wrapper.log 2>&1; then
  echo "expected success when docker profile-default-gate-run real-host command is converted to live wrapper under A_HOST/B_HOST"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_run_real_host_live_wrapper.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_live_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def is_profile_gate_live_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def has_hosts($cmd):
    (($cmd // "") | test("(^| )--host-a 100\\.113\\.245\\.61( |$)"))
    and (($cmd // "") | test("(^| )--host-b 100\\.64\\.244\\.24( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  def has_refresh_campaign($cmd):
    (($cmd // "") | test("(^| )--refresh-campaign 1( |$)"));
  def has_fail_on_no_go($cmd):
    (($cmd // "") | test("(^| )--fail-on-no-go 0( |$)"));
  def has_campaign_timeout($cmd):
    (($cmd // "") | test("(^| )--campaign-timeout-sec 901( |$)"));
  ((.next_actions // []) | any(
    .id == "profile_default_gate"
    and is_profile_gate_live_non_sudo_cmd(.command)
    and has_hosts(.command)
    and has_subject_placeholder(.command)
    and has_refresh_campaign(.command)
    and has_fail_on_no_go(.command)
    and has_campaign_timeout(.command)
  ))
  and (.vpn_track.optional_gate_status.profile_default_gate == "pending")
  and ((.vpn_track.profile_default_gate.next_command_source // "") == "docker_rehearsal_artifacts")
  and is_profile_gate_live_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_live_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and has_hosts(.vpn_track.profile_default_gate.next_command)
  and has_hosts(.vpn_track.profile_default_gate.next_command_sudo)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command_sudo)
  and has_refresh_campaign(.vpn_track.profile_default_gate.next_command)
  and has_refresh_campaign(.vpn_track.profile_default_gate.next_command_sudo)
  and has_fail_on_no_go(.vpn_track.profile_default_gate.next_command)
  and has_fail_on_no_go(.vpn_track.profile_default_gate.next_command_sudo)
  and has_campaign_timeout(.vpn_track.profile_default_gate.next_command)
  and has_campaign_timeout(.vpn_track.profile_default_gate.next_command_sudo)
' "$TMP_DIR/roadmap_progress_profile_default_docker_run_real_host_live_wrapper_summary.json" >/dev/null; then
  echo "profile default docker run real-host live-wrapper summary JSON missing expected host-aware conversion fields"
  cat "$TMP_DIR/roadmap_progress_profile_default_docker_run_real_host_live_wrapper_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default docker source derives live wrapper hosts from command directories when A_HOST/B_HOST are unset"
PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_NO_ENV_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_docker_run_real_host_no_env_summary.json"
cat >"$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_NO_ENV_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_NO_ENV_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "docker source should derive hosts from command directory endpoints when A_HOST/B_HOST are unset",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a https://100.113.245.61:8081 --directory-b https://100.64.244.24:8081 --campaign-issuer-url https://100.113.245.61:8082 --campaign-entry-url https://100.113.245.61:8083 --campaign-exit-url https://100.113.245.61:8084 --subject INVITE_KEY --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec 901 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-default-gate-run --reports-dir .easy-node-logs --directory-a https://203.0.113.10:8081 --directory-b https://198.51.100.20:8081 --campaign-issuer-url https://203.0.113.10:8082 --campaign-entry-url https://203.0.113.10:8083 --campaign-exit-url https://203.0.113.10:8084 --subject INVITE_KEY --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec 901 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "docker_rehearsal_artifacts",
      "docker_rehearsal_hint_available": true
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_NO_ENV_SUMMARY

if ! A_HOST="" B_HOST="" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_RUN_REAL_HOST_NO_ENV_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_profile_default_docker_run_real_host_no_env_live_wrapper_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_profile_default_docker_run_real_host_no_env_live_wrapper_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_run_real_host_no_env_live_wrapper.log 2>&1; then
  echo "expected success when docker profile-default-gate-run real-host command is converted to live wrapper without A_HOST/B_HOST"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_run_real_host_no_env_live_wrapper.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_live_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def is_profile_gate_live_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def has_hosts_real($cmd):
    (($cmd // "") | test("(^| )--host-a 100\\.113\\.245\\.61( |$)"))
    and (($cmd // "") | test("(^| )--host-b 100\\.64\\.244\\.24( |$)"));
  def has_hosts_sudo($cmd):
    (($cmd // "") | test("(^| )--host-a 203\\.0\\.113\\.10( |$)"))
    and (($cmd // "") | test("(^| )--host-b 198\\.51\\.100\\.20( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  def has_refresh_campaign($cmd):
    (($cmd // "") | test("(^| )--refresh-campaign 1( |$)"));
  def has_fail_on_no_go($cmd):
    (($cmd // "") | test("(^| )--fail-on-no-go 0( |$)"));
  def has_campaign_timeout($cmd):
    (($cmd // "") | test("(^| )--campaign-timeout-sec 901( |$)"));
  ((.next_actions // []) | any(
    .id == "profile_default_gate"
    and is_profile_gate_live_non_sudo_cmd(.command)
    and has_hosts_real(.command)
    and has_subject_placeholder(.command)
    and has_refresh_campaign(.command)
    and has_fail_on_no_go(.command)
    and has_campaign_timeout(.command)
  ))
  and (.vpn_track.optional_gate_status.profile_default_gate == "pending")
  and ((.vpn_track.profile_default_gate.next_command_source // "") == "docker_rehearsal_artifacts")
  and is_profile_gate_live_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_live_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and has_hosts_real(.vpn_track.profile_default_gate.next_command)
  and has_hosts_sudo(.vpn_track.profile_default_gate.next_command_sudo)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command_sudo)
  and has_refresh_campaign(.vpn_track.profile_default_gate.next_command)
  and has_refresh_campaign(.vpn_track.profile_default_gate.next_command_sudo)
  and has_fail_on_no_go(.vpn_track.profile_default_gate.next_command)
  and has_fail_on_no_go(.vpn_track.profile_default_gate.next_command_sudo)
  and has_campaign_timeout(.vpn_track.profile_default_gate.next_command)
  and has_campaign_timeout(.vpn_track.profile_default_gate.next_command_sudo)
' "$TMP_DIR/roadmap_progress_profile_default_docker_run_real_host_no_env_live_wrapper_summary.json" >/dev/null; then
  echo "profile default docker run real-host no-env live-wrapper summary JSON missing expected extracted-host conversion fields"
  cat "$TMP_DIR/roadmap_progress_profile_default_docker_run_real_host_no_env_live_wrapper_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default docker signoff source prefers live wrapper when A_HOST/B_HOST are set"
PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_docker_signoff_source_summary.json"
cat >"$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "docker signoff hint should convert to host-aware live wrapper when real hosts are provided",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec 901 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec 901 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "docker_rehearsal_artifacts",
      "docker_rehearsal_hint_available": true
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_SUMMARY

if ! A_HOST="100.113.245.61" B_HOST="100.64.244.24" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_profile_default_docker_signoff_source_live_wrapper_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_profile_default_docker_signoff_source_live_wrapper_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_signoff_source_live_wrapper.log 2>&1; then
  echo "expected success when docker signoff hint is converted to live wrapper under A_HOST/B_HOST"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_signoff_source_live_wrapper.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_live_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def is_profile_gate_live_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def has_hosts($cmd):
    (($cmd // "") | test("(^| )--host-a 100\\.113\\.245\\.61( |$)"))
    and (($cmd // "") | test("(^| )--host-b 100\\.64\\.244\\.24( |$)"));
  def has_subject_placeholder($cmd):
    (($cmd // "") | test("(^| )--subject INVITE_KEY( |$)"));
  def has_refresh_campaign($cmd):
    (($cmd // "") | test("(^| )--refresh-campaign 1( |$)"));
  def has_fail_on_no_go($cmd):
    (($cmd // "") | test("(^| )--fail-on-no-go 0( |$)"));
  def has_campaign_timeout($cmd):
    (($cmd // "") | test("(^| )--campaign-timeout-sec 901( |$)"));
  ((.next_actions // []) | any(
    .id == "profile_default_gate"
    and is_profile_gate_live_non_sudo_cmd(.command)
    and has_hosts(.command)
    and has_subject_placeholder(.command)
    and has_refresh_campaign(.command)
    and has_fail_on_no_go(.command)
    and has_campaign_timeout(.command)
  ))
  and (.vpn_track.optional_gate_status.profile_default_gate == "pending")
  and ((.vpn_track.profile_default_gate.next_command_source // "") == "docker_rehearsal_artifacts")
  and is_profile_gate_live_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_live_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and has_hosts(.vpn_track.profile_default_gate.next_command)
  and has_hosts(.vpn_track.profile_default_gate.next_command_sudo)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command)
  and has_subject_placeholder(.vpn_track.profile_default_gate.next_command_sudo)
  and has_refresh_campaign(.vpn_track.profile_default_gate.next_command)
  and has_refresh_campaign(.vpn_track.profile_default_gate.next_command_sudo)
  and has_fail_on_no_go(.vpn_track.profile_default_gate.next_command)
  and has_fail_on_no_go(.vpn_track.profile_default_gate.next_command_sudo)
  and has_campaign_timeout(.vpn_track.profile_default_gate.next_command)
  and has_campaign_timeout(.vpn_track.profile_default_gate.next_command_sudo)
' "$TMP_DIR/roadmap_progress_profile_default_docker_signoff_source_live_wrapper_summary.json" >/dev/null; then
  echo "profile default docker-signoff live-wrapper summary JSON missing expected host-aware conversion fields"
  cat "$TMP_DIR/roadmap_progress_profile_default_docker_signoff_source_live_wrapper_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default docker signoff source with anon creds stays signoff-mode and redacts credential values when A_HOST/B_HOST are unset"
PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_NO_ENV_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_docker_signoff_source_no_env_summary.json"
cat >"$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_NO_ENV_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_NO_ENV_SUMMARY'
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
    "profile_default_gate": {
      "status": "pending",
      "notes": "docker signoff hint should derive hosts from campaign-directory-urls with bootstrap fallback for host-a when env hosts are unset",
      "decision": "NO-GO",
      "recommended_profile": "balanced",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --campaign-directory-urls 'https://198.51.100.31:8081,https://198.51.100.32:8081' --campaign-anon-cred SIGNOFF_CAMPAIGN_ANON --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec 901 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_sudo": "sudo ./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --campaign-directory-urls ',https://203.0.113.42:8081' --campaign-bootstrap-directory https://203.0.113.41:8081 --anon-cred SIGNOFF_ANON --refresh-campaign 1 --fail-on-no-go 0 --campaign-timeout-sec 901 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "next_command_source": "docker_rehearsal_artifacts",
      "docker_rehearsal_hint_available": true
    },
    "docker_rehearsal_gate": {
      "status": "pass",
      "command": "./scripts/easy_node.sh three-machine-docker-readiness-record --path-profile balanced --soak-rounds 6 --soak-pause-sec 3 --print-summary-json 1"
    },
    "real_wg_privileged_gate": {
      "status": "pass",
      "command": "sudo ./scripts/easy_node.sh real-wg-privileged-matrix-record --print-summary-json 1"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_NO_ENV_SUMMARY

if ! A_HOST="" B_HOST="" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_MANUAL_DOCKER_SIGNOFF_NO_ENV_SUMMARY_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_profile_default_docker_signoff_source_no_env_live_wrapper_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_profile_default_docker_signoff_source_no_env_live_wrapper_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_signoff_source_no_env_live_wrapper.log 2>&1; then
  echo "expected success when docker signoff hint stays signoff-mode for anon creds without A_HOST/B_HOST"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_docker_signoff_source_no_env_live_wrapper.log
  exit 1
fi
if ! jq -e '
  def is_profile_gate_signoff_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-compare-campaign-signoff( |$)"));
  def is_profile_gate_signoff_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-compare-campaign-signoff( |$)"));
  def is_profile_gate_live_non_sudo_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def is_profile_gate_live_sudo_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-default-gate-live( |$)"));
  def has_campaign_anon_cred_redacted($cmd):
    (($cmd // "") | test("(^| )--campaign-anon-cred ANON_CRED( |$)"));
  def has_anon_cred_redacted($cmd):
    (($cmd // "") | test("(^| )--anon-cred ANON_CRED( |$)"));
  def has_raw_anon_tokens($cmd):
    (($cmd // "") | test("SIGNOFF_CAMPAIGN_ANON|SIGNOFF_ANON"));
  def has_refresh_campaign($cmd):
    (($cmd // "") | test("(^| )--refresh-campaign 1( |$)"));
  def has_fail_on_no_go($cmd):
    (($cmd // "") | test("(^| )--fail-on-no-go 0( |$)"));
  def has_campaign_timeout($cmd):
    (($cmd // "") | test("(^| )--campaign-timeout-sec 901( |$)"));
  ((.next_actions // []) | any(
    .id == "profile_default_gate"
    and is_profile_gate_signoff_non_sudo_cmd(.command)
    and has_campaign_anon_cred_redacted(.command)
    and ((is_profile_gate_live_non_sudo_cmd(.command)) | not)
    and ((has_raw_anon_tokens(.command)) | not)
    and has_refresh_campaign(.command)
    and has_fail_on_no_go(.command)
    and has_campaign_timeout(.command)
  ))
  and (.vpn_track.optional_gate_status.profile_default_gate == "pending")
  and ((.vpn_track.profile_default_gate.next_command_source // "") == "docker_rehearsal_artifacts")
  and is_profile_gate_signoff_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)
  and is_profile_gate_signoff_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and ((is_profile_gate_live_non_sudo_cmd(.vpn_track.profile_default_gate.next_command)) | not)
  and ((is_profile_gate_live_sudo_cmd(.vpn_track.profile_default_gate.next_command_sudo)) | not)
  and has_campaign_anon_cred_redacted(.vpn_track.profile_default_gate.next_command)
  and has_anon_cred_redacted(.vpn_track.profile_default_gate.next_command_sudo)
  and ((has_raw_anon_tokens(.vpn_track.profile_default_gate.next_command)) | not)
  and ((has_raw_anon_tokens(.vpn_track.profile_default_gate.next_command_sudo)) | not)
  and has_refresh_campaign(.vpn_track.profile_default_gate.next_command)
  and has_refresh_campaign(.vpn_track.profile_default_gate.next_command_sudo)
  and has_fail_on_no_go(.vpn_track.profile_default_gate.next_command)
  and has_fail_on_no_go(.vpn_track.profile_default_gate.next_command_sudo)
  and has_campaign_timeout(.vpn_track.profile_default_gate.next_command)
  and has_campaign_timeout(.vpn_track.profile_default_gate.next_command_sudo)
' "$TMP_DIR/roadmap_progress_profile_default_docker_signoff_source_no_env_live_wrapper_summary.json" >/dev/null; then
  echo "profile default docker-signoff no-env summary JSON missing expected signoff-mode anon-cred redaction fields"
  cat "$TMP_DIR/roadmap_progress_profile_default_docker_signoff_source_no_env_live_wrapper_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate derives warn from NO-GO signoff summary"
PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_JSON="$TMP_DIR/profile_compare_campaign_signoff_no_go.json"
cat >"$PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_JSON" <<'EOF_PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO'
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "decision": {
    "decision": "NO-GO",
    "go": false,
    "recommended_profile": "balanced"
  }
}
EOF_PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$OPTIONAL_FALLBACK_MANUAL_SUMMARY_JSON" \
  --profile-compare-signoff-summary-json "$PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_no_go_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_no_go_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_no_go.log 2>&1; then
  echo "expected success when profile default gate signoff summary reports NO-GO"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_no_go.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_JSON" '
  .vpn_track.optional_gate_status.profile_default_gate == "warn"
  and .artifacts.profile_compare_signoff_summary_json == $src
  and .vpn_track.profile_default_gate.selection_policy_evidence_present == false
  and .vpn_track.profile_default_gate.selection_policy_evidence_valid == false
  and ((.vpn_track.profile_default_gate.selection_policy_evidence_note // "") | test("selection-policy evidence missing"))
  and .vpn_track.profile_default_gate.micro_relay_evidence_available == false
  and .vpn_track.profile_default_gate.micro_relay_quality_status_pass == null
  and .vpn_track.profile_default_gate.micro_relay_demotion_policy_present == false
  and .vpn_track.profile_default_gate.micro_relay_promotion_policy_present == false
  and .vpn_track.profile_default_gate.trust_tier_port_unlock_policy_present == false
  and ((.vpn_track.profile_default_gate.micro_relay_evidence_note // "") | test("micro-relay M4 evidence unavailable"))
' "$TMP_DIR/roadmap_progress_profile_default_gate_no_go_summary.json" >/dev/null; then
  echo "NO-GO profile default gate summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_no_go_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate surfaces micro-relay M4 evidence when present in signoff summary"
PROFILE_DEFAULT_GATE_SIGNOFF_M4_PRESENT_JSON="$TMP_DIR/profile_compare_campaign_signoff_m4_present.json"
cat >"$PROFILE_DEFAULT_GATE_SIGNOFF_M4_PRESENT_JSON" <<'EOF_PROFILE_DEFAULT_GATE_SIGNOFF_M4_PRESENT'
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "decision": {
    "decision": "NO-GO",
    "go": false,
    "recommended_profile": "balanced"
  },
  "summary": {
    "m4_micro_relay_evidence": {
      "available": true,
      "micro_relay_quality": {
        "available": true,
        "quality_band": "good",
        "quality_score": 92
      },
      "adaptive_demotion_promotion": {
        "available": true,
        "demotion_candidate": false,
        "promotion_candidate": true
      },
      "trust_tier_port_unlock_wiring": {
        "present": true,
        "evidence_hits": 2
      }
    }
  }
}
EOF_PROFILE_DEFAULT_GATE_SIGNOFF_M4_PRESENT

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$OPTIONAL_FALLBACK_MANUAL_SUMMARY_JSON" \
  --profile-compare-signoff-summary-json "$PROFILE_DEFAULT_GATE_SIGNOFF_M4_PRESENT_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_m4_present_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_m4_present_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_m4_present.log 2>&1; then
  echo "expected success when profile default gate signoff summary includes micro-relay M4 evidence"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_m4_present.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_SIGNOFF_M4_PRESENT_JSON" '
  .vpn_track.optional_gate_status.profile_default_gate == "warn"
  and .artifacts.profile_compare_signoff_summary_json == $src
  and .vpn_track.profile_default_gate.micro_relay_evidence_available == true
  and .vpn_track.profile_default_gate.micro_relay_quality_status_pass == true
  and .vpn_track.profile_default_gate.micro_relay_demotion_policy_present == true
  and .vpn_track.profile_default_gate.micro_relay_promotion_policy_present == true
  and .vpn_track.profile_default_gate.trust_tier_port_unlock_policy_present == true
  and .vpn_track.profile_default_gate.micro_relay_evidence_note == null
' "$TMP_DIR/roadmap_progress_profile_default_gate_m4_present_summary.json" >/dev/null; then
  echo "micro-relay evidence profile default gate summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_m4_present_summary.json"
  exit 1
fi
if ! grep -q '\[roadmap-progress-report\] profile_default_gate_micro_relay_evidence_available=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_m4_present.log; then
  echo "expected micro-relay evidence stdout line not found"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_m4_present.log
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate derives pending from NO-GO signoff when campaign evidence is insufficient"
PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_INSUFFICIENT_JSON="$TMP_DIR/profile_compare_campaign_signoff_no_go_insufficient.json"
PROFILE_DEFAULT_GATE_CAMPAIGN_CHECK_REL_PATH="profile_gate_signoff_artifacts/profile_compare_campaign_check_summary_insufficient.json"
PROFILE_DEFAULT_GATE_CAMPAIGN_CHECK_ABS_PATH="$TMP_DIR/$PROFILE_DEFAULT_GATE_CAMPAIGN_CHECK_REL_PATH"
mkdir -p "$(dirname "$PROFILE_DEFAULT_GATE_CAMPAIGN_CHECK_ABS_PATH")"
cat >"$PROFILE_DEFAULT_GATE_CAMPAIGN_CHECK_ABS_PATH" <<'EOF_PROFILE_DEFAULT_GATE_CAMPAIGN_CHECK_INSUFFICIENT'
{
  "version": 1,
  "decision": "NO-GO",
  "status": "fail",
  "rc": 1,
  "inputs": {
    "policy": {
      "require_status_pass": true,
      "require_trend_status_pass": true,
      "require_min_runs_total": 3,
      "require_min_runs_with_summary": 3
    }
  },
  "observed": {
    "campaign_status": "pass",
    "trend_status": "pass",
    "runs_total": 1,
    "runs_with_summary": 1
  }
}
EOF_PROFILE_DEFAULT_GATE_CAMPAIGN_CHECK_INSUFFICIENT
cat >"$PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_INSUFFICIENT_JSON" <<EOF_PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_INSUFFICIENT
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "decision": {
    "decision": "NO-GO",
    "go": false,
    "recommended_profile": "balanced"
  },
  "artifacts": {
    "campaign_check_summary_json": "$PROFILE_DEFAULT_GATE_CAMPAIGN_CHECK_REL_PATH"
  }
}
EOF_PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_INSUFFICIENT

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$OPTIONAL_FALLBACK_MANUAL_SUMMARY_JSON" \
  --profile-compare-signoff-summary-json "$PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_INSUFFICIENT_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_no_go_insufficient_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_no_go_insufficient_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_no_go_insufficient.log 2>&1; then
  echo "expected success when profile default gate NO-GO has insufficient campaign evidence"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_no_go_insufficient.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_SIGNOFF_NO_GO_INSUFFICIENT_JSON" '
  .vpn_track.optional_gate_status.profile_default_gate == "pending"
  and .artifacts.profile_compare_signoff_summary_json == $src
  and .vpn_track.profile_default_gate.selection_policy_evidence_present == false
  and .vpn_track.profile_default_gate.selection_policy_evidence_valid == false
  and ((.vpn_track.profile_default_gate.selection_policy_evidence_note // "") | test("selection-policy evidence missing"))
  and .vpn_track.profile_default_gate.micro_relay_evidence_available == false
  and .vpn_track.profile_default_gate.micro_relay_quality_status_pass == null
  and .vpn_track.profile_default_gate.micro_relay_demotion_policy_present == false
  and .vpn_track.profile_default_gate.micro_relay_promotion_policy_present == false
  and .vpn_track.profile_default_gate.trust_tier_port_unlock_policy_present == false
  and ((.vpn_track.profile_default_gate.micro_relay_evidence_note // "") | test("micro-relay M4 evidence unavailable"))
' "$TMP_DIR/roadmap_progress_profile_default_gate_no_go_insufficient_summary.json" >/dev/null; then
  echo "NO-GO insufficient evidence profile default gate summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_no_go_insufficient_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate derives pending from pending signoff summary"
PROFILE_DEFAULT_GATE_SIGNOFF_PENDING_JSON="$TMP_DIR/profile_compare_campaign_signoff_pending.json"
cat >"$PROFILE_DEFAULT_GATE_SIGNOFF_PENDING_JSON" <<'EOF_PROFILE_DEFAULT_GATE_SIGNOFF_PENDING'
{
  "version": 1,
  "status": "pending",
  "final_rc": 0
}
EOF_PROFILE_DEFAULT_GATE_SIGNOFF_PENDING

if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$OPTIONAL_FALLBACK_MANUAL_SUMMARY_JSON" \
  --profile-compare-signoff-summary-json "$PROFILE_DEFAULT_GATE_SIGNOFF_PENDING_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_pending_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_pending_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_pending.log 2>&1; then
  echo "expected success when profile default gate signoff summary is pending"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_pending.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_SIGNOFF_PENDING_JSON" '
  .vpn_track.optional_gate_status.profile_default_gate == "pending"
  and .artifacts.profile_compare_signoff_summary_json == $src
  and .vpn_track.profile_default_gate.selection_policy_evidence_present == false
  and .vpn_track.profile_default_gate.selection_policy_evidence_valid == false
  and ((.vpn_track.profile_default_gate.selection_policy_evidence_note // "") | test("selection-policy evidence missing"))
' "$TMP_DIR/roadmap_progress_profile_default_gate_pending_summary.json" >/dev/null; then
  echo "pending profile default gate summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_pending_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate falls back to pending when signoff summary is missing"
MISSING_PROFILE_DEFAULT_GATE_SIGNOFF_JSON="$TMP_DIR/missing_profile_compare_campaign_signoff_summary.json"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$OPTIONAL_FALLBACK_MANUAL_SUMMARY_JSON" \
  --profile-compare-signoff-summary-json "$MISSING_PROFILE_DEFAULT_GATE_SIGNOFF_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_missing_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_missing_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_missing.log 2>&1; then
  echo "expected success when profile default gate signoff summary is missing"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_missing.log
  exit 1
fi
if ! jq -e '
  .vpn_track.optional_gate_status.profile_default_gate == "pending"
  and .vpn_track.profile_default_gate.selection_policy_evidence_present == null
  and .vpn_track.profile_default_gate.selection_policy_evidence_valid == null
  and ((.vpn_track.profile_default_gate.selection_policy_evidence_note // "") | test("selection-policy evidence unavailable"))
' "$TMP_DIR/roadmap_progress_profile_default_gate_missing_summary.json" >/dev/null; then
  echo "missing profile default gate fallback summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_missing_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate generates fallback command when summary lacks next_command"
if ! run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$OPTIONAL_FALLBACK_MANUAL_SUMMARY_JSON" \
  --profile-compare-signoff-summary-json "$PROFILE_DEFAULT_GATE_SIGNOFF_PENDING_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_missing_command_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_missing_command_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_missing_command.log 2>&1; then
  echo "expected success when profile default gate next_command fields are missing"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_missing_command.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_SIGNOFF_PENDING_JSON" '
  def is_non_sudo_profile_gate_cmd($cmd):
    (($cmd // "") | test("^\\./scripts/easy_node\\.sh profile-compare-campaign-signoff( |$)"));
  def is_sudo_profile_gate_cmd($cmd):
    (($cmd // "") | test("^sudo \\./scripts/easy_node\\.sh profile-compare-campaign-signoff( |$)"));
  .vpn_track.optional_gate_status.profile_default_gate == "pending"
  and is_non_sudo_profile_gate_cmd(.vpn_track.profile_default_gate.next_command)
  and is_sudo_profile_gate_cmd(.vpn_track.profile_default_gate.next_command_sudo)
  and (.vpn_track.profile_default_gate.next_command_source == "default_non_sudo")
  and ((.vpn_track.profile_default_gate.next_command // "") | contains("--campaign-timeout-sec 2400"))
  and ((.vpn_track.profile_default_gate.next_command // "") | contains("--summary-json " + $src))
  and ((.vpn_track.profile_default_gate.next_command // "") | contains("--subject INVITE_KEY"))
  and .vpn_track.profile_default_gate.selection_policy_evidence_present == false
  and .vpn_track.profile_default_gate.selection_policy_evidence_valid == false
  and ((.vpn_track.profile_default_gate.selection_policy_evidence_note // "") | test("selection-policy evidence missing"))
  and ((.next_actions // []) | any(.id == "profile_default_gate" and is_non_sudo_profile_gate_cmd(.command)))
' "$TMP_DIR/roadmap_progress_profile_default_gate_missing_command_summary.json" >/dev/null; then
  echo "profile default gate missing-command fallback summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_missing_command_summary.json"
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate stability summary defaults to reports_dir artifact"
PROFILE_DEFAULT_GATE_STABILITY_REPORTS_DIR="$TMP_DIR/profile_default_gate_stability_reports"
mkdir -p "$PROFILE_DEFAULT_GATE_STABILITY_REPORTS_DIR"
PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_SUMMARY_JSON="$PROFILE_DEFAULT_GATE_STABILITY_REPORTS_DIR/profile_default_gate_stability_summary.json"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_default_gate_stability_summary"
  },
  "status": "ok",
  "rc": 0,
  "inputs": {
    "runs_requested": 3
  },
  "runs_completed": 3,
  "consistent_selection_policy": true,
  "selection_policy_present_all": true,
  "recommended_profile_counts": {
    "balanced": 2,
    "private": 1
  },
  "stability_ok": true
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_SUMMARY
PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_gate_stability_default_summary.json"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_MANUAL_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_MANUAL_SUMMARY'
{
  "version": 1,
  "summary": {
    "next_action_check_id": "",
    "next_action_command": "",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": [],
    "optional_check_ids": [],
    "profile_default_gate": {
      "status": "pending",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1"
    },
    "docker_rehearsal_gate": {
      "status": "pending"
    },
    "real_wg_privileged_gate": {
      "status": "pending"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_MANUAL_SUMMARY
if ! EASY_NODE_LOG_DIR="$PROFILE_DEFAULT_GATE_STABILITY_REPORTS_DIR" run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_stability_default_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_stability_default_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_default.log 2>&1; then
  echo "expected success when profile default gate stability summary exists at reports_dir default artifact path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_default.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_STABILITY_DEFAULT_SUMMARY_JSON" '
  .vpn_track.profile_default_gate.stability_summary_json == $src
  and .vpn_track.profile_default_gate.stability_summary_available == true
  and .vpn_track.profile_default_gate.stability_status == "ok"
  and .vpn_track.profile_default_gate.stability_rc == 0
  and .vpn_track.profile_default_gate.stability_runs_requested == 3
  and .vpn_track.profile_default_gate.stability_runs_completed == 3
  and .vpn_track.profile_default_gate.stability_selection_policy_present_all == true
  and .vpn_track.profile_default_gate.stability_consistent_selection_policy == true
  and .vpn_track.profile_default_gate.stability_ok == true
  and .vpn_track.profile_default_gate.stability_recommended_profile_counts == {"balanced":2,"private":1}
' "$TMP_DIR/roadmap_progress_profile_default_gate_stability_default_summary.json" >/dev/null; then
  echo "profile default gate stability default-artifact summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_stability_default_summary.json"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] profile_default_gate_stability_summary_json=.*stability_summary_available=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_default.log; then
  echo "expected profile default gate stability availability log line in default-artifact scenario"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_default.log
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate stability summary explicit invalid artifact is fail-closed/null-safe"
PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_DIR="$TMP_DIR/profile_default_gate_stability_explicit_invalid"
mkdir -p "$PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_DIR/artifacts"
PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_REL_PATH="artifacts/profile_default_gate_stability_summary_invalid.json"
PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_JSON="$PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_DIR/$PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_REL_PATH"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_JSON" <<'EOF_PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID'
{
  "version": 1,
  "schema": {
    "id": "wrong_schema"
  },
  "status": "ok",
  "rc": 0
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID
PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_MANUAL_SUMMARY_JSON="$PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_DIR/manual_validation_profile_default_gate_stability_invalid_summary.json"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_MANUAL_SUMMARY_JSON" <<EOF_PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_MANUAL_SUMMARY
{
  "version": 1,
  "summary": {
    "next_action_check_id": "",
    "next_action_command": "",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": [],
    "optional_check_ids": [],
    "profile_default_gate": {
      "status": "pending",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "artifacts": {
        "profile_default_gate_stability_summary_json": "$PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_REL_PATH"
      }
    },
    "docker_rehearsal_gate": {
      "status": "pending"
    },
    "real_wg_privileged_gate": {
      "status": "pending"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_MANUAL_SUMMARY
if ! EASY_NODE_LOG_DIR="$PROFILE_DEFAULT_GATE_STABILITY_REPORTS_DIR" run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_stability_explicit_invalid_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_stability_explicit_invalid_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_explicit_invalid.log 2>&1; then
  echo "expected success when explicit profile default gate stability summary path is invalid"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_explicit_invalid.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_STABILITY_EXPLICIT_INVALID_JSON" '
  .vpn_track.profile_default_gate.stability_summary_json == $src
  and .vpn_track.profile_default_gate.stability_summary_available == false
  and .vpn_track.profile_default_gate.stability_status == null
  and .vpn_track.profile_default_gate.stability_rc == null
  and .vpn_track.profile_default_gate.stability_runs_requested == null
  and .vpn_track.profile_default_gate.stability_runs_completed == null
  and .vpn_track.profile_default_gate.stability_selection_policy_present_all == null
  and .vpn_track.profile_default_gate.stability_consistent_selection_policy == null
  and .vpn_track.profile_default_gate.stability_ok == null
  and .vpn_track.profile_default_gate.stability_recommended_profile_counts == null
' "$TMP_DIR/roadmap_progress_profile_default_gate_stability_explicit_invalid_summary.json" >/dev/null; then
  echo "profile default gate stability explicit-invalid summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_stability_explicit_invalid_summary.json"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] profile_default_gate_stability_summary_json=.*stability_summary_available=false' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_explicit_invalid.log; then
  echo "expected profile default gate stability availability log line in explicit-invalid scenario"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_explicit_invalid.log
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate stability-check summary defaults to reports_dir artifact"
PROFILE_DEFAULT_GATE_STABILITY_CHECK_REPORTS_DIR="$TMP_DIR/profile_default_gate_stability_check_reports"
mkdir -p "$PROFILE_DEFAULT_GATE_STABILITY_CHECK_REPORTS_DIR"
PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_SUMMARY_JSON="$PROFILE_DEFAULT_GATE_STABILITY_CHECK_REPORTS_DIR/profile_default_gate_stability_check_summary.json"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_SUMMARY'
{
  "version": 1,
  "decision": "GO",
  "status": "ok",
  "rc": 0,
  "observed": {
    "modal_recommended_profile": "balanced",
    "modal_support_rate_pct": 66.67
  }
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_SUMMARY
PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_gate_stability_check_default_summary.json"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_MANUAL_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_MANUAL_SUMMARY'
{
  "version": 1,
  "summary": {
    "next_action_check_id": "",
    "next_action_command": "",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": [],
    "optional_check_ids": [],
    "profile_default_gate": {
      "status": "pending",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1"
    },
    "docker_rehearsal_gate": {
      "status": "pending"
    },
    "real_wg_privileged_gate": {
      "status": "pending"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_MANUAL_SUMMARY
if ! EASY_NODE_LOG_DIR="$PROFILE_DEFAULT_GATE_STABILITY_CHECK_REPORTS_DIR" run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_stability_check_default_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_stability_check_default_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_check_default.log 2>&1; then
  echo "expected success when profile default gate stability-check summary exists at reports_dir default artifact path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_check_default.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_STABILITY_CHECK_DEFAULT_SUMMARY_JSON" '
  .vpn_track.profile_default_gate.stability_check_summary_json == $src
  and .vpn_track.profile_default_gate.stability_check_summary_available == true
  and .vpn_track.profile_default_gate.stability_check_decision == "GO"
  and .vpn_track.profile_default_gate.stability_check_status == "ok"
  and .vpn_track.profile_default_gate.stability_check_rc == 0
  and .vpn_track.profile_default_gate.stability_check_modal_recommended_profile == "balanced"
  and .vpn_track.profile_default_gate.stability_check_modal_support_rate_pct == 66.67
' "$TMP_DIR/roadmap_progress_profile_default_gate_stability_check_default_summary.json" >/dev/null; then
  echo "profile default gate stability-check default-artifact summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_stability_check_default_summary.json"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] profile_default_gate_stability_check_summary_json=.*stability_check_summary_available=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_check_default.log; then
  echo "expected profile default gate stability-check availability log line in default-artifact scenario"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_check_default.log
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate stability-check summary explicit invalid artifact is fail-closed/null-safe"
PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_DIR="$TMP_DIR/profile_default_gate_stability_check_explicit_invalid"
mkdir -p "$PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_DIR/artifacts"
PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_REL_PATH="artifacts/profile_default_gate_stability_check_summary_invalid.json"
PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_JSON="$PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_DIR/$PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_REL_PATH"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_JSON" <<'EOF_PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID'
{
  "version": 1,
  "status": "ok",
  "rc": 0,
  "observed": {
    "modal_recommended_profile": "balanced",
    "modal_support_rate_pct": 66.67
  }
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID
PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_MANUAL_SUMMARY_JSON="$PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_DIR/manual_validation_profile_default_gate_stability_check_invalid_summary.json"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_MANUAL_SUMMARY_JSON" <<EOF_PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_MANUAL_SUMMARY
{
  "version": 1,
  "summary": {
    "next_action_check_id": "",
    "next_action_command": "",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": [],
    "optional_check_ids": [],
    "profile_default_gate": {
      "status": "pending",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "artifacts": {
        "profile_default_gate_stability_check_summary_json": "$PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_REL_PATH"
      }
    },
    "docker_rehearsal_gate": {
      "status": "pending"
    },
    "real_wg_privileged_gate": {
      "status": "pending"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_MANUAL_SUMMARY
if ! EASY_NODE_LOG_DIR="$PROFILE_DEFAULT_GATE_STABILITY_CHECK_REPORTS_DIR" run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_stability_check_explicit_invalid_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_stability_check_explicit_invalid_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_check_explicit_invalid.log 2>&1; then
  echo "expected success when explicit profile default gate stability-check summary path is invalid"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_check_explicit_invalid.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_STABILITY_CHECK_EXPLICIT_INVALID_JSON" '
  .vpn_track.profile_default_gate.stability_check_summary_json == $src
  and .vpn_track.profile_default_gate.stability_check_summary_available == false
  and .vpn_track.profile_default_gate.stability_check_decision == null
  and .vpn_track.profile_default_gate.stability_check_status == null
  and .vpn_track.profile_default_gate.stability_check_rc == null
  and .vpn_track.profile_default_gate.stability_check_modal_recommended_profile == null
  and .vpn_track.profile_default_gate.stability_check_modal_support_rate_pct == null
' "$TMP_DIR/roadmap_progress_profile_default_gate_stability_check_explicit_invalid_summary.json" >/dev/null; then
  echo "profile default gate stability-check explicit-invalid summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_stability_check_explicit_invalid_summary.json"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] profile_default_gate_stability_check_summary_json=.*stability_check_summary_available=false' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_check_explicit_invalid.log; then
  echo "expected profile default gate stability-check availability log line in explicit-invalid scenario"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_check_explicit_invalid.log
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate stability-cycle summary defaults to reports_dir artifact"
PROFILE_DEFAULT_GATE_STABILITY_CYCLE_REPORTS_DIR="$TMP_DIR/profile_default_gate_stability_cycle_reports"
mkdir -p "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_REPORTS_DIR"
PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_SUMMARY_JSON="$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_REPORTS_DIR/profile_default_gate_stability_cycle_summary.json"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_default_gate_stability_cycle_summary"
  },
  "decision": "GO",
  "status": "pass",
  "rc": 0,
  "failure_stage": null,
  "failure_reason": null
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_SUMMARY
PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_MANUAL_SUMMARY_JSON="$TMP_DIR/manual_validation_profile_default_gate_stability_cycle_default_summary.json"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_MANUAL_SUMMARY_JSON" <<'EOF_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_MANUAL_SUMMARY'
{
  "version": 1,
  "summary": {
    "next_action_check_id": "",
    "next_action_command": "",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": [],
    "optional_check_ids": [],
    "profile_default_gate": {
      "status": "pending",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1"
    },
    "docker_rehearsal_gate": {
      "status": "pending"
    },
    "real_wg_privileged_gate": {
      "status": "pending"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_MANUAL_SUMMARY
if ! EASY_NODE_LOG_DIR="$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_REPORTS_DIR" run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_default_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_default_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_default.log 2>&1; then
  echo "expected success when profile default gate stability-cycle summary exists at reports_dir default artifact path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_default.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_SUMMARY_JSON" '
  .vpn_track.profile_default_gate.cycle_summary_json == $src
  and .vpn_track.profile_default_gate.cycle_summary_available == true
  and .vpn_track.profile_default_gate.cycle_decision == "GO"
  and .vpn_track.profile_default_gate.cycle_status == "pass"
  and .vpn_track.profile_default_gate.cycle_rc == 0
  and .vpn_track.profile_default_gate.cycle_failure_stage == null
  and .vpn_track.profile_default_gate.cycle_failure_reason == null
' "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_default_summary.json" >/dev/null; then
  echo "profile default gate stability-cycle default-artifact summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_default_summary.json"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] profile_default_gate_stability_cycle_summary_json=.*cycle_summary_available=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_default.log; then
  echo "expected profile default gate stability-cycle availability log line in default-artifact scenario"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_default.log
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate stability-cycle summary explicit invalid artifact is fail-closed/null-safe"
PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_DIR="$TMP_DIR/profile_default_gate_stability_cycle_explicit_invalid"
mkdir -p "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_DIR/artifacts"
PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_REL_PATH="artifacts/profile_default_gate_stability_cycle_summary_invalid.json"
PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_JSON="$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_DIR/$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_REL_PATH"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_JSON" <<'EOF_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID'
{
  "version": 1,
  "schema": {
    "id": "wrong_schema"
  },
  "decision": 1,
  "status": false,
  "rc": "0"
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID
PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_MANUAL_SUMMARY_JSON="$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_DIR/manual_validation_profile_default_gate_stability_cycle_invalid_summary.json"
cat >"$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_MANUAL_SUMMARY_JSON" <<EOF_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_MANUAL_SUMMARY
{
  "version": 1,
  "summary": {
    "next_action_check_id": "",
    "next_action_command": "",
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "single_machine_ready": true,
    "blocking_check_ids": [],
    "optional_check_ids": [],
    "profile_default_gate": {
      "status": "pending",
      "next_command": "./scripts/easy_node.sh profile-compare-campaign-signoff --reports-dir .easy-node-logs --refresh-campaign 1 --fail-on-no-go 0 --summary-json .easy-node-logs/profile_compare_campaign_signoff_summary.json --print-summary-json 1",
      "artifacts": {
        "profile_default_gate_stability_cycle_summary_json": "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_REL_PATH"
      }
    },
    "docker_rehearsal_gate": {
      "status": "pending"
    },
    "real_wg_privileged_gate": {
      "status": "pending"
    }
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_MANUAL_SUMMARY
if ! EASY_NODE_LOG_DIR="$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_REPORTS_DIR" run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_explicit_invalid_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_explicit_invalid_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_explicit_invalid.log 2>&1; then
  echo "expected success when explicit profile default gate stability-cycle summary path is invalid"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_explicit_invalid.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_EXPLICIT_INVALID_JSON" '
  .vpn_track.profile_default_gate.cycle_summary_json == $src
  and .vpn_track.profile_default_gate.cycle_summary_available == false
  and .vpn_track.profile_default_gate.cycle_decision == null
  and .vpn_track.profile_default_gate.cycle_status == null
  and .vpn_track.profile_default_gate.cycle_rc == null
  and .vpn_track.profile_default_gate.cycle_failure_stage == null
  and .vpn_track.profile_default_gate.cycle_failure_reason == null
' "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_explicit_invalid_summary.json" >/dev/null; then
  echo "profile default gate stability-cycle explicit-invalid summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_explicit_invalid_summary.json"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] profile_default_gate_stability_cycle_summary_json=.*cycle_summary_available=false' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_explicit_invalid.log; then
  echo "expected profile default gate stability-cycle availability log line in explicit-invalid scenario"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_explicit_invalid.log
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] profile default gate stability-cycle summary missing default artifact is fail-closed/null-safe"
PROFILE_DEFAULT_GATE_STABILITY_CYCLE_MISSING_REPORTS_DIR="$TMP_DIR/profile_default_gate_stability_cycle_missing_reports"
rm -rf "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_MISSING_REPORTS_DIR"
PROFILE_DEFAULT_GATE_STABILITY_CYCLE_MISSING_DEFAULT_JSON="$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_MISSING_REPORTS_DIR/profile_default_gate_stability_cycle_summary.json"
if ! EASY_NODE_LOG_DIR="$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_MISSING_REPORTS_DIR" run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_missing_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_missing_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_missing.log 2>&1; then
  echo "expected success when profile default gate stability-cycle summary default path is missing"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_missing.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_MISSING_DEFAULT_JSON" '
  .vpn_track.profile_default_gate.cycle_summary_json == $src
  and .vpn_track.profile_default_gate.cycle_summary_available == false
  and .vpn_track.profile_default_gate.cycle_decision == null
  and .vpn_track.profile_default_gate.cycle_status == null
  and .vpn_track.profile_default_gate.cycle_rc == null
  and .vpn_track.profile_default_gate.cycle_failure_stage == null
  and .vpn_track.profile_default_gate.cycle_failure_reason == null
' "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_missing_summary.json" >/dev/null; then
  echo "profile default gate stability-cycle missing-default summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_default_gate_stability_cycle_missing_summary.json"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] profile_default_gate_stability_cycle_summary_json=.*cycle_summary_available=false' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_missing.log; then
  echo "expected profile default gate stability-cycle availability log line in missing-default scenario"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_default_gate_stability_cycle_missing.log
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] multi-VM stability-check summary defaults to reports_dir artifact"
PROFILE_COMPARE_MULTI_VM_STABILITY_REPORTS_DIR="$TMP_DIR/profile_compare_multi_vm_stability_reports"
mkdir -p "$PROFILE_COMPARE_MULTI_VM_STABILITY_REPORTS_DIR"
PROFILE_COMPARE_MULTI_VM_STABILITY_DEFAULT_SUMMARY_JSON="$PROFILE_COMPARE_MULTI_VM_STABILITY_REPORTS_DIR/profile_compare_multi_vm_stability_check_summary.json"
cat >"$PROFILE_COMPARE_MULTI_VM_STABILITY_DEFAULT_SUMMARY_JSON" <<'EOF_PROFILE_COMPARE_MULTI_VM_STABILITY_DEFAULT_SUMMARY'
{
  "version": 1,
  "schema": {
    "id": "profile_compare_multi_vm_stability_check_summary"
  },
  "decision": "GO",
  "status": "ok",
  "rc": 0,
  "notes": "multi-VM stability summary passes configured policy",
  "observed": {
    "runs_requested": 3,
    "runs_completed": 3,
    "runs_fail": 0,
    "modal_recommended_profile": "balanced",
    "modal_support_rate_pct": 66.67,
    "decision_counts": {
      "GO": 2,
      "NO-GO": 1
    },
    "recommended_profile_counts": {
      "balanced": 2,
      "private": 1
    }
  },
  "errors": []
}
EOF_PROFILE_COMPARE_MULTI_VM_STABILITY_DEFAULT_SUMMARY
if ! EASY_NODE_LOG_DIR="$PROFILE_COMPARE_MULTI_VM_STABILITY_REPORTS_DIR" run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_compare_multi_vm_stability_default_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_compare_multi_vm_stability_default_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_compare_multi_vm_stability_default.log 2>&1; then
  echo "expected success when multi-VM stability-check summary exists at reports_dir default artifact path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_compare_multi_vm_stability_default.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_COMPARE_MULTI_VM_STABILITY_DEFAULT_SUMMARY_JSON" '
  .vpn_track.multi_vm_stability.available == true
  and .vpn_track.multi_vm_stability.input_summary_json == $src
  and .vpn_track.multi_vm_stability.source_summary_json == $src
  and .vpn_track.multi_vm_stability.source_summary_kind == "check"
  and .vpn_track.multi_vm_stability.status == "ok"
  and .vpn_track.multi_vm_stability.rc == 0
  and .vpn_track.multi_vm_stability.decision == "GO"
  and .vpn_track.multi_vm_stability.go == true
  and .vpn_track.multi_vm_stability.no_go == false
  and .vpn_track.multi_vm_stability.recommended_profile == "balanced"
  and .vpn_track.multi_vm_stability.support_rate_pct == 66.67
  and .vpn_track.multi_vm_stability.runs_requested == 3
  and .vpn_track.multi_vm_stability.runs_completed == 3
  and .vpn_track.multi_vm_stability.runs_fail == 0
  and .vpn_track.multi_vm_stability.decision_counts == {"GO":2,"NO-GO":1}
  and .vpn_track.multi_vm_stability.recommended_profile_counts == {"balanced":2,"private":1}
  and .vpn_track.multi_vm_stability.reasons == []
  and ((.vpn_track.multi_vm_stability.notes // "") | test("passes configured policy"))
  and .vpn_track.multi_vm_stability.needs_attention == false
  and .vpn_track.multi_vm_stability.next_command == null
  and .vpn_track.multi_vm_stability.next_command_reason == null
  and .artifacts.profile_compare_multi_vm_stability_summary_json == $src
' "$TMP_DIR/roadmap_progress_profile_compare_multi_vm_stability_default_summary.json" >/dev/null; then
  echo "multi-VM stability default-artifact summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_compare_multi_vm_stability_default_summary.json"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] profile_compare_multi_vm_stability_available=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_compare_multi_vm_stability_default.log; then
  echo "expected multi-VM stability availability log line in default-artifact scenario"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_compare_multi_vm_stability_default.log
  exit 1
fi

: >"$CAPTURE"

echo "[roadmap-progress-report] multi-VM stability-check summary missing default artifact is fail-closed/null-safe"
PROFILE_COMPARE_MULTI_VM_STABILITY_MISSING_REPORTS_DIR="$TMP_DIR/profile_compare_multi_vm_stability_missing_reports"
rm -rf "$PROFILE_COMPARE_MULTI_VM_STABILITY_MISSING_REPORTS_DIR"
PROFILE_COMPARE_MULTI_VM_STABILITY_MISSING_DEFAULT_JSON="$PROFILE_COMPARE_MULTI_VM_STABILITY_MISSING_REPORTS_DIR/profile_compare_multi_vm_stability_check_summary.json"
if ! EASY_NODE_LOG_DIR="$PROFILE_COMPARE_MULTI_VM_STABILITY_MISSING_REPORTS_DIR" run_roadmap_progress_report \
  --refresh-manual-validation 0 \
  --refresh-single-machine-readiness 0 \
  --manual-validation-summary-json "$PROFILE_DEFAULT_GATE_STABILITY_CYCLE_DEFAULT_MANUAL_SUMMARY_JSON" \
  --summary-json "$TMP_DIR/roadmap_progress_profile_compare_multi_vm_stability_missing_summary.json" \
  --report-md "$TMP_DIR/roadmap_progress_profile_compare_multi_vm_stability_missing_report.md" \
  --print-report 0 \
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_compare_multi_vm_stability_missing.log 2>&1; then
  echo "expected success when multi-VM stability-check summary default path is missing"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_compare_multi_vm_stability_missing.log
  exit 1
fi
if ! jq -e --arg src "$PROFILE_COMPARE_MULTI_VM_STABILITY_MISSING_DEFAULT_JSON" '
  .vpn_track.multi_vm_stability.available == false
  and .vpn_track.multi_vm_stability.input_summary_json == $src
  and .vpn_track.multi_vm_stability.source_summary_json == null
  and .vpn_track.multi_vm_stability.source_summary_kind == null
  and .vpn_track.multi_vm_stability.status == "missing"
  and .vpn_track.multi_vm_stability.rc == null
  and .vpn_track.multi_vm_stability.decision == null
  and .vpn_track.multi_vm_stability.go == null
  and .vpn_track.multi_vm_stability.no_go == null
  and .vpn_track.multi_vm_stability.recommended_profile == null
  and .vpn_track.multi_vm_stability.support_rate_pct == null
  and .vpn_track.multi_vm_stability.runs_requested == null
  and .vpn_track.multi_vm_stability.runs_completed == null
  and .vpn_track.multi_vm_stability.runs_fail == null
  and .vpn_track.multi_vm_stability.decision_counts == null
  and .vpn_track.multi_vm_stability.recommended_profile_counts == null
  and .vpn_track.multi_vm_stability.reasons == []
  and .vpn_track.multi_vm_stability.notes == null
  and .vpn_track.multi_vm_stability.needs_attention == true
  and ((.vpn_track.multi_vm_stability.next_command // "") | test("profile-compare-multi-vm-stability-cycle"))
  and ((.vpn_track.multi_vm_stability.next_command_reason // "") | test("missing"; "i"))
  and .artifacts.profile_compare_multi_vm_stability_summary_json == null
' "$TMP_DIR/roadmap_progress_profile_compare_multi_vm_stability_missing_summary.json" >/dev/null; then
  echo "multi-VM stability missing-default summary mismatch"
  cat "$TMP_DIR/roadmap_progress_profile_compare_multi_vm_stability_missing_summary.json"
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] profile_compare_multi_vm_stability_available=false' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_compare_multi_vm_stability_missing.log; then
  echo "expected multi-VM stability availability log line in missing-default scenario"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_profile_compare_multi_vm_stability_missing.log
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
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_manual_restore.log 2>&1; then
  echo "expected failure when manual refresh emits invalid summary"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_manual_restore.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] status=fail rc=1' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_manual_restore.log; then
  echo "manual restore path missing fail status line"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_manual_restore.log
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
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_manual_partial_restore.log 2>&1; then
  echo "expected failure when manual refresh emits partial summary schema"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_manual_partial_restore.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] status=fail rc=1' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_manual_partial_restore.log; then
  echo "manual partial restore path missing fail status line"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_manual_partial_restore.log
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
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_fail.log 2>&1; then
  echo "expected failure when single-machine refresh fails"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_fail.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] status=fail rc=1' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_fail.log; then
  echo "expected fail status when single-machine refresh fails"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_fail.log
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
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_transient_warn.log 2>&1; then
  echo "expected success with warn status when single-machine refresh hits transient docker registry failure"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_transient_warn.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] status=warn rc=0' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_transient_warn.log; then
  echo "transient warning path missing warn status line"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_transient_warn.log
  exit 1
fi
if ! rg -q '\[roadmap-progress-report\] refresh_step=single_machine_prod_readiness status=warn rc=1 timed_out=false' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_transient_warn.log; then
  echo "transient warning path missing single-machine warn heartbeat line"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_transient_warn.log
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
      --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_timeout.log 2>&1; then
    echo "expected failure when single-machine refresh times out"
    cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_timeout.log
    exit 1
  fi
  if ! rg -q '\[roadmap-progress-report\] refresh_step=single_machine_prod_readiness status=running timeout_sec=1' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_timeout.log; then
    echo "timeout path missing running heartbeat line"
    cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_timeout.log
    exit 1
  fi
  if ! rg -q '\[roadmap-progress-report\] refresh_step=single_machine_prod_readiness status=fail rc=124 timed_out=true' ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_timeout.log; then
    echo "timeout path missing timeout completion heartbeat line"
    cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_timeout.log
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
  local phase1_log="${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_phase1_actionable_${case_id}.log"

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
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_phase0_actionable.log 2>&1; then
  echo "expected success for phase0 actionable-gate precedence path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_phase0_actionable.log
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
  --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_phase2_actionable.log 2>&1; then
  echo "expected success for phase2 actionable-gate progression path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_phase2_actionable.log
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
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_auto_resilience.log 2>&1; then
  echo "expected success for auto resilience source selection path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_auto_resilience.log
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

echo "[roadmap-progress-report] phase5 auto-source selection avoids degraded clobbered summaries"
AUTO_PHASE5_LOGS_ROOT="$TMP_DIR/auto_phase5_logs_root"
AUTO_PHASE5_GOOD_DIR="$AUTO_PHASE5_LOGS_ROOT/healthy_older"
AUTO_PHASE5_CLOBBERED_DIR="$AUTO_PHASE5_LOGS_ROOT/clobbered_newer"
AUTO_PHASE5_DRY_RUN_DIR="$AUTO_PHASE5_LOGS_ROOT/dry_run_newest"
mkdir -p "$AUTO_PHASE5_GOOD_DIR" "$AUTO_PHASE5_CLOBBERED_DIR" "$AUTO_PHASE5_DRY_RUN_DIR"

AUTO_PHASE5_GOOD_JSON="$AUTO_PHASE5_GOOD_DIR/phase5_settlement_layer_handoff_check_summary.json"
cat >"$AUTO_PHASE5_GOOD_JSON" <<'EOF_AUTO_PHASE5_GOOD'
{
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "settlement_failsoft_ok": true,
  "settlement_acceptance_ok": true,
  "settlement_bridge_smoke_ok": true,
  "settlement_state_persistence_ok": true,
  "settlement_adapter_roundtrip_ok": true,
  "settlement_adapter_roundtrip_status": "pass",
  "settlement_dual_asset_parity_ok": true,
  "settlement_dual_asset_parity_status": "pass",
  "settlement_adapter_signed_tx_roundtrip_ok": true,
  "settlement_adapter_signed_tx_roundtrip_status": "pass",
  "settlement_shadow_env_ok": true,
  "settlement_shadow_env_status": "pass",
  "settlement_shadow_status_surface_ok": true,
  "settlement_shadow_status_surface_status": "pass",
  "issuer_sponsor_api_live_smoke_ok": true,
  "issuer_sponsor_api_live_smoke_status": "pass",
  "issuer_settlement_status_live_smoke_ok": true,
  "issuer_settlement_status_live_smoke_status": "pass",
  "issuer_admin_blockchain_handlers_coverage_ok": true,
  "issuer_admin_blockchain_handlers_coverage_status": "pass",
  "exit_settlement_status_live_smoke_ok": true,
  "exit_settlement_status_live_smoke_status": "pass"
}
EOF_AUTO_PHASE5_GOOD
touch -t 202601010101 "$AUTO_PHASE5_GOOD_JSON"

AUTO_PHASE5_CLOBBERED_JSON="$AUTO_PHASE5_CLOBBERED_DIR/phase5_settlement_layer_handoff_check_summary.json"
cat >"$AUTO_PHASE5_CLOBBERED_JSON" <<'EOF_AUTO_PHASE5_CLOBBERED'
{
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "settlement_failsoft_ok": false,
  "settlement_acceptance_ok": false,
  "settlement_bridge_smoke_ok": false,
  "settlement_state_persistence_ok": false,
  "settlement_adapter_roundtrip_ok": false,
  "settlement_adapter_roundtrip_status": "fail",
  "settlement_dual_asset_parity_ok": false,
  "settlement_dual_asset_parity_status": "fail",
  "settlement_adapter_signed_tx_roundtrip_ok": false,
  "settlement_adapter_signed_tx_roundtrip_status": "fail",
  "settlement_shadow_env_ok": false,
  "settlement_shadow_env_status": "fail",
  "settlement_shadow_status_surface_ok": false,
  "settlement_shadow_status_surface_status": "fail",
  "issuer_sponsor_api_live_smoke_ok": false,
  "issuer_sponsor_api_live_smoke_status": "fail",
  "issuer_settlement_status_live_smoke_ok": false,
  "issuer_settlement_status_live_smoke_status": "fail",
  "issuer_admin_blockchain_handlers_coverage_ok": false,
  "issuer_admin_blockchain_handlers_coverage_status": "fail",
  "exit_settlement_status_live_smoke_ok": false,
  "exit_settlement_status_live_smoke_status": "fail"
}
EOF_AUTO_PHASE5_CLOBBERED
touch -t 202601020202 "$AUTO_PHASE5_CLOBBERED_JSON"

AUTO_PHASE5_DRY_RUN_JSON="$AUTO_PHASE5_DRY_RUN_DIR/phase5_settlement_layer_handoff_check_summary.json"
cat >"$AUTO_PHASE5_DRY_RUN_JSON" <<'EOF_AUTO_PHASE5_DRY_RUN'
{
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "dry_run": true,
  "settlement_failsoft_ok": true,
  "settlement_acceptance_ok": true,
  "settlement_bridge_smoke_ok": true,
  "settlement_state_persistence_ok": true,
  "settlement_adapter_roundtrip_ok": true,
  "settlement_adapter_roundtrip_status": "pass",
  "settlement_dual_asset_parity_ok": true,
  "settlement_dual_asset_parity_status": "pass",
  "settlement_adapter_signed_tx_roundtrip_ok": true,
  "settlement_adapter_signed_tx_roundtrip_status": "pass",
  "settlement_shadow_env_ok": true,
  "settlement_shadow_env_status": "pass",
  "settlement_shadow_status_surface_ok": true,
  "settlement_shadow_status_surface_status": "pass",
  "issuer_sponsor_api_live_smoke_ok": true,
  "issuer_sponsor_api_live_smoke_status": "pass",
  "issuer_settlement_status_live_smoke_ok": true,
  "issuer_settlement_status_live_smoke_status": "pass",
  "issuer_admin_blockchain_handlers_coverage_ok": true,
  "issuer_admin_blockchain_handlers_coverage_status": "pass",
  "exit_settlement_status_live_smoke_ok": true,
  "exit_settlement_status_live_smoke_status": "pass"
}
EOF_AUTO_PHASE5_DRY_RUN
touch -t 202601030303 "$AUTO_PHASE5_DRY_RUN_JSON"

if ! ROADMAP_PROGRESS_LOGS_ROOT="$AUTO_PHASE5_LOGS_ROOT" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
    --phase5-settlement-layer-summary-json "" \
    --summary-json "$TMP_DIR/roadmap_progress_auto_phase5_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_auto_phase5_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_auto_phase5.log 2>&1; then
  echo "expected success for auto phase5 source selection path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_auto_phase5.log
  exit 1
fi
if ! jq -e --arg src "$AUTO_PHASE5_GOOD_JSON" '
  .status == "warn"
  and .rc == 0
  and .vpn_track.phase5_settlement_layer_handoff.available == true
  and .vpn_track.phase5_settlement_layer_handoff.source_summary_json == $src
  and .vpn_track.phase5_settlement_layer_handoff.status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_failsoft_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_acceptance_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_bridge_smoke_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_state_persistence_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_ok == true
  and .artifacts.phase5_settlement_layer_summary_json == $src
' "$TMP_DIR/roadmap_progress_auto_phase5_summary.json" >/dev/null; then
  echo "auto phase5 source selection summary mismatch"
  cat "$TMP_DIR/roadmap_progress_auto_phase5_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] phase5 CI step-status fallback fills settlement status signals when direct fields are missing"
PHASE5_STEP_STATUS_FALLBACK_LOGS_ROOT="$TMP_DIR/phase5_step_status_fallback_logs_root"
mkdir -p "$PHASE5_STEP_STATUS_FALLBACK_LOGS_ROOT"
PHASE5_STEP_STATUS_FALLBACK_JSON="$PHASE5_STEP_STATUS_FALLBACK_LOGS_ROOT/phase5_settlement_layer_handoff_check_summary.json"
cat >"$PHASE5_STEP_STATUS_FALLBACK_JSON" <<'EOF_PHASE5_STEP_STATUS_FALLBACK'
{
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "steps": {
    "settlement_adapter_signed_tx_roundtrip": {
      "status": "pass"
    },
    "settlement_shadow_env": {
      "status": "pass"
    },
    "settlement_shadow_status_surface": {
      "status": "pass"
    }
  }
}
EOF_PHASE5_STEP_STATUS_FALLBACK

if ! jq -e '
  (.settlement_adapter_signed_tx_roundtrip_status // null) == null
  and (.settlement_adapter_signed_tx_roundtrip_ok // null) == null
  and (.settlement_shadow_env_status // null) == null
  and (.settlement_shadow_env_ok // null) == null
  and (.settlement_shadow_status_surface_status // null) == null
  and (.settlement_shadow_status_surface_ok // null) == null
' "$PHASE5_STEP_STATUS_FALLBACK_JSON" >/dev/null; then
  echo "phase5 step-status fallback fixture unexpectedly contains direct settlement fields"
  cat "$PHASE5_STEP_STATUS_FALLBACK_JSON"
  exit 1
fi

if ! ROADMAP_PROGRESS_LOGS_ROOT="$PHASE5_STEP_STATUS_FALLBACK_LOGS_ROOT" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
    --phase5-settlement-layer-summary-json "$PHASE5_STEP_STATUS_FALLBACK_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_phase5_ci_step_status_fallback_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_phase5_ci_step_status_fallback_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_phase5_ci_step_status_fallback.log 2>&1; then
  echo "expected success for phase5 CI step-status fallback path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_phase5_ci_step_status_fallback.log
  exit 1
fi
if ! jq -e --arg src "$PHASE5_STEP_STATUS_FALLBACK_JSON" '
  .status == "warn"
  and .rc == 0
  and .vpn_track.phase5_settlement_layer_handoff.available == true
  and .vpn_track.phase5_settlement_layer_handoff.source_summary_json == $src
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok == true
  and .artifacts.phase5_settlement_layer_summary_json == $src
' "$TMP_DIR/roadmap_progress_phase5_ci_step_status_fallback_summary.json" >/dev/null; then
  echo "phase5 CI step-status fallback summary mismatch"
  cat "$TMP_DIR/roadmap_progress_phase5_ci_step_status_fallback_summary.json"
  exit 1
fi

echo "[roadmap-progress-report] phase5 sparse source backfills null signals from richer available summary"
FALLBACK_PHASE5_LOGS_ROOT="$TMP_DIR/fallback_phase5_logs_root"
FALLBACK_PHASE5_RICH_DIR="$FALLBACK_PHASE5_LOGS_ROOT/rich_older"
FALLBACK_PHASE5_SPARSE_DIR="$FALLBACK_PHASE5_LOGS_ROOT/sparse_newer"
mkdir -p "$FALLBACK_PHASE5_RICH_DIR" "$FALLBACK_PHASE5_SPARSE_DIR"

FALLBACK_PHASE5_RICH_JSON="$FALLBACK_PHASE5_RICH_DIR/phase5_settlement_layer_handoff_check_summary.json"
cat >"$FALLBACK_PHASE5_RICH_JSON" <<'EOF_FALLBACK_PHASE5_RICH'
{
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "settlement_failsoft_ok": true,
  "settlement_acceptance_ok": true,
  "settlement_bridge_smoke_ok": true,
  "settlement_state_persistence_ok": true,
  "stages": {
    "settlement_adapter_roundtrip": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    }
  },
  "settlement_dual_asset_parity_status": "pass",
  "settlement_dual_asset_parity_ok": true,
  "settlement_adapter_signed_tx_roundtrip_status": "pass",
  "settlement_adapter_signed_tx_roundtrip_ok": true,
  "settlement_shadow_env_status": "pass",
  "settlement_shadow_env_ok": true,
  "settlement_shadow_status_surface_status": "pass",
  "settlement_shadow_status_surface_ok": true,
  "issuer_sponsor_api_live_smoke_status": "pass",
  "issuer_sponsor_api_live_smoke_ok": true,
  "issuer_settlement_status_live_smoke_status": "pass",
  "issuer_settlement_status_live_smoke_ok": true,
  "issuer_admin_blockchain_handlers_coverage_status": "pass",
  "issuer_admin_blockchain_handlers_coverage_ok": true,
  "exit_settlement_status_live_smoke_status": "pass",
  "exit_settlement_status_live_smoke_ok": true
}
EOF_FALLBACK_PHASE5_RICH
touch -t 202601040404 "$FALLBACK_PHASE5_RICH_JSON"

FALLBACK_PHASE5_SPARSE_JSON="$FALLBACK_PHASE5_SPARSE_DIR/phase5_settlement_layer_handoff_check_summary.json"
cat >"$FALLBACK_PHASE5_SPARSE_JSON" <<'EOF_FALLBACK_PHASE5_SPARSE'
{
  "schema": {
    "id": "phase5_settlement_layer_handoff_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "settlement_failsoft_ok": true,
  "settlement_acceptance_ok": true,
  "settlement_bridge_smoke_ok": true,
  "settlement_state_persistence_ok": true,
  "issuer_sponsor_api_live_smoke_status": "pass",
  "issuer_sponsor_api_live_smoke_ok": true
}
EOF_FALLBACK_PHASE5_SPARSE
touch -t 202601050505 "$FALLBACK_PHASE5_SPARSE_JSON"

if ! ROADMAP_PROGRESS_LOGS_ROOT="$FALLBACK_PHASE5_LOGS_ROOT" \
  run_roadmap_progress_report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --manual-validation-summary-json "$MINIMAL_MANUAL_SUMMARY_JSON" \
    --phase5-settlement-layer-summary-json "$FALLBACK_PHASE5_SPARSE_JSON" \
    --summary-json "$TMP_DIR/roadmap_progress_phase5_sparse_source_fallback_summary.json" \
    --report-md "$TMP_DIR/roadmap_progress_phase5_sparse_source_fallback_report.md" \
    --print-report 0 \
    --print-summary-json 0 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_phase5_sparse_source_fallback.log 2>&1; then
  echo "expected success for phase5 sparse source fallback path"
  cat ${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_phase5_sparse_source_fallback.log
  exit 1
fi
if ! jq -e --arg src "$FALLBACK_PHASE5_SPARSE_JSON" '
  .status == "warn"
  and .rc == 0
  and .vpn_track.phase5_settlement_layer_handoff.available == true
  and .vpn_track.phase5_settlement_layer_handoff.source_summary_json == $src
  and .vpn_track.phase5_settlement_layer_handoff.status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_roundtrip_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_adapter_signed_tx_roundtrip_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_env_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.settlement_shadow_status_surface_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.issuer_settlement_status_live_smoke_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok == true
  and .vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_status == "pass"
  and .vpn_track.phase5_settlement_layer_handoff.exit_settlement_status_live_smoke_ok == true
  and .artifacts.phase5_settlement_layer_summary_json == $src
' "$TMP_DIR/roadmap_progress_phase5_sparse_source_fallback_summary.json" >/dev/null; then
  echo "phase5 sparse source fallback summary mismatch"
  cat "$TMP_DIR/roadmap_progress_phase5_sparse_source_fallback_summary.json"
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
  --summary-json "$ROADMAP_PROGRESS_FORWARD_SUMMARY_JSON" \
  --print-summary-json 1 >${ROADMAP_PROGRESS_REPORT_LOG_PREFIX}_forward.log 2>&1

forward_line="$(rg '^roadmap-progress-report ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing roadmap-progress-report forward capture"
  cat "$CAPTURE"
  exit 1
fi
for expected in "--refresh-manual-validation 0" "--refresh-single-machine-readiness 1" "--summary-json $ROADMAP_PROGRESS_FORWARD_SUMMARY_JSON" "--print-summary-json 1"; do
  if [[ "$forward_line" != *"$expected"* ]]; then
    echo "forwarded command missing expected fragment: $expected"
    echo "$forward_line"
    exit 1
  fi
done

echo "roadmap progress report integration check ok"
