#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat cmp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

RUNNER="${PHASE5_SETTLEMENT_LAYER_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase5_settlement_layer_run.sh}"
if [[ ! -x "$RUNNER" ]]; then
  echo "missing executable script under test: $RUNNER"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_capture.tsv"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"
ENV_DRY_RUN_LOG="$TMP_DIR/env_dry_run.log"
CI_FAIL_LOG="$TMP_DIR/ci_fail.log"
CONTRACT_FAIL_LOG="$TMP_DIR/contract_fail.log"

FAKE_CI="$TMP_DIR/fake_ci_phase5.sh"
cat >"$FAKE_CI" <<'EOF_FAKE_CI'
#!/usr/bin/env bash
set -euo pipefail

capture="${PHASE5_SETTLEMENT_LAYER_RUN_CAPTURE_FILE:?}"
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

fail_rc="${FAKE_CI_FAIL_RC:-27}"
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
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "steps": {
    "settlement_failsoft": {
      "status": "$status"
    },
    "settlement_acceptance": {
      "status": "$status"
    },
    "settlement_bridge_smoke": {
      "status": "$status"
    },
    "settlement_state_persistence": {
      "status": "$status"
    }
  }
}
EOF_CI_SUMMARY
fi

if [[ "${FAKE_CI_FAIL:-0}" == "1" ]]; then
  exit "$fail_rc"
fi
exit 0
EOF_FAKE_CI
chmod +x "$FAKE_CI"

FAKE_CHECK="$TMP_DIR/fake_phase5_settlement_layer_check.sh"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" == "--help" ]]; then
  help_mode="${FAKE_CHECK_HELP_MODE:-canonical}"
  if [[ "$help_mode" == "legacy" ]]; then
    cat <<'EOF_HELP_LEGACY'
Usage:
  fake check
    [--require-windows-server-packaging-ok [0|1]]
    [--require-windows-role-runbooks-ok [0|1]]
    [--require-cross-platform-interop-ok [0|1]]
    [--require-role-combination-validation-ok [0|1]]
EOF_HELP_LEGACY
  else
    cat <<'EOF_HELP'
Usage:
  fake check
    [--require-settlement-failsoft-ok [0|1]]
    [--require-settlement-acceptance-ok [0|1]]
    [--require-settlement-bridge-smoke-ok [0|1]]
    [--require-settlement-state-persistence-ok [0|1]]
    [--require-settlement-dual-asset-parity-ok [0|1]]
    [--require-issuer-sponsor-api-live-smoke-ok [0|1]]
EOF_HELP
  fi
  exit 0
fi

capture="${PHASE5_SETTLEMENT_LAYER_RUN_CAPTURE_FILE:?}"
printf 'check\t%s\n' "$*" >>"$capture"

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

fail_rc="${FAKE_CHECK_FAIL_RC:-19}"
status="pass"
rc=0
if [[ "${FAKE_CHECK_FAIL:-0}" == "1" ]]; then
  status="fail"
  rc="$fail_rc"
fi

issuer_sponsor_api_live_smoke_mode="${FAKE_CHECK_ISSUER_SPONSOR_API_LIVE_SMOKE_MODE:-present}"
issuer_sponsor_api_live_smoke_status="$status"
issuer_sponsor_api_live_smoke_signal_json="true"
issuer_sponsor_api_live_smoke_stage_ok_json="true"
issuer_sponsor_api_live_smoke_stage_resolved_json="true"
if [[ "$status" != "pass" ]]; then
  issuer_sponsor_api_live_smoke_signal_json="false"
  issuer_sponsor_api_live_smoke_stage_ok_json="false"
fi
if [[ "$issuer_sponsor_api_live_smoke_mode" == "legacy_missing" ]]; then
  issuer_sponsor_api_live_smoke_status=""
  issuer_sponsor_api_live_smoke_signal_json="null"
  issuer_sponsor_api_live_smoke_stage_ok_json="null"
  issuer_sponsor_api_live_smoke_stage_resolved_json="false"
fi

issuer_admin_blockchain_handlers_coverage_mode="${FAKE_CHECK_ISSUER_ADMIN_BLOCKCHAIN_HANDLERS_COVERAGE_MODE:-present}"
issuer_admin_blockchain_handlers_coverage_status="$status"
issuer_admin_blockchain_handlers_coverage_signal_json="true"
issuer_admin_blockchain_handlers_coverage_stage_ok_json="true"
issuer_admin_blockchain_handlers_coverage_stage_resolved_json="true"
if [[ "$status" != "pass" ]]; then
  issuer_admin_blockchain_handlers_coverage_signal_json="false"
  issuer_admin_blockchain_handlers_coverage_stage_ok_json="false"
fi
if [[ "$issuer_admin_blockchain_handlers_coverage_mode" == "legacy_missing" ]]; then
  issuer_admin_blockchain_handlers_coverage_status=""
  issuer_admin_blockchain_handlers_coverage_signal_json="null"
  issuer_admin_blockchain_handlers_coverage_stage_ok_json="null"
  issuer_admin_blockchain_handlers_coverage_stage_resolved_json="false"
elif [[ "$issuer_admin_blockchain_handlers_coverage_mode" == "fail" ]]; then
  issuer_admin_blockchain_handlers_coverage_status="fail"
  issuer_admin_blockchain_handlers_coverage_signal_json="false"
  issuer_admin_blockchain_handlers_coverage_stage_ok_json="false"
  issuer_admin_blockchain_handlers_coverage_stage_resolved_json="true"
fi

if [[ -n "$summary_json" && "${FAKE_CHECK_OMIT_SUMMARY:-0}" != "1" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<EOF_CHECK_SUMMARY
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "$status",
  "rc": $rc,
  "policy": {
    "require_settlement_failsoft_ok": true,
    "require_settlement_acceptance_ok": true,
    "require_settlement_bridge_smoke_ok": true,
    "require_settlement_state_persistence_ok": true,
    "require_settlement_dual_asset_parity_ok": true,
    "require_issuer_sponsor_api_live_smoke_ok": true,
    "require_issuer_admin_blockchain_handlers_coverage_ok": true
  },
  "signals": {
    "settlement_failsoft_ok": true,
    "settlement_acceptance_ok": true,
    "settlement_bridge_smoke_ok": true,
    "settlement_state_persistence_ok": true,
    "settlement_dual_asset_parity_ok": true,
    "issuer_sponsor_api_live_smoke_ok": $issuer_sponsor_api_live_smoke_signal_json,
    "issuer_admin_blockchain_handlers_coverage_ok": $issuer_admin_blockchain_handlers_coverage_signal_json
  },
  "stages": {
    "settlement_failsoft": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "settlement_acceptance": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "settlement_bridge_smoke": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "settlement_state_persistence": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "settlement_dual_asset_parity": {
      "status": "$status",
      "resolved": true,
      "ok": true
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "$issuer_sponsor_api_live_smoke_status",
      "resolved": $issuer_sponsor_api_live_smoke_stage_resolved_json,
      "ok": $issuer_sponsor_api_live_smoke_stage_ok_json
    },
    "issuer_admin_blockchain_handlers_coverage": {
      "status": "$issuer_admin_blockchain_handlers_coverage_status",
      "resolved": $issuer_admin_blockchain_handlers_coverage_stage_resolved_json,
      "ok": $issuer_admin_blockchain_handlers_coverage_stage_ok_json
    }
  }
}
EOF_CHECK_SUMMARY
fi

if [[ "${FAKE_CHECK_FAIL:-0}" == "1" ]]; then
  exit "$fail_rc"
fi
exit 0
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

DRY_RUN_RUN_SUMMARY="$TMP_DIR/run_dry.json"
ENV_DRY_RUN_RUN_SUMMARY="$TMP_DIR/run_env_dry.json"
CI_FAIL_RUN_SUMMARY="$TMP_DIR/run_ci_fail.json"
CONTRACT_FAIL_RUN_SUMMARY="$TMP_DIR/run_contract_fail.json"
DRY_RUN_CANONICAL_SUMMARY="$TMP_DIR/run_dry_canonical.json"
ENV_DRY_RUN_CANONICAL_SUMMARY="$TMP_DIR/run_env_dry_canonical.json"
CI_FAIL_CANONICAL_SUMMARY="$TMP_DIR/run_ci_fail_canonical.json"
CONTRACT_FAIL_CANONICAL_SUMMARY="$TMP_DIR/run_contract_fail_canonical.json"

echo "[phase5-settlement-layer-run] dry-run forwarding contract"
: >"$CAPTURE"
PHASE5_SETTLEMENT_LAYER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE5_SETTLEMENT_LAYER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE5_SETTLEMENT_LAYER_RUN_CANONICAL_SUMMARY_JSON="$DRY_RUN_CANONICAL_SUMMARY" \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_dry" \
  --ci-summary-json "$TMP_DIR/ci_dry_summary.json" \
  --check-summary-json "$TMP_DIR/check_dry_summary.json" \
  --summary-json "$DRY_RUN_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 \
  --ci-run-settlement-failsoft 1 \
  --check-require-windows-server-packaging-ok 1 \
  --check-require-settlement-bridge-smoke-ok 1 \
  --check-show-json 1 >"$DRY_RUN_LOG" 2>&1

ci_line="$(grep '^ci	' "$CAPTURE" | tail -n 1 || true)"
check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$ci_line" || -z "$check_line" ]]; then
  echo "expected both stages to run in dry-run path"
  cat "$CAPTURE"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if [[ "$ci_line" != *"--dry-run 1"* || "$ci_line" != *"--summary-json $TMP_DIR/ci_dry_summary.json"* ]]; then
  echo "dry-run ci forwarding contract mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$ci_line" != *"--run-settlement-failsoft 1"* ]]; then
  echo "ci passthrough contract mismatch"
  echo "$ci_line"
  exit 1
fi
if [[ "$check_line" != *"--ci-phase5-summary-json $TMP_DIR/ci_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing ci summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--summary-json $TMP_DIR/check_dry_summary.json"* ]]; then
  echo "dry-run check forwarding missing check summary path"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--require-settlement-failsoft-ok 1"* || "$check_line" != *"--require-settlement-bridge-smoke-ok 1"* ]]; then
  echo "check requirement passthrough canonicalization mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--require-settlement-acceptance-ok 0"* || "$check_line" != *"--require-settlement-state-persistence-ok 0"* || "$check_line" != *"--require-issuer-sponsor-api-live-smoke-ok 0"* ]]; then
  echo "dry-run default requirement relax canonicalization mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" != *"--show-json 1"* ]]; then
  echo "check show-json forwarding mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" == *"--dry-run 1"* || "$check_line" == *"--print-summary-json 0"* ]]; then
  echo "wrapper-only flags leaked into checker"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" == *"--require-windows-server-packaging-ok"* || "$check_line" == *"--require-cross-platform-interop-ok"* || "$check_line" == *"--require-windows-role-runbooks-ok"* || "$check_line" == *"--require-role-combination-validation-ok"* ]]; then
  echo "legacy checker requirement flags leaked despite canonical checker support"
  echo "$check_line"
  exit 1
fi
if [[ ! -f "$DRY_RUN_CANONICAL_SUMMARY" ]]; then
  echo "missing dry-run canonical summary JSON: $DRY_RUN_CANONICAL_SUMMARY"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! cmp -s "$DRY_RUN_RUN_SUMMARY" "$DRY_RUN_CANONICAL_SUMMARY"; then
  echo "dry-run canonical summary content mismatch"
  cat "$DRY_RUN_RUN_SUMMARY"
  cat "$DRY_RUN_CANONICAL_SUMMARY"
  exit 1
fi
if ! grep -Fq -- "[phase5-settlement-layer-run] canonical_summary_json=$DRY_RUN_CANONICAL_SUMMARY" "$DRY_RUN_LOG"; then
  echo "dry-run log missing canonical summary line"
  cat "$DRY_RUN_LOG"
  exit 1
fi

if [[ ! -f "$DRY_RUN_RUN_SUMMARY" ]]; then
  echo "missing dry-run combined summary JSON: $DRY_RUN_RUN_SUMMARY"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! jq -e --arg canonical "$DRY_RUN_CANONICAL_SUMMARY" '
  .version == 1
  and .schema.id == "phase5_settlement_layer_run_summary"
  and .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $canonical
  and .inputs.dry_run == true
  and .steps.ci_phase5_settlement_layer.status == "pass"
  and .steps.ci_phase5_settlement_layer.rc == 0
  and .steps.ci_phase5_settlement_layer.command_rc == 0
  and .steps.ci_phase5_settlement_layer.contract_valid == true
  and .steps.ci_phase5_settlement_layer.artifacts.summary_exists == true
  and .steps.phase5_settlement_layer_check.status == "pass"
  and .steps.phase5_settlement_layer_check.rc == 0
  and .steps.phase5_settlement_layer_check.command_rc == 0
  and .steps.phase5_settlement_layer_check.contract_valid == true
  and .steps.phase5_settlement_layer_check.artifacts.summary_exists == true
  and .signals.issuer_sponsor_api_live_smoke_ok == true
  and .signals.issuer_sponsor_api_live_smoke_status == "pass"
  and .signals.issuer_sponsor_api_live_smoke_resolved == true
  and .signals.sources.issuer_sponsor_api_live_smoke_ok == "phase5_settlement_layer_check_summary.signals.issuer_sponsor_api_live_smoke_ok"
  and (
    if (.signals | has("issuer_admin_blockchain_handlers_coverage_ok")) then
      .signals.issuer_admin_blockchain_handlers_coverage_ok == true
      and .signals.issuer_admin_blockchain_handlers_coverage_status == "pass"
      and .signals.issuer_admin_blockchain_handlers_coverage_resolved == true
      and .signals.sources.issuer_admin_blockchain_handlers_coverage_ok == "phase5_settlement_layer_check_summary.signals.issuer_admin_blockchain_handlers_coverage_ok"
    else true
    end
  )
' "$DRY_RUN_RUN_SUMMARY" >/dev/null; then
  echo "dry-run combined summary contract mismatch"
  cat "$DRY_RUN_RUN_SUMMARY"
  exit 1
fi

echo "[phase5-settlement-layer-run] env dry-run + legacy checker requirement compatibility"
: >"$CAPTURE"
PHASE5_SETTLEMENT_LAYER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE5_SETTLEMENT_LAYER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE5_SETTLEMENT_LAYER_RUN_DRY_RUN=1 \
PHASE5_SETTLEMENT_LAYER_RUN_CANONICAL_SUMMARY_JSON="$ENV_DRY_RUN_CANONICAL_SUMMARY" \
FAKE_CHECK_HELP_MODE=legacy \
FAKE_CHECK_ISSUER_SPONSOR_API_LIVE_SMOKE_MODE=legacy_missing \
FAKE_CHECK_ISSUER_ADMIN_BLOCKCHAIN_HANDLERS_COVERAGE_MODE=legacy_missing \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_env_dry" \
  --ci-summary-json "$TMP_DIR/ci_env_dry_summary.json" \
  --check-summary-json "$TMP_DIR/check_env_dry_summary.json" \
  --summary-json "$ENV_DRY_RUN_RUN_SUMMARY" \
  --print-summary-json 0 \
  --check-require-settlement-acceptance-ok 1 \
  --check-require-windows-server-packaging-ok 1 >"$ENV_DRY_RUN_LOG" 2>&1

ci_line="$(grep '^ci	' "$CAPTURE" | tail -n 1 || true)"
check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$ci_line" || -z "$check_line" ]]; then
  echo "expected both stages to run in env dry-run path"
  cat "$CAPTURE"
  cat "$ENV_DRY_RUN_LOG"
  exit 1
fi
if [[ "$ci_line" != *"--dry-run 1"* ]]; then
  echo "env dry-run did not forward --dry-run 1 to ci stage"
  echo "$ci_line"
  exit 1
fi
if [[ "$check_line" != *"--require-windows-server-packaging-ok 1"* || "$check_line" != *"--require-windows-role-runbooks-ok 1"* || "$check_line" != *"--require-cross-platform-interop-ok 0"* || "$check_line" != *"--require-role-combination-validation-ok 0"* ]]; then
  echo "env dry-run legacy checker requirement forwarding mismatch"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" == *"--require-settlement-failsoft-ok"* || "$check_line" == *"--require-settlement-acceptance-ok"* || "$check_line" == *"--require-settlement-bridge-smoke-ok"* || "$check_line" == *"--require-settlement-state-persistence-ok"* ]]; then
  echo "canonical checker requirement flags leaked for legacy checker help mode"
  echo "$check_line"
  exit 1
fi
if [[ "$check_line" == *"--require-issuer-sponsor-api-live-smoke-ok"* ]]; then
  echo "issuer sponsor requirement flag leaked for legacy checker help mode"
  echo "$check_line"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.ci_phase5_settlement_layer.contract_valid == true
  and .steps.phase5_settlement_layer_check.contract_valid == true
  and .signals.issuer_sponsor_api_live_smoke_ok == null
  and .signals.issuer_sponsor_api_live_smoke_status == "missing"
  and .signals.issuer_sponsor_api_live_smoke_resolved == false
  and .signals.sources.issuer_sponsor_api_live_smoke_ok == "phase5_settlement_layer_check_summary.stages.issuer_sponsor_api_live_smoke.resolved"
  and (
    if (.signals | has("issuer_admin_blockchain_handlers_coverage_ok")) then
      .signals.issuer_admin_blockchain_handlers_coverage_ok == null
      and .signals.issuer_admin_blockchain_handlers_coverage_status == "missing"
      and .signals.issuer_admin_blockchain_handlers_coverage_resolved == false
      and .signals.sources.issuer_admin_blockchain_handlers_coverage_ok == "phase5_settlement_layer_check_summary.stages.issuer_admin_blockchain_handlers_coverage.resolved"
    else true
    end
  )
' "$ENV_DRY_RUN_RUN_SUMMARY" >/dev/null; then
  echo "env dry-run combined summary contract mismatch"
  cat "$ENV_DRY_RUN_RUN_SUMMARY"
  exit 1
fi

echo "[phase5-settlement-layer-run] ci failure keeps checker execution"
: >"$CAPTURE"
set +e
PHASE5_SETTLEMENT_LAYER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE5_SETTLEMENT_LAYER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE5_SETTLEMENT_LAYER_RUN_CANONICAL_SUMMARY_JSON="$CI_FAIL_CANONICAL_SUMMARY" \
FAKE_CI_FAIL=1 \
FAKE_CI_FAIL_RC=27 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_fail" \
  --ci-summary-json "$TMP_DIR/ci_fail_summary.json" \
  --check-summary-json "$TMP_DIR/check_fail_summary.json" \
  --summary-json "$CI_FAIL_RUN_SUMMARY" \
  --print-summary-json 0 >"$CI_FAIL_LOG" 2>&1
ci_fail_rc=$?
set -e
if [[ "$ci_fail_rc" -ne 27 ]]; then
  echo "expected wrapper fail rc=27, got rc=$ci_fail_rc"
  cat "$CI_FAIL_LOG"
  exit 1
fi
ci_line="$(grep '^ci	' "$CAPTURE" | tail -n 1 || true)"
check_line="$(grep '^check	' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$ci_line" || -z "$check_line" ]]; then
  echo "expected both stages to run in ci-failure path"
  cat "$CAPTURE"
  cat "$CI_FAIL_LOG"
  exit 1
fi
if [[ "$check_line" != *"--show-json 0"* ]]; then
  echo "default checker show-json forwarding missing"
  echo "$check_line"
  exit 1
fi
if [[ ! -f "$CI_FAIL_RUN_SUMMARY" ]]; then
  echo "missing fail-path combined summary JSON: $CI_FAIL_RUN_SUMMARY"
  cat "$CI_FAIL_LOG"
  exit 1
fi
if [[ ! -f "$CI_FAIL_CANONICAL_SUMMARY" ]]; then
  echo "missing ci-fail canonical summary JSON: $CI_FAIL_CANONICAL_SUMMARY"
  cat "$CI_FAIL_LOG"
  exit 1
fi
if ! cmp -s "$CI_FAIL_RUN_SUMMARY" "$CI_FAIL_CANONICAL_SUMMARY"; then
  echo "ci-fail canonical summary content mismatch"
  cat "$CI_FAIL_RUN_SUMMARY"
  cat "$CI_FAIL_CANONICAL_SUMMARY"
  exit 1
fi
if ! grep -Fq -- "[phase5-settlement-layer-run] canonical_summary_json=$CI_FAIL_CANONICAL_SUMMARY" "$CI_FAIL_LOG"; then
  echo "ci-fail log missing canonical summary line"
  cat "$CI_FAIL_LOG"
  exit 1
fi
if ! jq -e --arg canonical "$CI_FAIL_CANONICAL_SUMMARY" '
  .status == "fail"
  and .rc == 27
  and .artifacts.canonical_summary_json == $canonical
  and .steps.ci_phase5_settlement_layer.status == "fail"
  and .steps.ci_phase5_settlement_layer.rc == 27
  and .steps.ci_phase5_settlement_layer.command_rc == 27
  and .steps.ci_phase5_settlement_layer.contract_valid == true
  and .steps.phase5_settlement_layer_check.status == "pass"
  and .steps.phase5_settlement_layer_check.rc == 0
  and .steps.phase5_settlement_layer_check.command_rc == 0
  and .steps.phase5_settlement_layer_check.contract_valid == true
  and .signals.issuer_sponsor_api_live_smoke_ok == true
  and .signals.issuer_sponsor_api_live_smoke_status == "pass"
  and .signals.issuer_sponsor_api_live_smoke_resolved == true
  and .signals.sources.issuer_sponsor_api_live_smoke_ok == "phase5_settlement_layer_check_summary.signals.issuer_sponsor_api_live_smoke_ok"
  and (
    if (.signals | has("issuer_admin_blockchain_handlers_coverage_ok")) then
      .signals.issuer_admin_blockchain_handlers_coverage_ok == true
      and .signals.issuer_admin_blockchain_handlers_coverage_status == "pass"
      and .signals.issuer_admin_blockchain_handlers_coverage_resolved == true
      and .signals.sources.issuer_admin_blockchain_handlers_coverage_ok == "phase5_settlement_layer_check_summary.signals.issuer_admin_blockchain_handlers_coverage_ok"
    else true
    end
  )
' "$CI_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "ci-failure combined summary contract mismatch"
  cat "$CI_FAIL_RUN_SUMMARY"
  exit 1
fi

echo "[phase5-settlement-layer-run] checker contract failure is fail-closed"
: >"$CAPTURE"
set +e
PHASE5_SETTLEMENT_LAYER_RUN_CAPTURE_FILE="$CAPTURE" \
PHASE5_SETTLEMENT_LAYER_RUN_CI_SCRIPT="$FAKE_CI" \
PHASE5_SETTLEMENT_LAYER_RUN_CHECK_SCRIPT="$FAKE_CHECK" \
PHASE5_SETTLEMENT_LAYER_RUN_CANONICAL_SUMMARY_JSON="$CONTRACT_FAIL_CANONICAL_SUMMARY" \
FAKE_CHECK_OMIT_SUMMARY=1 \
bash "$RUNNER" \
  --reports-dir "$TMP_DIR/reports_contract_fail" \
  --ci-summary-json "$TMP_DIR/ci_contract_fail_summary.json" \
  --check-summary-json "$TMP_DIR/check_contract_fail_summary.json" \
  --summary-json "$CONTRACT_FAIL_RUN_SUMMARY" \
  --dry-run 1 \
  --print-summary-json 0 >"$CONTRACT_FAIL_LOG" 2>&1
contract_fail_rc=$?
set -e
if [[ "$contract_fail_rc" -ne 3 ]]; then
  echo "expected wrapper rc=3 when checker contract is missing, got rc=$contract_fail_rc"
  cat "$CONTRACT_FAIL_LOG"
  exit 1
fi
if [[ ! -f "$CONTRACT_FAIL_RUN_SUMMARY" ]]; then
  echo "missing contract-fail combined summary JSON: $CONTRACT_FAIL_RUN_SUMMARY"
  cat "$CONTRACT_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 3
  and .steps.ci_phase5_settlement_layer.status == "pass"
  and .steps.ci_phase5_settlement_layer.contract_valid == true
  and .steps.phase5_settlement_layer_check.status == "fail"
  and .steps.phase5_settlement_layer_check.command_rc == 0
  and .steps.phase5_settlement_layer_check.contract_valid == false
  and .steps.phase5_settlement_layer_check.contract_error != null
  and .signals.issuer_sponsor_api_live_smoke_ok == null
  and .signals.issuer_sponsor_api_live_smoke_status == "missing"
  and .signals.issuer_sponsor_api_live_smoke_resolved == false
  and .signals.sources.issuer_sponsor_api_live_smoke_ok == "unresolved"
  and (
    if (.signals | has("issuer_admin_blockchain_handlers_coverage_ok")) then
      .signals.issuer_admin_blockchain_handlers_coverage_ok == null
      and .signals.issuer_admin_blockchain_handlers_coverage_status == "missing"
      and .signals.issuer_admin_blockchain_handlers_coverage_resolved == false
      and .signals.sources.issuer_admin_blockchain_handlers_coverage_ok == "unresolved"
    else true
    end
  )
' "$CONTRACT_FAIL_RUN_SUMMARY" >/dev/null; then
  echo "checker-contract-fail combined summary mismatch"
  cat "$CONTRACT_FAIL_RUN_SUMMARY"
  exit 1
fi

echo "phase5 settlement layer run integration ok"
