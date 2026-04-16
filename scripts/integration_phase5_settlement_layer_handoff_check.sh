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

SCRIPT_UNDER_TEST="${PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase5_settlement_layer_handoff_check.sh}"
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
PASS_CANONICAL="$TMP_DIR/pass_canonical_summary.json"
ENV_ROADMAP="$TMP_DIR/roadmap_env_relaxed.json"
ENV_CANONICAL_OUTPUT="$TMP_DIR/env_canonical_output.json"
ENV_CANONICAL_LOG="$TMP_DIR/env_canonical.log"
ENV_LEGACY_OUTPUT="$TMP_DIR/env_legacy_output.json"
ENV_LEGACY_LOG="$TMP_DIR/env_legacy.log"
LEGACY_ALIAS_OUTPUT="$TMP_DIR/legacy_alias_output.json"
LEGACY_ALIAS_LOG="$TMP_DIR/legacy_alias.log"

FALLBACK_RUN="$TMP_DIR/run_fallback.json"
FALLBACK_CHECK="$TMP_DIR/check_fallback.json"
FALLBACK_ROADMAP="$TMP_DIR/roadmap_fallback.json"
FALLBACK_OUTPUT="$TMP_DIR/fallback_output.json"
FALLBACK_LOG="$TMP_DIR/fallback.log"

UNRESOLVED_RUN="$TMP_DIR/run_unresolved.json"
UNRESOLVED_ROADMAP="$TMP_DIR/roadmap_unresolved.json"
UNRESOLVED_OUTPUT="$TMP_DIR/unresolved_output.json"
UNRESOLVED_LOG="$TMP_DIR/unresolved.log"
UNRESOLVED_CANONICAL="$TMP_DIR/unresolved_canonical_summary.json"

FAIL_RUN="$TMP_DIR/run_fail.json"
FAIL_ROADMAP="$TMP_DIR/roadmap_fail.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
FAIL_LOG="$TMP_DIR/fail.log"
FAIL_CANONICAL="$TMP_DIR/fail_canonical_summary.json"

MISSING_OUTPUT="$TMP_DIR/missing_output.json"
MISSING_LOG="$TMP_DIR/missing.log"

# Isolation default: keep canonical handoff-check artifacts scoped to tmp
# unless a test case intentionally overrides the path.
DEFAULT_CANONICAL="$TMP_DIR/default_canonical_summary.json"
export PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$DEFAULT_CANONICAL"

assert_default_canonical() {
  local summary_json="$1"
  local log_file="$2"
  local label="$3"

  if [[ ! -f "$DEFAULT_CANONICAL" ]]; then
    echo "$label: missing default canonical summary: $DEFAULT_CANONICAL"
    cat "$log_file"
    exit 1
  fi
  if ! jq -e --arg expected_canonical "$DEFAULT_CANONICAL" '.artifacts.canonical_summary_json == $expected_canonical' "$summary_json" >/dev/null; then
    echo "$label: summary did not use isolated default canonical path"
    cat "$summary_json"
    cat "$log_file"
    exit 1
  fi
  if ! cmp -s "$summary_json" "$DEFAULT_CANONICAL"; then
    echo "$label: default canonical summary diverges from run summary"
    cat "$summary_json"
    cat "$DEFAULT_CANONICAL"
    cat "$log_file"
    exit 1
  fi
}

cat >"$PASS_ROADMAP" <<'EOF_PASS_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase5_settlement_layer_handoff": {
      "settlement_failsoft_ok": true,
      "settlement_acceptance_ok": true,
      "settlement_bridge_smoke_ok": true,
      "settlement_state_persistence_ok": true,
      "settlement_dual_asset_parity_ok": true,
      "issuer_sponsor_api_live_smoke_ok": true,
      "issuer_admin_blockchain_handlers_coverage_ok": true
    }
  }
}
EOF_PASS_ROADMAP

cat >"$PASS_CHECK" <<'EOF_PASS_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "settlement_failsoft_ok": true,
    "settlement_acceptance_ok": true,
    "settlement_bridge_smoke_ok": true,
    "settlement_state_persistence_ok": true,
    "settlement_dual_asset_parity_ok": true,
    "issuer_sponsor_api_live_smoke_ok": true,
    "issuer_admin_blockchain_handlers_coverage_ok": true
  }
}
EOF_PASS_CHECK

cat >"$PASS_RUN" <<EOF_PASS_RUN
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase5_settlement_layer": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase5_settlement_layer_check": {
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

echo "[phase5-settlement-layer-handoff-check] primary roadmap pass path"
PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase5-run-summary-json "$PASS_RUN" \
  --roadmap-summary-json "$PASS_ROADMAP" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if [[ ! -f "$PASS_CANONICAL" ]]; then
  echo "missing canonical summary on pass path: $PASS_CANONICAL"
  cat "$PASS_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase5_settlement_layer_handoff_check_summary"
  and .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $expected_canonical
  and .fail_closed == true
  and .inputs.usable.phase5_run_summary_json == true
  and .inputs.usable.roadmap_summary_json == true
  and .handoff.run_pipeline_ok == true
  and .handoff.settlement_failsoft_ok == true
  and .handoff.settlement_acceptance_ok == true
  and .handoff.settlement_bridge_smoke_ok == true
  and .handoff.settlement_state_persistence_ok == true
  and .handoff.settlement_dual_asset_parity_ok == true
  and .handoff.issuer_sponsor_api_live_smoke_ok == true
  and .handoff.issuer_admin_blockchain_handlers_coverage_ok == true
  and .handoff.issuer_admin_blockchain_handlers_coverage_status == "pass"
  and .handoff.sources.settlement_failsoft_ok == "roadmap_progress_summary.vpn_track.phase5_settlement_layer_handoff.settlement_failsoft_ok"
  and .handoff.sources.settlement_dual_asset_parity_ok == "roadmap_progress_summary.vpn_track.phase5_settlement_layer_handoff.settlement_dual_asset_parity_ok"
  and .handoff.sources.issuer_sponsor_api_live_smoke_ok == "roadmap_progress_summary.vpn_track.phase5_settlement_layer_handoff.issuer_sponsor_api_live_smoke_ok"
  and .handoff.sources.issuer_admin_blockchain_handlers_coverage_ok == "roadmap_progress_summary.vpn_track.phase5_settlement_layer_handoff.issuer_admin_blockchain_handlers_coverage_ok"
' --arg expected_canonical "$PASS_CANONICAL" "$PASS_OUTPUT" >/dev/null; then
  echo "primary pass-path summary mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi
if ! cmp -s "$PASS_OUTPUT" "$PASS_CANONICAL"; then
  echo "pass-path canonical summary diverges from run summary"
  cat "$PASS_OUTPUT"
  cat "$PASS_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-handoff-check] legacy run summary flag alias remains supported"
"$SCRIPT_UNDER_TEST" \
  --phase4-run-summary-json "$PASS_RUN" \
  --roadmap-summary-json "$PASS_ROADMAP" \
  --summary-json "$LEGACY_ALIAS_OUTPUT" \
  --show-json 0 >"$LEGACY_ALIAS_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.phase5_run_summary_json != null
  and .inputs.phase4_run_summary_json != null
' "$LEGACY_ALIAS_OUTPUT" >/dev/null; then
  echo "legacy alias summary mismatch"
  cat "$LEGACY_ALIAS_OUTPUT"
  cat "$LEGACY_ALIAS_LOG"
  exit 1
fi
assert_default_canonical "$LEGACY_ALIAS_OUTPUT" "$LEGACY_ALIAS_LOG" "legacy run summary alias path"

cat >"$ENV_ROADMAP" <<'EOF_ENV_ROADMAP'
{
  "version": 1,
  "status": "pass",
  "rc": 0,
  "vpn_track": {
    "phase5_settlement_layer_handoff": {
      "settlement_failsoft_ok": true,
      "settlement_acceptance_ok": false,
      "settlement_bridge_smoke_ok": true,
      "settlement_state_persistence_ok": true,
      "settlement_dual_asset_parity_ok": true,
      "issuer_sponsor_api_live_smoke_ok": true,
      "issuer_admin_blockchain_handlers_coverage_ok": true
    }
  }
}
EOF_ENV_ROADMAP

echo "[phase5-settlement-layer-handoff-check] canonical env-var requirement toggle path"
PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_SETTLEMENT_ACCEPTANCE_OK=0 \
"$SCRIPT_UNDER_TEST" \
  --phase5-run-summary-json "$PASS_RUN" \
  --roadmap-summary-json "$ENV_ROADMAP" \
  --summary-json "$ENV_CANONICAL_OUTPUT" \
  --show-json 0 >"$ENV_CANONICAL_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.requirements.settlement_acceptance_ok == false
  and .handoff.settlement_acceptance_ok == false
  and .handoff.settlement_acceptance_status == "fail"
' "$ENV_CANONICAL_OUTPUT" >/dev/null; then
  echo "canonical-env summary mismatch"
  cat "$ENV_CANONICAL_OUTPUT"
  cat "$ENV_CANONICAL_LOG"
  exit 1
fi
assert_default_canonical "$ENV_CANONICAL_OUTPUT" "$ENV_CANONICAL_LOG" "canonical-env toggle path"

echo "[phase5-settlement-layer-handoff-check] legacy env-var compatibility path"
PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_SETTLEMENT_ACCEPTANCE_OK= \
PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_REQUIRE_WINDOWS_ROLE_RUNBOOKS_OK=0 \
"$SCRIPT_UNDER_TEST" \
  --phase5-run-summary-json "$PASS_RUN" \
  --roadmap-summary-json "$ENV_ROADMAP" \
  --summary-json "$ENV_LEGACY_OUTPUT" \
  --show-json 0 >"$ENV_LEGACY_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.requirements.settlement_acceptance_ok == false
  and .handoff.settlement_acceptance_ok == false
  and .handoff.settlement_acceptance_status == "fail"
' "$ENV_LEGACY_OUTPUT" >/dev/null; then
  echo "legacy-env summary mismatch"
  cat "$ENV_LEGACY_OUTPUT"
  cat "$ENV_LEGACY_LOG"
  exit 1
fi
assert_default_canonical "$ENV_LEGACY_OUTPUT" "$ENV_LEGACY_LOG" "legacy-env compatibility path"

cat >"$FALLBACK_CHECK" <<'EOF_FALLBACK_CHECK'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_check_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "signals": {
    "settlement_failsoft_ok": true,
    "settlement_acceptance_ok": true,
    "settlement_bridge_smoke_ok": true,
    "settlement_state_persistence_ok": true,
    "settlement_dual_asset_parity_ok": true,
    "issuer_sponsor_api_live_smoke_ok": true,
    "issuer_admin_blockchain_handlers_coverage_ok": true
  }
}
EOF_FALLBACK_CHECK

cat >"$FALLBACK_RUN" <<EOF_FALLBACK_RUN
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase5_settlement_layer": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase5_settlement_layer_check": {
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
    "phase5_settlement_layer_handoff": {
      "note": "missing booleans on purpose"
    }
  }
}
EOF_FALLBACK_ROADMAP

echo "[phase5-settlement-layer-handoff-check] nested check fallback path"
"$SCRIPT_UNDER_TEST" \
  --phase5-run-summary-json "$FALLBACK_RUN" \
  --roadmap-summary-json "$FALLBACK_ROADMAP" \
  --summary-json "$FALLBACK_OUTPUT" \
  --show-json 0 >"$FALLBACK_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .handoff.settlement_failsoft_ok == true
  and .handoff.settlement_acceptance_ok == true
  and .handoff.settlement_bridge_smoke_ok == true
  and .handoff.settlement_state_persistence_ok == true
  and .handoff.settlement_dual_asset_parity_ok == true
  and .handoff.issuer_sponsor_api_live_smoke_ok == true
  and .handoff.issuer_admin_blockchain_handlers_coverage_ok == true
  and .handoff.issuer_admin_blockchain_handlers_coverage_status == "pass"
  and .handoff.sources.settlement_failsoft_ok == "phase5_settlement_layer_check_summary.settlement_failsoft_ok"
  and .handoff.sources.settlement_acceptance_ok == "phase5_settlement_layer_check_summary.settlement_acceptance_ok"
  and .handoff.sources.settlement_bridge_smoke_ok == "phase5_settlement_layer_check_summary.settlement_bridge_smoke_ok"
  and .handoff.sources.settlement_state_persistence_ok == "phase5_settlement_layer_check_summary.settlement_state_persistence_ok"
  and .handoff.sources.settlement_dual_asset_parity_ok == "phase5_settlement_layer_check_summary.settlement_dual_asset_parity_ok"
  and .handoff.sources.issuer_sponsor_api_live_smoke_ok == "phase5_settlement_layer_check_summary.issuer_sponsor_api_live_smoke_ok"
  and .handoff.sources.issuer_admin_blockchain_handlers_coverage_ok == "phase5_settlement_layer_check_summary.issuer_admin_blockchain_handlers_coverage_ok"
' "$FALLBACK_OUTPUT" >/dev/null; then
  echo "fallback-path summary mismatch"
  cat "$FALLBACK_OUTPUT"
  cat "$FALLBACK_LOG"
  exit 1
fi
assert_default_canonical "$FALLBACK_OUTPUT" "$FALLBACK_LOG" "nested check fallback path"

cat >"$UNRESOLVED_RUN" <<'EOF_UNRESOLVED_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "ci_phase5_settlement_layer": {
      "status": "pass",
      "rc": 0,
      "command_rc": 0,
      "contract_valid": true
    },
    "phase5_settlement_layer_check": {
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
    "phase5_settlement_layer_handoff": {
      "note": "intentionally unresolved"
    }
  }
}
EOF_UNRESOLVED_ROADMAP

echo "[phase5-settlement-layer-handoff-check] unresolved booleans with relaxed requirements (canonical flags + one legacy requirement alias)"
PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$UNRESOLVED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase5-run-summary-json "$UNRESOLVED_RUN" \
  --roadmap-summary-json "$UNRESOLVED_ROADMAP" \
  --summary-json "$UNRESOLVED_OUTPUT" \
  --require-run-pipeline-ok 0 \
  --require-windows-server-packaging-ok 0 \
  --require-settlement-acceptance-ok 0 \
  --require-settlement-bridge-smoke-ok 0 \
  --require-settlement-state-persistence-ok 0 \
  --require-settlement-dual-asset-parity-ok 0 \
  --require-issuer-sponsor-api-live-smoke-ok 0 \
  --require-issuer-admin-blockchain-handlers-coverage-ok 0 \
  --show-json 0 >"$UNRESOLVED_LOG" 2>&1

if [[ ! -f "$UNRESOLVED_CANONICAL" ]]; then
  echo "missing canonical summary on unresolved-relaxed path: $UNRESOLVED_CANONICAL"
  cat "$UNRESOLVED_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $expected_canonical
  and .handoff.run_pipeline_ok == true
  and .handoff.settlement_failsoft_ok == null
  and .handoff.settlement_acceptance_ok == null
  and .handoff.settlement_bridge_smoke_ok == null
  and .handoff.settlement_state_persistence_ok == null
  and .handoff.settlement_dual_asset_parity_ok == null
  and .handoff.issuer_sponsor_api_live_smoke_ok == null
  and .handoff.issuer_admin_blockchain_handlers_coverage_ok == null
  and .handoff.issuer_admin_blockchain_handlers_coverage_status == "missing"
' --arg expected_canonical "$UNRESOLVED_CANONICAL" "$UNRESOLVED_OUTPUT" >/dev/null; then
  echo "unresolved relaxed summary mismatch"
  cat "$UNRESOLVED_OUTPUT"
  cat "$UNRESOLVED_LOG"
  exit 1
fi
if ! cmp -s "$UNRESOLVED_OUTPUT" "$UNRESOLVED_CANONICAL"; then
  echo "unresolved-relaxed canonical summary diverges from run summary"
  cat "$UNRESOLVED_OUTPUT"
  cat "$UNRESOLVED_CANONICAL"
  exit 1
fi

cat >"$FAIL_RUN" <<'EOF_FAIL_RUN'
{
  "version": 1,
  "schema": {
    "id": "phase5_settlement_layer_run_summary",
    "major": 1,
    "minor": 0
  },
  "status": "fail",
  "rc": 27,
  "steps": {
    "ci_phase5_settlement_layer": {
      "status": "fail",
      "rc": 27,
      "command_rc": 27,
      "contract_valid": true
    },
    "phase5_settlement_layer_check": {
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
    "phase5_settlement_layer_handoff": {
      "settlement_failsoft_ok": true,
      "settlement_acceptance_ok": true,
      "settlement_bridge_smoke_ok": true,
      "settlement_state_persistence_ok": true,
      "settlement_dual_asset_parity_ok": true,
      "issuer_sponsor_api_live_smoke_ok": true,
      "issuer_admin_blockchain_handlers_coverage_ok": true
    }
  }
}
EOF_FAIL_ROADMAP

echo "[phase5-settlement-layer-handoff-check] run pipeline failure is fail-closed"
set +e
PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --phase5-run-summary-json "$FAIL_RUN" \
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
if [[ ! -f "$FAIL_CANONICAL" ]]; then
  echo "missing canonical summary on fail path: $FAIL_CANONICAL"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .artifacts.canonical_summary_json == $expected_canonical
  and .handoff.run_pipeline_ok == false
  and ((.decision.reasons // []) | any(test("run_pipeline_ok is false|run_pipeline_ok unresolved")))
' --arg expected_canonical "$FAIL_CANONICAL" "$FAIL_OUTPUT" >/dev/null; then
  echo "run pipeline failure summary mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi
if ! cmp -s "$FAIL_OUTPUT" "$FAIL_CANONICAL"; then
  echo "fail-path canonical summary diverges from run summary"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-handoff-check] missing run summary contract fail-close"
set +e
"$SCRIPT_UNDER_TEST" \
  --phase5-run-summary-json "$TMP_DIR/missing_run.json" \
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
  and .inputs.usable.phase5_run_summary_json == false
  and ((.decision.reasons // []) | any(test("phase5 run summary file not found or invalid JSON")))
' "$MISSING_OUTPUT" >/dev/null; then
  echo "missing-run summary mismatch"
  cat "$MISSING_OUTPUT"
  cat "$MISSING_LOG"
  exit 1
fi
assert_default_canonical "$MISSING_OUTPUT" "$MISSING_LOG" "missing run summary fail-close path"
if ! grep -q '"schema"' "$MISSING_LOG"; then
  echo "--show-json 1 did not print summary payload"
  cat "$MISSING_LOG"
  exit 1
fi

echo "phase5 settlement layer handoff check integration ok"
