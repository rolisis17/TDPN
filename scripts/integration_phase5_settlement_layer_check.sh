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

SCRIPT_UNDER_TEST="${PHASE5_SETTLEMENT_LAYER_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase5_settlement_layer_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SUMMARY="$TMP_DIR/ci_phase5_pass.json"
FAIL_SUMMARY="$TMP_DIR/ci_phase5_fail.json"
RELAXED_SUMMARY="$TMP_DIR/ci_phase5_relaxed.json"
DUAL_FAIL_SUMMARY="$TMP_DIR/ci_phase5_dual_fail.json"
SPONSOR_FAIL_SUMMARY="$TMP_DIR/ci_phase5_sponsor_fail.json"
MISSING_SUMMARY="$TMP_DIR/ci_phase5_missing.json"

PASS_OUTPUT="$TMP_DIR/pass_output.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
RELAXED_OUTPUT="$TMP_DIR/relaxed_output.json"
DUAL_FAIL_OUTPUT="$TMP_DIR/dual_fail_output.json"
DUAL_RELAXED_OUTPUT="$TMP_DIR/dual_relaxed_output.json"
SPONSOR_FAIL_OUTPUT="$TMP_DIR/sponsor_fail_output.json"
SPONSOR_RELAXED_OUTPUT="$TMP_DIR/sponsor_relaxed_output.json"
PASS_CANONICAL="$TMP_DIR/pass_canonical_summary.json"
FAIL_CANONICAL="$TMP_DIR/fail_canonical_summary.json"
RELAXED_CANONICAL="$TMP_DIR/relaxed_canonical_summary.json"
DUAL_FAIL_CANONICAL="$TMP_DIR/dual_fail_canonical_summary.json"
DUAL_RELAXED_CANONICAL="$TMP_DIR/dual_relaxed_canonical_summary.json"
SPONSOR_FAIL_CANONICAL="$TMP_DIR/sponsor_fail_canonical_summary.json"
SPONSOR_RELAXED_CANONICAL="$TMP_DIR/sponsor_relaxed_canonical_summary.json"
ENV_CANONICAL_OUTPUT="$TMP_DIR/env_canonical_output.json"
ENV_LEGACY_OUTPUT="$TMP_DIR/env_legacy_output.json"
LEGACY_ALIAS_OUTPUT="$TMP_DIR/legacy_alias_output.json"
MISSING_OUTPUT="$TMP_DIR/missing_output.json"

PASS_LOG="$TMP_DIR/pass.log"
FAIL_LOG="$TMP_DIR/fail.log"
RELAXED_LOG="$TMP_DIR/relaxed.log"
DUAL_FAIL_LOG="$TMP_DIR/dual_fail.log"
DUAL_RELAXED_LOG="$TMP_DIR/dual_relaxed.log"
SPONSOR_FAIL_LOG="$TMP_DIR/sponsor_fail.log"
SPONSOR_RELAXED_LOG="$TMP_DIR/sponsor_relaxed.log"
ENV_CANONICAL_LOG="$TMP_DIR/env_canonical.log"
ENV_LEGACY_LOG="$TMP_DIR/env_legacy.log"
LEGACY_ALIAS_LOG="$TMP_DIR/legacy_alias.log"
MISSING_LOG="$TMP_DIR/missing.log"

cat >"$PASS_SUMMARY" <<'EOF_PASS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    }
  }
}
EOF_PASS

cat >"$FAIL_SUMMARY" <<'EOF_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "fail"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    }
  }
}
EOF_FAIL

cat >"$RELAXED_SUMMARY" <<'EOF_RELAXED'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "fail"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    }
  }
}
EOF_RELAXED

cat >"$SPONSOR_FAIL_SUMMARY" <<'EOF_SPONSOR_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "pass"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "fail"
    }
  }
}
EOF_SPONSOR_FAIL

cat >"$DUAL_FAIL_SUMMARY" <<'EOF_DUAL_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase5_settlement_layer_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "settlement_failsoft": {
      "status": "pass"
    },
    "settlement_acceptance": {
      "status": "pass"
    },
    "settlement_bridge_smoke": {
      "status": "pass"
    },
    "settlement_state_persistence": {
      "status": "pass"
    },
    "settlement_dual_asset_parity": {
      "status": "fail"
    },
    "issuer_sponsor_api_live_smoke": {
      "status": "pass"
    }
  }
}
EOF_DUAL_FAIL

echo "[phase5-settlement-layer-check] stage-derived pass path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$PASS_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$PASS_SUMMARY" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if [[ ! -f "$PASS_CANONICAL" ]]; then
  echo "missing canonical summary on pass path: $PASS_CANONICAL"
  cat "$PASS_LOG"
  exit 1
fi
if ! jq -e '
  .version == 1
  and .schema.id == "phase5_settlement_layer_check_summary"
  and .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $expected_canonical
  and .inputs.usable.ci_phase5_summary_json == true
  and .policy.require_settlement_failsoft_ok == true
  and .policy.require_settlement_acceptance_ok == true
  and .policy.require_settlement_bridge_smoke_ok == true
  and .policy.require_settlement_state_persistence_ok == true
  and .policy.require_settlement_dual_asset_parity_ok == true
  and .policy.require_issuer_sponsor_api_live_smoke_ok == true
  and .signals.settlement_failsoft_ok == true
  and .signals.settlement_acceptance_ok == true
  and .signals.settlement_bridge_smoke_ok == true
  and .signals.settlement_state_persistence_ok == true
  and .signals.settlement_dual_asset_parity_ok == true
  and .signals.issuer_sponsor_api_live_smoke_ok == true
' --arg expected_canonical "$PASS_CANONICAL" "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary contract mismatch"
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

echo "[phase5-settlement-layer-check] fail-closed path on stage failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$FAIL_SUMMARY" \
  --summary-json "$FAIL_OUTPUT" \
  --show-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for fail-closed stage failure, got rc=$fail_rc"
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
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
  and ((.decision.reasons // []) | any(test("settlement_acceptance_ok is false")))
' --arg expected_canonical "$FAIL_CANONICAL" "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary contract mismatch"
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

echo "[phase5-settlement-layer-check] canonical relaxed policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-settlement-acceptance-ok 0 \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if [[ ! -f "$RELAXED_CANONICAL" ]]; then
  echo "missing canonical summary on relaxed path: $RELAXED_CANONICAL"
  cat "$RELAXED_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .artifacts.canonical_summary_json == $expected_canonical
  and .policy.require_settlement_acceptance_ok == false
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
' --arg expected_canonical "$RELAXED_CANONICAL" "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-policy summary mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
  exit 1
fi
if ! cmp -s "$RELAXED_OUTPUT" "$RELAXED_CANONICAL"; then
  echo "relaxed-path canonical summary diverges from run summary"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_CANONICAL"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on dual-asset parity failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$DUAL_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$DUAL_FAIL_SUMMARY" \
  --summary-json "$DUAL_FAIL_OUTPUT" \
  --show-json 0 >"$DUAL_FAIL_LOG" 2>&1
dual_fail_rc=$?
set -e
if [[ "$dual_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for dual-asset parity fail-closed path, got rc=$dual_fail_rc"
  cat "$DUAL_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_settlement_dual_asset_parity_ok == true
  and .signals.settlement_dual_asset_parity_ok == false
  and .stages.settlement_dual_asset_parity.status == "fail"
  and ((.decision.reasons // []) | any(test("settlement_dual_asset_parity_ok is false")))
' "$DUAL_FAIL_OUTPUT" >/dev/null; then
  echo "dual-asset fail-path summary mismatch"
  cat "$DUAL_FAIL_OUTPUT"
  cat "$DUAL_FAIL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] dual-asset policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$DUAL_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$DUAL_FAIL_SUMMARY" \
  --summary-json "$DUAL_RELAXED_OUTPUT" \
  --require-settlement-dual-asset-parity-ok 0 \
  --show-json 0 >"$DUAL_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_dual_asset_parity_ok == false
  and .signals.settlement_dual_asset_parity_ok == false
  and .stages.settlement_dual_asset_parity.status == "fail"
' "$DUAL_RELAXED_OUTPUT" >/dev/null; then
  echo "dual-asset relaxed-policy summary mismatch"
  cat "$DUAL_RELAXED_OUTPUT"
  cat "$DUAL_RELAXED_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on sponsor live-smoke failure"
set +e
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SPONSOR_FAIL_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SPONSOR_FAIL_SUMMARY" \
  --summary-json "$SPONSOR_FAIL_OUTPUT" \
  --show-json 0 >"$SPONSOR_FAIL_LOG" 2>&1
sponsor_fail_rc=$?
set -e
if [[ "$sponsor_fail_rc" -ne 1 ]]; then
  echo "expected rc=1 for sponsor fail-closed path, got rc=$sponsor_fail_rc"
  cat "$SPONSOR_FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .policy.require_issuer_sponsor_api_live_smoke_ok == true
  and .signals.issuer_sponsor_api_live_smoke_ok == false
  and .stages.issuer_sponsor_api_live_smoke.status == "fail"
  and ((.decision.reasons // []) | any(test("issuer_sponsor_api_live_smoke_ok is false")))
' "$SPONSOR_FAIL_OUTPUT" >/dev/null; then
  echo "sponsor fail-path summary mismatch"
  cat "$SPONSOR_FAIL_OUTPUT"
  cat "$SPONSOR_FAIL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] sponsor policy toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_CANONICAL_SUMMARY_JSON="$SPONSOR_RELAXED_CANONICAL" \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$SPONSOR_FAIL_SUMMARY" \
  --summary-json "$SPONSOR_RELAXED_OUTPUT" \
  --require-issuer-sponsor-api-live-smoke-ok 0 \
  --show-json 0 >"$SPONSOR_RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_issuer_sponsor_api_live_smoke_ok == false
  and .signals.issuer_sponsor_api_live_smoke_ok == false
  and .stages.issuer_sponsor_api_live_smoke.status == "fail"
' "$SPONSOR_RELAXED_OUTPUT" >/dev/null; then
  echo "sponsor relaxed-policy summary mismatch"
  cat "$SPONSOR_RELAXED_OUTPUT"
  cat "$SPONSOR_RELAXED_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] canonical env-var requirement toggle path"
PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_ACCEPTANCE_OK=0 \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$ENV_CANONICAL_OUTPUT" \
  --show-json 0 >"$ENV_CANONICAL_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_acceptance_ok == false
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
' "$ENV_CANONICAL_OUTPUT" >/dev/null; then
  echo "canonical-env policy summary mismatch"
  cat "$ENV_CANONICAL_OUTPUT"
  cat "$ENV_CANONICAL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] legacy env-var compatibility path"
PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_SETTLEMENT_ACCEPTANCE_OK= \
PHASE5_SETTLEMENT_LAYER_CHECK_REQUIRE_WINDOWS_ROLE_RUNBOOKS_OK=0 \
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$ENV_LEGACY_OUTPUT" \
  --show-json 0 >"$ENV_LEGACY_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_acceptance_ok == false
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
' "$ENV_LEGACY_OUTPUT" >/dev/null; then
  echo "legacy-env policy summary mismatch"
  cat "$ENV_LEGACY_OUTPUT"
  cat "$ENV_LEGACY_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] legacy alias compatibility path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$LEGACY_ALIAS_OUTPUT" \
  --require-windows-role-runbooks-ok 0 \
  --show-json 0 >"$LEGACY_ALIAS_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_acceptance_ok == false
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
' "$LEGACY_ALIAS_OUTPUT" >/dev/null; then
  echo "legacy-alias policy summary mismatch"
  cat "$LEGACY_ALIAS_OUTPUT"
  cat "$LEGACY_ALIAS_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] dual-asset compatibility alias path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$DUAL_FAIL_SUMMARY" \
  --summary-json "$LEGACY_ALIAS_OUTPUT" \
  --require-settlement-dual-asset-ok 0 \
  --show-json 0 >"$LEGACY_ALIAS_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_dual_asset_parity_ok == false
  and .signals.settlement_dual_asset_parity_ok == false
  and .stages.settlement_dual_asset_parity.status == "fail"
' "$LEGACY_ALIAS_OUTPUT" >/dev/null; then
  echo "dual-asset legacy-alias policy summary mismatch"
  cat "$LEGACY_ALIAS_OUTPUT"
  cat "$LEGACY_ALIAS_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] missing-summary show-json path"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$MISSING_SUMMARY" \
  --summary-json "$MISSING_OUTPUT" \
  --show-json 1 >"$MISSING_LOG" 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 1 ]]; then
  echo "expected rc=1 for missing summary fail-close, got rc=$missing_rc"
  cat "$MISSING_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .inputs.usable.ci_phase5_summary_json == false
  and ((.decision.reasons // []) | any(test("summary file not found or invalid JSON")))
' "$MISSING_OUTPUT" >/dev/null; then
  echo "missing-summary contract mismatch"
  cat "$MISSING_OUTPUT"
  cat "$MISSING_LOG"
  exit 1
fi
if ! grep -q '"schema"' "$MISSING_LOG"; then
  echo "--show-json 1 did not print summary payload"
  cat "$MISSING_LOG"
  exit 1
fi

echo "phase5 settlement layer check integration ok"
