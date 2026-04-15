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
MISSING_SUMMARY="$TMP_DIR/ci_phase5_missing.json"

PASS_OUTPUT="$TMP_DIR/pass_output.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
RELAXED_OUTPUT="$TMP_DIR/relaxed_output.json"
LEGACY_ALIAS_OUTPUT="$TMP_DIR/legacy_alias_output.json"
MISSING_OUTPUT="$TMP_DIR/missing_output.json"

PASS_LOG="$TMP_DIR/pass.log"
FAIL_LOG="$TMP_DIR/fail.log"
RELAXED_LOG="$TMP_DIR/relaxed.log"
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
    }
  }
}
EOF_RELAXED

echo "[phase5-settlement-layer-check] stage-derived pass path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$PASS_SUMMARY" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
  .version == 1
  and .schema.id == "phase5_settlement_layer_check_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.usable.ci_phase5_summary_json == true
  and .policy.require_settlement_failsoft_ok == true
  and .policy.require_settlement_acceptance_ok == true
  and .policy.require_settlement_bridge_smoke_ok == true
  and .policy.require_settlement_state_persistence_ok == true
  and .signals.settlement_failsoft_ok == true
  and .signals.settlement_acceptance_ok == true
  and .signals.settlement_bridge_smoke_ok == true
  and .signals.settlement_state_persistence_ok == true
' "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary contract mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] fail-closed path on stage failure"
set +e
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
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
  and ((.decision.reasons // []) | any(test("settlement_acceptance_ok is false")))
' "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary contract mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase5-settlement-layer-check] canonical relaxed policy toggle path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase5-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-settlement-acceptance-ok 0 \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_settlement_acceptance_ok == false
  and .signals.settlement_acceptance_ok == false
  and .stages.settlement_acceptance.status == "fail"
' "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-policy summary mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
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
