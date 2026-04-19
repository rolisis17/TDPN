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

SCRIPT_UNDER_TEST="${PHASE4_WINDOWS_FULL_PARITY_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase4_windows_full_parity_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SUMMARY="$TMP_DIR/ci_phase4_pass.json"
FAIL_SUMMARY="$TMP_DIR/ci_phase4_fail.json"
RELAXED_SUMMARY="$TMP_DIR/ci_phase4_relaxed.json"
MISSING_SUMMARY="$TMP_DIR/ci_phase4_missing.json"

PASS_OUTPUT="$TMP_DIR/pass_output.json"
FAIL_OUTPUT="$TMP_DIR/fail_output.json"
RELAXED_OUTPUT="$TMP_DIR/relaxed_output.json"
MISSING_OUTPUT="$TMP_DIR/missing_output.json"

PASS_LOG="$TMP_DIR/pass.log"
FAIL_LOG="$TMP_DIR/fail.log"
RELAXED_LOG="$TMP_DIR/relaxed.log"
MISSING_LOG="$TMP_DIR/missing.log"

cat >"$PASS_SUMMARY" <<'EOF_PASS'
{
  "version": 1,
  "schema": {
    "id": "ci_phase4_windows_full_parity_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "windows_server_packaging": {
      "status": "pass"
    },
    "windows_native_bootstrap_guardrails": {
      "status": "pass"
    },
    "windows_role_runbooks": {
      "status": "pass"
    },
    "cross_platform_interop": {
      "status": "pass"
    },
    "role_combination_validation": {
      "status": "pass"
    }
  }
}
EOF_PASS

cat >"$FAIL_SUMMARY" <<'EOF_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase4_windows_full_parity_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "windows_server_packaging": {
      "status": "pass"
    },
    "windows_native_bootstrap_guardrails": {
      "status": "pass"
    },
    "windows_role_runbooks": {
      "status": "fail"
    },
    "cross_platform_interop": {
      "status": "pass"
    },
    "role_combination_validation": {
      "status": "pass"
    }
  }
}
EOF_FAIL

cat >"$RELAXED_SUMMARY" <<'EOF_RELAXED'
{
  "version": 1,
  "schema": {
    "id": "ci_phase4_windows_full_parity_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "windows_server_packaging": {
      "status": "pass"
    },
    "windows_native_bootstrap_guardrails": {
      "status": "fail"
    },
    "windows_role_runbooks": {
      "status": "fail"
    },
    "cross_platform_interop": {
      "status": "pass"
    },
    "role_combination_validation": {
      "status": "pass"
    }
  }
}
EOF_RELAXED

echo "[phase4-windows-full-parity-check] stage-derived pass path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase4-summary-json "$PASS_SUMMARY" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
  .version == 1
  and .schema.id == "phase4_windows_full_parity_check_summary"
  and .status == "pass"
  and .rc == 0
  and .inputs.usable.ci_phase4_summary_json == true
  and .policy.require_windows_server_packaging_ok == true
  and .policy.require_windows_native_bootstrap_guardrails_ok == false
  and .policy.require_windows_role_runbooks_ok == true
  and .policy.require_cross_platform_interop_ok == true
  and .policy.require_role_combination_validation_ok == true
  and .signals.windows_server_packaging_ok == true
  and .signals.windows_native_bootstrap_guardrails_ok == true
  and .signals.windows_role_runbooks_ok == true
  and .signals.cross_platform_interop_ok == true
  and .signals.role_combination_validation_ok == true
  and .decision.failure_kind == "none"
  and ((.decision.reason_codes // []) | length) == 0
  and .failure.kind == "none"
  and .signal_semantics.windows_server_packaging_ok.failure_kind == "ok"
  and .signal_semantics.windows_native_bootstrap_guardrails_ok.failure_kind == "not_required"
  and .signal_semantics.windows_role_runbooks_ok.failure_kind == "ok"
  and .signal_semantics.cross_platform_interop_ok.failure_kind == "ok"
  and .signal_semantics.role_combination_validation_ok.failure_kind == "ok"
' "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary contract mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase4-windows-full-parity-check] fail-closed path on stage failure"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-phase4-summary-json "$FAIL_SUMMARY" \
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
  and .signals.windows_role_runbooks_ok == false
  and .stages.windows_role_runbooks.status == "fail"
  and ((.decision.reasons // []) | any(test("windows_role_runbooks_ok is false")))
  and ((.decision.reason_codes // []) | any(. == "windows_role_runbooks_ok_false"))
  and .decision.failure_kind == "policy_no_go"
  and .failure.kind == "policy_no_go"
  and .signal_semantics.windows_role_runbooks_ok.failure_kind == "false"
  and (
    (.decision.reason_details // [])
    | any(.signal == "windows_role_runbooks_ok" and .kind == "false")
  )
' "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary contract mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase4-windows-full-parity-check] relaxed policy toggle path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase4-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-windows-native-bootstrap-guardrails-ok 0 \
  --require-windows-role-runbooks-ok 0 \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_windows_native_bootstrap_guardrails_ok == false
  and .policy.require_windows_role_runbooks_ok == false
  and .signals.windows_native_bootstrap_guardrails_ok == false
  and .stages.windows_native_bootstrap_guardrails.status == "fail"
  and .signal_semantics.windows_native_bootstrap_guardrails_ok.failure_kind == "not_required"
  and .signals.windows_role_runbooks_ok == false
  and .stages.windows_role_runbooks.status == "fail"
  and .signal_semantics.windows_role_runbooks_ok.failure_kind == "not_required"
  and ((.decision.reason_codes // []) | any(. == "windows_native_bootstrap_guardrails_ok_false") | not)
  and ((.decision.reason_codes // []) | any(. == "windows_role_runbooks_ok_false") | not)
' "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-policy summary mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
  exit 1
fi

echo "[phase4-windows-full-parity-check] missing-summary show-json path"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-phase4-summary-json "$MISSING_SUMMARY" \
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
  and .inputs.usable.ci_phase4_summary_json == false
  and ((.decision.reasons // []) | any(test("summary file not found or invalid JSON")))
  and ((.decision.reason_codes // []) | any(. == "ci_phase4_summary_unusable"))
  and .signal_semantics.windows_server_packaging_ok.failure_kind == "unresolved"
  and .signal_semantics.windows_native_bootstrap_guardrails_ok.failure_kind == "not_required"
  and .signal_semantics.windows_role_runbooks_ok.failure_kind == "unresolved"
  and .signal_semantics.cross_platform_interop_ok.failure_kind == "unresolved"
  and .signal_semantics.role_combination_validation_ok.failure_kind == "unresolved"
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

echo "phase4 windows full parity check integration ok"
