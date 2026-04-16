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

SCRIPT_UNDER_TEST="${PHASE2_LINUX_PROD_CANDIDATE_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/phase2_linux_prod_candidate_check.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_SUMMARY="$TMP_DIR/ci_phase2_pass.json"
FAIL_SUMMARY="$TMP_DIR/ci_phase2_fail.json"
RELAXED_SUMMARY="$TMP_DIR/ci_phase2_relaxed.json"
MISSING_SUMMARY="$TMP_DIR/ci_phase2_missing.json"

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
    "id": "ci_phase2_linux_prod_candidate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "release_integrity": {
      "status": "pass"
    },
    "release_policy_gate": {
      "status": "pass"
    },
    "prod_operator_lifecycle_runbook": {
      "status": "pass"
    },
    "prod_pilot_cohort_signoff": {
      "status": "pass"
    }
  }
}
EOF_PASS

cat >"$FAIL_SUMMARY" <<'EOF_FAIL'
{
  "version": 1,
  "schema": {
    "id": "ci_phase2_linux_prod_candidate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "release_integrity": {
      "status": "pass"
    },
    "release_policy_gate": {
      "status": "fail"
    },
    "prod_operator_lifecycle_runbook": {
      "status": "pass"
    },
    "prod_pilot_cohort_signoff": {
      "status": "pass"
    }
  }
}
EOF_FAIL

cat >"$RELAXED_SUMMARY" <<'EOF_RELAXED'
{
  "version": 1,
  "schema": {
    "id": "ci_phase2_linux_prod_candidate_summary",
    "major": 1,
    "minor": 0
  },
  "status": "pass",
  "rc": 0,
  "steps": {
    "release_integrity": {
      "status": "pass"
    },
    "release_policy_gate": {
      "status": "fail"
    },
    "prod_operator_lifecycle_runbook": {
      "status": "pass"
    },
    "prod_pilot_cohort_signoff": {
      "status": "pass"
    }
  }
}
EOF_RELAXED

echo "[phase2-linux-prod-candidate-check] stage-derived pass path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase2-summary-json "$PASS_SUMMARY" \
  --summary-json "$PASS_OUTPUT" \
  --show-json 0 >"$PASS_LOG" 2>&1

if ! jq -e '
  .version == 1
  and .schema.id == "phase2_linux_prod_candidate_check_summary"
  and .status == "pass"
  and .rc == 0
  and .fail_closed == true
  and .inputs.usable.ci_phase2_summary_json == true
  and .policy.require_release_integrity_ok == true
  and .policy.require_release_policy_ok == true
  and .signals.release_integrity_ok == true
  and .signals.release_policy_ok == true
  and .signals.operator_lifecycle_ok == true
  and .signals.pilot_signoff_ok == true
  and .stages.release_integrity.status == "pass"
  and .stages.release_policy.status == "pass"
  and .stages.operator_lifecycle.status == "pass"
  and .stages.pilot_signoff.status == "pass"
  and (.decision.reason_details | length) == 0
  and (.decision.warnings | length) == 0
  and (.decision.warning_details | length) == 0
' "$PASS_OUTPUT" >/dev/null; then
  echo "pass-path summary contract mismatch"
  cat "$PASS_OUTPUT"
  cat "$PASS_LOG"
  exit 1
fi

echo "[phase2-linux-prod-candidate-check] fail-closed path on stage failure"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-phase2-summary-json "$FAIL_SUMMARY" \
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
  and .signals.release_policy_ok == false
  and .stages.release_policy.status == "fail"
  and ((.decision.reasons // []) | any(test("release_policy_ok is false")))
  and ((.decision.reason_details // []) | any(.code == "required_signal_false" and .signal == "release_policy_ok"))
  and ((.decision.reason_codes // []) | index("required_signal_false") != null)
' "$FAIL_OUTPUT" >/dev/null; then
  echo "fail-path summary contract mismatch"
  cat "$FAIL_OUTPUT"
  cat "$FAIL_LOG"
  exit 1
fi

echo "[phase2-linux-prod-candidate-check] relaxed policy toggle path"
"$SCRIPT_UNDER_TEST" \
  --ci-phase2-summary-json "$RELAXED_SUMMARY" \
  --summary-json "$RELAXED_OUTPUT" \
  --require-release-policy-ok 0 \
  --show-json 0 >"$RELAXED_LOG" 2>&1

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .policy.require_release_policy_ok == false
  and .signals.release_policy_ok == false
  and .stages.release_policy.status == "fail"
  and ((.decision.warnings // []) | any(test("release_policy_ok is not ready but requirement is disabled")))
  and ((.decision.warning_details // []) | any(.code == "optional_signal_not_ready" and .signal == "release_policy_ok"))
  and ((.decision.warning_codes // []) | index("optional_signal_not_ready") != null)
' "$RELAXED_OUTPUT" >/dev/null; then
  echo "relaxed-policy summary mismatch"
  cat "$RELAXED_OUTPUT"
  cat "$RELAXED_LOG"
  exit 1
fi

echo "[phase2-linux-prod-candidate-check] missing-summary show-json path"
set +e
"$SCRIPT_UNDER_TEST" \
  --ci-phase2-summary-json "$MISSING_SUMMARY" \
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
  and .inputs.usable.ci_phase2_summary_json == false
  and ((.decision.reasons // []) | any(test("summary file not found or invalid JSON")))
  and ((.decision.reason_details // []) | any(.code == "ci_summary_unusable"))
  and ((.decision.reason_codes // []) | index("ci_summary_unusable") != null)
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

echo "phase2 linux prod candidate check integration ok"
