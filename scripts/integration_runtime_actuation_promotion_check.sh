#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${RUNTIME_ACTUATION_PROMOTION_CHECK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/runtime_actuation_promotion_check.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

PASS_CAMPAIGN_A="$TMP_DIR/campaign_check_pass_a.json"
PASS_CAMPAIGN_B="$TMP_DIR/campaign_check_pass_b.json"
PASS_SIGNOFF="$TMP_DIR/signoff_pass.json"
SIGNOFF_UNKNOWN_DUPLICATE="$TMP_DIR/signoff_unknown_duplicate.json"
SIGNOFF_MISSING_CONTEXT="$TMP_DIR/signoff_missing_context.json"
FAIL_CAMPAIGN_A="$TMP_DIR/campaign_check_fail_a.json"
FAIL_CAMPAIGN_B="$TMP_DIR/campaign_check_fail_b.json"
MISSING_DIAGNOSTICS="$TMP_DIR/campaign_check_missing_diagnostics.json"

cat >"$PASS_CAMPAIGN_A" <<'EOF_PASS_CAMPAIGN_A'
{
  "version": 1,
  "status": "ok",
  "rc": 0,
  "decision": "GO",
  "decision_diagnostics": {
    "m4_policy": {
      "gate_evaluation": {
        "runtime_actuation_status_pass": {
          "required": true,
          "observed": true,
          "status": "pass",
          "source": "explicit_campaign_summary"
        }
      }
    }
  }
}
EOF_PASS_CAMPAIGN_A

cat >"$PASS_CAMPAIGN_B" <<'EOF_PASS_CAMPAIGN_B'
{
  "version": 1,
  "status": "ok",
  "rc": 0,
  "decision": "GO",
  "decision_diagnostics": {
    "m4_policy": {
      "gate_evaluation": {
        "runtime_actuation_status_pass": {
          "required": true,
          "observed": true,
          "status": "pass",
          "source": "explicit_selected_summaries"
        }
      }
    }
  }
}
EOF_PASS_CAMPAIGN_B

cat >"$PASS_SIGNOFF" <<'EOF_PASS_SIGNOFF'
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "decision": {
    "decision": "GO",
    "next_operator_action": "No action required; runtime evidence is healthy",
    "campaign_check_gate_diagnostics": {
      "runtime_actuation_status_pass": {
        "available": true,
        "required": true,
        "status": "pass",
        "blocking": false,
        "source": "explicit_campaign_summary"
      }
    }
  },
  "artifacts": {
    "campaign_check_summary_json": ".easy-node-logs/profile_compare_campaign_check_summary.json"
  }
}
EOF_PASS_SIGNOFF

cat >"$SIGNOFF_UNKNOWN_DUPLICATE" <<EOF_SIGNOFF_UNKNOWN_DUPLICATE
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "decision": {
    "decision": "GO",
    "next_operator_action": "No action required",
    "campaign_check_gate_diagnostics": {
      "runtime_actuation_status_pass": {
        "available": false,
        "required": true,
        "status": "unknown",
        "blocking": false,
        "source": "explicit_campaign_summary"
      }
    }
  },
  "artifacts": {
    "campaign_check_summary_json": "$TMP_DIR/./campaign_check_pass_a.json"
  }
}
EOF_SIGNOFF_UNKNOWN_DUPLICATE

cat >"$SIGNOFF_MISSING_CONTEXT" <<'EOF_SIGNOFF_MISSING_CONTEXT'
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "decision": {
    "decision": "GO",
    "next_operator_action": "refresh signoff context"
  },
  "artifacts": {
    "campaign_check_summary_json": ".easy-node-logs/profile_compare_campaign_check_summary.json"
  }
}
EOF_SIGNOFF_MISSING_CONTEXT

cat >"$FAIL_CAMPAIGN_A" <<'EOF_FAIL_CAMPAIGN_A'
{
  "version": 1,
  "status": "fail",
  "rc": 0,
  "decision": "NO-GO",
  "decision_diagnostics": {
    "m4_policy": {
      "gate_evaluation": {
        "runtime_actuation_status_pass": {
          "required": true,
          "observed": false,
          "status": "fail",
          "source": "explicit_campaign_summary",
          "actionable_reason": "runtime actuation explicit status is fail; fix runtime evidence and rerun"
        }
      }
    }
  }
}
EOF_FAIL_CAMPAIGN_A

cat >"$FAIL_CAMPAIGN_B" <<'EOF_FAIL_CAMPAIGN_B'
{
  "version": 1,
  "status": "fail",
  "rc": 0,
  "decision": "NO-GO",
  "decision_diagnostics": {
    "m4_policy": {
      "gate_evaluation": {
        "runtime_actuation_status_pass": {
          "required": true,
          "observed": false,
          "status": "fail",
          "source": "explicit_selected_summaries_partial_fail",
          "actionable_reason": "runtime actuation selected summaries are failing; repair and rerun"
        }
      }
    }
  }
}
EOF_FAIL_CAMPAIGN_B

cat >"$MISSING_DIAGNOSTICS" <<'EOF_MISSING_DIAGNOSTICS'
{
  "version": 1,
  "status": "ok",
  "rc": 0,
  "decision": "GO",
  "decision_diagnostics": {
    "m4_policy": {
      "gate_evaluation": {}
    }
  }
}
EOF_MISSING_DIAGNOSTICS

echo "[runtime-actuation-promotion-check] strict happy path"
STRICT_SUMMARY="$TMP_DIR/runtime_actuation_promotion_strict.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-check-summary-json "$PASS_CAMPAIGN_A" \
  --campaign-check-summary-json "$PASS_CAMPAIGN_B" \
  --signoff-summary-json "$PASS_SIGNOFF" \
  --require-min-samples 3 \
  --require-min-pass-samples 3 \
  --require-max-fail-samples 0 \
  --require-max-warn-samples 0 \
  --require-min-ready-rate-pct 100 \
  --require-modal-runtime-actuation-status pass \
  --fail-on-no-go 1 \
  --summary-json "$STRICT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_check_strict.log 2>&1
strict_rc=$?
set -e

if [[ "$strict_rc" -ne 0 ]]; then
  echo "expected strict happy-path rc=0, got rc=$strict_rc"
  cat /tmp/integration_runtime_actuation_promotion_check_strict.log
  exit 1
fi
if ! jq -e '
  .schema.id == "runtime_actuation_promotion_check_summary"
  and .decision == "GO"
  and .status == "ok"
  and .rc == 0
  and .observed.samples_total == 3
  and .observed.samples_pass == 3
  and .observed.samples_fail == 0
  and .observed.runtime_actuation_ready_rate_pct >= 99.9
  and .observed.modal_runtime_actuation_status == "pass"
  and (.violations | length) == 0
  and .outcome.should_promote == true
  and .outcome.action == "promote_allowed"
' "$STRICT_SUMMARY" >/dev/null 2>&1; then
  echo "strict happy-path summary mismatch"
  cat "$STRICT_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-promotion-check] signoff duplicate reference is deduplicated in favor of campaign-check evidence"
DUPLICATE_REF_SUMMARY="$TMP_DIR/runtime_actuation_promotion_duplicate_ref.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-check-summary-json "$PASS_CAMPAIGN_A" \
  --signoff-summary-json "$SIGNOFF_UNKNOWN_DUPLICATE" \
  --require-min-samples 1 \
  --require-min-pass-samples 1 \
  --require-max-fail-samples 0 \
  --require-max-warn-samples 0 \
  --require-min-ready-rate-pct 100 \
  --require-modal-runtime-actuation-status pass \
  --fail-on-no-go 1 \
  --summary-json "$DUPLICATE_REF_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_check_duplicate_ref.log 2>&1
duplicate_ref_rc=$?
set -e

if [[ "$duplicate_ref_rc" -ne 0 ]]; then
  echo "expected duplicate-reference path rc=0, got rc=$duplicate_ref_rc"
  cat /tmp/integration_runtime_actuation_promotion_check_duplicate_ref.log
  exit 1
fi
if ! jq -e '
  .decision == "GO"
  and .status == "ok"
  and .rc == 0
  and .observed.samples_total == 1
  and .observed.samples_pass == 1
  and .observed.samples_fail == 0
  and .observed.runtime_actuation_ready_rate_pct >= 99.9
' "$DUPLICATE_REF_SUMMARY" >/dev/null 2>&1; then
  echo "duplicate-reference summary mismatch"
  cat "$DUPLICATE_REF_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-promotion-check] modal status requirement mismatch"
MODAL_MISMATCH_SUMMARY="$TMP_DIR/runtime_actuation_promotion_modal_mismatch.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-check-summary-json "$PASS_CAMPAIGN_A" \
  --campaign-check-summary-json "$FAIL_CAMPAIGN_A" \
  --campaign-check-summary-json "$FAIL_CAMPAIGN_B" \
  --require-min-samples 3 \
  --require-min-pass-samples 1 \
  --require-max-fail-samples 3 \
  --require-max-warn-samples 1 \
  --require-min-ready-rate-pct 0 \
  --require-modal-runtime-actuation-status pass \
  --fail-on-no-go 0 \
  --summary-json "$MODAL_MISMATCH_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_check_modal_mismatch.log 2>&1
modal_mismatch_rc=$?
set -e

if [[ "$modal_mismatch_rc" -ne 0 ]]; then
  echo "expected modal mismatch soft path rc=0, got rc=$modal_mismatch_rc"
  cat /tmp/integration_runtime_actuation_promotion_check_modal_mismatch.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc == 0
  and .enforcement.no_go_enforced == false
  and .diagnostics.no_go.primary_driver == "pass_sample_thresholds"
  and (.diagnostics.no_go.driver_codes | length) > 0
  and (.outcome.remediation.next_command | contains("runtime-actuation-promotion-cycle"))
  and .outcome.action == "hold_promotion_warn_only"
  and .observed.modal_runtime_actuation_status == "fail"
  and ((.violations | map(.code) | index("modal_runtime_actuation_status_mismatch")) != null)
' "$MODAL_MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "modal mismatch summary mismatch"
  cat "$MODAL_MISMATCH_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-promotion-check] missing diagnostics fails closed"
MISSING_DIAGNOSTICS_SUMMARY="$TMP_DIR/runtime_actuation_promotion_missing_diagnostics.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --campaign-check-summary-json "$MISSING_DIAGNOSTICS" \
  --require-min-samples 1 \
  --require-min-pass-samples 0 \
  --require-max-fail-samples 1 \
  --require-max-warn-samples 1 \
  --require-min-ready-rate-pct 0 \
  --fail-on-no-go 1 \
  --summary-json "$MISSING_DIAGNOSTICS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_check_missing_diagnostics.log 2>&1
missing_diag_rc=$?
set -e

if [[ "$missing_diag_rc" -eq 0 ]]; then
  echo "expected missing diagnostics path to fail closed with rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_check_missing_diagnostics.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc != 0
  and .enforcement.no_go_enforced == true
  and .diagnostics.no_go.primary_driver == "runtime_diagnostics_missing"
  and ((.violations | map(.code) | index("runtime_actuation_diagnostics_missing")) != null)
  and ((.violations | map(.code) | index("runtime_actuation_status_missing")) != null)
  and ((.violations | map(.code) | index("runtime_actuation_ready_missing")) != null)
' "$MISSING_DIAGNOSTICS_SUMMARY" >/dev/null 2>&1; then
  echo "missing diagnostics summary mismatch"
  cat "$MISSING_DIAGNOSTICS_SUMMARY"
  exit 1
fi

echo "[runtime-actuation-promotion-check] signoff context missing fails closed with actionable remediation"
MISSING_SIGNOFF_CONTEXT_SUMMARY="$TMP_DIR/runtime_actuation_promotion_missing_signoff_context.json"
set +e
bash "$SCRIPT_UNDER_TEST" \
  --signoff-summary-json "$SIGNOFF_MISSING_CONTEXT" \
  --require-min-samples 1 \
  --require-min-pass-samples 0 \
  --require-max-fail-samples 1 \
  --require-max-warn-samples 1 \
  --require-min-ready-rate-pct 0 \
  --fail-on-no-go 1 \
  --summary-json "$MISSING_SIGNOFF_CONTEXT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_check_missing_signoff_context.log 2>&1
missing_signoff_context_rc=$?
set -e

if [[ "$missing_signoff_context_rc" -eq 0 ]]; then
  echo "expected missing signoff context path to fail closed with rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_check_missing_signoff_context.log
  exit 1
fi
if ! jq -e '
  .decision == "NO-GO"
  and .status == "fail"
  and .rc != 0
  and .observed.signoff_context_missing_samples == 1
  and .diagnostics.no_go.primary_driver == "missing_signoff_context"
  and ((.violations | map(.code) | index("signoff_context_missing")) != null)
  and (.outcome.remediation.next_command | contains("runtime-actuation-promotion-cycle"))
' "$MISSING_SIGNOFF_CONTEXT_SUMMARY" >/dev/null 2>&1; then
  echo "missing signoff context summary mismatch"
  cat "$MISSING_SIGNOFF_CONTEXT_SUMMARY"
  exit 1
fi

echo "runtime actuation promotion check integration ok"
