#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq grep sed wc cat chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

GATE_SCRIPT="$ROOT_DIR/scripts/ci_phase5_settlement_layer.sh"
if [[ ! -x "$GATE_SCRIPT" ]]; then
  echo "missing executable script under test: $GATE_SCRIPT"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/stage_calls.tsv"
SUCCESS_LOG="$TMP_DIR/success.log"
DRY_RUN_LOG="$TMP_DIR/dry_run.log"
TOGGLE_LOG="$TMP_DIR/toggle.log"
FAIL_LOG="$TMP_DIR/fail.log"

SUCCESS_REPORTS_DIR="$TMP_DIR/reports_success"
DRY_RUN_REPORTS_DIR="$TMP_DIR/reports_dry_run"
TOGGLE_REPORTS_DIR="$TMP_DIR/reports_toggle"
FAIL_REPORTS_DIR="$TMP_DIR/reports_fail"

SUCCESS_SUMMARY_JSON="$TMP_DIR/summary_success.json"
DRY_RUN_SUMMARY_JSON="$TMP_DIR/summary_dry_run.json"
TOGGLE_SUMMARY_JSON="$TMP_DIR/summary_toggle.json"
FAIL_SUMMARY_JSON="$TMP_DIR/summary_fail.json"

STAGE_ENV_NAMES=(
  "CI_PHASE5_SETTLEMENT_LAYER_WINDOWS_SERVER_PACKAGING_SCRIPT"
  "CI_PHASE5_SETTLEMENT_LAYER_WINDOWS_ROLE_RUNBOOKS_SCRIPT"
  "CI_PHASE5_SETTLEMENT_LAYER_CROSS_PLATFORM_INTEROP_SCRIPT"
  "CI_PHASE5_SETTLEMENT_LAYER_ROLE_COMBINATION_VALIDATION_SCRIPT"
  "CI_PHASE5_SETTLEMENT_LAYER_SETTLEMENT_ADAPTER_ROUNDTRIP_SCRIPT"
  "CI_PHASE5_SETTLEMENT_LAYER_PHASE5_SETTLEMENT_LAYER_CHECK_SCRIPT"
  "CI_PHASE5_SETTLEMENT_LAYER_PHASE5_SETTLEMENT_LAYER_RUN_SCRIPT"
  "CI_PHASE5_SETTLEMENT_LAYER_PHASE5_SETTLEMENT_LAYER_HANDOFF_CHECK_SCRIPT"
  "CI_PHASE5_SETTLEMENT_LAYER_PHASE5_SETTLEMENT_LAYER_HANDOFF_RUN_SCRIPT"
)

STAGE_IDS=(
  "settlement_failsoft"
  "settlement_acceptance"
  "settlement_bridge_smoke"
  "settlement_state_persistence"
  "settlement_adapter_roundtrip"
  "phase5_settlement_layer_check"
  "phase5_settlement_layer_run"
  "phase5_settlement_layer_handoff_check"
  "phase5_settlement_layer_handoff_run"
)

TOGGLE_STAGE_IDS=(
  "settlement_bridge_smoke"
  "settlement_state_persistence"
)

FAKE_STAGE_HELPER="$TMP_DIR/fake_stage_helper.sh"
cat >"$FAKE_STAGE_HELPER" <<'EOF_FAKE_STAGE_HELPER'
#!/usr/bin/env bash
set -euo pipefail

capture="${CI_PHASE5_CAPTURE_FILE:?}"
stage_id="${CI_PHASE5_STAGE_ID:?}"

{
  printf '%s' "$stage_id"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"

fail_matrix="${CI_PHASE5_FAIL_MATRIX:-}"
if [[ -n "$fail_matrix" ]]; then
  old_ifs="$IFS"
  IFS=',;'
  read -r -a fail_specs <<<"$fail_matrix"
  IFS="$old_ifs"
  for spec in "${fail_specs[@]}"; do
    case "$spec" in
      "$stage_id"=*)
        rc="${spec#*=}"
        if [[ "$rc" =~ ^-?[0-9]+$ ]]; then
          exit "$rc"
        fi
        exit 1
        ;;
    esac
  done
fi

exit 0
EOF_FAKE_STAGE_HELPER
chmod +x "$FAKE_STAGE_HELPER"

for idx in "${!STAGE_ENV_NAMES[@]}"; do
  env_name="${STAGE_ENV_NAMES[$idx]}"
  stage_id="${STAGE_IDS[$idx]}"
  fake_stage="$TMP_DIR/fake_stage_${idx}.sh"
  cat >"$fake_stage" <<EOF_FAKE_STAGE
#!/usr/bin/env bash
set -euo pipefail
CI_PHASE5_CAPTURE_FILE="\${CI_PHASE5_CAPTURE_FILE:?}" \
CI_PHASE5_STAGE_ID="$stage_id" \
CI_PHASE5_FAIL_MATRIX="\${CI_PHASE5_FAIL_MATRIX:-}" \
"$FAKE_STAGE_HELPER" "\$@"
EOF_FAKE_STAGE
  chmod +x "$fake_stage"
  export "$env_name=$fake_stage"
done

assert_stage_order() {
  local capture_file="$1"
  shift
  local expected_ids=("$@")
  local count idx line actual expected

  count="$(wc -l <"$capture_file" | tr -d ' ')"
  if [[ "$count" -ne "${#expected_ids[@]}" ]]; then
    echo "unexpected stage invocation count: expected ${#expected_ids[@]}, got $count"
    cat "$capture_file"
    exit 1
  fi

  for idx in "${!expected_ids[@]}"; do
    expected="${expected_ids[$idx]}"
    line="$(sed -n "$((idx + 1))p" "$capture_file" || true)"
    if [[ -z "$line" ]]; then
      echo "missing stage invocation at index $idx"
      cat "$capture_file"
      exit 1
    fi
    actual="${line%%$'\t'*}"
    if [[ "$actual" != "$expected" ]]; then
      echo "stage order mismatch at index $idx: expected $expected, got $actual"
      cat "$capture_file"
      exit 1
    fi
  done
}

assert_capture_empty() {
  local capture_file="$1"
  if [[ -s "$capture_file" ]]; then
    echo "expected dry-run to skip all stage invocations"
    cat "$capture_file"
    exit 1
  fi
}

echo "[ci-phase5-settlement-layer] success ordering path"
: >"$CAPTURE"
CI_PHASE5_CAPTURE_FILE="$CAPTURE" \
"$GATE_SCRIPT" \
  --reports-dir "$SUCCESS_REPORTS_DIR" \
  --summary-json "$SUCCESS_SUMMARY_JSON" \
  --print-summary-json 0 >"$SUCCESS_LOG" 2>&1

assert_stage_order "$CAPTURE" "${STAGE_IDS[@]}"

if [[ ! -f "$SUCCESS_SUMMARY_JSON" ]]; then
  echo "missing success summary json: $SUCCESS_SUMMARY_JSON"
  cat "$SUCCESS_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .schema.id == "ci_phase5_settlement_layer_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .inputs.dry_run == false
  and .inputs.run_settlement_adapter_roundtrip == true
  and .inputs.run_phase5_settlement_layer_check == true
  and .inputs.run_phase5_settlement_layer_run == true
  and .inputs.run_phase5_settlement_layer_handoff_check == true
  and .inputs.run_phase5_settlement_layer_handoff_run == true
  and (.steps | to_entries | all(.value.enabled == true and .value.status == "pass" and .value.rc == 0 and .value.command != null))
  and .steps.settlement_adapter_roundtrip.status == "pass"
  and .steps.settlement_adapter_roundtrip.rc == 0
  and .steps.phase5_settlement_layer_check.status == "pass"
  and .steps.phase5_settlement_layer_check.rc == 0
  and .steps.phase5_settlement_layer_run.status == "pass"
  and .steps.phase5_settlement_layer_run.rc == 0
  and .steps.phase5_settlement_layer_handoff_check.status == "pass"
  and .steps.phase5_settlement_layer_handoff_check.rc == 0
  and .steps.phase5_settlement_layer_handoff_run.status == "pass"
  and .steps.phase5_settlement_layer_handoff_run.rc == 0
' "$SUCCESS_SUMMARY_JSON" >/dev/null; then
  echo "success summary missing expected contract fields"
  cat "$SUCCESS_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[ci-phase5-settlement-layer] status=pass rc=0 dry_run=0' "$SUCCESS_LOG"; then
  echo "success log missing final pass status line"
  cat "$SUCCESS_LOG"
  exit 1
fi

echo "[ci-phase5-settlement-layer] dry-run skip accounting"
: >"$CAPTURE"
CI_PHASE5_CAPTURE_FILE="$CAPTURE" \
"$GATE_SCRIPT" \
  --dry-run 1 \
  --reports-dir "$DRY_RUN_REPORTS_DIR" \
  --summary-json "$DRY_RUN_SUMMARY_JSON" \
  --print-summary-json 0 >"$DRY_RUN_LOG" 2>&1

assert_capture_empty "$CAPTURE"

if [[ ! -f "$DRY_RUN_SUMMARY_JSON" ]]; then
  echo "missing dry-run summary json: $DRY_RUN_SUMMARY_JSON"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.dry_run == true
  and .steps.settlement_adapter_roundtrip.status == "skip"
  and .steps.settlement_adapter_roundtrip.reason == "dry-run"
  and .steps.phase5_settlement_layer_check.status == "skip"
  and .steps.phase5_settlement_layer_check.reason == "dry-run"
  and .steps.phase5_settlement_layer_run.status == "skip"
  and .steps.phase5_settlement_layer_run.reason == "dry-run"
  and .steps.phase5_settlement_layer_handoff_check.status == "skip"
  and .steps.phase5_settlement_layer_handoff_check.reason == "dry-run"
  and .steps.phase5_settlement_layer_handoff_run.status == "skip"
  and .steps.phase5_settlement_layer_handoff_run.reason == "dry-run"
  and (.steps | to_entries | all(.value.enabled == true and .value.status == "skip" and .value.rc == 0 and .value.reason == "dry-run"))
' "$DRY_RUN_SUMMARY_JSON" >/dev/null; then
  echo "dry-run summary missing expected skip accounting"
  cat "$DRY_RUN_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[ci-phase5-settlement-layer] status=pass rc=0 dry_run=1' "$DRY_RUN_LOG"; then
  echo "dry-run log missing final pass status line"
  cat "$DRY_RUN_LOG"
  exit 1
fi
if ! grep -Fq -- 'step=settlement_failsoft status=skip reason=dry-run' "$DRY_RUN_LOG"; then
  echo "dry-run log missing settlement_failsoft skip signal"
  cat "$DRY_RUN_LOG"
  exit 1
fi

echo "[ci-phase5-settlement-layer] toggle path"
: >"$CAPTURE"
CI_PHASE5_CAPTURE_FILE="$CAPTURE" \
"$GATE_SCRIPT" \
  --reports-dir "$TOGGLE_REPORTS_DIR" \
  --summary-json "$TOGGLE_SUMMARY_JSON" \
  --print-summary-json 0 \
  --run-settlement-failsoft 0 \
  --run-settlement-acceptance 0 \
  --run-settlement-adapter-roundtrip 0 \
  --run-phase5-settlement-layer-check 0 \
  --run-phase5-settlement-layer-run 0 \
  --run-phase5-settlement-layer-handoff-check 0 \
  --run-phase5-settlement-layer-handoff-run 0 >"$TOGGLE_LOG" 2>&1

assert_stage_order "$CAPTURE" "${TOGGLE_STAGE_IDS[@]}"

if [[ ! -f "$TOGGLE_SUMMARY_JSON" ]]; then
  echo "missing toggle summary json: $TOGGLE_SUMMARY_JSON"
  cat "$TOGGLE_LOG"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.run_settlement_failsoft == false
  and .steps.settlement_failsoft.enabled == false
  and .steps.settlement_failsoft.status == "skip"
  and .steps.settlement_failsoft.reason == "disabled"
  and .inputs.run_settlement_adapter_roundtrip == false
  and .steps.settlement_adapter_roundtrip.enabled == false
  and .steps.settlement_adapter_roundtrip.status == "skip"
  and .steps.settlement_adapter_roundtrip.reason == "disabled"
  and .steps.settlement_bridge_smoke.enabled == true
  and .steps.settlement_bridge_smoke.status == "pass"
  and .inputs.run_phase5_settlement_layer_check == false
  and .inputs.run_phase5_settlement_layer_run == false
  and .inputs.run_phase5_settlement_layer_handoff_check == false
  and .inputs.run_phase5_settlement_layer_handoff_run == false
  and .steps.phase5_settlement_layer_check.enabled == false
  and .steps.phase5_settlement_layer_check.status == "skip"
  and .steps.phase5_settlement_layer_check.reason == "disabled"
  and .steps.phase5_settlement_layer_run.enabled == false
  and .steps.phase5_settlement_layer_run.status == "skip"
  and .steps.phase5_settlement_layer_run.reason == "disabled"
  and .steps.phase5_settlement_layer_handoff_check.enabled == false
  and .steps.phase5_settlement_layer_handoff_check.status == "skip"
  and .steps.phase5_settlement_layer_handoff_check.reason == "disabled"
  and .steps.phase5_settlement_layer_handoff_run.enabled == false
  and .steps.phase5_settlement_layer_handoff_run.status == "skip"
  and .steps.phase5_settlement_layer_handoff_run.reason == "disabled"
' "$TOGGLE_SUMMARY_JSON" >/dev/null; then
  echo "toggle summary missing expected disabled/enabled fields"
  cat "$TOGGLE_SUMMARY_JSON"
  exit 1
fi

echo "[ci-phase5-settlement-layer] first-failure rc propagation"
: >"$CAPTURE"
set +e
CI_PHASE5_CAPTURE_FILE="$CAPTURE" \
CI_PHASE5_FAIL_MATRIX="settlement_acceptance=23,settlement_bridge_smoke=41,settlement_adapter_roundtrip=43,phase5_settlement_layer_check=47,phase5_settlement_layer_run=53,phase5_settlement_layer_handoff_check=55,phase5_settlement_layer_handoff_run=59" \
"$GATE_SCRIPT" \
  --reports-dir "$FAIL_REPORTS_DIR" \
  --summary-json "$FAIL_SUMMARY_JSON" \
  --print-summary-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e

if [[ "$fail_rc" -ne 23 ]]; then
  echo "expected fail rc=23, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi

assert_stage_order "$CAPTURE" "${STAGE_IDS[@]}"

if [[ ! -f "$FAIL_SUMMARY_JSON" ]]; then
  echo "missing fail summary json: $FAIL_SUMMARY_JSON"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 23
  and .inputs.dry_run == false
  and .steps.settlement_acceptance.status == "fail"
  and .steps.settlement_acceptance.rc == 23
  and .steps.settlement_bridge_smoke.status == "fail"
  and .steps.settlement_bridge_smoke.rc == 41
  and .steps.settlement_adapter_roundtrip.status == "fail"
  and .steps.settlement_adapter_roundtrip.rc == 43
  and .steps.phase5_settlement_layer_check.status == "fail"
  and .steps.phase5_settlement_layer_check.rc == 47
  and .steps.phase5_settlement_layer_run.status == "fail"
  and .steps.phase5_settlement_layer_run.rc == 53
  and .steps.phase5_settlement_layer_handoff_check.status == "fail"
  and .steps.phase5_settlement_layer_handoff_check.rc == 55
  and .steps.phase5_settlement_layer_handoff_run.status == "fail"
  and .steps.phase5_settlement_layer_handoff_run.rc == 59
  and .steps.settlement_state_persistence.status == "pass"
' "$FAIL_SUMMARY_JSON" >/dev/null; then
  echo "fail summary missing expected first-failure accounting"
  cat "$FAIL_SUMMARY_JSON"
  exit 1
fi
if ! grep -Fq -- '[ci-phase5-settlement-layer] status=fail rc=23 dry_run=0' "$FAIL_LOG"; then
  echo "fail log missing final fail status line"
  cat "$FAIL_LOG"
  exit 1
fi

echo "ci phase5 settlement layer integration check ok"
