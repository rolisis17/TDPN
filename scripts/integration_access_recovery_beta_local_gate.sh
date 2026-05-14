#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash chmod cmp jq mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access recovery beta local gate integration failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

test_path() {
  local path="${1:-}"
  if [[ -f "$path" ]]; then
    return 0
  fi
  if command -v cygpath >/dev/null 2>&1; then
    path="$(cygpath -u "$path" 2>/dev/null || printf '%s' "$path")"
    [[ -f "$path" ]]
    return
  fi
  return 1
}

PASS_STEP="$TMP_DIR/pass-step.sh"
FAIL_STEP="$TMP_DIR/fail-step.sh"
FAKE_GATE="$TMP_DIR/fake-easy-node-gate.sh"
FORWARDED_ARGS="$TMP_DIR/forwarded-args.txt"
EXPECTED_ARGS="$TMP_DIR/expected-args.txt"

cat >"$PASS_STEP" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
echo "fake step ok"
SCRIPT
cat >"$FAIL_STEP" <<'SCRIPT'
#!/usr/bin/env bash
set -euo pipefail
echo "fake step fail" >&2
exit 7
SCRIPT
cat >"$FAKE_GATE" <<SCRIPT
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "\$@" >"$FORWARDED_ARGS"
echo "fake access recovery gate ok"
SCRIPT
chmod +x "$PASS_STEP" "$FAIL_STEP" "$FAKE_GATE"

run_gate_with_overrides() {
  env \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_ALLOW_CUSTOM_STEP_SCRIPTS=1 \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_DEMO_CONTRACT_SCRIPT="$PASS_STEP" \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_EXAMPLES_CONTRACT_SCRIPT="$PASS_STEP" \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_BROWSER_SMOKE_SCRIPT="${1:-$PASS_STEP}" \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_BRIDGE_SERVICE_SERVE_SCRIPT="$PASS_STEP" \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_BRIDGE_DEPLOYMENT_EVIDENCE_SCRIPT="$PASS_STEP" \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_BRIDGE_HOST_INSTALL_SCRIPT="$PASS_STEP" \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$PASS_STEP" \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$PASS_STEP" \
    ACCESS_RECOVERY_BETA_LOCAL_GATE_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$PASS_STEP" \
    bash ./scripts/access_recovery_beta_local_gate.sh "${@:2}"
}

REFUSE_DIR="$TMP_DIR/refuse-reports"
REFUSE_SUMMARY="$REFUSE_DIR/summary.json"
set +e
env \
  ACCESS_RECOVERY_BETA_LOCAL_GATE_DEMO_CONTRACT_SCRIPT="$PASS_STEP" \
  ACCESS_RECOVERY_BETA_LOCAL_GATE_EXAMPLES_CONTRACT_SCRIPT="$PASS_STEP" \
  ACCESS_RECOVERY_BETA_LOCAL_GATE_BROWSER_SMOKE_SCRIPT="$PASS_STEP" \
  ACCESS_RECOVERY_BETA_LOCAL_GATE_BRIDGE_SERVICE_SERVE_SCRIPT="$PASS_STEP" \
  ACCESS_RECOVERY_BETA_LOCAL_GATE_BRIDGE_DEPLOYMENT_EVIDENCE_SCRIPT="$PASS_STEP" \
  ACCESS_RECOVERY_BETA_LOCAL_GATE_BRIDGE_HOST_INSTALL_SCRIPT="$PASS_STEP" \
  ACCESS_RECOVERY_BETA_LOCAL_GATE_PILOT_EVIDENCE_BUNDLE_SCRIPT="$PASS_STEP" \
  ACCESS_RECOVERY_BETA_LOCAL_GATE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT="$PASS_STEP" \
  ACCESS_RECOVERY_BETA_LOCAL_GATE_REAL_HELPER_EVIDENCE_RUN_SCRIPT="$PASS_STEP" \
  bash ./scripts/access_recovery_beta_local_gate.sh \
    --reports-dir "$REFUSE_DIR" \
    --summary-json "$REFUSE_SUMMARY" \
    --print-summary-json 0 >"$TMP_DIR/refuse.log" 2>&1
refuse_rc=$?
set -e

if [[ "$refuse_rc" -ne 1 ]]; then
  echo "access recovery beta local gate integration failed: custom step override should fail closed without explicit allow"
  cat "$TMP_DIR/refuse.log"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .security.custom_step_scripts_allowed == false
  and .summary.steps_total == 9
  and .summary.steps_pass == 0
  and .summary.steps_fail == 9
  and .summary.first_failed_step == "demo_contract"
  and ([.steps[].rc] | all(. == 2))
  and ([.steps[].status] | all(. == "fail"))
' "$REFUSE_SUMMARY" >/dev/null; then
  echo "access recovery beta local gate integration failed: custom override refusal summary mismatch"
  cat "$REFUSE_SUMMARY"
  exit 1
fi
first_refuse_log="$(jq -r '.steps[0].log' "$REFUSE_SUMMARY")"
if ! test_path "$first_refuse_log" || ! grep -F 'custom step script refused' "$first_refuse_log" >/dev/null 2>&1; then
  echo "access recovery beta local gate integration failed: custom override refusal log missing"
  cat "$first_refuse_log" 2>/dev/null || true
  exit 1
fi

PASS_DIR="$TMP_DIR/pass-reports"
PASS_SUMMARY="$PASS_DIR/summary.json"
PASS_REPORT="$PASS_DIR/report.md"
run_gate_with_overrides "$PASS_STEP" \
  --reports-dir "$PASS_DIR" \
  --summary-json "$PASS_SUMMARY" \
  --report-md "$PASS_REPORT" \
  --print-summary-json 1 >"$TMP_DIR/pass.log"

if ! jq -e '
  .schema.id == "access_recovery_beta_local_gate_summary"
  and .status == "pass"
  and .rc == 0
  and .security.custom_step_scripts_allowed == true
  and .summary.steps_total == 9
  and .summary.steps_pass == 9
  and .summary.steps_fail == 0
  and .summary.first_failed_step == null
  and .recommended_next_action.id == "real_helper_bridge_evidence"
  and (.recommended_next_action.reason | contains("trusted provenance") or contains("provenance") or contains("verifier receipt"))
  and ((.recommended_next_action.command // "") | test("access-recovery-real-helper-evidence-run"))
  and ((.recommended_next_action.command // "") | test("--provenance-private-key-file PROVENANCE_PRIVATE_KEY_FILE"))
  and ((.recommended_next_action.command // "") | test("--trust-store TRUST_STORE"))
  and ((.recommended_next_action.command // "") | test("--reports-dir .easy-node-logs/access-recovery-pilot"))
  and ([.steps[].id] == [
    "demo_contract",
    "examples_contract",
    "browser_smoke",
    "bridge_service_serve",
    "bridge_deployment_evidence",
    "bridge_host_install",
    "pilot_evidence_bundle",
    "pilot_evidence_bundle_verify",
    "real_helper_evidence_run"
  ])
  and ([.steps[].status] | all(. == "pass"))
' "$PASS_SUMMARY" >/dev/null; then
  echo "access recovery beta local gate integration failed: pass summary mismatch"
  cat "$PASS_SUMMARY"
  exit 1
fi

if [[ ! -f "$PASS_REPORT" ]] || ! grep -q "Access Recovery Beta Local Gate" "$PASS_REPORT"; then
  echo "access recovery beta local gate integration failed: pass report missing expected title"
  cat "$PASS_REPORT" 2>/dev/null || true
  exit 1
fi

while IFS= read -r step_log; do
  if ! test_path "$step_log"; then
    echo "access recovery beta local gate integration failed: missing step log $step_log"
    cat "$PASS_SUMMARY"
    exit 1
  fi
done < <(jq -r '.steps[].log' "$PASS_SUMMARY")

FAIL_DIR="$TMP_DIR/fail-reports"
FAIL_SUMMARY="$FAIL_DIR/summary.json"
set +e
run_gate_with_overrides "$FAIL_STEP" \
  --reports-dir "$FAIL_DIR" \
  --summary-json "$FAIL_SUMMARY" \
  --print-summary-json 0 >"$TMP_DIR/fail.log" 2>&1
fail_rc=$?
set -e

if [[ "$fail_rc" -ne 1 ]]; then
  echo "access recovery beta local gate integration failed: failing step should return rc=1"
  cat "$TMP_DIR/fail.log"
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .rc == 1
  and .security.custom_step_scripts_allowed == true
  and .summary.steps_total == 9
  and .summary.steps_pass == 8
  and .summary.steps_fail == 1
  and .summary.first_failed_step == "browser_smoke"
  and .recommended_next_action.id == "fix_access_recovery_local_gate"
  and (.steps[] | select(.id == "browser_smoke") | .status == "fail" and .rc == 7)
' "$FAIL_SUMMARY" >/dev/null; then
  echo "access recovery beta local gate integration failed: fail summary mismatch"
  cat "$FAIL_SUMMARY"
  exit 1
fi

printf '%s\n' "--sample" "ok" "--print-summary-json" "0" >"$EXPECTED_ARGS"
ACCESS_RECOVERY_BETA_LOCAL_GATE_SCRIPT="$FAKE_GATE" \
  bash ./scripts/easy_node.sh access-recovery-beta-local-gate --sample ok --print-summary-json 0 >"$TMP_DIR/easy-node.log"
if ! cmp -s "$EXPECTED_ARGS" "$FORWARDED_ARGS"; then
  echo "access recovery beta local gate integration failed: easy_node wrapper did not preserve args"
  echo "expected:"
  cat "$EXPECTED_ARGS"
  echo "actual:"
  cat "$FORWARDED_ARGS"
  exit 1
fi

echo "access recovery beta local gate integration check ok"
