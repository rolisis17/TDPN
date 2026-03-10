#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

PASS_WG_VALIDATE="$TMP_DIR/wg_validate_ok.json"
PASS_WG_SOAK="$TMP_DIR/wg_soak_ok.json"
PASS_GATE="$TMP_DIR/prod_gate_ok.json"

cat >"$PASS_WG_VALIDATE" <<'EOF_WG_VALIDATE_OK'
{
  "status": "ok",
  "failed_step": ""
}
EOF_WG_VALIDATE_OK

cat >"$PASS_WG_SOAK" <<'EOF_WG_SOAK_OK'
{
  "status": "ok",
  "rounds_failed": 0,
  "failure_classes": {}
}
EOF_WG_SOAK_OK

cat >"$PASS_GATE" <<EOF_GATE_OK
{
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  },
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "ok",
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_GATE_OK

echo "[prod-gate-check] pass baseline"
./scripts/prod_gate_check.sh --gate-summary-json "$PASS_GATE" --show-json 0 >/tmp/integration_prod_gate_check_pass.log 2>&1

echo "[prod-gate-check] fail on gate status"
FAIL_GATE_STATUS="$TMP_DIR/prod_gate_fail_status.json"
cat >"$FAIL_GATE_STATUS" <<EOF_GATE_FAIL_STATUS
{
  "status": "fail",
  "failed_step": "prod_wg_soak",
  "failed_rc": 1,
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "failed"
  },
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "fail",
  "wg_soak_rounds_failed": 2,
  "wg_soak_top_failure_class": "timeout",
  "wg_soak_top_failure_count": 2
}
EOF_GATE_FAIL_STATUS
set +e
./scripts/prod_gate_check.sh --gate-summary-json "$FAIL_GATE_STATUS" >/tmp/integration_prod_gate_check_fail_status.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc for failing gate status"
  cat /tmp/integration_prod_gate_check_fail_status.log
  exit 1
fi
if ! rg -q 'gate status is not ok' /tmp/integration_prod_gate_check_fail_status.log; then
  echo "expected gate-status failure message not found"
  cat /tmp/integration_prod_gate_check_fail_status.log
  exit 1
fi

echo "[prod-gate-check] full-sequence override"
SKIP_GATE="$TMP_DIR/prod_gate_skip_control_soak.json"
cat >"$SKIP_GATE" <<EOF_GATE_SKIP
{
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
  "steps": {
    "control_validate": "ok",
    "control_soak": "skipped",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  },
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "ok",
  "wg_soak_rounds_failed": 0,
  "wg_soak_top_failure_class": "none",
  "wg_soak_top_failure_count": 0
}
EOF_GATE_SKIP
set +e
./scripts/prod_gate_check.sh --gate-summary-json "$SKIP_GATE" --require-full-sequence 1 >/tmp/integration_prod_gate_check_skip_strict.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc when full sequence is required and a step is skipped"
  cat /tmp/integration_prod_gate_check_skip_strict.log
  exit 1
fi
./scripts/prod_gate_check.sh --gate-summary-json "$SKIP_GATE" --require-full-sequence 0 >/tmp/integration_prod_gate_check_skip_relaxed.log 2>&1

echo "[prod-gate-check] soak failed-round budget"
SOAK_FAILED_GATE="$TMP_DIR/prod_gate_soak_failed_rounds.json"
cat >"$SOAK_FAILED_GATE" <<EOF_GATE_SOAK_FAILED
{
  "status": "ok",
  "failed_step": "",
  "failed_rc": 0,
  "steps": {
    "control_validate": "ok",
    "control_soak": "ok",
    "prod_wg_validate": "ok",
    "prod_wg_soak": "ok"
  },
  "wg_validate_summary_json": "$PASS_WG_VALIDATE",
  "wg_validate_status": "ok",
  "wg_validate_failed_step": "",
  "wg_soak_summary_json": "$PASS_WG_SOAK",
  "wg_soak_status": "ok",
  "wg_soak_rounds_failed": 2,
  "wg_soak_top_failure_class": "timeout",
  "wg_soak_top_failure_count": 2
}
EOF_GATE_SOAK_FAILED
set +e
./scripts/prod_gate_check.sh --gate-summary-json "$SOAK_FAILED_GATE" --max-wg-soak-failed-rounds 1 >/tmp/integration_prod_gate_check_soak_budget.log 2>&1
rc=$?
set -e
if [[ "$rc" -eq 0 ]]; then
  echo "expected non-zero rc when wg_soak_rounds_failed exceeds budget"
  cat /tmp/integration_prod_gate_check_soak_budget.log
  exit 1
fi
if ! rg -q 'wg_soak_rounds_failed exceeds limit' /tmp/integration_prod_gate_check_soak_budget.log; then
  echo "expected soak budget failure message not found"
  cat /tmp/integration_prod_gate_check_soak_budget.log
  exit 1
fi
./scripts/prod_gate_check.sh --gate-summary-json "$SOAK_FAILED_GATE" --max-wg-soak-failed-rounds 2 >/tmp/integration_prod_gate_check_soak_budget_ok.log 2>&1

echo "[prod-gate-check] easy_node forwarding"
FAKE_CHECK="$TMP_DIR/fake_prod_gate_check.sh"
CAPTURE="$TMP_DIR/easy_node_prod_gate_check_args.log"
cat >"$FAKE_CHECK" <<'EOF_FAKE_CHECK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"
exit 0
EOF_FAKE_CHECK
chmod +x "$FAKE_CHECK"

CAPTURE_FILE="$CAPTURE" \
THREE_MACHINE_PROD_GATE_CHECK_SCRIPT="$FAKE_CHECK" \
./scripts/easy_node.sh prod-gate-check \
  --bundle-dir /tmp/prod_bundle \
  --max-wg-soak-failed-rounds 1 \
  --show-json 1 >/tmp/integration_prod_gate_check_easy_node.log 2>&1

if ! rg -q -- '--bundle-dir /tmp/prod_bundle' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --bundle-dir"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--max-wg-soak-failed-rounds 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --max-wg-soak-failed-rounds"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-json 1' "$CAPTURE"; then
  echo "easy_node prod-gate-check forwarding failed: missing --show-json"
  cat "$CAPTURE"
  exit 1
fi

echo "prod gate check integration ok"
