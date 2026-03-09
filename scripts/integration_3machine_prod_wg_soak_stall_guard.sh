#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
FAKE_VALIDATE="$TMP_DIR/fake_prod_wg_validate.sh"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

run_expect_fail() {
  local out_file="$1"
  shift
  set +e
  THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_VALIDATE" ./scripts/integration_3machine_prod_wg_soak.sh "$@" >"$out_file" 2>&1
  local rc=$?
  set -e
  if [[ "$rc" -eq 0 ]]; then
    echo "expected soak command to fail but it succeeded"
    cat "$out_file"
    exit 1
  fi
}

run_expect_ok() {
  local out_file="$1"
  shift
  THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_VALIDATE" ./scripts/integration_3machine_prod_wg_soak.sh "$@" >"$out_file" 2>&1
}

# Case 1: validate succeeds but omits dataplane summary -> soak must fail.
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_MISSING'
#!/usr/bin/env bash
set -euo pipefail
report=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$report" ]]; then
  {
    echo "[3machine-prod-wg] success"
  } >>"$report"
fi
exit 0
EOF_FAKE_MISSING
chmod +x "$FAKE_VALIDATE"

OUT_MISSING="$TMP_DIR/out_missing_summary.log"
SUMMARY_MISSING="$TMP_DIR/soak_missing_summary.json"
run_expect_fail "$OUT_MISSING" --rounds 1 --pause-sec 0 --summary-json "$SUMMARY_MISSING" --report-file "$TMP_DIR/soak_missing_summary.log"
if ! rg -q 'missing dataplane summary marker' "$OUT_MISSING"; then
  echo "missing expected dataplane-summary failure signal"
  cat "$OUT_MISSING"
  exit 1
fi
if ! rg -q 'class=dataplane_summary_missing' "$OUT_MISSING"; then
  echo "missing expected failure class for dataplane summary missing"
  cat "$OUT_MISSING"
  exit 1
fi
if [[ ! -f "$SUMMARY_MISSING" ]]; then
  echo "missing expected summary json output for dataplane-summary failure case"
  cat "$OUT_MISSING"
  exit 1
fi
if ! rg -q '"status": "fail"' "$SUMMARY_MISSING" || ! rg -q '"dataplane_summary_missing": 1' "$SUMMARY_MISSING"; then
  echo "unexpected summary json payload for dataplane-summary failure case"
  cat "$SUMMARY_MISSING"
  exit 1
fi

# Case 2: validate succeeds with positive dataplane summary -> soak passes.
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_OK'
#!/usr/bin/env bash
set -euo pipefail
report=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$report" ]]; then
  {
    echo "[3machine-prod-wg] dataplane-summary handshake_epoch=1 rx_bytes=10 tx_bytes=20 exit_a_accepted_packets=11 exit_b_accepted_packets=12 accepted_delta_a=1 accepted_delta_b=2 accepted_delta_total=3"
    echo "[3machine-prod-wg] success"
  } >>"$report"
fi
exit 0
EOF_FAKE_OK
chmod +x "$FAKE_VALIDATE"

OUT_OK="$TMP_DIR/out_ok.log"
SUMMARY_OK="$TMP_DIR/soak_ok_summary.json"
run_expect_ok "$OUT_OK" --rounds 2 --pause-sec 0 --summary-json "$SUMMARY_OK" --report-file "$TMP_DIR/soak_ok.log"
if ! rg -q '\[3machine-prod-wg-soak\] summary passed=2 failed=0 total=2' "$OUT_OK"; then
  echo "missing expected successful soak summary"
  cat "$OUT_OK"
  exit 1
fi
if [[ ! -f "$SUMMARY_OK" ]]; then
  echo "missing expected summary json output for successful soak case"
  cat "$OUT_OK"
  exit 1
fi
if ! rg -q '"status": "ok"' "$SUMMARY_OK" || ! rg -q '"rounds_passed": 2' "$SUMMARY_OK"; then
  echo "unexpected summary json payload for successful soak case"
  cat "$SUMMARY_OK"
  exit 1
fi

# Case 3: continue-on-fail with sustained failures should stop at threshold.
CALLS_FILE="$TMP_DIR/fail_calls.count"
echo "0" >"$CALLS_FILE"
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_FAIL'
#!/usr/bin/env bash
set -euo pipefail
calls_file="${FAKE_VALIDATE_CALLS_FILE:?}"
count="$(cat "$calls_file")"
count=$((count + 1))
echo "$count" >"$calls_file"
exit 1
EOF_FAKE_FAIL
chmod +x "$FAKE_VALIDATE"

OUT_FAIL_STREAK="$TMP_DIR/out_fail_streak.log"
SUMMARY_FAIL_STREAK="$TMP_DIR/soak_fail_streak_summary.json"
set +e
FAKE_VALIDATE_CALLS_FILE="$CALLS_FILE" THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_VALIDATE" ./scripts/integration_3machine_prod_wg_soak.sh \
  --rounds 5 \
  --pause-sec 0 \
  --continue-on-fail 1 \
  --max-consecutive-failures 2 \
  --summary-json "$SUMMARY_FAIL_STREAK" \
  --report-file "$TMP_DIR/soak_fail_streak.log" >"$OUT_FAIL_STREAK" 2>&1
rc_fail_streak=$?
set -e
if [[ "$rc_fail_streak" -eq 0 ]]; then
  echo "expected sustained-failure soak run to fail"
  cat "$OUT_FAIL_STREAK"
  exit 1
fi
if ! rg -q 'sustained failure threshold reached' "$OUT_FAIL_STREAK"; then
  echo "missing expected sustained-failure threshold signal"
  cat "$OUT_FAIL_STREAK"
  exit 1
fi
if ! rg -q 'failure_class unknown=2' "$OUT_FAIL_STREAK"; then
  echo "missing expected failure-class summary for sustained failures"
  cat "$OUT_FAIL_STREAK"
  exit 1
fi
if [[ ! -f "$SUMMARY_FAIL_STREAK" ]]; then
  echo "missing expected summary json output for sustained failure case"
  cat "$OUT_FAIL_STREAK"
  exit 1
fi
if ! rg -q '"status": "fail"' "$SUMMARY_FAIL_STREAK" || ! rg -q '"unknown": 2' "$SUMMARY_FAIL_STREAK"; then
  echo "unexpected summary json payload for sustained failure case"
  cat "$SUMMARY_FAIL_STREAK"
  exit 1
fi
if [[ "$(cat "$CALLS_FILE")" != "2" ]]; then
  echo "expected soak to stop after 2 consecutive failures; observed calls=$(cat "$CALLS_FILE")"
  cat "$OUT_FAIL_STREAK"
  exit 1
fi

echo "3-machine prod wg soak stall guard integration check ok"
