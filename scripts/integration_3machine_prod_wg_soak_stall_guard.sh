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

# Case 4: failure class budget enforcement should stop when class exceeds limit.
CALLS_FILE_CLASS_LIMIT="$TMP_DIR/class_limit_calls.count"
echo "0" >"$CALLS_FILE_CLASS_LIMIT"
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_CLASS_LIMIT'
#!/usr/bin/env bash
set -euo pipefail
calls_file="${FAKE_VALIDATE_CALLS_FILE:?}"
count="$(cat "$calls_file")"
count=$((count + 1))
echo "$count" >"$calls_file"
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
  echo "timeout waiting for validation dependency" >>"$report"
fi
exit 1
EOF_FAKE_CLASS_LIMIT
chmod +x "$FAKE_VALIDATE"

OUT_CLASS_LIMIT="$TMP_DIR/out_class_limit.log"
SUMMARY_CLASS_LIMIT="$TMP_DIR/soak_class_limit_summary.json"
set +e
FAKE_VALIDATE_CALLS_FILE="$CALLS_FILE_CLASS_LIMIT" THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_VALIDATE" ./scripts/integration_3machine_prod_wg_soak.sh \
  --rounds 5 \
  --pause-sec 0 \
  --continue-on-fail 1 \
  --max-consecutive-failures 5 \
  --max-failure-class timeout=1 \
  --summary-json "$SUMMARY_CLASS_LIMIT" \
  --report-file "$TMP_DIR/soak_class_limit.log" >"$OUT_CLASS_LIMIT" 2>&1
rc_class_limit=$?
set -e
if [[ "$rc_class_limit" -eq 0 ]]; then
  echo "expected class-limit soak run to fail"
  cat "$OUT_CLASS_LIMIT"
  exit 1
fi
if ! rg -q 'failure class limit exceeded class=timeout observed=2 limit=1' "$OUT_CLASS_LIMIT"; then
  echo "missing expected failure-class limit breach signal"
  cat "$OUT_CLASS_LIMIT"
  exit 1
fi
if [[ "$(cat "$CALLS_FILE_CLASS_LIMIT")" != "2" ]]; then
  echo "expected class-limit enforcement to stop on 2nd timeout failure; observed calls=$(cat "$CALLS_FILE_CLASS_LIMIT")"
  cat "$OUT_CLASS_LIMIT"
  exit 1
fi
if ! rg -q '"failure_class_limits"' "$SUMMARY_CLASS_LIMIT" || ! rg -q '"timeout": 1' "$SUMMARY_CLASS_LIMIT"; then
  echo "summary json missing failure-class limits payload"
  cat "$SUMMARY_CLASS_LIMIT"
  exit 1
fi
if ! rg -q '"failure_class_limit_violations_total": 1' "$SUMMARY_CLASS_LIMIT"; then
  echo "summary json missing failure-class limit violation count"
  cat "$SUMMARY_CLASS_LIMIT"
  exit 1
fi

# Case 5: max round duration SLO should fail even when dataplane summary is present.
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_SLOW_OK'
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
sleep 2
if [[ -n "$report" ]]; then
  echo "[3machine-prod-wg] dataplane-summary handshake_epoch=1 rx_bytes=10 tx_bytes=20 exit_a_accepted_packets=11 exit_b_accepted_packets=12 accepted_delta_a=1 accepted_delta_b=2 accepted_delta_total=3" >>"$report"
fi
exit 0
EOF_FAKE_SLOW_OK
chmod +x "$FAKE_VALIDATE"

OUT_ROUND_SLO="$TMP_DIR/out_round_slo.log"
SUMMARY_ROUND_SLO="$TMP_DIR/soak_round_slo_summary.json"
run_expect_fail "$OUT_ROUND_SLO" \
  --rounds 1 \
  --pause-sec 0 \
  --max-round-duration-sec 1 \
  --summary-json "$SUMMARY_ROUND_SLO" \
  --report-file "$TMP_DIR/soak_round_slo.log"
if ! rg -q 'exceeded max round duration: observed=' "$OUT_ROUND_SLO"; then
  echo "missing expected max-round-duration SLO signal"
  cat "$OUT_ROUND_SLO"
  exit 1
fi
if ! rg -q 'class=round_duration_slo' "$OUT_ROUND_SLO"; then
  echo "missing expected round_duration_slo failure class"
  cat "$OUT_ROUND_SLO"
  exit 1
fi
if ! rg -q '"max_round_duration_limit_sec": 1' "$SUMMARY_ROUND_SLO"; then
  echo "summary json missing max_round_duration_limit_sec"
  cat "$SUMMARY_ROUND_SLO"
  exit 1
fi

# Case 6: recovery SLO should fail when recovery takes too long.
CALLS_FILE_RECOVERY="$TMP_DIR/recovery_calls.count"
echo "0" >"$CALLS_FILE_RECOVERY"
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_RECOVERY'
#!/usr/bin/env bash
set -euo pipefail
calls_file="${FAKE_VALIDATE_CALLS_FILE:?}"
count="$(cat "$calls_file")"
count=$((count + 1))
echo "$count" >"$calls_file"
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
if [[ "$count" -eq 1 ]]; then
  if [[ -n "$report" ]]; then
    echo "connection refused while waiting for endpoint" >>"$report"
  fi
  exit 1
fi
sleep 2
if [[ -n "$report" ]]; then
  echo "[3machine-prod-wg] dataplane-summary handshake_epoch=1 rx_bytes=10 tx_bytes=20 exit_a_accepted_packets=11 exit_b_accepted_packets=12 accepted_delta_a=1 accepted_delta_b=2 accepted_delta_total=3" >>"$report"
fi
exit 0
EOF_FAKE_RECOVERY
chmod +x "$FAKE_VALIDATE"

OUT_RECOVERY_SLO="$TMP_DIR/out_recovery_slo.log"
SUMMARY_RECOVERY_SLO="$TMP_DIR/soak_recovery_slo_summary.json"
set +e
FAKE_VALIDATE_CALLS_FILE="$CALLS_FILE_RECOVERY" THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_VALIDATE" ./scripts/integration_3machine_prod_wg_soak.sh \
  --rounds 2 \
  --pause-sec 0 \
  --continue-on-fail 1 \
  --max-consecutive-failures 5 \
  --max-recovery-sec 1 \
  --summary-json "$SUMMARY_RECOVERY_SLO" \
  --report-file "$TMP_DIR/soak_recovery_slo.log" >"$OUT_RECOVERY_SLO" 2>&1
rc_recovery_slo=$?
set -e
if [[ "$rc_recovery_slo" -eq 0 ]]; then
  echo "expected recovery-slo soak run to fail"
  cat "$OUT_RECOVERY_SLO"
  exit 1
fi
if ! rg -q 'recovery SLO exceeded: observed=' "$OUT_RECOVERY_SLO"; then
  echo "missing expected recovery SLO breach signal"
  cat "$OUT_RECOVERY_SLO"
  exit 1
fi
if ! rg -q 'class=recovery_slo' "$OUT_RECOVERY_SLO"; then
  echo "missing expected recovery_slo failure class"
  cat "$OUT_RECOVERY_SLO"
  exit 1
fi
if ! rg -q '"recovery_slo_violations": 1' "$SUMMARY_RECOVERY_SLO"; then
  echo "summary json missing recovery_slo_violations count"
  cat "$SUMMARY_RECOVERY_SLO"
  exit 1
fi

# Case 7: disallow unknown class should stop immediately.
CALLS_FILE_UNKNOWN="$TMP_DIR/unknown_calls.count"
echo "0" >"$CALLS_FILE_UNKNOWN"
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_UNKNOWN'
#!/usr/bin/env bash
set -euo pipefail
calls_file="${FAKE_VALIDATE_CALLS_FILE:?}"
count="$(cat "$calls_file")"
count=$((count + 1))
echo "$count" >"$calls_file"
exit 1
EOF_FAKE_UNKNOWN
chmod +x "$FAKE_VALIDATE"

OUT_UNKNOWN="$TMP_DIR/out_unknown.log"
SUMMARY_UNKNOWN="$TMP_DIR/soak_unknown_summary.json"
set +e
FAKE_VALIDATE_CALLS_FILE="$CALLS_FILE_UNKNOWN" THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_VALIDATE" ./scripts/integration_3machine_prod_wg_soak.sh \
  --rounds 5 \
  --pause-sec 0 \
  --continue-on-fail 1 \
  --max-consecutive-failures 5 \
  --disallow-unknown-failure-class 1 \
  --summary-json "$SUMMARY_UNKNOWN" \
  --report-file "$TMP_DIR/soak_unknown.log" >"$OUT_UNKNOWN" 2>&1
rc_unknown=$?
set -e
if [[ "$rc_unknown" -eq 0 ]]; then
  echo "expected disallow-unknown soak run to fail"
  cat "$OUT_UNKNOWN"
  exit 1
fi
if ! rg -q 'disallowed unknown failure class encountered' "$OUT_UNKNOWN"; then
  echo "missing expected disallow-unknown stop signal"
  cat "$OUT_UNKNOWN"
  exit 1
fi
if [[ "$(cat "$CALLS_FILE_UNKNOWN")" != "1" ]]; then
  echo "expected disallow-unknown enforcement to stop on first failure; observed calls=$(cat "$CALLS_FILE_UNKNOWN")"
  cat "$OUT_UNKNOWN"
  exit 1
fi
if ! rg -q '"disallow_unknown_failure_class": 1' "$SUMMARY_UNKNOWN"; then
  echo "summary json missing disallow_unknown_failure_class flag"
  cat "$SUMMARY_UNKNOWN"
  exit 1
fi

# Case 8: diversity thresholds should fail when selection spread is too narrow.
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_DIVERSITY'
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
    echo "2026/03/01 client selected entry=entry-op-a (http://a:8083) exit=exit-op-b (http://b:8084) entry_op=op-a exit_op=op-b token_exp=123"
    echo "[3machine-prod-wg] dataplane-summary handshake_epoch=1 rx_bytes=10 tx_bytes=20 exit_a_accepted_packets=11 exit_b_accepted_packets=12 accepted_delta_a=1 accepted_delta_b=2 accepted_delta_total=3"
    echo "[3machine-prod-wg] success"
  } >>"$report"
fi
exit 0
EOF_FAKE_DIVERSITY
chmod +x "$FAKE_VALIDATE"

OUT_DIVERSITY="$TMP_DIR/out_diversity.log"
SUMMARY_DIVERSITY="$TMP_DIR/soak_diversity_summary.json"
run_expect_fail "$OUT_DIVERSITY" \
  --rounds 2 \
  --pause-sec 0 \
  --min-selection-lines 4 \
  --min-entry-operators 2 \
  --min-exit-operators 2 \
  --min-cross-operator-pairs 2 \
  --summary-json "$SUMMARY_DIVERSITY" \
  --report-file "$TMP_DIR/soak_diversity.log"
if ! rg -q 'diversity threshold not met' "$OUT_DIVERSITY"; then
  echo "missing expected diversity threshold failure signal"
  cat "$OUT_DIVERSITY"
  exit 1
fi
if ! rg -q 'failure_class diversity_threshold=1' "$OUT_DIVERSITY"; then
  echo "missing expected diversity_threshold failure class summary"
  cat "$OUT_DIVERSITY"
  exit 1
fi
if ! rg -q '"selection_diversity_failed": 1' "$SUMMARY_DIVERSITY"; then
  echo "summary json missing selection_diversity_failed flag"
  cat "$SUMMARY_DIVERSITY"
  exit 1
fi
if ! rg -q '"selection_min_entry_operators": 2' "$SUMMARY_DIVERSITY"; then
  echo "summary json missing diversity threshold fields"
  cat "$SUMMARY_DIVERSITY"
  exit 1
fi

# Case 9: strict ingress policy failures should classify distinctly.
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_STRICT_INGRESS'
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
  echo "strict real-packet mode requires CLIENT_INNER_SOURCE=udp" >>"$report"
fi
exit 1
EOF_FAKE_STRICT_INGRESS
chmod +x "$FAKE_VALIDATE"

OUT_STRICT_INGRESS="$TMP_DIR/out_strict_ingress.log"
SUMMARY_STRICT_INGRESS="$TMP_DIR/soak_strict_ingress_summary.json"
run_expect_fail "$OUT_STRICT_INGRESS" \
  --rounds 1 \
  --pause-sec 0 \
  --summary-json "$SUMMARY_STRICT_INGRESS" \
  --report-file "$TMP_DIR/soak_strict_ingress.log"
if ! rg -q 'class=strict_ingress_policy' "$OUT_STRICT_INGRESS"; then
  echo "missing expected strict_ingress_policy failure class"
  cat "$OUT_STRICT_INGRESS"
  exit 1
fi
if ! rg -q '"strict_ingress_policy": 1' "$SUMMARY_STRICT_INGRESS"; then
  echo "summary json missing strict_ingress_policy class count"
  cat "$SUMMARY_STRICT_INGRESS"
  exit 1
fi

# Case 10: strict-ingress rehearsal flag should force synthetic inner-source on validate call.
STRICT_REHEARSAL_ARGS_FILE="$TMP_DIR/strict_rehearsal_args.log"
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_REHEARSAL_WIRING'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >"${STRICT_REHEARSAL_ARGS_FILE:?}"
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
  echo "strict real-packet mode requires CLIENT_INNER_SOURCE=udp" >>"$report"
fi
exit 1
EOF_FAKE_REHEARSAL_WIRING
chmod +x "$FAKE_VALIDATE"

OUT_REHEARSAL_WIRING="$TMP_DIR/out_rehearsal_wiring.log"
SUMMARY_REHEARSAL_WIRING="$TMP_DIR/soak_rehearsal_wiring_summary.json"
set +e
STRICT_REHEARSAL_ARGS_FILE="$STRICT_REHEARSAL_ARGS_FILE" THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_VALIDATE" ./scripts/integration_3machine_prod_wg_soak.sh \
  --rounds 1 \
  --pause-sec 0 \
  --strict-ingress-rehearsal 1 \
  --summary-json "$SUMMARY_REHEARSAL_WIRING" \
  --report-file "$TMP_DIR/soak_rehearsal_wiring.log" >"$OUT_REHEARSAL_WIRING" 2>&1
rc_rehearsal_wiring=$?
set -e
if [[ "$rc_rehearsal_wiring" -eq 0 ]]; then
  echo "expected strict-ingress rehearsal soak run to fail"
  cat "$OUT_REHEARSAL_WIRING"
  exit 1
fi
if [[ ! -f "$STRICT_REHEARSAL_ARGS_FILE" ]] || ! rg -q -- '--client-inner-source synthetic' "$STRICT_REHEARSAL_ARGS_FILE"; then
  echo "strict-ingress rehearsal did not forward --client-inner-source synthetic to validate script"
  [[ -f "$STRICT_REHEARSAL_ARGS_FILE" ]] && cat "$STRICT_REHEARSAL_ARGS_FILE"
  cat "$OUT_REHEARSAL_WIRING"
  exit 1
fi
if [[ ! -f "$STRICT_REHEARSAL_ARGS_FILE" ]] || ! rg -q -- '--allow-synthetic-ingress 1' "$STRICT_REHEARSAL_ARGS_FILE"; then
  echo "strict-ingress rehearsal did not forward --allow-synthetic-ingress 1 to validate script"
  [[ -f "$STRICT_REHEARSAL_ARGS_FILE" ]] && cat "$STRICT_REHEARSAL_ARGS_FILE"
  cat "$OUT_REHEARSAL_WIRING"
  exit 1
fi
if ! rg -q 'class=strict_ingress_policy' "$OUT_REHEARSAL_WIRING"; then
  echo "strict-ingress rehearsal missing strict_ingress_policy classification"
  cat "$OUT_REHEARSAL_WIRING"
  exit 1
fi

echo "3-machine prod wg soak stall guard integration check ok"
