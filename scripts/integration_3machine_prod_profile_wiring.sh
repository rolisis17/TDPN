#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg awk sed; do
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

cat >"$TMP_BIN/curl" <<'EOF_CURL'
#!/usr/bin/env bash
set -euo pipefail
url="${@: -1}"
case "$url" in
  *"/v1/relays")
    printf '{"relays":[{"relay_id":"entry-op-a","role":"entry","operator_id":"op-a"},{"relay_id":"exit-op-a","role":"exit","operator_id":"op-a"},{"relay_id":"entry-op-b","role":"entry","operator_id":"op-b"},{"relay_id":"exit-op-b","role":"exit","operator_id":"op-b"}]}\n'
    ;;
  *"issuer-a"*"/v1/pubkeys")
    printf '{"issuer":"issuer-a","pub_keys":["issuer-a-key"]}\n'
    ;;
  *"issuer-b"*"/v1/pubkeys")
    printf '{"issuer":"issuer-b","pub_keys":["issuer-b-key"]}\n'
    ;;
  *"/v1/pubkeys")
    printf '{"issuer":"issuer-main","pub_keys":["issuer-main-key"]}\n'
    ;;
  *"/v1/health"|*"/v1/peers"|*"/v1/metrics")
    printf '{}\n'
    ;;
  *)
    printf '{}\n'
    ;;
esac
EOF_CURL

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "image" && "${2:-}" == "inspect" ]]; then
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER

cat >"$TMP_BIN/timeout" <<'EOF_TIMEOUT'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -lt 2 ]]; then
  exit 2
fi
# Ignore timeout wrappers in wiring tests and run wrapped command directly.
shift
exec "$@"
EOF_TIMEOUT

chmod +x "$TMP_BIN/curl" "$TMP_BIN/docker" "$TMP_BIN/timeout"

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
VALIDATE_CAPTURE="$TMP_DIR/validate_easy_node_args.log"
cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${VALIDATE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_EASY
chmod +x "$FAKE_EASY_NODE"

echo "[wiring] validate -> easy_node prod-profile forwarding"
PATH="$TMP_BIN:$PATH" \
VALIDATE_CAPTURE_FILE="$VALIDATE_CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/integration_3machine_beta_validate.sh \
  --directory-a http://dir-a:8081 \
  --directory-b http://dir-b:8081 \
  --issuer-url http://issuer-main:8082 \
  --issuer-a-url http://issuer-a:8082 \
  --issuer-b-url http://issuer-b:8082 \
  --entry-url http://entry-main:8083 \
  --exit-url http://exit-main:8084 \
  --min-sources 1 \
  --min-operators 2 \
  --federation-timeout-sec 3 \
  --timeout-sec 5 \
  --client-min-selection-lines 1 \
  --client-min-entry-operators 1 \
  --client-min-exit-operators 1 \
  --client-require-cross-operator-pair 0 \
  --distinct-operators 1 \
  --require-issuer-quorum 1 \
  --beta-profile 0 \
  --prod-profile 1 >/tmp/integration_3machine_prod_profile_wiring_validate.log 2>&1

if ! rg -q -- 'client-test' "$VALIDATE_CAPTURE"; then
  echo "validate wiring failed: client-test command was not invoked"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--prod-profile 1' "$VALIDATE_CAPTURE"; then
  echo "validate wiring failed: --prod-profile 1 was not forwarded to easy_node client-test"
  cat "$VALIDATE_CAPTURE"
  exit 1
fi

FAKE_VALIDATE="$TMP_DIR/fake_validate.sh"
SOAK_CAPTURE="$TMP_DIR/soak_validate_args.log"
cat >"$FAKE_VALIDATE" <<'EOF_FAKE_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SOAK_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_VALIDATE
chmod +x "$FAKE_VALIDATE"

echo "[wiring] soak -> validate prod-profile forwarding"
PATH="$TMP_BIN:$PATH" \
SOAK_CAPTURE_FILE="$SOAK_CAPTURE" \
THREE_MACHINE_VALIDATE_SCRIPT="$FAKE_VALIDATE" \
./scripts/integration_3machine_beta_soak.sh \
  --directory-a http://dir-a:8081 \
  --directory-b http://dir-b:8081 \
  --issuer-url http://issuer-main:8082 \
  --entry-url http://entry-main:8083 \
  --exit-url http://exit-main:8084 \
  --rounds 1 \
  --pause-sec 0 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 1 \
  --timeout-sec 5 \
  --client-min-selection-lines 1 \
  --client-min-entry-operators 1 \
  --client-min-exit-operators 1 \
  --client-require-cross-operator-pair 0 \
  --distinct-operators 1 \
  --require-issuer-quorum 1 \
  --beta-profile 0 \
  --prod-profile 1 >/tmp/integration_3machine_prod_profile_wiring_soak.log 2>&1

if ! rg -q -- '--prod-profile 1' "$SOAK_CAPTURE"; then
  echo "soak wiring failed: --prod-profile 1 was not forwarded to validate script"
  cat "$SOAK_CAPTURE"
  exit 1
fi

FAKE_RUNBOOK_VALIDATE="$TMP_DIR/fake_runbook_validate.sh"
FAKE_RUNBOOK_SOAK="$TMP_DIR/fake_runbook_soak.sh"
RUNBOOK_VALIDATE_CAPTURE="$TMP_DIR/runbook_validate_args.log"
RUNBOOK_SOAK_CAPTURE="$TMP_DIR/runbook_soak_args.log"

cat >"$FAKE_RUNBOOK_VALIDATE" <<'EOF_FAKE_R_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${RUNBOOK_VALIDATE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_R_VALIDATE

cat >"$FAKE_RUNBOOK_SOAK" <<'EOF_FAKE_R_SOAK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${RUNBOOK_SOAK_CAPTURE_FILE:?}"
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
  printf '[fake-soak] ok\n' >>"$report"
fi
exit 0
EOF_FAKE_R_SOAK

chmod +x "$FAKE_RUNBOOK_VALIDATE" "$FAKE_RUNBOOK_SOAK"

RUNBOOK_BUNDLE="$TMP_DIR/pilot_bundle"
echo "[wiring] runbook -> validate/soak prod-profile forwarding"
PATH="$TMP_BIN:$PATH" \
RUNBOOK_VALIDATE_CAPTURE_FILE="$RUNBOOK_VALIDATE_CAPTURE" \
RUNBOOK_SOAK_CAPTURE_FILE="$RUNBOOK_SOAK_CAPTURE" \
THREE_MACHINE_VALIDATE_SCRIPT="$FAKE_RUNBOOK_VALIDATE" \
THREE_MACHINE_SOAK_SCRIPT="$FAKE_RUNBOOK_SOAK" \
./scripts/beta_pilot_runbook.sh \
  --directory-a http://dir-a:8081 \
  --directory-b http://dir-b:8081 \
  --issuer-url http://issuer-main:8082 \
  --issuer-a-url http://issuer-a:8082 \
  --issuer-b-url http://issuer-b:8082 \
  --entry-url http://entry-main:8083 \
  --exit-url http://exit-main:8084 \
  --rounds 1 \
  --pause-sec 0 \
  --min-sources 1 \
  --min-operators 1 \
  --federation-timeout-sec 1 \
  --timeout-sec 5 \
  --client-min-selection-lines 1 \
  --client-min-entry-operators 1 \
  --client-min-exit-operators 1 \
  --client-require-cross-operator-pair 0 \
  --distinct-operators 1 \
  --require-issuer-quorum 1 \
  --beta-profile 0 \
  --prod-profile 1 \
  --bundle-dir "$RUNBOOK_BUNDLE" >/tmp/integration_3machine_prod_profile_wiring_runbook.log 2>&1

if ! rg -q -- '--prod-profile 1' "$RUNBOOK_VALIDATE_CAPTURE"; then
  echo "runbook wiring failed: --prod-profile 1 missing from validate invocation"
  cat "$RUNBOOK_VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--prod-profile 1' "$RUNBOOK_SOAK_CAPTURE"; then
  echo "runbook wiring failed: --prod-profile 1 missing from soak invocation"
  cat "$RUNBOOK_SOAK_CAPTURE"
  exit 1
fi

FAKE_GATE="$TMP_DIR/fake_prod_gate.sh"
GATE_CAPTURE="$TMP_DIR/prod_gate_args.log"
cat >"$FAKE_GATE" <<'EOF_FAKE_GATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_GATE
chmod +x "$FAKE_GATE"

echo "[wiring] easy_node -> prod gate forwarding"
PATH="$TMP_BIN:$PATH" \
GATE_CAPTURE_FILE="$GATE_CAPTURE" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_GATE" \
./scripts/easy_node.sh three-machine-prod-gate \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --wg-slo-profile strict \
  --control-fault-every 2 \
  --control-fault-command test-control-fault \
  --control-continue-on-fail 1 \
  --wg-fault-every 3 \
  --wg-fault-command test-wg-fault \
  --wg-continue-on-fail 1 \
  --wg-max-round-duration-sec 90 \
  --wg-max-recovery-sec 120 \
  --wg-max-failure-class endpoint_connectivity=2 \
  --wg-disallow-unknown-failure-class 1 \
  --wg-strict-ingress-rehearsal 1 \
  --wg-min-selection-lines 12 \
  --wg-min-entry-operators 2 \
  --wg-min-exit-operators 2 \
  --wg-min-cross-operator-pairs 3 \
  --strict-distinct 1 \
  --wg-max-consecutive-failures 3 \
  --wg-validate-summary-json /tmp/prod_gate_wg_validate_summary.json \
  --wg-soak-summary-json /tmp/prod_gate_wg_soak_summary.json \
  --gate-summary-json /tmp/prod_gate_summary.json \
  --control-soak-rounds 2 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_gate.log 2>&1

if ! rg -q -- '--strict-distinct 1' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --strict-distinct 1 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--skip-wg 1' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --skip-wg 1 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-max-consecutive-failures 3' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-max-consecutive-failures 3 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-soak-summary-json /tmp/prod_gate_wg_soak_summary.json' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-soak-summary-json missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-validate-summary-json /tmp/prod_gate_wg_validate_summary.json' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-validate-summary-json missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--control-fault-every 2' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --control-fault-every 2 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--control-fault-command test-control-fault' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --control-fault-command missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-fault-every 3' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-fault-every 3 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-fault-command test-wg-fault' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-fault-command missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-slo-profile strict' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-slo-profile strict missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-max-round-duration-sec 90' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-max-round-duration-sec 90 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-max-recovery-sec 120' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-max-recovery-sec 120 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-max-failure-class endpoint_connectivity=2' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-max-failure-class endpoint_connectivity=2 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-disallow-unknown-failure-class 1' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-disallow-unknown-failure-class 1 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-strict-ingress-rehearsal 1' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-strict-ingress-rehearsal 1 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-min-selection-lines 12' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-min-selection-lines 12 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-min-entry-operators 2' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-min-entry-operators 2 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-min-exit-operators 2' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-min-exit-operators 2 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-min-cross-operator-pairs 3' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --wg-min-cross-operator-pairs 3 missing"
  cat "$GATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--gate-summary-json /tmp/prod_gate_summary.json' "$GATE_CAPTURE"; then
  echo "easy_node prod gate wiring failed: --gate-summary-json missing"
  cat "$GATE_CAPTURE"
  exit 1
fi

echo "[wiring] easy_node reminder command output"
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-reminder | rg -q 'True 3-machine production reminder checklist'; then
  echo "easy_node reminder command missing expected checklist heading"
  exit 1
fi

echo "[wiring] easy_node client-vpn-preflight help dispatch"
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh client-vpn-preflight --help | rg -q 'client-vpn-preflight'; then
  echo "easy_node client-vpn-preflight command help dispatch failed"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh client-vpn-preflight --help | rg -q -- '--operator-floor-check'; then
  echo "easy_node client-vpn-preflight help missing --operator-floor-check"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh client-vpn-preflight --help | rg -q -- '--issuer-quorum-check'; then
  echo "easy_node client-vpn-preflight help missing --issuer-quorum-check"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-wg-soak --help | rg -q -- '--max-consecutive-failures'; then
  echo "easy_node prod-wg-soak help missing --max-consecutive-failures"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-wg-soak --help | rg -q -- '--summary-json'; then
  echo "easy_node prod-wg-soak help missing --summary-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-wg-validate --help | rg -q -- '--client-inner-source'; then
  echo "easy_node prod-wg-validate help missing --client-inner-source"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh prod-wg-soak --help | rg -q -- '--strict-ingress-rehearsal'; then
  echo "easy_node prod-wg-soak help missing --strict-ingress-rehearsal"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-max-round-duration-sec'; then
  echo "easy_node three-machine-prod-gate help missing --wg-max-round-duration-sec"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-max-failure-class'; then
  echo "easy_node three-machine-prod-gate help missing --wg-max-failure-class"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-strict-ingress-rehearsal'; then
  echo "easy_node three-machine-prod-gate help missing --wg-strict-ingress-rehearsal"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-slo-profile'; then
  echo "easy_node three-machine-prod-gate help missing --wg-slo-profile"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-validate-summary-json'; then
  echo "easy_node three-machine-prod-gate help missing --wg-validate-summary-json"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh three-machine-prod-gate --help | rg -q -- '--wg-min-selection-lines'; then
  echo "easy_node three-machine-prod-gate help missing --wg-min-selection-lines"
  exit 1
fi
if ! PATH="$TMP_BIN:$PATH" ./scripts/easy_node.sh --help | rg -q -- 'prod-wg-strict-ingress-rehearsal'; then
  echo "easy_node usage missing prod-wg-strict-ingress-rehearsal command"
  exit 1
fi

echo "[wiring] easy_node strict-ingress rehearsal preset"
FAKE_EASY_REHEARSAL_SOAK="$TMP_DIR/fake_easy_rehearsal_soak.sh"
EASY_REHEARSAL_CAPTURE="$TMP_DIR/easy_rehearsal_soak_args.log"
cat >"$FAKE_EASY_REHEARSAL_SOAK" <<'EOF_FAKE_EASY_REHEARSAL_SOAK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${EASY_REHEARSAL_CAPTURE_FILE:?}"
report_file=""
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report_file="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$report_file" ]]; then
  mkdir -p "$(dirname "$report_file")"
  cat >"$report_file" <<'EOF_REHEARSAL_REPORT'
[3machine-prod-wg-soak] round=1 result=fail rc=1 class=strict_ingress_policy duration_sec=1
[3machine-prod-wg-soak] failure_class strict_ingress_policy=1
EOF_REHEARSAL_REPORT
fi
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_REHEARSAL_SUMMARY'
{
  "status": "fail",
  "rounds_requested": 1,
  "rounds_passed": 0,
  "rounds_failed": 1,
  "failure_classes": {
    "strict_ingress_policy": 1
  }
}
EOF_REHEARSAL_SUMMARY
fi
exit 1
EOF_FAKE_EASY_REHEARSAL_SOAK
chmod +x "$FAKE_EASY_REHEARSAL_SOAK"

EASY_REHEARSAL_LOG="/tmp/integration_3machine_prod_profile_wiring_easy_rehearsal.log"
set +e
PATH="$TMP_BIN:$PATH" \
EASY_REHEARSAL_CAPTURE_FILE="$EASY_REHEARSAL_CAPTURE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_EASY_REHEARSAL_SOAK" \
./scripts/easy_node.sh prod-wg-strict-ingress-rehearsal \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 >"$EASY_REHEARSAL_LOG" 2>&1
easy_rehearsal_rc=$?
set -e
if [[ "$easy_rehearsal_rc" -ne 0 ]]; then
  echo "easy_node strict-ingress rehearsal preset failed"
  cat "$EASY_REHEARSAL_LOG"
  exit 1
fi
if ! rg -q -- '--strict-ingress-rehearsal 1' "$EASY_REHEARSAL_CAPTURE"; then
  echo "easy_node strict-ingress rehearsal preset missing --strict-ingress-rehearsal 1"
  cat "$EASY_REHEARSAL_CAPTURE"
  cat "$EASY_REHEARSAL_LOG"
  exit 1
fi
if ! rg -q -- '--max-failure-class strict_ingress_policy=0' "$EASY_REHEARSAL_CAPTURE"; then
  echo "easy_node strict-ingress rehearsal preset missing strict_ingress_policy budget"
  cat "$EASY_REHEARSAL_CAPTURE"
  cat "$EASY_REHEARSAL_LOG"
  exit 1
fi
if ! rg -q 'prod wg strict-ingress rehearsal check ok' "$EASY_REHEARSAL_LOG"; then
  echo "easy_node strict-ingress rehearsal preset missing success marker"
  cat "$EASY_REHEARSAL_LOG"
  exit 1
fi

FAKE_GATE_VALIDATE="$TMP_DIR/fake_gate_validate.sh"
FAKE_GATE_SOAK="$TMP_DIR/fake_gate_soak.sh"
FAKE_GATE_WG_VALIDATE="$TMP_DIR/fake_gate_wg_validate.sh"
FAKE_GATE_WG_SOAK="$TMP_DIR/fake_gate_wg_soak.sh"
GATE_VALIDATE_CAPTURE="$TMP_DIR/gate_validate_args.log"
GATE_SOAK_CAPTURE="$TMP_DIR/gate_soak_args.log"
GATE_WG_VALIDATE_CAPTURE="$TMP_DIR/gate_wg_validate_args.log"
GATE_WG_SOAK_CAPTURE="$TMP_DIR/gate_wg_soak_args.log"

cat >"$FAKE_GATE_VALIDATE" <<'EOF_FAKE_GATE_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_VALIDATE_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_GATE_VALIDATE

cat >"$FAKE_GATE_SOAK" <<'EOF_FAKE_GATE_SOAK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_SOAK_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_GATE_SOAK

cat >"$FAKE_GATE_WG_VALIDATE" <<'EOF_FAKE_GATE_WG_VALIDATE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_WG_VALIDATE_CAPTURE_FILE:?}"
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_VALIDATE_SUMMARY'
{
  "status": "ok",
  "failed_step": ""
}
EOF_VALIDATE_SUMMARY
fi
exit 0
EOF_FAKE_GATE_WG_VALIDATE

cat >"$FAKE_GATE_WG_SOAK" <<'EOF_FAKE_GATE_WG_SOAK'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${GATE_WG_SOAK_CAPTURE_FILE:?}"
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_SUMMARY'
{
  "status": "fail",
  "rounds_requested": 3,
  "rounds_passed": 1,
  "rounds_failed": 2,
  "max_consecutive_failures_seen": 2,
  "max_consecutive_failures_limit": 2,
  "report_file": "/tmp/fake.log",
  "summary_generated_at_utc": "2026-03-09T00:00:00Z",
  "failure_classes": {
    "endpoint_connectivity": 2,
    "timeout": 1
  }
}
EOF_SUMMARY
fi
exit 0
EOF_FAKE_GATE_WG_SOAK

chmod +x "$FAKE_GATE_VALIDATE" "$FAKE_GATE_SOAK" "$FAKE_GATE_WG_VALIDATE" "$FAKE_GATE_WG_SOAK"

echo "[wiring] prod gate script control-step forwarding"
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK" \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --control-fault-every 2 \
  --control-fault-command test-control-fault \
  --control-continue-on-fail 1 \
  --control-soak-rounds 2 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_prod_gate.log 2>&1

if ! rg -q -- '--prod-profile 1' "$GATE_VALIDATE_CAPTURE"; then
  echo "prod gate wiring failed: validate call missing --prod-profile 1"
  cat "$GATE_VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--require-issuer-quorum 1' "$GATE_VALIDATE_CAPTURE"; then
  echo "prod gate wiring failed: validate call missing --require-issuer-quorum 1"
  cat "$GATE_VALIDATE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--rounds 2' "$GATE_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: soak call missing --rounds 2"
  cat "$GATE_SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fault-every 2' "$GATE_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: control soak call missing --fault-every 2"
  cat "$GATE_SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--fault-command test-control-fault' "$GATE_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: control soak call missing --fault-command test-control-fault"
  cat "$GATE_SOAK_CAPTURE"
  exit 1
fi
if ! rg -q -- '--continue-on-fail 1' "$GATE_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: control soak call missing --continue-on-fail 1"
  cat "$GATE_SOAK_CAPTURE"
  exit 1
fi
if [[ -s "$GATE_WG_VALIDATE_CAPTURE" || -s "$GATE_WG_SOAK_CAPTURE" ]]; then
  echo "prod gate wiring failed: WG scripts should not run when --skip-wg 1"
  cat "$GATE_WG_VALIDATE_CAPTURE" "$GATE_WG_SOAK_CAPTURE"
  exit 1
fi

: >"$GATE_WG_VALIDATE_CAPTURE"
: >"$GATE_WG_SOAK_CAPTURE"

echo "[wiring] prod gate script wg-step summary output"
WG_SUMMARY_FILE="$TMP_DIR/prod_gate_wg_summary.json"
GATE_SUMMARY_FILE="$TMP_DIR/prod_gate_summary.json"
WG_GATE_LOG="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg.log"
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-fault-every 4 \
  --wg-fault-command test-wg-fault \
  --wg-continue-on-fail 1 \
  --wg-max-round-duration-sec 90 \
  --wg-max-recovery-sec 120 \
  --wg-max-failure-class endpoint_connectivity=2 \
  --wg-disallow-unknown-failure-class 1 \
  --wg-strict-ingress-rehearsal 1 \
  --wg-min-selection-lines 6 \
  --wg-min-entry-operators 2 \
  --wg-min-exit-operators 2 \
  --wg-min-cross-operator-pairs 2 \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_FILE" >"$WG_GATE_LOG" 2>&1

if [[ ! -s "$GATE_WG_VALIDATE_CAPTURE" || ! -s "$GATE_WG_SOAK_CAPTURE" ]]; then
  echo "prod gate wiring failed: WG scripts should run when --skip-wg 0"
  cat "$GATE_WG_VALIDATE_CAPTURE" "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--summary-json' "$GATE_WG_VALIDATE_CAPTURE"; then
  echo "prod gate wiring failed: WG validate call missing --summary-json forwarding"
  cat "$GATE_WG_VALIDATE_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--summary-json' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --summary-json forwarding"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--fault-every 4' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --fault-every 4"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--fault-command test-wg-fault' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --fault-command test-wg-fault"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--continue-on-fail 1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --continue-on-fail 1"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--max-round-duration-sec 90' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --max-round-duration-sec 90"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--max-recovery-sec 120' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --max-recovery-sec 120"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--max-failure-class endpoint_connectivity=2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --max-failure-class endpoint_connectivity=2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--disallow-unknown-failure-class 1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --disallow-unknown-failure-class 1"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--strict-ingress-rehearsal 1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --strict-ingress-rehearsal 1"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--min-selection-lines 6' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --min-selection-lines 6"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--min-entry-operators 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --min-entry-operators 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--min-exit-operators 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --min-exit-operators 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q -- '--min-cross-operator-pairs 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: WG soak call missing --min-cross-operator-pairs 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG"
  exit 1
fi

echo "[wiring] prod gate script wg slo profile defaults"
: >"$GATE_WG_VALIDATE_CAPTURE"
: >"$GATE_WG_SOAK_CAPTURE"
WG_GATE_LOG_PROFILE="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg_profile.log"
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-slo-profile recommended \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_FILE" >"$WG_GATE_LOG_PROFILE" 2>&1
if ! rg -q -- '--max-round-duration-sec 180' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --max-round-duration-sec 180"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-recovery-sec 240' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --max-recovery-sec 240"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-failure-class endpoint_connectivity=2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing endpoint_connectivity budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-failure-class timeout=2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing timeout budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-failure-class wg_dataplane_stall=1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing wg_dataplane_stall budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--max-failure-class strict_ingress_policy=0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing strict_ingress_policy budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--disallow-unknown-failure-class 1' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing disallow-unknown flag"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--min-selection-lines 0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --min-selection-lines 0"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--min-entry-operators 0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --min-entry-operators 0"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--min-exit-operators 0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --min-exit-operators 0"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi
if ! rg -q -- '--min-cross-operator-pairs 0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile recommended missing --min-cross-operator-pairs 0"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE"
  exit 1
fi

echo "[wiring] prod gate script wg slo strict diversity defaults"
: >"$GATE_WG_VALIDATE_CAPTURE"
: >"$GATE_WG_SOAK_CAPTURE"
WG_GATE_LOG_PROFILE_STRICT="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg_profile_strict.log"
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-slo-profile strict \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_FILE" >"$WG_GATE_LOG_PROFILE_STRICT" 2>&1
if ! rg -q -- '--min-selection-lines 8' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing --min-selection-lines 8"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q -- '--min-entry-operators 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing --min-entry-operators 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q -- '--min-exit-operators 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing --min-exit-operators 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q -- '--min-cross-operator-pairs 2' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing --min-cross-operator-pairs 2"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q -- '--max-failure-class strict_ingress_policy=0' "$GATE_WG_SOAK_CAPTURE"; then
  echo "prod gate wiring failed: wg-slo-profile strict missing strict_ingress_policy budget"
  cat "$GATE_WG_SOAK_CAPTURE"
  cat "$WG_GATE_LOG_PROFILE_STRICT"
  exit 1
fi
if ! rg -q '\[prod-gate\] wg_soak_summary status=fail .* top_failure_class=endpoint_connectivity top_failure_count=2 ' "$WG_GATE_LOG"; then
  echo "prod gate wiring failed: compact WG soak summary output missing/incorrect"
  cat "$WG_GATE_LOG"
  exit 1
fi
if [[ ! -f "$GATE_SUMMARY_FILE" ]]; then
  echo "prod gate wiring failed: gate summary json missing on successful run"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"status": "ok"' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary status missing/incorrect on successful run"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"wg_soak_status": "fail"' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary missing embedded WG status"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"wg_validate_summary_json": "' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary missing WG validate summary path field"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"wg_validate_status": "ok"' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary missing WG validate status"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi
if ! rg -q '"prod_wg_soak": "ok"' "$GATE_SUMMARY_FILE"; then
  echo "prod gate wiring failed: gate summary missing per-step status for prod_wg_soak"
  cat "$GATE_SUMMARY_FILE"
  cat "$WG_GATE_LOG"
  exit 1
fi

echo "[wiring] prod gate script summary on failure path"
FAKE_GATE_WG_SOAK_FAIL="$TMP_DIR/fake_gate_wg_soak_fail.sh"
cat >"$FAKE_GATE_WG_SOAK_FAIL" <<'EOF_FAKE_GATE_WG_SOAK_FAIL'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_SUMMARY_FAIL'
{
  "status": "fail",
  "rounds_requested": 2,
  "rounds_passed": 0,
  "rounds_failed": 2,
  "max_consecutive_failures_seen": 2,
  "max_consecutive_failures_limit": 2,
  "report_file": "/tmp/fake_fail.log",
  "summary_generated_at_utc": "2026-03-09T00:00:01Z",
  "failure_classes": {
    "timeout": 2
  }
}
EOF_SUMMARY_FAIL
fi
exit 1
EOF_FAKE_GATE_WG_SOAK_FAIL
chmod +x "$FAKE_GATE_WG_SOAK_FAIL"

GATE_SUMMARY_FAIL_FILE="$TMP_DIR/prod_gate_summary_fail.json"
WG_GATE_FAIL_LOG="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg_fail.log"
set +e
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK_FAIL" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_FAIL_FILE" >"$WG_GATE_FAIL_LOG" 2>&1
gate_fail_rc=$?
set -e
if [[ "$gate_fail_rc" -eq 0 ]]; then
  echo "prod gate wiring failed: expected non-zero rc on failing WG soak path"
  cat "$WG_GATE_FAIL_LOG"
  exit 1
fi
if [[ ! -f "$GATE_SUMMARY_FAIL_FILE" ]]; then
  echo "prod gate wiring failed: missing gate summary json on failing path"
  cat "$WG_GATE_FAIL_LOG"
  exit 1
fi
if ! rg -q '"status": "fail"' "$GATE_SUMMARY_FAIL_FILE" || ! rg -q '"failed_step": "prod_wg_soak"' "$GATE_SUMMARY_FAIL_FILE"; then
  echo "prod gate wiring failed: failure summary missing status/failed_step"
  cat "$GATE_SUMMARY_FAIL_FILE"
  cat "$WG_GATE_FAIL_LOG"
  exit 1
fi
if ! rg -q '\[prod-gate\] wg_soak_summary status=fail .* top_failure_class=timeout top_failure_count=2 ' "$WG_GATE_FAIL_LOG"; then
  echo "prod gate wiring failed: compact WG summary missing on failing path"
  cat "$WG_GATE_FAIL_LOG"
  exit 1
fi

echo "[wiring] prod gate script strict-ingress summary path"
FAKE_GATE_WG_SOAK_STRICT="$TMP_DIR/fake_gate_wg_soak_strict.sh"
cat >"$FAKE_GATE_WG_SOAK_STRICT" <<'EOF_FAKE_GATE_WG_SOAK_STRICT'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  cat >"$summary_json" <<'EOF_SUMMARY_STRICT'
{
  "status": "fail",
  "rounds_requested": 3,
  "rounds_passed": 0,
  "rounds_failed": 3,
  "max_consecutive_failures_seen": 3,
  "max_consecutive_failures_limit": 3,
  "report_file": "/tmp/fake_strict.log",
  "summary_generated_at_utc": "2026-03-10T00:00:00Z",
  "failure_classes": {
    "strict_ingress_policy": 3,
    "timeout": 1
  }
}
EOF_SUMMARY_STRICT
fi
exit 1
EOF_FAKE_GATE_WG_SOAK_STRICT
chmod +x "$FAKE_GATE_WG_SOAK_STRICT"

GATE_SUMMARY_STRICT_FILE="$TMP_DIR/prod_gate_summary_strict_ingress.json"
WG_GATE_STRICT_LOG="/tmp/integration_3machine_prod_profile_wiring_prod_gate_wg_strict_ingress.log"
set +e
PATH="$TMP_BIN:$PATH" \
GATE_VALIDATE_CAPTURE_FILE="$GATE_VALIDATE_CAPTURE" \
GATE_SOAK_CAPTURE_FILE="$GATE_SOAK_CAPTURE" \
GATE_WG_VALIDATE_CAPTURE_FILE="$GATE_WG_VALIDATE_CAPTURE" \
GATE_WG_SOAK_CAPTURE_FILE="$GATE_WG_SOAK_CAPTURE" \
THREE_MACHINE_BETA_VALIDATE_SCRIPT="$FAKE_GATE_VALIDATE" \
THREE_MACHINE_BETA_SOAK_SCRIPT="$FAKE_GATE_SOAK" \
THREE_MACHINE_PROD_WG_VALIDATE_SCRIPT="$FAKE_GATE_WG_VALIDATE" \
THREE_MACHINE_PROD_WG_SOAK_SCRIPT="$FAKE_GATE_WG_SOAK_STRICT" \
THREE_MACHINE_PROD_GATE_ALLOW_NON_ROOT=1 \
./scripts/integration_3machine_prod_gate.sh \
  --directory-a https://dir-a:8081 \
  --directory-b https://dir-b:8081 \
  --issuer-url https://issuer-main:8082 \
  --entry-url https://entry-main:8083 \
  --exit-url https://exit-main:8084 \
  --skip-control-soak 1 \
  --wg-soak-rounds 1 \
  --wg-soak-pause-sec 0 \
  --wg-soak-summary-json "$WG_SUMMARY_FILE" \
  --gate-summary-json "$GATE_SUMMARY_STRICT_FILE" >"$WG_GATE_STRICT_LOG" 2>&1
gate_strict_rc=$?
set -e
if [[ "$gate_strict_rc" -eq 0 ]]; then
  echo "prod gate wiring failed: expected non-zero rc on strict-ingress WG soak path"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi
if [[ ! -f "$GATE_SUMMARY_STRICT_FILE" ]]; then
  echo "prod gate wiring failed: missing gate summary json on strict-ingress path"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi
if ! rg -q '\[prod-gate\] wg_soak_summary status=fail .* top_failure_class=strict_ingress_policy top_failure_count=3 ' "$WG_GATE_STRICT_LOG"; then
  echo "prod gate wiring failed: strict-ingress compact WG summary missing/incorrect"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi
if ! rg -q '"wg_soak_top_failure_class": "strict_ingress_policy"' "$GATE_SUMMARY_STRICT_FILE"; then
  echo "prod gate wiring failed: strict-ingress gate summary missing top failure class"
  cat "$GATE_SUMMARY_STRICT_FILE"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi
if ! rg -q '"wg_soak_top_failure_count": 3' "$GATE_SUMMARY_STRICT_FILE"; then
  echo "prod gate wiring failed: strict-ingress gate summary missing top failure count"
  cat "$GATE_SUMMARY_STRICT_FILE"
  cat "$WG_GATE_STRICT_LOG"
  exit 1
fi

FAKE_BUNDLE_GATE="$TMP_DIR/fake_bundle_gate.sh"
BUNDLE_CAPTURE="$TMP_DIR/prod_bundle_gate_args.log"
BUNDLE_SOURCE_STEP_LOGS="$TMP_DIR/fake_bundle_step_logs_src"
cat >"$FAKE_BUNDLE_GATE" <<'EOF_FAKE_BUNDLE_GATE'
#!/usr/bin/env bash
set -euo pipefail

printf '%s\n' "$*" >>"${BUNDLE_CAPTURE_FILE:?}"

report_file=""
wg_validate_summary=""
wg_summary=""
gate_summary=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report_file="${2:-}"
      shift 2
      ;;
    --wg-validate-summary-json)
      wg_validate_summary="${2:-}"
      shift 2
      ;;
    --wg-soak-summary-json)
      wg_summary="${2:-}"
      shift 2
      ;;
    --gate-summary-json)
      gate_summary="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

mkdir -p "${BUNDLE_SOURCE_STEP_LOGS_DIR:?}"
printf 'step log marker\n' >"${BUNDLE_SOURCE_STEP_LOGS_DIR}/marker.log"

if [[ -n "$report_file" ]]; then
  mkdir -p "$(dirname "$report_file")"
  {
    printf '[prod-gate] fake gate running\n'
    printf '[prod-gate] step_logs: %s\n' "${BUNDLE_SOURCE_STEP_LOGS_DIR}"
  } >"$report_file"
fi
if [[ -n "$wg_validate_summary" ]]; then
  mkdir -p "$(dirname "$wg_validate_summary")"
  cat >"$wg_validate_summary" <<'EOF_WG_VALIDATE_SUMMARY'
{
  "status": "ok",
  "failed_step": ""
}
EOF_WG_VALIDATE_SUMMARY
fi
if [[ -n "$wg_summary" ]]; then
  mkdir -p "$(dirname "$wg_summary")"
  cat >"$wg_summary" <<'EOF_WG_SUMMARY'
{
  "status": "ok",
  "rounds_requested": 1,
  "rounds_passed": 1,
  "rounds_failed": 0
}
EOF_WG_SUMMARY
fi
if [[ -n "$gate_summary" ]]; then
  mkdir -p "$(dirname "$gate_summary")"
  cat >"$gate_summary" <<EOF_GATE_SUMMARY
{
  "status": "ok",
  "failed_step": "",
  "step_logs": "${BUNDLE_SOURCE_STEP_LOGS_DIR}"
}
EOF_GATE_SUMMARY
fi

exit "${FAKE_BUNDLE_GATE_RC:-0}"
EOF_FAKE_BUNDLE_GATE
chmod +x "$FAKE_BUNDLE_GATE"

echo "[wiring] prod gate bundle script success path"
BUNDLE_DIR_OK="$TMP_DIR/prod_gate_bundle_ok"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/prod_gate_bundle.sh \
  --bundle-dir "$BUNDLE_DIR_OK" \
  --strict-distinct 1 \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_bundle_ok.log 2>&1
bundle_ok_rc=$?
set -e
if [[ "$bundle_ok_rc" -ne 0 ]]; then
  echo "prod gate bundle wiring failed: expected success rc=0"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if [[ ! -f "${BUNDLE_DIR_OK}.tar.gz" ]]; then
  echo "prod gate bundle wiring failed: bundle tarball missing on success"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if [[ ! -f "$BUNDLE_DIR_OK/step_logs/marker.log" ]]; then
  echo "prod gate bundle wiring failed: copied step logs missing"
  find "$BUNDLE_DIR_OK" -maxdepth 3 -type f -print || true
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if [[ ! -f "$BUNDLE_DIR_OK/prod_wg_validate_summary.json" ]]; then
  echo "prod gate bundle wiring failed: WG validate summary missing in bundle dir"
  find "$BUNDLE_DIR_OK" -maxdepth 2 -type f -print || true
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_ok.log
  exit 1
fi
if ! rg -q -- '--strict-distinct 1' "$BUNDLE_CAPTURE"; then
  echo "prod gate bundle wiring failed: forwarded gate args missing"
  cat "$BUNDLE_CAPTURE"
  exit 1
fi
if ! rg -q -- '--wg-validate-summary-json' "$BUNDLE_CAPTURE"; then
  echo "prod gate bundle wiring failed: missing --wg-validate-summary-json forwarding"
  cat "$BUNDLE_CAPTURE"
  exit 1
fi
if ! rg -q 'gate_rc=0' "$BUNDLE_DIR_OK/metadata.txt"; then
  echo "prod gate bundle wiring failed: metadata missing gate_rc=0"
  cat "$BUNDLE_DIR_OK/metadata.txt"
  exit 1
fi
if ! rg -q 'wg_validate_summary_json=' "$BUNDLE_DIR_OK/metadata.txt"; then
  echo "prod gate bundle wiring failed: metadata missing wg_validate_summary_json entry"
  cat "$BUNDLE_DIR_OK/metadata.txt"
  exit 1
fi

echo "[wiring] prod gate bundle script failure path"
BUNDLE_DIR_FAIL="$TMP_DIR/prod_gate_bundle_fail"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
FAKE_BUNDLE_GATE_RC=17 \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/prod_gate_bundle.sh \
  --bundle-dir "$BUNDLE_DIR_FAIL" \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_bundle_fail.log 2>&1
bundle_fail_rc=$?
set -e
if [[ "$bundle_fail_rc" -ne 17 ]]; then
  echo "prod gate bundle wiring failed: expected rc=17 on failing path (got $bundle_fail_rc)"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_fail.log
  exit 1
fi
if [[ ! -f "${BUNDLE_DIR_FAIL}.tar.gz" ]]; then
  echo "prod gate bundle wiring failed: bundle tarball missing on failure"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_bundle_fail.log
  exit 1
fi
if ! rg -q 'gate_rc=17' "$BUNDLE_DIR_FAIL/metadata.txt"; then
  echo "prod gate bundle wiring failed: metadata missing gate_rc=17"
  cat "$BUNDLE_DIR_FAIL/metadata.txt"
  exit 1
fi

echo "[wiring] easy_node -> prod bundle dispatch"
EASY_BUNDLE_DIR="$TMP_DIR/easy_node_prod_bundle"
set +e
PATH="$TMP_BIN:$PATH" \
BUNDLE_CAPTURE_FILE="$BUNDLE_CAPTURE" \
BUNDLE_SOURCE_STEP_LOGS_DIR="$BUNDLE_SOURCE_STEP_LOGS" \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="./scripts/prod_gate_bundle.sh" \
THREE_MACHINE_PROD_GATE_SCRIPT="$FAKE_BUNDLE_GATE" \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$EASY_BUNDLE_DIR" \
  --skip-wg 1 >/tmp/integration_3machine_prod_profile_wiring_easy_bundle.log 2>&1
easy_bundle_rc=$?
set -e
if [[ "$easy_bundle_rc" -ne 0 ]]; then
  echo "easy_node prod bundle wiring failed: non-zero rc"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle.log
  exit 1
fi
if [[ ! -f "${EASY_BUNDLE_DIR}.tar.gz" ]]; then
  echo "easy_node prod bundle wiring failed: expected tarball missing"
  ls -la "$TMP_DIR"
  cat /tmp/integration_3machine_prod_profile_wiring_easy_bundle.log
  exit 1
fi

echo "3-machine prod-profile wiring integration check ok"
