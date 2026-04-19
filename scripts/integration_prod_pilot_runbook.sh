#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp rg; do
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

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
CAPTURE="$TMP_DIR/prod_pilot_args.log"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${CAPTURE_FILE:?}"

mode="${FAKE_MODE:-pass}"
cmd="${1:-}"

summary_json_path() {
  local prev=""
  local arg=""
  for arg in "$@"; do
    if [[ "$prev" == "--summary-json" ]]; then
      printf '%s\n' "$arg"
      return 0
    fi
    prev="$arg"
  done
  printf '%s\n' ""
}

write_summary_json_if_requested() {
  local payload="$1"
  shift
  local path
  path="$(summary_json_path "$@")"
  if [[ -n "$path" ]]; then
    mkdir -p "$(dirname "$path")"
    printf '%s\n' "$payload" >"$path"
  fi
}

case "$cmd" in
  pre-real-host-readiness)
    if [[ "$mode" == "root-deferred" ]]; then
      summary_payload='{
  "version": 1,
  "status": "fail",
  "stage": "wg_only_stack_selftest",
  "notes": "WG-only stack selftest deferred: requires root privileges",
  "wg_only_stack_selftest": {
    "status": "skip",
    "notes": "WG-only stack selftest deferred: requires root privileges"
  },
  "machine_c_smoke_gate": {
    "ready": false,
    "blockers": ["wg_only_stack_selftest"]
  }
}'
      write_summary_json_if_requested "$summary_payload" "$@"
      echo "[pre-real-host-readiness] status=FAIL stage=wg_only_stack_selftest"
      echo "[pre-real-host-readiness] summary_json_payload:"
      printf '%s\n' "$summary_payload"
      exit 1
    fi
    if [[ "$mode" == "non-root-fail" ]]; then
      summary_payload='{
  "version": 1,
  "status": "fail",
  "stage": "runtime_fix",
  "notes": "runtime hygiene failed without root-specific reason",
  "wg_only_stack_selftest": {
    "status": "skipped",
    "notes": ""
  },
  "machine_c_smoke_gate": {
    "ready": false,
    "blockers": ["runtime_hygiene"]
  }
}'
      write_summary_json_if_requested "$summary_payload" "$@"
      echo "[pre-real-host-readiness] status=FAIL stage=runtime_fix"
      echo "[pre-real-host-readiness] summary_json_payload:"
      printf '%s\n' "$summary_payload"
      exit 1
    fi
    summary_payload='{
  "version": 1,
  "status": "pass",
  "stage": "complete",
  "notes": "ready",
  "machine_c_smoke_gate": {
    "ready": true,
    "blockers": []
  }
}'
    write_summary_json_if_requested "$summary_payload" "$@"
    echo "[pre-real-host-readiness] status=PASS stage=complete"
    echo "[pre-real-host-readiness] summary_json_payload:"
    printf '%s\n' "$summary_payload"
    exit 0
    ;;
  three-machine-prod-bundle|prod-gate-slo-dashboard)
    exit 0
    ;;
  *)
    exit 0
    ;;
esac
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

echo "[prod-pilot] wrapper defaults + forwarding"
CAPTURE_FILE="$CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_PILOT_PRE_REAL_HOST_READINESS_EFFECTIVE_UID_OVERRIDE=1000 \
./scripts/prod_pilot_runbook.sh \
  --bootstrap-directory https://dir-a:8081 \
  --subject pilot-client \
  --signoff-check 0 \
  --wg-slo-profile strict >/tmp/integration_prod_pilot_runbook_wrapper.log 2>&1

if ! rg -q -- '^pre-real-host-readiness' "$CAPTURE"; then
  echo "prod-pilot wrapper did not dispatch pre-real-host-readiness by default"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^three-machine-prod-bundle' "$CAPTURE"; then
  echo "prod-pilot wrapper did not dispatch three-machine-prod-bundle"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-gate-slo-dashboard' "$CAPTURE"; then
  echo "prod-pilot wrapper did not dispatch prod-gate-slo-dashboard"
  cat "$CAPTURE"
  exit 1
fi

pre_line="$(sed -n '1p' "$CAPTURE")"
bundle_line="$(sed -n '2p' "$CAPTURE")"
dashboard_line="$(sed -n '3p' "$CAPTURE")"

if [[ -z "$pre_line" || -z "$bundle_line" || -z "$dashboard_line" ]]; then
  echo "expected three easy-node dispatch lines (pre-readiness + bundle + dashboard)"
  cat "$CAPTURE"
  exit 1
fi

if ! printf '%s\n' "$pre_line" | rg -q -- '^pre-real-host-readiness '; then
  echo "prod-pilot wrapper first dispatch should be pre-real-host-readiness"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$pre_line" | rg -q -- '--defer-no-root 1'; then
  echo "prod-pilot wrapper should default to --defer-no-root 1 for non-root pre-real-host readiness"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$pre_line" | rg -q -- '--summary-json '; then
  echo "prod-pilot wrapper missing pre-real-host readiness --summary-json"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$pre_line" | rg -q -- '--print-summary-json 1'; then
  echo "prod-pilot wrapper missing pre-real-host readiness --print-summary-json 1"
  cat "$CAPTURE"
  exit 1
fi

if ! printf '%s\n' "$bundle_line" | rg -q -- '--preflight-check 1'; then
  echo "prod-pilot wrapper missing default --preflight-check 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--bundle-verify-check 1'; then
  echo "prod-pilot wrapper missing default --bundle-verify-check 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-check 1'; then
  echo "prod-pilot wrapper missing default --signoff-check 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-require-wg-validate-udp-source 1'; then
  echo "prod-pilot wrapper missing default --signoff-require-wg-validate-udp-source 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-require-wg-validate-strict-distinct 1'; then
  echo "prod-pilot wrapper missing default --signoff-require-wg-validate-strict-distinct 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-require-wg-soak-diversity-pass 1'; then
  echo "prod-pilot wrapper missing default --signoff-require-wg-soak-diversity-pass 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-min-wg-soak-selection-lines 12'; then
  echo "prod-pilot wrapper missing default --signoff-min-wg-soak-selection-lines 12"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-min-wg-soak-entry-operators 2'; then
  echo "prod-pilot wrapper missing default --signoff-min-wg-soak-entry-operators 2"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-min-wg-soak-exit-operators 2'; then
  echo "prod-pilot wrapper missing default --signoff-min-wg-soak-exit-operators 2"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-min-wg-soak-cross-operator-pairs 2'; then
  echo "prod-pilot wrapper missing default --signoff-min-wg-soak-cross-operator-pairs 2"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--strict-distinct 1'; then
  echo "prod-pilot wrapper missing default --strict-distinct 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--wg-slo-profile recommended'; then
  echo "prod-pilot wrapper missing default --wg-slo-profile recommended"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--bootstrap-directory https://dir-a:8081'; then
  echo "prod-pilot wrapper missing forwarded --bootstrap-directory"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--subject pilot-client'; then
  echo "prod-pilot wrapper missing forwarded --subject"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--signoff-check 0'; then
  echo "prod-pilot wrapper missing caller override --signoff-check 0"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--wg-slo-profile strict'; then
  echo "prod-pilot wrapper missing caller override --wg-slo-profile strict"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$bundle_line" | rg -q -- '--run-report-json '; then
  echo "prod-pilot wrapper missing default --run-report-json dispatch"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$dashboard_line" | rg -q -- '--dashboard-md '; then
  echo "prod-pilot wrapper missing dashboard markdown output flag"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$dashboard_line" | rg -q -- '--reports-dir '; then
  echo "prod-pilot wrapper missing dashboard reports-dir fallback"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$dashboard_line" | rg -q -- '--print-dashboard 1'; then
  echo "prod-pilot wrapper missing default --print-dashboard 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$dashboard_line" | rg -q -- '--require-wg-validate-udp-source 1'; then
  echo "prod-pilot wrapper missing dashboard --require-wg-validate-udp-source 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$dashboard_line" | rg -q -- '--require-wg-validate-strict-distinct 1'; then
  echo "prod-pilot wrapper missing dashboard --require-wg-validate-strict-distinct 1"
  cat "$CAPTURE"
  exit 1
fi
if ! printf '%s\n' "$dashboard_line" | rg -q -- '--require-wg-soak-diversity-pass 1'; then
  echo "prod-pilot wrapper missing dashboard --require-wg-soak-diversity-pass 1"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"
echo "[prod-pilot] root-only deferred pre-real-host readiness continues"
set +e
CAPTURE_FILE="$CAPTURE" \
FAKE_MODE="root-deferred" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_PILOT_PRE_REAL_HOST_READINESS_EFFECTIVE_UID_OVERRIDE=1000 \
./scripts/prod_pilot_runbook.sh \
  --bootstrap-directory https://dir-a:8081 >/tmp/integration_prod_pilot_runbook_root_deferred.log 2>&1
root_deferred_rc=$?
set -e
if [[ "$root_deferred_rc" -ne 0 ]]; then
  echo "prod-pilot wrapper should continue when pre-real-host readiness reports root-only deferred condition"
  cat /tmp/integration_prod_pilot_runbook_root_deferred.log
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- 'warning: pre-real-host readiness reported root-only deferred condition; continuing to bundle flow' /tmp/integration_prod_pilot_runbook_root_deferred.log; then
  echo "prod-pilot wrapper missing root-only deferred continuation warning"
  cat /tmp/integration_prod_pilot_runbook_root_deferred.log
  exit 1
fi
if ! rg -q -- '^pre-real-host-readiness .*--defer-no-root 1 ' "$CAPTURE"; then
  echo "prod-pilot wrapper root-deferred run missing --defer-no-root 1 forwarding"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^three-machine-prod-bundle' "$CAPTURE"; then
  echo "prod-pilot wrapper root-deferred run should continue to three-machine-prod-bundle"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-gate-slo-dashboard' "$CAPTURE"; then
  echo "prod-pilot wrapper root-deferred run should continue to prod-gate-slo-dashboard"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"
echo "[prod-pilot] non-root-independent pre-real-host readiness failure blocks"
set +e
CAPTURE_FILE="$CAPTURE" \
FAKE_MODE="non-root-fail" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
PROD_PILOT_PRE_REAL_HOST_READINESS_EFFECTIVE_UID_OVERRIDE=1000 \
./scripts/prod_pilot_runbook.sh \
  --bootstrap-directory https://dir-a:8081 >/tmp/integration_prod_pilot_runbook_non_root_fail.log 2>&1
non_root_fail_rc=$?
set -e
if [[ "$non_root_fail_rc" -eq 0 ]]; then
  echo "prod-pilot wrapper should fail closed on non-root-independent pre-real-host readiness failures"
  cat /tmp/integration_prod_pilot_runbook_non_root_fail.log
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^pre-real-host-readiness ' "$CAPTURE"; then
  echo "prod-pilot wrapper non-root-fail run missing pre-real-host-readiness dispatch"
  cat "$CAPTURE"
  exit 1
fi
if rg -q -- '^three-machine-prod-bundle' "$CAPTURE"; then
  echo "prod-pilot wrapper non-root-fail run should not continue to three-machine-prod-bundle"
  cat "$CAPTURE"
  exit 1
fi
if rg -q -- '^prod-gate-slo-dashboard' "$CAPTURE"; then
  echo "prod-pilot wrapper non-root-fail run should not continue to prod-gate-slo-dashboard"
  cat "$CAPTURE"
  exit 1
fi

: >"$CAPTURE"

echo "[prod-pilot] wrapper pre-real-host readiness override"
CAPTURE_FILE="$CAPTURE" \
EASY_NODE_SH="$FAKE_EASY_NODE" \
./scripts/prod_pilot_runbook.sh \
  --bootstrap-directory https://dir-a:8081 \
  --pre-real-host-readiness 0 >/tmp/integration_prod_pilot_runbook_pre_override.log 2>&1

if rg -q -- '^pre-real-host-readiness' "$CAPTURE"; then
  echo "prod-pilot wrapper should not dispatch pre-real-host-readiness when explicitly disabled"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^three-machine-prod-bundle' "$CAPTURE"; then
  echo "prod-pilot wrapper override run did not dispatch three-machine-prod-bundle"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '^prod-gate-slo-dashboard' "$CAPTURE"; then
  echo "prod-pilot wrapper override run did not dispatch prod-gate-slo-dashboard"
  cat "$CAPTURE"
  exit 1
fi

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "--version" ]]; then
  printf 'Docker version test\n'
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER
chmod +x "$TMP_BIN/docker"

FAKE_PROD_PILOT="$TMP_DIR/fake_prod_pilot.sh"
DISPATCH_CAPTURE="$TMP_DIR/prod_pilot_dispatch_args.log"
cat >"$FAKE_PROD_PILOT" <<'EOF_FAKE_PROD_PILOT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${DISPATCH_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_PROD_PILOT
chmod +x "$FAKE_PROD_PILOT"

echo "[prod-pilot] easy-node command dispatch"
PATH="$TMP_BIN:$PATH" \
DISPATCH_CAPTURE_FILE="$DISPATCH_CAPTURE" \
PROD_PILOT_RUNBOOK_SCRIPT="$FAKE_PROD_PILOT" \
./scripts/easy_node.sh prod-pilot-runbook --bootstrap-directory https://dir-b:8081 >/tmp/integration_prod_pilot_runbook_dispatch.log 2>&1

if ! rg -q -- '--bootstrap-directory https://dir-b:8081' "$DISPATCH_CAPTURE"; then
  echo "easy-node prod-pilot-runbook did not forward command arguments"
  cat "$DISPATCH_CAPTURE"
  exit 1
fi

echo "prod pilot runbook integration check ok"
