#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.log"
SINGLE_SUMMARY="$TMP_DIR/single_machine.json"
ROADMAP_SUMMARY="$TMP_DIR/roadmap_summary.json"
ROADMAP_REPORT="$TMP_DIR/roadmap_report.md"

FAKE_SINGLE="$TMP_DIR/fake_single_machine.sh"
cat >"$FAKE_SINGLE" <<'EOF_FAKE_SINGLE'
#!/usr/bin/env bash
set -euo pipefail
printf 'single-machine %s\n' "$*" >>"${VPN_RC_CAPTURE_FILE:?}"
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
{"status":"warn","summary":{"next_action_check_id":"machine_c_vpn_smoke"}}
EOF_SUMMARY
fi

if [[ "${FAKE_SINGLE_FAIL:-0}" == "1" ]]; then
  exit 1
fi
exit 0
EOF_FAKE_SINGLE
chmod +x "$FAKE_SINGLE"

FAKE_ROADMAP="$TMP_DIR/fake_roadmap.sh"
cat >"$FAKE_ROADMAP" <<'EOF_FAKE_ROADMAP'
#!/usr/bin/env bash
set -euo pipefail
printf 'roadmap-progress %s\n' "$*" >>"${VPN_RC_CAPTURE_FILE:?}"
summary_json=""
report_md=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
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
  "summary": {
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "next_action_check_id": "machine_c_vpn_smoke",
    "next_action_command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY --path-profile balanced --interface wgvpn0 --pre-real-host-readiness 1 --runtime-fix 1 --public-ip-url https://api.ipify.org --country-url https://ipinfo.io/country"
  },
  "report": {
    "readiness_status": "NOT_READY"
  }
}
EOF_SUMMARY
fi
if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake roadmap report\n' >"$report_md"
fi

if [[ "${FAKE_ROADMAP_FAIL:-0}" == "1" ]]; then
  exit 1
fi
exit 0
EOF_FAKE_ROADMAP
chmod +x "$FAKE_ROADMAP"

echo "[vpn-rc-standard-path] success path"
VPN_RC_CAPTURE_FILE="$CAPTURE" \
VPN_RC_STANDARD_PATH_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
VPN_RC_STANDARD_PATH_ROADMAP_PROGRESS_SCRIPT="$FAKE_ROADMAP" \
./scripts/vpn_rc_standard_path.sh \
  --run-profile-compare-campaign-signoff 1 \
  --profile-compare-campaign-signoff-refresh-campaign 1 \
  --single-machine-summary-json "$SINGLE_SUMMARY" \
  --roadmap-summary-json "$ROADMAP_SUMMARY" \
  --roadmap-report-md "$ROADMAP_REPORT" \
  --print-report 0 \
  --print-summary-json 1 >/tmp/integration_vpn_rc_standard_path_ok.log 2>&1

single_line="$(rg '^single-machine ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$single_line" ]]; then
  echo "missing single-machine invocation"
  cat /tmp/integration_vpn_rc_standard_path_ok.log
  exit 1
fi
for expected in \
  '--run-ci-local 1' \
  '--run-beta-preflight 1' \
  '--run-deep-suite 1' \
  '--run-runtime-fix-record 1' \
  '--run-three-machine-docker-readiness 1' \
  '--three-machine-docker-readiness-run-validate 1' \
  '--three-machine-docker-readiness-run-soak 1' \
  '--three-machine-docker-readiness-soak-rounds 6' \
  '--three-machine-docker-readiness-soak-pause-sec 3' \
  '--three-machine-docker-readiness-path-profile balanced' \
  '--three-machine-docker-readiness-keep-stacks 0' \
  '--three-machine-docker-readiness-run-peer-failover 1' \
  '--three-machine-docker-readiness-peer-failover-downtime-sec 8' \
  '--three-machine-docker-readiness-peer-failover-timeout-sec 45' \
  "--run-profile-compare-campaign-signoff 1" \
  '--profile-compare-campaign-signoff-refresh-campaign 1' \
  "--summary-json $SINGLE_SUMMARY"; do
  if ! printf '%s\n' "$single_line" | rg -q -- "$expected"; then
    echo "single-machine invocation missing: $expected"
    cat /tmp/integration_vpn_rc_standard_path_ok.log
    exit 1
  fi
done

roadmap_line="$(rg '^roadmap-progress ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$roadmap_line" ]]; then
  echo "missing roadmap invocation"
  cat /tmp/integration_vpn_rc_standard_path_ok.log
  exit 1
fi
for expected in \
  '--refresh-manual-validation 1' \
  '--refresh-single-machine-readiness 0' \
  "--single-machine-summary-json $SINGLE_SUMMARY" \
  "--summary-json $ROADMAP_SUMMARY" \
  "--report-md $ROADMAP_REPORT" \
  '--print-report 0' \
  '--print-summary-json 0'; do
  if ! printf '%s\n' "$roadmap_line" | rg -q -- "$expected"; then
    echo "roadmap invocation missing: $expected"
    cat /tmp/integration_vpn_rc_standard_path_ok.log
    exit 1
  fi
done

if ! rg -q '\[vpn-rc-standard-path\] status=pass rc=0' /tmp/integration_vpn_rc_standard_path_ok.log; then
  echo "success path missing pass status line"
  cat /tmp/integration_vpn_rc_standard_path_ok.log
  exit 1
fi
if ! rg -q '"status": "pass"' /tmp/integration_vpn_rc_standard_path_ok.log; then
  echo "success path missing JSON payload"
  cat /tmp/integration_vpn_rc_standard_path_ok.log
  exit 1
fi

: >"$CAPTURE"

echo "[vpn-rc-standard-path] fail path still runs roadmap"
set +e
VPN_RC_CAPTURE_FILE="$CAPTURE" \
FAKE_SINGLE_FAIL=1 \
VPN_RC_STANDARD_PATH_SINGLE_MACHINE_SCRIPT="$FAKE_SINGLE" \
VPN_RC_STANDARD_PATH_ROADMAP_PROGRESS_SCRIPT="$FAKE_ROADMAP" \
./scripts/vpn_rc_standard_path.sh \
  --single-machine-summary-json "$SINGLE_SUMMARY" \
  --roadmap-summary-json "$ROADMAP_SUMMARY" \
  --roadmap-report-md "$ROADMAP_REPORT" \
  --print-summary-json 0 >/tmp/integration_vpn_rc_standard_path_fail.log 2>&1
fail_rc=$?
set -e
if [[ $fail_rc -eq 0 ]]; then
  echo "expected non-zero rc when single-machine step fails"
  cat /tmp/integration_vpn_rc_standard_path_fail.log
  exit 1
fi
if ! rg -q '^roadmap-progress ' "$CAPTURE"; then
  echo "roadmap step was not executed after single-machine failure"
  cat /tmp/integration_vpn_rc_standard_path_fail.log
  exit 1
fi
if ! rg -q '\[vpn-rc-standard-path\] status=fail rc=1' /tmp/integration_vpn_rc_standard_path_fail.log; then
  echo "fail path missing fail status line"
  cat /tmp/integration_vpn_rc_standard_path_fail.log
  exit 1
fi

echo "[vpn-rc-standard-path] easy_node forwarding"
FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"
FAKE_FORWARD="$TMP_DIR/fake_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FAKE_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'forward %s\n' "$*" >>"${VPN_RC_FORWARD_CAPTURE_FILE:?}"
EOF_FAKE_FORWARD
chmod +x "$FAKE_FORWARD"

VPN_RC_STANDARD_PATH_SCRIPT="$FAKE_FORWARD" \
VPN_RC_FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
./scripts/easy_node.sh vpn-rc-standard-path --print-report 0 --print-summary-json 0

forward_line="$(rg '^forward ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding invocation"
  exit 1
fi
if ! printf '%s\n' "$forward_line" | rg -q -- '--print-report 0'; then
  echo "easy_node forwarding missing --print-report 0"
  exit 1
fi
if ! printf '%s\n' "$forward_line" | rg -q -- '--print-summary-json 0'; then
  echo "easy_node forwarding missing --print-summary-json 0"
  exit 1
fi

echo "vpn-rc standard path integration check ok"
