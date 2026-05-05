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
FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"

REPORTS_DIR="$TMP_DIR/reports"
MATRIX_SUMMARY="$TMP_DIR/matrix_summary.json"
MATRIX_REPORT="$TMP_DIR/matrix_report.md"
SIGNOFF_SUMMARY="$TMP_DIR/signoff_summary.json"
ROADMAP_SUMMARY="$TMP_DIR/roadmap_summary.json"
ROADMAP_REPORT="$TMP_DIR/roadmap_report.md"
FINAL_SUMMARY="$TMP_DIR/final_summary.json"
FAIL_SUMMARY="$TMP_DIR/fail_summary.json"

SUCCESS_LOG="$TMP_DIR/success.log"
FAIL_LOG="$TMP_DIR/fail.log"
FORWARD_LOG="$TMP_DIR/forward.log"

FAKE_MATRIX="$TMP_DIR/fake_matrix.sh"
cat >"$FAKE_MATRIX" <<'EOF_FAKE_MATRIX'
#!/usr/bin/env bash
set -euo pipefail
printf 'matrix %s\n' "$*" >>"${VPN_RC_CAPTURE_FILE:?}"
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
  "version": 1,
  "status": "pass",
  "rc": 0,
  "summary": {
    "runs_total": 3,
    "runs_pass": 3,
    "runs_warn": 0,
    "runs_fail": 0
  }
}
EOF_SUMMARY
fi
if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake matrix report\n' >"$report_md"
fi
exit "${FAKE_MATRIX_FAIL:-0}"
EOF_FAKE_MATRIX
chmod +x "$FAKE_MATRIX"

FAKE_SIGNOFF="$TMP_DIR/fake_signoff.sh"
cat >"$FAKE_SIGNOFF" <<'EOF_FAKE_SIGNOFF'
#!/usr/bin/env bash
set -euo pipefail
printf 'signoff %s\n' "$*" >>"${VPN_RC_CAPTURE_FILE:?}"
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
  decision="${FAKE_SIGNOFF_DECISION:-GO}"
  cat >"$summary_json" <<EOF_SUMMARY
{
  "status": "ok",
  "final_rc": 0,
  "decision": {
    "decision": "$decision"
  }
}
EOF_SUMMARY
fi
exit "${FAKE_SIGNOFF_FAIL:-0}"
EOF_FAKE_SIGNOFF
chmod +x "$FAKE_SIGNOFF"

FAKE_ROADMAP="$TMP_DIR/fake_roadmap.sh"
cat >"$FAKE_ROADMAP" <<'EOF_FAKE_ROADMAP'
#!/usr/bin/env bash
set -euo pipefail
printf 'roadmap %s\n' "$*" >>"${VPN_RC_CAPTURE_FILE:?}"
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
  "vpn_track": {
    "roadmap_stage": "READY_FOR_MACHINE_C_SMOKE",
    "readiness_status": "NOT_READY",
    "next_action": {
      "command": "sudo ./scripts/easy_node.sh client-vpn-smoke --bootstrap-directory http://A_HOST:8081 --subject INVITE_KEY"
    }
  }
}
EOF_SUMMARY
fi
if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake roadmap report\n' >"$report_md"
fi
exit "${FAKE_ROADMAP_FAIL:-0}"
EOF_FAKE_ROADMAP
chmod +x "$FAKE_ROADMAP"

echo "[vpn-rc-matrix-path] success path"
: >"$CAPTURE"
VPN_RC_CAPTURE_FILE="$CAPTURE" \
VPN_RC_MATRIX_PATH_MATRIX_SCRIPT="$FAKE_MATRIX" \
VPN_RC_MATRIX_PATH_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
VPN_RC_MATRIX_PATH_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/vpn_rc_matrix_path.sh \
  --reports-dir "$REPORTS_DIR" \
  --matrix-summary-json "$MATRIX_SUMMARY" \
  --matrix-report-md "$MATRIX_REPORT" \
  --signoff-summary-json "$SIGNOFF_SUMMARY" \
  --roadmap-summary-json "$ROADMAP_SUMMARY" \
  --roadmap-report-md "$ROADMAP_REPORT" \
  --summary-json "$FINAL_SUMMARY" \
  --campaign-execution-mode docker \
  --campaign-bootstrap-directory "http://127.0.0.1:18081" \
  --campaign-discovery-wait-sec 9 \
  --signoff-refresh-campaign 1 \
  --signoff-fail-on-no-go 1 \
  --roadmap-refresh-manual-validation 1 \
  --roadmap-refresh-single-machine-readiness 0 \
  --print-report 0 \
  --print-summary-json 1 >"$SUCCESS_LOG" 2>&1

first_line="$(sed -n '1p' "$CAPTURE" || true)"
second_line="$(sed -n '2p' "$CAPTURE" || true)"
third_line="$(sed -n '3p' "$CAPTURE" || true)"
if [[ "$first_line" != matrix* ]]; then
  echo "expected matrix stage to run first"
  cat "$CAPTURE"
  cat "$SUCCESS_LOG"
  exit 1
fi
if [[ "$second_line" != signoff* ]]; then
  echo "expected signoff stage to run second"
  cat "$CAPTURE"
  cat "$SUCCESS_LOG"
  exit 1
fi
if [[ "$third_line" != roadmap* ]]; then
  echo "expected roadmap stage to run third"
  cat "$CAPTURE"
  cat "$SUCCESS_LOG"
  exit 1
fi

matrix_line="$(rg '^matrix ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$matrix_line" ]]; then
  echo "missing matrix invocation line"
  cat "$CAPTURE"
  cat "$SUCCESS_LOG"
  exit 1
fi
for expected in \
  "--reports-dir $REPORTS_DIR" \
  "--summary-json $MATRIX_SUMMARY" \
  "--report-md $MATRIX_REPORT" \
  "--execution-mode docker" \
  "--bootstrap-directory http://127.0.0.1:18081" \
  "--discovery-wait-sec 9" \
  "--print-summary-json 0"; do
  if ! grep -F -- "$expected" <<<"$matrix_line" >/dev/null; then
    echo "matrix invocation missing: $expected"
    cat "$CAPTURE"
    cat "$SUCCESS_LOG"
    exit 1
  fi
done

signoff_line="$(rg '^signoff ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$signoff_line" ]]; then
  echo "missing signoff invocation line"
  cat "$CAPTURE"
  cat "$SUCCESS_LOG"
  exit 1
fi
for expected in \
  "--campaign-summary-json $MATRIX_SUMMARY" \
  "--campaign-report-md $MATRIX_REPORT" \
  "--refresh-campaign 1" \
  "--fail-on-no-go 1" \
  "--allow-summary-overwrite 0" \
  "--campaign-execution-mode docker" \
  "--campaign-bootstrap-directory http://127.0.0.1:18081" \
  "--campaign-discovery-wait-sec 9" \
  "--summary-json $SIGNOFF_SUMMARY" \
  "--show-json 0" \
  "--print-summary-json 0"; do
  if ! grep -F -- "$expected" <<<"$signoff_line" >/dev/null; then
    echo "signoff invocation missing: $expected"
    cat "$CAPTURE"
    cat "$SUCCESS_LOG"
    exit 1
  fi
done

roadmap_line="$(rg '^roadmap ' "$CAPTURE" | tail -n 1 || true)"
if [[ -z "$roadmap_line" ]]; then
  echo "missing roadmap invocation line"
  cat "$CAPTURE"
  cat "$SUCCESS_LOG"
  exit 1
fi
for expected in \
  "--refresh-manual-validation 1" \
  "--refresh-single-machine-readiness 0" \
  "--profile-compare-signoff-summary-json $SIGNOFF_SUMMARY" \
  "--summary-json $ROADMAP_SUMMARY" \
  "--report-md $ROADMAP_REPORT" \
  "--print-report 0" \
  "--print-summary-json 0"; do
  if ! grep -F -- "$expected" <<<"$roadmap_line" >/dev/null; then
    echo "roadmap invocation missing: $expected"
    cat "$CAPTURE"
    cat "$SUCCESS_LOG"
    exit 1
  fi
done

if ! rg -q '\[vpn-rc-matrix-path\] status=pass rc=0' "$SUCCESS_LOG"; then
  echo "success path missing pass status line"
  cat "$SUCCESS_LOG"
  exit 1
fi
if ! jq -e '.status == "pass" and .rc == 0 and .policy.signoff_fail_on_no_go == true and .steps.profile_compare_docker_matrix.rc == 0 and .steps.profile_compare_campaign_signoff.rc == 0 and .steps.roadmap_progress_report.rc == 0 and .artifacts.matrix_summary_json == "'"$MATRIX_SUMMARY"'" and .artifacts.signoff_summary_json == "'"$SIGNOFF_SUMMARY"'" and .artifacts.roadmap_summary_json == "'"$ROADMAP_SUMMARY"'"' "$FINAL_SUMMARY" >/dev/null 2>&1; then
  echo "final summary JSON missing expected success values"
  cat "$FINAL_SUMMARY"
  exit 1
fi

echo "[vpn-rc-matrix-path] fail path still runs remaining stages"
: >"$CAPTURE"
set +e
VPN_RC_CAPTURE_FILE="$CAPTURE" \
FAKE_MATRIX_FAIL=17 \
VPN_RC_MATRIX_PATH_MATRIX_SCRIPT="$FAKE_MATRIX" \
VPN_RC_MATRIX_PATH_SIGNOFF_SCRIPT="$FAKE_SIGNOFF" \
VPN_RC_MATRIX_PATH_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/vpn_rc_matrix_path.sh \
  --reports-dir "$REPORTS_DIR/fail_case" \
  --summary-json "$FAIL_SUMMARY" \
  --print-summary-json 0 >"$FAIL_LOG" 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -ne 17 ]]; then
  echo "expected matrix failure rc=17, got rc=$fail_rc"
  cat "$FAIL_LOG"
  exit 1
fi
if ! rg -q '^signoff ' "$CAPTURE"; then
  echo "signoff stage did not run after matrix failure"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
if ! rg -q '^roadmap ' "$CAPTURE"; then
  echo "roadmap stage did not run after matrix failure"
  cat "$CAPTURE"
  cat "$FAIL_LOG"
  exit 1
fi
if ! rg -q '\[vpn-rc-matrix-path\] status=fail rc=17' "$FAIL_LOG"; then
  echo "fail path missing fail status line"
  cat "$FAIL_LOG"
  exit 1
fi
if ! jq -e '.status == "fail" and .rc == 17 and .steps.profile_compare_docker_matrix.status == "fail" and .steps.profile_compare_campaign_signoff.status == "pass" and .steps.roadmap_progress_report.status == "pass"' "$FAIL_SUMMARY" >/dev/null 2>&1; then
  echo "final summary JSON missing expected fail values"
  cat "$FAIL_SUMMARY"
  exit 1
fi

echo "[vpn-rc-matrix-path] easy_node forwarding"
FAKE_FORWARD="$TMP_DIR/fake_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FAKE_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'forward %s\n' "$*" >>"${VPN_RC_FORWARD_CAPTURE_FILE:?}"
EOF_FAKE_FORWARD
chmod +x "$FAKE_FORWARD"

: >"$FORWARD_CAPTURE"
set +e
VPN_RC_MATRIX_PATH_SCRIPT="$FAKE_FORWARD" \
VPN_RC_FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
./scripts/easy_node.sh vpn-rc-matrix-path --print-report 0 --print-summary-json 0 >"$FORWARD_LOG" 2>&1
forward_rc=$?
set -e
if [[ "$forward_rc" -ne 0 ]]; then
  echo "easy_node forwarding invocation failed"
  cat "$FORWARD_LOG"
  exit 1
fi

forward_line="$(rg '^forward ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--print-report 0' '--print-summary-json 0'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing: $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "vpn-rc matrix path integration check ok"
