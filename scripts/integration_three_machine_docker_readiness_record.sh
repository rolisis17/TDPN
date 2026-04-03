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

CAPTURE="$TMP_DIR/easy_node_calls.log"
FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"

cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${FAKE_EASY_CAPTURE_FILE:?}"
cmd="${1:-}"
shift || true
case "$cmd" in
  three-machine-docker-readiness)
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
      cat >"$summary_json" <<EOF_REHEARSAL
{
  "version": 1,
  "status": "${FAKE_DOCKER_READINESS_STATUS:-pass}",
  "rc": ${FAKE_DOCKER_READINESS_RC:-0},
  "notes": "${FAKE_DOCKER_READINESS_NOTES:-Docker rehearsal completed}",
  "artifacts": {
    "summary_log": "${summary_json%.json}.log"
  }
}
EOF_REHEARSAL
      : >"${summary_json%.json}.log"
    fi
    if [[ "${FAKE_DOCKER_READINESS_FAIL:-0}" == "1" ]]; then
      exit 1
    fi
    exit 0
    ;;
  manual-validation-report)
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
    mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
    cat >"$summary_json" <<'EOF_REPORT_JSON'
{"report":{"readiness_status":"NOT_READY"},"summary":{"next_action_check_id":"machine_c_vpn_smoke"}}
EOF_REPORT_JSON
    printf '# Manual Validation Readiness Report\n' >"$report_md"
    echo "[manual-validation-report] readiness_status=NOT_READY total=4 pass=2 warn=0 fail=0 pending=2"
    echo "[manual-validation-report] summary_json=$summary_json"
    echo "[manual-validation-report] report_md=$report_md"
    echo "[manual-validation-report] next_action_check_id=machine_c_vpn_smoke"
    echo "[manual-validation-report] summary_json_payload:"
    cat "$summary_json"
    exit 0
    ;;
  manual-validation-record)
    echo "manual-validation-record ok"
    exit 0
    ;;
esac
echo "unexpected command: $cmd" >&2
exit 1
EOF_FAKE_EASY
chmod +x "$FAKE_EASY_NODE"

echo "[three-machine-docker-readiness-record] success path"
FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
THREE_MACHINE_DOCKER_READINESS_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
./scripts/three_machine_docker_readiness_record.sh \
  --path-profile balanced \
  --soak-rounds 4 \
  --soak-pause-sec 1 \
  --print-summary-json 1 >/tmp/integration_three_machine_docker_readiness_record_ok.log 2>&1

if ! rg -q 'three-machine-docker-readiness-record: status=pass' /tmp/integration_three_machine_docker_readiness_record_ok.log; then
  echo "expected pass status for three-machine-docker-readiness-record success path"
  cat /tmp/integration_three_machine_docker_readiness_record_ok.log
  exit 1
fi
if ! rg -q '^three-machine-docker-readiness --path-profile balanced --soak-rounds 4 --soak-pause-sec 1 --summary-json .* --print-summary-json 0$' "$CAPTURE"; then
  echo "expected three-machine-docker-readiness forwarding missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id three_machine_docker_readiness --status pass ' "$CAPTURE"; then
  echo "expected manual-validation-record pass call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-report --overlay-check-id three_machine_docker_readiness --overlay-status pass ' "$CAPTURE"; then
  echo "expected manual-validation-report overlay call missing"
  cat "$CAPTURE"
  exit 1
fi

summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_three_machine_docker_readiness_record_ok.log | tail -n 1)"
if [[ -z "$summary_json_path" || ! -f "$summary_json_path" ]]; then
  echo "expected success summary JSON missing"
  cat /tmp/integration_three_machine_docker_readiness_record_ok.log
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .schema.id == "three_machine_docker_readiness_record_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .rc == 0
  and .rehearsal.status == "pass"
  and .rehearsal.rc == 0
  and .manual_validation_report.status == "ok"
  and .manual_validation_report.readiness_status == "NOT_READY"
  and .manual_validation_report.next_action_check_id == "machine_c_vpn_smoke"
' "$summary_json_path" >/dev/null; then
  echo "success summary JSON missing expected fields"
  cat "$summary_json_path"
  exit 1
fi

: >"$CAPTURE"

echo "[three-machine-docker-readiness-record] failure path"
if env \
  FAKE_EASY_CAPTURE_FILE="$CAPTURE" \
  FAKE_DOCKER_READINESS_FAIL="1" \
  FAKE_DOCKER_READINESS_STATUS="fail" \
  FAKE_DOCKER_READINESS_RC=1 \
  FAKE_DOCKER_READINESS_NOTES="Docker rehearsal failed" \
  THREE_MACHINE_DOCKER_READINESS_RECORD_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
  ./scripts/three_machine_docker_readiness_record.sh \
    --path-profile private >/tmp/integration_three_machine_docker_readiness_record_fail.log 2>&1; then
  echo "expected failure path to return non-zero"
  cat /tmp/integration_three_machine_docker_readiness_record_fail.log
  exit 1
fi

if ! rg -q 'three-machine-docker-readiness-record: status=fail' /tmp/integration_three_machine_docker_readiness_record_fail.log; then
  echo "expected fail status for three-machine-docker-readiness-record failure path"
  cat /tmp/integration_three_machine_docker_readiness_record_fail.log
  exit 1
fi
if ! rg -q '^manual-validation-record --check-id three_machine_docker_readiness --status fail ' "$CAPTURE"; then
  echo "expected manual-validation-record fail call missing"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q '^manual-validation-report --overlay-check-id three_machine_docker_readiness --overlay-status fail ' "$CAPTURE"; then
  echo "expected manual-validation-report fail overlay call missing"
  cat "$CAPTURE"
  exit 1
fi

fail_summary_json_path="$(sed -n 's/^summary_json: //p' /tmp/integration_three_machine_docker_readiness_record_fail.log | tail -n 1)"
if [[ -z "$fail_summary_json_path" || ! -f "$fail_summary_json_path" ]]; then
  echo "expected failure summary JSON missing"
  cat /tmp/integration_three_machine_docker_readiness_record_fail.log
  exit 1
fi
if ! jq -e '
  .status == "fail"
  and .schema.id == "three_machine_docker_readiness_record_summary"
  and .schema.major == 1
  and .schema.minor == 0
  and .rc == 1
  and .rehearsal.status == "fail"
  and .rehearsal.rc == 1
  and .manual_validation_report.status == "ok"
' "$fail_summary_json_path" >/dev/null; then
  echo "failure summary JSON missing expected fields"
  cat "$fail_summary_json_path"
  exit 1
fi

echo "three machine docker readiness record integration ok"
