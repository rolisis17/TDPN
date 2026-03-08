#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/integration_machine_c_client_check.sh \
    [--directory-a URL] \
    [--directory-b URL] \
    [--bootstrap-directory URL] \
    [--discovery-wait-sec N] \
    [--issuer-url URL] \
    [--issuer-a-url URL] \
    [--issuer-b-url URL] \
    [--entry-url URL] \
    [--exit-url URL] \
    [--subject ID] \
    [--anon-cred TOKEN] \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--timeout-sec N] \
    [--client-min-selection-lines N] \
    [--client-min-entry-operators N] \
    [--client-min-exit-operators N] \
    [--client-require-cross-operator-pair [0|1]] \
    [--exit-country CC] \
    [--exit-region REGION] \
    [--distinct-operators [0|1]] \
    [--require-issuer-quorum [0|1]] \
    [--beta-profile [0|1]] \
    [--prod-profile [0|1]] \
    [--report-file PATH]

Purpose:
  Run on machine C (client host). Wraps full 3-machine validation and
  stores a single report file for sharing/debugging.
  Default report path is ./.easy-node-logs (override with EASY_NODE_LOG_DIR).
USAGE
}

report_file=""
pass_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --report-file)
      report_file="${2:-}"
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      # Pass-through all arguments verbatim to the underlying validator.
      pass_args+=("$1")
      shift
      ;;
  esac
done

if [[ -z "$report_file" ]]; then
  report_file="$(default_log_dir)/privacynode_machine_c_test_$(date +%Y%m%d_%H%M%S).log"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

echo "[machine-c-test] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[machine-c-test] report: $report_file"
overall_timeout_sec="${MACHINE_C_TEST_TIMEOUT_SEC:-720}"
echo "[machine-c-test] overall timeout: ${overall_timeout_sec}s (override with MACHINE_C_TEST_TIMEOUT_SEC)"
echo "[machine-c-test] running 3-machine validation..."

set +e
timeout --foreground -k 20s "${overall_timeout_sec}s" "$ROOT_DIR/scripts/integration_3machine_beta_validate.sh" "${pass_args[@]}"
rc=$?
set -e
if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
  echo "[machine-c-test] timed out after ${overall_timeout_sec}s"
  exit 1
fi
if [[ "$rc" -ne 0 ]]; then
  exit "$rc"
fi

echo "[machine-c-test] ok"
echo "[machine-c-test] report saved: $report_file"
