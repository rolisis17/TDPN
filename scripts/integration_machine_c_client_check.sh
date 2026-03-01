#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/integration_machine_c_client_check.sh \
    --directory-a URL \
    --directory-b URL \
    --issuer-url URL \
    --entry-url URL \
    --exit-url URL \
    [--min-sources N] \
    [--min-operators N] \
    [--federation-timeout-sec N] \
    [--timeout-sec N] \
    [--exit-country CC] \
    [--exit-region REGION] \
    [--report-file PATH]

Purpose:
  Run on machine C (client host). Wraps full 3-machine validation and
  stores a single report file for sharing/debugging.
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
      pass_args+=("$1")
      shift
      if [[ ${#pass_args[@]} -gt 0 ]]; then
        last="${pass_args[${#pass_args[@]}-1]}"
        case "$last" in
          --directory-a|--directory-b|--issuer-url|--entry-url|--exit-url|--min-sources|--min-operators|--federation-timeout-sec|--timeout-sec|--exit-country|--exit-region)
            if [[ $# -eq 0 ]]; then
              echo "missing value for $last"
              usage
              exit 2
            fi
            pass_args+=("$1")
            shift
            ;;
        esac
      fi
      ;;
  esac
done

if [[ -z "$report_file" ]]; then
  report_file="/tmp/privacynode_machine_c_test_$(date +%Y%m%d_%H%M%S).log"
fi
mkdir -p "$(dirname "$report_file")"
exec > >(tee -a "$report_file") 2>&1

echo "[machine-c-test] started at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "[machine-c-test] report: $report_file"

"$ROOT_DIR/scripts/integration_3machine_beta_validate.sh" "${pass_args[@]}"

echo "[machine-c-test] ok"
echo "[machine-c-test] report saved: $report_file"
