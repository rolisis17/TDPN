#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GATE_SCRIPT="${THREE_MACHINE_PROD_GATE_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_prod_gate.sh}"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_gate_bundle.sh [--bundle-dir PATH] [three-machine-prod-gate args...]

Purpose:
  Run production 3-machine gate and always produce a shareable diagnostics bundle:
  - prod gate report log
  - WG validate summary JSON
  - WG soak summary JSON
  - gate summary JSON
  - copied gate step logs (when available)
  - metadata file
  - .tar.gz archive

Notes:
  - Returns the same exit code as integration_3machine_prod_gate.sh.
  - Bundle is still produced when gate fails.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

json_string_field() {
  local file="$1"
  local key="$2"
  sed -nE "s/^[[:space:]]*\"${key}\":[[:space:]]*\"([^\"]*)\".*/\1/p" "$file" | head -n1
}

bundle_dir=""
declare -a gate_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      gate_args+=("$1")
      shift
      ;;
  esac
done

for cmd in bash tar cp date tee; do
  need_cmd "$cmd"
done

if [[ ! -x "$GATE_SCRIPT" ]]; then
  echo "missing executable gate script: $GATE_SCRIPT"
  exit 2
fi

if [[ -z "$bundle_dir" ]]; then
  bundle_dir="$(default_log_dir)/prod_gate_bundle_$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$bundle_dir"
bundle_dir="$(cd "$bundle_dir" && pwd)"

bundle_log="$bundle_dir/prod_gate_bundle.log"
exec > >(tee -a "$bundle_log") 2>&1

started_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
report_file="$bundle_dir/prod_gate.log"
wg_validate_summary_json="$bundle_dir/prod_wg_validate_summary.json"
wg_soak_summary_json="$bundle_dir/prod_wg_soak_summary.json"
gate_summary_json="$bundle_dir/prod_gate_summary.json"

echo "[prod-gate-bundle] started at $started_at_utc"
echo "[prod-gate-bundle] bundle_dir=$bundle_dir"
echo "[prod-gate-bundle] gate_script=$GATE_SCRIPT"

set +e
"$GATE_SCRIPT" \
  "${gate_args[@]}" \
  --report-file "$report_file" \
  --wg-validate-summary-json "$wg_validate_summary_json" \
  --wg-soak-summary-json "$wg_soak_summary_json" \
  --gate-summary-json "$gate_summary_json"
gate_rc=$?
set -e

step_logs_dir=""
if [[ -s "$gate_summary_json" ]]; then
  step_logs_dir="$(json_string_field "$gate_summary_json" "step_logs")"
fi
if [[ -z "$step_logs_dir" && -s "$report_file" ]]; then
  step_logs_dir="$(sed -nE 's/^\[prod-gate\] step_logs:[[:space:]]*(.*)$/\1/p' "$report_file" | tail -n1)"
fi

if [[ -n "$step_logs_dir" && -d "$step_logs_dir" ]]; then
  mkdir -p "$bundle_dir/step_logs"
  cp -a "$step_logs_dir"/. "$bundle_dir/step_logs/"
  echo "[prod-gate-bundle] copied step logs from: $step_logs_dir"
else
  echo "[prod-gate-bundle] note: step logs directory not found (${step_logs_dir:-unset})"
fi

finished_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
cat >"$bundle_dir/metadata.txt" <<EOF
started_at_utc=$started_at_utc
finished_at_utc=$finished_at_utc
gate_script=$GATE_SCRIPT
gate_rc=$gate_rc
bundle_dir=$bundle_dir
bundle_log=$bundle_log
report_file=$report_file
wg_soak_summary_json=$wg_soak_summary_json
wg_validate_summary_json=$wg_validate_summary_json
gate_summary_json=$gate_summary_json
step_logs_dir=$step_logs_dir
EOF

bundle_tar="${bundle_dir}.tar.gz"
tar -czf "$bundle_tar" -C "$(dirname "$bundle_dir")" "$(basename "$bundle_dir")"

echo "[prod-gate-bundle] bundle ready: $bundle_tar"
echo "[prod-gate-bundle] gate_rc=$gate_rc"

exit "$gate_rc"
