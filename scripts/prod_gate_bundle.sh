#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

GATE_SCRIPT="${THREE_MACHINE_PROD_GATE_SCRIPT:-$ROOT_DIR/scripts/integration_3machine_prod_gate.sh}"
CHECK_SCRIPT="${THREE_MACHINE_PROD_GATE_CHECK_SCRIPT:-$ROOT_DIR/scripts/prod_gate_check.sh}"

default_log_dir() {
  echo "${EASY_NODE_LOG_DIR:-$ROOT_DIR/.easy-node-logs}"
}

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/prod_gate_bundle.sh [--bundle-dir PATH] [--signoff-check [0|1]] [--signoff-require-full-sequence [0|1]] [--signoff-require-wg-validate-ok [0|1]] [--signoff-require-wg-soak-ok [0|1]] [--signoff-max-wg-soak-failed-rounds N] [--signoff-show-json [0|1]] [three-machine-prod-gate args...]

Purpose:
  Run production 3-machine gate and always produce a shareable diagnostics bundle:
  - prod gate report log
  - WG validate summary JSON
  - WG soak summary JSON
  - gate summary JSON
  - copied gate step logs (when available)
  - in-bundle manifest (sha256 over bundle files)
  - metadata file
  - .tar.gz archive
  - tarball sha256 sidecar

Notes:
  - Returns the same exit code as integration_3machine_prod_gate.sh.
  - Bundle is still produced when gate fails.
  - Optional signoff mode runs prod_gate_check.sh on the generated gate summary and fails closed when signoff policy fails.
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

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

sha256_tool=""

detect_sha256_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256_tool="sha256sum"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    sha256_tool="shasum"
    return
  fi
  echo "missing required command: sha256sum or shasum"
  exit 2
}

sha256_value() {
  local file="$1"
  local line=""
  if [[ "$sha256_tool" == "sha256sum" ]]; then
    line="$(sha256sum "$file")"
  else
    line="$(shasum -a 256 "$file")"
  fi
  printf '%s' "${line%% *}"
}

write_sha256_line() {
  local file="$1"
  local label="$2"
  local digest
  digest="$(sha256_value "$file")"
  printf '%s  %s\n' "$digest" "$label"
}

bundle_dir=""
signoff_check="${PROD_GATE_BUNDLE_SIGNOFF_CHECK:-0}"
signoff_require_full_sequence="${PROD_GATE_BUNDLE_SIGNOFF_REQUIRE_FULL_SEQUENCE:-1}"
signoff_require_wg_validate_ok="${PROD_GATE_BUNDLE_SIGNOFF_REQUIRE_WG_VALIDATE_OK:-1}"
signoff_require_wg_soak_ok="${PROD_GATE_BUNDLE_SIGNOFF_REQUIRE_WG_SOAK_OK:-1}"
signoff_max_wg_soak_failed_rounds="${PROD_GATE_BUNDLE_SIGNOFF_MAX_WG_SOAK_FAILED_ROUNDS:-0}"
signoff_show_json="${PROD_GATE_BUNDLE_SIGNOFF_SHOW_JSON:-0}"
declare -a gate_args=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    --signoff-check)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_check="${2:-}"
        shift 2
      else
        signoff_check="1"
        shift
      fi
      ;;
    --signoff-require-full-sequence)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_full_sequence="${2:-}"
        shift 2
      else
        signoff_require_full_sequence="1"
        shift
      fi
      ;;
    --signoff-require-wg-validate-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_wg_validate_ok="${2:-}"
        shift 2
      else
        signoff_require_wg_validate_ok="1"
        shift
      fi
      ;;
    --signoff-require-wg-soak-ok)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_require_wg_soak_ok="${2:-}"
        shift 2
      else
        signoff_require_wg_soak_ok="1"
        shift
      fi
      ;;
    --signoff-max-wg-soak-failed-rounds)
      signoff_max_wg_soak_failed_rounds="${2:-}"
      shift 2
      ;;
    --signoff-show-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        signoff_show_json="${2:-}"
        shift 2
      else
        signoff_show_json="1"
        shift
      fi
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

bool_arg_or_die "--signoff-check" "$signoff_check"
bool_arg_or_die "--signoff-require-full-sequence" "$signoff_require_full_sequence"
bool_arg_or_die "--signoff-require-wg-validate-ok" "$signoff_require_wg_validate_ok"
bool_arg_or_die "--signoff-require-wg-soak-ok" "$signoff_require_wg_soak_ok"
bool_arg_or_die "--signoff-show-json" "$signoff_show_json"
if [[ ! "$signoff_max_wg_soak_failed_rounds" =~ ^[0-9]+$ ]]; then
  echo "--signoff-max-wg-soak-failed-rounds must be an integer >= 0"
  exit 2
fi

for cmd in bash tar cp date tee find sort grep; do
  need_cmd "$cmd"
done
detect_sha256_tool

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
if [[ "$signoff_check" == "1" ]]; then
  echo "[prod-gate-bundle] signoff enabled: script=$CHECK_SCRIPT full_sequence=$signoff_require_full_sequence wg_validate_ok=$signoff_require_wg_validate_ok wg_soak_ok=$signoff_require_wg_soak_ok max_wg_soak_failed_rounds=$signoff_max_wg_soak_failed_rounds show_json=$signoff_show_json"
else
  echo "[prod-gate-bundle] signoff disabled"
fi

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

signoff_rc=0
if [[ "$signoff_check" == "1" ]]; then
  if [[ ! -x "$CHECK_SCRIPT" ]]; then
    echo "[prod-gate-bundle] signoff failed: missing executable signoff script: $CHECK_SCRIPT"
    signoff_rc=2
  elif [[ ! -s "$gate_summary_json" ]]; then
    echo "[prod-gate-bundle] signoff failed: gate summary missing: $gate_summary_json"
    signoff_rc=1
  else
    set +e
    "$CHECK_SCRIPT" \
      --gate-summary-json "$gate_summary_json" \
      --require-full-sequence "$signoff_require_full_sequence" \
      --require-wg-validate-ok "$signoff_require_wg_validate_ok" \
      --require-wg-soak-ok "$signoff_require_wg_soak_ok" \
      --max-wg-soak-failed-rounds "$signoff_max_wg_soak_failed_rounds" \
      --show-json "$signoff_show_json"
    signoff_rc=$?
    set -e
  fi
  echo "[prod-gate-bundle] signoff_rc=$signoff_rc"
fi

bundle_tar="${bundle_dir}.tar.gz"
bundle_tar_sha256_file="${bundle_tar}.sha256"
manifest_file="$bundle_dir/manifest.sha256"

cat >"$bundle_dir/metadata.txt" <<EOF
started_at_utc=$started_at_utc
finished_at_utc=$finished_at_utc
gate_script=$GATE_SCRIPT
gate_rc=$gate_rc
signoff_enabled=$signoff_check
signoff_script=$CHECK_SCRIPT
signoff_rc=$signoff_rc
signoff_require_full_sequence=$signoff_require_full_sequence
signoff_require_wg_validate_ok=$signoff_require_wg_validate_ok
signoff_require_wg_soak_ok=$signoff_require_wg_soak_ok
signoff_max_wg_soak_failed_rounds=$signoff_max_wg_soak_failed_rounds
signoff_show_json=$signoff_show_json
bundle_dir=$bundle_dir
bundle_log=$bundle_log
report_file=$report_file
wg_soak_summary_json=$wg_soak_summary_json
wg_validate_summary_json=$wg_validate_summary_json
gate_summary_json=$gate_summary_json
step_logs_dir=$step_logs_dir
bundle_tar=$bundle_tar
bundle_tar_sha256_file=$bundle_tar_sha256_file
manifest_file=$manifest_file
EOF

: >"$manifest_file"
manifest_entries=0
while IFS= read -r rel_file; do
  [[ -n "$rel_file" ]] || continue
  write_sha256_line "$bundle_dir/$rel_file" "$rel_file" >>"$manifest_file"
  manifest_entries=$((manifest_entries + 1))
done < <(
  cd "$bundle_dir"
  find . -type f -print \
    | sed 's|^\./||' \
    | grep -v '^manifest\.sha256$' \
    | grep -v '^prod_gate_bundle\.log$' \
    | LC_ALL=C sort
)
echo "[prod-gate-bundle] manifest generated: $manifest_file entries=$manifest_entries"

tar -czf "$bundle_tar" -C "$(dirname "$bundle_dir")" "$(basename "$bundle_dir")"
write_sha256_line "$bundle_tar" "$(basename "$bundle_tar")" >"$bundle_tar_sha256_file"
bundle_tar_sha256="$(cut -d' ' -f1 "$bundle_tar_sha256_file")"

final_rc="$gate_rc"
if [[ "$signoff_check" == "1" && "$signoff_rc" -ne 0 && "$final_rc" -eq 0 ]]; then
  final_rc="$signoff_rc"
fi

echo "[prod-gate-bundle] bundle ready: $bundle_tar"
echo "[prod-gate-bundle] bundle_sha256=$bundle_tar_sha256"
echo "[prod-gate-bundle] gate_rc=$gate_rc"
if [[ "$signoff_check" == "1" ]]; then
  echo "[prod-gate-bundle] signoff_rc=$signoff_rc"
fi
echo "[prod-gate-bundle] final_rc=$final_rc"

exit "$final_rc"
