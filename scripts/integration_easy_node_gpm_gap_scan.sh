#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod wc sed cat grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${EASY_NODE_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/easy_node.sh}"
if [[ ! -x "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing executable script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE_FILE="$TMP_DIR/capture.tsv"
FAKE_WRAPPER="$TMP_DIR/fake_gpm_gap_scan.sh"

cat >"$FAKE_WRAPPER" <<'EOF_FAKE_WRAPPER'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${EASY_NODE_GPM_GAP_SCAN_CAPTURE_FILE:?}"
{
  printf 'gpm_gap_scan'
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
EOF_FAKE_WRAPPER
chmod +x "$FAKE_WRAPPER"

assert_help_includes_command_token() {
  local help_output="$1"
  local command_token="$2"

  if ! grep -Fq -- "$command_token" <<<"$help_output"; then
    echo "help output missing command token: $command_token"
    printf '%s\n' "$help_output"
    exit 1
  fi
}

assert_single_invocation() {
  local capture_file="$1"
  local count

  count="$(wc -l <"$capture_file")"
  count="${count//[[:space:]]/}"
  if [[ "$count" != "1" ]]; then
    echo "expected exactly one wrapper invocation, got $count"
    cat "$capture_file"
    exit 1
  fi
}

assert_forwarded_args() {
  local capture_file="$1"
  local expected_reports_dir="$2"
  local expected_summary_json="$3"
  local expected_custom="$4"
  local line
  local -a fields=()

  line="$(sed -n '1p' "$capture_file" || true)"
  if [[ -z "$line" ]]; then
    echo "missing forwarded invocation payload"
    cat "$capture_file"
    exit 1
  fi

  IFS=$'\t' read -r -a fields <<<"$line"
  if [[ "${fields[0]:-}" != "gpm_gap_scan" ]]; then
    echo "forwarded marker mismatch"
    echo "$line"
    exit 1
  fi

  if [[ "${#fields[@]}" -ne 7 ]]; then
    echo "unexpected forwarded arg count: expected 7 got ${#fields[@]}"
    echo "$line"
    exit 1
  fi

  if [[ "${fields[1]:-}" != "--reports-dir" || "${fields[2]:-}" != "$expected_reports_dir" ]]; then
    echo "forwarded --reports-dir mismatch"
    echo "$line"
    exit 1
  fi

  if [[ "${fields[3]:-}" != "--summary-json" || "${fields[4]:-}" != "$expected_summary_json" ]]; then
    echo "forwarded --summary-json mismatch"
    echo "$line"
    exit 1
  fi

  if [[ "${fields[5]:-}" != "--sample-arg" || "${fields[6]:-}" != "$expected_custom" ]]; then
    echo "forwarded custom arg mismatch"
    echo "$line"
    exit 1
  fi
}

assert_unknown_command_behavior() {
  local unknown_command="$1"
  local unknown_log="$TMP_DIR/unknown_command.log"
  local rc

  set +e
  bash "$SCRIPT_UNDER_TEST" "$unknown_command" >"$unknown_log" 2>&1
  rc=$?
  set -e

  if [[ "$rc" -ne 2 ]]; then
    echo "expected unknown command to exit 2, got rc=$rc"
    cat "$unknown_log"
    exit 1
  fi

  if ! grep -Fq -- "unknown command: $unknown_command" "$unknown_log"; then
    echo "unknown command message regression"
    cat "$unknown_log"
    exit 1
  fi
}

HELP_OUTPUT="$(bash "$SCRIPT_UNDER_TEST" --help)"
assert_help_includes_command_token "$HELP_OUTPUT" "gpm-gap-scan"
HELP_EXPERT_OUTPUT="$(bash "$SCRIPT_UNDER_TEST" --help --expert)"
assert_help_includes_command_token "$HELP_EXPERT_OUTPUT" "gpm-gap-scan wraps the GPM gap-scan helper path"

: >"$CAPTURE_FILE"
(
  cd "$TMP_DIR"
  GPM_GAP_SCAN_SCRIPT="$FAKE_WRAPPER" \
  EASY_NODE_GPM_GAP_SCAN_CAPTURE_FILE="$CAPTURE_FILE" \
  bash "$SCRIPT_UNDER_TEST" gpm-gap-scan --reports-dir fixture-reports --summary-json fixture-summary.json --sample-arg "value with spaces" >/dev/null 2>&1
)

assert_single_invocation "$CAPTURE_FILE"
assert_forwarded_args "$CAPTURE_FILE" "fixture-reports" "fixture-summary.json" "value with spaces"
assert_unknown_command_behavior "worker-d-gap-scan-unknown-command-fixture"

echo "integration_easy_node_gpm_gap_scan: PASS"
