#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod grep tail cat; do
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

CAPTURE="$TMP_DIR/capture.tsv"
HELP_OUT="$TMP_DIR/help.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
FAKE_SCRIPT="$TMP_DIR/fake_profile_default_gate_stability_check.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_DEFAULT_GATE_STABILITY_CHECK_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile default gate stability check: $*"
exit "${FAKE_PROFILE_DEFAULT_GATE_STABILITY_CHECK_RC:-0}"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

assert_token() {
  local line="$1"
  local token="$2"
  local message="$3"
  if [[ "$line" != *"$token"* ]]; then
    echo "$message"
    echo "line: $line"
    echo "capture:"
    cat "$CAPTURE"
    exit 1
  fi
}

echo "[easy-node-profile-default-gate-stability-check] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh profile-default-gate-stability-check --stability-summary-json PATH [--require-stability-ok [0|1]] [--require-min-runs-completed N] [--require-modal-support-rate-pct N] [--fail-on-no-go [0|1]] [--summary-json PATH] [--print-summary-json [0|1]]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-default-gate-stability-check command contract"
  cat "$HELP_OUT"
  exit 1
fi

echo "[easy-node-profile-default-gate-stability-check] forwarding contract"
: >"$CAPTURE"
PROFILE_DEFAULT_GATE_STABILITY_CHECK_SCRIPT="$FAKE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CHECK_CAPTURE_FILE="$CAPTURE" \
bash "$SCRIPT_UNDER_TEST" profile-default-gate-stability-check \
  --stability-summary-json .easy-node-logs/profile_default_gate_stability_summary.json \
  --require-stability-ok 1 \
  --require-min-runs-completed 3 \
  --require-modal-support-rate-pct 66.67 \
  --fail-on-no-go 0 \
  --summary-json .easy-node-logs/profile_default_gate_stability_check_summary.json \
  --print-summary-json 1 \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--stability-summary-json\t.easy-node-logs/profile_default_gate_stability_summary.json' "missing --stability-summary-json forwarding"
assert_token "$line" $'\t--require-stability-ok\t1' "missing --require-stability-ok forwarding"
assert_token "$line" $'\t--require-min-runs-completed\t3' "missing --require-min-runs-completed forwarding"
assert_token "$line" $'\t--require-modal-support-rate-pct\t66.67' "missing --require-modal-support-rate-pct forwarding"
assert_token "$line" $'\t--fail-on-no-go\t0' "missing --fail-on-no-go forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/profile_default_gate_stability_check_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing passthrough arg forwarding"

if ! grep -F -- 'fake profile default gate stability check:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "easy node profile-default-gate-stability-check integration check ok"
