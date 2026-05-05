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
STDERR_OUT="$TMP_DIR/stderr.txt"
FAKE_SCRIPT="$TMP_DIR/fake_runtime_actuation_promotion_cycle.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${RUNTIME_ACTUATION_PROMOTION_CYCLE_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake runtime-actuation promotion cycle: $*"
exit "${FAKE_RUNTIME_ACTUATION_PROMOTION_CYCLE_RC:-0}"
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

echo "[easy-node-runtime-actuation-promotion-cycle] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh runtime-actuation-promotion-cycle [runtime_actuation_promotion_cycle args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing runtime-actuation-promotion-cycle command contract"
  cat "$HELP_OUT"
  exit 1
fi

echo "[easy-node-runtime-actuation-promotion-cycle] forwarding contract"
: >"$CAPTURE"
RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CYCLE_CAPTURE_FILE="$CAPTURE" \
bash "$SCRIPT_UNDER_TEST" runtime-actuation-promotion-cycle \
  --cycles 4 \
  --reports-dir .easy-node-logs/runtime_actuation_promotion_cycle \
  --summary-list .easy-node-logs/runtime_actuation_promotion_cycle_signoff_summaries.list \
  --promotion-summary-json .easy-node-logs/runtime_actuation_promotion_cycle_promotion_summary.json \
  --fail-on-no-go 0 \
  --summary-json .easy-node-logs/runtime_actuation_promotion_cycle_summary.json \
  --print-summary-json 1 \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--cycles\t4' "missing --cycles forwarding"
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/runtime_actuation_promotion_cycle' "missing --reports-dir forwarding"
assert_token "$line" $'\t--summary-list\t.easy-node-logs/runtime_actuation_promotion_cycle_signoff_summaries.list' "missing --summary-list forwarding"
assert_token "$line" $'\t--promotion-summary-json\t.easy-node-logs/runtime_actuation_promotion_cycle_promotion_summary.json' "missing --promotion-summary-json forwarding"
assert_token "$line" $'\t--fail-on-no-go\t0' "missing --fail-on-no-go forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/runtime_actuation_promotion_cycle_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing passthrough arg forwarding"

if ! grep -F -- 'fake runtime-actuation promotion cycle:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-runtime-actuation-promotion-cycle] exit code contract"
set +e
RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_CYCLE_CAPTURE_FILE="$CAPTURE" \
FAKE_RUNTIME_ACTUATION_PROMOTION_CYCLE_RC=9 \
bash "$SCRIPT_UNDER_TEST" runtime-actuation-promotion-cycle --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 9 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 9, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake runtime-actuation promotion cycle: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "easy node runtime-actuation-promotion-cycle integration check ok"
