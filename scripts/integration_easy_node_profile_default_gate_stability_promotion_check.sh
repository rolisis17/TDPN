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
FAKE_SCRIPT="$TMP_DIR/fake_profile_default_gate_stability_promotion_check.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CHECK_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile default gate stability promotion check: $*"
exit "${FAKE_PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CHECK_RC:-0}"
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

echo "[easy-node-profile-default-gate-stability-promotion-check] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh profile-default-gate-stability-promotion-check [--cycle-summary-json PATH]... [--cycle-summary-list FILE] [--reports-dir DIR] [--require-min-cycles N] [--require-min-pass-cycles N] [--require-max-fail-cycles N] [--require-max-warn-cycles N] [--require-min-pass-rate-pct N] [--require-min-go-decision-rate-pct N] [--require-check-schema-valid [0|1]] [--require-check-usable-decision [0|1]] [--require-check-policy-modal-decision GO|NO-GO] [--fail-on-no-go [0|1]] [--summary-json PATH] [--print-summary-json [0|1]]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-default-gate-stability-promotion-check command contract"
  cat "$HELP_OUT"
  exit 1
fi

echo "[easy-node-profile-default-gate-stability-promotion-check] forwarding contract"
: >"$CAPTURE"
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CHECK_SCRIPT="$FAKE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_PROMOTION_CHECK_CAPTURE_FILE="$CAPTURE" \
bash "$SCRIPT_UNDER_TEST" profile-default-gate-stability-promotion-check \
  --cycle-summary-json .easy-node-logs/cycle_a.json \
  --cycle-summary-json .easy-node-logs/cycle_b.json \
  --cycle-summary-list .easy-node-logs/cycle_paths.list \
  --reports-dir .easy-node-logs/stability_promotion \
  --require-min-cycles 3 \
  --require-min-pass-cycles 3 \
  --require-max-fail-cycles 0 \
  --require-max-warn-cycles 0 \
  --require-min-pass-rate-pct 100 \
  --require-min-go-decision-rate-pct 100 \
  --require-check-schema-valid 1 \
  --require-check-usable-decision 1 \
  --require-check-policy-modal-decision GO \
  --fail-on-no-go 0 \
  --summary-json .easy-node-logs/profile_default_gate_stability_promotion_check_summary.json \
  --print-summary-json 1 \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--cycle-summary-json\t.easy-node-logs/cycle_a.json' "missing first --cycle-summary-json forwarding"
assert_token "$line" $'\t--cycle-summary-json\t.easy-node-logs/cycle_b.json' "missing second --cycle-summary-json forwarding"
assert_token "$line" $'\t--cycle-summary-list\t.easy-node-logs/cycle_paths.list' "missing --cycle-summary-list forwarding"
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/stability_promotion' "missing --reports-dir forwarding"
assert_token "$line" $'\t--require-min-cycles\t3' "missing --require-min-cycles forwarding"
assert_token "$line" $'\t--require-min-pass-cycles\t3' "missing --require-min-pass-cycles forwarding"
assert_token "$line" $'\t--require-max-fail-cycles\t0' "missing --require-max-fail-cycles forwarding"
assert_token "$line" $'\t--require-max-warn-cycles\t0' "missing --require-max-warn-cycles forwarding"
assert_token "$line" $'\t--require-min-pass-rate-pct\t100' "missing --require-min-pass-rate-pct forwarding"
assert_token "$line" $'\t--require-min-go-decision-rate-pct\t100' "missing --require-min-go-decision-rate-pct forwarding"
assert_token "$line" $'\t--require-check-schema-valid\t1' "missing --require-check-schema-valid forwarding"
assert_token "$line" $'\t--require-check-usable-decision\t1' "missing --require-check-usable-decision forwarding"
assert_token "$line" $'\t--require-check-policy-modal-decision\tGO' "missing --require-check-policy-modal-decision forwarding"
assert_token "$line" $'\t--fail-on-no-go\t0' "missing --fail-on-no-go forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/profile_default_gate_stability_promotion_check_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing passthrough arg forwarding"

if ! grep -F -- 'fake profile default gate stability promotion check:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "easy node profile-default-gate-stability-promotion-check integration check ok"
