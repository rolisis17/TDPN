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
FAKE_SCRIPT="$TMP_DIR/fake_profile_default_gate_stability_run.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_DEFAULT_GATE_STABILITY_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile default gate stability run: $*"
exit "${FAKE_PROFILE_DEFAULT_GATE_STABILITY_RUN_RC:-0}"
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

echo "[easy-node-profile-default-gate-stability-run] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh profile-default-gate-stability-run --host-a HOST --host-b HOST [--campaign-subject ID|--subject ID] [--runs N] [--campaign-timeout-sec N] [--sleep-between-sec N] [--reports-dir DIR] [--summary-json PATH] [--print-summary-json [0|1]] [--allow-partial [0|1]]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-default-gate-stability-run command contract"
  cat "$HELP_OUT"
  exit 1
fi

echo "[easy-node-profile-default-gate-stability-run] forwarding contract"
: >"$CAPTURE"
PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT="$FAKE_SCRIPT" \
PROFILE_DEFAULT_GATE_STABILITY_CAPTURE_FILE="$CAPTURE" \
bash "$SCRIPT_UNDER_TEST" profile-default-gate-stability-run \
  --host-a host-a.example \
  --host-b host-b.example \
  --campaign-subject invite-123 \
  --runs 4 \
  --campaign-timeout-sec 900 \
  --sleep-between-sec 3 \
  --reports-dir .easy-node-logs/stability_contract \
  --summary-json .easy-node-logs/profile_default_gate_stability_contract_summary.json \
  --print-summary-json 1 \
  --allow-partial 0 \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--host-a\thost-a.example' "missing --host-a forwarding"
assert_token "$line" $'\t--host-b\thost-b.example' "missing --host-b forwarding"
assert_token "$line" $'\t--campaign-subject\tinvite-123' "missing --campaign-subject forwarding"
assert_token "$line" $'\t--runs\t4' "missing --runs forwarding"
assert_token "$line" $'\t--campaign-timeout-sec\t900' "missing --campaign-timeout-sec forwarding"
assert_token "$line" $'\t--sleep-between-sec\t3' "missing --sleep-between-sec forwarding"
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/stability_contract' "missing --reports-dir forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/profile_default_gate_stability_contract_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"
assert_token "$line" $'\t--allow-partial\t0' "missing --allow-partial forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing passthrough arg forwarding"

if ! grep -F -- 'fake profile default gate stability run:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "easy node profile-default-gate-stability-run integration check ok"
