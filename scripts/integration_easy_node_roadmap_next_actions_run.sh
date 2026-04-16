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

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
HELP_OUT="$TMP_DIR/help.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
STDERR_OUT="$TMP_DIR/stderr.txt"
FAKE_SCRIPT="$TMP_DIR/fake_roadmap_next_actions_run.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ROADMAP_NEXT_ACTIONS_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake roadmap next actions run: $*"
exit "${FAKE_ROADMAP_NEXT_ACTIONS_RUN_RC:-0}"
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

echo "[easy-node-roadmap-next-actions] help contract"
./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh roadmap-next-actions-run [--max-actions N] [--action-timeout-sec N] [--parallel [0|1]] [--allow-profile-default-gate-unreachable [0|1]] [--profile-default-gate-subject ID] [--include-id-prefix PREFIX] [--exclude-id-prefix PREFIX] [roadmap_next_actions_run args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing roadmap-next-actions-run command contract"
  cat "$HELP_OUT"
  exit 1
fi

echo "[easy-node-roadmap-next-actions] env override + forwarding contract"
: >"$CAPTURE"
ROADMAP_NEXT_ACTIONS_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_NEXT_ACTIONS_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh roadmap-next-actions-run \
  --max-actions 2 \
  --action-timeout-sec 9 \
  --parallel 1 \
  --allow-profile-default-gate-unreachable 1 \
  --profile-default-gate-subject inv-forwarded-subject \
  --include-id-prefix blockchain_ \
  --exclude-id-prefix profile_ \
  --reports-dir .easy-node-logs/roadmap_next_actions_contract \
  --summary-json .easy-node-logs/roadmap_next_actions_contract_summary.json \
  --print-summary-json 1 >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--max-actions\t2' "missing --max-actions forwarding"
assert_token "$line" $'\t--action-timeout-sec\t9' "missing --action-timeout-sec forwarding"
assert_token "$line" $'\t--parallel\t1' "missing --parallel forwarding"
assert_token "$line" $'\t--allow-profile-default-gate-unreachable\t1' "missing --allow-profile-default-gate-unreachable forwarding"
assert_token "$line" $'\t--profile-default-gate-subject\tinv-forwarded-subject' "missing --profile-default-gate-subject forwarding"
assert_token "$line" $'\t--include-id-prefix\tblockchain_' "missing --include-id-prefix forwarding"
assert_token "$line" $'\t--exclude-id-prefix\tprofile_' "missing --exclude-id-prefix forwarding"
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/roadmap_next_actions_contract' "missing --reports-dir forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/roadmap_next_actions_contract_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"

if ! grep -F -- 'fake roadmap next actions run:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-next-actions] output + exit semantics contract"
set +e
ROADMAP_NEXT_ACTIONS_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_NEXT_ACTIONS_CAPTURE_FILE="$CAPTURE" \
FAKE_ROADMAP_NEXT_ACTIONS_RUN_RC=7 \
./scripts/easy_node.sh roadmap-next-actions-run --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 7 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 7, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake roadmap next actions run: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "easy node roadmap next-actions run integration check ok"
