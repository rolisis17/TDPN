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
FAKE_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_promotion_check.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake profile compare multi-vm stability promotion check: $*"
exit "${FAKE_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_RC:-0}"
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

echo "[easy-node-profile-compare-multi-vm-stability-promotion-check] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh profile-compare-multi-vm-stability-promotion-check [profile_compare_multi_vm_stability_promotion_check args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing profile-compare-multi-vm-stability-promotion-check command contract"
  cat "$HELP_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm-stability-promotion-check] forwarding contract"
: >"$CAPTURE"
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_SCRIPT="$FAKE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_CAPTURE_FILE="$CAPTURE" \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-stability-promotion-check \
  --reports-dir .easy-node-logs/multi_vm_stability_promotion \
  --summary-json .easy-node-logs/profile_compare_multi_vm_stability_promotion_check_summary.json \
  --print-summary-json 1 \
  --sample-arg sample-value >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/multi_vm_stability_promotion' "missing --reports-dir forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/profile_compare_multi_vm_stability_promotion_check_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"
assert_token "$line" $'\t--sample-arg\tsample-value' "missing passthrough arg forwarding"

if ! grep -F -- 'fake profile compare multi-vm stability promotion check:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-profile-compare-multi-vm-stability-promotion-check] exit code contract"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_SCRIPT="$FAKE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_CAPTURE_FILE="$CAPTURE" \
FAKE_PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_CHECK_RC=9 \
bash "$SCRIPT_UNDER_TEST" profile-compare-multi-vm-stability-promotion-check --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 9 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 9, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake profile compare multi-vm stability promotion check: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "easy node profile-compare-multi-vm-stability-promotion-check integration check ok"
