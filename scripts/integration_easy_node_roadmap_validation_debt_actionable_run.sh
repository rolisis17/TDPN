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
HELP_EXPERT_OUT="$TMP_DIR/help_expert.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
STDERR_OUT="$TMP_DIR/stderr.txt"
FAKE_SCRIPT="$TMP_DIR/fake_roadmap_validation_debt_actionable_run.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ROADMAP_VALIDATION_DEBT_ACTIONABLE_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake roadmap validation-debt actionable run: $*"
exit "${FAKE_ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_RC:-0}"
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

echo "[easy-node-roadmap-validation-debt-actionable] help contract"
./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh roadmap-validation-debt-actionable-run' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing roadmap-validation-debt-actionable-run command contract"
  cat "$HELP_OUT"
  exit 1
fi
for expected in \
  '--reports-dir DIR' \
  '--summary-json PATH' \
  '--parallel [0|1]' \
  '--max-actions N' \
  '--include-id ID' \
  '--exclude-id ID' \
  '--print-summary-json [0|1]'; do
  if ! grep -F -- "$expected" "$HELP_OUT" >/dev/null 2>&1; then
    echo "easy_node help missing roadmap-validation-debt-actionable-run flag token: $expected"
    cat "$HELP_OUT"
    exit 1
  fi
done
./scripts/easy_node.sh help --expert >"$HELP_EXPERT_OUT"
if ! grep -F -- 'roadmap-validation-debt-actionable-run wraps the roadmap validation-debt actionable helper path' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-validation-debt-actionable-run description"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi
if ! grep -F -- 'roadmap_validation_debt_actionable_run_summary' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-validation-debt-actionable summary schema token"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi
if ! grep -F -- 'selection_accounting' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-validation-debt-actionable selection_accounting token"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi
if ! grep -F -- 'checks_catalog' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-validation-debt-actionable checks_catalog token"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-validation-debt-actionable] env override + forwarding contract"
: >"$CAPTURE"
ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh roadmap-validation-debt-actionable-run \
  --reports-dir .easy-node-logs/validation_debt_actionable_contract \
  --summary-json .easy-node-logs/validation_debt_actionable_contract_summary.json \
  --parallel 1 \
  --include-id m3_three_machine_real_host_validation_pack \
  --exclude-id m1_client_3hop_runtime \
  --max-actions 3 \
  --print-summary-json 0 >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/validation_debt_actionable_contract' "missing --reports-dir forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/validation_debt_actionable_contract_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--parallel\t1' "missing --parallel forwarding"
assert_token "$line" $'\t--include-id\tm3_three_machine_real_host_validation_pack' "missing --include-id forwarding"
assert_token "$line" $'\t--exclude-id\tm1_client_3hop_runtime' "missing --exclude-id forwarding"
assert_token "$line" $'\t--max-actions\t3' "missing --max-actions forwarding"
assert_token "$line" $'\t--print-summary-json\t0' "missing --print-summary-json forwarding"

if ! grep -F -- 'fake roadmap validation-debt actionable run:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-validation-debt-actionable] output + exit semantics contract"
set +e
ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CAPTURE_FILE="$CAPTURE" \
FAKE_ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_RC=9 \
./scripts/easy_node.sh roadmap-validation-debt-actionable-run --probe debt >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 9 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 9, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake roadmap validation-debt actionable run: --probe debt' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-validation-debt-actionable] missing helper script contract"
MISSING_SCRIPT_PATH="$TMP_DIR/does_not_exist_validation_debt.sh"
set +e
ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_SCRIPT="$MISSING_SCRIPT_PATH" \
./scripts/easy_node.sh roadmap-validation-debt-actionable-run --probe missing >"$STDOUT_OUT" 2>"$STDERR_OUT"
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 2 ]]; then
  echo "expected missing helper script rc=2, got $missing_rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- "missing helper script: $MISSING_SCRIPT_PATH" "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing helper-script error message for roadmap-validation-debt-actionable-run"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

echo "easy node roadmap validation debt actionable run integration check ok"
