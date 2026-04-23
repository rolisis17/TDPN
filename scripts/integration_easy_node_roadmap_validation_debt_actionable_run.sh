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
  '--max-actions N' \
  '--include-id ID' \
  '--exclude-id ID'; do
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

echo "[easy-node-roadmap-validation-debt-actionable] env override + forwarding contract"
: >"$CAPTURE"
ROADMAP_VALIDATION_DEBT_ACTIONABLE_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_VALIDATION_DEBT_ACTIONABLE_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh roadmap-validation-debt-actionable-run \
  --summary-json .easy-node-logs/validation_debt_actionable_contract_summary.json \
  --max-actions 3 >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--summary-json\t.easy-node-logs/validation_debt_actionable_contract_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--max-actions\t3' "missing --max-actions forwarding"

if ! grep -F -- 'fake roadmap validation-debt actionable run: --summary-json .easy-node-logs/validation_debt_actionable_contract_summary.json --max-actions 3' "$STDOUT_OUT" >/dev/null 2>&1; then
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
