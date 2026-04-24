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
FAKE_SCRIPT="$TMP_DIR/fake_roadmap_live_evidence_cycle_batch_run.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake roadmap live-evidence-cycle-batch run: $*"
exit "${FAKE_ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_RC:-0}"
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

echo "[easy-node-roadmap-live-evidence-cycle-batch] help contract"
./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh roadmap-live-evidence-cycle-batch-run' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing roadmap-live-evidence-cycle-batch-run command contract"
  cat "$HELP_OUT"
  exit 1
fi
for expected in \
  '--reports-dir DIR' \
  '--summary-json PATH' \
  '--iterations N' \
  '--continue-on-fail [0|1]' \
  '--parallel [0|1]' \
  '--include-track-id ID' \
  '--exclude-track-id ID' \
  '--print-summary-json [0|1]'; do
  if ! grep -F -- "$expected" "$HELP_OUT" >/dev/null 2>&1; then
    echo "easy_node help missing roadmap-live-evidence-cycle-batch-run flag token: $expected"
    cat "$HELP_OUT"
    exit 1
  fi
done
./scripts/easy_node.sh help --expert >"$HELP_EXPERT_OUT"
if ! grep -F -- 'roadmap-live-evidence-cycle-batch-run wraps the roadmap live-evidence cycle-batch helper path' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-live-evidence-cycle-batch-run description"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi
if ! grep -F -- 'roadmap_live_evidence_cycle_batch_run_summary' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-live-evidence-cycle-batch summary schema token"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi
if ! grep -F -- 'selection_accounting' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-live-evidence-cycle-batch selection_accounting token"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi
if ! grep -F -- 'per-iteration track results' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-live-evidence-cycle-batch iteration-results token"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-live-evidence-cycle-batch] env override + forwarding contract"
: >"$CAPTURE"
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh roadmap-live-evidence-cycle-batch-run \
  --reports-dir .easy-node-logs/roadmap_live_evidence_cycle_batch_contract \
  --summary-json .easy-node-logs/roadmap_live_evidence_cycle_batch_contract_summary.json \
  --iterations 2 \
  --continue-on-fail 1 \
  --parallel 1 \
  --include-track-id runtime_actuation_promotion_cycle \
  --exclude-track-id profile_compare_multi_vm_stability_promotion_cycle \
  --print-summary-json 0 >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/roadmap_live_evidence_cycle_batch_contract' "missing --reports-dir forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/roadmap_live_evidence_cycle_batch_contract_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--iterations\t2' "missing --iterations forwarding"
assert_token "$line" $'\t--continue-on-fail\t1' "missing --continue-on-fail forwarding"
assert_token "$line" $'\t--parallel\t1' "missing --parallel forwarding"
assert_token "$line" $'\t--include-track-id\truntime_actuation_promotion_cycle' "missing --include-track-id forwarding"
assert_token "$line" $'\t--exclude-track-id\tprofile_compare_multi_vm_stability_promotion_cycle' "missing --exclude-track-id forwarding"
assert_token "$line" $'\t--print-summary-json\t0' "missing --print-summary-json forwarding"

if ! grep -F -- 'fake roadmap live-evidence-cycle-batch run:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-live-evidence-cycle-batch] output + exit semantics contract"
set +e
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_CAPTURE_FILE="$CAPTURE" \
FAKE_ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_RC=7 \
./scripts/easy_node.sh roadmap-live-evidence-cycle-batch-run --probe-id abc >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 7 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 7, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake roadmap live-evidence-cycle-batch run: --probe-id abc' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-live-evidence-cycle-batch] missing helper script contract"
MISSING_SCRIPT_PATH="$TMP_DIR/does_not_exist_live_cycle_batch.sh"
set +e
ROADMAP_LIVE_EVIDENCE_CYCLE_BATCH_RUN_SCRIPT="$MISSING_SCRIPT_PATH" \
./scripts/easy_node.sh roadmap-live-evidence-cycle-batch-run --probe-id missing >"$STDOUT_OUT" 2>"$STDERR_OUT"
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 2 ]]; then
  echo "expected missing helper script rc=2, got $missing_rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- "missing helper script: $MISSING_SCRIPT_PATH" "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing helper-script error message for roadmap-live-evidence-cycle-batch-run"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

echo "easy node roadmap live evidence cycle batch run integration check ok"
