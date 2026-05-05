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
FAKE_SCRIPT="$TMP_DIR/fake_roadmap_live_evidence_actionable_run.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ROADMAP_LIVE_EVIDENCE_ACTIONABLE_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake roadmap live evidence actionable run: $*"
exit "${FAKE_ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_RC:-0}"
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

echo "[easy-node-roadmap-live-evidence-actionable] help contract"
./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh roadmap-live-evidence-actionable-run' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing roadmap-live-evidence-actionable-run command contract"
  cat "$HELP_OUT"
  exit 1
fi
for expected in \
  '--roadmap-summary-json PATH' \
  '--roadmap-report-md PATH' \
  '--action-timeout-sec N' \
  '--allow-unsafe-shell-commands [0|1]' \
  '--refresh-manual-validation [0|1]' \
  '--refresh-single-machine-readiness [0|1]' \
  '--max-actions N' \
  '--parallel [0|1]' \
  '--print-summary-json [0|1]'; do
  if ! grep -F -- "$expected" "$HELP_OUT" >/dev/null 2>&1; then
    echo "easy_node help missing roadmap-live-evidence-actionable-run flag token: $expected"
    cat "$HELP_OUT"
    exit 1
  fi
done
./scripts/easy_node.sh help --expert >"$HELP_EXPERT_OUT"
if ! grep -F -- 'roadmap-live-evidence-actionable-run wraps the roadmap live-evidence actionable helper path' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-live-evidence-actionable-run description"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi
if ! grep -F -- 'roadmap_live_evidence_actionable_run_summary' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-live-evidence summary schema token"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-live-evidence-actionable] env override + forwarding contract"
: >"$CAPTURE"
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh roadmap-live-evidence-actionable-run \
  --reports-dir .easy-node-logs/roadmap_live_evidence_actionable_contract \
  --summary-json .easy-node-logs/roadmap_live_evidence_actionable_contract_summary.json \
  --print-summary-json 1 \
  --max-actions 2 \
  --parallel 1 >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/roadmap_live_evidence_actionable_contract' "missing --reports-dir forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/roadmap_live_evidence_actionable_contract_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"
assert_token "$line" $'\t--max-actions\t2' "missing --max-actions forwarding"
assert_token "$line" $'\t--parallel\t1' "missing --parallel forwarding"

if ! grep -F -- 'fake roadmap live evidence actionable run:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-live-evidence-actionable] output + exit semantics contract"
set +e
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_LIVE_EVIDENCE_ACTIONABLE_CAPTURE_FILE="$CAPTURE" \
FAKE_ROADMAP_LIVE_EVIDENCE_ACTIONABLE_RUN_RC=7 \
./scripts/easy_node.sh roadmap-live-evidence-actionable-run --sample-arg boom >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 7 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 7, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake roadmap live evidence actionable run: --sample-arg boom' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "easy node roadmap live evidence actionable run integration check ok"
