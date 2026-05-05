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
if ! command -v timeout >/dev/null 2>&1; then
  echo "missing required command: timeout"
  echo "install GNU coreutils timeout (required to bound easy_node wrapper invocations)"
  exit 2
fi

EASY_NODE_WRAPPER_TIMEOUT_SEC="${EASY_NODE_WRAPPER_TIMEOUT_SEC:-120}"
if ! [[ "$EASY_NODE_WRAPPER_TIMEOUT_SEC" =~ ^[0-9]+$ ]] || [[ "$EASY_NODE_WRAPPER_TIMEOUT_SEC" == "0" ]]; then
  echo "EASY_NODE_WRAPPER_TIMEOUT_SEC must be a positive integer (seconds)"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
HELP_OUT="$TMP_DIR/help.txt"
HELP_EXPERT_OUT="$TMP_DIR/help_expert.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
STDERR_OUT="$TMP_DIR/stderr.txt"
FAKE_SCRIPT="$TMP_DIR/fake_roadmap_live_evidence_archive_run.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture_file="${ROADMAP_LIVE_EVIDENCE_ARCHIVE_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"
echo "fake roadmap live-evidence archive run: $*"
exit "${FAKE_ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_RC:-0}"
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

run_easy_node_bounded() {
  local stdout_path="$1"
  local stderr_path="$2"
  shift 2

  local errexit_was_set=0
  if [[ "$-" == *e* ]]; then
    errexit_was_set=1
    set +e
  fi
  local rc=0
  timeout --foreground "${EASY_NODE_WRAPPER_TIMEOUT_SEC}s" ./scripts/easy_node.sh "$@" >"$stdout_path" 2>"$stderr_path"
  rc=$?
  if [[ "$errexit_was_set" -eq 1 ]]; then
    set -e
  fi

  if [[ "$rc" -eq 124 || "$rc" -eq 137 ]]; then
    echo "easy_node wrapper timed out after ${EASY_NODE_WRAPPER_TIMEOUT_SEC}s: ./scripts/easy_node.sh $*"
    echo "captured stdout:"
    cat "$stdout_path" 2>/dev/null || true
    echo "captured stderr:"
    cat "$stderr_path" 2>/dev/null || true
    exit 1
  fi

  return "$rc"
}

echo "[easy-node-roadmap-live-evidence-archive] help contract"
if ! run_easy_node_bounded "$HELP_OUT" "$STDERR_OUT" help; then
  echo "easy_node help command failed unexpectedly"
  cat "$HELP_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- './scripts/easy_node.sh roadmap-live-evidence-archive-run' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing roadmap-live-evidence-archive-run command contract"
  cat "$HELP_OUT"
  exit 1
fi
if ! run_easy_node_bounded "$HELP_EXPERT_OUT" "$STDERR_OUT" help --expert; then
  echo "easy_node expert help command failed unexpectedly"
  cat "$HELP_EXPERT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'roadmap-live-evidence-archive-run wraps the roadmap live-evidence archive helper path' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-live-evidence-archive-run description"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi
if ! grep -F -- 'ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_SCRIPT' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing roadmap-live-evidence-archive override token"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-live-evidence-archive] env override + forwarding contract"
: >"$CAPTURE"
if ! ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_LIVE_EVIDENCE_ARCHIVE_CAPTURE_FILE="$CAPTURE" \
run_easy_node_bounded "$STDOUT_OUT" "$STDERR_OUT" roadmap-live-evidence-archive-run \
  --reports-dir .easy-node-logs/roadmap_live_evidence_archive_contract \
  --roadmap-summary-json .easy-node-logs/roadmap_live_evidence_archive_contract_roadmap.json \
  --archive-root .easy-node-logs/roadmap_live_evidence_archive_contract_archive \
  --scope runtime-actuation \
  --missing-source-policy fail \
  --summary-json .easy-node-logs/roadmap_live_evidence_archive_contract_summary.json \
  --print-summary-json 1; then
  echo "easy_node roadmap-live-evidence-archive-run contract invocation failed unexpectedly"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/roadmap_live_evidence_archive_contract' "missing --reports-dir forwarding"
assert_token "$line" $'\t--roadmap-summary-json\t.easy-node-logs/roadmap_live_evidence_archive_contract_roadmap.json' "missing --roadmap-summary-json forwarding"
assert_token "$line" $'\t--archive-root\t.easy-node-logs/roadmap_live_evidence_archive_contract_archive' "missing --archive-root forwarding"
assert_token "$line" $'\t--scope\truntime-actuation' "missing --scope forwarding"
assert_token "$line" $'\t--missing-source-policy\tfail' "missing --missing-source-policy forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/roadmap_live_evidence_archive_contract_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"
if ! grep -F -- 'fake roadmap live-evidence archive run:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-live-evidence-archive] output + exit semantics contract"
set +e
ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_LIVE_EVIDENCE_ARCHIVE_CAPTURE_FILE="$CAPTURE" \
FAKE_ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_RC=7 \
run_easy_node_bounded "$STDOUT_OUT" "$STDERR_OUT" roadmap-live-evidence-archive-run --probe-id abc
rc=$?
set -e
if [[ "$rc" -ne 7 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 7, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake roadmap live-evidence archive run: --probe-id abc' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-roadmap-live-evidence-archive] missing helper script contract"
MISSING_SCRIPT_PATH="$TMP_DIR/does_not_exist_live_evidence_archive.sh"
set +e
ROADMAP_LIVE_EVIDENCE_ARCHIVE_RUN_SCRIPT="$MISSING_SCRIPT_PATH" \
run_easy_node_bounded "$STDOUT_OUT" "$STDERR_OUT" roadmap-live-evidence-archive-run --probe-id missing
missing_rc=$?
set -e
if [[ "$missing_rc" -ne 2 ]]; then
  echo "expected missing helper script rc=2, got $missing_rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- "missing helper script: $MISSING_SCRIPT_PATH" "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing helper-script error message for roadmap-live-evidence-archive-run"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi

echo "easy node roadmap live evidence archive run integration check ok"
