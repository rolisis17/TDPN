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
HELP_EXPERT_OUT="$TMP_DIR/help_expert.txt"
STDOUT_OUT="$TMP_DIR/stdout.txt"
STDERR_OUT="$TMP_DIR/stderr.txt"
FAKE_SCRIPT="$TMP_DIR/fake_runtime_actuation_live_evidence_publish_bundle.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail

capture_file="${RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture_file"

expect_value=0
for arg in "$@"; do
  if [[ "$expect_value" -eq 1 ]]; then
    expect_value=0
    continue
  fi
  case "$arg" in
    --reports-dir|--fail-on-no-go|--summary-json|--report-md|--print-summary-json)
      expect_value=1
      ;;
    --*=*)
      flag="${arg%%=*}"
      case "$flag" in
        --reports-dir|--fail-on-no-go|--summary-json|--report-md|--print-summary-json)
          ;;
        *)
          echo "unknown argument: $arg" >&2
          exit 64
          ;;
      esac
      ;;
    --*)
      echo "unknown argument: $arg" >&2
      exit 64
      ;;
    *)
      ;;
  esac
done

if [[ "$expect_value" -eq 1 ]]; then
  echo "missing value for final option" >&2
  exit 64
fi

echo "fake runtime-actuation live evidence publish bundle: $*"
exit "${FAKE_RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RC:-0}"
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

echo "[easy-node-runtime-actuation-live-evidence-publish-bundle] help contract"
bash "$SCRIPT_UNDER_TEST" help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh runtime-actuation-live-evidence-publish-bundle [runtime_actuation_live_evidence_publish_bundle args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing runtime-actuation-live-evidence-publish-bundle command contract"
  cat "$HELP_OUT"
  exit 1
fi
bash "$SCRIPT_UNDER_TEST" help --expert >"$HELP_EXPERT_OUT"
if ! grep -F -- 'runtime-actuation-live-evidence-publish-bundle wraps the runtime-actuation live+publish bundle helper path' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing runtime-actuation live evidence publish bundle description"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi
if ! grep -F -- 'runtime_actuation_live_evidence_publish_bundle_summary' "$HELP_EXPERT_OUT" >/dev/null 2>&1; then
  echo "easy_node expert help missing runtime-actuation live evidence publish summary schema token"
  cat "$HELP_EXPERT_OUT"
  exit 1
fi

echo "[easy-node-runtime-actuation-live-evidence-publish-bundle] forwarding contract"
: >"$CAPTURE"
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_SCRIPT="$FAKE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_CAPTURE_FILE="$CAPTURE" \
bash "$SCRIPT_UNDER_TEST" runtime-actuation-live-evidence-publish-bundle \
  --reports-dir .easy-node-logs/runtime_actuation_live_bundle_contract \
  --fail-on-no-go 0 \
  --summary-json .easy-node-logs/runtime_actuation_live_bundle_contract_summary.json \
  --report-md .easy-node-logs/runtime_actuation_live_bundle_contract_report.md \
  --print-summary-json 1 >"$STDOUT_OUT"

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/runtime_actuation_live_bundle_contract' "missing --reports-dir forwarding"
assert_token "$line" $'\t--fail-on-no-go\t0' "missing --fail-on-no-go forwarding"
assert_token "$line" $'\t--summary-json\t.easy-node-logs/runtime_actuation_live_bundle_contract_summary.json' "missing --summary-json forwarding"
assert_token "$line" $'\t--report-md\t.easy-node-logs/runtime_actuation_live_bundle_contract_report.md' "missing --report-md forwarding"
assert_token "$line" $'\t--print-summary-json\t1' "missing --print-summary-json forwarding"

if ! grep -F -- 'fake runtime-actuation live evidence publish bundle:' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing wrapper output from fake script"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-runtime-actuation-live-evidence-publish-bundle] output + exit semantics contract"
set +e
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_SCRIPT="$FAKE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_CAPTURE_FILE="$CAPTURE" \
FAKE_RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_RC=7 \
bash "$SCRIPT_UNDER_TEST" runtime-actuation-live-evidence-publish-bundle --reports-dir .easy-node-logs --fail-on-no-go 1 >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 7 ]]; then
  echo "expected easy_node wrapper to return fake script exit code 7, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'fake runtime-actuation live evidence publish bundle: --reports-dir .easy-node-logs --fail-on-no-go 1' "$STDOUT_OUT" >/dev/null 2>&1; then
  echo "missing forwarded output text for non-zero exit contract"
  cat "$STDOUT_OUT"
  exit 1
fi

echo "[easy-node-runtime-actuation-live-evidence-publish-bundle] unknown args fail contract"
set +e
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_SCRIPT="$FAKE_SCRIPT" \
RUNTIME_ACTUATION_LIVE_EVIDENCE_PUBLISH_BUNDLE_CAPTURE_FILE="$CAPTURE" \
bash "$SCRIPT_UNDER_TEST" runtime-actuation-live-evidence-publish-bundle --totally-unknown 1 >"$STDOUT_OUT" 2>"$STDERR_OUT"
rc=$?
set -e
if [[ "$rc" -ne 64 ]]; then
  echo "expected easy_node wrapper to return fake script unknown-arg exit code 64, got $rc"
  cat "$STDOUT_OUT"
  cat "$STDERR_OUT"
  exit 1
fi
if ! grep -F -- 'unknown argument: --totally-unknown' "$STDERR_OUT" >/dev/null 2>&1; then
  echo "missing unknown argument failure text for explicit unknown arg"
  cat "$STDERR_OUT"
  exit 1
fi

echo "easy node runtime-actuation-live-evidence-publish-bundle integration check ok"
