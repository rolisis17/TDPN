#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep tail cat mkdir; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/capture.tsv"
HELP_OUT="$TMP_DIR/help.txt"
FAKE_SCRIPT="$TMP_DIR/fake_roadmap_non_blockchain_actionable_run.sh"
PASS_ACTION="$TMP_DIR/pass_action.sh"
FAKE_ROADMAP="$TMP_DIR/fake_roadmap_progress_report.sh"

cat >"$FAKE_SCRIPT" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
capture="${ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"
EOF_FAKE
chmod +x "$FAKE_SCRIPT"

cat >"$PASS_ACTION" <<'EOF_PASS'
#!/usr/bin/env bash
set -euo pipefail
echo "pass action"
EOF_PASS
chmod +x "$PASS_ACTION"

cat >"$FAKE_ROADMAP" <<'EOF_FAKE_ROADMAP'
#!/usr/bin/env bash
set -euo pipefail
summary_json=""
report_md=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -z "$summary_json" || -z "$report_md" ]]; then
  echo "fake roadmap: missing --summary-json or --report-md"
  exit 2
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

reason_mode="${ROADMAP_REASON_SCENARIO:-legacy}"
case "$reason_mode" in
  semantics)
    reason="status=fail, failure.kind=policy_no_go, policy_outcome.decision=NO-GO"
    ;;
  legacy)
    reason="status=fail"
    ;;
  *)
    echo "unknown reason mode: $reason_mode"
    exit 2
    ;;
esac

cat >"$summary_json" <<JSON
{
  "vpn_track": {
    "non_blockchain_recommended_gate_id": "phase1_resilience_handoff_run_dry",
    "non_blockchain_actionable_no_sudo_or_github": [
      {
        "id": "phase1_resilience_handoff_run_dry",
        "label": "Phase 1 resilience handoff run (dry)",
        "command": "bash \"$PASS_ACTION\"",
        "reason": "$reason"
      }
    ]
  }
}
JSON
echo "# fake roadmap report" >"$report_md"
EOF_FAKE_ROADMAP
chmod +x "$FAKE_ROADMAP"

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

echo "[easy-node-roadmap-actionable] help contract"
./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh roadmap-non-blockchain-actionable-run [--recommended-only [0|1]] [--max-actions N] [--action-timeout-sec N] [roadmap_non_blockchain_actionable_run args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help missing roadmap-non-blockchain-actionable-run command contract"
  cat "$HELP_OUT"
  exit 1
fi

echo "[easy-node-roadmap-actionable] forwarding contract"
: >"$CAPTURE"
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_SCRIPT="$FAKE_SCRIPT" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh roadmap-non-blockchain-actionable-run \
  --recommended-only 1 \
  --max-actions 2 \
  --action-timeout-sec 9 \
  --allow-policy-no-go 1 \
  --reports-dir .easy-node-logs/roadmap_actionable_contract

line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$line" ]]; then
  echo "missing forwarded invocation capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$line" $'\t--recommended-only\t1' "missing --recommended-only forwarding"
assert_token "$line" $'\t--max-actions\t2' "missing --max-actions forwarding"
assert_token "$line" $'\t--action-timeout-sec\t9' "missing --action-timeout-sec forwarding"
assert_token "$line" $'\t--allow-policy-no-go\t1' "missing --allow-policy-no-go forwarding"
assert_token "$line" $'\t--reports-dir\t.easy-node-logs/roadmap_actionable_contract' "missing --reports-dir forwarding"

echo "[easy-node-roadmap-actionable] phase1 reason contract (enriched semantics)"
SUMMARY_SEMANTICS="$TMP_DIR/summary_semantics.json"
REPORTS_SEMANTICS="$TMP_DIR/reports_semantics"
ROADMAP_REASON_SCENARIO=semantics \
PASS_ACTION="$PASS_ACTION" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/easy_node.sh roadmap-non-blockchain-actionable-run \
  --recommended-only 1 \
  --max-actions 1 \
  --allow-policy-no-go 1 \
  --reports-dir "$REPORTS_SEMANTICS" \
  --summary-json "$SUMMARY_SEMANTICS" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .inputs.allow_policy_no_go == true
  and .roadmap.recommended_gate_id == "phase1_resilience_handoff_run_dry"
  and ((.actions // []) | length == 1)
  and .actions[0].id == "phase1_resilience_handoff_run_dry"
  and ((.actions[0].allow_policy_no_go_applied // false) == true)
  and ((.actions[0].command // "") | contains("--allow-policy-no-go 1"))
  and ((.actions[0].reason // "") | contains("status=fail"))
  and ((.actions[0].reason // "") | contains("failure.kind="))
  and ((.actions[0].reason // "") | contains("policy_outcome.decision="))
  and ((.actions[0].reason // "") | contains("allow_policy_no_go=1"))
' "$SUMMARY_SEMANTICS" >/dev/null; then
  echo "enriched semantics reason contract mismatch"
  cat "$SUMMARY_SEMANTICS"
  exit 1
fi

echo "[easy-node-roadmap-actionable] phase1 reason contract (legacy compatibility)"
SUMMARY_LEGACY="$TMP_DIR/summary_legacy.json"
REPORTS_LEGACY="$TMP_DIR/reports_legacy"
ROADMAP_REASON_SCENARIO=legacy \
PASS_ACTION="$PASS_ACTION" \
ROADMAP_NON_BLOCKCHAIN_ACTIONABLE_RUN_ROADMAP_SCRIPT="$FAKE_ROADMAP" \
./scripts/easy_node.sh roadmap-non-blockchain-actionable-run \
  --recommended-only 1 \
  --max-actions 1 \
  --reports-dir "$REPORTS_LEGACY" \
  --summary-json "$SUMMARY_LEGACY" \
  --print-summary-json 0

if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .roadmap.recommended_gate_id == "phase1_resilience_handoff_run_dry"
  and ((.actions // []) | length == 1)
  and .actions[0].id == "phase1_resilience_handoff_run_dry"
  and ((.actions[0].reason // "") | contains("status=fail"))
' "$SUMMARY_LEGACY" >/dev/null; then
  echo "legacy reason compatibility contract mismatch"
  cat "$SUMMARY_LEGACY"
  exit 1
fi

echo "easy node roadmap non-blockchain actionable run integration check ok"
