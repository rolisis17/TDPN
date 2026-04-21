#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat grep chmod; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_DEFAULT_GATE_STABILITY_RUN_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_default_gate_stability_run.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

FAKE_EASY_NODE="$TMP_DIR/fake_easy_node.sh"
cat >"$FAKE_EASY_NODE" <<'EOF_FAKE_EASY_NODE'
#!/usr/bin/env bash
set -euo pipefail

counter_file="${FAKE_EASY_NODE_COUNTER_FILE:?}"
capture_file="${FAKE_EASY_NODE_CAPTURE_FILE:-}"
scenario="${FAKE_EASY_NODE_SCENARIO:-stable}"

if [[ $# -lt 1 || "${1:-}" != "profile-default-gate-live" ]]; then
  echo "unexpected fake easy_node command: $*" >&2
  exit 2
fi
shift

summary_json=""
host_a=""
host_b=""
campaign_subject=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*)
      summary_json="${1#*=}"
      shift
      ;;
    --host-a)
      host_a="${2:-}"
      shift 2
      ;;
    --host-a=*)
      host_a="${1#*=}"
      shift
      ;;
    --host-b)
      host_b="${2:-}"
      shift 2
      ;;
    --host-b=*)
      host_b="${1#*=}"
      shift
      ;;
    --campaign-subject)
      campaign_subject="${2:-}"
      shift 2
      ;;
    --campaign-subject=*)
      campaign_subject="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake easy_node requires --summary-json" >&2
  exit 2
fi

run_index=0
if [[ -f "$counter_file" ]]; then
  run_index="$(cat "$counter_file" 2>/dev/null || echo "0")"
fi
if ! [[ "$run_index" =~ ^[0-9]+$ ]]; then
  run_index="0"
fi
run_index=$((run_index + 1))
printf '%s' "$run_index" >"$counter_file"

sticky_pair_sec=300
entry_rotation_sec=180
entry_rotation_jitter_pct=15
exit_exploration_pct=10
path_profile="2hop"
decision_value="GO"

if [[ "$scenario" == "mismatch" && "$run_index" -eq 2 ]]; then
  sticky_pair_sec=420
  entry_rotation_sec=240
  entry_rotation_jitter_pct=10
  exit_exploration_pct=5
  path_profile="3hop"
fi
if [[ "$scenario" == "mixed_decision" && "$run_index" -eq 2 ]]; then
  decision_value="NO-GO"
fi

campaign_summary_json="${summary_json%.json}_campaign_summary.json"
mkdir -p "$(dirname "$summary_json")"
mkdir -p "$(dirname "$campaign_summary_json")"

jq -n \
  --argjson sticky_pair_sec "$sticky_pair_sec" \
  --argjson entry_rotation_sec "$entry_rotation_sec" \
  --argjson entry_rotation_jitter_pct "$entry_rotation_jitter_pct" \
  --argjson exit_exploration_pct "$exit_exploration_pct" \
  --arg path_profile "$path_profile" \
  '{
    summary: {
      selection_policy: {
        sticky_pair_sec: $sticky_pair_sec,
        entry_rotation_sec: $entry_rotation_sec,
        entry_rotation_jitter_pct: $entry_rotation_jitter_pct,
        exit_exploration_pct: $exit_exploration_pct,
        path_profile: $path_profile
      }
    }
  }' >"$campaign_summary_json"

jq -n \
  --arg campaign_summary_json "$campaign_summary_json" \
  --arg decision_value "$decision_value" \
  '{
    status: "ok",
    final_rc: 0,
    decision: {
      decision: $decision_value,
      recommended_profile: "balanced",
      support_rate_pct: 88.5
    },
    artifacts: {
      campaign_summary_json: $campaign_summary_json
    }
  }' >"$summary_json"

if [[ -n "$capture_file" ]]; then
  printf 'profile-default-gate-live\trun=%s\thost_a=%s\thost_b=%s\tsubject=%s\tsummary_json=%s\n' \
    "$run_index" \
    "$host_a" \
    "$host_b" \
    "$campaign_subject" \
    "$summary_json" >>"$capture_file"
fi

exit 0
EOF_FAKE_EASY_NODE
chmod +x "$FAKE_EASY_NODE"

echo "[profile-default-gate-stability-run] stable policy path"
STABLE_SUMMARY="$TMP_DIR/stable_summary.json"
STABLE_REPORTS_DIR="$TMP_DIR/reports_stable"
STABLE_COUNTER="$TMP_DIR/stable_counter.txt"
STABLE_CAPTURE="$TMP_DIR/stable_capture.log"
set +e
PROFILE_DEFAULT_GATE_STABILITY_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_EASY_NODE_COUNTER_FILE="$STABLE_COUNTER" \
FAKE_EASY_NODE_CAPTURE_FILE="$STABLE_CAPTURE" \
FAKE_EASY_NODE_SCENARIO="stable" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "host-a.test" \
  --host-b "host-b.test" \
  --campaign-subject "inv-stable" \
  --runs 3 \
  --campaign-timeout-sec 2400 \
  --sleep-between-sec 0 \
  --reports-dir "$STABLE_REPORTS_DIR" \
  --summary-json "$STABLE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_run_stable.log 2>&1
stable_rc=$?
set -e

if [[ "$stable_rc" -ne 0 ]]; then
  echo "expected stable path rc=0, got rc=$stable_rc"
  cat /tmp/integration_profile_default_gate_stability_run_stable.log
  exit 1
fi
if [[ ! -f "$STABLE_SUMMARY" ]]; then
  echo "expected stable summary JSON artifact missing"
  cat /tmp/integration_profile_default_gate_stability_run_stable.log
  exit 1
fi
if ! jq -e '
  .schema.id == "profile_default_gate_stability_summary"
  and .runs_total == 3
  and .runs_completed == 3
  and .runs_pass == 3
  and .runs_fail == 0
  and .selection_policy_present_all == true
  and .consistent_selection_policy == true
  and .stability_ok == true
  and .recommended_profile_counts.balanced == 3
  and .decision_counts.GO == 3
  and .decision_total == 3
  and .modal_decision == "GO"
  and .modal_decision_count == 3
  and (.modal_decision_support_rate_pct >= 99.9)
  and .decision_consensus == true
  and (.runs | length) == 3
' "$STABLE_SUMMARY" >/dev/null 2>&1; then
  echo "stable summary JSON missing expected fields"
  cat "$STABLE_SUMMARY"
  exit 1
fi
stable_counter_value="$(cat "$STABLE_COUNTER" 2>/dev/null || echo "0")"
if [[ "$stable_counter_value" != "3" ]]; then
  echo "expected stable fake easy_node run count to be 3, got: $stable_counter_value"
  cat "$STABLE_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-stability-run] --subject alias path"
ALIAS_SUMMARY="$TMP_DIR/alias_summary.json"
ALIAS_REPORTS_DIR="$TMP_DIR/reports_alias"
ALIAS_COUNTER="$TMP_DIR/alias_counter.txt"
ALIAS_CAPTURE="$TMP_DIR/alias_capture.log"
set +e
PROFILE_DEFAULT_GATE_STABILITY_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_EASY_NODE_COUNTER_FILE="$ALIAS_COUNTER" \
FAKE_EASY_NODE_CAPTURE_FILE="$ALIAS_CAPTURE" \
FAKE_EASY_NODE_SCENARIO="stable" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "host-a.test" \
  --host-b "host-b.test" \
  --subject "inv-alias" \
  --runs 1 \
  --campaign-timeout-sec 2400 \
  --sleep-between-sec 0 \
  --reports-dir "$ALIAS_REPORTS_DIR" \
  --summary-json "$ALIAS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_run_alias.log 2>&1
alias_rc=$?
set -e

if [[ "$alias_rc" -ne 0 ]]; then
  echo "expected --subject alias path rc=0, got rc=$alias_rc"
  cat /tmp/integration_profile_default_gate_stability_run_alias.log
  exit 1
fi
if ! grep -q $'subject=inv-alias' "$ALIAS_CAPTURE"; then
  echo "expected alias subject to be forwarded"
  cat "$ALIAS_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-stability-run] conflicting --campaign-subject/--subject is rejected"
set +e
PROFILE_DEFAULT_GATE_STABILITY_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_EASY_NODE_COUNTER_FILE="$TMP_DIR/conflict_counter.txt" \
FAKE_EASY_NODE_CAPTURE_FILE="$TMP_DIR/conflict_capture.log" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "host-a.test" \
  --host-b "host-b.test" \
  --campaign-subject "inv-one" \
  --subject "inv-two" \
  --runs 1 \
  --campaign-timeout-sec 2400 \
  --sleep-between-sec 0 \
  --reports-dir "$TMP_DIR/reports_conflict" \
  --summary-json "$TMP_DIR/conflict_summary.json" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_run_conflict.log 2>&1
conflict_rc=$?
set -e

if [[ "$conflict_rc" -ne 2 ]]; then
  echo "expected conflicting subject values to return rc=2, got rc=$conflict_rc"
  cat /tmp/integration_profile_default_gate_stability_run_conflict.log
  exit 1
fi
if ! grep -q 'conflicting subject values' /tmp/integration_profile_default_gate_stability_run_conflict.log; then
  echo "expected conflicting subject error message not found"
  cat /tmp/integration_profile_default_gate_stability_run_conflict.log
  exit 1
fi

echo "[profile-default-gate-stability-run] mismatched policy path"
MISMATCH_SUMMARY="$TMP_DIR/mismatch_summary.json"
MISMATCH_REPORTS_DIR="$TMP_DIR/reports_mismatch"
MISMATCH_COUNTER="$TMP_DIR/mismatch_counter.txt"
MISMATCH_CAPTURE="$TMP_DIR/mismatch_capture.log"
set +e
PROFILE_DEFAULT_GATE_STABILITY_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_EASY_NODE_COUNTER_FILE="$MISMATCH_COUNTER" \
FAKE_EASY_NODE_CAPTURE_FILE="$MISMATCH_CAPTURE" \
FAKE_EASY_NODE_SCENARIO="mismatch" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "host-a.test" \
  --host-b "host-b.test" \
  --campaign-subject "inv-mismatch" \
  --runs 3 \
  --campaign-timeout-sec 2400 \
  --sleep-between-sec 0 \
  --reports-dir "$MISMATCH_REPORTS_DIR" \
  --summary-json "$MISMATCH_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_run_mismatch.log 2>&1
mismatch_rc=$?
set -e

if [[ "$mismatch_rc" -ne 0 ]]; then
  echo "expected mismatch path rc=0, got rc=$mismatch_rc"
  cat /tmp/integration_profile_default_gate_stability_run_mismatch.log
  exit 1
fi
if [[ ! -f "$MISMATCH_SUMMARY" ]]; then
  echo "expected mismatch summary JSON artifact missing"
  cat /tmp/integration_profile_default_gate_stability_run_mismatch.log
  exit 1
fi
if ! jq -e '
  .runs_total == 3
  and .runs_completed == 3
  and .selection_policy_present_all == true
  and .consistent_selection_policy == false
  and .stability_ok == false
' "$MISMATCH_SUMMARY" >/dev/null 2>&1; then
  echo "mismatch summary JSON missing expected inconsistency markers"
  cat "$MISMATCH_SUMMARY"
  exit 1
fi
mismatch_counter_value="$(cat "$MISMATCH_COUNTER" 2>/dev/null || echo "0")"
if [[ "$mismatch_counter_value" != "3" ]]; then
  echo "expected mismatch fake easy_node run count to be 3, got: $mismatch_counter_value"
  cat "$MISMATCH_CAPTURE"
  exit 1
fi

echo "[profile-default-gate-stability-run] mixed decision evidence"
MIXED_DECISION_SUMMARY="$TMP_DIR/mixed_decision_summary.json"
MIXED_DECISION_REPORTS_DIR="$TMP_DIR/reports_mixed_decision"
MIXED_DECISION_COUNTER="$TMP_DIR/mixed_decision_counter.txt"
MIXED_DECISION_CAPTURE="$TMP_DIR/mixed_decision_capture.log"
set +e
PROFILE_DEFAULT_GATE_STABILITY_EASY_NODE_SCRIPT="$FAKE_EASY_NODE" \
FAKE_EASY_NODE_COUNTER_FILE="$MIXED_DECISION_COUNTER" \
FAKE_EASY_NODE_CAPTURE_FILE="$MIXED_DECISION_CAPTURE" \
FAKE_EASY_NODE_SCENARIO="mixed_decision" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "host-a.test" \
  --host-b "host-b.test" \
  --campaign-subject "inv-mixed-decision" \
  --runs 3 \
  --campaign-timeout-sec 2400 \
  --sleep-between-sec 0 \
  --reports-dir "$MIXED_DECISION_REPORTS_DIR" \
  --summary-json "$MIXED_DECISION_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_run_mixed_decision.log 2>&1
mixed_decision_rc=$?
set -e

if [[ "$mixed_decision_rc" -ne 0 ]]; then
  echo "expected mixed-decision path rc=0, got rc=$mixed_decision_rc"
  cat /tmp/integration_profile_default_gate_stability_run_mixed_decision.log
  exit 1
fi
if ! jq -e '
  .runs_total == 3
  and .runs_completed == 3
  and .decision_counts.GO == 2
  and .decision_counts."NO-GO" == 1
  and .decision_total == 3
  and .modal_decision == "GO"
  and .modal_decision_count == 2
  and (.modal_decision_support_rate_pct > 66 and .modal_decision_support_rate_pct < 67)
  and .decision_consensus == false
' "$MIXED_DECISION_SUMMARY" >/dev/null 2>&1; then
  echo "mixed-decision summary JSON missing expected decision evidence"
  cat "$MIXED_DECISION_SUMMARY"
  exit 1
fi
mixed_decision_counter_value="$(cat "$MIXED_DECISION_COUNTER" 2>/dev/null || echo "0")"
if [[ "$mixed_decision_counter_value" != "3" ]]; then
  echo "expected mixed-decision fake easy_node run count to be 3, got: $mixed_decision_counter_value"
  cat "$MIXED_DECISION_CAPTURE"
  exit 1
fi

echo "profile default gate stability run integration ok"
