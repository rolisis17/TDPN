#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

REPORTS_DIR="$TMP_DIR/reports"
mkdir -p "$REPORTS_DIR"

cat >"$REPORTS_DIR/profile_compare_local_a.json" <<'EOF_A'
{
  "version": 1,
  "generated_at_utc": "2026-03-24T00:00:00Z",
  "status": "pass",
  "rc": 0,
  "summary": {
    "runs_executed": 4,
    "runs_fail": 0,
    "selection_policy": {
      "sticky_pair_sec": 0,
      "entry_rotation_sec": 0,
      "entry_rotation_jitter_pct": 0,
      "exit_exploration_pct": 10,
      "path_profile": "2hop"
    }
  },
  "decision": {
    "recommended_default_profile": "balanced"
  },
  "profiles": [
    {"profile": "balanced", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 10.0},
    {"profile": "speed", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 9.4},
    {"profile": "private", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 12.2},
    {"profile": "speed-1hop", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 7.2}
  ]
}
EOF_A

cat >"$REPORTS_DIR/profile_compare_local_b.json" <<'EOF_B'
{
  "version": 1,
  "generated_at_utc": "2026-03-24T00:05:00Z",
  "status": "pass",
  "rc": 0,
  "summary": {
    "runs_executed": 4,
    "runs_fail": 0,
    "selection_policy": {
      "sticky_pair_sec": 300,
      "entry_rotation_sec": 0,
      "entry_rotation_jitter_pct": 0,
      "exit_exploration_pct": 10,
      "path_profile": "1hop"
    }
  },
  "decision": {
    "recommended_default_profile": "speed"
  },
  "profiles": [
    {"profile": "balanced", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 10.4},
    {"profile": "speed", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 9.7},
    {"profile": "private", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 12.7},
    {"profile": "speed-1hop", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 7.0}
  ]
}
EOF_B

cat >"$REPORTS_DIR/profile_compare_local_c.json" <<'EOF_C'
{
  "version": 1,
  "generated_at_utc": "2026-03-24T00:10:00Z",
  "status": "pass",
  "rc": 0,
  "summary": {
    "runs_executed": 4,
    "runs_fail": 0,
    "selection_policy": {
      "sticky_pair_sec": 60,
      "entry_rotation_sec": 30,
      "entry_rotation_jitter_pct": 25,
      "exit_exploration_pct": 12,
      "path_profile": "3hop"
    }
  },
  "decision": {
    "recommended_default_profile": "balanced"
  },
  "profiles": [
    {"profile": "balanced", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 10.2},
    {"profile": "speed", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 9.8},
    {"profile": "private", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 13.1},
    {"profile": "speed-1hop", "runs_executed": 4, "runs_pass": 4, "runs_fail": 0, "avg_duration_sec": 6.9}
  ]
}
EOF_C

touch -t 202603240000 "$REPORTS_DIR/profile_compare_local_a.json"
touch -t 202603240005 "$REPORTS_DIR/profile_compare_local_b.json"

echo "[profile-compare-trend] baseline recommendation"
SUMMARY_JSON="$TMP_DIR/profile_compare_trend_summary.json"
REPORT_MD="$TMP_DIR/profile_compare_trend_report.md"
./scripts/profile_compare_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --max-reports 3 \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-summary-json 1 >/tmp/integration_profile_compare_trend_baseline.log 2>&1

if ! rg -q 'profile-compare-trend: status=pass' /tmp/integration_profile_compare_trend_baseline.log; then
  echo "expected baseline pass status"
  cat /tmp/integration_profile_compare_trend_baseline.log
  exit 1
fi
if [[ ! -f "$SUMMARY_JSON" || ! -f "$REPORT_MD" ]]; then
  echo "expected baseline artifacts missing"
  ls -la "$TMP_DIR"
  exit 1
fi
if ! jq -e '
  .status == "pass"
  and .rc == 0
  and .summary.reports_total == 3
  and .summary.pass_reports == 3
  and .summary.fail_reports == 0
  and .decision.recommended_default_profile == "balanced"
  and .decision.experimental_non_default_profiles == ["speed-1hop"]
  and (.summary.selection_policy.sticky_pair_sec | type == "number")
  and (.summary.selection_policy.entry_rotation_sec | type == "number")
  and (.summary.selection_policy.entry_rotation_jitter_pct | type == "number")
  and (.summary.selection_policy.exit_exploration_pct | type == "number")
  and (.summary.selection_policy.path_profile | type == "string")
  and .summary.selection_policy.sticky_pair_sec == 60
  and .summary.selection_policy.entry_rotation_sec == 30
  and .summary.selection_policy.entry_rotation_jitter_pct == 25
  and .summary.selection_policy.exit_exploration_pct == 12
  and .summary.selection_policy.path_profile == "3hop"
' "$SUMMARY_JSON" >/dev/null 2>&1; then
  echo "baseline summary JSON missing expected fields"
  cat "$SUMMARY_JSON"
  exit 1
fi

echo "[profile-compare-trend] since-hours filter"
touch -t 202001010101 "$REPORTS_DIR/profile_compare_local_a.json" "$REPORTS_DIR/profile_compare_local_b.json"
SINCE_JSON="$TMP_DIR/profile_compare_trend_since.json"
./scripts/profile_compare_trend.sh \
  --reports-dir "$REPORTS_DIR" \
  --since-hours 1 \
  --max-reports 10 \
  --summary-json "$SINCE_JSON" >/tmp/integration_profile_compare_trend_since.log 2>&1

if ! jq -e '.summary.reports_total == 1' "$SINCE_JSON" >/dev/null 2>&1; then
  echo "expected since-hours filtering to keep only one recent report"
  cat /tmp/integration_profile_compare_trend_since.log
  cat "$SINCE_JSON"
  exit 1
fi

echo "[profile-compare-trend] fail-on-any-fail"
FAIL_REPORT="$REPORTS_DIR/profile_compare_local_fail.json"
cat >"$FAIL_REPORT" <<'EOF_FAIL'
{
  "version": 1,
  "generated_at_utc": "2026-03-24T00:20:00Z",
  "status": "fail",
  "rc": 1,
  "summary": {
    "runs_executed": 4,
    "runs_fail": 4
  },
  "decision": {
    "recommended_default_profile": "balanced"
  },
  "profiles": [
    {"profile": "balanced", "runs_executed": 4, "runs_pass": 0, "runs_fail": 4, "avg_duration_sec": 0},
    {"profile": "speed", "runs_executed": 4, "runs_pass": 0, "runs_fail": 4, "avg_duration_sec": 0}
  ]
}
EOF_FAIL

set +e
./scripts/profile_compare_trend.sh \
  --compare-summary-json "$REPORTS_DIR/profile_compare_local_c.json" \
  --compare-summary-json "$FAIL_REPORT" \
  --fail-on-any-fail 1 \
  --summary-json "$TMP_DIR/profile_compare_trend_fail.json" >/tmp/integration_profile_compare_trend_fail.log 2>&1
fail_rc=$?
set -e
if [[ "$fail_rc" -eq 0 ]]; then
  echo "expected non-zero rc when fail-on-any-fail is enabled"
  cat /tmp/integration_profile_compare_trend_fail.log
  exit 1
fi
if ! rg -q 'profile-compare-trend: status=fail' /tmp/integration_profile_compare_trend_fail.log; then
  echo "expected fail status output in fail-on-any-fail path"
  cat /tmp/integration_profile_compare_trend_fail.log
  exit 1
fi
if ! jq -e '
  .summary.selection_policy.sticky_pair_sec == 60
  and .summary.selection_policy.entry_rotation_sec == 30
  and .summary.selection_policy.entry_rotation_jitter_pct == 25
  and .summary.selection_policy.exit_exploration_pct == 12
  and .summary.selection_policy.path_profile == "3hop"
' "$TMP_DIR/profile_compare_trend_fail.json" >/dev/null 2>&1; then
  echo "expected fail-path trend summary to keep first valid selection policy evidence"
  cat "$TMP_DIR/profile_compare_trend_fail.json"
  exit 1
fi

FORWARD_CAPTURE="$TMP_DIR/forward_capture.log"
FAKE_FORWARD="$TMP_DIR/fake_profile_compare_trend_forward.sh"
cat >"$FAKE_FORWARD" <<'EOF_FORWARD'
#!/usr/bin/env bash
set -euo pipefail
printf 'profile-compare-trend %s\n' "$*" >>"${FORWARD_CAPTURE_FILE:?}"
EOF_FORWARD
chmod +x "$FAKE_FORWARD"

: >"$FORWARD_CAPTURE"

echo "[profile-compare-trend] easy_node forwarding"
FORWARD_CAPTURE_FILE="$FORWARD_CAPTURE" \
PROFILE_COMPARE_TREND_SCRIPT="$FAKE_FORWARD" \
./scripts/easy_node.sh profile-compare-trend \
  --reports-dir /tmp/profile_compare_reports \
  --max-reports 9 \
  --print-summary-json 1

forward_line="$(rg '^profile-compare-trend ' "$FORWARD_CAPTURE" | tail -n 1 || true)"
if [[ -z "$forward_line" ]]; then
  echo "missing easy_node forwarding capture"
  cat "$FORWARD_CAPTURE"
  exit 1
fi
for expected in '--reports-dir /tmp/profile_compare_reports' '--max-reports 9' '--print-summary-json 1'; do
  if ! grep -F -- "$expected" <<<"$forward_line" >/dev/null; then
    echo "easy_node forwarding missing $expected"
    cat "$FORWARD_CAPTURE"
    exit 1
  fi
done

echo "profile compare trend integration check ok"
