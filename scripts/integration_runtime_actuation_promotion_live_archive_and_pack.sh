#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat find wc; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/runtime_actuation_promotion_live_archive_and_pack.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

assert_jq() {
  local file="$1"
  local query="$2"
  if ! jq -e "$query" "$file" >/dev/null 2>&1; then
    echo "assertion failed: $query"
    echo "file: $file"
    cat "$file"
    exit 1
  fi
}

assert_file_exists() {
  local path="$1"
  local label="$2"
  if [[ ! -e "$path" ]]; then
    echo "missing $label: $path"
    exit 1
  fi
}

FAKE_CYCLE_SCRIPT="$TMP_DIR/fake_runtime_actuation_promotion_cycle.sh"
FAKE_EVIDENCE_SCRIPT="$TMP_DIR/fake_runtime_actuation_promotion_evidence_pack.sh"

cat >"$FAKE_CYCLE_SCRIPT" <<'EOF_FAKE_CYCLE'
#!/usr/bin/env bash
set -euo pipefail

summary_json=""
reports_dir=""
print_summary_json="0"

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
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    --print-summary-json=*)
      print_summary_json="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake cycle missing --summary-json" >&2
  exit 2
fi

if [[ -z "$reports_dir" ]]; then
  reports_dir="$(cd "$(dirname "$summary_json")" && pwd)"
fi

mode="${FAKE_CYCLE_MODE:-pass}"
mkdir -p "$reports_dir"
mkdir -p "$(dirname "$summary_json")"

promotion_summary_json="$reports_dir/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json"
signoff_summary_list="$reports_dir/runtime_actuation_promotion_cycle_latest_signoff_summaries.list"
signoff_summary_1="$reports_dir/runtime_actuation_promotion_cycle_0001_signoff.json"
signoff_summary_2="$reports_dir/runtime_actuation_promotion_cycle_0002_signoff.json"

write_supporting_artifacts() {
  local include_promotion="$1"
  local status="$2"
  local rc="$3"
  local decision="$4"

  if [[ "$include_promotion" == "1" ]]; then
    cat >"$promotion_summary_json" <<'EOF_PROMOTION'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_check_summary" },
  "status": "ok",
  "rc": 0,
  "decision": "GO"
}
EOF_PROMOTION
  else
    rm -f "$promotion_summary_json"
  fi

  cat >"$signoff_summary_1" <<'EOF_SIGNOFF_1'
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "decision": { "decision": "GO" }
}
EOF_SIGNOFF_1

  cat >"$signoff_summary_2" <<'EOF_SIGNOFF_2'
{
  "version": 1,
  "status": "ok",
  "final_rc": 0,
  "decision": { "decision": "GO" }
}
EOF_SIGNOFF_2

  {
    printf '%s\n' "$signoff_summary_1"
    printf '%s\n' "$signoff_summary_2"
  } >"$signoff_summary_list"

  jq -n \
    --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    --arg status "$status" \
    --arg decision "$decision" \
    --arg promotion_summary_json "$promotion_summary_json" \
    --arg signoff_summary_list "$signoff_summary_list" \
    --argjson rc "$rc" \
    '{
      version: 1,
      schema: { id: "runtime_actuation_promotion_cycle_summary" },
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      decision: $decision,
      artifacts: {
        promotion_summary_json: $promotion_summary_json,
        signoff_summary_list: $signoff_summary_list
      }
    }' >"$summary_json"
}

case "$mode" in
  pass)
    write_supporting_artifacts "1" "pass" 0 "GO"
    exit_code=0
    ;;
  pass_missing_promotion)
    write_supporting_artifacts "0" "pass" 0 "GO"
    exit_code=0
    ;;
  no_go_fail_rc1)
    write_supporting_artifacts "1" "fail" 1 "NO-GO"
    exit_code=1
    ;;
  missing)
    rm -f "$summary_json"
    exit_code=0
    ;;
  reuse)
    # Intentionally leave summary untouched to simulate stale reuse.
    exit_code=0
    ;;
  invalid)
    printf '%s\n' '{ invalid-json' >"$summary_json"
    exit_code=0
    ;;
  *)
    echo "fake cycle unknown mode: $mode" >&2
    exit 2
    ;;
esac

if [[ "$print_summary_json" == "1" && -f "$summary_json" ]]; then
  cat "$summary_json"
fi

exit "$exit_code"
EOF_FAKE_CYCLE

cat >"$FAKE_EVIDENCE_SCRIPT" <<'EOF_FAKE_EVIDENCE'
#!/usr/bin/env bash
set -euo pipefail

summary_json=""
report_md=""
print_summary_json="0"
print_report="0"

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
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --report-md=*)
      report_md="${1#*=}"
      shift
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    --print-summary-json=*)
      print_summary_json="${1#*=}"
      shift
      ;;
    --print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_report="${2:-}"
        shift 2
      else
        print_report="1"
        shift
      fi
      ;;
    --print-report=*)
      print_report="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake evidence missing --summary-json" >&2
  exit 2
fi

mkdir -p "$(dirname "$summary_json")"
if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
fi

mode="${FAKE_EVIDENCE_MODE:-pass}"
case "$mode" in
  pass)
    cat >"$summary_json" <<'EOF_SUMMARY'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_evidence_pack_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO",
  "next_operator_action": "No action required",
  "next_command": null,
  "next_command_reason": null
}
EOF_SUMMARY
    if [[ -n "$report_md" ]]; then
      printf '%s\n' "# fake runtime-actuation evidence-pack report" >"$report_md"
    fi
    exit_code=0
    ;;
  no_go_fail)
    cat >"$summary_json" <<'EOF_NOGO'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_evidence_pack_summary" },
  "status": "fail",
  "rc": 1,
  "decision": "NO-GO",
  "next_operator_action": "Use REPLACE_WITH_INVITE_SUBJECT and [redacted] placeholders.",
  "next_command": "./scripts/easy_node.sh runtime-actuation-promotion-cycle --subject INVITE_KEY --campaign-subject REPLACE_WITH_INVITE_SUBJECT",
  "next_command_reason": "set CAMPAIGN_SUBJECT=INVITE_KEY and rerun using [redacted] values"
}
EOF_NOGO
    if [[ -n "$report_md" ]]; then
      printf '%s\n' "# fake runtime-actuation evidence-pack report (NO-GO)" >"$report_md"
    fi
    exit_code=1
    ;;
  *)
    echo "fake evidence unknown mode: $mode" >&2
    exit 2
    ;;
esac

if [[ "$print_report" == "1" && -n "$report_md" && -f "$report_md" ]]; then
  cat "$report_md"
fi
if [[ "$print_summary_json" == "1" && -f "$summary_json" ]]; then
  cat "$summary_json"
fi

exit "$exit_code"
EOF_FAKE_EVIDENCE

chmod +x "$FAKE_CYCLE_SCRIPT" "$FAKE_EVIDENCE_SCRIPT"

echo "[runtime-actuation-promotion-live-archive-and-pack] pass path"
PASS_REPORTS="$TMP_DIR/pass_reports"
PASS_SUMMARY="$TMP_DIR/pass_summary.json"
set +e
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="pass" \
FAKE_EVIDENCE_MODE="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$PASS_REPORTS" \
  --cycles 3 \
  --fail-on-no-go 1 \
  --summary-json "$PASS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_live_archive_and_pack_pass.log 2>&1
PASS_RC=$?
set -e
if [[ "$PASS_RC" -ne 0 ]]; then
  echo "expected pass path rc=0, got rc=$PASS_RC"
  cat /tmp/integration_runtime_actuation_promotion_live_archive_and_pack_pass.log
  exit 1
fi
if grep -F '"runtime_actuation_promotion_live_archive_and_pack_summary"' /tmp/integration_runtime_actuation_promotion_live_archive_and_pack_pass.log >/dev/null 2>&1; then
  echo "expected --print-summary-json 0 to suppress summary payload output"
  cat /tmp/integration_runtime_actuation_promotion_live_archive_and_pack_pass.log
  exit 1
fi
assert_jq "$PASS_SUMMARY" '.schema.id == "runtime_actuation_promotion_live_archive_and_pack_summary"'
assert_jq "$PASS_SUMMARY" '.status == "pass" and .rc == 0 and .failure_substep == null'
assert_jq "$PASS_SUMMARY" '.stages.runtime_actuation_promotion_cycle.summary_usable_for_archive == true'
assert_jq "$PASS_SUMMARY" '.stages.runtime_actuation_promotion_cycle.publish_ready == true'
assert_jq "$PASS_SUMMARY" '.stages.live_evidence_archive.attempted == true'
assert_jq "$PASS_SUMMARY" '.stages.live_evidence_archive.status == "pass" and .stages.live_evidence_archive.required_missing_total == 0'
assert_jq "$PASS_SUMMARY" '.stages.runtime_actuation_promotion_evidence_pack.status == "pass" and .stages.runtime_actuation_promotion_evidence_pack.publish_ready == true'
assert_jq "$PASS_SUMMARY" '.outcome.publish_ready == true and .outcome.action == "archive_and_pack_complete"'
assert_jq "$PASS_SUMMARY" '.next_command == null and .next_command_reason == null'
PASS_MANIFEST="$(jq -r '.artifacts.runtime_actuation_live_archive_manifest_json // ""' "$PASS_SUMMARY")"
PASS_ARCHIVE_DIR="$(jq -r '.artifacts.runtime_actuation_live_archive_dir // ""' "$PASS_SUMMARY")"
assert_file_exists "$PASS_MANIFEST" "pass manifest"
assert_file_exists "$PASS_ARCHIVE_DIR" "pass archive dir"
assert_jq "$PASS_MANIFEST" '.schema.id == "runtime_actuation_live_archive_manifest" and .status == "pass" and .rc == 0'
assert_file_exists "$PASS_ARCHIVE_DIR/cycle/runtime_actuation_promotion_cycle_latest_summary.json" "archived cycle summary"
assert_file_exists "$PASS_ARCHIVE_DIR/cycle/runtime_actuation_promotion_cycle_latest_promotion_check_summary.json" "archived promotion summary"
assert_file_exists "$PASS_ARCHIVE_DIR/cycle/runtime_actuation_promotion_cycle_latest_signoff_summaries.list" "archived signoff summary list"
PASS_ARCHIVED_SIGNOFF_COUNT="$(find "$PASS_ARCHIVE_DIR/cycle/signoff_summaries" -type f | wc -l | tr -d ' ')"
if [[ "$PASS_ARCHIVED_SIGNOFF_COUNT" -lt 2 ]]; then
  echo "expected archived signoff summaries, got count=$PASS_ARCHIVED_SIGNOFF_COUNT"
  find "$PASS_ARCHIVE_DIR" -maxdepth 4 -type f
  exit 1
fi

echo "[runtime-actuation-promotion-live-archive-and-pack] print-summary-json flag controls payload output"
PRINT_REPORTS="$TMP_DIR/print_reports"
PRINT_SUMMARY="$TMP_DIR/print_summary.json"
PRINT_STDOUT="$TMP_DIR/print_stdout.log"
set +e
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="pass" \
FAKE_EVIDENCE_MODE="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$PRINT_REPORTS" \
  --cycles 3 \
  --fail-on-no-go 1 \
  --summary-json "$PRINT_SUMMARY" \
  --print-summary-json 1 >"$PRINT_STDOUT" 2>&1
PRINT_RC=$?
set -e
if [[ "$PRINT_RC" -ne 0 ]]; then
  echo "expected print-summary-json path rc=0, got rc=$PRINT_RC"
  cat "$PRINT_STDOUT"
  exit 1
fi
if ! grep -F '"runtime_actuation_promotion_live_archive_and_pack_summary"' "$PRINT_STDOUT" >/dev/null 2>&1; then
  echo "expected --print-summary-json 1 to emit summary payload output"
  cat "$PRINT_STDOUT"
  exit 1
fi

echo "[runtime-actuation-promotion-live-archive-and-pack] cycle missing summary fail-closed"
MISSING_REPORTS="$TMP_DIR/missing_reports"
MISSING_SUMMARY="$TMP_DIR/missing_summary.json"
set +e
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="missing" \
FAKE_EVIDENCE_MODE="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MISSING_REPORTS" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$MISSING_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_live_archive_and_pack_missing.log 2>&1
MISSING_RC=$?
set -e
if [[ "$MISSING_RC" -eq 0 ]]; then
  echo "expected missing-summary path rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_live_archive_and_pack_missing.log
  exit 1
fi
assert_jq "$MISSING_SUMMARY" '.status == "fail" and .failure_substep == "runtime_actuation_promotion_cycle_summary_missing_or_invalid"'
assert_jq "$MISSING_SUMMARY" '.stages.live_evidence_archive.status == "skipped" and .stages.live_evidence_archive.skip_reason == "cycle_summary_unusable_for_archive"'
assert_jq "$MISSING_SUMMARY" '.stages.runtime_actuation_promotion_evidence_pack.status == "skipped" and .stages.runtime_actuation_promotion_evidence_pack.skip_reason == "cycle_summary_unusable_for_archive"'

echo "[runtime-actuation-promotion-live-archive-and-pack] cycle stale summary reuse fail-closed"
STALE_REPORTS="$TMP_DIR/stale_reports"
STALE_SUMMARY="$TMP_DIR/stale_summary.json"
mkdir -p "$STALE_REPORTS"
cat >"$STALE_REPORTS/runtime_actuation_promotion_cycle_latest_summary.json" <<'EOF_STALE'
{
  "version": 1,
  "schema": { "id": "runtime_actuation_promotion_cycle_summary" },
  "status": "pass",
  "rc": 0,
  "decision": "GO"
}
EOF_STALE
set +e
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="reuse" \
FAKE_EVIDENCE_MODE="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$STALE_REPORTS" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$STALE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_live_archive_and_pack_stale.log 2>&1
STALE_RC=$?
set -e
if [[ "$STALE_RC" -eq 0 ]]; then
  echo "expected stale-summary-reuse path rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_live_archive_and_pack_stale.log
  exit 1
fi
assert_jq "$STALE_SUMMARY" '.status == "fail" and .failure_substep == "runtime_actuation_promotion_cycle_summary_stale_reused"'
assert_jq "$STALE_SUMMARY" '.stages.runtime_actuation_promotion_cycle.summary_fresh_after_run == false'
assert_jq "$STALE_SUMMARY" '.stages.live_evidence_archive.status == "skipped"'

echo "[runtime-actuation-promotion-live-archive-and-pack] archive required-input contract fail-closed"
ARCHIVE_FAIL_REPORTS="$TMP_DIR/archive_fail_reports"
ARCHIVE_FAIL_SUMMARY="$TMP_DIR/archive_fail_summary.json"
set +e
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="pass_missing_promotion" \
FAKE_EVIDENCE_MODE="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$ARCHIVE_FAIL_REPORTS" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$ARCHIVE_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_live_archive_and_pack_archive_fail.log 2>&1
ARCHIVE_FAIL_RC=$?
set -e
if [[ "$ARCHIVE_FAIL_RC" -eq 0 ]]; then
  echo "expected archive-required-input path rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_live_archive_and_pack_archive_fail.log
  exit 1
fi
assert_jq "$ARCHIVE_FAIL_SUMMARY" '.status == "fail" and .failure_substep == "runtime_actuation_live_evidence_archive_required_artifacts_missing"'
assert_jq "$ARCHIVE_FAIL_SUMMARY" '.stages.live_evidence_archive.status == "fail" and .stages.live_evidence_archive.required_missing_total >= 1'
assert_jq "$ARCHIVE_FAIL_SUMMARY" '.stages.runtime_actuation_promotion_evidence_pack.status == "skipped" and .stages.runtime_actuation_promotion_evidence_pack.skip_reason == "live_evidence_archive_failed"'

echo "[runtime-actuation-promotion-live-archive-and-pack] cycle NO-GO keeps archive and evidence-pack diagnostics fail-closed"
NOGO_REPORTS="$TMP_DIR/nogo_reports"
NOGO_SUMMARY="$TMP_DIR/nogo_summary.json"
set +e
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_CYCLE_SCRIPT="$FAKE_CYCLE_SCRIPT" \
RUNTIME_ACTUATION_PROMOTION_LIVE_ARCHIVE_AND_PACK_RUNTIME_ACTUATION_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_EVIDENCE_SCRIPT" \
FAKE_CYCLE_MODE="no_go_fail_rc1" \
FAKE_EVIDENCE_MODE="no_go_fail" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$NOGO_REPORTS" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$NOGO_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_runtime_actuation_promotion_live_archive_and_pack_nogo.log 2>&1
NOGO_RC=$?
set -e
if [[ "$NOGO_RC" -eq 0 ]]; then
  echo "expected NO-GO path rc!=0"
  cat /tmp/integration_runtime_actuation_promotion_live_archive_and_pack_nogo.log
  exit 1
fi
assert_jq "$NOGO_SUMMARY" '.status == "fail" and .failure_substep == "runtime_actuation_publish_blocked_cycle_not_publish_ready"'
assert_jq "$NOGO_SUMMARY" '.stages.runtime_actuation_promotion_cycle.status == "warn"'
assert_jq "$NOGO_SUMMARY" '.stages.runtime_actuation_promotion_cycle.publish_blocked == true and .stages.runtime_actuation_promotion_cycle.publish_ready == false'
assert_jq "$NOGO_SUMMARY" '.stages.runtime_actuation_promotion_cycle.summary_usable_for_archive == true'
assert_jq "$NOGO_SUMMARY" '.stages.live_evidence_archive.status == "pass"'
assert_jq "$NOGO_SUMMARY" '.stages.runtime_actuation_promotion_evidence_pack.status == "fail" and .stages.runtime_actuation_promotion_evidence_pack.failure_substep == "runtime_actuation_promotion_evidence_pack_runner_nonzero"'
assert_jq "$NOGO_SUMMARY" '.next_command != null and (.next_command | test("runtime-actuation-promotion-cycle"))'
assert_jq "$NOGO_SUMMARY" '(.next_command | test("INVITE_KEY|CAMPAIGN_SUBJECT|REPLACE_WITH_INVITE_SUBJECT|\\[redacted\\]|\\[REDACTED\\]") | not)'
assert_jq "$NOGO_SUMMARY" '((.next_command_reason // "") | test("INVITE_KEY|CAMPAIGN_SUBJECT|REPLACE_WITH_INVITE_SUBJECT|\\[redacted\\]|\\[REDACTED\\]") | not)'
assert_jq "$NOGO_SUMMARY" '((.next_operator_action // "") | test("INVITE_KEY|CAMPAIGN_SUBJECT|REPLACE_WITH_INVITE_SUBJECT|\\[redacted\\]|\\[REDACTED\\]") | not)'

echo "runtime actuation promotion live archive and pack integration ok"
