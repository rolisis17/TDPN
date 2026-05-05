#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp cat chmod grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_compare_multi_vm_stability_promotion_live_archive_and_pack.sh}"
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

FAKE_PROMOTION_CYCLE_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_promotion_cycle.sh"
cat >"$FAKE_PROMOTION_CYCLE_SCRIPT" <<'EOF_FAKE_PROMOTION_CYCLE'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_M5_PROMOTION_CYCLE_SCENARIO:-pass}"
summary_json=""
cycle_summary_list=""
promotion_summary_json=""
fail_on_no_go="1"
capture_file="${FAKE_M5_CAPTURE_FILE:-}"

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
    --cycle-summary-list)
      cycle_summary_list="${2:-}"
      shift 2
      ;;
    --cycle-summary-list=*)
      cycle_summary_list="${1#*=}"
      shift
      ;;
    --promotion-summary-json)
      promotion_summary_json="${2:-}"
      shift 2
      ;;
    --promotion-summary-json=*)
      promotion_summary_json="${1#*=}"
      shift
      ;;
    --fail-on-no-go)
      fail_on_no_go="${2:-}"
      shift 2
      ;;
    --fail-on-no-go=*)
      fail_on_no_go="${1#*=}"
      shift
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake promotion cycle missing --summary-json" >&2
  exit 2
fi

scenario="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ -z "$scenario" ]]; then
  scenario="pass"
fi

if [[ -n "$capture_file" ]]; then
  printf 'promotion_cycle\tscenario=%s\tfail_on_no_go=%s\tsummary_json=%s\tcycle_summary_list=%s\tpromotion_summary_json=%s\n' \
    "$scenario" "$fail_on_no_go" "$summary_json" "$cycle_summary_list" "$promotion_summary_json" >>"$capture_file"
fi

if [[ -n "$cycle_summary_list" ]]; then
  mkdir -p "$(dirname "$cycle_summary_list")"
  printf '%s\n' "$(dirname "$summary_json")/cycle_001/profile_compare_multi_vm_stability_cycle_summary.json" >"$cycle_summary_list"
fi

if [[ -n "$promotion_summary_json" ]]; then
  mkdir -p "$(dirname "$promotion_summary_json")"
  jq -n '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_stability_promotion_check_summary" },
    decision: "GO",
    status: "ok",
    rc: 0
  }' >"$promotion_summary_json"
fi

if [[ "$scenario" == "missing_no_write" ]]; then
  exit 0
fi

if [[ "$scenario" == "runner_nonzero_vm_log_not_found" ]]; then
  echo "vm command file preflight failed: not_found" >&2
  echo "preflight_diag: source=vm-command-file path=/tmp/does_not_exist_vm_commands.txt reason=not_found" >&2
  exit "${FAKE_M5_PROMOTION_CYCLE_RC:-7}"
fi

mkdir -p "$(dirname "$summary_json")"

if [[ "$scenario" == "invalid_json" ]]; then
  printf '%s\n' '{ invalid json' >"$summary_json"
  exit 0
fi

decision="GO"
status="pass"
rc=0
if [[ "$scenario" == "no_go" ]]; then
  decision="NO-GO"
  status="warn"
  rc=0
fi

archive_root="${FAKE_M5_PROMOTION_CYCLE_ARCHIVE_ROOT:-$(dirname "$summary_json")/fake_promotion_archive}"

jq -n \
  --arg decision "$decision" \
  --arg status "$status" \
  --arg archive_root "$archive_root" \
  --arg operator_next_action_command "./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --reports-dir .easy-node-logs --print-summary-json 1" \
  --argjson rc "$rc" \
  '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_stability_promotion_cycle_summary" },
    status: $status,
    rc: $rc,
    decision: $decision,
    next_operator_action: "promotion cycle action",
    operator_next_action_command: $operator_next_action_command,
    promotion: {
      summary_exists: true,
      summary_valid_json: true,
      summary_fresh: true
    },
    artifacts: {
      archive_root: $archive_root
    }
  }' >"$summary_json"

if [[ "$scenario" == "runner_nonzero_with_summary" ]]; then
  exit "${FAKE_M5_PROMOTION_CYCLE_RC:-7}"
fi

exit 0
EOF_FAKE_PROMOTION_CYCLE
chmod +x "$FAKE_PROMOTION_CYCLE_SCRIPT"

FAKE_PACK_SCRIPT="$TMP_DIR/fake_profile_compare_multi_vm_stability_promotion_evidence_pack.sh"
cat >"$FAKE_PACK_SCRIPT" <<'EOF_FAKE_PACK'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_M5_PACK_SCENARIO:-pass}"
summary_json=""
report_md=""
capture_file="${FAKE_M5_CAPTURE_FILE:-}"

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
    *)
      shift
      ;;
  esac
done

if [[ -z "$summary_json" ]]; then
  echo "fake evidence-pack missing --summary-json" >&2
  exit 2
fi

scenario="$(printf '%s' "$scenario" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
if [[ -z "$scenario" ]]; then
  scenario="pass"
fi

if [[ -n "$capture_file" ]]; then
  printf 'pack\tscenario=%s\tsummary_json=%s\treport_md=%s\n' "$scenario" "$summary_json" "$report_md" >>"$capture_file"
fi

if [[ "$scenario" == "missing_no_write" ]]; then
  exit 0
fi

mkdir -p "$(dirname "$summary_json")"
if [[ -n "$report_md" ]]; then
  mkdir -p "$(dirname "$report_md")"
  printf '# fake pack report\n' >"$report_md"
fi

decision="GO"
status="ok"
rc=0
next_command="./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --reports-dir .easy-node-logs --print-summary-json 1"
operator_next_action_command="$next_command"

if [[ "$scenario" == "no_go_placeholder" ]]; then
  decision="NO-GO"
  status="warn"
  rc=0
  next_command="./scripts/profile_compare_multi_vm_stability_promotion_cycle.sh --campaign-subject INVITE_KEY --print-summary-json 1"
  operator_next_action_command="$next_command"
fi
if [[ "$scenario" == "unsafe_command_hint" ]]; then
  decision="NO-GO"
  status="warn"
  rc=0
  next_command="rm -rf /tmp/unsafe-pack"
  operator_next_action_command="$next_command"
fi

jq -n \
  --arg decision "$decision" \
  --arg status "$status" \
  --arg next_command "$next_command" \
  --arg operator_next_action_command "$operator_next_action_command" \
  --argjson rc "$rc" \
  '{
    version: 1,
    schema: { id: "profile_compare_multi_vm_stability_promotion_evidence_pack_summary" },
    status: $status,
    rc: $rc,
    decision: $decision,
    next_operator_action: "promotion evidence-pack action",
    next_command: $next_command,
    operator_next_action_command: $operator_next_action_command,
    evidence: {
      promotion_cycle: {
        freshness: {
          fresh: true
        }
      }
    }
  }' >"$summary_json"

if [[ "$scenario" == "runner_nonzero_with_summary" ]]; then
  exit "${FAKE_M5_PACK_RC:-9}"
fi
exit 0
EOF_FAKE_PACK
chmod +x "$FAKE_PACK_SCRIPT"

echo "[promotion-live-archive-and-pack] pass path"
PASS_SUMMARY="$TMP_DIR/pass_summary.json"
PASS_CAPTURE="$TMP_DIR/pass_capture.log"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_CAPTURE_FILE="$PASS_CAPTURE" \
FAKE_M5_PROMOTION_CYCLE_SCENARIO="pass" \
FAKE_M5_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/pass_reports" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$PASS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_pass.log 2>&1
pass_rc=$?
set -e

if [[ "$pass_rc" -ne 0 ]]; then
  echo "expected pass path rc=0, got rc=$pass_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_pass.log
  exit 1
fi
assert_jq "$PASS_SUMMARY" '
  .schema.id == "profile_compare_multi_vm_stability_promotion_live_archive_and_pack_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .stages.promotion_cycle_live_archive.attempted == true
  and .stages.promotion_evidence_pack.attempted == true
  and .stages.promotion_cycle_live_archive.summary.usable == true
  and .stages.promotion_evidence_pack.summary.usable == true
  and .next_command == null
'

echo "[promotion-live-archive-and-pack] promotion-cycle summary missing fail-closed path"
MISSING_SUMMARY="$TMP_DIR/missing_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_PROMOTION_CYCLE_SCENARIO="missing_no_write" \
FAKE_M5_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/missing_reports" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$MISSING_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_missing.log 2>&1
missing_rc=$?
set -e

if [[ "$missing_rc" -eq 0 ]]; then
  echo "expected missing-summary path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_missing.log
  exit 1
fi
assert_jq "$MISSING_SUMMARY" '
  .status == "fail"
  and .decision == "NO-GO"
  and .rc != 0
  and .failure_reason_code == "promotion_cycle_summary_missing_or_stale"
  and .stages.promotion_cycle_live_archive.attempted == true
  and .stages.promotion_cycle_live_archive.summary.summary_exists == false
  and .stages.promotion_evidence_pack.attempted == false
  and .stages.promotion_evidence_pack.status == "skip"
  and (.next_command_reason | test("summary artifact is missing or stale"))
'

echo "[promotion-live-archive-and-pack] NO-GO warn-only path with placeholder sanitization"
NOGO_SUMMARY="$TMP_DIR/nogo_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_PROMOTION_CYCLE_SCENARIO="no_go" \
FAKE_M5_PACK_SCENARIO="no_go_placeholder" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/nogo_reports" \
  --cycles 2 \
  --fail-on-no-go 0 \
  --summary-json "$NOGO_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_nogo.log 2>&1
nogo_rc=$?
set -e

if [[ "$nogo_rc" -ne 0 ]]; then
  echo "expected NO-GO warn-only path rc=0, got rc=$nogo_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_nogo.log
  exit 1
fi
assert_jq "$NOGO_SUMMARY" '
  .status == "warn"
  and .rc == 0
  and .decision == "NO-GO"
  and .failure_reason_code == "promotion_decision_no_go_warn_only"
  and .stages.promotion_cycle_live_archive.attempted == true
  and .stages.promotion_evidence_pack.attempted == true
  and (.next_command_reason | test("NO-GO"))
'
assert_jq "$NOGO_SUMMARY" '((.next_command // "") | test("INVITE_KEY") | not)'
assert_jq "$NOGO_SUMMARY" '((.next_command // "") | test("CAMPAIGN_SUBJECT") | not)'
assert_jq "$NOGO_SUMMARY" '((.next_command // "") | test("profile_compare_multi_vm_stability_promotion_cycle\\.sh|profile_compare_multi_vm_stability_promotion_live_archive_and_pack\\.sh"))'

echo "[promotion-live-archive-and-pack] unsafe next-command hint is dropped fail-closed"
UNSAFE_SUMMARY="$TMP_DIR/unsafe_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_PROMOTION_CYCLE_SCENARIO="pass" \
FAKE_M5_PACK_SCENARIO="unsafe_command_hint" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/unsafe_reports" \
  --cycles 2 \
  --fail-on-no-go 0 \
  --summary-json "$UNSAFE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_unsafe.log 2>&1
unsafe_rc=$?
set -e

if [[ "$unsafe_rc" -ne 0 ]]; then
  echo "expected unsafe-hint warn-only path rc=0, got rc=$unsafe_rc"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_unsafe.log
  exit 1
fi
assert_jq "$UNSAFE_SUMMARY" '
  .status == "warn"
  and .decision == "NO-GO"
  and .rc == 0
  and ((.next_command // "") | contains("rm -rf") | not)
  and ((.next_command // "") | test("profile_compare_multi_vm_stability_promotion_cycle\\.sh|profile_compare_multi_vm_stability_promotion_live_archive_and_pack\\.sh"))
'

echo "[promotion-live-archive-and-pack] unresolved placeholder env VM command source is classified fail-closed"
VM_PLACEHOLDER_SUMMARY="$TMP_DIR/vm_placeholder_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="REPLACE_WITH_VM_COMMAND_FILE" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_PROMOTION_CYCLE_SCENARIO="runner_nonzero_with_summary" \
FAKE_M5_PROMOTION_CYCLE_RC="7" \
FAKE_M5_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/vm_placeholder_reports" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$VM_PLACEHOLDER_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_vm_placeholder.log 2>&1
vm_placeholder_rc=$?
set -e

if [[ "$vm_placeholder_rc" -eq 0 ]]; then
  echo "expected unresolved placeholder VM source path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_vm_placeholder.log
  exit 1
fi
assert_jq "$VM_PLACEHOLDER_SUMMARY" '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_reason_code == "vm_command_source_unresolved_placeholder"
  and .failure_substep == "vm_command_source_unresolved_placeholder"
  and .inputs.vm_command_source_preflight.ready == false
  and .inputs.vm_command_source_preflight.explicit_env_seen == true
  and .inputs.vm_command_source_preflight.primary_reason == "placeholder_value"
  and (.inputs.vm_command_source_preflight.diagnostics | map(test("placeholder_value")) | any)
'

echo "[promotion-live-archive-and-pack] unsafe env VM command source path is classified fail-closed"
VM_UNSAFE_SUMMARY="$TMP_DIR/vm_unsafe_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_RUN_VM_COMMAND_FILE="unsafe;path" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_PROMOTION_CYCLE_SCENARIO="runner_nonzero_with_summary" \
FAKE_M5_PROMOTION_CYCLE_RC="7" \
FAKE_M5_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/vm_unsafe_reports" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$VM_UNSAFE_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_vm_unsafe.log 2>&1
vm_unsafe_rc=$?
set -e

if [[ "$vm_unsafe_rc" -eq 0 ]]; then
  echo "expected unsafe VM source path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_vm_unsafe.log
  exit 1
fi
assert_jq "$VM_UNSAFE_SUMMARY" '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_reason_code == "vm_command_source_unsafe_path"
  and .failure_substep == "vm_command_source_unsafe_path"
  and .inputs.vm_command_source_preflight.ready == false
  and .inputs.vm_command_source_preflight.explicit_env_seen == true
  and .inputs.vm_command_source_preflight.primary_reason == "unsafe_path_value"
  and (.inputs.vm_command_source_preflight.diagnostics | map(test("unsafe_path_value")) | any)
'

echo "[promotion-live-archive-and-pack] VM command-file not-found failure in logs is classified fail-closed"
VM_LOG_NOT_FOUND_SUMMARY="$TMP_DIR/vm_log_not_found_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_PROMOTION_CYCLE_SCENARIO="runner_nonzero_vm_log_not_found" \
FAKE_M5_PROMOTION_CYCLE_RC="7" \
FAKE_M5_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/vm_log_not_found_reports" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$VM_LOG_NOT_FOUND_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_vm_log_not_found.log 2>&1
vm_log_not_found_rc=$?
set -e

if [[ "$vm_log_not_found_rc" -eq 0 ]]; then
  echo "expected VM command-file not-found log scenario rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_vm_log_not_found.log
  exit 1
fi
assert_jq "$VM_LOG_NOT_FOUND_SUMMARY" '
  .status == "fail"
  and .decision == "NO-GO"
  and .failure_reason_code == "vm_command_source_unresolved"
  and .failure_substep == "vm_command_source_unresolved"
'

echo "[promotion-live-archive-and-pack] promotion-cycle runner nonzero with summary fail-closed"
RUNNER_FAIL_SUMMARY="$TMP_DIR/runner_fail_summary.json"
set +e
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_CYCLE_SCRIPT="$FAKE_PROMOTION_CYCLE_SCRIPT" \
PROFILE_COMPARE_MULTI_VM_STABILITY_PROMOTION_LIVE_ARCHIVE_AND_PACK_PROMOTION_EVIDENCE_PACK_SCRIPT="$FAKE_PACK_SCRIPT" \
FAKE_M5_PROMOTION_CYCLE_SCENARIO="runner_nonzero_with_summary" \
FAKE_M5_PROMOTION_CYCLE_RC="7" \
FAKE_M5_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$TMP_DIR/runner_fail_reports" \
  --cycles 2 \
  --fail-on-no-go 1 \
  --summary-json "$RUNNER_FAIL_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_runner_fail.log 2>&1
runner_fail_rc=$?
set -e

if [[ "$runner_fail_rc" -eq 0 ]]; then
  echo "expected promotion-cycle runner nonzero path rc!=0"
  cat /tmp/integration_profile_compare_multi_vm_stability_promotion_live_archive_and_pack_runner_fail.log
  exit 1
fi
assert_jq "$RUNNER_FAIL_SUMMARY" '
  .status == "fail"
  and .rc != 0
  and .decision == "NO-GO"
  and .failure_reason_code == "promotion_cycle_runner_nonzero"
  and .failure_substep == "promotion_cycle_runner_nonzero"
  and .stages.promotion_cycle_live_archive.attempted == true
  and .stages.promotion_cycle_live_archive.status == "fail"
  and .stages.promotion_cycle_live_archive.rc == 7
  and .stages.promotion_evidence_pack.attempted == false
  and .stages.promotion_evidence_pack.status == "skip"
'

echo "profile compare multi-vm stability promotion live archive and pack integration ok"
