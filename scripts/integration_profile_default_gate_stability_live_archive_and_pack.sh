#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp chmod grep cat date; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/profile_default_gate_stability_live_archive_and_pack.sh}"
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

CAPTURE_FILE="$TMP_DIR/capture.tsv"
FAKE_CYCLE="$TMP_DIR/fake_cycle.sh"
FAKE_PACK="$TMP_DIR/fake_pack.sh"

cat >"$FAKE_CYCLE" <<'EOF_FAKE_CYCLE'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_LIVE_ARCHIVE_PACK_CYCLE_SCENARIO:-pass}"
capture_file="${FAKE_LIVE_ARCHIVE_PACK_CAPTURE_FILE:-}"
host_a=""
host_b=""
campaign_subject=""
run_summary_json=""
check_summary_json=""
cycle_summary_json=""
reports_dir=""
fail_on_no_go=""

while [[ $# -gt 0 ]]; do
  case "$1" in
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
    --campaign-subject|--subject)
      campaign_subject="${2:-}"
      shift 2
      ;;
    --campaign-subject=*|--subject=*)
      campaign_subject="${1#*=}"
      shift
      ;;
    --stability-summary-json|--run-summary-json)
      run_summary_json="${2:-}"
      shift 2
      ;;
    --stability-summary-json=*|--run-summary-json=*)
      run_summary_json="${1#*=}"
      shift
      ;;
    --stability-check-summary-json|--check-summary-json)
      check_summary_json="${2:-}"
      shift 2
      ;;
    --stability-check-summary-json=*|--check-summary-json=*)
      check_summary_json="${1#*=}"
      shift
      ;;
    --summary-json|--stability-cycle-summary-json|--cycle-summary-json)
      cycle_summary_json="${2:-}"
      shift 2
      ;;
    --summary-json=*|--stability-cycle-summary-json=*|--cycle-summary-json=*)
      cycle_summary_json="${1#*=}"
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

if [[ -z "$cycle_summary_json" ]]; then
  echo "fake cycle: missing cycle summary path" >&2
  exit 2
fi
if [[ -z "$run_summary_json" ]]; then
  echo "fake cycle: missing run summary path" >&2
  exit 2
fi
if [[ -z "$check_summary_json" ]]; then
  echo "fake cycle: missing check summary path" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'cycle\tscenario=%s\thost_a=%s\thost_b=%s\tcampaign_subject=%s\treports_dir=%s\tfail_on_no_go=%s\trun_summary_json=%s\tcheck_summary_json=%s\tcycle_summary_json=%s\n' \
    "$scenario" "$host_a" "$host_b" "$campaign_subject" "$reports_dir" "$fail_on_no_go" "$run_summary_json" "$check_summary_json" "$cycle_summary_json" >>"$capture_file"
fi

if [[ "$scenario" == "runner_fail" ]]; then
  exit 17
fi
if [[ "$scenario" == "stale_reuse_no_write" ]]; then
  exit 0
fi

mkdir -p "$(dirname "$run_summary_json")" "$(dirname "$check_summary_json")" "$(dirname "$cycle_summary_json")"
now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ "$scenario" != "missing_artifacts" ]]; then
  jq -n \
    --arg generated_at_utc "$now_utc" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_summary" },
      generated_at_utc: $generated_at_utc,
      status: "pass",
      rc: 0
    }' >"$run_summary_json"

  jq -n \
    --arg generated_at_utc "$now_utc" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_check_summary" },
      generated_at_utc: $generated_at_utc,
      status: "ok",
      rc: 0,
      decision: "GO",
      errors: []
    }' >"$check_summary_json"
fi

jq -n \
  --arg generated_at_utc "$now_utc" \
  '{
    version: 1,
    schema: { id: "profile_default_gate_stability_cycle_summary" },
    generated_at_utc: $generated_at_utc,
    status: "pass",
    rc: 0,
    decision: "GO"
  }' >"$cycle_summary_json"
EOF_FAKE_CYCLE
chmod +x "$FAKE_CYCLE"

cat >"$FAKE_PACK" <<'EOF_FAKE_PACK'
#!/usr/bin/env bash
set -euo pipefail

scenario="${FAKE_LIVE_ARCHIVE_PACK_PACK_SCENARIO:-pass}"
capture_file="${FAKE_LIVE_ARCHIVE_PACK_CAPTURE_FILE:-}"
reports_dir=""
run_summary_json=""
check_summary_json=""
cycle_summary_json=""
summary_json=""
report_md=""
fail_on_no_go=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --reports-dir=*)
      reports_dir="${1#*=}"
      shift
      ;;
    --stability-summary-json|--run-summary-json)
      run_summary_json="${2:-}"
      shift 2
      ;;
    --stability-summary-json=*|--run-summary-json=*)
      run_summary_json="${1#*=}"
      shift
      ;;
    --stability-check-summary-json|--check-summary-json)
      check_summary_json="${2:-}"
      shift 2
      ;;
    --stability-check-summary-json=*|--check-summary-json=*)
      check_summary_json="${1#*=}"
      shift
      ;;
    --cycle-summary-json)
      cycle_summary_json="${2:-}"
      shift 2
      ;;
    --cycle-summary-json=*)
      cycle_summary_json="${1#*=}"
      shift
      ;;
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
  echo "fake pack: missing --summary-json" >&2
  exit 2
fi
if [[ -z "$report_md" ]]; then
  echo "fake pack: missing --report-md" >&2
  exit 2
fi

if [[ -n "$capture_file" ]]; then
  printf 'pack\tscenario=%s\treports_dir=%s\tfail_on_no_go=%s\trun_summary_json=%s\tcheck_summary_json=%s\tcycle_summary_json=%s\tsummary_json=%s\treport_md=%s\n' \
    "$scenario" "$reports_dir" "$fail_on_no_go" "$run_summary_json" "$check_summary_json" "$cycle_summary_json" "$summary_json" "$report_md" >>"$capture_file"
fi

if [[ "$scenario" == "runner_fail" ]]; then
  exit 23
fi

mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
now_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

if [[ "$scenario" == "warn_no_go" ]]; then
  jq -n \
    --arg generated_at_utc "$now_utc" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_evidence_pack_summary" },
      generated_at_utc: $generated_at_utc,
      status: "warn",
      rc: 0,
      decision: "NO-GO",
      reasons: ["simulated warn-only NO-GO"]
    }' >"$summary_json"
else
  jq -n \
    --arg generated_at_utc "$now_utc" \
    '{
      version: 1,
      schema: { id: "profile_default_gate_stability_evidence_pack_summary" },
      generated_at_utc: $generated_at_utc,
      status: "ok",
      rc: 0,
      decision: "GO",
      reasons: []
    }' >"$summary_json"
fi

cat >"$report_md" <<'EOF_PACK_REPORT'
# Fake Profile Default Gate Stability Evidence Pack Report
EOF_PACK_REPORT
EOF_FAKE_PACK
chmod +x "$FAKE_PACK"

echo "[profile-default-gate-stability-live-archive-and-pack] help contract"
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--reports-dir DIR" >/dev/null; then
  echo "help output missing --reports-dir DIR"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--summary-json PATH" >/dev/null; then
  echo "help output missing --summary-json PATH"
  exit 1
fi
if ! bash "$SCRIPT_UNDER_TEST" --help | grep -F -- "--print-summary-json [0|1]" >/dev/null; then
  echo "help output missing --print-summary-json [0|1]"
  exit 1
fi

echo "[profile-default-gate-stability-live-archive-and-pack] pass path"
PASS_DIR="$TMP_DIR/pass"
PASS_REPORTS="$PASS_DIR/reports"
PASS_SUMMARY="$PASS_DIR/bundle_summary.json"
: >"$CAPTURE_FILE"
set +e
PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_CYCLE_SCRIPT="$FAKE_CYCLE" \
PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_EVIDENCE_PACK_SCRIPT="$FAKE_PACK" \
FAKE_LIVE_ARCHIVE_PACK_CAPTURE_FILE="$CAPTURE_FILE" \
FAKE_LIVE_ARCHIVE_PACK_CYCLE_SCENARIO="pass" \
FAKE_LIVE_ARCHIVE_PACK_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "198.51.100.10" \
  --host-b "198.51.100.11" \
  --campaign-subject "inv-pass-01" \
  --reports-dir "$PASS_REPORTS" \
  --summary-json "$PASS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_live_archive_and_pack_pass.log 2>&1
pass_rc=$?
set -e
if [[ "$pass_rc" -ne 0 ]]; then
  echo "expected pass-path rc=0, got rc=$pass_rc"
  cat /tmp/integration_profile_default_gate_stability_live_archive_and_pack_pass.log
  exit 1
fi

assert_jq "$PASS_SUMMARY" '
  .schema.id == "profile_default_gate_stability_live_archive_and_pack_summary"
  and .status == "pass"
  and .rc == 0
  and .decision == "GO"
  and .failure_reason_code == null
  and .prerequisites.ok == true
  and .prerequisites.missing_prerequisites_count == 0
  and .prerequisites.missing_artifacts_count == 0
  and .stages.cycle.attempted == true
  and .stages.cycle.status == "pass"
  and .stages.cycle.summary.usable == true
  and .stages.evidence_pack.attempted == true
  and .stages.evidence_pack.status == "pass"
  and .stages.evidence_pack.summary.usable == true
  and .stages.archive.attempted == true
  and .stages.archive.status == "pass"
  and .stages.archive.missing_required_count == 0
  and .stages.archive.copied_count >= 4
'

PASS_ARCHIVE_SUMMARY="$(jq -r '.artifacts.archive_summary_json' "$PASS_SUMMARY")"
if [[ ! -f "$PASS_ARCHIVE_SUMMARY" ]]; then
  echo "expected archive summary missing: $PASS_ARCHIVE_SUMMARY"
  cat "$PASS_SUMMARY"
  exit 1
fi
assert_jq "$PASS_ARCHIVE_SUMMARY" '
  .schema.id == "profile_default_gate_stability_live_archive_summary"
  and .status == "pass"
  and .rc == 0
  and .summary.missing_required_count == 0
'

if ! grep -q '^cycle' "$CAPTURE_FILE"; then
  echo "expected cycle invocation capture"
  cat "$CAPTURE_FILE"
  exit 1
fi
if ! grep -q '^pack' "$CAPTURE_FILE"; then
  echo "expected pack invocation capture"
  cat "$CAPTURE_FILE"
  exit 1
fi
if ! grep -q $'cycle\t.*\thost_a=198.51.100.10\thost_b=198.51.100.11\tcampaign_subject=inv-pass-01\t' "$CAPTURE_FILE"; then
  echo "expected cycle argument forwarding capture"
  cat "$CAPTURE_FILE"
  exit 1
fi

echo "[profile-default-gate-stability-live-archive-and-pack] missing artifacts fail closed"
MISS_DIR="$TMP_DIR/missing_artifacts"
MISS_REPORTS="$MISS_DIR/reports"
MISS_SUMMARY="$MISS_DIR/bundle_summary.json"
: >"$CAPTURE_FILE"
set +e
PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_CYCLE_SCRIPT="$FAKE_CYCLE" \
PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_EVIDENCE_PACK_SCRIPT="$FAKE_PACK" \
FAKE_LIVE_ARCHIVE_PACK_CAPTURE_FILE="$CAPTURE_FILE" \
FAKE_LIVE_ARCHIVE_PACK_CYCLE_SCENARIO="missing_artifacts" \
FAKE_LIVE_ARCHIVE_PACK_PACK_SCENARIO="pass" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "198.51.100.20" \
  --host-b "198.51.100.21" \
  --campaign-subject "inv-missing-01" \
  --reports-dir "$MISS_REPORTS" \
  --summary-json "$MISS_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_live_archive_and_pack_missing.log 2>&1
miss_rc=$?
set -e
if [[ "$miss_rc" -eq 0 ]]; then
  echo "expected missing-artifacts path rc!=0"
  cat /tmp/integration_profile_default_gate_stability_live_archive_and_pack_missing.log
  exit 1
fi

assert_jq "$MISS_SUMMARY" '
  .status == "fail"
  and .rc != 0
  and .failure_reason_code == "archive_missing_required_artifacts"
  and .failure_substep == "archive_missing_required_artifacts"
  and .prerequisites.ok == false
  and .prerequisites.missing_prerequisites_count == 0
  and .prerequisites.missing_artifacts_count >= 2
  and (.prerequisites.missing_artifacts | index("run_summary_json")) != null
  and (.prerequisites.missing_artifacts | index("check_summary_json")) != null
  and .stages.cycle.attempted == true
  and .stages.cycle.status == "pass"
  and .stages.evidence_pack.attempted == true
  and .stages.evidence_pack.status == "pass"
  and .stages.archive.attempted == true
  and .stages.archive.status == "fail"
  and .stages.archive.missing_required_count >= 2
  and (.stages.archive.missing_required_artifacts | index("run_summary_json")) != null
  and (.stages.archive.missing_required_artifacts | index("check_summary_json")) != null
  and ((.reasons | map(test("^archive: missing required artifact run_summary_json$")) | any) == true)
'

echo "[profile-default-gate-stability-live-archive-and-pack] preflight missing-subject fail closed"
PREFLIGHT_DIR="$TMP_DIR/preflight"
PREFLIGHT_SUMMARY="$PREFLIGHT_DIR/bundle_summary.json"
mkdir -p "$PREFLIGHT_DIR"
set +e
PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_CYCLE_SCRIPT="$FAKE_CYCLE" \
PROFILE_DEFAULT_GATE_STABILITY_LIVE_ARCHIVE_AND_PACK_EVIDENCE_PACK_SCRIPT="$FAKE_PACK" \
bash "$SCRIPT_UNDER_TEST" \
  --host-a "198.51.100.30" \
  --host-b "198.51.100.31" \
  --reports-dir "$PREFLIGHT_DIR/reports" \
  --summary-json "$PREFLIGHT_SUMMARY" \
  --print-summary-json 0 >/tmp/integration_profile_default_gate_stability_live_archive_and_pack_preflight.log 2>&1
preflight_rc=$?
set -e
if [[ "$preflight_rc" -ne 2 ]]; then
  echo "expected preflight-missing-subject rc=2, got rc=$preflight_rc"
  cat /tmp/integration_profile_default_gate_stability_live_archive_and_pack_preflight.log
  exit 1
fi

assert_jq "$PREFLIGHT_SUMMARY" '
  .status == "fail"
  and .rc == 2
  and .failure_reason_code == "preflight_missing_prerequisites"
  and .failure_substep == "preflight_validation_failed"
  and .prerequisites.ok == false
  and .prerequisites.missing_prerequisites_count >= 1
  and ((.prerequisites.missing_prerequisites | index("campaign_subject_missing")) != null)
  and .stages.cycle.attempted == false
  and .stages.evidence_pack.attempted == false
  and .stages.archive.attempted == false
'

echo "integration_profile_default_gate_stability_live_archive_and_pack: PASS"
