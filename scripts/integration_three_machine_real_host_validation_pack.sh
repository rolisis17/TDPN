#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp grep cat date; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

SCRIPT_UNDER_TEST="${THREE_MACHINE_REAL_HOST_VALIDATION_PACK_SCRIPT_UNDER_TEST:-$ROOT_DIR/scripts/three_machine_real_host_validation_pack.sh}"
if [[ ! -f "$SCRIPT_UNDER_TEST" ]]; then
  echo "missing script under test: $SCRIPT_UNDER_TEST"
  exit 2
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT
FRESH_GENERATED_AT_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
STALE_GENERATED_AT_UTC="2000-01-01T00:00:00Z"

assert_jq() {
  local file="$1"
  local query="$2"
  if ! jq -e "$query" "$file" >/dev/null; then
    echo "assertion failed: $query"
    echo "file: $file"
    cat "$file"
    exit 1
  fi
}

write_matrix_summary() {
  local path="$1"
  local generated_at_utc="${2:-$FRESH_GENERATED_AT_UTC}"
  jq -n --arg generated_at_utc "$generated_at_utc" '{
    version: 1,
    schema: { id: "three_machine_docker_profile_matrix_summary" },
    generated_at_utc: $generated_at_utc,
    status: "pass",
    rc: 0
  }' >"$path"
}

write_matrix_record_summary() {
  local path="$1"
  local generated_at_utc="${2:-$FRESH_GENERATED_AT_UTC}"
  local manual_report_status="${3:-ok}"
  local receipt_status="${4:-ok}"
  local receipt_written="${5:-true}"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg manual_report_status "$manual_report_status" \
    --arg receipt_status "$receipt_status" \
    --argjson receipt_written "$receipt_written" \
    '{
      version: 1,
      schema: { id: "three_machine_docker_profile_matrix_record_summary" },
      generated_at_utc: $generated_at_utc,
      status: "pass",
      rc: 0,
      stages: {
        matrix: { status: "pass", rc: 0 },
        manual_validation_report: {
          enabled: true,
          status: $manual_report_status,
          rc: (if $manual_report_status == "ok" then 0 else 1 end),
          written_summary_json: true,
          written_report_md: true
        },
        manual_validation_record: {
          enabled: true,
          status: $receipt_status,
          rc: (if $receipt_status == "ok" then 0 else 1 end),
          written_receipt: $receipt_written
        }
      }
    }' >"$path"
}

write_readiness_summary() {
  local path="$1"
  local generated_at_utc="${2:-$FRESH_GENERATED_AT_UTC}"
  jq -n --arg generated_at_utc "$generated_at_utc" '{
    version: 1,
    schema: { id: "three_machine_docker_readiness_summary" },
    generated_at_utc: $generated_at_utc,
    status: "pass",
    rc: 0
  }' >"$path"
}

write_readiness_record_summary() {
  local path="$1"
  local generated_at_utc="${2:-$FRESH_GENERATED_AT_UTC}"
  local manual_status="${3:-ok}"
  local receipt_status="${4:-ok}"
  local receipt_written="${5:-true}"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg manual_status "$manual_status" \
    --arg receipt_status "$receipt_status" \
    --argjson receipt_written "$receipt_written" \
    '{
    version: 1,
    schema: { id: "three_machine_docker_readiness_record_summary" },
    generated_at_utc: $generated_at_utc,
    status: "pass",
    rc: 0,
    rehearsal: {
      status: "pass",
      rc: 0,
      summary: {
        generated_at_utc: $generated_at_utc,
        status: "pass",
        rc: 0
      }
    },
    manual_validation_report: {
      enabled: true,
      status: $manual_status
    },
    manual_validation_record: {
      enabled: true,
      status: $receipt_status,
      rc: (if $receipt_status == "ok" then 0 else 1 end),
      written_receipt: $receipt_written
    }
  }' >"$path"
}

write_real_host_summary() {
  local path="$1"
  local generated_at_utc="${2:-$FRESH_GENERATED_AT_UTC}"
  jq -n --arg generated_at_utc "$generated_at_utc" '{
    version: 1,
    schema: { id: "three_machine_prod_signoff_summary" },
    generated_at_utc: $generated_at_utc,
    status: "pass",
    rc: 0,
    decision: "GO"
  }' >"$path"
}

write_real_host_summary_fail() {
  local path="$1"
  local generated_at_utc="${2:-$FRESH_GENERATED_AT_UTC}"
  jq -n --arg generated_at_utc "$generated_at_utc" '{
    version: 1,
    schema: { id: "three_machine_prod_signoff_summary" },
    generated_at_utc: $generated_at_utc,
    status: "fail",
    rc: 1,
    decision: "NO-GO"
  }' >"$path"
}

write_real_host_summary_missing_rc() {
  local path="$1"
  local generated_at_utc="${2:-$FRESH_GENERATED_AT_UTC}"
  jq -n --arg generated_at_utc "$generated_at_utc" '{
    version: 1,
    schema: { id: "three_machine_prod_signoff_summary" },
    generated_at_utc: $generated_at_utc,
    status: "pass",
    decision: "GO"
  }' >"$path"
}

echo "[three-machine-real-host-validation-pack] pass path"
PASS_DIR="$TMP_DIR/pass"
mkdir -p "$PASS_DIR"
write_matrix_summary "$PASS_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_summary "$PASS_DIR/three_machine_docker_readiness_2hop.json" "$FRESH_GENERATED_AT_UTC"
write_real_host_summary "$PASS_DIR/three_machine_prod_signoff_summary.json" "$FRESH_GENERATED_AT_UTC"

PASS_SUMMARY="$PASS_DIR/validation_pack_summary.json"
PASS_REPORT="$PASS_DIR/validation_pack_report.md"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$PASS_DIR" \
  --summary-json "$PASS_SUMMARY" \
  --report-md "$PASS_REPORT" \
  --print-summary-json 0

assert_jq "$PASS_SUMMARY" '.schema.id == "three_machine_real_host_validation_pack_summary"'
assert_jq "$PASS_SUMMARY" '.status == "ok"'
assert_jq "$PASS_SUMMARY" '.rc == 0'
assert_jq "$PASS_SUMMARY" '.decision == "GO"'
if ! jq -e --arg summary_path "$PASS_SUMMARY" '.inputs.summary_json == $summary_path' "$PASS_SUMMARY" >/dev/null; then
  echo "assertion failed: .inputs.summary_json == PASS_SUMMARY"
  cat "$PASS_SUMMARY"
  exit 1
fi
if ! jq -e --arg report_path "$PASS_REPORT" '.inputs.report_md == $report_path' "$PASS_SUMMARY" >/dev/null; then
  echo "assertion failed: .inputs.report_md == PASS_REPORT"
  cat "$PASS_SUMMARY"
  exit 1
fi
assert_jq "$PASS_SUMMARY" '.inputs.include_missing == false'
assert_jq "$PASS_SUMMARY" '.required_groups.docker_matrix.usable == true'
assert_jq "$PASS_SUMMARY" '.required_groups.docker_readiness.usable == true'
assert_jq "$PASS_SUMMARY" '.required_groups.real_host.usable == true'
assert_jq "$PASS_SUMMARY" '.counts.discovered_artifacts >= 3'
if [[ ! -f "$PASS_REPORT" ]]; then
  echo "expected report markdown missing: $PASS_REPORT"
  exit 1
fi
if [[ ! -d "$PASS_DIR/three_machine_real_host_validation_pack_artifacts" ]]; then
  echo "expected collected artifacts dir missing in pass path"
  exit 1
fi

echo "[three-machine-real-host-validation-pack] timestamped docker readiness record path"
RECORD_DIR="$TMP_DIR/record"
mkdir -p "$RECORD_DIR"
write_matrix_summary "$RECORD_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_record_summary "$RECORD_DIR/three_machine_docker_readiness_record_20260507_110000.json" "$FRESH_GENERATED_AT_UTC"
write_real_host_summary "$RECORD_DIR/three_machine_prod_signoff_summary.json" "$FRESH_GENERATED_AT_UTC"

RECORD_SUMMARY="$RECORD_DIR/validation_pack_summary.json"
RECORD_REPORT="$RECORD_DIR/validation_pack_report.md"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$RECORD_DIR" \
  --summary-json "$RECORD_SUMMARY" \
  --report-md "$RECORD_REPORT" \
  --print-summary-json 0

assert_jq "$RECORD_SUMMARY" '.status == "ok"'
assert_jq "$RECORD_SUMMARY" '.rc == 0'
assert_jq "$RECORD_SUMMARY" '.decision == "GO"'
assert_jq "$RECORD_SUMMARY" '.required_groups.docker_readiness.usable == true'
assert_jq "$RECORD_SUMMARY" '.artifacts | map(select(.id == "docker_readiness_record_summary" and .usable == true)) | length == 1'

echo "[three-machine-real-host-validation-pack] docker readiness record with failed manual report is unusable"
RECORD_MANUAL_FAIL_DIR="$TMP_DIR/record_manual_fail"
mkdir -p "$RECORD_MANUAL_FAIL_DIR"
write_matrix_summary "$RECORD_MANUAL_FAIL_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_record_summary "$RECORD_MANUAL_FAIL_DIR/three_machine_docker_readiness_record_20260507_120000.json" "$FRESH_GENERATED_AT_UTC" "fail"
write_real_host_summary "$RECORD_MANUAL_FAIL_DIR/three_machine_prod_signoff_summary.json" "$FRESH_GENERATED_AT_UTC"

RECORD_MANUAL_FAIL_SUMMARY="$RECORD_MANUAL_FAIL_DIR/validation_pack_summary.json"
RECORD_MANUAL_FAIL_REPORT="$RECORD_MANUAL_FAIL_DIR/validation_pack_report.md"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$RECORD_MANUAL_FAIL_DIR" \
  --summary-json "$RECORD_MANUAL_FAIL_SUMMARY" \
  --report-md "$RECORD_MANUAL_FAIL_REPORT" \
  --include-missing 0 \
  --print-summary-json 0 >/tmp/integration_three_machine_real_host_validation_pack_record_manual_fail.log 2>&1
RECORD_MANUAL_FAIL_RC=$?
set -e

if [[ "$RECORD_MANUAL_FAIL_RC" -eq 0 ]]; then
  echo "expected non-zero rc when docker readiness record manual report failed"
  cat /tmp/integration_three_machine_real_host_validation_pack_record_manual_fail.log
  exit 1
fi
assert_jq "$RECORD_MANUAL_FAIL_SUMMARY" '.status == "fail"'
assert_jq "$RECORD_MANUAL_FAIL_SUMMARY" '.decision == "NO-GO"'
assert_jq "$RECORD_MANUAL_FAIL_SUMMARY" '.required_groups.docker_readiness.usable == false'
assert_jq "$RECORD_MANUAL_FAIL_SUMMARY" '.artifacts | map(select(.id == "docker_readiness_record_summary" and .semantic_usable == false)) | length == 1'

echo "[three-machine-real-host-validation-pack] docker readiness record with missing receipt is unusable"
RECORD_RECEIPT_MISSING_DIR="$TMP_DIR/record_receipt_missing"
mkdir -p "$RECORD_RECEIPT_MISSING_DIR"
write_matrix_summary "$RECORD_RECEIPT_MISSING_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_record_summary "$RECORD_RECEIPT_MISSING_DIR/three_machine_docker_readiness_record_20260507_120500.json" "$FRESH_GENERATED_AT_UTC" "ok" "ok" "false"
write_real_host_summary "$RECORD_RECEIPT_MISSING_DIR/three_machine_prod_signoff_summary.json" "$FRESH_GENERATED_AT_UTC"

RECORD_RECEIPT_MISSING_SUMMARY="$RECORD_RECEIPT_MISSING_DIR/validation_pack_summary.json"
RECORD_RECEIPT_MISSING_REPORT="$RECORD_RECEIPT_MISSING_DIR/validation_pack_report.md"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$RECORD_RECEIPT_MISSING_DIR" \
  --summary-json "$RECORD_RECEIPT_MISSING_SUMMARY" \
  --report-md "$RECORD_RECEIPT_MISSING_REPORT" \
  --include-missing 0 \
  --print-summary-json 0 >/tmp/integration_three_machine_real_host_validation_pack_record_receipt_missing.log 2>&1
RECORD_RECEIPT_MISSING_RC=$?
set -e

if [[ "$RECORD_RECEIPT_MISSING_RC" -eq 0 ]]; then
  echo "expected non-zero rc when docker readiness record receipt is missing"
  cat /tmp/integration_three_machine_real_host_validation_pack_record_receipt_missing.log
  exit 1
fi
assert_jq "$RECORD_RECEIPT_MISSING_SUMMARY" '.status == "fail"'
assert_jq "$RECORD_RECEIPT_MISSING_SUMMARY" '.decision == "NO-GO"'
assert_jq "$RECORD_RECEIPT_MISSING_SUMMARY" '.required_groups.docker_readiness.usable == false'
assert_jq "$RECORD_RECEIPT_MISSING_SUMMARY" '.artifacts | map(select(.id == "docker_readiness_record_summary" and .semantic_usable == false)) | length == 1'

echo "[three-machine-real-host-validation-pack] failed readiness record is not masked by passing rehearsal child"
RECORD_REHEARSAL_MASK_DIR="$TMP_DIR/record_rehearsal_mask"
mkdir -p "$RECORD_REHEARSAL_MASK_DIR"
write_matrix_summary "$RECORD_REHEARSAL_MASK_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_record_summary "$RECORD_REHEARSAL_MASK_DIR/three_machine_docker_readiness_record_20260507_121500.json" "$FRESH_GENERATED_AT_UTC" "fail"
write_readiness_summary "$RECORD_REHEARSAL_MASK_DIR/three_machine_docker_readiness_record_20260507_121500_rehearsal.json" "$FRESH_GENERATED_AT_UTC"
write_real_host_summary "$RECORD_REHEARSAL_MASK_DIR/three_machine_prod_signoff_summary.json" "$FRESH_GENERATED_AT_UTC"

RECORD_REHEARSAL_MASK_SUMMARY="$RECORD_REHEARSAL_MASK_DIR/validation_pack_summary.json"
RECORD_REHEARSAL_MASK_REPORT="$RECORD_REHEARSAL_MASK_DIR/validation_pack_report.md"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$RECORD_REHEARSAL_MASK_DIR" \
  --summary-json "$RECORD_REHEARSAL_MASK_SUMMARY" \
  --report-md "$RECORD_REHEARSAL_MASK_REPORT" \
  --include-missing 0 \
  --print-summary-json 0 >/tmp/integration_three_machine_real_host_validation_pack_record_rehearsal_mask.log 2>&1
RECORD_REHEARSAL_MASK_RC=$?
set -e

if [[ "$RECORD_REHEARSAL_MASK_RC" -eq 0 ]]; then
  echo "expected non-zero rc when failed docker readiness record has a passing rehearsal child"
  cat /tmp/integration_three_machine_real_host_validation_pack_record_rehearsal_mask.log
  exit 1
fi
assert_jq "$RECORD_REHEARSAL_MASK_SUMMARY" '.status == "fail"'
assert_jq "$RECORD_REHEARSAL_MASK_SUMMARY" '.decision == "NO-GO"'
assert_jq "$RECORD_REHEARSAL_MASK_SUMMARY" '.required_groups.docker_readiness.usable == false'
assert_jq "$RECORD_REHEARSAL_MASK_SUMMARY" '.artifacts | map(select(.id == "docker_readiness_record_summary" and .group == "docker_readiness" and .semantic_usable == false)) | length == 1'
assert_jq "$RECORD_REHEARSAL_MASK_SUMMARY" '.artifacts | map(select(.id == "docker_readiness_record_rehearsal" and .group == "docker_readiness_support" and .usable == true)) | length == 1'

echo "[three-machine-real-host-validation-pack] profile matrix record with failed nested report is unusable"
MATRIX_RECORD_FAIL_DIR="$TMP_DIR/matrix_record_fail"
mkdir -p "$MATRIX_RECORD_FAIL_DIR"
write_matrix_record_summary "$MATRIX_RECORD_FAIL_DIR/three_machine_docker_profile_matrix_record_summary.json" "$FRESH_GENERATED_AT_UTC" "fail"
write_readiness_summary "$MATRIX_RECORD_FAIL_DIR/three_machine_docker_readiness_2hop.json" "$FRESH_GENERATED_AT_UTC"
write_real_host_summary "$MATRIX_RECORD_FAIL_DIR/three_machine_prod_signoff_summary.json" "$FRESH_GENERATED_AT_UTC"

MATRIX_RECORD_FAIL_SUMMARY="$MATRIX_RECORD_FAIL_DIR/validation_pack_summary.json"
MATRIX_RECORD_FAIL_REPORT="$MATRIX_RECORD_FAIL_DIR/validation_pack_report.md"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MATRIX_RECORD_FAIL_DIR" \
  --summary-json "$MATRIX_RECORD_FAIL_SUMMARY" \
  --report-md "$MATRIX_RECORD_FAIL_REPORT" \
  --include-missing 0 \
  --print-summary-json 0 >/tmp/integration_three_machine_real_host_validation_pack_matrix_record_fail.log 2>&1
MATRIX_RECORD_FAIL_RC=$?
set -e

if [[ "$MATRIX_RECORD_FAIL_RC" -eq 0 ]]; then
  echo "expected non-zero rc when docker profile matrix record nested report failed"
  cat /tmp/integration_three_machine_real_host_validation_pack_matrix_record_fail.log
  exit 1
fi
assert_jq "$MATRIX_RECORD_FAIL_SUMMARY" '.status == "fail"'
assert_jq "$MATRIX_RECORD_FAIL_SUMMARY" '.decision == "NO-GO"'
assert_jq "$MATRIX_RECORD_FAIL_SUMMARY" '.required_groups.docker_matrix.usable == false'
assert_jq "$MATRIX_RECORD_FAIL_SUMMARY" '.artifacts | map(select(.id == "docker_matrix_record_summary" and .semantic_usable == false)) | length == 1'

echo "[three-machine-real-host-validation-pack] missing real-host fail-closed path"
FAIL_DIR="$TMP_DIR/fail"
mkdir -p "$FAIL_DIR"
write_matrix_summary "$FAIL_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_summary "$FAIL_DIR/three_machine_docker_readiness_2hop.json" "$FRESH_GENERATED_AT_UTC"

FAIL_SUMMARY="$FAIL_DIR/validation_pack_summary.json"
FAIL_REPORT="$FAIL_DIR/validation_pack_report.md"

set +e
bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$FAIL_DIR" \
  --summary-json "$FAIL_SUMMARY" \
  --report-md "$FAIL_REPORT" \
  --include-missing 0 \
  --print-summary-json 0 >/tmp/integration_three_machine_real_host_validation_pack_fail.log 2>&1
FAIL_RC=$?
set -e

if [[ "$FAIL_RC" -eq 0 ]]; then
  echo "expected non-zero rc when required real-host evidence is missing"
  cat /tmp/integration_three_machine_real_host_validation_pack_fail.log
  exit 1
fi
assert_jq "$FAIL_SUMMARY" '.status == "fail"'
assert_jq "$FAIL_SUMMARY" '.rc != 0'
assert_jq "$FAIL_SUMMARY" '.decision == "NO-GO"'
assert_jq "$FAIL_SUMMARY" '.required_groups.real_host.usable == false'
assert_jq "$FAIL_SUMMARY" '.reasons | index("missing usable real-host signoff evidence artifacts") != null'
assert_jq "$FAIL_SUMMARY" '.next_recommended_commands | map(select(.command | contains("three-machine-prod-signoff"))) | length > 0'

echo "[three-machine-real-host-validation-pack] missing real-host warn path"
WARN_DIR="$TMP_DIR/warn"
mkdir -p "$WARN_DIR"
write_matrix_summary "$WARN_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_summary "$WARN_DIR/three_machine_docker_readiness_2hop.json" "$FRESH_GENERATED_AT_UTC"

WARN_SUMMARY="$WARN_DIR/validation_pack_summary.json"
WARN_REPORT="$WARN_DIR/validation_pack_report.md"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$WARN_DIR" \
  --summary-json "$WARN_SUMMARY" \
  --report-md "$WARN_REPORT" \
  --include-missing 1 \
  --print-summary-json 0

assert_jq "$WARN_SUMMARY" '.status == "warn"'
assert_jq "$WARN_SUMMARY" '.rc == 0'
assert_jq "$WARN_SUMMARY" '.decision == "NO-GO"'
assert_jq "$WARN_SUMMARY" '.inputs.include_missing == true'
assert_jq "$WARN_SUMMARY" '.required_groups.real_host.usable == false'
assert_jq "$WARN_SUMMARY" '.reasons | index("missing usable real-host signoff evidence artifacts") != null'

echo "[three-machine-real-host-validation-pack] semantic NO-GO real-host artifact stays unusable"
SEMANTIC_DIR="$TMP_DIR/semantic"
mkdir -p "$SEMANTIC_DIR"
write_matrix_summary "$SEMANTIC_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_summary "$SEMANTIC_DIR/three_machine_docker_readiness_2hop.json" "$FRESH_GENERATED_AT_UTC"
write_real_host_summary_fail "$SEMANTIC_DIR/three_machine_prod_signoff_summary.json" "$FRESH_GENERATED_AT_UTC"

SEMANTIC_SUMMARY="$SEMANTIC_DIR/validation_pack_summary.json"
SEMANTIC_REPORT="$SEMANTIC_DIR/validation_pack_report.md"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$SEMANTIC_DIR" \
  --summary-json "$SEMANTIC_SUMMARY" \
  --report-md "$SEMANTIC_REPORT" \
  --include-missing 1 \
  --print-summary-json 0

assert_jq "$SEMANTIC_SUMMARY" '.status == "warn"'
assert_jq "$SEMANTIC_SUMMARY" '.rc == 0'
assert_jq "$SEMANTIC_SUMMARY" '.decision == "NO-GO"'
assert_jq "$SEMANTIC_SUMMARY" '.required_groups.real_host.found == true'
assert_jq "$SEMANTIC_SUMMARY" '.required_groups.real_host.usable == false'
assert_jq "$SEMANTIC_SUMMARY" '.reasons | index("missing usable real-host signoff evidence artifacts") != null'

echo "[three-machine-real-host-validation-pack] missing rc real-host artifact stays unusable"
MISSING_RC_DIR="$TMP_DIR/missing_rc"
mkdir -p "$MISSING_RC_DIR"
write_matrix_summary "$MISSING_RC_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_summary "$MISSING_RC_DIR/three_machine_docker_readiness_2hop.json" "$FRESH_GENERATED_AT_UTC"
write_real_host_summary_missing_rc "$MISSING_RC_DIR/three_machine_prod_signoff_summary.json" "$FRESH_GENERATED_AT_UTC"

MISSING_RC_SUMMARY="$MISSING_RC_DIR/validation_pack_summary.json"
MISSING_RC_REPORT="$MISSING_RC_DIR/validation_pack_report.md"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$MISSING_RC_DIR" \
  --summary-json "$MISSING_RC_SUMMARY" \
  --report-md "$MISSING_RC_REPORT" \
  --include-missing 1 \
  --print-summary-json 0

assert_jq "$MISSING_RC_SUMMARY" '.status == "warn"'
assert_jq "$MISSING_RC_SUMMARY" '.rc == 0'
assert_jq "$MISSING_RC_SUMMARY" '.decision == "NO-GO"'
assert_jq "$MISSING_RC_SUMMARY" '.required_groups.real_host.found == true'
assert_jq "$MISSING_RC_SUMMARY" '.required_groups.real_host.usable == false'
assert_jq "$MISSING_RC_SUMMARY" '.reasons | index("missing usable real-host signoff evidence artifacts") != null'

echo "[three-machine-real-host-validation-pack] stale GO real-host artifact fails freshness gate"
STALE_DIR="$TMP_DIR/stale"
mkdir -p "$STALE_DIR"
write_matrix_summary "$STALE_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_summary "$STALE_DIR/three_machine_docker_readiness_2hop.json" "$FRESH_GENERATED_AT_UTC"
write_real_host_summary "$STALE_DIR/three_machine_prod_signoff_summary.json" "$STALE_GENERATED_AT_UTC"

STALE_SUMMARY="$STALE_DIR/validation_pack_summary.json"
STALE_REPORT="$STALE_DIR/validation_pack_report.md"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$STALE_DIR" \
  --summary-json "$STALE_SUMMARY" \
  --report-md "$STALE_REPORT" \
  --include-missing 1 \
  --max-age-sec 3600 \
  --print-summary-json 0

assert_jq "$STALE_SUMMARY" '.status == "warn"'
assert_jq "$STALE_SUMMARY" '.rc == 0'
assert_jq "$STALE_SUMMARY" '.decision == "NO-GO"'
assert_jq "$STALE_SUMMARY" '.inputs.max_age_sec == 3600'
assert_jq "$STALE_SUMMARY" '.required_groups.real_host.found == true'
assert_jq "$STALE_SUMMARY" '.required_groups.real_host.usable == false'
assert_jq "$STALE_SUMMARY" '.required_groups.real_host.freshness_blocked == true'
assert_jq "$STALE_SUMMARY" '.reasons | index("missing usable real-host signoff evidence artifacts") != null'
assert_jq "$STALE_SUMMARY" '.reasons | index("real-host signoff evidence artifacts are stale or freshness-unknown (max-age-sec=3600)") != null'
assert_jq "$STALE_SUMMARY" '.artifacts | map(select(.group == "real_host")) | map(select(.semantic_usable == true and .freshness.fresh == false and .usable == false)) | length > 0'

echo "[three-machine-real-host-validation-pack] archived real-host artifacts are ignored for required signoff gating"
ARCHIVE_FILTER_DIR="$TMP_DIR/archive_filter"
mkdir -p "$ARCHIVE_FILTER_DIR"
write_matrix_summary "$ARCHIVE_FILTER_DIR/three_machine_docker_profile_matrix_summary.json" "$FRESH_GENERATED_AT_UTC"
write_readiness_summary "$ARCHIVE_FILTER_DIR/three_machine_docker_readiness_2hop.json" "$FRESH_GENERATED_AT_UTC"
mkdir -p "$ARCHIVE_FILTER_DIR/roadmap_live_evidence_archive/roadmap_live_evidence_archive_20260423_000000/profile-default"
write_real_host_summary "$ARCHIVE_FILTER_DIR/roadmap_live_evidence_archive/roadmap_live_evidence_archive_20260423_000000/profile-default/three_machine_prod_signoff_summary.json" "$FRESH_GENERATED_AT_UTC"

ARCHIVE_FILTER_SUMMARY="$ARCHIVE_FILTER_DIR/validation_pack_summary.json"
ARCHIVE_FILTER_REPORT="$ARCHIVE_FILTER_DIR/validation_pack_report.md"

bash "$SCRIPT_UNDER_TEST" \
  --reports-dir "$ARCHIVE_FILTER_DIR" \
  --summary-json "$ARCHIVE_FILTER_SUMMARY" \
  --report-md "$ARCHIVE_FILTER_REPORT" \
  --include-missing 1 \
  --print-summary-json 0

assert_jq "$ARCHIVE_FILTER_SUMMARY" '.status == "warn"'
assert_jq "$ARCHIVE_FILTER_SUMMARY" '.required_groups.real_host.found == false'
assert_jq "$ARCHIVE_FILTER_SUMMARY" '.required_groups.real_host.usable == false'

echo "integration_three_machine_real_host_validation_pack: PASS"
