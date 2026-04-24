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
