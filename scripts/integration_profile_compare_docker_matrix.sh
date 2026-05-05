#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp chmod grep tail id jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

CAPTURE="$TMP_DIR/profile_compare_docker_matrix_calls.tsv"
HELP_OUT="$TMP_DIR/easy_node_help.txt"
FAKE_MATRIX="$TMP_DIR/fake_profile_compare_docker_matrix.sh"
MATRIX_RUNTIME_CAPTURE="$TMP_DIR/profile_compare_docker_matrix_runtime_calls.tsv"
MATRIX_RUNTIME_STDOUT="$TMP_DIR/profile_compare_docker_matrix_runtime_stdout.txt"
MATRIX_RUNTIME_STDERR="$TMP_DIR/profile_compare_docker_matrix_runtime_stderr.txt"
FAKE_CAMPAIGN="$TMP_DIR/fake_profile_compare_campaign.sh"

cat >"$FAKE_MATRIX" <<'EOF_FAKE_MATRIX'
#!/usr/bin/env bash
set -euo pipefail
capture="${PROFILE_COMPARE_DOCKER_MATRIX_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"
EOF_FAKE_MATRIX
chmod +x "$FAKE_MATRIX"

cat >"$FAKE_CAMPAIGN" <<'EOF_FAKE_CAMPAIGN'
#!/usr/bin/env bash
set -euo pipefail
capture="${PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_CAPTURE_FILE:?}"
{
  printf 'argc=%s' "$#"
  for arg in "$@"; do
    printf '\t%s' "$arg"
  done
  printf '\n'
} >>"$capture"
exit "${PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_FAKE_RC:-0}"
EOF_FAKE_CAMPAIGN
chmod +x "$FAKE_CAMPAIGN"

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

extract_stdout_value() {
  local file="$1"
  local key="$2"
  local line
  line="$(grep -m 1 -E "^${key}: " "$file" || true)"
  if [[ -z "$line" ]]; then
    printf '%s' ""
    return
  fi
  printf '%s' "${line#"$key: "}"
}

assert_file_exists() {
  local path="$1"
  local message="$2"
  if [[ ! -f "$path" ]]; then
    echo "$message"
    echo "missing file: $path"
    exit 1
  fi
}

echo "[profile-compare-docker-matrix] usage contract is advertised"
./scripts/easy_node.sh help >"$HELP_OUT"
if ! grep -F -- './scripts/easy_node.sh profile-compare-docker-matrix [--dry-run [0|1]] [profile-compare-campaign args...]' "$HELP_OUT" >/dev/null 2>&1; then
  echo "easy_node help is missing profile-compare-docker-matrix contract line"
  cat "$HELP_OUT"
  exit 1
fi

echo "[profile-compare-docker-matrix] default invocation preserves wrapper defaults"
: >"$CAPTURE"
PROFILE_COMPARE_DOCKER_MATRIX_SCRIPT="$FAKE_MATRIX" \
PROFILE_COMPARE_DOCKER_MATRIX_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh profile-compare-docker-matrix

default_line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$default_line" ]]; then
  echo "missing default forwarding capture line"
  cat "$CAPTURE"
  exit 1
fi
if [[ "$default_line" != "argc=0" ]]; then
  echo "expected default invocation to forward zero arguments"
  echo "line: $default_line"
  exit 1
fi

echo "[profile-compare-docker-matrix] key override forwarding"
reports_dir="$TMP_DIR/reports dir"
summary_json="$reports_dir/summary.json"
report_md="$reports_dir/report.md"
mkdir -p "$reports_dir"
: >"$CAPTURE"

PROFILE_COMPARE_DOCKER_MATRIX_SCRIPT="$FAKE_MATRIX" \
PROFILE_COMPARE_DOCKER_MATRIX_CAPTURE_FILE="$CAPTURE" \
./scripts/easy_node.sh profile-compare-docker-matrix \
  --dry-run 1 \
  --profiles "1hop,2hop,3hop" \
  --campaign-runs 4 \
  --campaign-pause-sec 2 \
  --rounds 3 \
  --timeout-sec 27 \
  --reports-dir "$reports_dir" \
  --summary-json "$summary_json" \
  --report-md "$report_md" \
  --campaign-execution-mode local \
  --campaign-start-local-stack 1 \
  --campaign-discovery-wait-sec 21 \
  --campaign-bootstrap-directory "http://127.0.0.1:18081"

override_line="$(tail -n 1 "$CAPTURE" || true)"
if [[ -z "$override_line" ]]; then
  echo "missing override forwarding capture line"
  cat "$CAPTURE"
  exit 1
fi
assert_token "$override_line" $'\t--dry-run\t1' "missing forwarded --dry-run 1"
assert_token "$override_line" $'\t--profiles\t1hop,2hop,3hop' "missing forwarded --profiles override"
assert_token "$override_line" $'\t--campaign-runs\t4' "missing forwarded --campaign-runs override"
assert_token "$override_line" $'\t--campaign-pause-sec\t2' "missing forwarded --campaign-pause-sec override"
assert_token "$override_line" $'\t--rounds\t3' "missing forwarded --rounds override"
assert_token "$override_line" $'\t--timeout-sec\t27' "missing forwarded --timeout-sec override"
assert_token "$override_line" $'\t--reports-dir\t'"$reports_dir" "missing forwarded --reports-dir override"
assert_token "$override_line" $'\t--summary-json\t'"$summary_json" "missing forwarded --summary-json override"
assert_token "$override_line" $'\t--report-md\t'"$report_md" "missing forwarded --report-md override"
assert_token "$override_line" $'\t--campaign-execution-mode\tlocal' "missing forwarded --campaign-execution-mode override"
assert_token "$override_line" $'\t--campaign-start-local-stack\t1' "missing forwarded --campaign-start-local-stack override"
assert_token "$override_line" $'\t--campaign-discovery-wait-sec\t21' "missing forwarded --campaign-discovery-wait-sec override"
assert_token "$override_line" $'\t--campaign-bootstrap-directory\thttp://127.0.0.1:18081' "missing forwarded --campaign-bootstrap-directory override"

echo "[profile-compare-docker-matrix] explicit dry-run writes synthetic campaign/trend artifacts"
EXPLICIT_DRY_RUN_REPORTS_DIR="$TMP_DIR/profile compare dry run reports"
: >"$MATRIX_RUNTIME_CAPTURE"
set +e
PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_CAPTURE_FILE="$MATRIX_RUNTIME_CAPTURE" \
./scripts/profile_compare_docker_matrix.sh \
  --dry-run 1 \
  --reports-dir "$EXPLICIT_DRY_RUN_REPORTS_DIR" >"$MATRIX_RUNTIME_STDOUT" 2>"$MATRIX_RUNTIME_STDERR"
explicit_dry_run_rc=$?
set -e

if [[ "$explicit_dry_run_rc" -ne 0 ]]; then
  echo "expected explicit dry-run to exit with rc=0"
  echo "rc=$explicit_dry_run_rc"
  cat "$MATRIX_RUNTIME_STDOUT"
  cat "$MATRIX_RUNTIME_STDERR"
  exit 1
fi
if [[ -s "$MATRIX_RUNTIME_CAPTURE" ]]; then
  echo "campaign should not be invoked for explicit dry-run"
  cat "$MATRIX_RUNTIME_CAPTURE"
  exit 1
fi
if ! grep -F -- 'profile-compare-docker-matrix: dry-run' "$MATRIX_RUNTIME_STDOUT" >/dev/null 2>&1; then
  echo "missing explicit dry-run marker"
  cat "$MATRIX_RUNTIME_STDOUT"
  exit 1
fi

explicit_summary_json="$(extract_stdout_value "$MATRIX_RUNTIME_STDOUT" "summary_json")"
explicit_report_md="$(extract_stdout_value "$MATRIX_RUNTIME_STDOUT" "report_md")"
explicit_trend_summary_json="$(extract_stdout_value "$MATRIX_RUNTIME_STDOUT" "trend_summary_json")"
explicit_trend_report_md="$(extract_stdout_value "$MATRIX_RUNTIME_STDOUT" "trend_report_md")"

if [[ -z "$explicit_summary_json" || -z "$explicit_report_md" || -z "$explicit_trend_summary_json" || -z "$explicit_trend_report_md" ]]; then
  echo "expected dry-run stdout to include synthetic artifact paths"
  cat "$MATRIX_RUNTIME_STDOUT"
  exit 1
fi

assert_file_exists "$explicit_summary_json" "missing dry-run campaign summary json"
assert_file_exists "$explicit_report_md" "missing dry-run campaign report markdown"
assert_file_exists "$explicit_trend_summary_json" "missing dry-run trend summary json"
assert_file_exists "$explicit_trend_report_md" "missing dry-run trend report markdown"

if ! jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object") and (.trend | type == "object") and .status == "warn" and (.summary.runs_total == 0) and (.decision.source == "safe_default_fallback") and (.trend.summary_json == "'"$explicit_trend_summary_json"'")' "$explicit_summary_json" >/dev/null 2>&1; then
  echo "dry-run campaign summary JSON schema/contract mismatch"
  cat "$explicit_summary_json"
  exit 1
fi
if ! jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object") and .status == "warn" and (.summary.reports_total == 0) and (.decision.source == "safe_default_fallback")' "$explicit_trend_summary_json" >/dev/null 2>&1; then
  echo "dry-run trend summary JSON schema/contract mismatch"
  cat "$explicit_trend_summary_json"
  exit 1
fi
if ! grep -F -- 'Dry Run' "$explicit_report_md" >/dev/null 2>&1; then
  echo "dry-run campaign report should be marked as Dry Run"
  cat "$explicit_report_md"
  exit 1
fi
if ! grep -F -- 'Dry Run' "$explicit_trend_report_md" >/dev/null 2>&1; then
  echo "dry-run trend report should be marked as Dry Run"
  cat "$explicit_trend_report_md"
  exit 1
fi

set +e
./scripts/profile_compare_campaign_check.sh \
  --campaign-summary-json "$explicit_summary_json" \
  --trend-summary-json "$explicit_trend_summary_json" \
  --require-status-pass 0 \
  --require-trend-status-pass 0 \
  --fail-on-no-go 0 \
  --summary-json "$TMP_DIR/dry_run_campaign_check_summary.json" >/tmp/integration_profile_compare_docker_matrix_dry_run_check.log 2>&1
dry_run_check_rc=$?
set -e

if [[ "$dry_run_check_rc" -ne 0 ]]; then
  echo "dry-run artifacts should be consumable by campaign check without schema/missing-file failure"
  cat /tmp/integration_profile_compare_docker_matrix_dry_run_check.log
  exit 1
fi
if ! jq -e '.version == 1 and (.observed | type == "object") and (.errors | type == "array") and ([.errors[]? | select(test("campaign summary JSON not found|trend summary JSON is missing or invalid"))] | length == 0)' "$TMP_DIR/dry_run_campaign_check_summary.json" >/dev/null 2>&1; then
  echo "campaign check reported missing/invalid summary artifacts for dry-run output"
  cat "$TMP_DIR/dry_run_campaign_check_summary.json"
  exit 1
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "[profile-compare-docker-matrix] non-root default auto-falls back to dry-run without fake runtime pass"
  : >"$MATRIX_RUNTIME_CAPTURE"
  set +e
  PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
  PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_CAPTURE_FILE="$MATRIX_RUNTIME_CAPTURE" \
  ./scripts/profile_compare_docker_matrix.sh >"$MATRIX_RUNTIME_STDOUT" 2>"$MATRIX_RUNTIME_STDERR"
  auto_dry_run_rc=$?
  set -e

  if [[ "$auto_dry_run_rc" -ne 0 ]]; then
    echo "expected non-root default to succeed via dry-run fallback"
    echo "rc=$auto_dry_run_rc"
    cat "$MATRIX_RUNTIME_STDOUT"
    cat "$MATRIX_RUNTIME_STDERR"
    exit 1
  fi
  if [[ -s "$MATRIX_RUNTIME_CAPTURE" ]]; then
    echo "campaign should not be invoked in non-root fallback dry-run mode"
    cat "$MATRIX_RUNTIME_CAPTURE"
    exit 1
  fi
  if ! grep -F -- 'non-root default detected without explicit endpoints; switching to dry-run' "$MATRIX_RUNTIME_STDOUT" >/dev/null 2>&1; then
    echo "missing non-root dry-run fallback note"
    cat "$MATRIX_RUNTIME_STDOUT"
    exit 1
  fi
  if ! grep -F -- 'profile-compare-docker-matrix: dry-run' "$MATRIX_RUNTIME_STDOUT" >/dev/null 2>&1; then
    echo "missing dry-run mode marker for non-root fallback"
    cat "$MATRIX_RUNTIME_STDOUT"
    exit 1
  fi

  fallback_summary_json="$(extract_stdout_value "$MATRIX_RUNTIME_STDOUT" "summary_json")"
  fallback_trend_summary_json="$(extract_stdout_value "$MATRIX_RUNTIME_STDOUT" "trend_summary_json")"
  if [[ -z "$fallback_summary_json" || -z "$fallback_trend_summary_json" ]]; then
    echo "non-root fallback dry-run should emit summary paths"
    cat "$MATRIX_RUNTIME_STDOUT"
    exit 1
  fi
  assert_file_exists "$fallback_summary_json" "missing non-root fallback campaign summary json"
  assert_file_exists "$fallback_trend_summary_json" "missing non-root fallback trend summary json"
  if ! jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object") and (.trend | type == "object")' "$fallback_summary_json" >/dev/null 2>&1; then
    echo "non-root fallback campaign summary schema mismatch"
    cat "$fallback_summary_json"
    exit 1
  fi
  if ! jq -e '.version == 1 and (.summary | type == "object") and (.decision | type == "object")' "$fallback_trend_summary_json" >/dev/null 2>&1; then
    echo "non-root fallback trend summary schema mismatch"
    cat "$fallback_trend_summary_json"
    exit 1
  fi

  echo "[profile-compare-docker-matrix] non-root explicit --start-local-stack 1 fails with clear guidance"
  : >"$MATRIX_RUNTIME_CAPTURE"
  set +e
  PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
  PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_CAPTURE_FILE="$MATRIX_RUNTIME_CAPTURE" \
  ./scripts/profile_compare_docker_matrix.sh \
    --start-local-stack 1 \
    --bootstrap-directory "http://127.0.0.1:18081" >"$MATRIX_RUNTIME_STDOUT" 2>"$MATRIX_RUNTIME_STDERR"
  explicit_root_required_rc=$?
  set -e

  if [[ "$explicit_root_required_rc" -ne 2 ]]; then
    echo "expected explicit non-root --start-local-stack 1 to fail with rc=2"
    echo "rc=$explicit_root_required_rc"
    cat "$MATRIX_RUNTIME_STDOUT"
    cat "$MATRIX_RUNTIME_STDERR"
    exit 1
  fi
  if [[ -s "$MATRIX_RUNTIME_CAPTURE" ]]; then
    echo "campaign should not be invoked when explicit non-root --start-local-stack 1 is rejected"
    cat "$MATRIX_RUNTIME_CAPTURE"
    exit 1
  fi
  if ! grep -F -- 'non-root cannot use --start-local-stack=1 in docker mode.' "$MATRIX_RUNTIME_STDOUT" >/dev/null 2>&1; then
    echo "missing explicit non-root stack guidance"
    cat "$MATRIX_RUNTIME_STDOUT"
    exit 1
  fi

  echo "[profile-compare-docker-matrix] non-root with explicit endpoints forces --start-local-stack 0 and executes campaign"
  : >"$MATRIX_RUNTIME_CAPTURE"
  PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_SCRIPT="$FAKE_CAMPAIGN" \
  PROFILE_COMPARE_DOCKER_MATRIX_CAMPAIGN_CAPTURE_FILE="$MATRIX_RUNTIME_CAPTURE" \
  ./scripts/profile_compare_docker_matrix.sh \
    --bootstrap-directory "http://127.0.0.1:18081" \
    --campaign-runs 1 \
    --rounds 1 \
    --timeout-sec 5 \
    --discovery-wait-sec 1 \
    --min-sources 1 >"$MATRIX_RUNTIME_STDOUT" 2>"$MATRIX_RUNTIME_STDERR"

  runtime_line="$(tail -n 1 "$MATRIX_RUNTIME_CAPTURE" || true)"
  if [[ -z "$runtime_line" ]]; then
    echo "expected campaign invocation capture for explicit endpoint flow"
    cat "$MATRIX_RUNTIME_CAPTURE"
    cat "$MATRIX_RUNTIME_STDOUT"
    exit 1
  fi
  assert_token "$runtime_line" $'\t--bootstrap-directory\thttp://127.0.0.1:18081' "missing forwarded bootstrap endpoint in runtime flow"
  assert_token "$runtime_line" $'\t--start-local-stack\t0' "missing forced --start-local-stack 0 in non-root endpoint flow"
else
  echo "[profile-compare-docker-matrix] non-root fallback checks skipped (running as root)"
fi

echo "profile compare docker matrix integration check ok"
