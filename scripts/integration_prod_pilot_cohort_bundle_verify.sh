#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp jq rg tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "[prod-pilot-cohort-bundle-verify] prepare baseline cohort artifacts"
REPORTS_DIR="$TMP_DIR/cohort_reports"
mkdir -p "$REPORTS_DIR/round_1" "$REPORTS_DIR/round_2"
printf 'round-1 log\n' >"$REPORTS_DIR/round_1/prod_pilot_round.log"
printf 'round-2 log\n' >"$REPORTS_DIR/round_2/prod_pilot_round.log"

RUN_REPORT_1="$REPORTS_DIR/round_1/prod_bundle_run_report.json"
RUN_REPORT_2="$REPORTS_DIR/round_2/prod_bundle_run_report.json"
cat >"$RUN_REPORT_1" <<'EOF_RUN_REPORT_1'
{"status":"ok","round":1}
EOF_RUN_REPORT_1
cat >"$RUN_REPORT_2" <<'EOF_RUN_REPORT_2'
{"status":"ok","round":2}
EOF_RUN_REPORT_2

printf '%s\n%s\n' "$RUN_REPORT_1" "$RUN_REPORT_2" >"$REPORTS_DIR/run_reports.list"
cat >"$REPORTS_DIR/prod_pilot_cohort_trend.json" <<'EOF_TREND'
{"decision":"go","go_rate_pct":100}
EOF_TREND
cat >"$REPORTS_DIR/prod_pilot_cohort_alert.json" <<'EOF_ALERT'
{"severity":"OK"}
EOF_ALERT

SUMMARY_JSON="$REPORTS_DIR/prod_pilot_cohort_summary.json"
BUNDLE_TAR="${REPORTS_DIR}.tar.gz"
BUNDLE_SHA="${BUNDLE_TAR}.sha256"
MANIFEST_JSON="$REPORTS_DIR/prod_pilot_cohort_bundle_manifest.json"

cat >"$MANIFEST_JSON" <<EOF_MANIFEST
{
  "generated_at": "2026-03-11T00:00:00Z",
  "reports_dir": "$REPORTS_DIR",
  "report_list_file": "$REPORTS_DIR/run_reports.list",
  "trend_summary_json": "$REPORTS_DIR/prod_pilot_cohort_trend.json",
  "alert_summary_json": "$REPORTS_DIR/prod_pilot_cohort_alert.json",
  "summary_json": "$SUMMARY_JSON",
  "run_reports": ["$RUN_REPORT_1","$RUN_REPORT_2"],
  "round_results": [
    {"round":1,"status":"ok","rc":0,"bundle_dir":"$REPORTS_DIR/round_1","run_report_json":"$RUN_REPORT_1","log_file":"$REPORTS_DIR/round_1/prod_pilot_round.log"},
    {"round":2,"status":"ok","rc":0,"bundle_dir":"$REPORTS_DIR/round_2","run_report_json":"$RUN_REPORT_2","log_file":"$REPORTS_DIR/round_2/prod_pilot_round.log"}
  ]
}
EOF_MANIFEST

tar -czf "$BUNDLE_TAR" -C "$(dirname "$REPORTS_DIR")" "$(basename "$REPORTS_DIR")"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "$BUNDLE_TAR" | awk '{print $1"  "FILENAME}' FILENAME="$(basename "$BUNDLE_TAR")" >"$BUNDLE_SHA"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "$BUNDLE_TAR" | awk '{print $1"  "FILENAME}' FILENAME="$(basename "$BUNDLE_TAR")" >"$BUNDLE_SHA"
else
  openssl dgst -sha256 "$BUNDLE_TAR" | awk '{print $NF"  "FILENAME}' FILENAME="$(basename "$BUNDLE_TAR")" >"$BUNDLE_SHA"
fi

cat >"$SUMMARY_JSON" <<EOF_SUMMARY
{
  "status": "ok",
  "artifacts": {
    "reports_dir": "$REPORTS_DIR",
    "bundle_tar": "$BUNDLE_TAR",
    "bundle_sha256_file": "$BUNDLE_SHA",
    "bundle_manifest_json": "$MANIFEST_JSON"
  },
  "bundle": {
    "created": true
  }
}
EOF_SUMMARY

echo "[prod-pilot-cohort-bundle-verify] verify by summary-json"
./scripts/prod_pilot_cohort_bundle_verify.sh \
  --summary-json "$SUMMARY_JSON" >/tmp/integration_prod_pilot_cohort_bundle_verify_summary.log 2>&1

echo "[prod-pilot-cohort-bundle-verify] verify by bundle-tar + extraction path"
./scripts/prod_pilot_cohort_bundle_verify.sh \
  --bundle-tar "$BUNDLE_TAR" >/tmp/integration_prod_pilot_cohort_bundle_verify_tar.log 2>&1

echo "[prod-pilot-cohort-bundle-verify] detect tar checksum tamper"
TAMPER_TAR="$TMP_DIR/cohort_tamper.tar.gz"
cp "$BUNDLE_TAR" "$TAMPER_TAR"
cp "$BUNDLE_SHA" "${TAMPER_TAR}.sha256"
printf 'X' >>"$TAMPER_TAR"
set +e
./scripts/prod_pilot_cohort_bundle_verify.sh \
  --bundle-tar "$TAMPER_TAR" >/tmp/integration_prod_pilot_cohort_bundle_verify_tamper_tar.log 2>&1
tamper_tar_rc=$?
set -e
if [[ "$tamper_tar_rc" -eq 0 ]]; then
  echo "expected non-zero rc for tampered cohort tar checksum"
  cat /tmp/integration_prod_pilot_cohort_bundle_verify_tamper_tar.log
  exit 1
fi
if ! rg -q 'checksum mismatch' /tmp/integration_prod_pilot_cohort_bundle_verify_tamper_tar.log; then
  echo "expected checksum mismatch signal not found for tampered cohort tar"
  cat /tmp/integration_prod_pilot_cohort_bundle_verify_tamper_tar.log
  exit 1
fi

echo "[prod-pilot-cohort-bundle-verify] detect manifest missing field"
BAD_MANIFEST="$TMP_DIR/bad_manifest.json"
cat >"$BAD_MANIFEST" <<EOF_BAD_MANIFEST
{
  "generated_at": "2026-03-11T00:00:00Z",
  "reports_dir": "$REPORTS_DIR",
  "report_list_file": "$REPORTS_DIR/run_reports.list",
  "trend_summary_json": "$REPORTS_DIR/prod_pilot_cohort_trend.json",
  "alert_summary_json": "$REPORTS_DIR/prod_pilot_cohort_alert.json",
  "summary_json": "$SUMMARY_JSON",
  "run_reports": ["$RUN_REPORT_1"]
}
EOF_BAD_MANIFEST
set +e
./scripts/prod_pilot_cohort_bundle_verify.sh \
  --reports-dir "$REPORTS_DIR" \
  --bundle-manifest-json "$BAD_MANIFEST" >/tmp/integration_prod_pilot_cohort_bundle_verify_bad_manifest.log 2>&1
bad_manifest_rc=$?
set -e
if [[ "$bad_manifest_rc" -eq 0 ]]; then
  echo "expected non-zero rc for bad cohort manifest"
  cat /tmp/integration_prod_pilot_cohort_bundle_verify_bad_manifest.log
  exit 1
fi
if ! rg -q 'manifest missing required field' /tmp/integration_prod_pilot_cohort_bundle_verify_bad_manifest.log; then
  echo "expected manifest required-field signal not found"
  cat /tmp/integration_prod_pilot_cohort_bundle_verify_bad_manifest.log
  exit 1
fi

cat >"$TMP_BIN/docker" <<'EOF_DOCKER'
#!/usr/bin/env bash
set -euo pipefail
if [[ "${1:-}" == "compose" && "${2:-}" == "version" ]]; then
  printf 'Docker Compose version vtest\n'
  exit 0
fi
if [[ "${1:-}" == "compose" ]]; then
  exit 0
fi
if [[ "${1:-}" == "--version" ]]; then
  printf 'Docker version test\n'
  exit 0
fi
if [[ "${1:-}" == "info" ]]; then
  exit 0
fi
exit 0
EOF_DOCKER
chmod +x "$TMP_BIN/docker"

echo "[prod-pilot-cohort-bundle-verify] easy_node forwarding"
FAKE_VERIFY="$TMP_DIR/fake_verify.sh"
VERIFY_CAPTURE="$TMP_DIR/verify_capture.log"
cat >"$FAKE_VERIFY" <<'EOF_FAKE_VERIFY'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${VERIFY_CAPTURE_FILE:?}"
exit 0
EOF_FAKE_VERIFY
chmod +x "$FAKE_VERIFY"

PATH="$TMP_BIN:$PATH" \
VERIFY_CAPTURE_FILE="$VERIFY_CAPTURE" \
PROD_PILOT_COHORT_BUNDLE_VERIFY_SCRIPT="$FAKE_VERIFY" \
./scripts/easy_node.sh prod-pilot-cohort-bundle-verify \
  --summary-json /tmp/cohort/summary.json \
  --bundle-tar /tmp/cohort.tar.gz \
  --show-details 1 >/tmp/integration_prod_pilot_cohort_bundle_verify_easy_node.log 2>&1

if ! rg -q -- '--summary-json /tmp/cohort/summary.json' "$VERIFY_CAPTURE"; then
  echo "easy_node cohort bundle verify forwarding failed: missing --summary-json"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--bundle-tar /tmp/cohort.tar.gz' "$VERIFY_CAPTURE"; then
  echo "easy_node cohort bundle verify forwarding failed: missing --bundle-tar"
  cat "$VERIFY_CAPTURE"
  exit 1
fi
if ! rg -q -- '--show-details 1' "$VERIFY_CAPTURE"; then
  echo "easy_node cohort bundle verify forwarding failed: missing --show-details"
  cat "$VERIFY_CAPTURE"
  exit 1
fi

echo "prod pilot cohort bundle verify integration check ok"
