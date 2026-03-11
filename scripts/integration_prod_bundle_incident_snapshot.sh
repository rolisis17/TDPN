#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
GATE_FAIL_SCRIPT="$TMP_DIR/fake_gate_fail.sh"
SNAPSHOT_SCRIPT="$TMP_DIR/fake_incident_snapshot.sh"
SNAPSHOT_CAPTURE="$TMP_DIR/incident_snapshot_args.log"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$GATE_FAIL_SCRIPT" <<'EOF_GATE_FAIL'
#!/usr/bin/env bash
set -euo pipefail
exit "${FAKE_GATE_FAIL_RC:-31}"
EOF_GATE_FAIL
chmod +x "$GATE_FAIL_SCRIPT"

cat >"$SNAPSHOT_SCRIPT" <<'EOF_SNAPSHOT'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SNAPSHOT_CAPTURE_FILE:?}"
bundle_dir=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done
if [[ -n "$bundle_dir" ]]; then
  mkdir -p "$bundle_dir"
  printf 'ok\n' >"$bundle_dir/fake_snapshot.txt"
  tar -czf "${bundle_dir}.tar.gz" -C "$(dirname "$bundle_dir")" "$(basename "$bundle_dir")"
fi
exit 0
EOF_SNAPSHOT
chmod +x "$SNAPSHOT_SCRIPT"

echo "[incident-bundle] fail path with snapshot enabled"
BUNDLE_ENABLE="$TMP_DIR/prod_bundle_incident_enable"
set +e
SNAPSHOT_CAPTURE_FILE="$SNAPSHOT_CAPTURE" \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="./scripts/prod_gate_bundle.sh" \
THREE_MACHINE_PROD_GATE_SCRIPT="$GATE_FAIL_SCRIPT" \
INCIDENT_SNAPSHOT_SCRIPT="$SNAPSHOT_SCRIPT" \
FAKE_GATE_FAIL_RC=31 \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$BUNDLE_ENABLE" \
  --preflight-check 0 \
  --bundle-verify-check 0 \
  --skip-wg 1 \
  --incident-snapshot-on-fail 1 \
  --incident-snapshot-include-docker-logs 0 \
  --incident-snapshot-docker-log-lines 33 \
  --incident-snapshot-timeout-sec 5 \
  --incident-snapshot-compose-project deploy \
  --directory-a http://dir-a:8081 \
  --directory-b http://dir-b:8081 \
  --issuer-url http://issuer-main:8082 \
  --entry-url http://entry-main:8083 \
  --exit-url http://exit-main:8084 >/tmp/integration_prod_bundle_incident_snapshot_enable.log 2>&1
enable_rc=$?
set -e
if [[ "$enable_rc" -ne 31 ]]; then
  echo "incident bundle integration failed: expected rc=31 for failing gate (got $enable_rc)"
  cat /tmp/integration_prod_bundle_incident_snapshot_enable.log
  exit 1
fi
if [[ ! -s "$SNAPSHOT_CAPTURE" ]]; then
  echo "incident bundle integration failed: incident snapshot script was not invoked"
  cat /tmp/integration_prod_bundle_incident_snapshot_enable.log
  exit 1
fi
if ! rg -q -- '--directory-url http://dir-a:8081' "$SNAPSHOT_CAPTURE"; then
  echo "incident bundle integration failed: directory URL not forwarded to snapshot command"
  cat "$SNAPSHOT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--include-docker-logs 0' "$SNAPSHOT_CAPTURE"; then
  echo "incident bundle integration failed: include-docker-logs not forwarded"
  cat "$SNAPSHOT_CAPTURE"
  exit 1
fi
if ! rg -q -- '--docker-log-lines 33' "$SNAPSHOT_CAPTURE"; then
  echo "incident bundle integration failed: docker-log-lines not forwarded"
  cat "$SNAPSHOT_CAPTURE"
  exit 1
fi
if [[ ! -f "$BUNDLE_ENABLE/incident_snapshot/fake_snapshot.txt" ]]; then
  echo "incident bundle integration failed: snapshot bundle output missing"
  find "$BUNDLE_ENABLE" -maxdepth 3 -type f -print || true
  exit 1
fi
if ! rg -q '"enabled_on_fail"[[:space:]]*:[[:space:]]*true' "$BUNDLE_ENABLE/prod_bundle_run_report.json"; then
  echo "incident bundle integration failed: run report missing enabled_on_fail=true"
  cat "$BUNDLE_ENABLE/prod_bundle_run_report.json"
  exit 1
fi
if ! rg -q '"status"[[:space:]]*:[[:space:]]*"ok"' "$BUNDLE_ENABLE/prod_bundle_run_report.json"; then
  echo "incident bundle integration failed: run report missing incident snapshot status=ok"
  cat "$BUNDLE_ENABLE/prod_bundle_run_report.json"
  exit 1
fi

echo "[incident-bundle] fail path with snapshot disabled"
: >"$SNAPSHOT_CAPTURE"
BUNDLE_DISABLE="$TMP_DIR/prod_bundle_incident_disable"
set +e
SNAPSHOT_CAPTURE_FILE="$SNAPSHOT_CAPTURE" \
THREE_MACHINE_PROD_BUNDLE_SCRIPT="./scripts/prod_gate_bundle.sh" \
THREE_MACHINE_PROD_GATE_SCRIPT="$GATE_FAIL_SCRIPT" \
INCIDENT_SNAPSHOT_SCRIPT="$SNAPSHOT_SCRIPT" \
FAKE_GATE_FAIL_RC=31 \
./scripts/easy_node.sh three-machine-prod-bundle \
  --bundle-dir "$BUNDLE_DISABLE" \
  --preflight-check 0 \
  --bundle-verify-check 0 \
  --skip-wg 1 \
  --incident-snapshot-on-fail 0 >/tmp/integration_prod_bundle_incident_snapshot_disable.log 2>&1
disable_rc=$?
set -e
if [[ "$disable_rc" -ne 31 ]]; then
  echo "incident bundle integration failed: expected rc=31 for failing gate with snapshot disabled (got $disable_rc)"
  cat /tmp/integration_prod_bundle_incident_snapshot_disable.log
  exit 1
fi
if [[ -s "$SNAPSHOT_CAPTURE" ]]; then
  echo "incident bundle integration failed: snapshot script should not run when disabled"
  cat "$SNAPSHOT_CAPTURE"
  exit 1
fi
if ! rg -q '"enabled_on_fail"[[:space:]]*:[[:space:]]*false' "$BUNDLE_DISABLE/prod_bundle_run_report.json"; then
  echo "incident bundle integration failed: run report missing enabled_on_fail=false"
  cat "$BUNDLE_DISABLE/prod_bundle_run_report.json"
  exit 1
fi
if ! rg -q '"status"[[:space:]]*:[[:space:]]*"skipped"' "$BUNDLE_DISABLE/prod_bundle_run_report.json"; then
  echo "incident bundle integration failed: run report missing incident snapshot status=skipped"
  cat "$BUNDLE_DISABLE/prod_bundle_run_report.json"
  exit 1
fi

echo "prod bundle incident snapshot integration check ok"
