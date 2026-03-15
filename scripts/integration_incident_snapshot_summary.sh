#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq rg tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

BUNDLE_DIR="$TMP_DIR/incident_bundle"
mkdir -p "$BUNDLE_DIR/endpoints" "$BUNDLE_DIR/docker" "$BUNDLE_DIR/system"
mkdir -p "$BUNDLE_DIR/attachments"

cat >"$BUNDLE_DIR/metadata.txt" <<'EOF_META'
generated_at_utc=2026-03-14T00:00:00Z
host=test-host
user=tester
uid=1000
mode=authority
env_file=/tmp/.env.easy.server
directory_url=http://dir-a:8081
issuer_url=http://issuer-a:8082
entry_url=http://entry-a:8083
exit_url=http://exit-a:8084
compose_project=deploy
EOF_META

cat >"$BUNDLE_DIR/endpoints/directory_relays.json" <<'EOF_RELAYS'
{"relays":[{"relay_id":"entry-op-a","operator_id":"op-a"},{"relay_id":"exit-op-b","operator_id":"op-b"}]}
EOF_RELAYS
cat >"$BUNDLE_DIR/endpoints/directory_peers.json" <<'EOF_PEERS'
{"peers":[{"url":"http://peer-a:8081"},{"url":"http://peer-b:8081"}]}
EOF_PEERS
cat >"$BUNDLE_DIR/endpoints/directory_health.json" <<'EOF_DIR_HEALTH'
{"ok":true}
EOF_DIR_HEALTH
cat >"$BUNDLE_DIR/endpoints/issuer_pubkeys.json" <<'EOF_PUBKEYS'
{"issuer":"issuer-a","pub_keys":["k1","k2"]}
EOF_PUBKEYS
cat >"$BUNDLE_DIR/endpoints/entry_health.json" <<'EOF_ENTRY_HEALTH'
{"ok":true}
EOF_ENTRY_HEALTH
cat >"$BUNDLE_DIR/endpoints/exit_health.json" <<'EOF_EXIT_HEALTH'
{"ok":true}
EOF_EXIT_HEALTH
cat >"$BUNDLE_DIR/endpoints/exit_metrics.json" <<'EOF_METRICS'
{"accepted_packets":9,"wg_proxy_created":3}
EOF_METRICS

printf 'CONTAINER ID   IMAGE   STATUS\nabc123         test    Up 1 minute\n' >"$BUNDLE_DIR/docker/docker_ps.txt"
printf 'NAME                IMAGE               STATUS\ndeploy-directory-1  deploy-directory    Up\n' >"$BUNDLE_DIR/docker/compose_ps.txt"
printf '[directory] fake log\n' >"$BUNDLE_DIR/docker/directory_tail.log"
printf '[issuer] fake log\n' >"$BUNDLE_DIR/docker/issuer_tail.log"
printf '[entry-exit] fake log\n' >"$BUNDLE_DIR/docker/entry-exit_tail.log"
printf 'sha256\n' >"$BUNDLE_DIR/manifest.sha256"
cat >"$BUNDLE_DIR/attachments/manifest.tsv" <<'EOF_ATTACH'
attachments/01_runtime_doctor_before.log	file	/tmp/runtime_doctor_before.log
attachments/02_runtime_doctor_before.json	file	/tmp/runtime_doctor_before.json
EOF_ATTACH
printf 'runtime doctor\n' >"$BUNDLE_DIR/attachments/01_runtime_doctor_before.log"
printf '{"status":"OK"}\n' >"$BUNDLE_DIR/attachments/02_runtime_doctor_before.json"
tar -czf "${BUNDLE_DIR}.tar.gz" -C "$TMP_DIR" "$(basename "$BUNDLE_DIR")"
printf 'sha256 %s\n' "${BUNDLE_DIR}.tar.gz" >"${BUNDLE_DIR}.tar.gz.sha256"

SUMMARY_JSON="$TMP_DIR/incident_summary.json"
REPORT_MD="$TMP_DIR/incident_report.md"

./scripts/incident_snapshot_summary.sh \
  --bundle-dir "$BUNDLE_DIR" \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_incident_snapshot_summary_ok.log 2>&1

if ! jq -e '.status == "ok" and .critical_count == 0 and .warning_count == 0 and .endpoints.directory_relays.relay_count == 2 and .endpoints.exit_metrics.accepted_packets == 9 and .attachments.count == 2 and .attachments.skipped_count == 0' "$SUMMARY_JSON" >/dev/null; then
  echo "incident snapshot summary integration failed: healthy bundle summary incorrect"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! rg -q 'Status: `ok`' "$REPORT_MD"; then
  echo "incident snapshot summary integration failed: healthy report missing ok status"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Attached artifacts: `2`' "$REPORT_MD"; then
  echo "incident snapshot summary integration failed: healthy report missing attachment summary"
  cat "$REPORT_MD"
  exit 1
fi

printf 'probe_failed: http://entry-a:8083/v1/health\nconnection refused\n' >"$BUNDLE_DIR/endpoints/entry_health.json"
printf '/tmp/runtime_fix.json\tmissing\n' >"$BUNDLE_DIR/attachments/skipped.tsv"
./scripts/incident_snapshot_summary.sh \
  --bundle-dir "$BUNDLE_DIR" \
  --summary-json "$SUMMARY_JSON" \
  --report-md "$REPORT_MD" \
  --print-report 0 \
  --print-summary-json 0 >/tmp/integration_incident_snapshot_summary_fail.log 2>&1

if ! jq -e '.status == "fail" and .critical_count >= 1 and .attachments.skipped_count == 1 and (.findings | any(. == "Entry health probe failed or did not report ok=true.")) and (.findings | any(. == "One or more requested attached artifacts were missing or could not be copied into the incident bundle."))' "$SUMMARY_JSON" >/dev/null; then
  echo "incident snapshot summary integration failed: failing bundle summary incorrect"
  cat "$SUMMARY_JSON"
  exit 1
fi
if ! rg -q 'Entry health probe failed or did not report ok=true' "$REPORT_MD"; then
  echo "incident snapshot summary integration failed: failing report missing entry finding"
  cat "$REPORT_MD"
  exit 1
fi
if ! rg -q 'Skipped attachments: `1`' "$REPORT_MD"; then
  echo "incident snapshot summary integration failed: failing report missing skipped attachment summary"
  cat "$REPORT_MD"
  exit 1
fi

FAKE_SUMMARY="$TMP_DIR/fake_summary.sh"
CAPTURE="$TMP_DIR/summary_capture.log"
cat >"$FAKE_SUMMARY" <<'EOF_FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"${SUMMARY_CAPTURE_FILE:?}"
EOF_FAKE
chmod +x "$FAKE_SUMMARY"

SUMMARY_CAPTURE_FILE="$CAPTURE" \
INCIDENT_SNAPSHOT_SUMMARY_SCRIPT="$FAKE_SUMMARY" \
./scripts/easy_node.sh incident-snapshot-summary \
  --bundle-dir /tmp/incident_bundle \
  --summary-json /tmp/incident_summary.json \
  --report-md /tmp/incident_report.md \
  --print-report 0 \
  --print-summary-json 1 >/tmp/integration_incident_snapshot_summary_forwarding.log 2>&1

if ! rg -q -- '--bundle-dir /tmp/incident_bundle' "$CAPTURE"; then
  echo "incident snapshot summary forwarding failed: missing --bundle-dir"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--summary-json /tmp/incident_summary.json' "$CAPTURE"; then
  echo "incident snapshot summary forwarding failed: missing --summary-json"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--report-md /tmp/incident_report.md' "$CAPTURE"; then
  echo "incident snapshot summary forwarding failed: missing --report-md"
  cat "$CAPTURE"
  exit 1
fi
if ! rg -q -- '--print-summary-json 1' "$CAPTURE"; then
  echo "incident snapshot summary forwarding failed: missing --print-summary-json"
  cat "$CAPTURE"
  exit 1
fi

echo "incident snapshot summary integration check ok"
