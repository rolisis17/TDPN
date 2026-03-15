#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash jq mktemp rg; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

bundle_dir="$TMP_DIR/incident_bundle"
mkdir -p "$bundle_dir/endpoints" "$bundle_dir/docker" "$bundle_dir/system" "$bundle_dir/attachments"

cat >"$bundle_dir/metadata.txt" <<'EOF_META'
generated_at_utc=2026-03-15T00:00:00Z
host=test-host
mode=client
env_file=deploy/.env.easy.client
directory_url=http://127.0.0.1:18081
issuer_url=http://127.0.0.1:18082
entry_url=http://127.0.0.1:18083
exit_url=http://127.0.0.1:18084
compose_project=testproj
EOF_META

cat >"$bundle_dir/endpoints/directory_relays.json" <<'EOF_RELAYS'
{"relays":[{"id":"entry-local-1"}]}
EOF_RELAYS
cat >"$bundle_dir/endpoints/directory_peers.json" <<'EOF_PEERS'
{"peers":[]}
EOF_PEERS
cat >"$bundle_dir/endpoints/directory_health.json" <<'EOF_DIR_HEALTH'
{"ok":true}
EOF_DIR_HEALTH
cat >"$bundle_dir/endpoints/issuer_pubkeys.json" <<'EOF_ISSUER'
{"issuer":"iss-1","pub_keys":["pub-1"]}
EOF_ISSUER
cat >"$bundle_dir/endpoints/entry_health.json" <<'EOF_ENTRY'
{"ok":true}
EOF_ENTRY
cat >"$bundle_dir/endpoints/exit_health.json" <<'EOF_EXIT'
{"ok":true}
EOF_EXIT
cat >"$bundle_dir/endpoints/exit_metrics.json" <<'EOF_METRICS'
{"accepted_packets":1,"wg_proxy_created":1}
EOF_METRICS
cat >"$bundle_dir/docker/docker_ps.txt" <<'EOF_DOCKER_PS'
CONTAINER ID   STATUS
abc123         Up 2 minutes
EOF_DOCKER_PS
cat >"$bundle_dir/docker/compose_ps.txt" <<'EOF_COMPOSE_PS'
NAME            STATUS
svc             Up
EOF_COMPOSE_PS
printf '%s\n' 'directory log tail' >"$bundle_dir/docker/directory_tail.log"
printf '%s\n' 'issuer log tail' >"$bundle_dir/docker/issuer_tail.log"
printf '%s\n' 'entry-exit log tail' >"$bundle_dir/docker/entry-exit_tail.log"
: >"$bundle_dir/attachments/manifest.tsv"
: >"$bundle_dir/attachments/skipped.tsv"

artifact_one="$TMP_DIR/runtime_doctor_after.json"
artifact_two="$TMP_DIR/manual_validation_readiness_summary.json"
printf '%s\n' '{"status":"OK"}' >"$artifact_one"
printf '%s\n' '{"readiness_status":"NOT_READY"}' >"$artifact_two"
missing_artifact="$TMP_DIR/missing-artifact.txt"

./scripts/incident_snapshot_attach_artifacts.sh \
  --bundle-dir "$bundle_dir" \
  --attach-artifact "$artifact_one" \
  --attach-artifact "$missing_artifact" \
  --print-summary-json 1 >/tmp/integration_incident_snapshot_attach_first.log 2>&1

if ! rg -q '^incident snapshot attachments updated$' /tmp/integration_incident_snapshot_attach_first.log; then
  echo "expected attach helper success output missing"
  cat /tmp/integration_incident_snapshot_attach_first.log
  exit 1
fi

first_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_incident_snapshot_attach_first.log | tail -n 1)"
if [[ -z "$first_summary_json" || ! -f "$first_summary_json" ]]; then
  echo "expected regenerated summary json missing"
  cat /tmp/integration_incident_snapshot_attach_first.log
  exit 1
fi
if ! jq -e '.attachments.count == 1 and .attachments.skipped_count == 1 and .bundle.manifest_exists == true and .bundle.tar_exists == true and .bundle.tar_sha256_exists == true' "$first_summary_json" >/dev/null 2>&1; then
  echo "summary json missing expected attachment/integrity values after first refresh"
  cat "$first_summary_json"
  exit 1
fi
manifest_file="$(sed -n 's/^attachment_manifest: //p' /tmp/integration_incident_snapshot_attach_first.log | tail -n 1)"
skipped_file="$(sed -n 's/^attachment_skipped: //p' /tmp/integration_incident_snapshot_attach_first.log | tail -n 1)"
if [[ -z "$manifest_file" || ! -f "$manifest_file" ]]; then
  echo "expected attachment manifest missing"
  cat /tmp/integration_incident_snapshot_attach_first.log
  exit 1
fi
if [[ -z "$skipped_file" || ! -f "$skipped_file" ]]; then
  echo "expected skipped attachment file missing"
  cat /tmp/integration_incident_snapshot_attach_first.log
  exit 1
fi
if ! rg -q "$artifact_one" "$manifest_file"; then
  echo "expected manifest to include first artifact source path"
  cat "$manifest_file"
  exit 1
fi
if ! rg -q "$missing_artifact" "$skipped_file"; then
  echo "expected skipped file to include missing artifact"
  cat "$skipped_file"
  exit 1
fi

./scripts/incident_snapshot_attach_artifacts.sh \
  --bundle-dir "$bundle_dir" \
  --attach-artifact "$artifact_one" \
  --attach-artifact "$artifact_two" \
  --print-summary-json 1 >/tmp/integration_incident_snapshot_attach_second.log 2>&1

second_summary_json="$(sed -n 's/^summary_json: //p' /tmp/integration_incident_snapshot_attach_second.log | tail -n 1)"
if [[ -z "$second_summary_json" || ! -f "$second_summary_json" ]]; then
  echo "expected second regenerated summary json missing"
  cat /tmp/integration_incident_snapshot_attach_second.log
  exit 1
fi
if ! jq -e '.attachments.count == 2 and .attachments.skipped_count == 1' "$second_summary_json" >/dev/null 2>&1; then
  echo "summary json missing expected deduplicated attachment counts after second refresh"
  cat "$second_summary_json"
  exit 1
fi
if [[ "$(wc -l < "$manifest_file")" -ne 2 ]]; then
  echo "expected manifest to contain exactly two attached artifacts after dedupe"
  cat "$manifest_file"
  exit 1
fi
if ! rg -q "$artifact_two" "$manifest_file"; then
  echo "expected manifest to include second artifact source path"
  cat "$manifest_file"
  exit 1
fi

bundle_tar="$(sed -n 's/^bundle_tar: //p' /tmp/integration_incident_snapshot_attach_second.log | tail -n 1)"
if [[ -z "$bundle_tar" || ! -f "$bundle_tar" || ! -f "$bundle_tar.sha256" ]]; then
  echo "expected bundle tarball artifacts missing after second refresh"
  cat /tmp/integration_incident_snapshot_attach_second.log
  exit 1
fi

report_md="$(sed -n 's/^report_md: //p' /tmp/integration_incident_snapshot_attach_second.log | tail -n 1)"
if [[ -z "$report_md" || ! -f "$report_md" ]]; then
  echo "expected regenerated report markdown missing"
  cat /tmp/integration_incident_snapshot_attach_second.log
  exit 1
fi
if ! rg -q '^## Attachments$' "$report_md"; then
  echo "expected regenerated report to include attachments section"
  cat "$report_md"
  exit 1
fi

echo "incident snapshot attach artifacts integration check ok"
