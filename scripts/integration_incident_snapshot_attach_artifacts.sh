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
cat >"$bundle_dir/attachments/00_preexisting_client.pem" <<'EOF_PREEXISTING_CLIENT_PEM'
legacy attachment
-----BEGIN OPENSSH PRIVATE KEY-----
preexisting-private-key-marker-should-not-survive-refresh
-----END OPENSSH PRIVATE KEY-----
EOF_PREEXISTING_CLIENT_PEM
printf '%s\t%s\t%s\n' "attachments/00_preexisting_client.pem" "file" "source-sha256:preexisting-sensitive" >"$bundle_dir/attachments/manifest.tsv"

artifact_one="$TMP_DIR/runtime_doctor_after.json"
artifact_two="$TMP_DIR/manual_validation_readiness_summary.json"
artifact_public_ca_pem="$TMP_DIR/ca.pem"
artifact_client_pem="$TMP_DIR/client.pem"
artifact_ssh_key="$TMP_DIR/id_ed25519"
artifact_p12="$TMP_DIR/client.p12"
artifact_pfx="$TMP_DIR/client.pfx"
artifact_private_key_marker="$TMP_DIR/diagnostics.log"
artifact_dir_with_key="$TMP_DIR/diagnostics_dir"
printf '%s\n' '{"status":"OK","token":"attach-one-secret","subject":"attach-one-subject-secret","url":"http://attach-one-user-secret@attach-one:8081?auth_token=attach-one-query-secret#access_token=attach-one-fragment-secret"}' >"$artifact_one"
printf '%s\n' 'readiness_status: NOT_READY secret: attach-two-secret inv-attach-two-secret url=http://attach-two-user-secret@attach-two:8081?admin_token=attach-two-admin-query-secret&invite_key=attach-two-invite-query-secret&anon_cred=attach-two-anon-query-secret&subject=attach-two-subject-query-secret#key=attach-two-fragment-secret' >"$artifact_two"
cat >"$artifact_public_ca_pem" <<'EOF_PUBLIC_CA_PEM'
-----BEGIN CERTIFICATE-----
benign-public-ca-pem-evidence
-----END CERTIFICATE-----
EOF_PUBLIC_CA_PEM
printf '%s\n' 'fake client pem material should not attach' >"$artifact_client_pem"
printf '%s\n' 'fake ssh private key should not attach' >"$artifact_ssh_key"
printf '%s\n' 'fake p12 bytes should not attach' >"$artifact_p12"
printf '%s\n' 'fake pfx bytes should not attach' >"$artifact_pfx"
cat >"$artifact_private_key_marker" <<'EOF_PRIVATE_KEY_MARKER'
diagnostic preface
-----BEGIN PRIVATE KEY-----
fake-private-key-marker-should-not-attach
-----END PRIVATE KEY-----
EOF_PRIVATE_KEY_MARKER
mkdir -p "$artifact_dir_with_key"
printf '%s\n' 'directory evidence line' >"$artifact_dir_with_key/readme.txt"
printf '%s\n' 'nested fake key should not attach' >"$artifact_dir_with_key/id_ed25519"
missing_artifact="$TMP_DIR/missing-artifact.txt"

./scripts/incident_snapshot_attach_artifacts.sh \
  --bundle-dir "$bundle_dir" \
  --attach-artifact "$artifact_one" \
  --attach-artifact "$artifact_public_ca_pem" \
  --attach-artifact "$artifact_client_pem" \
  --attach-artifact "$artifact_ssh_key" \
  --attach-artifact "$artifact_p12" \
  --attach-artifact "$artifact_pfx" \
  --attach-artifact "$artifact_private_key_marker" \
  --attach-artifact "$artifact_dir_with_key" \
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
if ! jq -e '.attachments.count == 2 and .attachments.skipped_count == 8 and .attachments.sensitive_skipped_count == 7 and .bundle.manifest_exists == true and .bundle.tar_exists == true and .bundle.tar_sha256_exists == true' "$first_summary_json" >/dev/null 2>&1; then
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
if rg -q "$artifact_one" "$manifest_file"; then
  echo "attachment manifest leaked first artifact source path"
  cat "$manifest_file"
  exit 1
fi
if ! rg -q 'source-sha256:' "$manifest_file"; then
  echo "expected manifest to include redacted first artifact source reference"
  cat "$manifest_file"
  exit 1
fi
if ! rg -q 'ca.pem' "$manifest_file"; then
  echo "expected benign public PEM evidence to be attached"
  cat "$manifest_file"
  exit 1
fi
if rg -q "$missing_artifact" "$skipped_file"; then
  echo "skipped attachment file leaked missing artifact source path"
  cat "$skipped_file"
  exit 1
fi
if ! rg -q 'source-sha256:' "$skipped_file"; then
  echo "expected skipped file to include redacted missing artifact source reference"
  cat "$skipped_file"
  exit 1
fi
if [[ "$(rg -c $'\tsensitive_artifact$' "$skipped_file")" -ne 7 ]]; then
  echo "expected sensitive attachments to be skipped"
  cat "$skipped_file"
  exit 1
fi
if [[ -e "$bundle_dir/attachments/00_preexisting_client.pem" ]]; then
  echo "preexisting sensitive attachment survived refresh"
  ls -la "$bundle_dir/attachments"
  exit 1
fi
if rg -a -q 'fake client pem material|fake ssh private key|fake p12 bytes|fake pfx bytes|fake-private-key-marker|nested fake key|directory evidence line|preexisting-private-key-marker' "$bundle_dir/attachments"; then
  echo "sensitive attachment content was copied into bundle attachments"
  rg -a -n 'fake client pem material|fake ssh private key|fake p12 bytes|fake pfx bytes|fake-private-key-marker|nested fake key|directory evidence line|preexisting-private-key-marker' "$bundle_dir/attachments" || true
  exit 1
fi
if rg -a -q 'attach-one-secret|attach-one-subject-secret|attach-one-user-secret|attach-one-query-secret|attach-one-fragment-secret' "$bundle_dir/attachments"; then
  echo "attached artifact content leaked first fake secret"
  rg -a -n 'attach-one-secret|attach-one-subject-secret|attach-one-user-secret|attach-one-query-secret|attach-one-fragment-secret' "$bundle_dir/attachments" || true
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
if ! jq -e '.attachments.count == 3 and .attachments.skipped_count == 8 and .attachments.sensitive_skipped_count == 7' "$second_summary_json" >/dev/null 2>&1; then
  echo "summary json missing expected deduplicated attachment counts after second refresh"
  cat "$second_summary_json"
  exit 1
fi
if [[ "$(wc -l < "$manifest_file")" -ne 3 ]]; then
  echo "expected manifest to contain exactly three attached artifacts after dedupe"
  cat "$manifest_file"
  exit 1
fi
if rg -q "$artifact_two" "$manifest_file"; then
  echo "attachment manifest leaked second artifact source path"
  cat "$manifest_file"
  exit 1
fi
if rg -a -q 'attach-two-secret|inv-attach-two-secret|attach-two-user-secret|attach-two-admin-query-secret|attach-two-invite-query-secret|attach-two-anon-query-secret|attach-two-subject-query-secret|attach-two-fragment-secret' "$bundle_dir/attachments"; then
  echo "attached artifact content leaked second fake secret"
  rg -a -n 'attach-two-secret|inv-attach-two-secret|attach-two-user-secret|attach-two-admin-query-secret|attach-two-invite-query-secret|attach-two-anon-query-secret|attach-two-subject-query-secret|attach-two-fragment-secret' "$bundle_dir/attachments" || true
  exit 1
fi

bundle_tar="$(sed -n 's/^bundle_tar: //p' /tmp/integration_incident_snapshot_attach_second.log | tail -n 1)"
if [[ -z "$bundle_tar" || ! -f "$bundle_tar" || ! -f "$bundle_tar.sha256" ]]; then
  echo "expected bundle tarball artifacts missing after second refresh"
  cat /tmp/integration_incident_snapshot_attach_second.log
  exit 1
fi
if tar -xOzf "$bundle_tar" | rg -a -q 'attach-one-secret|attach-one-subject-secret|attach-one-user-secret|attach-one-query-secret|attach-one-fragment-secret|attach-two-secret|inv-attach-two-secret|attach-two-user-secret|attach-two-admin-query-secret|attach-two-invite-query-secret|attach-two-anon-query-secret|attach-two-subject-query-secret|attach-two-fragment-secret|preexisting-private-key-marker'; then
  echo "attachment refresh bundle tar leaked fake secrets"
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
