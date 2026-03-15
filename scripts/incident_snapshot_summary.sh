#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/incident_snapshot_summary.sh \
    [--bundle-dir PATH] \
    [--bundle-tar PATH] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-report [0|1]] \
    [--print-summary-json [0|1]]

Purpose:
  Build one operator-facing summary from an incident snapshot bundle.

Notes:
  - Recommended input: --bundle-dir from incident_snapshot.sh
  - If --bundle-tar is provided, the script looks for the extracted bundle
    directory next to the tarball (<bundle_tar without .tar.gz>).
  - Outputs:
      1) machine-readable summary JSON
      2) concise markdown incident report
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
    return
  fi
  if [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

kv_value() {
  local file="$1"
  local key="$2"
  if [[ ! -f "$file" ]]; then
    printf '%s' ""
    return
  fi
  sed -nE "s/^${key}=(.*)$/\\1/p" "$file" | head -n1
}

json_string() {
  local file="$1"
  local expr="$2"
  if [[ ! -f "$file" ]]; then
    printf '%s' ""
    return
  fi
  jq -r "$expr // \"\"" "$file" 2>/dev/null || printf '%s' ""
}

json_int() {
  local file="$1"
  local expr="$2"
  local value
  value="$(json_string "$file" "$expr")"
  if [[ -z "$value" || ! "$value" =~ ^-?[0-9]+$ ]]; then
    printf '%s' "0"
    return
  fi
  printf '%s' "$value"
}

probe_status() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    printf '%s' "missing"
    return
  fi
  if rg -q '^probe_failed:' "$file"; then
    printf '%s' "fail"
    return
  fi
  if rg -q '^skipped:' "$file"; then
    printf '%s' "skipped"
    return
  fi
  printf '%s' "ok"
}

probe_note() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    printf '%s' "file missing"
    return
  fi
  if rg -q '^(probe_failed|skipped):' "$file"; then
    head -n1 "$file" | tr -d '\r'
    return
  fi
  printf '%s' ""
}

add_finding() {
  local file="$1"
  local message="$2"
  printf '%s\n' "$message" >>"$file"
}

bundle_dir=""
bundle_tar=""
summary_json=""
report_md=""
print_report="${INCIDENT_SNAPSHOT_SUMMARY_PRINT_REPORT:-1}"
print_summary_json="${INCIDENT_SNAPSHOT_SUMMARY_PRINT_SUMMARY_JSON:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    --bundle-tar)
      bundle_tar="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --print-report)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_report="${2:-}"
        shift 2
      else
        print_report="1"
        shift
      fi
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

for cmd in bash jq date rg; do
  need_cmd "$cmd"
done

bool_arg_or_die "--print-report" "$print_report"
bool_arg_or_die "--print-summary-json" "$print_summary_json"

bundle_dir="$(abs_path "$bundle_dir")"
bundle_tar="$(abs_path "$bundle_tar")"
if [[ -z "$bundle_dir" && -n "$bundle_tar" ]]; then
  if [[ "$bundle_tar" == *.tar.gz ]]; then
    bundle_dir="${bundle_tar%.tar.gz}"
  else
    bundle_dir="${bundle_tar}.dir"
  fi
fi
if [[ -z "$bundle_dir" ]]; then
  echo "missing required input: --bundle-dir or --bundle-tar"
  exit 2
fi
if [[ ! -d "$bundle_dir" ]]; then
  echo "bundle directory not found: $bundle_dir"
  exit 1
fi

if [[ -z "$bundle_tar" ]]; then
  bundle_tar="${bundle_dir}.tar.gz"
fi

summary_json="$(abs_path "${summary_json:-$bundle_dir/incident_summary.json}")"
report_md="$(abs_path "${report_md:-$bundle_dir/incident_report.md}")"
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

metadata_file="$bundle_dir/metadata.txt"
directory_relays_file="$bundle_dir/endpoints/directory_relays.json"
directory_peers_file="$bundle_dir/endpoints/directory_peers.json"
directory_health_file="$bundle_dir/endpoints/directory_health.json"
issuer_pubkeys_file="$bundle_dir/endpoints/issuer_pubkeys.json"
entry_health_file="$bundle_dir/endpoints/entry_health.json"
exit_health_file="$bundle_dir/endpoints/exit_health.json"
exit_metrics_file="$bundle_dir/endpoints/exit_metrics.json"
docker_ps_file="$bundle_dir/docker/docker_ps.txt"
compose_ps_file="$bundle_dir/docker/compose_ps.txt"
directory_log_file="$bundle_dir/docker/directory_tail.log"
issuer_log_file="$bundle_dir/docker/issuer_tail.log"
entry_exit_log_file="$bundle_dir/docker/entry-exit_tail.log"
manifest_file="$bundle_dir/manifest.sha256"
bundle_tar_sha_file="$bundle_tar.sha256"
attachments_manifest_file="$bundle_dir/attachments/manifest.tsv"
attachments_skipped_file="$bundle_dir/attachments/skipped.tsv"

tmp_findings="$(mktemp)"
trap 'rm -f "$tmp_findings"' EXIT

generated_at="$(kv_value "$metadata_file" "generated_at_utc")"
host="$(kv_value "$metadata_file" "host")"
mode="$(kv_value "$metadata_file" "mode")"
env_file="$(kv_value "$metadata_file" "env_file")"
directory_url="$(kv_value "$metadata_file" "directory_url")"
issuer_url="$(kv_value "$metadata_file" "issuer_url")"
entry_url="$(kv_value "$metadata_file" "entry_url")"
exit_url="$(kv_value "$metadata_file" "exit_url")"
compose_project="$(kv_value "$metadata_file" "compose_project")"

directory_relays_status="$(probe_status "$directory_relays_file")"
directory_peers_status="$(probe_status "$directory_peers_file")"
directory_health_status="$(probe_status "$directory_health_file")"
issuer_pubkeys_status="$(probe_status "$issuer_pubkeys_file")"
entry_health_status="$(probe_status "$entry_health_file")"
exit_health_status="$(probe_status "$exit_health_file")"
exit_metrics_status="$(probe_status "$exit_metrics_file")"

directory_relays_note="$(probe_note "$directory_relays_file")"
directory_peers_note="$(probe_note "$directory_peers_file")"
directory_health_note="$(probe_note "$directory_health_file")"
issuer_pubkeys_note="$(probe_note "$issuer_pubkeys_file")"
entry_health_note="$(probe_note "$entry_health_file")"
exit_health_note="$(probe_note "$exit_health_file")"
exit_metrics_note="$(probe_note "$exit_metrics_file")"

relay_count="$(json_int "$directory_relays_file" '(.relays // []) | length')"
peer_count="$(json_int "$directory_peers_file" '(.peers // []) | length')"
issuer_id="$(json_string "$issuer_pubkeys_file" '.issuer')"
issuer_pubkey_count="$(json_int "$issuer_pubkeys_file" '(.pub_keys // []) | length')"
directory_health_ok="$(json_string "$directory_health_file" '.ok')"
entry_health_ok="$(json_string "$entry_health_file" '.ok')"
exit_health_ok="$(json_string "$exit_health_file" '.ok')"
accepted_packets="$(json_int "$exit_metrics_file" '.accepted_packets')"
wg_proxy_created="$(json_int "$exit_metrics_file" '.wg_proxy_created')"

critical_count=0
warning_count=0

if [[ "$directory_health_status" != "ok" || "$directory_health_ok" != "true" ]]; then
  critical_count=$((critical_count + 1))
  add_finding "$tmp_findings" "Directory health probe failed or did not report ok=true."
fi
if [[ "$issuer_pubkeys_status" != "ok" || "$issuer_pubkey_count" -lt 1 ]]; then
  critical_count=$((critical_count + 1))
  add_finding "$tmp_findings" "Issuer pubkey feed is unavailable or returned zero keys."
fi
if [[ "$entry_health_status" != "ok" || "$entry_health_ok" != "true" ]]; then
  critical_count=$((critical_count + 1))
  add_finding "$tmp_findings" "Entry health probe failed or did not report ok=true."
fi
if [[ "$exit_health_status" != "ok" || "$exit_health_ok" != "true" ]]; then
  critical_count=$((critical_count + 1))
  add_finding "$tmp_findings" "Exit health probe failed or did not report ok=true."
fi

if [[ "$directory_relays_status" != "ok" || "$relay_count" -lt 1 ]]; then
  warning_count=$((warning_count + 1))
  add_finding "$tmp_findings" "Directory relay feed is unavailable or returned zero relays."
fi
if [[ "$directory_peers_status" != "ok" ]]; then
  warning_count=$((warning_count + 1))
  add_finding "$tmp_findings" "Directory peer feed was not captured successfully."
fi
if [[ "$exit_metrics_status" != "ok" ]]; then
  warning_count=$((warning_count + 1))
  add_finding "$tmp_findings" "Exit metrics endpoint was not captured successfully."
elif [[ "$accepted_packets" -lt 1 ]]; then
  warning_count=$((warning_count + 1))
  add_finding "$tmp_findings" "Exit metrics show zero accepted packets in the snapshot."
fi

docker_ps_status="ok"
docker_ps_note=""
if [[ ! -f "$docker_ps_file" ]]; then
  docker_ps_status="missing"
  docker_ps_note="file missing"
elif rg -q 'docker command missing' "$docker_ps_file"; then
  docker_ps_status="warn"
  docker_ps_note="docker command missing"
elif ! rg -q 'CONTAINER ID|STATUS|Up' "$docker_ps_file"; then
  docker_ps_status="warn"
  docker_ps_note="docker ps output did not include expected runtime state"
fi
if [[ "$docker_ps_status" != "ok" ]]; then
  warning_count=$((warning_count + 1))
  add_finding "$tmp_findings" "Docker runtime state could not be verified from docker_ps.txt."
fi

compose_ps_status="ok"
compose_ps_note=""
if [[ ! -f "$compose_ps_file" ]]; then
  compose_ps_status="missing"
  compose_ps_note="file missing"
elif rg -q 'docker compose plugin missing' "$compose_ps_file"; then
  compose_ps_status="warn"
  compose_ps_note="docker compose plugin missing"
elif ! rg -q 'STATUS|Up|Exit|running|Created' "$compose_ps_file"; then
  compose_ps_status="warn"
  compose_ps_note="compose ps output did not include expected service state"
fi
if [[ "$compose_ps_status" != "ok" ]]; then
  warning_count=$((warning_count + 1))
  add_finding "$tmp_findings" "Docker compose service state could not be verified from compose_ps.txt."
fi

directory_log_present="0"
issuer_log_present="0"
entry_exit_log_present="0"
if [[ -f "$directory_log_file" ]]; then directory_log_present="1"; fi
if [[ -f "$issuer_log_file" ]]; then issuer_log_present="1"; fi
if [[ -f "$entry_exit_log_file" ]]; then entry_exit_log_present="1"; fi
if [[ "$directory_log_present" != "1" || "$issuer_log_present" != "1" || "$entry_exit_log_present" != "1" ]]; then
  warning_count=$((warning_count + 1))
  add_finding "$tmp_findings" "One or more docker log tail artifacts are missing from the incident bundle."
fi

bundle_dir_exists="0"
bundle_tar_exists="0"
bundle_tar_sha_exists="0"
manifest_exists="0"
if [[ -d "$bundle_dir" ]]; then bundle_dir_exists="1"; fi
if [[ -f "$bundle_tar" ]]; then bundle_tar_exists="1"; fi
if [[ -f "$bundle_tar_sha_file" ]]; then bundle_tar_sha_exists="1"; fi
if [[ -f "$manifest_file" ]]; then manifest_exists="1"; fi

if [[ "$manifest_exists" != "1" || "$bundle_tar_exists" != "1" || "$bundle_tar_sha_exists" != "1" ]]; then
  warning_count=$((warning_count + 1))
  add_finding "$tmp_findings" "Bundle integrity artifacts are incomplete (manifest, tarball, or tarball checksum missing)."
fi

attachments_json='[]'
attachments_skipped_json='[]'
attachment_count=0
attachment_skipped_count=0
attachments_status="none"
if [[ -f "$attachments_manifest_file" ]]; then
  while IFS=$'\t' read -r stored_path attachment_type source_path; do
    [[ -n "${stored_path:-}" && -n "${attachment_type:-}" && -n "${source_path:-}" ]] || continue
    attachments_json="$(
      jq -c \
        --arg stored_path "$stored_path" \
        --arg type "$attachment_type" \
        --arg source_path "$source_path" \
        '. + [{stored_path: $stored_path, type: $type, source_path: $source_path}]' \
        <<<"$attachments_json"
    )"
  done <"$attachments_manifest_file"
  attachment_count="$(jq 'length' <<<"$attachments_json")"
fi
if [[ -f "$attachments_skipped_file" ]]; then
  while IFS=$'\t' read -r source_path reason; do
    [[ -n "${source_path:-}" && -n "${reason:-}" ]] || continue
    attachments_skipped_json="$(
      jq -c \
        --arg source_path "$source_path" \
        --arg reason "$reason" \
        '. + [{source_path: $source_path, reason: $reason}]' \
        <<<"$attachments_skipped_json"
    )"
  done <"$attachments_skipped_file"
  attachment_skipped_count="$(jq 'length' <<<"$attachments_skipped_json")"
fi
if ((attachment_count > 0)); then
  attachments_status="ok"
fi
if ((attachment_skipped_count > 0)); then
  attachments_status="warn"
  warning_count=$((warning_count + 1))
  add_finding "$tmp_findings" "One or more requested attached artifacts were missing or could not be copied into the incident bundle."
fi

if [[ "$critical_count" -gt 0 ]]; then
  overall_status="fail"
elif [[ "$warning_count" -gt 0 ]]; then
  overall_status="warn"
else
  overall_status="ok"
  add_finding "$tmp_findings" "No immediate failures detected in the captured incident snapshot."
fi

findings_json="$(jq -Rs 'split("\n") | map(select(length > 0))' "$tmp_findings")"
finding_count="$(printf '%s' "$findings_json" | jq 'length')"

jq -n \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$overall_status" \
  --arg bundle_dir "$bundle_dir" \
  --arg bundle_tar "$bundle_tar" \
  --arg report_md "$report_md" \
  --arg host "$host" \
  --arg mode "$mode" \
  --arg env_file "$env_file" \
  --arg directory_url "$directory_url" \
  --arg issuer_url "$issuer_url" \
  --arg entry_url "$entry_url" \
  --arg exit_url "$exit_url" \
  --arg compose_project "$compose_project" \
  --arg attachments_status "$attachments_status" \
  --arg attachments_manifest_file "$attachments_manifest_file" \
  --arg attachments_skipped_file "$attachments_skipped_file" \
  --arg metadata_generated_at "$generated_at" \
  --arg directory_relays_status "$directory_relays_status" \
  --arg directory_relays_note "$directory_relays_note" \
  --arg directory_peers_status "$directory_peers_status" \
  --arg directory_peers_note "$directory_peers_note" \
  --arg directory_health_status "$directory_health_status" \
  --arg directory_health_note "$directory_health_note" \
  --arg issuer_pubkeys_status "$issuer_pubkeys_status" \
  --arg issuer_pubkeys_note "$issuer_pubkeys_note" \
  --arg issuer_id "$issuer_id" \
  --arg entry_health_status "$entry_health_status" \
  --arg entry_health_note "$entry_health_note" \
  --arg exit_health_status "$exit_health_status" \
  --arg exit_health_note "$exit_health_note" \
  --arg exit_metrics_status "$exit_metrics_status" \
  --arg exit_metrics_note "$exit_metrics_note" \
  --arg docker_ps_status "$docker_ps_status" \
  --arg docker_ps_note "$docker_ps_note" \
  --arg compose_ps_status "$compose_ps_status" \
  --arg compose_ps_note "$compose_ps_note" \
  --argjson relay_count "$relay_count" \
  --argjson peer_count "$peer_count" \
  --argjson issuer_pubkey_count "$issuer_pubkey_count" \
  --argjson accepted_packets "$accepted_packets" \
  --argjson wg_proxy_created "$wg_proxy_created" \
  --argjson bundle_dir_exists "$bundle_dir_exists" \
  --argjson bundle_tar_exists "$bundle_tar_exists" \
  --argjson bundle_tar_sha_exists "$bundle_tar_sha_exists" \
  --argjson manifest_exists "$manifest_exists" \
  --argjson directory_log_present "$directory_log_present" \
  --argjson issuer_log_present "$issuer_log_present" \
  --argjson entry_exit_log_present "$entry_exit_log_present" \
  --argjson finding_count "$finding_count" \
  --argjson critical_count "$critical_count" \
  --argjson warning_count "$warning_count" \
  --argjson attachment_count "$attachment_count" \
  --argjson attachment_skipped_count "$attachment_skipped_count" \
  --argjson attachments "$attachments_json" \
  --argjson attachments_skipped "$attachments_skipped_json" \
  --argjson findings "$findings_json" \
  '{
    generated_at_utc: $generated_at_utc,
    status: $status,
    finding_count: $finding_count,
    critical_count: $critical_count,
    warning_count: $warning_count,
    bundle: {
      dir: $bundle_dir,
      tar: $bundle_tar,
      report_md: $report_md,
      dir_exists: ($bundle_dir_exists == 1),
      tar_exists: ($bundle_tar_exists == 1),
      tar_sha256_exists: ($bundle_tar_sha_exists == 1),
      manifest_exists: ($manifest_exists == 1)
    },
    attachments: {
      status: $attachments_status,
      count: $attachment_count,
      skipped_count: $attachment_skipped_count,
      manifest_file: (if $attachment_count > 0 then $attachments_manifest_file else "" end),
      skipped_file: (if $attachment_skipped_count > 0 then $attachments_skipped_file else "" end),
      items: $attachments,
      skipped: $attachments_skipped
    },
    context: {
      metadata_generated_at: $metadata_generated_at,
      host: $host,
      mode: $mode,
      env_file: $env_file,
      compose_project: $compose_project,
      directory_url: $directory_url,
      issuer_url: $issuer_url,
      entry_url: $entry_url,
      exit_url: $exit_url
    },
    endpoints: {
      directory_relays: {status: $directory_relays_status, note: $directory_relays_note, relay_count: $relay_count},
      directory_peers: {status: $directory_peers_status, note: $directory_peers_note, peer_count: $peer_count},
      directory_health: {status: $directory_health_status, note: $directory_health_note},
      issuer_pubkeys: {status: $issuer_pubkeys_status, note: $issuer_pubkeys_note, issuer: $issuer_id, pub_key_count: $issuer_pubkey_count},
      entry_health: {status: $entry_health_status, note: $entry_health_note},
      exit_health: {status: $exit_health_status, note: $exit_health_note},
      exit_metrics: {status: $exit_metrics_status, note: $exit_metrics_note, accepted_packets: $accepted_packets, wg_proxy_created: $wg_proxy_created}
    },
    docker: {
      docker_ps_status: $docker_ps_status,
      docker_ps_note: $docker_ps_note,
      compose_ps_status: $compose_ps_status,
      compose_ps_note: $compose_ps_note,
      log_tails_present: {
        directory: ($directory_log_present == 1),
        issuer: ($issuer_log_present == 1),
        entry_exit: ($entry_exit_log_present == 1)
      }
    },
    findings: $findings
  }' >"$summary_json"

{
  echo "# Incident Snapshot Summary"
  echo
  echo "- Status: \`$overall_status\`"
  echo "- Bundle dir: \`$bundle_dir\`"
  echo "- Bundle tar: \`$bundle_tar\`"
  echo "- Generated: \`$(date -u +%Y-%m-%dT%H:%M:%SZ)\`"
  echo
  echo "## Attachments"
  echo "- Status: \`${attachments_status}\`"
  echo "- Attached artifacts: \`${attachment_count}\`"
  echo "- Skipped attachments: \`${attachment_skipped_count}\`"
  if ((attachment_count > 0)); then
    echo
    echo "| Stored path | Type | Source path |"
    echo "| --- | --- | --- |"
    while IFS=$'\t' read -r stored_path attachment_type source_path; do
      [[ -n "${stored_path:-}" && -n "${attachment_type:-}" && -n "${source_path:-}" ]] || continue
      echo "| \`${stored_path}\` | \`${attachment_type}\` | \`${source_path}\` |"
    done <"$attachments_manifest_file"
  fi
  if ((attachment_skipped_count > 0)); then
    echo
    echo "| Skipped source path | Reason |"
    echo "| --- | --- |"
    while IFS=$'\t' read -r source_path reason; do
      [[ -n "${source_path:-}" && -n "${reason:-}" ]] || continue
      echo "| \`${source_path}\` | \`${reason}\` |"
    done <"$attachments_skipped_file"
  fi
  echo
  echo "## Context"
  echo "- Host: \`${host:-unknown}\`"
  echo "- Mode: \`${mode:-unknown}\`"
  echo "- Env file: \`${env_file:-unknown}\`"
  echo "- Compose project: \`${compose_project:-unknown}\`"
  echo "- Directory URL: \`${directory_url:-}\`"
  echo "- Issuer URL: \`${issuer_url:-}\`"
  echo "- Entry URL: \`${entry_url:-}\`"
  echo "- Exit URL: \`${exit_url:-}\`"
  echo
  echo "## Endpoint Summary"
  echo "| Check | Status | Note |"
  echo "| --- | --- | --- |"
  echo "| Directory relays | ${directory_relays_status} | relays=${relay_count} ${directory_relays_note} |"
  echo "| Directory peers | ${directory_peers_status} | peers=${peer_count} ${directory_peers_note} |"
  echo "| Directory health | ${directory_health_status} | ${directory_health_note} |"
  echo "| Issuer pubkeys | ${issuer_pubkeys_status} | issuer=${issuer_id:-unknown} keys=${issuer_pubkey_count} ${issuer_pubkeys_note} |"
  echo "| Entry health | ${entry_health_status} | ${entry_health_note} |"
  echo "| Exit health | ${exit_health_status} | ${exit_health_note} |"
  echo "| Exit metrics | ${exit_metrics_status} | accepted_packets=${accepted_packets} wg_proxy_created=${wg_proxy_created} ${exit_metrics_note} |"
  echo
  echo "## Docker Summary"
  echo "- docker ps: \`${docker_ps_status}\` ${docker_ps_note}"
  echo "- compose ps: \`${compose_ps_status}\` ${compose_ps_note}"
  echo "- log tails present: directory=\`${directory_log_present}\`, issuer=\`${issuer_log_present}\`, entry-exit=\`${entry_exit_log_present}\`"
  echo
  echo "## Findings"
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    echo "- $line"
  done <"$tmp_findings"
} >"$report_md"

if [[ "$print_report" == "1" ]]; then
  cat "$report_md"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

echo "incident snapshot summary ready"
echo "summary_json: $summary_json"
echo "report_md: $report_md"
