#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/incident_snapshot_attach_artifacts.sh \
    --bundle-dir PATH \
    [--bundle-tar PATH] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--attach-artifact PATH]... \
    [--print-summary-json [0|1]]

Purpose:
  Attach extra evidence files to an existing incident snapshot bundle,
  regenerate the concise summary/report, and refresh bundle integrity outputs.
USAGE
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path="$1"
  path="$(trim "$path")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" == /* ]]; then
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

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

hash_file_line() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file"
    return 0
  fi
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$file"
    return 0
  fi
  return 1
}

refresh_bundle_integrity() {
  local bundle_dir="$1"
  local bundle_tar="$2"
  local manifest_file="$3"
  local bundle_tar_sha="$4"

  if hash_file_line "$bundle_dir/metadata.txt" >/dev/null 2>&1; then
    (
      cd "$bundle_dir"
      while IFS= read -r rel_path; do
        hash_file_line "$rel_path"
      done < <(find . -type f ! -name 'manifest.sha256' -print | sed 's#^\./##' | sort)
    ) >"$manifest_file"
  else
    echo "sha256 tooling missing (sha256sum/shasum)" >"$manifest_file"
  fi

  tar -czf "$bundle_tar" -C "$(dirname "$bundle_dir")" "$(basename "$bundle_dir")"
  if hash_file_line "$bundle_tar" >"$bundle_tar_sha" 2>/dev/null; then
    :
  else
    echo "sha256 tooling missing (sha256sum/shasum)" >"$bundle_tar_sha"
  fi
}

sanitize_attachment_name() {
  local name="$1"
  name="${name//[^A-Za-z0-9._-]/_}"
  while [[ "$name" == .* ]]; do
    name="_${name#.}"
  done
  if [[ -z "$name" ]]; then
    name="artifact"
  fi
  printf '%s' "$name"
}

manifest_has_source() {
  local manifest_file="$1"
  local source_path="$2"
  [[ -f "$manifest_file" ]] || return 1
  awk -F'\t' -v src="$source_path" '$3 == src {found=1} END {exit found ? 0 : 1}' "$manifest_file"
}

skipped_has_source() {
  local skipped_file="$1"
  local source_path="$2"
  [[ -f "$skipped_file" ]] || return 1
  awk -F'\t' -v src="$source_path" '$1 == src {found=1} END {exit found ? 0 : 1}' "$skipped_file"
}

bundle_dir=""
bundle_tar=""
summary_json=""
report_md=""
print_summary_json="0"
declare -a attach_artifacts=()

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
    --attach-artifact)
      attach_artifacts+=("$(abs_path "${2:-}")")
      shift 2
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

for cmd in jq tar find sed awk date cp mkdir; do
  need_cmd "$cmd"
done
bool_arg_or_die "--print-summary-json" "$print_summary_json"

bundle_dir="$(abs_path "$bundle_dir")"
bundle_tar="$(abs_path "$bundle_tar")"
summary_json="$(abs_path "$summary_json")"
report_md="$(abs_path "$report_md")"

if [[ -z "$bundle_dir" ]]; then
  echo "missing required input: --bundle-dir"
  exit 2
fi
if [[ ! -d "$bundle_dir" ]]; then
  echo "bundle directory not found: $bundle_dir"
  exit 1
fi
if [[ -z "$bundle_tar" ]]; then
  bundle_tar="${bundle_dir}.tar.gz"
fi
if [[ -z "$summary_json" ]]; then
  summary_json="$bundle_dir/incident_summary.json"
fi
if [[ -z "$report_md" ]]; then
  report_md="$bundle_dir/incident_report.md"
fi

attachments_dir="$bundle_dir/attachments"
attachments_manifest="$attachments_dir/manifest.tsv"
attachments_skipped="$attachments_dir/skipped.tsv"
manifest_file="$bundle_dir/manifest.sha256"
bundle_tar_sha="$bundle_tar.sha256"
mkdir -p "$attachments_dir"
: >"${attachments_manifest}.tmp"
if [[ -f "$attachments_manifest" ]]; then
  cat "$attachments_manifest" >"${attachments_manifest}.tmp"
fi
mv "${attachments_manifest}.tmp" "$attachments_manifest"
: >"${attachments_skipped}.tmp"
if [[ -f "$attachments_skipped" ]]; then
  cat "$attachments_skipped" >"${attachments_skipped}.tmp"
fi
mv "${attachments_skipped}.tmp" "$attachments_skipped"

attachment_index="$(awk 'END {print NR+0}' "$attachments_manifest" 2>/dev/null || echo 0)"
for artifact in "${attach_artifacts[@]}"; do
  artifact="$(trim "$artifact")"
  [[ -n "$artifact" ]] || continue

  if manifest_has_source "$attachments_manifest" "$artifact"; then
    continue
  fi

  if [[ ! -e "$artifact" ]]; then
    if ! skipped_has_source "$attachments_skipped" "$artifact"; then
      printf '%s\t%s\n' "$artifact" "missing" >>"$attachments_skipped"
    fi
    continue
  fi

  attachment_index=$((attachment_index + 1))
  artifact_basename="$(basename "$artifact")"
  artifact_safe_name="$(sanitize_attachment_name "$artifact_basename")"
  artifact_dest_rel="attachments/$(printf '%02d' "$attachment_index")_${artifact_safe_name}"
  artifact_dest_path="$bundle_dir/$artifact_dest_rel"
  artifact_type="file"
  if [[ -d "$artifact" ]]; then
    artifact_type="dir"
  elif [[ -L "$artifact" ]]; then
    artifact_type="symlink"
  fi

  if cp -R "$artifact" "$artifact_dest_path" 2>/dev/null; then
    printf '%s\t%s\t%s\n' "$artifact_dest_rel" "$artifact_type" "$artifact" >>"$attachments_manifest"
  else
    printf '%s\t%s\n' "$artifact" "copy_failed" >>"$attachments_skipped"
  fi
done

summary_script="${INCIDENT_SNAPSHOT_SUMMARY_SCRIPT:-$ROOT_DIR/scripts/incident_snapshot_summary.sh}"
if [[ ! -x "$summary_script" ]]; then
  echo "missing incident summary script: $summary_script"
  exit 2
fi
refresh_bundle_integrity "$bundle_dir" "$bundle_tar" "$manifest_file" "$bundle_tar_sha"

"$summary_script" \
  --bundle-dir "$bundle_dir" \
  --summary-json "$summary_json" \
  --report-md "$report_md" \
  --print-report 0 \
  --print-summary-json 0 >/dev/null

refresh_bundle_integrity "$bundle_dir" "$bundle_tar" "$manifest_file" "$bundle_tar_sha"

attachment_count="$(awk 'END {print NR+0}' "$attachments_manifest" 2>/dev/null || echo 0)"
attachment_skipped_count="$(awk 'END {print NR+0}' "$attachments_skipped" 2>/dev/null || echo 0)"

echo "incident snapshot attachments updated"
echo "bundle_dir: $bundle_dir"
echo "bundle_tar: $bundle_tar"
echo "bundle_tar_sha256: $bundle_tar_sha"
echo "summary_json: $summary_json"
echo "report_md: $report_md"
echo "attachment_manifest: $attachments_manifest"
echo "attachment_skipped: $attachments_skipped"
echo "attachment_count: $attachment_count"
echo "attachment_skipped_count: $attachment_skipped_count"

if [[ "$print_summary_json" == "1" ]]; then
  echo "[incident-snapshot-attach] summary_json_payload:"
  jq -n \
    --arg bundle_dir "$bundle_dir" \
    --arg bundle_tar "$bundle_tar" \
    --arg bundle_tar_sha256 "$bundle_tar_sha" \
    --arg summary_json "$summary_json" \
    --arg report_md "$report_md" \
    --arg attachment_manifest "$attachments_manifest" \
    --arg attachment_skipped "$attachments_skipped" \
    --arg attachment_count "$attachment_count" \
    --arg attachment_skipped_count "$attachment_skipped_count" \
    '{
      version: 1,
      generated_at_utc: (now | todateiso8601),
      bundle_dir: $bundle_dir,
      bundle_tar: $bundle_tar,
      bundle_tar_sha256: $bundle_tar_sha256,
      summary_json: $summary_json,
      report_md: $report_md,
      attachment_manifest: $attachment_manifest,
      attachment_skipped: $attachment_skipped,
      attachment_count: ($attachment_count | tonumber),
      attachment_skipped_count: ($attachment_skipped_count | tonumber)
    }'
fi
