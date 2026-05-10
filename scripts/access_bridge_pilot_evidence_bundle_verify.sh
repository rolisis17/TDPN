#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
    [--summary-json PATH] \
    [--bundle-dir PATH] \
    [--bundle-tar PATH] \
    [--bundle-tar-sha256-file PATH] \
    [--check-tar-sha256 [0|1]] \
    [--check-manifest [0|1]] \
    [--show-details [0|1]]

Purpose:
  Verify Access Bridge pilot evidence bundle integrity artifacts:
  - tarball checksum sidecar (<bundle>.tar.gz.sha256)
  - in-bundle manifest.sha256
  - tar member safety before extraction (no absolute/parent paths, symlinks, or hardlinks)

Notes:
  - Provide at least one of --summary-json, --bundle-dir, or --bundle-tar.
  - --summary-json can auto-fill bundle_dir, bundle_tar, and checksum sidecar paths.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "missing required command: $1"
    exit 2
  fi
}

bool_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
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
  elif [[ "$path" =~ ^[A-Za-z]:[\\/] ]]; then
    if command -v wslpath >/dev/null 2>&1; then
      wslpath -u "$path"
    elif command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$path"
    else
      printf '%s' "$path"
    fi
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

json_string() {
  local file="$1"
  local filter="$2"
  jq -r "$filter // \"\"" "$file" 2>/dev/null || true
}

sha256_tool=""
detect_sha256_tool() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256_tool="sha256sum"
    return
  fi
  if command -v shasum >/dev/null 2>&1; then
    sha256_tool="shasum"
    return
  fi
  echo "missing required command: sha256sum or shasum"
  exit 2
}

sha256_value() {
  local file="$1"
  local line
  if [[ "$sha256_tool" == "sha256sum" ]]; then
    line="$(sha256sum "$file")"
  else
    line="$(shasum -a 256 "$file")"
  fi
  printf '%s' "${line%% *}" | tr '[:upper:]' '[:lower:]'
}

rel_path_is_safe() {
  local rel
  rel="$(trim "${1:-}")"
  while [[ "$rel" == ./* ]]; do
    rel="${rel#./}"
  done
  rel="${rel%/}"
  if [[ -z "$rel" || "$rel" == "." || "$rel" == /* ]]; then
    return 1
  fi

  local part
  local -a parts=()
  local IFS='/'
  read -r -a parts <<<"$rel"
  for part in "${parts[@]}"; do
    if [[ -z "$part" || "$part" == "." || "$part" == ".." ]]; then
      return 1
    fi
  done
  return 0
}

validate_tar_members_safe() {
  local tarball="$1"
  local entries_file details_file entry line unsafe=0

  entries_file="$(mktemp)"
  details_file="$(mktemp)"
  if ! tar -tzf "$tarball" >"$entries_file"; then
    rm -f "$entries_file" "$details_file"
    echo "failed to list bundle tar members: $tarball"
    return 1
  fi
  if ! tar -tvzf "$tarball" >"$details_file"; then
    rm -f "$entries_file" "$details_file"
    echo "failed to inspect bundle tar member metadata: $tarball"
    return 1
  fi

  while IFS= read -r entry || [[ -n "${entry:-}" ]]; do
    if ! rel_path_is_safe "$entry"; then
      echo "unsafe bundle tar member path: ${entry:-<empty>}"
      unsafe=1
    fi
  done <"$entries_file"

  while IFS= read -r line || [[ -n "${line:-}" ]]; do
    case "${line:0:1}" in
      l|h)
        echo "unsafe bundle tar link member: $line"
        unsafe=1
        ;;
    esac
  done <"$details_file"

  rm -f "$entries_file" "$details_file"
  return "$unsafe"
}

summary_json=""
bundle_dir=""
bundle_tar=""
bundle_tar_sha256_file=""
check_tar_sha256="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_CHECK_TAR_SHA256:-1}"
check_manifest="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_CHECK_MANIFEST:-1}"
show_details="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SHOW_DETAILS:-0}"
bundle_tar_explicit=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --bundle-dir)
      bundle_dir="${2:-}"
      shift 2
      ;;
    --bundle-tar)
      bundle_tar="${2:-}"
      bundle_tar_explicit=1
      shift 2
      ;;
    --bundle-tar-sha256-file)
      bundle_tar_sha256_file="${2:-}"
      shift 2
      ;;
    --check-tar-sha256)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        check_tar_sha256="${2:-}"
        shift 2
      else
        check_tar_sha256="1"
        shift
      fi
      ;;
    --check-manifest)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        check_manifest="${2:-}"
        shift 2
      else
        check_manifest="1"
        shift
      fi
      ;;
    --show-details)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        show_details="${2:-}"
        shift 2
      else
        show_details="1"
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

for cmd in bash basename dirname find grep head jq mktemp sed sort tar tr; do
  need_cmd "$cmd"
done
detect_sha256_tool
bool_or_die "--check-tar-sha256" "$check_tar_sha256"
bool_or_die "--check-manifest" "$check_manifest"
bool_or_die "--show-details" "$show_details"

summary_json="$(abs_path "$summary_json")"
bundle_dir="$(abs_path "$bundle_dir")"
bundle_tar="$(abs_path "$bundle_tar")"
bundle_tar_sha256_file="$(abs_path "$bundle_tar_sha256_file")"

if [[ -n "$summary_json" ]]; then
  if [[ ! -f "$summary_json" ]]; then
    echo "summary JSON not found: $summary_json"
    exit 1
  fi
  if [[ -z "$bundle_dir" ]]; then
    bundle_dir="$(abs_path "$(json_string "$summary_json" '.artifacts.bundle_dir')")"
  fi
  if [[ -z "$bundle_tar" ]]; then
    bundle_tar="$(abs_path "$(json_string "$summary_json" '.artifacts.bundle_tar')")"
  fi
  if [[ -z "$bundle_tar_sha256_file" ]]; then
    bundle_tar_sha256_file="$(abs_path "$(json_string "$summary_json" '.artifacts.bundle_tar_sha256_file')")"
  fi
fi

if [[ -z "$bundle_tar" && -n "$bundle_dir" && -f "${bundle_dir}.tar.gz" ]]; then
  bundle_tar="${bundle_dir}.tar.gz"
fi
if [[ -z "$bundle_tar_sha256_file" && -n "$bundle_tar" ]]; then
  bundle_tar_sha256_file="${bundle_tar}.sha256"
fi

if [[ -z "$summary_json" && -z "$bundle_dir" && -z "$bundle_tar" ]]; then
  echo "missing required input: provide --summary-json, --bundle-dir, and/or --bundle-tar"
  exit 2
fi
if [[ "$check_tar_sha256" == "0" && "$check_manifest" == "0" ]]; then
  echo "no checks enabled (set --check-tar-sha256=1 and/or --check-manifest=1)"
  exit 2
fi

tmp_extract_dir=""
cleanup() {
  if [[ -n "$tmp_extract_dir" && -d "$tmp_extract_dir" ]]; then
    rm -rf "$tmp_extract_dir"
  fi
}
trap cleanup EXIT

issues=0

if [[ -n "$bundle_dir" && ! -d "$bundle_dir" ]]; then
  echo "bundle dir not found: $bundle_dir"
  issues=$((issues + 1))
fi

if [[ -n "$bundle_tar" ]]; then
  if [[ ! -f "$bundle_tar" ]]; then
    echo "bundle tar not found: $bundle_tar"
    issues=$((issues + 1))
  elif ! validate_tar_members_safe "$bundle_tar"; then
    echo "refusing unsafe bundle tar: $bundle_tar"
    issues=$((issues + 1))
  elif [[ "$show_details" == "1" ]]; then
    echo "bundle tar members safe: $bundle_tar"
  fi
elif [[ "$bundle_tar_explicit" == "1" || "$check_tar_sha256" == "1" ]]; then
  echo "tarball checksum check requested but bundle tar is not resolved"
  issues=$((issues + 1))
fi

if [[ "$check_tar_sha256" == "1" && -n "$bundle_tar" && -f "$bundle_tar" ]]; then
  if [[ -z "$bundle_tar_sha256_file" || ! -f "$bundle_tar_sha256_file" ]]; then
    echo "bundle tar checksum sidecar not found: $bundle_tar_sha256_file"
    issues=$((issues + 1))
  else
    line="$(head -n1 "$bundle_tar_sha256_file" || true)"
    if [[ "$line" =~ ^([A-Fa-f0-9]{64})[[:space:]][[:space:]](.+)$ ]]; then
      expected="${BASH_REMATCH[1],,}"
      actual="$(sha256_value "$bundle_tar")"
      if [[ "$actual" != "$expected" ]]; then
        echo "bundle tar checksum mismatch: expected=$expected actual=$actual"
        issues=$((issues + 1))
      elif [[ "$show_details" == "1" ]]; then
        echo "bundle tar checksum ok: $bundle_tar"
      fi
    else
      echo "invalid bundle tar checksum sidecar format: $bundle_tar_sha256_file"
      issues=$((issues + 1))
    fi
  fi
fi

manifest_bundle_dir="$bundle_dir"
if [[ "$check_manifest" == "1" && ( -z "$manifest_bundle_dir" || ! -d "$manifest_bundle_dir" ) && -n "$bundle_tar" && -f "$bundle_tar" ]]; then
  if validate_tar_members_safe "$bundle_tar"; then
    tmp_extract_dir="$(mktemp -d)"
    if ! tar -xzf "$bundle_tar" -C "$tmp_extract_dir"; then
      echo "failed to extract bundle tar for manifest validation: $bundle_tar"
      issues=$((issues + 1))
    else
      extracted_dir=""
      while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        if [[ -z "$extracted_dir" ]]; then
          extracted_dir="$d"
        else
          extracted_dir=""
          break
        fi
      done < <(find "$tmp_extract_dir" -mindepth 1 -maxdepth 1 -type d | LC_ALL=C sort)
      if [[ -z "$extracted_dir" ]]; then
        echo "could not determine extracted bundle directory in: $tmp_extract_dir"
        issues=$((issues + 1))
      else
        manifest_bundle_dir="$extracted_dir"
      fi
    fi
  fi
fi

if [[ "$check_manifest" == "1" && -n "$manifest_bundle_dir" && -d "$manifest_bundle_dir" ]]; then
  manifest_file="$manifest_bundle_dir/manifest.sha256"
  if [[ ! -f "$manifest_file" ]]; then
    echo "manifest not found: $manifest_file"
    issues=$((issues + 1))
  else
    declare -A manifest_seen=()
    manifest_count=0
    while IFS= read -r link_path; do
      [[ -n "$link_path" ]] || continue
      echo "unsafe bundle dir link member: ${link_path#$manifest_bundle_dir/}"
      issues=$((issues + 1))
    done < <(find "$manifest_bundle_dir" -type l -print)

    while IFS= read -r line || [[ -n "$line" ]]; do
      [[ -z "$line" ]] && continue
      if [[ "$line" =~ ^([A-Fa-f0-9]{64})[[:space:]][[:space:]](.+)$ ]]; then
        expected="${BASH_REMATCH[1],,}"
        rel_path="${BASH_REMATCH[2]}"
        if ! rel_path_is_safe "$rel_path" || [[ "$rel_path" == "manifest.sha256" ]]; then
          echo "unsafe manifest entry path: $rel_path"
          issues=$((issues + 1))
          continue
        fi
        if [[ -n "${manifest_seen[$rel_path]+x}" ]]; then
          echo "duplicate manifest entry: $rel_path"
          issues=$((issues + 1))
          continue
        fi
        manifest_seen["$rel_path"]=1
        manifest_count=$((manifest_count + 1))
        file_path="$manifest_bundle_dir/$rel_path"
        if [[ -L "$file_path" ]]; then
          echo "manifest entry is a link: $rel_path"
          issues=$((issues + 1))
          continue
        fi
        if [[ ! -f "$file_path" ]]; then
          echo "manifest entry missing file: $rel_path"
          issues=$((issues + 1))
          continue
        fi
        actual="$(sha256_value "$file_path")"
        if [[ "$actual" != "$expected" ]]; then
          echo "manifest checksum mismatch: $rel_path expected=$expected actual=$actual"
          issues=$((issues + 1))
        elif [[ "$show_details" == "1" ]]; then
          echo "manifest checksum ok: $rel_path"
        fi
      else
        echo "invalid manifest line format: $line"
        issues=$((issues + 1))
      fi
    done <"$manifest_file"

    if ((manifest_count == 0)); then
      echo "manifest has no entries: $manifest_file"
      issues=$((issues + 1))
    fi

    while IFS= read -r file_path; do
      [[ -n "$file_path" ]] || continue
      rel_path="${file_path#$manifest_bundle_dir/}"
      [[ "$rel_path" != "manifest.sha256" ]] || continue
      if [[ -z "${manifest_seen[$rel_path]+x}" ]]; then
        echo "bundle file missing from manifest: $rel_path"
        issues=$((issues + 1))
      fi
    done < <(find "$manifest_bundle_dir" -type f -print | LC_ALL=C sort)
  fi
elif [[ "$check_manifest" == "1" ]]; then
  echo "manifest check requested but bundle dir is not resolved"
  issues=$((issues + 1))
fi

if ((issues > 0)); then
  echo "[access-bridge-pilot-evidence-bundle-verify] failed (issues=$issues)"
  exit 1
fi

echo "[access-bridge-pilot-evidence-bundle-verify] ok"
if [[ -n "$summary_json" ]]; then
  echo "[access-bridge-pilot-evidence-bundle-verify] summary_json=$summary_json"
fi
if [[ -n "$manifest_bundle_dir" ]]; then
  echo "[access-bridge-pilot-evidence-bundle-verify] bundle_dir=$manifest_bundle_dir"
fi
if [[ -n "$bundle_tar" ]]; then
  echo "[access-bridge-pilot-evidence-bundle-verify] bundle_tar=$bundle_tar"
fi
