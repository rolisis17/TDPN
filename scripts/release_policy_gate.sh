#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/release_policy_gate.sh --version vX.Y.Z [--release-dir dist/vX.Y.Z] [--require-tag-exists 0|1] [--require-tag-notes 0|1] [--min-binaries N]

Examples:
  ./scripts/release_policy_gate.sh --version v0.1.0 --release-dir dist/v0.1.0
  ./scripts/release_policy_gate.sh --version v0.1.0 --require-tag-exists 1 --require-tag-notes 1

Notes:
  - Verifies release artifact completeness and checksum integrity.
  - Optionally enforces annotated release tag existence and release-note sections.
USAGE
}

require_cmds() {
  local cmd
  for cmd in rg jq git; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "missing required command: $cmd"
      exit 2
    fi
  done
  if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
    echo "missing required command: sha256sum (or shasum)"
    exit 2
  fi
}

version=""
release_dir=""
require_tag_exists=0
require_tag_notes=0
min_binaries=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --release-dir)
      release_dir="${2:-}"
      shift 2
      ;;
    --require-tag-exists)
      require_tag_exists="${2:-}"
      shift 2
      ;;
    --require-tag-notes)
      require_tag_notes="${2:-}"
      shift 2
      ;;
    --min-binaries)
      min_binaries="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ -z "$version" ]]; then
  echo "--version is required"
  usage
  exit 1
fi
if [[ ! "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][0-9A-Za-z.-]+)?$ ]]; then
  echo "--version must match semver-like tag format (e.g. v1.2.3 or v1.2.3-rc1)"
  exit 1
fi
if [[ -z "$release_dir" ]]; then
  release_dir="dist/${version}"
fi
if [[ "$require_tag_exists" != "0" && "$require_tag_exists" != "1" ]]; then
  echo "--require-tag-exists must be 0 or 1"
  exit 1
fi
if [[ "$require_tag_notes" != "0" && "$require_tag_notes" != "1" ]]; then
  echo "--require-tag-notes must be 0 or 1"
  exit 1
fi
if [[ ! "$min_binaries" =~ ^[0-9]+$ || "$min_binaries" -lt 1 ]]; then
  echo "--min-binaries must be an integer >= 1"
  exit 1
fi

require_cmds

manifest_path="${release_dir}/manifest.json"
checksum_path="${release_dir}/sha256sums.txt"
source_tar_path="${release_dir}/source_${version}.tar"
sbom_path="${release_dir}/sbom_go_modules_${version}.json"
bin_dir="${release_dir}/bin"

for path in "$manifest_path" "$checksum_path" "$source_tar_path" "$sbom_path"; do
  if [[ ! -f "$path" ]]; then
    echo "missing expected release artifact: $path"
    exit 1
  fi
done
if [[ ! -d "$bin_dir" ]]; then
  echo "missing expected bin directory: $bin_dir"
  exit 1
fi

mapfile -t bin_files < <(find "$bin_dir" -type f | sort)
if (( "${#bin_files[@]}" < min_binaries )); then
  echo "insufficient release binaries in ${bin_dir}: found=${#bin_files[@]} required=${min_binaries}"
  exit 1
fi

if [[ "$(jq -r '.version // empty' "$manifest_path")" != "$version" ]]; then
  echo "manifest version mismatch in ${manifest_path}"
  cat "$manifest_path"
  exit 1
fi
if [[ -z "$(jq -r '.commit // empty' "$manifest_path")" ]]; then
  echo "manifest commit missing in ${manifest_path}"
  cat "$manifest_path"
  exit 1
fi
if [[ "$(jq -r '.targets | length' "$manifest_path")" == "0" ]]; then
  echo "manifest targets are empty in ${manifest_path}"
  cat "$manifest_path"
  exit 1
fi

check_checksum_contains_path() {
  local expected="$1"
  if ! rg -q "[[:space:]]${expected}$" "$checksum_path"; then
    echo "checksum file missing expected path entry: ${expected}"
    cat "$checksum_path"
    exit 1
  fi
}

check_checksum_contains_path "$source_tar_path"
check_checksum_contains_path "$manifest_path"
check_checksum_contains_path "$sbom_path"
for bin_file in "${bin_files[@]}"; do
  check_checksum_contains_path "$bin_file"
done

if command -v sha256sum >/dev/null 2>&1; then
  if ! sha256sum -c "$checksum_path" >/tmp/release_policy_gate_checksums.log 2>&1; then
    echo "checksum verification failed (sha256sum -c)"
    cat /tmp/release_policy_gate_checksums.log
    exit 1
  fi
else
  if ! shasum -a 256 -c "$checksum_path" >/tmp/release_policy_gate_checksums.log 2>&1; then
    echo "checksum verification failed (shasum -a 256 -c)"
    cat /tmp/release_policy_gate_checksums.log
    exit 1
  fi
fi

if [[ "$require_tag_exists" == "1" || "$require_tag_notes" == "1" ]]; then
  if ! git rev-parse -q --verify "refs/tags/${version}" >/dev/null 2>&1; then
    echo "required release tag not found: ${version}"
    exit 1
  fi
  tag_type="$(git cat-file -t "refs/tags/${version}" 2>/dev/null || true)"
  if [[ "$tag_type" != "tag" ]]; then
    echo "release tag must be annotated for policy gate: ${version} (found type=${tag_type:-unknown})"
    exit 1
  fi
fi

if [[ "$require_tag_notes" == "1" ]]; then
  tag_notes="$(git for-each-ref "refs/tags/${version}" --format='%(contents)')"
  missing_sections=()
  for section in "Known limitations" "Security model" "Supported environments"; do
    if ! printf '%s\n' "$tag_notes" | rg -qi "^${section}\b"; then
      missing_sections+=("$section")
    fi
  done
  if (( "${#missing_sections[@]}" > 0 )); then
    echo "tag annotation missing required release note sections: ${missing_sections[*]}"
    echo "expected headings:"
    echo "  Known limitations"
    echo "  Security model"
    echo "  Supported environments"
    exit 1
  fi
fi

echo "[release-policy-gate] version=${version} release_dir=${release_dir} binaries=${#bin_files[@]} require_tag_exists=${require_tag_exists} require_tag_notes=${require_tag_notes}"
echo "[release-policy-gate] ok"
