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

sha256_hash_file() {
  local file="$1"
  local line
  if command -v sha256sum >/dev/null 2>&1; then
    line="$(sha256sum "$file")"
  else
    line="$(shasum -a 256 "$file")"
  fi
  printf '%s\n' "${line%% *}"
}

sha256_hash_git_archive() {
  local commit="$1"
  local prefix="$2"
  local line
  if command -v sha256sum >/dev/null 2>&1; then
    line="$(git archive --format=tar --prefix="$prefix" "$commit" | sha256sum)"
  else
    line="$(git archive --format=tar --prefix="$prefix" "$commit" | shasum -a 256)"
  fi
  printf '%s\n' "${line%% *}"
}

resolve_existing_path() {
  local path="$1"
  local dir
  local base

  if [[ ! -e "$path" ]]; then
    return 1
  fi
  if [[ -L "$path" ]]; then
    return 2
  fi

  dir="$(cd "$(dirname "$path")" && pwd -P)" || return 1
  base="$(basename "$path")"
  printf '%s/%s\n' "$dir" "$base"
}

version=""
release_dir=""
require_tag_exists=0
require_tag_notes=0
min_binaries=1
checksum_verify_log=""
tmp_cleanup_paths=()

cleanup_tmp_files() {
  local path
  for path in "${tmp_cleanup_paths[@]:-}"; do
    [[ -n "$path" ]] && rm -f "$path"
  done
}
trap cleanup_tmp_files EXIT

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

if [[ ! -d "$release_dir" ]]; then
  echo "missing expected release directory: $release_dir"
  exit 1
fi
release_dir_abs="$(cd "$release_dir" && pwd -P)"

manifest_path="${release_dir_abs}/manifest.json"
checksum_path="${release_dir_abs}/sha256sums.txt"
source_tar_path="${release_dir_abs}/source_${version}.tar"
sbom_path="${release_dir_abs}/sbom_go_modules_${version}.json"
bin_dir="${release_dir_abs}/bin"

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
if [[ -n "$(find "$release_dir_abs" -type l -print -quit)" ]]; then
  echo "release directory contains symlinks; refusing non-canonical artifact paths"
  find "$release_dir_abs" -type l -print
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
manifest_commit="$(jq -r '.commit // empty' "$manifest_path")"
if [[ -z "$manifest_commit" ]]; then
  echo "manifest commit missing in ${manifest_path}"
  cat "$manifest_path"
  exit 1
fi
if [[ ! "$manifest_commit" =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "manifest commit is not a full git SHA in ${manifest_path}: ${manifest_commit}"
  cat "$manifest_path"
  exit 1
fi
if ! git cat-file -e "${manifest_commit}^{commit}" >/dev/null 2>&1; then
  echo "manifest commit is not present in this repository: ${manifest_commit}"
  exit 1
fi
if [[ "$(jq -r '.targets | length' "$manifest_path")" == "0" ]]; then
  echo "manifest targets are empty in ${manifest_path}"
  cat "$manifest_path"
  exit 1
fi
manifest_target_count="$(jq -r '.targets | length' "$manifest_path")"
if [[ "$manifest_target_count" != "${#bin_files[@]}" ]]; then
  echo "manifest target count does not match release binaries: targets=${manifest_target_count} binaries=${#bin_files[@]}"
  cat "$manifest_path"
  printf '%s\n' "${bin_files[@]}"
  exit 1
fi

while IFS= read -r target; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext=""
  if [[ "$goos" == "windows" ]]; then
    ext=".exe"
  fi
  expected_bin="${bin_dir}/node_${goos}_${goarch}${ext}"
  if [[ ! -f "$expected_bin" ]]; then
    echo "manifest target missing expected binary: target=${target} expected=${expected_bin}"
    exit 1
  fi
done < <(jq -r '.targets[]' "$manifest_path")

if ! jq -e --arg version "$version" --arg commit "$manifest_commit" '
  .schema == "tdpn-go-module-inventory/v1"
  and .release_version == $version
  and .commit == $commit
  and ((.module_count // 0) > 0)
  and ((.root_module.path // "") | length > 0)
  and ((.modules // []) | any(.main == true))
' "$sbom_path" >/dev/null; then
  echo "sbom release metadata mismatch in ${sbom_path}"
  cat "$sbom_path"
  exit 1
fi

source_actual_hash="$(sha256_hash_file "$source_tar_path")"
source_expected_hash="$(sha256_hash_git_archive "$manifest_commit" "tdpn-${version}/")"
if [[ "$source_actual_hash" != "$source_expected_hash" ]]; then
  echo "source tar does not match manifest commit: source=${source_tar_path} commit=${manifest_commit}"
  exit 1
fi

checksum_paths_tmp="$(mktemp "${TMPDIR:-/tmp}/release_policy_gate_checksum_paths.XXXXXX")"
tmp_cleanup_paths+=("$checksum_paths_tmp")

while IFS= read -r checksum_line || [[ -n "$checksum_line" ]]; do
  [[ -n "$checksum_line" ]] || continue
  if [[ ! "$checksum_line" =~ ^[0-9a-fA-F]{64}[[:space:]]+\*?(.+)$ ]]; then
    echo "malformed checksum entry in ${checksum_path}: ${checksum_line}"
    exit 1
  fi
  entry_path="${BASH_REMATCH[1]}"
  if [[ -z "$entry_path" ]]; then
    echo "checksum entry has an empty path in ${checksum_path}"
    exit 1
  fi
  entry_resolve_path="$entry_path"
  if [[ "$entry_resolve_path" != /* ]]; then
    entry_resolve_path="${release_dir_abs}/${entry_resolve_path}"
  fi
  if entry_abs="$(resolve_existing_path "$entry_resolve_path")"; then
    :
  else
    resolve_rc=$?
    if [[ "$resolve_rc" == "2" ]]; then
      echo "checksum file references symlinked artifact path: ${entry_path}"
    else
      echo "checksum file references missing artifact path: ${entry_path}"
    fi
    exit 1
  fi
  case "$entry_abs" in
    "$release_dir_abs"/*) ;;
    *)
      echo "checksum file references path outside release directory: ${entry_path}"
      exit 1
      ;;
  esac
  if rg -Fxq "$entry_abs" "$checksum_paths_tmp"; then
    echo "checksum file contains duplicate artifact path: ${entry_path}"
    exit 1
  fi
  printf '%s\n' "$entry_abs" >>"$checksum_paths_tmp"
done <"$checksum_path"

check_checksum_contains_path() {
  local expected="$1"
  local expected_abs
  if ! expected_abs="$(resolve_existing_path "$expected")"; then
    echo "expected checksum artifact is missing or unsafe: ${expected}"
    exit 1
  fi
  if ! rg -Fxq "$expected_abs" "$checksum_paths_tmp"; then
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

while IFS= read -r release_file; do
  if [[ "$release_file" == "$checksum_path" ]]; then
    continue
  fi
  release_file_abs="$(resolve_existing_path "$release_file")"
  if ! rg -Fxq "$release_file_abs" "$checksum_paths_tmp"; then
    echo "release file is not listed in checksum manifest: ${release_file}"
    exit 1
  fi
done < <(find "$release_dir_abs" -type f | sort)

if command -v sha256sum >/dev/null 2>&1; then
  checksum_verify_log="$(mktemp "${TMPDIR:-/tmp}/release_policy_gate_checksums.XXXXXX.log")"
  tmp_cleanup_paths+=("$checksum_verify_log")
  if ! (cd "$release_dir_abs" && sha256sum -c "$checksum_path") >"$checksum_verify_log" 2>&1; then
    echo "checksum verification failed (sha256sum -c)"
    cat "$checksum_verify_log"
    exit 1
  fi
else
  checksum_verify_log="$(mktemp "${TMPDIR:-/tmp}/release_policy_gate_checksums.XXXXXX.log")"
  tmp_cleanup_paths+=("$checksum_verify_log")
  if ! (cd "$release_dir_abs" && shasum -a 256 -c "$checksum_path") >"$checksum_verify_log" 2>&1; then
    echo "checksum verification failed (shasum -a 256 -c)"
    cat "$checksum_verify_log"
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
  tag_commit="$(git rev-list -n 1 "$version")"
  if [[ "$tag_commit" != "$manifest_commit" ]]; then
    echo "manifest commit does not match release tag: manifest=${manifest_commit} tag=${tag_commit}"
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
