#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/release_prepare.sh --version vX.Y.Z [--out-dir dist] [--targets csv] [--allow-dirty 0|1] [--require-tag-match 0|1] [--include-sbom 0|1]

Examples:
  ./scripts/release_prepare.sh --version v0.1.0
  ./scripts/release_prepare.sh --version v0.1.0-rc1 --targets linux/amd64,linux/arm64 --allow-dirty 1

Notes:
  - Builds release binaries for the selected GOOS/GOARCH targets.
  - Produces source tarball, manifest, and sha256 checksum file.
  - Defaults:
      out-dir: dist
      targets: linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64
      allow-dirty: 0
      require-tag-match: 0
      include-sbom: 1
USAGE
}

require_cmds() {
  local cmd
  for cmd in git go jq; do
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

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file"
  else
    shasum -a 256 "$file"
  fi
}

version=""
out_dir="$ROOT_DIR/dist"
targets_csv="linux/amd64,linux/arm64,darwin/amd64,darwin/arm64,windows/amd64"
allow_dirty=0
require_tag_match=0
include_sbom=1

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --out-dir)
      out_dir="${2:-}"
      shift 2
      ;;
    --targets)
      targets_csv="${2:-}"
      shift 2
      ;;
    --allow-dirty)
      allow_dirty="${2:-}"
      shift 2
      ;;
    --require-tag-match)
      require_tag_match="${2:-}"
      shift 2
      ;;
    --include-sbom)
      include_sbom="${2:-}"
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
if [[ "$allow_dirty" != "0" && "$allow_dirty" != "1" ]]; then
  echo "--allow-dirty must be 0 or 1"
  exit 1
fi
if [[ "$require_tag_match" != "0" && "$require_tag_match" != "1" ]]; then
  echo "--require-tag-match must be 0 or 1"
  exit 1
fi
if [[ "$include_sbom" != "0" && "$include_sbom" != "1" ]]; then
  echo "--include-sbom must be 0 or 1"
  exit 1
fi

require_cmds

if [[ "$allow_dirty" == "0" ]]; then
  if ! git diff --quiet || ! git diff --cached --quiet; then
    echo "working tree is dirty; commit or stash changes (or use --allow-dirty 1)"
    exit 1
  fi
fi

commit="$(git rev-parse HEAD)"
tag_exists=0
tag_commit=""
if git rev-parse "${version}^{tag}" >/dev/null 2>&1; then
  tag_exists=1
  tag_commit="$(git rev-list -n 1 "$version")"
fi
if [[ "$require_tag_match" == "1" ]]; then
  if [[ "$tag_exists" != "1" ]]; then
    echo "required tag not found locally: $version"
    exit 1
  fi
  if [[ "$tag_commit" != "$commit" ]]; then
    echo "tag ${version} points to ${tag_commit}, current HEAD is ${commit}"
    exit 1
  fi
fi

IFS=',' read -r -a targets_raw <<<"$targets_csv"
targets=()
for target in "${targets_raw[@]}"; do
  t="${target//[[:space:]]/}"
  [[ -n "$t" ]] || continue
  if [[ ! "$t" =~ ^[a-z0-9]+/[a-z0-9_]+$ ]]; then
    echo "invalid target format: $t (expected os/arch)"
    exit 1
  fi
  targets+=("$t")
done
if [[ "${#targets[@]}" -eq 0 ]]; then
  echo "no valid targets configured"
  exit 1
fi

release_dir="${out_dir%/}/${version}"
bin_dir="${release_dir}/bin"
rm -rf "$release_dir"
mkdir -p "$bin_dir"

echo "[release-prepare] version=${version} commit=${commit}"
echo "[release-prepare] output=${release_dir}"
echo "[release-prepare] targets=$(IFS=,; echo "${targets[*]}")"

source_tar="${release_dir}/source_${version}.tar"
git archive --format=tar --prefix="tdpn-${version}/" "$commit" >"$source_tar"

for target in "${targets[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  ext=""
  if [[ "$goos" == "windows" ]]; then
    ext=".exe"
  fi
  out_bin="${bin_dir}/node_${goos}_${goarch}${ext}"
  echo "[release-prepare] building ${goos}/${goarch} -> ${out_bin}"
  GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=0 go build -trimpath -o "$out_bin" ./cmd/node
done

targets_json="$(printf '%s\n' "${targets[@]}" | jq -R . | jq -s .)"
generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
jq -n \
  --arg version "$version" \
  --arg commit "$commit" \
  --arg generated_at "$generated_at" \
  --argjson tag_exists "$tag_exists" \
  --arg tag_commit "$tag_commit" \
  --argjson targets "$targets_json" \
  '{
    version: $version,
    commit: $commit,
    generated_at_utc: $generated_at,
    tag_exists: ($tag_exists == 1),
    tag_commit: (if $tag_commit == "" then null else $tag_commit end),
    targets: $targets
  }' >"${release_dir}/manifest.json"

sbom_path=""
if [[ "$include_sbom" == "1" ]]; then
  ./scripts/release_generate_sbom.sh --version "$version" --out-dir "$out_dir"
  sbom_path="${release_dir}/sbom_go_modules_${version}.json"
fi

checksum_file="${release_dir}/sha256sums.txt"
{
  sha256_file "$source_tar"
  while IFS= read -r file; do
    sha256_file "$file"
  done < <(find "$bin_dir" -type f | sort)
  sha256_file "${release_dir}/manifest.json"
  if [[ -n "$sbom_path" ]]; then
    sha256_file "$sbom_path"
  fi
} >"$checksum_file"

echo "[release-prepare] wrote:"
echo "  ${source_tar}"
echo "  ${release_dir}/manifest.json"
if [[ -n "$sbom_path" ]]; then
  echo "  ${sbom_path}"
fi
echo "  ${checksum_file}"
echo "[release-prepare] ok"
