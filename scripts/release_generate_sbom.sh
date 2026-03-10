#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/release_generate_sbom.sh --version vX.Y.Z [--out-dir dist]

Examples:
  ./scripts/release_generate_sbom.sh --version v0.1.0
  ./scripts/release_generate_sbom.sh --version v0.1.0 --out-dir dist

Notes:
  - Generates a Go module dependency inventory JSON for release artifacts.
  - Output path: <out-dir>/<version>/sbom_go_modules_<version>.json
USAGE
}

require_cmds() {
  local cmd
  for cmd in go jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "missing required command: $cmd"
      exit 2
    fi
  done
}

version=""
out_dir="$ROOT_DIR/dist"

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

require_cmds

release_dir="${out_dir%/}/${version}"
mkdir -p "$release_dir"

sbom_path="${release_dir}/sbom_go_modules_${version}.json"
modules_tmp="$(mktemp)"
trap 'rm -f "$modules_tmp"' EXIT

go list -m -json all >"$modules_tmp"
if [[ ! -s "$modules_tmp" ]]; then
  echo "go module list is empty"
  exit 1
fi

generated_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
commit="$(git rev-parse HEAD 2>/dev/null || true)"

jq -s \
  --arg schema "tdpn-go-module-inventory/v1" \
  --arg version "$version" \
  --arg generated_at "$generated_at" \
  --arg commit "$commit" \
  '
  {
    schema: $schema,
    release_version: $version,
    generated_at_utc: $generated_at,
    commit: (if $commit == "" then null else $commit end),
    root_module: (
      map(select(.Main == true)) | .[0] | {
        path: .Path,
        version: (.Version // null)
      }
    ),
    module_count: (length),
    modules: (
      map({
        path: .Path,
        version: (.Version // null),
        main: (.Main // false),
        indirect: (.Indirect // false),
        replacement: (
          if .Replace then
            {
              path: .Replace.Path,
              version: (.Replace.Version // null)
            }
          else
            null
          end
        )
      })
    )
  }
  ' "$modules_tmp" >"$sbom_path"

echo "[release-sbom] wrote ${sbom_path}"
echo "[release-sbom] ok"
