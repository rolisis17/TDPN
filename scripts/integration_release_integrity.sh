#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg jq; do
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

set +e
./scripts/release_prepare.sh --version bad-version --targets linux/amd64 --out-dir "$TMP_DIR/dist_bad" --allow-dirty 1 \
  >/tmp/integration_release_integrity_bad_version.log 2>&1
bad_rc=$?
set -e
if [[ "$bad_rc" -eq 0 ]]; then
  echo "expected release_prepare to fail on invalid version format"
  cat /tmp/integration_release_integrity_bad_version.log
  exit 1
fi
if ! rg -q "must match semver-like tag format" /tmp/integration_release_integrity_bad_version.log; then
  echo "missing expected invalid-version failure signal"
  cat /tmp/integration_release_integrity_bad_version.log
  exit 1
fi

version="v0.0.0-test"
out_root="$TMP_DIR/dist_ok"
./scripts/release_prepare.sh --version "$version" --targets linux/amd64 --out-dir "$out_root" --allow-dirty 1 \
  >/tmp/integration_release_integrity_ok.log 2>&1

release_dir="${out_root}/${version}"
bin_path="${release_dir}/bin/node_linux_amd64"
manifest_path="${release_dir}/manifest.json"
checksums_path="${release_dir}/sha256sums.txt"
source_tar="${release_dir}/source_${version}.tar"

for path in "$bin_path" "$manifest_path" "$checksums_path" "$source_tar"; do
  if [[ ! -f "$path" ]]; then
    echo "missing expected release artifact: $path"
    cat /tmp/integration_release_integrity_ok.log
    exit 1
  fi
done

if [[ ! -s "$bin_path" ]]; then
  echo "built binary is empty: $bin_path"
  exit 1
fi

if [[ "$(jq -r '.version' "$manifest_path")" != "$version" ]]; then
  echo "manifest version mismatch"
  cat "$manifest_path"
  exit 1
fi
if [[ "$(jq -r '.targets | length' "$manifest_path")" != "1" ]]; then
  echo "manifest targets length mismatch"
  cat "$manifest_path"
  exit 1
fi
if [[ "$(jq -r '.targets[0]' "$manifest_path")" != "linux/amd64" ]]; then
  echo "manifest target mismatch"
  cat "$manifest_path"
  exit 1
fi

if ! rg -q "node_linux_amd64" "$checksums_path"; then
  echo "checksum file missing binary entry"
  cat "$checksums_path"
  exit 1
fi
if ! rg -q "manifest.json" "$checksums_path"; then
  echo "checksum file missing manifest entry"
  cat "$checksums_path"
  exit 1
fi
if ! rg -q "source_${version}.tar" "$checksums_path"; then
  echo "checksum file missing source tar entry"
  cat "$checksums_path"
  exit 1
fi

echo "release integrity integration check ok"
