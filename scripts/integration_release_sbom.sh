#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in jq rg; do
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
./scripts/release_generate_sbom.sh --version not-a-version --out-dir "$TMP_DIR/out_bad" \
  >/tmp/integration_release_sbom_bad_version.log 2>&1
bad_rc=$?
set -e
if [[ "$bad_rc" -eq 0 ]]; then
  echo "expected release_generate_sbom to fail on invalid version"
  cat /tmp/integration_release_sbom_bad_version.log
  exit 1
fi
if ! rg -q "must match semver-like tag format" /tmp/integration_release_sbom_bad_version.log; then
  echo "missing expected invalid-version failure signal for sbom generation"
  cat /tmp/integration_release_sbom_bad_version.log
  exit 1
fi

version="v0.0.0-sbom"
out_root="$TMP_DIR/out_ok"
./scripts/release_generate_sbom.sh --version "$version" --out-dir "$out_root" \
  >/tmp/integration_release_sbom_ok.log 2>&1

sbom_path="${out_root}/${version}/sbom_go_modules_${version}.json"
if [[ ! -f "$sbom_path" ]]; then
  echo "missing expected sbom output file: $sbom_path"
  cat /tmp/integration_release_sbom_ok.log
  exit 1
fi

if [[ "$(jq -r '.schema' "$sbom_path")" != "tdpn-go-module-inventory/v1" ]]; then
  echo "sbom schema mismatch"
  cat "$sbom_path"
  exit 1
fi
if [[ "$(jq -r '.release_version' "$sbom_path")" != "$version" ]]; then
  echo "sbom release version mismatch"
  cat "$sbom_path"
  exit 1
fi
if [[ "$(jq -r '.module_count' "$sbom_path")" == "0" ]]; then
  echo "sbom module_count is zero"
  cat "$sbom_path"
  exit 1
fi
if [[ -z "$(jq -r '.root_module.path // empty' "$sbom_path")" ]]; then
  echo "sbom root module path missing"
  cat "$sbom_path"
  exit 1
fi
if ! jq -e '.modules[] | select(.main == true)' "$sbom_path" >/dev/null; then
  echo "sbom does not include a main module entry"
  cat "$sbom_path"
  exit 1
fi

echo "release sbom integration check ok"
