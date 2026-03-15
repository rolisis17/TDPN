#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg git; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

uniq_suffix="$(date +%s%N)"
version="v0.0.0-policy-${uniq_suffix}"
tmp_dir="$(mktemp -d)"
release_root="${tmp_dir}/dist"
release_dir="${release_root}/${version}"

cleanup() {
  git tag -d "$version" >/dev/null 2>&1 || true
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

git_tag_annotated() {
  local tag_name="$1"
  local tag_message="$2"
  local tag_target="${3:-HEAD}"
  # Keep integration hermetic: do not depend on user git config.
  git -c user.name='integration-bot' -c user.email='integration-bot@example.invalid' \
    tag -a "$tag_name" -m "$tag_message" "$tag_target" >/dev/null
}

./scripts/release_prepare.sh --version "$version" --targets linux/amd64 --out-dir "$release_root" --allow-dirty 1 \
  >/tmp/integration_release_policy_gate_prepare.log 2>&1

./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" \
  >/tmp/integration_release_policy_gate_ok.log 2>&1

rm -f "${release_dir}/sbom_go_modules_${version}.json"
set +e
./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" \
  >/tmp/integration_release_policy_gate_missing_sbom.log 2>&1
missing_sbom_rc=$?
set -e
if [[ "$missing_sbom_rc" -eq 0 ]]; then
  echo "expected release policy gate to fail when sbom artifact is missing"
  cat /tmp/integration_release_policy_gate_missing_sbom.log
  exit 1
fi
if ! rg -q "missing expected release artifact" /tmp/integration_release_policy_gate_missing_sbom.log; then
  echo "missing expected missing-artifact failure signal"
  cat /tmp/integration_release_policy_gate_missing_sbom.log
  exit 1
fi

./scripts/release_prepare.sh --version "$version" --targets linux/amd64 --out-dir "$release_root" --allow-dirty 1 \
  >/tmp/integration_release_policy_gate_prepare2.log 2>&1

checksum_file="${release_dir}/sha256sums.txt"
awk 'NR==1{$1="0000000000000000000000000000000000000000000000000000000000000000"} {print}' "$checksum_file" >"${checksum_file}.tmp"
mv "${checksum_file}.tmp" "$checksum_file"

set +e
./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" \
  >/tmp/integration_release_policy_gate_checksum_fail.log 2>&1
checksum_fail_rc=$?
set -e
if [[ "$checksum_fail_rc" -eq 0 ]]; then
  echo "expected release policy gate to fail when checksums are tampered"
  cat /tmp/integration_release_policy_gate_checksum_fail.log
  exit 1
fi
if ! rg -q "checksum verification failed" /tmp/integration_release_policy_gate_checksum_fail.log; then
  echo "missing expected checksum failure signal"
  cat /tmp/integration_release_policy_gate_checksum_fail.log
  exit 1
fi

./scripts/release_prepare.sh --version "$version" --targets linux/amd64 --out-dir "$release_root" --allow-dirty 1 \
  >/tmp/integration_release_policy_gate_prepare3.log 2>&1

git_tag_annotated "$version" "release ${version}" HEAD

set +e
./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" --require-tag-exists 1 --require-tag-notes 1 \
  >/tmp/integration_release_policy_gate_notes_fail.log 2>&1
notes_fail_rc=$?
set -e
if [[ "$notes_fail_rc" -eq 0 ]]; then
  echo "expected release policy gate to fail when tag notes are incomplete"
  cat /tmp/integration_release_policy_gate_notes_fail.log
  exit 1
fi
if ! rg -q "tag annotation missing required release note sections" /tmp/integration_release_policy_gate_notes_fail.log; then
  echo "missing expected tag notes failure signal"
  cat /tmp/integration_release_policy_gate_notes_fail.log
  exit 1
fi

git tag -d "$version" >/dev/null
git_tag_annotated "$version" "Known limitations
- integration test

Security model
- integration test

Supported environments
- integration test" HEAD

./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" --require-tag-exists 1 --require-tag-notes 1 \
  >/tmp/integration_release_policy_gate_notes_ok.log 2>&1

if ! rg -q "\\[release-policy-gate\\] ok" /tmp/integration_release_policy_gate_notes_ok.log; then
  echo "expected release policy gate success signal with valid tag notes"
  cat /tmp/integration_release_policy_gate_notes_ok.log
  exit 1
fi

echo "release policy gate integration check ok"
