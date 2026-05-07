#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg git jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done
if ! command -v sha256sum >/dev/null 2>&1 && ! command -v shasum >/dev/null 2>&1; then
  echo "missing required command: sha256sum (or shasum)"
  exit 2
fi

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

sha256_file() {
  local file="$1"
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$file"
  else
    shasum -a 256 "$file"
  fi
}

rewrite_release_checksums() {
  local dir="$1"
  local release_version="$2"
  {
    sha256_file "${dir}/source_${release_version}.tar"
    while IFS= read -r file; do
      sha256_file "$file"
    done < <(find "${dir}/bin" -type f | sort)
    sha256_file "${dir}/manifest.json"
    sha256_file "${dir}/sbom_go_modules_${release_version}.json"
  } >"${dir}/sha256sums.txt"
}

rewrite_release_checksums_relative() {
  local dir="$1"
  local release_version="$2"
  (
    cd "$dir"
    {
      sha256_file "source_${release_version}.tar"
      while IFS= read -r file; do
        sha256_file "$file"
      done < <(find bin -type f | sort)
      sha256_file "manifest.json"
      sha256_file "sbom_go_modules_${release_version}.json"
    } >"sha256sums.txt"
  )
}

./scripts/release_prepare.sh --version "$version" --targets linux/amd64 --out-dir "$release_root" --allow-dirty 1 \
  >/tmp/integration_release_policy_gate_prepare.log 2>&1

./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" \
  >/tmp/integration_release_policy_gate_ok.log 2>&1

checksum_file="${release_dir}/sha256sums.txt"
sbom_path="${release_dir}/sbom_go_modules_${version}.json"
checksum_clean="${tmp_dir}/sha256sums.clean.txt"
sbom_clean="${tmp_dir}/sbom.clean.json"
cp "$checksum_file" "$checksum_clean"
cp "$sbom_path" "$sbom_clean"

rewrite_release_checksums_relative "$release_dir" "$version"
./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" \
  >/tmp/integration_release_policy_gate_relative_checksums_ok.log 2>&1
cp "$checksum_clean" "$checksum_file"

printf '%s\n' 'unchecked release payload' >"${release_dir}/unchecked_payload.txt"
set +e
./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" \
  >/tmp/integration_release_policy_gate_unchecked_payload.log 2>&1
unchecked_payload_rc=$?
set -e
if [[ "$unchecked_payload_rc" -eq 0 ]]; then
  echo "expected release policy gate to fail when a release file is not checksummed"
  cat /tmp/integration_release_policy_gate_unchecked_payload.log
  exit 1
fi
if ! rg -q "release file is not listed in checksum manifest" /tmp/integration_release_policy_gate_unchecked_payload.log; then
  echo "missing expected unchecked-payload failure signal"
  cat /tmp/integration_release_policy_gate_unchecked_payload.log
  exit 1
fi
rm -f "${release_dir}/unchecked_payload.txt"

outside_checksum_target="${tmp_dir}/outside_checksum_target.txt"
printf '%s\n' 'outside release dir' >"$outside_checksum_target"
cp "$checksum_clean" "$checksum_file"
sha256_file "$outside_checksum_target" >>"$checksum_file"
set +e
./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" \
  >/tmp/integration_release_policy_gate_outside_checksum_path.log 2>&1
outside_checksum_path_rc=$?
set -e
if [[ "$outside_checksum_path_rc" -eq 0 ]]; then
  echo "expected release policy gate to fail when checksum manifest references an outside path"
  cat /tmp/integration_release_policy_gate_outside_checksum_path.log
  exit 1
fi
if ! rg -q "checksum file references path outside release directory" /tmp/integration_release_policy_gate_outside_checksum_path.log; then
  echo "missing expected outside-checksum-path failure signal"
  cat /tmp/integration_release_policy_gate_outside_checksum_path.log
  exit 1
fi
cp "$checksum_clean" "$checksum_file"

jq '.release_version = "v9.9.9-spoof"' "$sbom_path" >"${sbom_path}.tmp"
mv "${sbom_path}.tmp" "$sbom_path"
rewrite_release_checksums "$release_dir" "$version"
set +e
./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" \
  >/tmp/integration_release_policy_gate_spoofed_sbom.log 2>&1
spoofed_sbom_rc=$?
set -e
if [[ "$spoofed_sbom_rc" -eq 0 ]]; then
  echo "expected release policy gate to fail when sbom metadata is spoofed but checksums are self-consistent"
  cat /tmp/integration_release_policy_gate_spoofed_sbom.log
  exit 1
fi
if ! rg -q "sbom release metadata mismatch" /tmp/integration_release_policy_gate_spoofed_sbom.log; then
  echo "missing expected spoofed-sbom failure signal"
  cat /tmp/integration_release_policy_gate_spoofed_sbom.log
  exit 1
fi
cp "$sbom_clean" "$sbom_path"
cp "$checksum_clean" "$checksum_file"

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

old_head_commit="$(git rev-parse --verify HEAD~1 2>/dev/null || true)"
if [[ -n "$old_head_commit" ]]; then
  git_tag_annotated "$version" "Known limitations
- integration test

Security model
- integration test

Supported environments
- integration test" "$old_head_commit"
  set +e
  ./scripts/release_policy_gate.sh --version "$version" --release-dir "$release_dir" --require-tag-exists 1 --require-tag-notes 1 \
    >/tmp/integration_release_policy_gate_tag_manifest_mismatch.log 2>&1
  tag_manifest_mismatch_rc=$?
  set -e
  if [[ "$tag_manifest_mismatch_rc" -eq 0 ]]; then
    echo "expected release policy gate to fail when manifest commit does not match release tag"
    cat /tmp/integration_release_policy_gate_tag_manifest_mismatch.log
    exit 1
  fi
  if ! rg -q "manifest commit does not match release tag" /tmp/integration_release_policy_gate_tag_manifest_mismatch.log; then
    echo "missing expected tag-manifest mismatch failure signal"
    cat /tmp/integration_release_policy_gate_tag_manifest_mismatch.log
    exit 1
  fi
  git tag -d "$version" >/dev/null
else
  echo "[integration-release-policy-gate] skipped tag-manifest mismatch check because HEAD~1 is unavailable"
fi

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
