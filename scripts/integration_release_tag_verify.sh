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
annotated_tag="v0.0.0-int-ann-${uniq_suffix}"
lightweight_tag="v0.0.0-int-lw-${uniq_suffix}"
missing_tag="v0.0.0-int-missing-${uniq_suffix}"
old_head_tag="v0.0.0-int-old-${uniq_suffix}"

cleanup() {
  git tag -d "$annotated_tag" >/dev/null 2>&1 || true
  git tag -d "$lightweight_tag" >/dev/null 2>&1 || true
  git tag -d "$old_head_tag" >/dev/null 2>&1 || true
}
trap cleanup EXIT

git_tag_annotated() {
  local tag_name="$1"
  local tag_message="$2"
  local tag_target="$3"
  # Keep integration hermetic: do not depend on global/local git identity.
  git -c user.name='integration-bot' -c user.email='integration-bot@example.invalid' \
    tag -a "$tag_name" -m "$tag_message" "$tag_target" >/dev/null
}

git_tag_annotated "$annotated_tag" "integration annotated tag" HEAD
git tag "$lightweight_tag" HEAD

set +e
./scripts/release_verify_tag.sh --version "$missing_tag" >/tmp/integration_release_tag_verify_missing.log 2>&1
missing_rc=$?
set -e
if [[ "$missing_rc" -eq 0 ]]; then
  echo "expected missing tag verification to fail"
  cat /tmp/integration_release_tag_verify_missing.log
  exit 1
fi
if ! rg -q "tag not found" /tmp/integration_release_tag_verify_missing.log; then
  echo "missing expected missing-tag failure signal"
  cat /tmp/integration_release_tag_verify_missing.log
  exit 1
fi

set +e
./scripts/release_verify_tag.sh --version "$lightweight_tag" >/tmp/integration_release_tag_verify_lightweight.log 2>&1
lw_rc=$?
set -e
if [[ "$lw_rc" -eq 0 ]]; then
  echo "expected lightweight tag verification to fail"
  cat /tmp/integration_release_tag_verify_lightweight.log
  exit 1
fi
if ! rg -q "must be an annotated tag" /tmp/integration_release_tag_verify_lightweight.log; then
  echo "missing expected lightweight-tag failure signal"
  cat /tmp/integration_release_tag_verify_lightweight.log
  exit 1
fi

./scripts/release_verify_tag.sh --version "$annotated_tag" --require-head-match 1 >/tmp/integration_release_tag_verify_annotated.log 2>&1
if ! rg -q "ok" /tmp/integration_release_tag_verify_annotated.log; then
  echo "expected annotated tag verification to pass"
  cat /tmp/integration_release_tag_verify_annotated.log
  exit 1
fi

set +e
./scripts/release_verify_tag.sh --version "$annotated_tag" --require-signature 1 >/tmp/integration_release_tag_verify_signature.log 2>&1
sig_rc=$?
set -e
if [[ "$sig_rc" -eq 0 ]]; then
  echo "expected signature verification to fail for unsigned annotated tag"
  cat /tmp/integration_release_tag_verify_signature.log
  exit 1
fi
if ! rg -q "signature verification failed|No signature|not a signed tag|error" /tmp/integration_release_tag_verify_signature.log; then
  echo "missing expected signed-tag failure signal"
  cat /tmp/integration_release_tag_verify_signature.log
  exit 1
fi

if git rev-parse -q --verify HEAD~1 >/dev/null 2>&1; then
  git_tag_annotated "$old_head_tag" "integration old-head tag" HEAD~1
  set +e
  ./scripts/release_verify_tag.sh --version "$old_head_tag" --require-head-match 1 >/tmp/integration_release_tag_verify_head_mismatch.log 2>&1
  head_mismatch_rc=$?
  set -e
  if [[ "$head_mismatch_rc" -eq 0 ]]; then
    echo "expected head-match enforcement to fail for tag on non-HEAD commit"
    cat /tmp/integration_release_tag_verify_head_mismatch.log
    exit 1
  fi
  if ! rg -q "current HEAD" /tmp/integration_release_tag_verify_head_mismatch.log; then
    echo "missing expected head-mismatch failure signal"
    cat /tmp/integration_release_tag_verify_head_mismatch.log
    exit 1
  fi
fi

echo "release tag verify integration check ok"
