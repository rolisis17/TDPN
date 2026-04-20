#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/release_verify_tag.sh --version vX.Y.Z [--require-head-match 0|1] [--require-signature 0|1] [--require-contained-in-ref REF]

Examples:
  ./scripts/release_verify_tag.sh --version v0.1.0
  ./scripts/release_verify_tag.sh --version v0.1.0 --require-head-match 1 --require-signature 1

Notes:
  - Enforces existence of an annotated tag (lightweight tags are rejected).
  - `--require-signature 1` runs `git tag -v` and fails if signature verification fails.
  - `--require-contained-in-ref origin/main` enforces that tag commit is reachable from the protected base ref.
USAGE
}

require_cmds() {
  local cmd
  for cmd in git; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "missing required command: $cmd"
      exit 2
    fi
  done
}

version=""
require_head_match=0
require_signature=0
require_contained_in_ref=""
signature_verify_log=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      version="${2:-}"
      shift 2
      ;;
    --require-head-match)
      require_head_match="${2:-}"
      shift 2
      ;;
    --require-signature)
      require_signature="${2:-}"
      shift 2
      ;;
    --require-contained-in-ref)
      require_contained_in_ref="${2:-}"
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
if [[ "$require_head_match" != "0" && "$require_head_match" != "1" ]]; then
  echo "--require-head-match must be 0 or 1"
  exit 1
fi
if [[ "$require_signature" != "0" && "$require_signature" != "1" ]]; then
  echo "--require-signature must be 0 or 1"
  exit 1
fi
if [[ -n "$require_contained_in_ref" && ! "$require_contained_in_ref" =~ ^[A-Za-z0-9._/-]+$ ]]; then
  echo "--require-contained-in-ref must be a simple git ref name (e.g. origin/main)"
  exit 1
fi

require_cmds

if ! git rev-parse -q --verify "refs/tags/${version}" >/dev/null 2>&1; then
  echo "tag not found: ${version}"
  exit 1
fi

tag_type="$(git cat-file -t "refs/tags/${version}" 2>/dev/null || true)"
if [[ "$tag_type" != "tag" ]]; then
  echo "tag ${version} must be an annotated tag (found type=${tag_type:-unknown})"
  exit 1
fi

tag_commit="$(git rev-list -n 1 "$version")"
head_commit="$(git rev-parse HEAD)"
if [[ "$require_head_match" == "1" && "$tag_commit" != "$head_commit" ]]; then
  echo "tag ${version} points to ${tag_commit}, current HEAD is ${head_commit}"
  exit 1
fi

if [[ -n "$require_contained_in_ref" ]]; then
  if ! git rev-parse -q --verify "${require_contained_in_ref}^{commit}" >/dev/null 2>&1; then
    if [[ "$require_contained_in_ref" == origin/* ]]; then
      remote_branch="${require_contained_in_ref#origin/}"
      git fetch --no-tags origin "${remote_branch}:refs/remotes/origin/${remote_branch}" >/dev/null 2>&1 || true
    fi
  fi
  required_ref_commit="$(git rev-parse -q --verify "${require_contained_in_ref}^{commit}" 2>/dev/null || true)"
  if [[ -z "$required_ref_commit" ]]; then
    echo "required ref not found: ${require_contained_in_ref}"
    exit 1
  fi
  if ! git merge-base --is-ancestor "$tag_commit" "$required_ref_commit"; then
    echo "tag ${version} commit ${tag_commit} is not contained in ${require_contained_in_ref} (${required_ref_commit})"
    exit 1
  fi
fi

if [[ "$require_signature" == "1" ]]; then
  signature_verify_log="$(mktemp "${TMPDIR:-/tmp}/release_verify_tag_signature.XXXXXX.log")"
  trap '[[ -n "${signature_verify_log:-}" ]] && rm -f "$signature_verify_log"' EXIT
  if ! git tag -v "$version" >"$signature_verify_log" 2>&1; then
    echo "tag signature verification failed for ${version}"
    cat "$signature_verify_log"
    exit 1
  fi
fi

echo "[release-verify-tag] version=${version} annotated=1 commit=${tag_commit} head=${head_commit} require_signature=${require_signature} contained_in_ref=${require_contained_in_ref:-none}"
echo "[release-verify-tag] ok"
