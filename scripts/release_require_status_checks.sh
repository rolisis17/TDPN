#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/release_require_status_checks.sh --repo owner/name --sha <commit-sha> [--workflows ci.yml,security.yml]

Notes:
  - Requires GITHUB_TOKEN with read access to actions metadata.
  - Verifies each required workflow has at least one successful completed run for the exact commit SHA.
USAGE
}

require_cmds() {
  local cmd
  for cmd in curl jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "missing required command: $cmd"
      exit 2
    fi
  done
}

repo=""
sha=""
workflows="ci.yml,security.yml"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      repo="${2:-}"
      shift 2
      ;;
    --sha)
      sha="${2:-}"
      shift 2
      ;;
    --workflows)
      workflows="${2:-}"
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

if [[ -z "$repo" || -z "$sha" ]]; then
  echo "--repo and --sha are required"
  usage
  exit 1
fi
if [[ ! "$repo" =~ ^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$ ]]; then
  echo "--repo must be owner/name"
  exit 1
fi
if [[ ! "$sha" =~ ^[0-9a-fA-F]{7,40}$ ]]; then
  echo "--sha must be a commit hash"
  exit 1
fi
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "GITHUB_TOKEN is required"
  exit 1
fi

require_cmds

IFS=',' read -r -a required_workflows <<<"$workflows"
if [[ ${#required_workflows[@]} -eq 0 ]]; then
  echo "no required workflows supplied"
  exit 1
fi

api_root="https://api.github.com/repos/${repo}"
fail=0

for workflow in "${required_workflows[@]}"; do
  workflow="$(echo "$workflow" | xargs)"
  [[ -z "$workflow" ]] && continue

  url="${api_root}/actions/workflows/${workflow}/runs?head_sha=${sha}&per_page=30"
  response="$(curl -fsSL \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer ${GITHUB_TOKEN}" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "$url")"

  success_count="$(jq '[.workflow_runs[] | select(.status=="completed" and .conclusion=="success")] | length' <<<"$response")"
  if [[ "$success_count" -lt 1 ]]; then
    echo "[release-status-checks] missing successful run for ${workflow} on sha=${sha}"
    last_state="$(jq -r '.workflow_runs[0] | "\(.status // "none")/\(.conclusion // "none") \(.html_url // "")"' <<<"$response")"
    echo "[release-status-checks] latest observed for ${workflow}: ${last_state}"
    fail=1
    continue
  fi

  run_url="$(jq -r '.workflow_runs[] | select(.status=="completed" and .conclusion=="success") | .html_url' <<<"$response" | head -n 1)"
  echo "[release-status-checks] ok workflow=${workflow} sha=${sha} run=${run_url}"
done

if [[ "$fail" -ne 0 ]]; then
  echo "[release-status-checks] FAIL"
  exit 1
fi

echo "[release-status-checks] PASS"
