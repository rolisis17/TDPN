#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/release_require_status_checks.sh --repo owner/name --sha <commit-sha> [--workflows ci.yml,security.yml] [--events push,pull_request,merge_group] [--timeout-seconds 900] [--poll-interval-seconds 15]

Notes:
  - Requires GITHUB_TOKEN with read access to actions metadata.
  - Verifies the latest relevant run for each required workflow concludes with success for the exact commit SHA.
  - Polls in-progress runs until completion or timeout.
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

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

repo=""
sha=""
workflows="ci.yml,security.yml"
events="push,pull_request,merge_group"
timeout_seconds=900
poll_interval_seconds=15

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
    --events)
      events="${2:-}"
      shift 2
      ;;
    --timeout-seconds)
      timeout_seconds="${2:-}"
      shift 2
      ;;
    --poll-interval-seconds)
      poll_interval_seconds="${2:-}"
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
if [[ ! "$timeout_seconds" =~ ^[0-9]+$ || "$timeout_seconds" -lt 1 ]]; then
  echo "--timeout-seconds must be an integer >= 1"
  exit 1
fi
if [[ ! "$poll_interval_seconds" =~ ^[0-9]+$ || "$poll_interval_seconds" -lt 1 ]]; then
  echo "--poll-interval-seconds must be an integer >= 1"
  exit 1
fi
if [[ -z "${GITHUB_TOKEN:-}" ]]; then
  echo "GITHUB_TOKEN is required"
  exit 1
fi

require_cmds

IFS=',' read -r -a required_workflows_raw <<<"$workflows"
required_workflows=()
for workflow in "${required_workflows_raw[@]}"; do
  workflow="$(trim "$workflow")"
  [[ -z "$workflow" ]] && continue
  if [[ ! "$workflow" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "[release-status-checks] invalid workflow identifier: ${workflow}"
    exit 1
  fi
  required_workflows+=("$workflow")
done
if [[ ${#required_workflows[@]} -eq 0 ]]; then
  echo "no required workflows supplied"
  exit 1
fi

IFS=',' read -r -a required_events_raw <<<"$events"
required_events=()
for event in "${required_events_raw[@]}"; do
  event="$(trim "$event")"
  [[ -z "$event" ]] && continue
  event="${event,,}"
  if [[ ! "$event" =~ ^[A-Za-z0-9._-]+$ ]]; then
    echo "[release-status-checks] invalid event identifier: ${event}"
    exit 1
  fi
  required_events+=("$event")
done

events_json='[]'
events_display="any"
if [[ ${#required_events[@]} -gt 0 ]]; then
  events_json="$(printf '%s\n' "${required_events[@]}" | jq -R . | jq -s .)"
  events_display="$(IFS=,; echo "${required_events[*]}")"
fi

api_root="https://api.github.com/repos/${repo}"
fail=0
checked=0
sha_lc="${sha,,}"

for workflow in "${required_workflows[@]}"; do
  checked=$((checked + 1))
  deadline=$((SECONDS + timeout_seconds))

  while :; do
    url="${api_root}/actions/workflows/${workflow}/runs?head_sha=${sha}&per_page=30"
    if ! response="$(curl -fsSL \
      -H "Accept: application/vnd.github+json" \
      -H "Authorization: Bearer ${GITHUB_TOKEN}" \
      -H "X-GitHub-Api-Version: 2022-11-28" \
      "$url")"; then
      echo "[release-status-checks] failed to query workflow runs for ${workflow}"
      fail=1
      break
    fi

    latest_run="$(
      jq -c \
        --arg sha "$sha_lc" \
        --argjson events "$events_json" \
        '
        [
          .workflow_runs[]
          | (.event // "" | ascii_downcase) as $event
          | select(((.head_sha // "") | ascii_downcase) == $sha)
          | select(($events | length) == 0 or (($events | index($event)) != null))
        ] | first // empty
        ' <<<"$response"
    )"

    if [[ -z "$latest_run" ]]; then
      if (( SECONDS >= deadline )); then
        echo "[release-status-checks] no relevant run found workflow=${workflow} sha=${sha} events=${events_display} timeout=${timeout_seconds}s"
        fail=1
        break
      fi
      remaining=$((deadline - SECONDS))
      sleep_seconds="$poll_interval_seconds"
      if (( remaining < sleep_seconds )); then
        sleep_seconds="$remaining"
      fi
      if (( sleep_seconds < 1 )); then
        sleep_seconds=1
      fi
      echo "[release-status-checks] waiting workflow=${workflow} sha=${sha} (no relevant runs yet, events=${events_display}, remaining=${remaining}s)"
      sleep "$sleep_seconds"
      continue
    fi

    run_status="$(jq -r '.status // "unknown"' <<<"$latest_run")"
    run_conclusion="$(jq -r '.conclusion // "none"' <<<"$latest_run")"
    run_url="$(jq -r '.html_url // ""' <<<"$latest_run")"
    run_id="$(jq -r '.id // 0' <<<"$latest_run")"
    run_attempt="$(jq -r '.run_attempt // 0' <<<"$latest_run")"
    run_event="$(jq -r '(.event // "unknown") | ascii_downcase' <<<"$latest_run")"

    if [[ "$run_status" != "completed" ]]; then
      if (( SECONDS >= deadline )); then
        echo "[release-status-checks] timeout waiting workflow=${workflow} run_id=${run_id} status=${run_status} event=${run_event} timeout=${timeout_seconds}s run=${run_url}"
        fail=1
        break
      fi
      remaining=$((deadline - SECONDS))
      sleep_seconds="$poll_interval_seconds"
      if (( remaining < sleep_seconds )); then
        sleep_seconds="$remaining"
      fi
      if (( sleep_seconds < 1 )); then
        sleep_seconds=1
      fi
      echo "[release-status-checks] waiting workflow=${workflow} run_id=${run_id} status=${run_status} event=${run_event} remaining=${remaining}s run=${run_url}"
      sleep "$sleep_seconds"
      continue
    fi

    if [[ "$run_conclusion" != "success" ]]; then
      echo "[release-status-checks] latest run is not successful workflow=${workflow} sha=${sha} run_id=${run_id} attempt=${run_attempt} status=${run_status} conclusion=${run_conclusion} event=${run_event} run=${run_url}"
      fail=1
      break
    fi

    echo "[release-status-checks] ok workflow=${workflow} sha=${sha} run_id=${run_id} attempt=${run_attempt} event=${run_event} run=${run_url}"
    break
  done
done

if [[ "$checked" -eq 0 ]]; then
  echo "[release-status-checks] no valid workflow identifiers were provided"
  exit 1
fi

if [[ "$fail" -ne 0 ]]; then
  echo "[release-status-checks] FAIL"
  exit 1
fi

echo "[release-status-checks] PASS"
