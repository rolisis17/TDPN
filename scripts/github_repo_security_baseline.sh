#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/github_repo_security_baseline.sh status [--repo owner/repo] [--branch main] [--required-checks csv] [--no-fail]
  ./scripts/github_repo_security_baseline.sh apply  [--repo owner/repo] [--branch main] [--required-checks csv] [--approvals 1] [--enable-advanced-security 1]

Examples:
  ./scripts/github_repo_security_baseline.sh status --repo rolisis17/TDPN
  ./scripts/github_repo_security_baseline.sh apply --repo rolisis17/TDPN --branch main

Notes:
  - Requires GitHub CLI (`gh`) authenticated with admin rights on the repository.
  - `status` validates branch protection and repository security-analysis settings.
  - `apply` configures baseline branch protection + security-analysis settings and then re-runs `status`.
USAGE
}

require_cmds() {
  local cmd
  for cmd in gh jq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      echo "missing required command: $cmd"
      exit 2
    fi
  done
}

trim() {
  local s="$1"
  s="${s#"${s%%[![:space:]]*}"}"
  s="${s%"${s##*[![:space:]]}"}"
  printf '%s' "$s"
}

detect_repo_from_origin() {
  local url
  url="$(git config --get remote.origin.url 2>/dev/null || true)"
  if [[ -z "$url" ]]; then
    return 1
  fi
  if [[ "$url" =~ ^git@github\.com:([^/]+/[^/]+)(\.git)?$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$url" =~ ^https?://github\.com/([^/]+/[^/]+)(\.git)?$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  if [[ "$url" =~ ^ssh://git@github\.com/([^/]+/[^/]+)(\.git)?$ ]]; then
    printf '%s' "${BASH_REMATCH[1]}"
    return 0
  fi
  return 1
}

contains() {
  local needle="$1"
  shift
  local item
  for item in "$@"; do
    if [[ "$item" == "$needle" ]]; then
      return 0
    fi
  done
  return 1
}

repo=""
branch="main"
required_checks_csv="test,codeql-go,govulncheck,dependency-review"
required_approvals=1
enable_advanced_security=1
no_fail=0

if [[ $# -lt 1 ]]; then
  usage
  exit 1
fi

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

mode="$1"
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --repo)
      repo="${2:-}"
      shift 2
      ;;
    --branch)
      branch="${2:-}"
      shift 2
      ;;
    --required-checks)
      required_checks_csv="${2:-}"
      shift 2
      ;;
    --approvals)
      required_approvals="${2:-}"
      shift 2
      ;;
    --enable-advanced-security)
      enable_advanced_security="${2:-}"
      shift 2
      ;;
    --no-fail)
      no_fail=1
      shift
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

if [[ "$mode" != "status" && "$mode" != "apply" ]]; then
  echo "unknown mode: $mode"
  usage
  exit 1
fi

if [[ -z "$repo" ]]; then
  repo="$(detect_repo_from_origin || true)"
fi
if [[ -z "$repo" ]]; then
  echo "unable to detect repository; pass --repo owner/repo"
  exit 1
fi

if [[ "$required_approvals" =~ [^0-9] ]]; then
  echo "--approvals must be an integer"
  exit 1
fi
if [[ "$enable_advanced_security" != "0" && "$enable_advanced_security" != "1" ]]; then
  echo "--enable-advanced-security must be 0 or 1"
  exit 1
fi

IFS=',' read -r -a required_checks_raw <<<"$required_checks_csv"
required_checks=()
for check in "${required_checks_raw[@]}"; do
  check="$(trim "$check")"
  [[ -n "$check" ]] && required_checks+=("$check")
done
if [[ "${#required_checks[@]}" -eq 0 ]]; then
  echo "--required-checks must include at least one check context"
  exit 1
fi

require_cmds
if ! gh auth status >/dev/null 2>&1; then
  echo "gh is not authenticated; run: gh auth login"
  exit 1
fi

apply_baseline() {
  local checks_json_file bp_json_file repo_patch_file existing_bp_json_file
  checks_json_file="$(mktemp)"
  bp_json_file="$(mktemp)"
  repo_patch_file="$(mktemp)"
  existing_bp_json_file="$(mktemp)"
  trap 'rm -f "$checks_json_file" "$bp_json_file" "$repo_patch_file" "$existing_bp_json_file"' RETURN

  printf '%s\n' "${required_checks[@]}" | jq -R . | jq -s . >"$checks_json_file"

  # Preserve non-baseline protection controls so apply mode does not weaken stricter repositories.
  if ! gh api \
    -H "Accept: application/vnd.github+json" \
    "repos/${repo}/branches/${branch}/protection" >"$existing_bp_json_file" 2>/dev/null; then
    printf '{}\n' >"$existing_bp_json_file"
  fi

  jq -n \
    --argjson approvals "$required_approvals" \
    --argjson checks "$(cat "$checks_json_file")" \
    --argjson existing "$(cat "$existing_bp_json_file")" \
    '
    def scalar_bool:
      if type == "boolean" then .
      elif type == "object" then (.enabled // false)
      else false
      end;

    def principal_list($value; $field):
      if ($value | type) == "array" then
        [
          $value[]
          | if type == "string" then . else .[$field] // empty end
          | select(type == "string" and length > 0)
        ] | unique
      else
        []
      end;

    def normalize_allowances($obj):
      if ($obj | type) == "object" then
        {
          users: principal_list($obj.users; "login"),
          teams: principal_list($obj.teams; "slug"),
          apps: principal_list($obj.apps; "slug")
        }
      else
        { users: [], teams: [], apps: [] }
      end;

    def normalize_restrictions($obj):
      if ($obj | type) == "object" then
        {
          users: principal_list($obj.users; "login"),
          teams: principal_list($obj.teams; "slug"),
          apps: principal_list($obj.apps; "slug")
        }
      else
        null
      end;

    def existing_checks:
      if ($existing.required_status_checks.checks | type) == "array" then
        [
          $existing.required_status_checks.checks[]
          | {
              context: (.context // ""),
              app_id: (if has("app_id") then .app_id else null end)
            }
          | select(.context != "")
        ]
      elif ($existing.required_status_checks.contexts | type) == "array" then
        [
          $existing.required_status_checks.contexts[]
          | select(type == "string" and length > 0)
          | { context: ., app_id: null }
        ]
      else
        []
      end;

    def merged_checks:
      (existing_checks + ($checks | map({ context: ., app_id: null })))
      | unique_by(.context)
      | sort_by(.context);

    {
      required_status_checks: {
        strict: true,
        checks: merged_checks
      },
      enforce_admins: true,
      required_pull_request_reviews: {
        dismiss_stale_reviews: true,
        require_code_owner_reviews: ($existing.required_pull_request_reviews.require_code_owner_reviews // false),
        require_last_push_approval: ($existing.required_pull_request_reviews.require_last_push_approval // false),
        required_approving_review_count: (
          [
            ($existing.required_pull_request_reviews.required_approving_review_count // 0),
            $approvals
          ] | map(tonumber? // 0) | max
        ),
        dismissal_restrictions: normalize_allowances($existing.required_pull_request_reviews.dismissal_restrictions),
        bypass_pull_request_allowances: normalize_allowances($existing.required_pull_request_reviews.bypass_pull_request_allowances)
      },
      restrictions: normalize_restrictions($existing.restrictions),
      required_linear_history: (($existing.required_linear_history // false) | scalar_bool),
      allow_force_pushes: (($existing.allow_force_pushes // false) | scalar_bool),
      allow_deletions: (($existing.allow_deletions // false) | scalar_bool),
      block_creations: (($existing.block_creations // false) | scalar_bool),
      required_conversation_resolution: (($existing.required_conversation_resolution // false) | scalar_bool),
      lock_branch: (($existing.lock_branch // false) | scalar_bool),
      allow_fork_syncing: (($existing.allow_fork_syncing // false) | scalar_bool)
    }' >"$bp_json_file"

  echo "[repo-security] applying branch protection repo=${repo} branch=${branch}"
  gh api \
    -X PUT \
    -H "Accept: application/vnd.github+json" \
    "repos/${repo}/branches/${branch}/protection" \
    --input "$bp_json_file" >/dev/null

  if [[ "$enable_advanced_security" == "1" ]]; then
    jq -n '{
      security_and_analysis: {
        advanced_security: { status: "enabled" },
        secret_scanning: { status: "enabled" },
        secret_scanning_push_protection: { status: "enabled" }
      }
    }' >"$repo_patch_file"
  else
    jq -n '{
      security_and_analysis: {
        secret_scanning: { status: "enabled" },
        secret_scanning_push_protection: { status: "enabled" }
      }
    }' >"$repo_patch_file"
  fi

  echo "[repo-security] applying repository security_and_analysis settings"
  gh api \
    -X PATCH \
    -H "Accept: application/vnd.github+json" \
    "repos/${repo}" \
    --input "$repo_patch_file" >/dev/null

  echo "[repo-security] enabling vulnerability alerts"
  gh api \
    -X PUT \
    -H "Accept: application/vnd.github+json" \
    "repos/${repo}/vulnerability-alerts" >/dev/null

  echo "[repo-security] enabling automated security fixes"
  gh api \
    -X PUT \
    -H "Accept: application/vnd.github+json" \
    "repos/${repo}/automated-security-fixes" >/dev/null
}

status_baseline() {
  local failures=()
  local repo_json bp_json
  local adv_status secret_status push_protection_status
  local vuln_alerts_status fixes_status
  local bp_enabled review_count dismiss_stale strict
  local contexts=()
  local check

  echo "[repo-security] checking repo=${repo} branch=${branch}"

  repo_json="$(gh api -H "Accept: application/vnd.github+json" "repos/${repo}")"

  adv_status="$(jq -r '.security_and_analysis.advanced_security.status // "unknown"' <<<"$repo_json")"
  secret_status="$(jq -r '.security_and_analysis.secret_scanning.status // "unknown"' <<<"$repo_json")"
  push_protection_status="$(jq -r '.security_and_analysis.secret_scanning_push_protection.status // "unknown"' <<<"$repo_json")"

  vuln_alerts_status="disabled"
  if gh api -H "Accept: application/vnd.github+json" "repos/${repo}/vulnerability-alerts" >/dev/null 2>&1; then
    vuln_alerts_status="enabled"
  fi

  fixes_status="disabled"
  if gh api -H "Accept: application/vnd.github+json" "repos/${repo}/automated-security-fixes" >/dev/null 2>&1; then
    fixes_status="enabled"
  fi

  bp_enabled=0
  if bp_json="$(gh api -H "Accept: application/vnd.github+json" "repos/${repo}/branches/${branch}/protection" 2>/dev/null)"; then
    bp_enabled=1
  fi

  review_count=0
  dismiss_stale=false
  strict=false
  if [[ "$bp_enabled" == "1" ]]; then
    review_count="$(jq -r '.required_pull_request_reviews.required_approving_review_count // 0' <<<"$bp_json")"
    dismiss_stale="$(jq -r '.required_pull_request_reviews.dismiss_stale_reviews // false' <<<"$bp_json")"
    strict="$(jq -r '.required_status_checks.strict // false' <<<"$bp_json")"
    mapfile -t contexts < <(
      jq -r '
        if (.required_status_checks.checks | type) == "array" then
          .required_status_checks.checks[].context
        elif (.required_status_checks.contexts | type) == "array" then
          .required_status_checks.contexts[]
        else
          empty
        end
      ' <<<"$bp_json" | sort -u
    )
  fi

  [[ "$secret_status" == "enabled" ]] || failures+=("secret_scanning is not enabled")
  [[ "$push_protection_status" == "enabled" ]] || failures+=("secret_scanning_push_protection is not enabled")
  [[ "$vuln_alerts_status" == "enabled" ]] || failures+=("vulnerability alerts are not enabled")
  [[ "$fixes_status" == "enabled" ]] || failures+=("automated security fixes are not enabled")
  if [[ "$enable_advanced_security" == "1" ]]; then
    [[ "$adv_status" == "enabled" ]] || failures+=("advanced_security is not enabled")
  fi

  [[ "$bp_enabled" == "1" ]] || failures+=("branch protection is not enabled on ${branch}")
  if [[ "$bp_enabled" == "1" ]]; then
    if (( review_count < required_approvals )); then
      failures+=("required review count is ${review_count}, expected >= ${required_approvals}")
    fi
    [[ "$dismiss_stale" == "true" ]] || failures+=("dismiss_stale_reviews is not enabled")
    [[ "$strict" == "true" ]] || failures+=("required_status_checks.strict is not enabled")
    for check in "${required_checks[@]}"; do
      if ! contains "$check" "${contexts[@]}"; then
        failures+=("required status check missing: ${check}")
      fi
    done
  fi

  echo "[repo-security] security_and_analysis advanced_security=${adv_status} secret_scanning=${secret_status} push_protection=${push_protection_status}"
  echo "[repo-security] security features vulnerability_alerts=${vuln_alerts_status} automated_security_fixes=${fixes_status}"
  if [[ "$bp_enabled" == "1" ]]; then
    echo "[repo-security] branch protection reviews=${review_count} dismiss_stale=${dismiss_stale} strict_checks=${strict}"
    echo "[repo-security] branch checks contexts=$(IFS=,; echo "${contexts[*]}")"
  else
    echo "[repo-security] branch protection not configured"
  fi

  if [[ "${#failures[@]}" -gt 0 ]]; then
    echo "[repo-security] baseline check failed"
    printf -- '- %s\n' "${failures[@]}"
    if [[ "$mode" == "status" ]]; then
      echo "[repo-security] to apply baseline:"
      echo "  ./scripts/github_repo_security_baseline.sh apply --repo ${repo} --branch ${branch}"
    fi
    if [[ "$no_fail" == "1" ]]; then
      return 0
    fi
    return 1
  fi

  echo "[repo-security] baseline check ok"
}

if [[ "$mode" == "apply" ]]; then
  apply_baseline
fi

status_baseline
