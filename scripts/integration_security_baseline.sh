#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in perl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

require_file() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    echo "missing required file: $file"
    exit 1
  fi
}

require_match() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  if ! perl -0ne "exit((m{${pattern}}m) ? 0 : 1)" "$file"; then
    echo "missing expected setting in $file: $description"
    exit 1
  fi
}

require_pinned_action() {
  local file="$1"
  local action="$2"
  local description="$3"
  local line=""
  local spec=""
  local ref=""

  while IFS= read -r line; do
    if [[ "$line" =~ ^[[:space:]]*(-[[:space:]]*)?uses:[[:space:]]*([^[:space:]#]+) ]]; then
      spec="${BASH_REMATCH[2]}"
      if [[ "$spec" == "${action}"@* ]]; then
        ref="${spec#${action}@}"
        break
      fi
    fi
  done <"$file"

  if [[ -z "$ref" ]]; then
    echo "missing expected action usage in $file: $description (${action})"
    exit 1
  fi

  if [[ "$ref" =~ ^[0-9a-fA-F]{40}$ ]]; then
    return 0
  fi
  if [[ "$ref" =~ ^v[0-9]+(\.[0-9]+){0,2}([.-][0-9A-Za-z.-]+)?$ ]]; then
    return 0
  fi

  echo "action in $file is not pinned to a supported ref format: ${action}@${ref}"
  exit 1
}

echo "[security-baseline] checking required files"
require_file "SECURITY.md"
require_file ".github/dependabot.yml"
require_file ".github/workflows/security.yml"
require_file ".github/workflows/dependency-review.yml"
require_file ".github/workflows/release.yml"
require_file "scripts/github_repo_security_baseline.sh"
require_file "docs/github-security-baseline.md"
require_file "scripts/integration_github_repo_security_baseline.sh"
require_file "scripts/release_prepare.sh"
require_file "scripts/release_generate_sbom.sh"
require_file "scripts/integration_release_integrity.sh"
require_file "scripts/integration_release_sbom.sh"
require_file "scripts/release_verify_tag.sh"
require_file "scripts/integration_release_tag_verify.sh"
require_file "scripts/release_policy_gate.sh"
require_file "scripts/integration_release_policy_gate.sh"
require_file "docs/release-process.md"

echo "[security-baseline] checking dependabot ecosystems"
require_match ".github/dependabot.yml" 'package-ecosystem:\s*"gomod"' "gomod updates configured"
require_match ".github/dependabot.yml" 'package-ecosystem:\s*"github-actions"' "github-actions updates configured"

echo "[security-baseline] checking security workflow coverage"
require_pinned_action ".github/workflows/security.yml" "actions/checkout" "security workflow checkout action"
require_pinned_action ".github/workflows/security.yml" "github/codeql-action/init" "CodeQL init"
require_pinned_action ".github/workflows/security.yml" "github/codeql-action/autobuild" "CodeQL autobuild"
require_pinned_action ".github/workflows/security.yml" "github/codeql-action/analyze" "CodeQL analyze"
require_pinned_action ".github/workflows/security.yml" "actions/setup-go" "security workflow setup-go action"
require_match ".github/workflows/security.yml" 'languages:\s*go' "CodeQL go language target"
require_match ".github/workflows/security.yml" 'govulncheck' "govulncheck job"
require_match ".github/workflows/security.yml" 'schedule:' "scheduled security scan"
require_pinned_action ".github/workflows/dependency-review.yml" "actions/checkout" "dependency-review checkout action"
require_pinned_action ".github/workflows/dependency-review.yml" "actions/dependency-review-action" "dependency review action"
require_pinned_action ".github/workflows/release.yml" "actions/checkout" "release workflow checkout action"
require_pinned_action ".github/workflows/release.yml" "actions/setup-go" "release workflow setup-go action"
require_pinned_action ".github/workflows/release.yml" "actions/upload-artifact" "release workflow upload artifact action"
require_pinned_action ".github/workflows/release.yml" "actions/download-artifact" "release workflow download artifact action"
require_pinned_action ".github/workflows/release.yml" "softprops/action-gh-release" "release workflow publishes assets"
require_pinned_action ".github/workflows/release.yml" "actions/attest-build-provenance" "release workflow attests artifacts"
require_match ".github/workflows/release.yml" 'scripts/release_prepare.sh' "release workflow uses release_prepare"
require_match ".github/workflows/release.yml" 'scripts/release_verify_tag.sh' "release workflow verifies tag metadata"
require_match ".github/workflows/release.yml" 'scripts/release_policy_gate.sh' "release workflow enforces release policy gate"
require_match ".github/workflows/release.yml" 'sbom_go_modules_' "release workflow publishes sbom"
require_match "scripts/github_repo_security_baseline.sh" 'Usage:' "repo security baseline usage"
require_match "scripts/github_repo_security_baseline.sh" 'status' "repo security baseline status mode"
require_match "scripts/github_repo_security_baseline.sh" 'apply' "repo security baseline apply mode"
require_match "docs/open-source-checklist.md" 'github_repo_security_baseline.sh' "open-source checklist references repo baseline command"
require_match "scripts/ci_local.sh" 'integration_github_repo_security_baseline.sh' "ci_local includes repo-baseline integration"
require_match "scripts/beta_preflight.sh" 'integration_github_repo_security_baseline.sh' "beta_preflight includes repo-baseline integration"
require_match "scripts/ci_local.sh" 'integration_release_integrity.sh' "ci_local includes release integrity integration"
require_match "scripts/beta_preflight.sh" 'integration_release_integrity.sh' "beta_preflight includes release integrity integration"
require_match "scripts/ci_local.sh" 'integration_release_sbom.sh' "ci_local includes release sbom integration"
require_match "scripts/beta_preflight.sh" 'integration_release_sbom.sh' "beta_preflight includes release sbom integration"
require_match "scripts/ci_local.sh" 'integration_release_tag_verify.sh' "ci_local includes release tag verify integration"
require_match "scripts/beta_preflight.sh" 'integration_release_tag_verify.sh' "beta_preflight includes release tag verify integration"
require_match "scripts/ci_local.sh" 'integration_release_policy_gate.sh' "ci_local includes release policy gate integration"
require_match "scripts/beta_preflight.sh" 'integration_release_policy_gate.sh' "beta_preflight includes release policy gate integration"

echo "[security-baseline] ok"
