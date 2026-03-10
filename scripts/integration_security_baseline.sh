#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg; do
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
  if ! rg -q "$pattern" "$file"; then
    echo "missing expected setting in $file: $description"
    exit 1
  fi
}

echo "[security-baseline] checking required files"
require_file "SECURITY.md"
require_file ".github/dependabot.yml"
require_file ".github/workflows/security.yml"
require_file ".github/workflows/dependency-review.yml"
require_file "scripts/github_repo_security_baseline.sh"
require_file "docs/github-security-baseline.md"

echo "[security-baseline] checking dependabot ecosystems"
require_match ".github/dependabot.yml" 'package-ecosystem:\s*"gomod"' "gomod updates configured"
require_match ".github/dependabot.yml" 'package-ecosystem:\s*"github-actions"' "github-actions updates configured"

echo "[security-baseline] checking security workflow coverage"
require_match ".github/workflows/security.yml" 'github/codeql-action/init@v3' "CodeQL init"
require_match ".github/workflows/security.yml" 'languages:\s*go' "CodeQL go language target"
require_match ".github/workflows/security.yml" 'govulncheck' "govulncheck job"
require_match ".github/workflows/security.yml" 'schedule:' "scheduled security scan"
require_match ".github/workflows/dependency-review.yml" 'actions/dependency-review-action@v4' "dependency review action"
require_match "scripts/github_repo_security_baseline.sh" 'Usage:' "repo security baseline usage"
require_match "scripts/github_repo_security_baseline.sh" 'status' "repo security baseline status mode"
require_match "scripts/github_repo_security_baseline.sh" 'apply' "repo security baseline apply mode"
require_match "docs/open-source-checklist.md" 'github_repo_security_baseline.sh' "open-source checklist references repo baseline command"

echo "[security-baseline] ok"
