#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in rg jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
TMP_BIN="$TMP_DIR/bin"
MOCK_LOG="$TMP_DIR/gh_mock.log"
mkdir -p "$TMP_BIN"

cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

cat >"$TMP_BIN/gh" <<'EOF_GH'
#!/usr/bin/env bash
set -euo pipefail

mode="${GH_MOCK_MODE:-pass}"
log_file="${GH_MOCK_LOG:-/tmp/gh_mock.log}"

if [[ "${1:-}" == "auth" && "${2:-}" == "status" ]]; then
  exit 0
fi

if [[ "${1:-}" != "api" ]]; then
  echo "mock-gh unsupported command: $*" >&2
  exit 1
fi
shift

method="GET"
input_file=""
endpoint=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -X)
      method="${2:-}"
      shift 2
      ;;
    -H)
      shift 2
      ;;
    --input)
      input_file="${2:-}"
      shift 2
      ;;
    --silent)
      shift
      ;;
    *)
      if [[ -z "$endpoint" ]]; then
        endpoint="$1"
      fi
      shift
      ;;
  esac
done

if [[ -z "$endpoint" ]]; then
  echo "mock-gh missing endpoint" >&2
  exit 1
fi

echo "${method} ${endpoint} input=${input_file}" >>"$log_file"

repo_json_adv_status="enabled"
if [[ "$mode" == "adv_disabled" ]]; then
  repo_json_adv_status="disabled"
fi

case "${method} ${endpoint}" in
  "GET repos/testowner/testrepo")
    cat <<JSON
{
  "security_and_analysis": {
    "advanced_security": { "status": "${repo_json_adv_status}" },
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
JSON
    ;;
  "GET repos/testowner/testrepo/vulnerability-alerts")
    echo '{}'
    ;;
  "GET repos/testowner/testrepo/automated-security-fixes")
    echo '{}'
    ;;
  "GET repos/testowner/testrepo/branches/main/protection")
    if [[ "$mode" == "missing_check" ]]; then
      cat <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "test" },
      { "context": "codeql-go" },
      { "context": "govulncheck" }
    ]
  },
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  }
}
JSON
    else
      cat <<'JSON'
{
  "required_status_checks": {
    "strict": true,
    "checks": [
      { "context": "test" },
      { "context": "codeql-go" },
      { "context": "govulncheck" },
      { "context": "dependency-review" }
    ]
  },
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "dismiss_stale_reviews": true
  }
}
JSON
    fi
    ;;
  "PUT repos/testowner/testrepo/branches/main/protection")
    [[ -n "$input_file" ]] || {
      echo "missing --input for branch protection apply" >&2
      exit 1
    }
    echo '{}'
    ;;
  "PATCH repos/testowner/testrepo")
    [[ -n "$input_file" ]] || {
      echo "missing --input for repo patch" >&2
      exit 1
    }
    echo '{}'
    ;;
  "PUT repos/testowner/testrepo/vulnerability-alerts")
    echo '{}'
    ;;
  "PUT repos/testowner/testrepo/automated-security-fixes")
    echo '{}'
    ;;
  *)
    echo "mock-gh unsupported endpoint: ${method} ${endpoint}" >&2
    exit 1
    ;;
esac
EOF_GH
chmod +x "$TMP_BIN/gh"

pass_env=(
  "PATH=$TMP_BIN:$PATH"
  "GH_MOCK_LOG=$MOCK_LOG"
)

if ! env "${pass_env[@]}" GH_MOCK_MODE=pass \
  ./scripts/github_repo_security_baseline.sh status --repo testowner/testrepo --branch main \
  >/tmp/integration_github_repo_security_baseline_status_ok.log 2>&1; then
  echo "expected status mode to pass against baseline-compliant mock repo"
  cat /tmp/integration_github_repo_security_baseline_status_ok.log
  exit 1
fi
if ! rg -q "baseline check ok" /tmp/integration_github_repo_security_baseline_status_ok.log; then
  echo "missing success signal in status output"
  cat /tmp/integration_github_repo_security_baseline_status_ok.log
  exit 1
fi

set +e
env "${pass_env[@]}" GH_MOCK_MODE=missing_check \
  ./scripts/github_repo_security_baseline.sh status --repo testowner/testrepo --branch main \
  >/tmp/integration_github_repo_security_baseline_status_fail.log 2>&1
status_fail_rc=$?
set -e
if [[ "$status_fail_rc" -eq 0 ]]; then
  echo "expected status mode to fail when required checks are missing"
  cat /tmp/integration_github_repo_security_baseline_status_fail.log
  exit 1
fi
if ! rg -q "required status check missing: dependency-review" /tmp/integration_github_repo_security_baseline_status_fail.log; then
  echo "missing expected missing-check failure signal"
  cat /tmp/integration_github_repo_security_baseline_status_fail.log
  exit 1
fi

if ! env "${pass_env[@]}" GH_MOCK_MODE=missing_check \
  ./scripts/github_repo_security_baseline.sh status --repo testowner/testrepo --branch main --no-fail \
  >/tmp/integration_github_repo_security_baseline_status_nofail.log 2>&1; then
  echo "expected --no-fail status mode to return success"
  cat /tmp/integration_github_repo_security_baseline_status_nofail.log
  exit 1
fi
if ! rg -q "baseline check failed" /tmp/integration_github_repo_security_baseline_status_nofail.log; then
  echo "missing expected baseline-failed diagnostics in --no-fail output"
  cat /tmp/integration_github_repo_security_baseline_status_nofail.log
  exit 1
fi

set +e
env "${pass_env[@]}" GH_MOCK_MODE=adv_disabled \
  ./scripts/github_repo_security_baseline.sh status --repo testowner/testrepo --branch main \
  >/tmp/integration_github_repo_security_baseline_adv_fail.log 2>&1
adv_fail_rc=$?
set -e
if [[ "$adv_fail_rc" -eq 0 ]]; then
  echo "expected status mode to fail when advanced security is disabled by default policy"
  cat /tmp/integration_github_repo_security_baseline_adv_fail.log
  exit 1
fi
if ! rg -q "advanced_security is not enabled" /tmp/integration_github_repo_security_baseline_adv_fail.log; then
  echo "missing expected advanced-security failure signal"
  cat /tmp/integration_github_repo_security_baseline_adv_fail.log
  exit 1
fi

if ! env "${pass_env[@]}" GH_MOCK_MODE=adv_disabled \
  ./scripts/github_repo_security_baseline.sh status --repo testowner/testrepo --branch main --enable-advanced-security 0 \
  >/tmp/integration_github_repo_security_baseline_adv_relaxed.log 2>&1; then
  echo "expected status mode to pass when advanced-security requirement is disabled"
  cat /tmp/integration_github_repo_security_baseline_adv_relaxed.log
  exit 1
fi
if ! rg -q "baseline check ok" /tmp/integration_github_repo_security_baseline_adv_relaxed.log; then
  echo "missing expected success signal in relaxed advanced-security output"
  cat /tmp/integration_github_repo_security_baseline_adv_relaxed.log
  exit 1
fi

: >"$MOCK_LOG"
if ! env "${pass_env[@]}" GH_MOCK_MODE=pass \
  ./scripts/github_repo_security_baseline.sh apply --repo testowner/testrepo --branch main \
  >/tmp/integration_github_repo_security_baseline_apply_ok.log 2>&1; then
  echo "expected apply mode to pass against mock repo"
  cat /tmp/integration_github_repo_security_baseline_apply_ok.log
  exit 1
fi
if ! rg -q "baseline check ok" /tmp/integration_github_repo_security_baseline_apply_ok.log; then
  echo "missing success signal in apply output"
  cat /tmp/integration_github_repo_security_baseline_apply_ok.log
  exit 1
fi

for expected_call in \
  "PUT repos/testowner/testrepo/branches/main/protection" \
  "PATCH repos/testowner/testrepo" \
  "PUT repos/testowner/testrepo/vulnerability-alerts" \
  "PUT repos/testowner/testrepo/automated-security-fixes"
do
  if ! rg -q "^${expected_call}" "$MOCK_LOG"; then
    echo "missing expected gh api call: ${expected_call}"
    cat "$MOCK_LOG"
    exit 1
  fi
done

echo "github repo security baseline integration check ok"
