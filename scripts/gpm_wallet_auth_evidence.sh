#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
umask 077

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/gpm_wallet_auth_evidence.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--check-timeout-sec N] \
    [--print-summary-json [0|1]]

Purpose:
  Capture deterministic local GPM wallet-auth evidence for the Keplr/Leap
  secp256k1 binding path before beta or release handoff.

Evidence captured:
  - Keplr + Leap wallet-extension source with Cosmos secp256k1 pubkey aliases
  - local secp256k1 wallet binding and mismatched-wallet rejection
  - chain-id / wallet-HRP binding policy
  - command-backed Admin Console separation from local wallet binding
  - strict auth metadata and wallet-extension-source policy contracts
  - public portal wallet-extension assisted signing contract

Defaults:
  --reports-dir .easy-node-logs/gpm_wallet_auth_evidence
  --summary-json .easy-node-logs/gpm_wallet_auth_evidence_summary.json
  --report-md .easy-node-logs/gpm_wallet_auth_evidence_report.md
  --check-timeout-sec 300
  --print-summary-json 1
USAGE
}

trim() {
  local value="${1:-}"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

abs_path() {
  local path
  path="$(trim "${1:-}")"
  if [[ -z "$path" ]]; then
    printf '%s' ""
  elif [[ "$path" =~ ^[A-Za-z]:[\\/] ]]; then
    if command -v wslpath >/dev/null 2>&1; then
      wslpath -u "$path"
    elif command -v cygpath >/dev/null 2>&1; then
      cygpath -u "$path"
    else
      printf '%s' "$path"
    fi
  elif [[ "$path" == /* ]]; then
    printf '%s' "$path"
  else
    printf '%s' "$ROOT_DIR/$path"
  fi
}

reject_output_symlink_or_die() {
  local path
  path="$(trim "${1:-}")"
  if [[ -n "$path" && -L "$path" ]]; then
    echo "refusing to write evidence output through symlink: $path"
    exit 2
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
}

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1"
    exit 2
  fi
}

int_arg_or_die() {
  local name="$1"
  local value="$2"
  if ! [[ "$value" =~ ^[0-9]+$ ]]; then
    echo "$name must be an integer >= 0"
    exit 2
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

reports_dir="${GPM_WALLET_AUTH_EVIDENCE_REPORTS_DIR:-.easy-node-logs/gpm_wallet_auth_evidence}"
summary_json="${GPM_WALLET_AUTH_EVIDENCE_SUMMARY_JSON:-}"
report_md="${GPM_WALLET_AUTH_EVIDENCE_REPORT_MD:-}"
check_timeout_sec="${GPM_WALLET_AUTH_EVIDENCE_CHECK_TIMEOUT_SEC:-300}"
print_summary_json="${GPM_WALLET_AUTH_EVIDENCE_PRINT_SUMMARY_JSON:-1}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      reports_dir="${2:-}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --report-md)
      report_md="${2:-}"
      shift 2
      ;;
    --check-timeout-sec)
      check_timeout_sec="${2:-}"
      shift 2
      ;;
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

for cmd in bash date go jq mkdir; do
  need_cmd "$cmd"
done
bool_arg_or_die "--print-summary-json" "$print_summary_json"
int_arg_or_die "--check-timeout-sec" "$check_timeout_sec"

reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

if [[ -z "$summary_json" ]]; then
  summary_json="$ROOT_DIR/.easy-node-logs/gpm_wallet_auth_evidence_summary.json"
else
  summary_json="$(abs_path "$summary_json")"
fi
if [[ -z "$report_md" ]]; then
  report_md="$ROOT_DIR/.easy-node-logs/gpm_wallet_auth_evidence_report.md"
else
  report_md="$(abs_path "$report_md")"
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
reject_output_symlink_or_die "$summary_json"
reject_output_symlink_or_die "$report_md"

timeout_available=0
if command -v timeout >/dev/null 2>&1; then
  timeout_available=1
fi

declare -a check_ids=(
  "local_wallet_crypto_contracts"
  "strict_signature_metadata_contracts"
  "wallet_extension_source_policy"
  "local_control_api_wallet_session_contract"
  "web_portal_wallet_extension_contract"
)
declare -a check_names=(
  "Local wallet crypto contracts"
  "Strict signature metadata contracts"
  "Wallet-extension source policy contract"
  "Local Control API wallet-session contract"
  "Web portal wallet-extension contract"
)
declare -a check_commands=(
  "go test ./services/localapi -run '^(TestGPMAuthChallengeAndVerifyBindExpectedChainIDAndWalletHRP|TestGPMAuthVerifyRejectsMismatchedChainIDAgainstChallenge|TestGPMAuthVerifyRejectsChainIDNotBoundToChallenge|TestGPMAuthVerifyLocalSecp256k1WalletBindingMatchesDerivedAddress|TestGPMAuthVerifyLocalSecp256k1WalletBindingAcceptsCosmosPubKeyTypeAlias|TestGPMAuthVerifyWalletExtensionKeplrLeapAcceptAliasSecp256k1PubKeyTypes|TestGPMAuthVerifyRejectsManualSignatureSourceWhenWalletExtensionRequired|TestGPMAuthVerifyLocalSecp256k1WalletBindingMismatchUnboundAndStrictRejects|TestGPMAuthVerifyWalletExtensionMismatchedDerivedAddressRejectsAdminElevation|TestGPMAuthVerifyLocalSecp256k1WalletBindingChecksumHRPMismatchStaysUnbound|TestGPMAuthVerifyLocalSecp256k1BindingDoesNotReplaceCommandBackedAdminVerification)$' -count=1"
  "go test ./services/localapi -run 'TestGPMAuthVerifyRejects(InvalidOptionalSignatureMetadata|SignatureWithWhitespaceControlCharacters)' -count=1"
  "go test ./services/localapi -run '^(TestGPMAuthVerifyWalletExtensionKeplrLeapAcceptAliasSecp256k1PubKeyTypes|TestGPMAuthVerifyRejectsManualSignatureSourceWhenWalletExtensionRequired)$' -count=1"
  "bash ./scripts/integration_local_control_api_contract.sh"
  "bash ./scripts/integration_web_portal_contract.sh"
)
declare -a check_require_executed_go_tests=(
  1
  1
  1
  0
  0
)

checks_jsonl="$reports_dir/gpm_wallet_auth_evidence_checks.jsonl"
reject_output_symlink_or_die "$checks_jsonl"
: >"$checks_jsonl"

passed=0
failed=0
checks_total="${#check_ids[@]}"
started_at_utc="$(timestamp_utc)"

for ((idx = 0; idx < checks_total; idx++)); do
  check_id="${check_ids[$idx]}"
  check_name="${check_names[$idx]}"
  check_command="${check_commands[$idx]}"
  log_path="$reports_dir/$((idx + 1))_${check_id}.log"
  reject_output_symlink_or_die "$log_path"
  started_epoch="$(date +%s)"
  echo "[gpm-wallet-auth-evidence] check=$check_id status=running log_path=$log_path"
  set +e
  if [[ "$timeout_available" == "1" && "$check_timeout_sec" != "0" ]]; then
    timeout "$check_timeout_sec" bash -lc "$check_command" >"$log_path" 2>&1
    rc=$?
  else
    bash -lc "$check_command" >"$log_path" 2>&1
    rc=$?
  fi
  set -e
  finished_epoch="$(date +%s)"
  duration_sec=$((finished_epoch - started_epoch))
  timed_out=false
  if [[ "$rc" == "124" || "$rc" == "137" ]]; then
    timed_out=true
  fi
  no_tests_detected=false
  if [[ "${check_require_executed_go_tests[$idx]}" == "1" && "$rc" -eq 0 ]]; then
    if grep -Eiq '(^|[[:space:]])(no tests to run|\[no tests to run\]|\[no test files\])($|[[:space:]])' "$log_path"; then
      no_tests_detected=true
      rc=1
      echo "gpm-wallet-auth-evidence: refusing vacuous go test pass for $check_id; matched no-test output" >>"$log_path"
    fi
  fi
  check_status="pass"
  if [[ "$rc" -ne 0 ]]; then
    check_status="fail"
    failed=$((failed + 1))
  else
    passed=$((passed + 1))
  fi
  jq -nc \
    --arg id "$check_id" \
    --arg name "$check_name" \
    --arg command "$check_command" \
    --arg status "$check_status" \
    --arg log_path "$log_path" \
    --argjson rc "$rc" \
    --argjson duration_sec "$duration_sec" \
    --argjson timed_out "$timed_out" \
    --argjson no_tests_detected "$no_tests_detected" \
    '{
      id: $id,
      name: $name,
      command: $command,
      status: $status,
      rc: $rc,
      timed_out: $timed_out,
      no_tests_detected: $no_tests_detected,
      duration_sec: $duration_sec,
      log_path: $log_path
    }' >>"$checks_jsonl"
  echo "[gpm-wallet-auth-evidence] check=$check_id status=$check_status rc=$rc duration_sec=$duration_sec timed_out=$timed_out"
done

checks_json="$(jq -s '.' "$checks_jsonl")"
status="pass"
rc=0
if ((failed > 0)); then
  status="fail"
  rc=1
fi
finished_at_utc="$(timestamp_utc)"

local_wallet_contract_pass="$(jq -r '.[] | select(.id == "local_wallet_crypto_contracts") | .status == "pass"' <<<"$checks_json")"
metadata_contract_pass="$(jq -r '.[] | select(.id == "strict_signature_metadata_contracts") | .status == "pass"' <<<"$checks_json")"
wallet_source_policy_pass="$(jq -r '.[] | select(.id == "wallet_extension_source_policy") | .status == "pass"' <<<"$checks_json")"
local_control_contract_pass="$(jq -r '.[] | select(.id == "local_control_api_wallet_session_contract") | .status == "pass"' <<<"$checks_json")"
portal_contract_pass="$(jq -r '.[] | select(.id == "web_portal_wallet_extension_contract") | .status == "pass"' <<<"$checks_json")"
no_vacuous_go_tests="$(jq -r '[.[] | select(.no_tests_detected == true)] | length == 0' <<<"$checks_json")"

jq -n \
  --arg generated_at_utc "$finished_at_utc" \
  --arg started_at_utc "$started_at_utc" \
  --arg finished_at_utc "$finished_at_utc" \
  --arg status "$status" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --argjson rc "$rc" \
  --argjson checks "$checks_json" \
  --argjson checks_total "$checks_total" \
  --argjson checks_passed "$passed" \
  --argjson checks_failed "$failed" \
  --argjson check_timeout_sec "$check_timeout_sec" \
  --argjson timeout_available "$([[ "$timeout_available" == "1" ]] && echo true || echo false)" \
  --argjson local_wallet_contract_pass "$local_wallet_contract_pass" \
  --argjson metadata_contract_pass "$metadata_contract_pass" \
  --argjson wallet_source_policy_pass "$wallet_source_policy_pass" \
  --argjson local_control_contract_pass "$local_control_contract_pass" \
  --argjson portal_contract_pass "$portal_contract_pass" \
  --argjson no_vacuous_go_tests "$no_vacuous_go_tests" \
  '{
    version: 1,
    schema: {
      id: "gpm_wallet_auth_evidence_summary",
      major: 1,
      minor: 0
    },
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: $rc,
    notes: (if $status == "pass" then "GPM wallet-auth evidence checks passed" else "GPM wallet-auth evidence checks failed" end),
    inputs: {
      reports_dir: $reports_dir,
      check_timeout_sec: $check_timeout_sec,
      timeout_available: $timeout_available
    },
    summary: {
      checks_total: $checks_total,
      checks_passed: $checks_passed,
      checks_failed: $checks_failed
    },
    evidence: {
      keplr_wallet_extension_alias_pubkey_types: $local_wallet_contract_pass,
      leap_wallet_extension_alias_pubkey_types: $local_wallet_contract_pass,
      secp256k1_wallet_binding: $local_wallet_contract_pass,
      mismatched_wallet_rejection: $local_wallet_contract_pass,
      admin_elevation_rejection: $local_wallet_contract_pass,
      chain_id_hrp_binding: $local_wallet_contract_pass,
      signature_metadata_validation: $metadata_contract_pass,
      wallet_extension_source_policy: $wallet_source_policy_pass,
      local_control_api_session_binding: $local_control_contract_pass,
      admin_console_command_backed_only: ($local_wallet_contract_pass and $local_control_contract_pass),
      portal_wallet_extension_contract: $portal_contract_pass,
      public_app_admin_free: $portal_contract_pass,
      no_vacuous_go_test_evidence: $no_vacuous_go_tests,
      real_browser_extension_beta_evidence: false
    },
    release_evidence: {
      real_browser_extension_beta_evidence: {
        status: "pending",
        required_for_release: true,
        keplr_installed_extension_evidence: false,
        leap_installed_extension_evidence: false,
        notes: "Deterministic local tests prove request/verification contracts only; installed Keplr/Leap browser-extension evidence remains a separate beta/release artifact."
      }
    },
    checks: $checks,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      report_md: $report_md,
      checks_jsonl: ($reports_dir + "/gpm_wallet_auth_evidence_checks.jsonl")
    },
    timing: {
      started_at_utc: $started_at_utc,
      finished_at_utc: $finished_at_utc
    }
  }' >"$summary_json"

{
  echo "# GPM Wallet Auth Evidence"
  echo
  echo "- Status: \`$status\`"
  echo "- Generated: \`$finished_at_utc\`"
  echo "- Checks: $passed/$checks_total passed"
  echo
  echo "## Evidence"
  jq -r '.evidence | to_entries[] | "- \(.key): `\(.value)`"' "$summary_json"
  echo
  echo "## Checks"
  jq -r '.checks[] | "- \(.id): `\(.status)` rc=`\(.rc)` log=`\(.log_path)`"' "$summary_json"
  echo
  echo "## Scope"
  echo "This is deterministic local evidence for wallet-auth contracts. Real browser-extension beta evidence with installed Keplr/Leap remains a separate release artifact."
} >"$report_md"

echo "gpm-wallet-auth-evidence: status=$status"
echo "summary_json: $summary_json"
echo "report_md: $report_md"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

exit "$rc"
