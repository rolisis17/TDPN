#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

run_id="$(date -u +%Y%m%d_%H%M%S)"
reports_dir="${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_REPORTS_DIR:-.easy-node-logs/access-recovery-pilot}"

base_url=""
path_id="helper-web"
code=""
code_file=""
cacert=""
client_cert=""
client_key=""
config_json=""
deploy_pack_dir=""
service_name="gpm-access-bridge"
expect_helper_id=""
expect_org_id=""
expect_registry_id=""
provenance_private_key_file=""
provenance_org_id=""
provenance_org_name=""
provenance_key_id=""
provenance_lifetime_hours=""
trust_store=""
bundle_summary_json=""
provenance_out=""
verification_summary_json=""
roadmap_refresh="${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_ROADMAP_REFRESH:-1}"
roadmap_summary_json=""
roadmap_report_md=""
summary_json=""
report_md=""
print_summary_json="${ACCESS_RECOVERY_REAL_HELPER_EVIDENCE_RUN_PRINT_SUMMARY_JSON:-1}"
print_child_json="0"

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_recovery_real_helper_evidence_run.sh \
    --base-url https://HELPER_PUBLIC_DNS \
    --config-json FILE \
    --deploy-pack-dir DIR \
    (--code CODE | --code-file FILE) \
    --provenance-private-key-file FILE \
    --provenance-org-id ORG_ID \
    --provenance-org-name ORG_NAME \
    --trust-store FILE \
    [--path-id helper-web] \
    [--cacert FILE] \
    [--client-cert FILE --client-key FILE] \
    [--expect-helper-id ID] \
    [--expect-org-id ID] \
    [--expect-registry-id ID] \
    [--reports-dir DIR] \
    [--bundle-summary-json FILE] \
    [--provenance-out FILE] \
    [--verification-summary-json FILE] \
    [--roadmap-refresh 0|1] \
    [--roadmap-summary-json FILE] \
    [--roadmap-report-md FILE] \
    [--summary-json FILE] \
    [--report-md FILE] \
    [--print-summary-json 0|1] \
    [--print-child-json 0|1]

Purpose:
  Run the real public Access Recovery helper evidence flow as one operator-safe
  command:
  1. capture the HTTPS pilot evidence bundle with signed provenance
  2. verify it with trusted provenance and write the verifier receipt
  3. refresh roadmap readiness against that verifier receipt

This wrapper is intentionally stricter than local rehearsal helpers. It refuses
placeholder values, loopback/private-looking helper URLs, missing trust stores,
and unsigned provenance inputs before running the evidence tools.
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

bool_arg_or_die() {
  local name="$1"
  local value="$2"
  if [[ "$value" != "0" && "$value" != "1" ]]; then
    echo "$name must be 0 or 1" >&2
    exit 2
  fi
}

require_value_or_die() {
  local flag="$1"
  if [[ $# -lt 2 || -z "${2:-}" ]]; then
    echo "$flag requires a value" >&2
    exit 2
  fi
}

need_cmd() {
  local cmd="$1"
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access recovery real helper evidence run failed: missing required command: $cmd" >&2
    exit 2
  fi
}

value_looks_placeholder() {
  local value
  value="$(trim "${1:-}")"
  [[ -z "$value" ]] && return 0
  case "$value" in
    PATH|FILE|DIR|URL|HELPER_PUBLIC_DNS|TRUST_STORE|ACCESS_RECOVERY_TRUST_STORE|PROVENANCE_PRIVATE_KEY_FILE|ORG_ID|ORG_NAME|REPLACE_WITH_*|"<"*">")
      return 0
      ;;
  esac
  if [[ "$value" == *HELPER_PUBLIC_DNS* || "$value" == *REPLACE_WITH_* || "$value" == *PROVENANCE_PRIVATE_KEY_FILE* || "$value" == *TRUST_STORE* ]]; then
    return 0
  fi
  return 1
}

url_authority() {
  local rest="${1:-}"
  rest="${rest#*://}"
  rest="${rest%%/*}"
  rest="${rest%%\?*}"
  rest="${rest%%#*}"
  printf '%s' "$rest"
}

normalize_host() {
  local host="${1:-}"
  host="$(printf '%s' "$host" | tr '[:upper:]' '[:lower:]')"
  while [[ "$host" == *. ]]; do
    host="${host%.}"
  done
  printf '%s' "$host"
}

url_host() {
  local rest
  rest="$(url_authority "$1")"
  rest="${rest##*@}"
  if [[ "$rest" == \[*\]* ]]; then
    rest="${rest#\[}"
    normalize_host "${rest%%\]*}"
  else
    rest="${rest%%:*}"
    normalize_host "$rest"
  fi
}

host_looks_non_public_for_real_helper() {
  local host="$1"
  [[ -z "$host" ]] && return 0
  case "$host" in
    localhost|*.localhost|*.local|*.lan|*.internal|*.test|*.invalid|*.example|*.example.com|*.example.net|*.example.org|*.ts.net|*.tailscale.net|ts.net|tailscale.net)
      return 0
      ;;
  esac
  if [[ "$host" == *:* ]]; then
    case "$host" in
      ::1|0:0:0:0:0:0:0:1|fc*|fd*|fe80:*|2001:db8:*)
        return 0
        ;;
      *)
        return 1
        ;;
    esac
  fi
  case "$host" in
    127.*|10.*|192.168.*|169.254.*|0.*)
      return 0
      ;;
    100.*)
      local second="${host#100.}"
      second="${second%%.*}"
      if [[ "$second" =~ ^[0-9]+$ && "$second" -ge 64 && "$second" -le 127 ]]; then
        return 0
      fi
      ;;
    172.*)
      local second="${host#172.}"
      second="${second%%.*}"
      if [[ "$second" =~ ^[0-9]+$ && "$second" -ge 16 && "$second" -le 31 ]]; then
        return 0
      fi
      ;;
    ::1|0:0:0:0:0:0:0:1)
      return 0
      ;;
  esac
  [[ "$host" != *.* ]] && return 0
  return 1
}

json_file_or_null() {
  local file
  file="$(trim "${1:-}")"
  if [[ -n "$file" && -f "$file" ]]; then
    jq -c '.' "$file" 2>/dev/null || printf '%s' "null"
  else
    printf '%s' "null"
  fi
}

first_nonempty() {
  local value
  for value in "$@"; do
    if [[ -n "$(trim "${value:-}")" ]]; then
      printf '%s' "$value"
      return 0
    fi
  done
  printf '%s' ""
}

print_failure_log_tail() {
  local label="$1"
  local file="$2"
  if [[ -f "$file" ]]; then
    echo "$label failed; last log lines:" >&2
    tail -n 80 "$file" >&2 || true
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help|-h)
      usage
      exit 0
      ;;
    --base-url)
      require_value_or_die "$1" "${2:-}"
      base_url="$2"
      shift 2
      ;;
    --path-id)
      require_value_or_die "$1" "${2:-}"
      path_id="$2"
      shift 2
      ;;
    --code)
      require_value_or_die "$1" "${2:-}"
      code="$2"
      shift 2
      ;;
    --code-file)
      require_value_or_die "$1" "${2:-}"
      code_file="$2"
      shift 2
      ;;
    --cacert)
      require_value_or_die "$1" "${2:-}"
      cacert="$2"
      shift 2
      ;;
    --client-cert)
      require_value_or_die "$1" "${2:-}"
      client_cert="$2"
      shift 2
      ;;
    --client-key)
      require_value_or_die "$1" "${2:-}"
      client_key="$2"
      shift 2
      ;;
    --config-json)
      require_value_or_die "$1" "${2:-}"
      config_json="$2"
      shift 2
      ;;
    --deploy-pack-dir)
      require_value_or_die "$1" "${2:-}"
      deploy_pack_dir="$2"
      shift 2
      ;;
    --service-name)
      require_value_or_die "$1" "${2:-}"
      service_name="$2"
      shift 2
      ;;
    --expect-helper-id)
      require_value_or_die "$1" "${2:-}"
      expect_helper_id="$2"
      shift 2
      ;;
    --expect-org-id)
      require_value_or_die "$1" "${2:-}"
      expect_org_id="$2"
      shift 2
      ;;
    --expect-registry-id)
      require_value_or_die "$1" "${2:-}"
      expect_registry_id="$2"
      shift 2
      ;;
    --provenance-private-key-file)
      require_value_or_die "$1" "${2:-}"
      provenance_private_key_file="$2"
      shift 2
      ;;
    --provenance-org-id)
      require_value_or_die "$1" "${2:-}"
      provenance_org_id="$2"
      shift 2
      ;;
    --provenance-org-name)
      require_value_or_die "$1" "${2:-}"
      provenance_org_name="$2"
      shift 2
      ;;
    --provenance-key-id)
      require_value_or_die "$1" "${2:-}"
      provenance_key_id="$2"
      shift 2
      ;;
    --provenance-lifetime-hours)
      require_value_or_die "$1" "${2:-}"
      provenance_lifetime_hours="$2"
      shift 2
      ;;
    --trust-store)
      require_value_or_die "$1" "${2:-}"
      trust_store="$2"
      shift 2
      ;;
    --reports-dir)
      require_value_or_die "$1" "${2:-}"
      reports_dir="$2"
      shift 2
      ;;
    --bundle-summary-json)
      require_value_or_die "$1" "${2:-}"
      bundle_summary_json="$2"
      shift 2
      ;;
    --provenance-out)
      require_value_or_die "$1" "${2:-}"
      provenance_out="$2"
      shift 2
      ;;
    --verification-summary-json)
      require_value_or_die "$1" "${2:-}"
      verification_summary_json="$2"
      shift 2
      ;;
    --roadmap-refresh)
      require_value_or_die "$1" "${2:-}"
      roadmap_refresh="$2"
      shift 2
      ;;
    --roadmap-summary-json)
      require_value_or_die "$1" "${2:-}"
      roadmap_summary_json="$2"
      shift 2
      ;;
    --roadmap-report-md)
      require_value_or_die "$1" "${2:-}"
      roadmap_report_md="$2"
      shift 2
      ;;
    --summary-json)
      require_value_or_die "$1" "${2:-}"
      summary_json="$2"
      shift 2
      ;;
    --report-md)
      require_value_or_die "$1" "${2:-}"
      report_md="$2"
      shift 2
      ;;
    --print-summary-json)
      require_value_or_die "$1" "${2:-}"
      print_summary_json="$2"
      shift 2
      ;;
    --print-child-json)
      require_value_or_die "$1" "${2:-}"
      print_child_json="$2"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for cmd in date dirname jq mkdir tail; do
  need_cmd "$cmd"
done

bool_arg_or_die "--roadmap-refresh" "$roadmap_refresh"
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--print-child-json" "$print_child_json"

reports_dir="$(abs_path "$reports_dir")"
mkdir -p "$reports_dir"

bundle_summary_json="$(abs_path "$(first_nonempty "$bundle_summary_json" "$reports_dir/access_bridge_pilot_evidence_${run_id}.json")")"
provenance_out="$(abs_path "$(first_nonempty "$provenance_out" "$reports_dir/access_bridge_pilot_evidence_${run_id}.provenance.json")")"
verification_summary_json="$(abs_path "$(first_nonempty "$verification_summary_json" "$reports_dir/access_bridge_pilot_evidence_verify_${run_id}.json")")"
roadmap_summary_json="$(abs_path "$(first_nonempty "$roadmap_summary_json" "$reports_dir/roadmap_progress_${run_id}.json")")"
roadmap_report_md="$(abs_path "$(first_nonempty "$roadmap_report_md" "$reports_dir/roadmap_progress_${run_id}.md")")"
summary_json="$(abs_path "$(first_nonempty "$summary_json" "$reports_dir/access_recovery_real_helper_evidence_run_${run_id}.json")")"
report_md="$(abs_path "$(first_nonempty "$report_md" "$reports_dir/access_recovery_real_helper_evidence_run_${run_id}.md")")"

bundle_log="$reports_dir/access_recovery_real_helper_evidence_run_${run_id}_bundle.log"
verify_log="$reports_dir/access_recovery_real_helper_evidence_run_${run_id}_verify.log"
roadmap_log="$reports_dir/access_recovery_real_helper_evidence_run_${run_id}_roadmap.log"

config_json="$(abs_path "$config_json")"
deploy_pack_dir="$(abs_path "$deploy_pack_dir")"
code_file="$(abs_path "$code_file")"
cacert="$(abs_path "$cacert")"
client_cert="$(abs_path "$client_cert")"
client_key="$(abs_path "$client_key")"
provenance_private_key_file="$(abs_path "$provenance_private_key_file")"
trust_store="$(abs_path "$trust_store")"

write_summary() {
  local status="$1"
  local rc="$2"
  local stage="$3"
  local notes="$4"
  local generated_at_utc
  local bundle_obj verify_obj roadmap_obj pilot_ready roadmap_ready evidence_scope verifier_scope
  local code_present_json code_file_present_json
  local roadmap_refresh_json
  generated_at_utc="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  bundle_obj="$(json_file_or_null "$bundle_summary_json")"
  verify_obj="$(json_file_or_null "$verification_summary_json")"
  roadmap_obj="$(json_file_or_null "$roadmap_summary_json")"
  pilot_ready="$(printf '%s\n' "$verify_obj" | jq -r 'if type == "object" then (.pilot_handoff_ready // false | tostring) else "false" end')"
  roadmap_ready="$(printf '%s\n' "$roadmap_obj" | jq -r 'if type == "object" then (.access_recovery_pilot_handoff_ready // false | tostring) else "false" end')"
  evidence_scope="$(printf '%s\n' "$bundle_obj" | jq -r 'if type == "object" then (.evidence_scope // "") else "" end')"
  verifier_scope="$(printf '%s\n' "$verify_obj" | jq -r 'if type == "object" then ((.details.evidence_scope // .trusted_provenance.evidence_scope // .evidence_scope // "") | tostring) else "" end')"
  if [[ -n "$code" ]]; then
    code_present_json="true"
  else
    code_present_json="false"
  fi
  if [[ -n "$code_file" ]]; then
    code_file_present_json="true"
  else
    code_file_present_json="false"
  fi
  if [[ "$roadmap_refresh" == "1" ]]; then
    roadmap_refresh_json="true"
  else
    roadmap_refresh_json="false"
  fi
  mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"
  jq -n \
    --arg generated_at_utc "$generated_at_utc" \
    --arg status "$status" \
    --argjson rc "$rc" \
    --arg stage "$stage" \
    --arg notes "$notes" \
    --arg base_url "$base_url" \
    --arg path_id "$path_id" \
    --arg reports_dir "$reports_dir" \
    --arg bundle_summary_json "$bundle_summary_json" \
    --arg bundle_log "$bundle_log" \
    --arg provenance_json "$provenance_out" \
    --arg verification_summary_json "$verification_summary_json" \
    --arg verify_log "$verify_log" \
    --arg roadmap_summary_json "$roadmap_summary_json" \
    --arg roadmap_report_md "$roadmap_report_md" \
    --arg roadmap_log "$roadmap_log" \
    --arg summary_json "$summary_json" \
    --arg report_md "$report_md" \
    --arg evidence_scope "$evidence_scope" \
    --arg verifier_scope "$verifier_scope" \
    --argjson code_present "$code_present_json" \
    --argjson code_file_present "$code_file_present_json" \
    --argjson pilot_handoff_ready "$pilot_ready" \
    --argjson roadmap_ready "$roadmap_ready" \
    --argjson roadmap_refresh "$roadmap_refresh_json" \
    --argjson bundle "$bundle_obj" \
    --argjson verifier "$verify_obj" \
    --argjson roadmap "$roadmap_obj" \
    '{
      version: 1,
      schema: {id: "access_recovery_real_helper_evidence_run_summary", major: 1, minor: 0},
      generated_at_utc: $generated_at_utc,
      status: $status,
      rc: $rc,
      stage: $stage,
      notes: $notes,
      inputs: {
        base_url: $base_url,
        path_id: $path_id,
        code_present: $code_present,
        code_file_present: $code_file_present,
        roadmap_refresh: $roadmap_refresh
      },
      readiness: {
        evidence_scope: (if $evidence_scope == "" then null else $evidence_scope end),
        verifier_evidence_scope: (if $verifier_scope == "" then null else $verifier_scope end),
        trusted_verifier_pilot_handoff_ready: $pilot_handoff_ready,
        roadmap_access_recovery_pilot_handoff_ready: $roadmap_ready
      },
      child_summaries: {
        bundle: $bundle,
        verifier: $verifier,
        roadmap: $roadmap
      },
      artifacts: {
        reports_dir: $reports_dir,
        bundle_summary_json: $bundle_summary_json,
        bundle_log: $bundle_log,
        provenance_json: $provenance_json,
        verification_summary_json: $verification_summary_json,
        verify_log: $verify_log,
        roadmap_summary_json: $roadmap_summary_json,
        roadmap_report_md: $roadmap_report_md,
        roadmap_log: $roadmap_log,
        summary_json: $summary_json,
        report_md: $report_md
      }
    }' >"$summary_json"

  cat >"$report_md" <<REPORT
# Access Recovery Real Helper Evidence Run

- Status: ${status}
- Stage: ${stage}
- Notes: ${notes}
- Base URL: ${base_url}
- Bundle summary: ${bundle_summary_json}
- Verifier receipt: ${verification_summary_json}
- Roadmap summary: ${roadmap_summary_json}
- Summary JSON: ${summary_json}
REPORT
}

fail_preflight() {
  local message="$1"
  write_summary "fail" 2 "preflight" "$message"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=preflight" >&2
  echo "$message" >&2
  echo "summary_json: $summary_json" >&2
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit 2
}

if value_looks_placeholder "$base_url"; then
  fail_preflight "--base-url must be a real public HTTPS helper URL"
fi
if [[ "$(printf '%s' "$base_url" | tr '[:upper:]' '[:lower:]')" != https://* ]]; then
  fail_preflight "--base-url must use https:// for real helper evidence"
fi
host="$(url_host "$base_url")"
if host_looks_non_public_for_real_helper "$host"; then
  fail_preflight "--base-url host must look public-routable for real helper evidence: ${host:-<missing>}"
fi
if [[ -n "$code" && -n "$code_file" ]]; then
  fail_preflight "use either --code or --code-file, not both"
fi
if [[ -z "$code" && -z "$code_file" ]]; then
  fail_preflight "one of --code or --code-file is required"
fi
if [[ -n "$code_file" && ! -f "$code_file" ]]; then
  fail_preflight "--code-file not found: $code_file"
fi
if [[ ! -f "$config_json" ]]; then
  fail_preflight "--config-json not found: $config_json"
fi
if [[ ! -d "$deploy_pack_dir" ]]; then
  fail_preflight "--deploy-pack-dir not found: $deploy_pack_dir"
fi
if value_looks_placeholder "$provenance_private_key_file" || [[ ! -f "$provenance_private_key_file" ]]; then
  fail_preflight "--provenance-private-key-file must point to a real signing key"
fi
if value_looks_placeholder "$provenance_org_id"; then
  fail_preflight "--provenance-org-id must be a real organization id"
fi
if value_looks_placeholder "$provenance_org_name"; then
  fail_preflight "--provenance-org-name must be a real organization name"
fi
if value_looks_placeholder "$trust_store" || [[ ! -f "$trust_store" ]]; then
  fail_preflight "--trust-store must point to a real trusted verifier trust store"
fi
if [[ -n "$cacert" && ! -f "$cacert" ]]; then
  fail_preflight "--cacert not found: $cacert"
fi
if [[ -n "$client_cert" && ! -f "$client_cert" ]]; then
  fail_preflight "--client-cert not found: $client_cert"
fi
if [[ -n "$client_key" && ! -f "$client_key" ]]; then
  fail_preflight "--client-key not found: $client_key"
fi
if [[ -n "$client_cert" && -z "$client_key" || -z "$client_cert" && -n "$client_key" ]]; then
  fail_preflight "--client-cert and --client-key must be supplied together"
fi

bundle_script="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_SCRIPT:-$ROOT_DIR/scripts/access_bridge_pilot_evidence_bundle.sh}"
verify_script="${ACCESS_BRIDGE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT:-$ROOT_DIR/scripts/access_bridge_pilot_evidence_bundle_verify.sh}"
roadmap_script="${ROADMAP_PROGRESS_REPORT_SCRIPT:-$ROOT_DIR/scripts/roadmap_progress_report.sh}"
[[ -x "$bundle_script" ]] || fail_preflight "missing executable bundle script: $bundle_script"
[[ -x "$verify_script" ]] || fail_preflight "missing executable verifier script: $verify_script"
if [[ "$roadmap_refresh" == "1" && ! -x "$roadmap_script" ]]; then
  fail_preflight "missing executable roadmap script: $roadmap_script"
fi

bundle_args=(
  --base-url "$base_url"
  --path-id "$path_id"
  --config-json "$config_json"
  --deploy-pack-dir "$deploy_pack_dir"
  --service-name "$service_name"
  --summary-json "$bundle_summary_json"
  --provenance-sign 1
  --provenance-private-key-file "$provenance_private_key_file"
  --provenance-org-id "$provenance_org_id"
  --provenance-org-name "$provenance_org_name"
  --provenance-out "$provenance_out"
  --require-https 1
  --require-public-host 1
  --print-summary-json "$print_child_json"
)
if [[ -n "$code_file" ]]; then
  bundle_args+=(--code-file "$code_file")
else
  bundle_args+=(--code "$code")
fi
[[ -z "$cacert" ]] || bundle_args+=(--cacert "$cacert")
[[ -z "$client_cert" ]] || bundle_args+=(--client-cert "$client_cert")
[[ -z "$client_key" ]] || bundle_args+=(--client-key "$client_key")
[[ -z "$expect_helper_id" ]] || bundle_args+=(--expect-helper-id "$expect_helper_id")
[[ -z "$expect_org_id" ]] || bundle_args+=(--expect-org-id "$expect_org_id")
[[ -z "$expect_registry_id" ]] || bundle_args+=(--expect-registry-id "$expect_registry_id")
[[ -z "$provenance_key_id" ]] || bundle_args+=(--provenance-key-id "$provenance_key_id")
[[ -z "$provenance_lifetime_hours" ]] || bundle_args+=(--provenance-lifetime-hours "$provenance_lifetime_hours")

set +e
"$bundle_script" "${bundle_args[@]}" >"$bundle_log" 2>&1
bundle_rc=$?
set -e
if [[ "$bundle_rc" -ne 0 ]]; then
  write_summary "fail" "$bundle_rc" "bundle" "Access bridge pilot evidence bundle failed"
  print_failure_log_tail "bundle" "$bundle_log"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=bundle"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit "$bundle_rc"
fi

verify_args=(
  --summary-json "$bundle_summary_json"
  --provenance-json "$provenance_out"
  --trust-store "$trust_store"
  --require-trusted-provenance 1
  --verification-summary-json "$verification_summary_json"
  --print-verification-summary-json "$print_child_json"
)

set +e
"$verify_script" "${verify_args[@]}" >"$verify_log" 2>&1
verify_rc=$?
set -e
if [[ "$verify_rc" -ne 0 ]]; then
  write_summary "fail" "$verify_rc" "verify" "Trusted pilot evidence verifier failed"
  print_failure_log_tail "verifier" "$verify_log"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=verify"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit "$verify_rc"
fi

verifier_ready="$(jq -r '.pilot_handoff_ready // false | tostring' "$verification_summary_json" 2>/dev/null || printf '%s' "false")"
if [[ "$verifier_ready" != "true" ]]; then
  write_summary "fail" 1 "verify" "Trusted verifier receipt did not mark pilot_handoff_ready=true"
  echo "access-recovery-real-helper-evidence-run: status=fail stage=verify"
  echo "summary_json: $summary_json"
  [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
  exit 1
fi

if [[ "$roadmap_refresh" == "1" ]]; then
  roadmap_args=(
    --refresh-manual-validation 0
    --refresh-single-machine-readiness 0
    --access-bridge-pilot-evidence-bundle-verify-summary-json "$verification_summary_json"
    --summary-json "$roadmap_summary_json"
    --report-md "$roadmap_report_md"
    --print-summary-json 0
  )
  set +e
  "$roadmap_script" "${roadmap_args[@]}" >"$roadmap_log" 2>&1
  roadmap_rc=$?
  set -e
  if [[ "$roadmap_rc" -ne 0 ]]; then
    write_summary "fail" "$roadmap_rc" "roadmap" "Roadmap refresh failed after trusted evidence verification"
    print_failure_log_tail "roadmap" "$roadmap_log"
    echo "access-recovery-real-helper-evidence-run: status=fail stage=roadmap"
    echo "summary_json: $summary_json"
    [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
    exit "$roadmap_rc"
  fi
  roadmap_ready="$(jq -r '.access_recovery_pilot_handoff_ready // false | tostring' "$roadmap_summary_json" 2>/dev/null || printf '%s' "false")"
  if [[ "$roadmap_ready" != "true" ]]; then
    write_summary "fail" 1 "roadmap" "Roadmap did not mark Access Recovery pilot handoff ready"
    echo "access-recovery-real-helper-evidence-run: status=fail stage=roadmap"
    echo "summary_json: $summary_json"
    [[ "$print_summary_json" == "1" ]] && cat "$summary_json"
    exit 1
  fi
fi

write_summary "pass" 0 "complete" "Real helper HTTPS evidence and trusted verifier receipt completed"
echo "access-recovery-real-helper-evidence-run: status=pass stage=complete"
echo "summary_json: $summary_json"
echo "verification_summary_json: $verification_summary_json"
if [[ "$roadmap_refresh" == "1" ]]; then
  echo "roadmap_summary_json: $roadmap_summary_json"
fi
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi
