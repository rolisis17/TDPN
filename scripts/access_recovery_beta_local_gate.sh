#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/access_recovery_beta_local_gate.sh \
    [--reports-dir DIR] \
    [--summary-json PATH] \
    [--report-md PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run the focused local Access Recovery beta gate without running the legacy
  VPN/GPM production matrix. This checks the signed artifact demo/examples,
  browser-local verifier flow, local bridge service evidence, host-install
  checks, pilot evidence bundle generation, and the trusted verifier receipt
  contract plus real-helper evidence-run wrapper required for pilot handoff.

Notes:
  Live real helper HTTPS deployment evidence is still a separate real-host gate.

Environment:
  ACCESS_RECOVERY_BETA_LOCAL_GATE_ALLOW_CUSTOM_STEP_SCRIPTS=1 permits step
  script overrides outside this repository's scripts/ tree. The default is 0
  so copied or CI commands cannot silently execute arbitrary local paths.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "access recovery beta local gate failed: missing required command: $1" >&2
    exit 2
  fi
}

timestamp_utc() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

timestamp_file() {
  date -u +%Y%m%d_%H%M%S
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

path_arg_or_die() {
  local name="$1"
  local value="$2"
  value="$(trim "$value")"
  if [[ -z "$value" ]]; then
    echo "$name requires a value" >&2
    exit 2
  fi
  case "$value" in
    -*)
      echo "$name requires a path value, got flag-like token: $value" >&2
      exit 2
      ;;
  esac
}

reports_dir="$ROOT_DIR/.easy-node-logs/access_recovery_beta_local_gate_$(timestamp_file)"
summary_json=""
report_md=""
print_summary_json="1"
allow_custom_step_scripts="${ACCESS_RECOVERY_BETA_LOCAL_GATE_ALLOW_CUSTOM_STEP_SCRIPTS:-0}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reports-dir)
      path_arg_or_die "--reports-dir" "${2:-}"
      reports_dir="$(abs_path "${2:-}")"
      shift 2
      ;;
    --summary-json)
      path_arg_or_die "--summary-json" "${2:-}"
      summary_json="$(abs_path "${2:-}")"
      shift 2
      ;;
    --report-md)
      path_arg_or_die "--report-md" "${2:-}"
      report_md="$(abs_path "${2:-}")"
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
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

for cmd in bash date dirname jq mkdir mktemp rm; do
  need_cmd "$cmd"
done
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "ACCESS_RECOVERY_BETA_LOCAL_GATE_ALLOW_CUSTOM_STEP_SCRIPTS" "$allow_custom_step_scripts"

mkdir -p "$reports_dir"
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/access_recovery_beta_local_gate_summary.json"
fi
if [[ -z "$report_md" ]]; then
  report_md="$reports_dir/access_recovery_beta_local_gate_report.md"
fi
mkdir -p "$(dirname "$summary_json")" "$(dirname "$report_md")"

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT
steps_jsonl="$tmp_dir/steps.jsonl"
: >"$steps_jsonl"

step_script() {
  local env_name="$1"
  local default_script="$2"
  local configured="${!env_name:-}"
  if [[ -n "$(trim "$configured")" ]]; then
    abs_path "$configured"
  else
    printf '%s' "$ROOT_DIR/$default_script"
  fi
}

canonical_existing_path() {
  local path
  local dir
  local base
  path="$(abs_path "${1:-}")"
  if command -v realpath >/dev/null 2>&1; then
    realpath "$path" 2>/dev/null && return 0
  fi
  dir="${path%/*}"
  base="${path##*/}"
  if [[ -n "$dir" && "$dir" != "$path" && -d "$dir" ]]; then
    (cd "$dir" && printf '%s/%s\n' "$(pwd -P)" "$base")
  else
    printf '%s\n' "$path"
  fi
}

custom_step_script_allowed() {
  local script="$1"
  local canonical_script
  local canonical_scripts_root
  canonical_script="$(canonical_existing_path "$script")"
  canonical_scripts_root="$(canonical_existing_path "$ROOT_DIR/scripts")"
  if [[ "$canonical_script" == "$canonical_scripts_root" || "$canonical_script" == "$canonical_scripts_root/"* ]]; then
    return 0
  fi
  [[ "$allow_custom_step_scripts" == "1" ]]
}

append_step() {
  local id="$1"
  local label="$2"
  local status="$3"
  local rc="$4"
  local command="$5"
  local log="$6"
  jq -nc \
    --arg id "$id" \
    --arg step_label "$label" \
    --arg status "$status" \
    --arg command "$command" \
    --arg log "$log" \
    --argjson rc "$rc" \
    '{id:$id,label:$step_label,status:$status,rc:$rc,command:$command,log:$log}' >>"$steps_jsonl"
}

run_step() {
  local id="$1"
  local label="$2"
  local env_name="$3"
  local default_script="$4"
  local script
  local log
  local rc
  local status
  local configured
  script="$(step_script "$env_name" "$default_script")"
  configured="$(trim "${!env_name:-}")"
  log="$reports_dir/${id}.log"

  if [[ -n "$configured" ]] && ! custom_step_script_allowed "$script"; then
    {
      printf 'custom step script refused: %s\n' "$script"
      printf 'env override: %s\n' "$env_name"
      printf 'reason: step script overrides outside repository scripts/ require ACCESS_RECOVERY_BETA_LOCAL_GATE_ALLOW_CUSTOM_STEP_SCRIPTS=1\n'
    } >"$log"
    append_step "$id" "$label" "fail" 2 "bash $script" "$log"
    return
  fi

  if [[ ! -f "$script" ]]; then
    printf 'missing script: %s\n' "$script" >"$log"
    append_step "$id" "$label" "fail" 2 "bash $script" "$log"
    return
  fi

  set +e
  bash "$script" >"$log" 2>&1
  rc=$?
  set -e

  status="pass"
  if [[ "$rc" -ne 0 ]]; then
    status="fail"
  fi
  append_step "$id" "$label" "$status" "$rc" "bash $script" "$log"
}

run_step "demo_contract" "Access Recovery demo contract" "ACCESS_RECOVERY_BETA_LOCAL_GATE_DEMO_CONTRACT_SCRIPT" "scripts/integration_access_recovery_demo_contract.sh"
run_step "examples_contract" "Access Recovery checked examples contract" "ACCESS_RECOVERY_BETA_LOCAL_GATE_EXAMPLES_CONTRACT_SCRIPT" "scripts/integration_access_recovery_examples_contract.sh"
run_step "browser_smoke" "Browser-local recovery verifier smoke" "ACCESS_RECOVERY_BETA_LOCAL_GATE_BROWSER_SMOKE_SCRIPT" "scripts/integration_recovery_browser_smoke.sh"
run_step "bridge_service_serve" "Local bridge service smoke/evidence" "ACCESS_RECOVERY_BETA_LOCAL_GATE_BRIDGE_SERVICE_SERVE_SCRIPT" "scripts/integration_access_bridge_service_serve.sh"
run_step "bridge_deployment_evidence" "Bridge deployment evidence contract" "ACCESS_RECOVERY_BETA_LOCAL_GATE_BRIDGE_DEPLOYMENT_EVIDENCE_SCRIPT" "scripts/integration_access_bridge_deployment_evidence.sh"
run_step "bridge_host_install" "Bridge host-install check contract" "ACCESS_RECOVERY_BETA_LOCAL_GATE_BRIDGE_HOST_INSTALL_SCRIPT" "scripts/integration_access_bridge_host_install_check.sh"
run_step "pilot_evidence_bundle" "Pilot evidence bundle contract" "ACCESS_RECOVERY_BETA_LOCAL_GATE_PILOT_EVIDENCE_BUNDLE_SCRIPT" "scripts/integration_access_bridge_pilot_evidence_bundle.sh"
run_step "pilot_evidence_bundle_verify" "Pilot evidence bundle verifier contract" "ACCESS_RECOVERY_BETA_LOCAL_GATE_PILOT_EVIDENCE_BUNDLE_VERIFY_SCRIPT" "scripts/integration_access_bridge_pilot_evidence_bundle_verify.sh"
run_step "real_helper_evidence_run" "Real helper evidence-run wrapper contract" "ACCESS_RECOVERY_BETA_LOCAL_GATE_REAL_HELPER_EVIDENCE_RUN_SCRIPT" "scripts/integration_access_recovery_real_helper_evidence_run.sh"

steps_json="$(jq -s '.' "$steps_jsonl")"
fail_count="$(jq -s '[.[] | select(.status != "pass" or .rc != 0)] | length' "$steps_jsonl")"
first_failed_step="$(jq -rs '[.[] | select(.status != "pass" or .rc != 0)][0].id // ""' "$steps_jsonl")"
status="pass"
notes="Access Recovery local beta gate passed"
if [[ "$fail_count" != "0" ]]; then
  status="fail"
  notes="Access Recovery local beta gate failed"
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg reports_dir "$reports_dir" \
  --arg summary_json "$summary_json" \
  --arg report_md "$report_md" \
  --arg first_failed_step "$first_failed_step" \
  --arg allow_custom_step_scripts "$allow_custom_step_scripts" \
  --argjson fail_count "$fail_count" \
  --argjson steps "$steps_json" \
  '{
    version: 1,
    schema: {id: "access_recovery_beta_local_gate_summary", major: 1, minor: 0},
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: (if $status == "pass" then 0 else 1 end),
    notes: $notes,
    summary: {
      steps_total: ($steps | length),
      steps_pass: ($steps | map(select(.status == "pass" and .rc == 0)) | length),
      steps_fail: $fail_count,
      first_failed_step: (if $first_failed_step == "" then null else $first_failed_step end)
    },
    security: {
      custom_step_scripts_allowed: ($allow_custom_step_scripts == "1")
    },
    steps: $steps,
    artifacts: {
      reports_dir: $reports_dir,
      summary_json: $summary_json,
      report_md: $report_md
    },
    recommended_next_action: (
      if $status == "pass" then {
        id: "real_helper_bridge_evidence",
        command: "./scripts/easy_node.sh access-recovery-real-helper-evidence-run --base-url https://HELPER_PUBLIC_DNS --path-id helper-web --code-file PRIVATE_CODE_FILE --config-json BRIDGE_SERVICE_CONFIG --deploy-pack-dir BRIDGE_DEPLOY_PACK --host-install-evidence-mode installed-host --install-dir /etc/gpm/access-bridge --systemd-unit-file /etc/systemd/system/gpm-access-bridge.service --proxy-kind caddy --proxy-config-file /etc/caddy/Caddyfile.d/gpm-access-bridge.caddy --provenance-private-key-file PROVENANCE_PRIVATE_KEY_FILE --provenance-org-id ORG_ID --provenance-org-name ORG_NAME --trust-store TRUST_STORE --reports-dir .easy-node-logs/access-recovery-pilot",
        reason: "Local beta contracts are green; next blocker is signed real helper HTTPS deployment evidence plus a trusted verifier receipt bound to the verified bundle contents."
      } else {
        id: "fix_access_recovery_local_gate",
        command: ("Inspect the failing step log under " + $reports_dir + " and rerun this gate."),
        reason: "Local beta contracts must pass before pilot handoff."
      } end
    )
  }' >"$summary_json"

cat >"$report_md" <<REPORT
# Access Recovery Beta Local Gate

- Status: ${status}
- Notes: ${notes}
- Reports dir: ${reports_dir}
- First failed step: ${first_failed_step:-none}

## Steps

$(jq -r '.steps[] | "- " + .id + ": " + .status + " (rc=" + (.rc|tostring) + ") - " + .log' "$summary_json")

## Next

$(jq -r '.recommended_next_action.reason + "\n\n`" + .recommended_next_action.command + "`"' "$summary_json")
REPORT

echo "access-recovery-beta-local-gate: status=$status"
echo "summary_json: $summary_json"
echo "report_md: $report_md"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$status" != "pass" ]]; then
  exit 1
fi
