#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/access_recovery_local_evidence_refresh.sh \
    [--reports-dir DIR] \
    [--port N] \
    [--org-id ID] \
    [--org-name NAME] \
    [--helper-id ID] \
    [--helper-name NAME] \
    [--service-name NAME] \
    [--write-canonical [0|1]] \
    [--canonical-dir DIR] \
    [--refresh-roadmap [0|1]] \
    [--summary-json PATH] \
    [--print-summary-json [0|1]]

Purpose:
  Run a local Access Recovery helper rehearsal and, when --write-canonical 1 is
  explicitly set, write canonical evidence summaries for roadmap ingestion:
  - access_bridge_service_smoke_summary.json
  - access_bridge_deployment_evidence_summary.json
  - access_bridge_host_install_check_summary.json
  - access_bridge_pilot_evidence_bundle_summary.json

Notes:
  This is local beta evidence only. Real helper HTTPS deployment evidence is
  still required before pilot handoff.
USAGE
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "access recovery local evidence refresh failed: missing required command: $1" >&2
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
  local value="${2:-}"
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

value_arg_or_die() {
  local name="$1"
  local value="${2:-}"
  if [[ -z "$(trim "$value")" || "$value" == --* ]]; then
    echo "$name requires a value" >&2
    exit 2
  fi
}

sha256_value() {
  local file="$1"
  sha256sum "$file" | awk '{print $1}'
}

copy_if_present() {
  local src="$1"
  local dst="$2"
  if [[ ! -f "$src" ]]; then
    echo "expected artifact missing: $src" >&2
    exit 1
  fi
  mkdir -p "$(dirname "$dst")"
  cp -p "$src" "$dst"
}

verifier_summary_has_handoff_authority() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  jq -e '
    (.handoff_authority == true)
    or ((.authority_level // "") == "pilot_handoff")
    or (.pilot_handoff_ready == true)
    or (.trusted_pilot_receipt_ready == true)
    or ((.trusted_provenance.evidence_scope // "") == "real_helper_https")
  ' "$path" >/dev/null 2>&1
}

canonical_summary_json_is_invalid() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  ! jq -e 'type == "object"' "$path" >/dev/null 2>&1
}

canonical_child_summary_blocks_local_rehearsal_overwrite() {
  local path="$1"
  [[ -f "$path" ]] || return 1
  jq -e '
    def str($v): (($v // "") | tostring);
    def bool($v): ($v == true or $v == "true");
    def trim_trailing_dots: gsub("[.]+$"; "");
    def first_part($sep): split($sep)[0];
    def url_authority($url):
      ($url | sub("^[A-Za-z][A-Za-z0-9+.-]*://"; "") | first_part("/") | first_part("?") | first_part("#"));
    def url_host($url):
      (url_authority($url) | split("@") | .[-1]) as $authority
      | if ($authority | startswith("[")) then
          ($authority | sub("^\\["; "") | sub("\\].*$"; ""))
        else
          ($authority | first_part(":"))
        end
      | ascii_downcase
      | trim_trailing_dots;
    def private_or_reserved_host($host):
      (
        ($host == "")
        or ($host == "localhost")
        or ($host | test("(^|\\.)(localhost|local|lan|internal|test|invalid|example)$"))
        or ($host | test("(^|\\.)example\\.(com|net|org)$"))
        or ($host == "home.arpa")
        or ($host | endswith(".home.arpa"))
        or ($host == "ts.net")
        or ($host | endswith(".ts.net"))
        or ($host == "tailscale.net")
        or ($host | endswith(".tailscale.net"))
        or ($host | test("^127\\."))
        or ($host | test("^10\\."))
        or ($host | test("^172\\.(1[6-9]|2[0-9]|3[0-1])\\."))
        or ($host | test("^192\\.168\\."))
        or ($host | test("^169\\.254\\."))
        or ($host | test("^100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\\."))
        or ($host | test("^0\\."))
        or ($host | test("^192\\.0\\.(0|2)\\."))
        or ($host | test("^192\\.88\\.99\\."))
        or ($host | test("^198\\.(1[89]|51\\.100)\\."))
        or ($host | test("^203\\.0\\.113\\."))
        or ($host | test("^(22[4-9]|23[0-9]|24[0-9]|25[0-5])\\."))
        or ($host | test("^(::|::1|0:0:0:0:0:0:0:1|fc[0-9a-f]|fd[0-9a-f]|fe(8[0-9a-f]|9[0-9a-f]|a[0-9a-f]|b[0-9a-f])|2001:0?db8)(:|$)"))
        or ($host | test("^::ffff:(127|10|192\\.168|169\\.254|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])|172\\.(1[6-9]|2[0-9]|3[0-1])|192\\.0\\.(0|2)|192\\.88\\.99|198\\.(1[89]|51\\.100)|203\\.0\\.113|22[4-9]|23[0-9]|24[0-9]|25[0-5]|0)\\."))
        or ($host | test("^0:0:0:0:0:ffff:(127|10|192\\.168|169\\.254|100\\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])|172\\.(1[6-9]|2[0-9]|3[0-1])|192\\.0\\.(0|2)|192\\.88\\.99|198\\.(1[89]|51\\.100)|203\\.0\\.113|22[4-9]|23[0-9]|24[0-9]|25[0-5]|0)\\."))
      );
    def public_https_url($url):
      ($url | test("^https://"; "i"))
      and ((url_authority($url) | contains("@")) | not)
      and ((private_or_reserved_host(url_host($url))) | not);
    def schema_id: str(.schema.id);
    def evidence_scope: str(.evidence_scope // .details.evidence_scope // .trusted_provenance.evidence_scope // .details.trusted_provenance_evidence_scope);
    def real_service_smoke:
      schema_id == "access_bridge_service_smoke_summary"
      and str(.status) == "pass"
      and public_https_url(str(.base_url // .details.base_url))
      and bool(.transport.https // .details.transport_https)
      and bool(.transport.tls.verified // .details.transport_tls_verified)
      and str(.transport.tls.ssl_verify_result // .details.transport_ssl_verify_result) == "0";
    def real_deployment_evidence:
      schema_id == "access_bridge_deployment_evidence_summary"
      and str(.status) == "pass"
      and (
        evidence_scope == "real_helper_https"
        or bool(.pilot_handoff_candidate)
        or (
          public_https_url(str(.smoke.base_url // .details.base_url))
          and bool(.transport.https // .details.transport_https)
          and bool(.transport.tls_verified // .details.transport_tls_verified)
          and str(.transport.ssl_verify_result // .details.transport_ssl_verify_result) == "0"
        )
      );
    def installed_host_evidence:
      schema_id == "access_bridge_host_install_check_summary"
      and str(.status) == "pass"
      and (
        str(.inputs.evidence_mode // .observed.evidence_mode // .summary.evidence_mode // .details.evidence_mode) == "installed-host"
        or bool(.inputs.installed_host_mode // .observed.installed_host_mode // .summary.installed_host_mode // .details.installed_host_mode)
      );
    def real_or_trusted_bundle_evidence:
      schema_id == "access_bridge_pilot_evidence_bundle_summary"
      and str(.status) == "pass"
      and (
        evidence_scope == "real_helper_https"
        or bool(.provenance.enabled)
        or bool(.trusted_provenance.checked)
        or bool(.trusted_provenance.trusted)
      );
    real_service_smoke
    or real_deployment_evidence
    or installed_host_evidence
    or real_or_trusted_bundle_evidence
  ' "$path" >/dev/null 2>&1
}

refuse_protected_canonical_overwrite() {
  local label="$1"
  local path="$2"
  [[ -f "$path" ]] || return 0
  if canonical_summary_json_is_invalid "$path"; then
    echo "access recovery local evidence refresh failed: --write-canonical 1 refuses to overwrite unreadable existing canonical $label summary (fail-closed): $path" >&2
    exit 2
  fi
  if [[ "$label" == "pilot verifier receipt" ]] && verifier_summary_has_handoff_authority "$path"; then
    echo "access recovery local evidence refresh failed: --write-canonical 1 would overwrite existing trusted pilot verifier receipt: $path" >&2
    exit 2
  fi
  if canonical_child_summary_blocks_local_rehearsal_overwrite "$path"; then
    echo "access recovery local evidence refresh failed: --write-canonical 1 would overwrite existing canonical real-helper/installed-host/trusted child evidence with local rehearsal evidence: $path" >&2
    exit 2
  fi
}

reports_dir="$ROOT_DIR/.easy-node-logs/access_recovery_local_evidence_$(timestamp_file)"
summary_json=""
print_summary_json="1"
port="${ACCESS_RECOVERY_LOCAL_EVIDENCE_PORT:-19820}"
org_id="local-recovery-demo"
org_name="Local Recovery Demo"
helper_id="helper-local"
helper_name="Local Helper"
service_name="gpm-access-bridge-local"
write_canonical="0"
canonical_dir="$ROOT_DIR/.easy-node-logs"
refresh_roadmap="0"

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
    --print-summary-json)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        print_summary_json="${2:-}"
        shift 2
      else
        print_summary_json="1"
        shift
      fi
      ;;
    --port)
      value_arg_or_die "--port" "${2:-}"
      port="${2:-}"
      shift 2
      ;;
    --org-id)
      value_arg_or_die "--org-id" "${2:-}"
      org_id="${2:-}"
      shift 2
      ;;
    --org-name)
      value_arg_or_die "--org-name" "${2:-}"
      org_name="${2:-}"
      shift 2
      ;;
    --helper-id)
      value_arg_or_die "--helper-id" "${2:-}"
      helper_id="${2:-}"
      shift 2
      ;;
    --helper-name)
      value_arg_or_die "--helper-name" "${2:-}"
      helper_name="${2:-}"
      shift 2
      ;;
    --service-name)
      value_arg_or_die "--service-name" "${2:-}"
      service_name="${2:-}"
      shift 2
      ;;
    --write-canonical)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        write_canonical="${2:-}"
        shift 2
      else
        write_canonical="1"
        shift
      fi
      ;;
    --canonical-dir)
      path_arg_or_die "--canonical-dir" "${2:-}"
      canonical_dir="$(abs_path "${2:-}")"
      shift 2
      ;;
    --refresh-roadmap)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1" ) ]]; then
        refresh_roadmap="${2:-}"
        shift 2
      else
        refresh_roadmap="1"
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

for cmd in awk bash cp curl date go jq mkdir sha256sum tar tr; do
  need_cmd "$cmd"
done
bool_arg_or_die "--print-summary-json" "$print_summary_json"
bool_arg_or_die "--write-canonical" "$write_canonical"
bool_arg_or_die "--refresh-roadmap" "$refresh_roadmap"
if ! [[ "$port" =~ ^[0-9]+$ ]] || ((port < 1 || port > 65535)); then
  echo "--port must be an integer from 1 to 65535" >&2
  exit 2
fi

mkdir -p "$reports_dir"
if [[ -z "$summary_json" ]]; then
  summary_json="$reports_dir/access_recovery_local_evidence_refresh_summary.json"
fi
mkdir -p "$(dirname "$summary_json")"
if [[ "$write_canonical" == "1" ]]; then
  mkdir -p "$canonical_dir"
  refuse_protected_canonical_overwrite "service smoke" "$canonical_dir/access_bridge_service_smoke_summary.json"
  refuse_protected_canonical_overwrite "deployment evidence" "$canonical_dir/access_bridge_deployment_evidence_summary.json"
  refuse_protected_canonical_overwrite "host install" "$canonical_dir/access_bridge_host_install_check_summary.json"
  refuse_protected_canonical_overwrite "pilot bundle" "$canonical_dir/access_bridge_pilot_evidence_bundle_summary.json"
  refuse_protected_canonical_overwrite "pilot verifier receipt" "$canonical_dir/access_bridge_pilot_evidence_bundle_verify_summary.json"
fi

demo_dir="$reports_dir/access-recovery-demo"
private_dir="$reports_dir/private"
mkdir -p "$private_dir"
service_config="$reports_dir/bridge-service-config.json"
code_file="$private_dir/bridge-code.txt"
code_hash_json="$reports_dir/bridge-code-hash.json"
deploy_pack_dir="$reports_dir/bridge-deploy"
abuse_log="$reports_dir/bridge-abuse.jsonl"
server_log="$reports_dir/bridge-service.log"
base_url="http://127.0.0.1:${port}"
rehearsal_public_host="${helper_id}.gpm-pilot.net"
pilot_bundle_dir="$reports_dir/access-bridge-pilot-evidence-bundle"
pilot_summary_json="$reports_dir/access_bridge_pilot_evidence_bundle_summary.json"
pilot_report_md="$reports_dir/access_bridge_pilot_evidence_bundle_report.md"
pilot_verify_log="$reports_dir/access_bridge_pilot_evidence_bundle_verify.log"
roadmap_summary_json="$reports_dir/roadmap_progress_summary.json"
roadmap_report_md="$reports_dir/roadmap_progress_report.md"
BRIDGE_PID=""

cleanup() {
  if [[ -n "$BRIDGE_PID" ]]; then
    kill "$BRIDGE_PID" >/dev/null 2>&1 || true
    wait "$BRIDGE_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

go run ./cmd/gpmrecover demo-bundle \
  --out-dir "$demo_dir" \
  --org-id "$org_id" \
  --org-name "$org_name" \
  --base-url "https://${org_id}.gpm-pilot.net" \
  --helper-id "$helper_id" \
  --helper-name "$helper_name" \
  --helper-url "https://${helper_id}.gpm-pilot.net/bootstrap" \
  --helper-contact "mailto:${helper_id}@gpm-pilot.net" \
  >"$reports_dir/demo-bundle.stdout.json"

trust_store="$(jq -r '.files.trust_store' "$demo_dir/demo-manifest.json")"
bridge_invite="$(jq -r '.files.bridge_invite_signed' "$demo_dir/demo-manifest.json")"
signed_registry="$(jq -r '.files.bridge_helper_registry_signed' "$demo_dir/demo-manifest.json")"

go run ./cmd/gpmrecover bridge-service-config \
  --invite "$bridge_invite" \
  --trust-store "$trust_store" \
  --signed-helper-registry "$signed_registry" \
  --out "$service_config" >/dev/null

registry_id="$(jq -r '.registry_id' "$service_config")"
config_sha256="$(sha256_value "$service_config")"

go run ./cmd/gpmrecover bridge-service-code-generate \
  --code-out "$code_file" \
  --hash-out "$code_hash_json" >/dev/null
code_hash="$(jq -r '.sha256' "$code_hash_json")"

go run ./cmd/gpmrecover bridge-service-deploy-pack \
  --out-dir "$deploy_pack_dir" \
  --service-name "$service_name" \
  --public-host "$rehearsal_public_host" \
  --install-dir "/etc/gpm/${service_name}" \
  --config "/etc/gpm/${service_name}/bridge-service-config.json" \
  --config-sha256 "$config_sha256" \
  --access-code-sha256 "$code_hash" >/dev/null

go run ./cmd/gpmrecover bridge-service-serve \
  --config "$service_config" \
  --config-sha256 "$config_sha256" \
  --addr "127.0.0.1:${port}" \
  --rps 20 \
  --abuse-log "$abuse_log" \
  --access-code-sha256 "$code_hash" \
  >"$server_log" 2>&1 &
BRIDGE_PID=$!

for _ in $(seq 1 80); do
  if curl -fsS "${base_url}/health" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$BRIDGE_PID" >/dev/null 2>&1; then
    echo "access recovery local evidence refresh failed: bridge service exited early" >&2
    cat "$server_log" >&2
    exit 1
  fi
  sleep 0.25
done
if ! curl -fsS "${base_url}/health" >/dev/null 2>&1; then
  echo "access recovery local evidence refresh failed: bridge service did not become ready" >&2
  cat "$server_log" >&2
  exit 1
fi

bash ./scripts/access_bridge_pilot_evidence_bundle.sh \
  --base-url "$base_url" \
  --path-id helper-web \
  --code-file "$code_file" \
  --config-json "$service_config" \
  --deploy-pack-dir "$deploy_pack_dir" \
  --service-name "$service_name" \
  --expected-public-host "$rehearsal_public_host" \
  --expect-helper-id "$helper_id" \
  --expect-org-id "$org_id" \
  --expect-registry-id "$registry_id" \
  --bundle-dir "$pilot_bundle_dir" \
  --summary-json "$pilot_summary_json" \
  --report-md "$pilot_report_md" \
  --print-summary-json 0

pilot_verify_summary_json="$reports_dir/access_bridge_pilot_evidence_bundle_verify_summary.json"
bash ./scripts/access_bridge_pilot_evidence_bundle_verify.sh \
  --summary-json "$pilot_summary_json" \
  --verification-summary-json "$pilot_verify_summary_json" \
  --print-verification-summary-json 0 \
  --show-details 1 >"$pilot_verify_log" 2>&1

service_smoke_summary_json="$pilot_bundle_dir/access_bridge_service_smoke_summary.json"
deployment_evidence_summary_json="$pilot_bundle_dir/access_bridge_deployment_evidence_summary.json"
host_install_summary_json="$pilot_bundle_dir/access_bridge_host_install_check_summary.json"

canonical_service_smoke_summary_json=""
canonical_deployment_evidence_summary_json=""
canonical_host_install_summary_json=""
canonical_pilot_summary_json=""
canonical_pilot_verify_summary_json=""
if [[ "$write_canonical" == "1" ]]; then
  canonical_service_smoke_summary_json="$canonical_dir/access_bridge_service_smoke_summary.json"
  canonical_deployment_evidence_summary_json="$canonical_dir/access_bridge_deployment_evidence_summary.json"
  canonical_host_install_summary_json="$canonical_dir/access_bridge_host_install_check_summary.json"
  canonical_pilot_summary_json="$canonical_dir/access_bridge_pilot_evidence_bundle_summary.json"
  canonical_pilot_verify_summary_json="$canonical_dir/access_bridge_pilot_evidence_bundle_verify_summary.json"
  refuse_protected_canonical_overwrite "service smoke" "$canonical_service_smoke_summary_json"
  refuse_protected_canonical_overwrite "deployment evidence" "$canonical_deployment_evidence_summary_json"
  refuse_protected_canonical_overwrite "host install" "$canonical_host_install_summary_json"
  refuse_protected_canonical_overwrite "pilot bundle" "$canonical_pilot_summary_json"
  refuse_protected_canonical_overwrite "pilot verifier receipt" "$canonical_pilot_verify_summary_json"
  copy_if_present "$service_smoke_summary_json" "$canonical_service_smoke_summary_json"
  copy_if_present "$deployment_evidence_summary_json" "$canonical_deployment_evidence_summary_json"
  copy_if_present "$host_install_summary_json" "$canonical_host_install_summary_json"
  copy_if_present "$pilot_summary_json" "$canonical_pilot_summary_json"
  copy_if_present "$pilot_verify_summary_json" "$canonical_pilot_verify_summary_json"
fi

roadmap_status="skipped"
roadmap_rc=0
if [[ "$refresh_roadmap" == "1" ]]; then
  set +e
  bash ./scripts/easy_node.sh roadmap-progress-report \
    --refresh-manual-validation 0 \
    --refresh-single-machine-readiness 0 \
    --require-access-recovery-evidence 0 \
    --access-bridge-service-smoke-summary-json "$service_smoke_summary_json" \
    --access-bridge-deployment-evidence-summary-json "$deployment_evidence_summary_json" \
    --access-bridge-host-install-summary-json "$host_install_summary_json" \
    --access-bridge-pilot-evidence-bundle-verify-summary-json "$pilot_verify_summary_json" \
    --summary-json "$roadmap_summary_json" \
    --report-md "$roadmap_report_md" \
    --print-report 0 \
    --print-summary-json 0 >"$reports_dir/roadmap_progress.log" 2>&1
  roadmap_rc=$?
  set -e
  if [[ "$roadmap_rc" -eq 0 ]]; then
    roadmap_status="$(jq -r '.status // "unknown"' "$roadmap_summary_json" 2>/dev/null || printf '%s' "unknown")"
  else
    roadmap_status="fail"
  fi
fi

summary_status="pass"
summary_notes="Access Recovery local evidence refresh passed"
if [[ "$refresh_roadmap" == "1" && "$roadmap_rc" -ne 0 ]]; then
  summary_status="fail"
  summary_notes="Access Recovery evidence passed, but roadmap refresh failed"
fi

jq -n \
  --arg generated_at_utc "$(timestamp_utc)" \
  --arg status "$summary_status" \
  --arg notes "$summary_notes" \
  --arg reports_dir "$reports_dir" \
  --arg base_url "$base_url" \
  --arg rehearsal_public_host "$rehearsal_public_host" \
  --arg org_id "$org_id" \
  --arg helper_id "$helper_id" \
  --arg registry_id "$registry_id" \
  --arg service_name "$service_name" \
  --arg service_smoke_summary_json "$service_smoke_summary_json" \
  --arg deployment_evidence_summary_json "$deployment_evidence_summary_json" \
  --arg host_install_summary_json "$host_install_summary_json" \
  --arg pilot_summary_json "$pilot_summary_json" \
  --arg pilot_report_md "$pilot_report_md" \
  --arg pilot_verify_log "$pilot_verify_log" \
  --arg pilot_verify_summary_json "$pilot_verify_summary_json" \
  --arg canonical_service_smoke_summary_json "$canonical_service_smoke_summary_json" \
  --arg canonical_deployment_evidence_summary_json "$canonical_deployment_evidence_summary_json" \
  --arg canonical_host_install_summary_json "$canonical_host_install_summary_json" \
  --arg canonical_pilot_summary_json "$canonical_pilot_summary_json" \
  --arg canonical_pilot_verify_summary_json "$canonical_pilot_verify_summary_json" \
  --arg roadmap_status "$roadmap_status" \
  --argjson roadmap_rc "$roadmap_rc" \
  --arg roadmap_summary_json "$roadmap_summary_json" \
  --arg roadmap_report_md "$roadmap_report_md" \
  --argjson write_canonical "$( [[ "$write_canonical" == "1" ]] && printf 'true' || printf 'false' )" \
  --argjson refresh_roadmap "$( [[ "$refresh_roadmap" == "1" ]] && printf 'true' || printf 'false' )" \
  '{
    version: 1,
    schema: {id: "access_recovery_local_evidence_refresh_summary", major: 1, minor: 2},
    generated_at_utc: $generated_at_utc,
    status: $status,
    rc: (if $status == "pass" then 0 else 1 end),
    pilot_handoff_ready: false,
    evidence_scope: "local_rehearsal",
    notes: $notes,
    inputs: {
      base_url: $base_url,
      rehearsal_public_host: $rehearsal_public_host,
      org_id: $org_id,
      helper_id: $helper_id,
      registry_id: $registry_id,
      service_name: $service_name,
      write_canonical: $write_canonical,
      refresh_roadmap: $refresh_roadmap
    },
    artifacts: {
      reports_dir: $reports_dir,
      service_smoke_summary_json: $service_smoke_summary_json,
      deployment_evidence_summary_json: $deployment_evidence_summary_json,
      host_install_summary_json: $host_install_summary_json,
      pilot_summary_json: $pilot_summary_json,
      pilot_report_md: $pilot_report_md,
      pilot_verify_log: $pilot_verify_log,
      pilot_verify_summary_json: $pilot_verify_summary_json,
      canonical_service_smoke_summary_json: (if $canonical_service_smoke_summary_json == "" then null else $canonical_service_smoke_summary_json end),
      canonical_deployment_evidence_summary_json: (if $canonical_deployment_evidence_summary_json == "" then null else $canonical_deployment_evidence_summary_json end),
      canonical_host_install_summary_json: (if $canonical_host_install_summary_json == "" then null else $canonical_host_install_summary_json end),
      canonical_pilot_summary_json: (if $canonical_pilot_summary_json == "" then null else $canonical_pilot_summary_json end),
      canonical_pilot_verify_summary_json: (if $canonical_pilot_verify_summary_json == "" then null else $canonical_pilot_verify_summary_json end),
      roadmap_summary_json: (if $refresh_roadmap then $roadmap_summary_json else null end),
      roadmap_report_md: (if $refresh_roadmap then $roadmap_report_md else null end)
    },
    roadmap: {
      refreshed: $refresh_roadmap,
      status: $roadmap_status,
      rc: $roadmap_rc
    },
    recommended_next_action: {
      id: "real_helper_https_evidence",
      command: "./scripts/easy_node.sh access-recovery-real-helper-evidence-run --base-url https://HELPER_PUBLIC_DNS --path-id helper-web --code-file PRIVATE_CODE_FILE --config-json BRIDGE_SERVICE_CONFIG --deploy-pack-dir BRIDGE_DEPLOY_PACK --host-install-evidence-mode installed-host --install-dir /etc/gpm/access-bridge --systemd-unit-file /etc/systemd/system/gpm-access-bridge.service --proxy-kind caddy --proxy-config-file /etc/caddy/Caddyfile.d/gpm-access-bridge.caddy --provenance-private-key-file PROVENANCE_PRIVATE_KEY_FILE --provenance-org-id ORG_ID --provenance-org-name ORG_NAME --trust-store TRUST_STORE --reports-dir .easy-node-logs/access-recovery-pilot",
      reason: "Local evidence is only a rehearsal; real beta handoff still needs signed helper HTTPS deployment evidence from the actual host and trusted provenance verification.",
      placeholder_unresolved: true,
      placeholder_keys: [
        "HELPER_PUBLIC_DNS",
        "PRIVATE_CODE_FILE",
        "BRIDGE_SERVICE_CONFIG",
        "BRIDGE_DEPLOY_PACK",
        "PROVENANCE_PRIVATE_KEY_FILE",
        "ORG_ID",
        "ORG_NAME",
        "TRUST_STORE"
      ],
      safe_to_execute_as_is: false,
      operator_input_required: true,
      placeholder_resolution: "Template command only; replace Access Recovery placeholders with concrete pilot host, credential, config, deploy-pack, provenance, trust-store, and organization values before execution."
    }
  }' >"$summary_json"

echo "access-recovery-local-evidence-refresh: status=$summary_status"
echo "summary_json: $summary_json"
echo "reports_dir: $reports_dir"
if [[ "$print_summary_json" == "1" ]]; then
  cat "$summary_json"
fi

if [[ "$summary_status" != "pass" ]]; then
  exit 1
fi
