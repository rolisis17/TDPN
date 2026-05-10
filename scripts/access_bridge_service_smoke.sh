#!/usr/bin/env bash
set -euo pipefail

base_url=""
path_id="helper-web"
code=""
code_file=""
allow_unauthenticated="0"
summary_json=""
abuse_message="bridge service smoke"
expect_helper_id=""
expect_org_id=""
expect_registry_id=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_bridge_service_smoke.sh --base-url URL [--path-id helper-web] (--code CODE | --code-file FILE) [--expect-helper-id ID] [--expect-org-id ID] [--expect-registry-id ID] [--summary-json FILE] [--abuse-message TEXT]
  scripts/access_bridge_service_smoke.sh --base-url URL [--path-id helper-web] --allow-unauthenticated 1 [diagnostic only]

Checks /health, access-code-gated /bridge/{path_id}, no-store/no-referrer headers, and /abuse logging acceptance.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --base-url)
      base_url="${2:-}"
      shift 2
      ;;
    --path-id)
      path_id="${2:-}"
      shift 2
      ;;
    --code)
      code="${2:-}"
      shift 2
      ;;
    --code-file)
      code_file="${2:-}"
      shift 2
      ;;
    --allow-unauthenticated)
      allow_unauthenticated="${2:-1}"
      shift 2
      ;;
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --abuse-message)
      abuse_message="${2:-}"
      shift 2
      ;;
    --expect-helper-id)
      expect_helper_id="${2:-}"
      shift 2
      ;;
    --expect-org-id)
      expect_org_id="${2:-}"
      shift 2
      ;;
    --expect-registry-id)
      expect_registry_id="${2:-}"
      shift 2
      ;;
    -h|--help)
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

for cmd in curl date jq; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge service smoke failed: missing required command: $cmd" >&2
    exit 2
  fi
done

base_url="${base_url%/}"
if [[ -z "$base_url" ]]; then
  echo "access bridge service smoke failed: --base-url is required" >&2
  exit 2
fi
if [[ -z "$path_id" ]]; then
  echo "access bridge service smoke failed: --path-id is required" >&2
  exit 2
fi
if [[ "$allow_unauthenticated" != "0" && "$allow_unauthenticated" != "1" ]]; then
  echo "access bridge service smoke failed: --allow-unauthenticated must be 0 or 1" >&2
  exit 2
fi
if [[ -n "$code" && -n "$code_file" ]]; then
  echo "access bridge service smoke failed: use either --code or --code-file, not both" >&2
  exit 2
fi
if [[ -n "$code_file" ]]; then
  if [[ ! -f "$code_file" ]]; then
    echo "access bridge service smoke failed: code file not found: $code_file" >&2
    exit 2
  fi
  code="$(tr -d '\r\n' <"$code_file")"
fi
if [[ -z "$code" && "$allow_unauthenticated" != "1" ]]; then
  echo "access bridge service smoke failed: --code or --code-file is required unless --allow-unauthenticated 1 is set" >&2
  exit 2
fi

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

health_body="$tmp_dir/health.json"
bridge_body="$tmp_dir/bridge.json"
bridge_headers="$tmp_dir/bridge.headers"
missing_code_body="$tmp_dir/missing-code.json"
wrong_code_body="$tmp_dir/wrong-code.json"
abuse_body="$tmp_dir/abuse.json"
code_header_config="$tmp_dir/code-header.curl"
wrong_code_header_config="$tmp_dir/wrong-code-header.curl"

health_http="$(curl -sS -o "$health_body" -w '%{http_code}' "${base_url}/health" || true)"

missing_code_http="skipped"
wrong_code_http="skipped"
if [[ "$allow_unauthenticated" != "1" ]]; then
  missing_code_http="$(curl -sS -o "$missing_code_body" -w '%{http_code}' "${base_url}/bridge/${path_id}" || true)"
  printf 'header = "X-GPM-Bridge-Code: wrong-code-denied"\n' >"$wrong_code_header_config"
  wrong_code_http="$(curl -sS --config "$wrong_code_header_config" -o "$wrong_code_body" -w '%{http_code}' "${base_url}/bridge/${path_id}" || true)"
fi

curl_args=(-sS -D "$bridge_headers" -o "$bridge_body" -w '%{http_code}')
if [[ -n "$code" ]]; then
  printf 'header = "X-GPM-Bridge-Code: %s"\n' "$code" >"$code_header_config"
  curl_args+=(--config "$code_header_config")
fi
bridge_http="$(curl "${curl_args[@]}" "${base_url}/bridge/${path_id}" || true)"

abuse_payload="$(jq -cn --arg path_id "$path_id" --arg message "$abuse_message" '{path_id:$path_id,message:$message}')"
abuse_http="$(curl -sS -X POST -H 'Content-Type: application/json' -d "$abuse_payload" -o "$abuse_body" -w '%{http_code}' "${base_url}/abuse" || true)"

health_status="$(jq -r '.status // ""' "$health_body" 2>/dev/null || true)"
health_helper_id="$(jq -r '.decision.helper_id // ""' "$health_body" 2>/dev/null || true)"
health_org_id="$(jq -r '.decision.organization_id // ""' "$health_body" 2>/dev/null || true)"
health_registry_id="$(jq -r '.decision.registry_id // ""' "$health_body" 2>/dev/null || true)"
health_config_sha256="$(jq -r '.config_sha256 // ""' "$health_body" 2>/dev/null || true)"
bridge_status="$(jq -r '.status // ""' "$bridge_body" 2>/dev/null || true)"
headers_ok="false"
if grep -iq '^Referrer-Policy: no-referrer' "$bridge_headers" && grep -iq '^Cache-Control: no-store' "$bridge_headers"; then
  headers_ok="true"
fi

status="pass"
notes="bridge service smoke passed"
if [[ "$health_http" != "200" || "$health_status" != "ok" ]]; then
  status="fail"
  notes="health check failed"
elif [[ "$allow_unauthenticated" != "1" && "$missing_code_http" != "401" ]]; then
  status="fail"
  notes="missing access-code negative check failed"
elif [[ "$allow_unauthenticated" != "1" && "$wrong_code_http" != "401" ]]; then
  status="fail"
  notes="wrong access-code negative check failed"
elif [[ "$bridge_http" != "200" || "$bridge_status" != "ok" ]]; then
  status="fail"
  notes="bridge path check failed"
elif [[ "$headers_ok" != "true" ]]; then
  status="fail"
  notes="bridge response security headers missing"
elif [[ "$abuse_http" != "202" ]]; then
  status="fail"
  notes="abuse report check failed"
elif [[ -n "$expect_helper_id" && "$health_helper_id" != "$expect_helper_id" ]]; then
  status="fail"
  notes="helper id mismatch"
elif [[ -n "$expect_org_id" && "$health_org_id" != "$expect_org_id" ]]; then
  status="fail"
  notes="organization id mismatch"
elif [[ -n "$expect_registry_id" && "$health_registry_id" != "$expect_registry_id" ]]; then
  status="fail"
  notes="registry id mismatch"
fi

summary="$(jq -cn \
  --arg generated_at_utc "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg base_url "$base_url" \
  --arg path_id "$path_id" \
  --arg health_http "$health_http" \
  --arg health_status "$health_status" \
  --arg health_helper_id "$health_helper_id" \
  --arg health_org_id "$health_org_id" \
  --arg health_registry_id "$health_registry_id" \
  --arg health_config_sha256 "$health_config_sha256" \
  --arg missing_code_http "$missing_code_http" \
  --arg wrong_code_http "$wrong_code_http" \
  --arg bridge_http "$bridge_http" \
  --arg bridge_status "$bridge_status" \
  --arg abuse_http "$abuse_http" \
  --argjson headers_ok "$headers_ok" \
  --argjson auth_required "$( [[ "$allow_unauthenticated" == "1" ]] && echo false || echo true )" \
  '{version:1,schema:{id:"access_bridge_service_smoke_summary",major:1,minor:2},generated_at_utc:$generated_at_utc,status:$status,notes:$notes,base_url:$base_url,path_id:$path_id,health:{http_status:$health_http,status:$health_status,helper_id:$health_helper_id,organization_id:$health_org_id,registry_id:$health_registry_id,config_sha256:$health_config_sha256},auth:{required:$auth_required,missing_code_http_status:$missing_code_http,wrong_code_http_status:$wrong_code_http,valid_code_http_status:$bridge_http},bridge:{http_status:$bridge_http,status:$bridge_status,security_headers_ok:$headers_ok},abuse:{http_status:$abuse_http}}')"

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary" >"$summary_json"
fi
printf '%s\n' "$summary"

if [[ "$status" != "pass" ]]; then
  exit 1
fi
