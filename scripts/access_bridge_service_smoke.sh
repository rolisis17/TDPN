#!/usr/bin/env bash
set -euo pipefail

base_url=""
path_id="helper-web"
code=""
summary_json=""
abuse_message="bridge service smoke"

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_bridge_service_smoke.sh --base-url URL [--path-id helper-web] [--code CODE] [--summary-json FILE] [--abuse-message TEXT]

Checks /health, /bridge/{path_id}, no-store/no-referrer headers, and /abuse logging acceptance.
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
    --summary-json)
      summary_json="${2:-}"
      shift 2
      ;;
    --abuse-message)
      abuse_message="${2:-}"
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

for cmd in curl jq; do
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

tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

health_body="$tmp_dir/health.json"
bridge_body="$tmp_dir/bridge.json"
bridge_headers="$tmp_dir/bridge.headers"
abuse_body="$tmp_dir/abuse.json"

health_http="$(curl -sS -o "$health_body" -w '%{http_code}' "${base_url}/health" || true)"

curl_args=(-sS -D "$bridge_headers" -o "$bridge_body" -w '%{http_code}')
if [[ -n "$code" ]]; then
  curl_args+=(-H "X-GPM-Bridge-Code: ${code}")
fi
bridge_http="$(curl "${curl_args[@]}" "${base_url}/bridge/${path_id}" || true)"

abuse_payload="$(jq -cn --arg path_id "$path_id" --arg message "$abuse_message" '{path_id:$path_id,message:$message}')"
abuse_http="$(curl -sS -X POST -H 'Content-Type: application/json' -d "$abuse_payload" -o "$abuse_body" -w '%{http_code}' "${base_url}/abuse" || true)"

health_status="$(jq -r '.status // ""' "$health_body" 2>/dev/null || true)"
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
elif [[ "$bridge_http" != "200" || "$bridge_status" != "ok" ]]; then
  status="fail"
  notes="bridge path check failed"
elif [[ "$headers_ok" != "true" ]]; then
  status="fail"
  notes="bridge response security headers missing"
elif [[ "$abuse_http" != "202" ]]; then
  status="fail"
  notes="abuse report check failed"
fi

summary="$(jq -cn \
  --arg status "$status" \
  --arg notes "$notes" \
  --arg base_url "$base_url" \
  --arg path_id "$path_id" \
  --arg health_http "$health_http" \
  --arg health_status "$health_status" \
  --arg bridge_http "$bridge_http" \
  --arg bridge_status "$bridge_status" \
  --arg abuse_http "$abuse_http" \
  --argjson headers_ok "$headers_ok" \
  '{version:1,status:$status,notes:$notes,base_url:$base_url,path_id:$path_id,health:{http_status:$health_http,status:$health_status},bridge:{http_status:$bridge_http,status:$bridge_status,security_headers_ok:$headers_ok},abuse:{http_status:$abuse_http}}')"

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary" >"$summary_json"
fi
printf '%s\n' "$summary"

if [[ "$status" != "pass" ]]; then
  exit 1
fi
