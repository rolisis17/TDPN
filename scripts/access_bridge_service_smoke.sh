#!/usr/bin/env bash
set -euo pipefail

base_url=""
path_id="helper-web"
code=""
code_file=""
allow_unauthenticated="0"
require_tls="0"
require_mtls="0"
cacert=""
client_cert=""
client_key=""
summary_json=""
abuse_message="bridge service smoke"
expect_helper_id=""
expect_org_id=""
expect_registry_id=""

usage() {
  cat <<'USAGE'
Usage:
  scripts/access_bridge_service_smoke.sh --base-url URL [--path-id helper-web] (--code CODE | --code-file FILE) [--cacert FILE] [--client-cert FILE --client-key FILE] [--require-tls 0|1] [--require-mtls 0|1] [--expect-helper-id ID] [--expect-org-id ID] [--expect-registry-id ID] [--summary-json FILE] [--abuse-message TEXT]
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
    --require-tls)
      require_tls="${2:-1}"
      shift 2
      ;;
    --require-mtls)
      require_mtls="${2:-1}"
      shift 2
      ;;
    --cacert)
      cacert="${2:-}"
      shift 2
      ;;
    --client-cert)
      client_cert="${2:-}"
      shift 2
      ;;
    --client-key)
      client_key="${2:-}"
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

for cmd in awk curl date jq sed; do
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
if [[ "$require_tls" != "0" && "$require_tls" != "1" ]]; then
  echo "access bridge service smoke failed: --require-tls must be 0 or 1" >&2
  exit 2
fi
if [[ "$require_mtls" != "0" && "$require_mtls" != "1" ]]; then
  echo "access bridge service smoke failed: --require-mtls must be 0 or 1" >&2
  exit 2
fi
if [[ -n "$cacert" && ! -f "$cacert" ]]; then
  echo "access bridge service smoke failed: cacert file not found: $cacert" >&2
  exit 2
fi
if [[ -n "$client_cert" && ! -f "$client_cert" ]]; then
  echo "access bridge service smoke failed: client cert file not found: $client_cert" >&2
  exit 2
fi
if [[ -n "$client_key" && ! -f "$client_key" ]]; then
  echo "access bridge service smoke failed: client key file not found: $client_key" >&2
  exit 2
fi
if { [[ -n "$client_cert" ]] && [[ -z "$client_key" ]]; } || { [[ -z "$client_cert" ]] && [[ -n "$client_key" ]]; }; then
  echo "access bridge service smoke failed: --client-cert and --client-key must be supplied together" >&2
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
health_meta="$tmp_dir/health.meta"
health_stderr="$tmp_dir/health.stderr"
missing_client_cert_health_body="$tmp_dir/missing-client-cert-health.json"
missing_client_cert_health_meta="$tmp_dir/missing-client-cert-health.meta"
missing_client_cert_health_stderr="$tmp_dir/missing-client-cert-health.stderr"

url_scheme() {
  local raw="$1"
  if [[ "$raw" =~ ^([A-Za-z][A-Za-z0-9+.-]*):// ]]; then
    printf '%s' "${BASH_REMATCH[1]}" | tr '[:upper:]' '[:lower:]'
  fi
}

url_authority() {
  local raw="$1"
  raw="${raw#*://}"
  raw="${raw%%/*}"
  raw="${raw%%\?*}"
  raw="${raw%%#*}"
  printf '%s' "$raw"
}

url_host() {
  local authority host
  authority="$(url_authority "$1")"
  authority="${authority##*@}"
  if [[ "$authority" == \[* ]]; then
    host="${authority#\[}"
    host="${host%%\]*}"
  else
    host="${authority%%:*}"
  fi
  printf '%s' "$host" | tr '[:upper:]' '[:lower:]' | sed -E 's/\.+$//'
}

url_port() {
  local raw="$1"
  local scheme authority rest
  scheme="$(url_scheme "$raw")"
  authority="$(url_authority "$raw")"
  authority="${authority##*@}"
  if [[ "$authority" == \[* ]]; then
    rest="${authority#*\]}"
    if [[ "$rest" == :* ]]; then
      printf '%s' "${rest#:}"
      return 0
    fi
  elif [[ "$authority" == *:* ]]; then
    printf '%s' "${authority##*:}"
    return 0
  fi
  if [[ "$scheme" == "https" ]]; then
    printf '%s' "443"
  elif [[ "$scheme" == "http" ]]; then
    printf '%s' "80"
  fi
}

host_is_loopback() {
  local host
  host="$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')"
  [[ "$host" == "localhost" || "$host" == "127."* || "$host" == "::1" || "$host" == "0:0:0:0:0:0:0:1" ]]
}

meta_value() {
  local file="$1"
  local key="$2"
  awk -F= -v k="$key" '$1 == k {print substr($0, length(k) + 2); exit}' "$file" 2>/dev/null || true
}

mtls_rejection_signal_01() {
  local http_code="${1:-}"
  local body_file="${2:-}"
  local stderr_text="${3:-}"
  local probe_text=""
  if [[ -n "$body_file" && -f "$body_file" ]]; then
    probe_text="$(tr -d '\r' <"$body_file" | tr '[:upper:]' '[:lower:]')"
  fi
  probe_text="${probe_text}
$(printf '%s' "$stderr_text" | tr '[:upper:]' '[:lower:]')"
  if [[ "$http_code" == "495" || "$http_code" == "496" ]]; then
    return 0
  fi
  printf '%s\n' "$probe_text" | grep -Eiq \
    'client[ _-]*certificate|certificate[ _-]*(required|needed|missing)|no[ _-]*(required[ _-]*)?ssl[ _-]*certificate|tlsv[0-9.]*[ _-]*alert[ _-]*certificate[ _-]*required|ssl[ _-]*certificate[ _-]*(error|required)|mtls'
}

curl_common_args=(-sS)
if [[ -n "$cacert" ]]; then
  curl_common_args+=(--cacert "$cacert")
fi
curl_no_client_cert_args=(-sS)
if [[ -n "$cacert" ]]; then
  curl_no_client_cert_args+=(--cacert "$cacert")
fi
if [[ -n "$client_cert" ]]; then
  curl_common_args+=(--cert "$client_cert" --key "$client_key")
fi

base_url_scheme="$(url_scheme "$base_url")"
base_url_host="$(url_host "$base_url")"
base_url_port="$(url_port "$base_url")"
base_url_loopback="false"
if host_is_loopback "$base_url_host"; then
  base_url_loopback="true"
fi
base_url_https="false"
if [[ "$base_url_scheme" == "https" ]]; then
  base_url_https="true"
fi

curl "${curl_common_args[@]}" \
  -o "$health_body" \
  -w $'http_code=%{http_code}\nssl_verify_result=%{ssl_verify_result}\nremote_ip=%{remote_ip}\nremote_port=%{remote_port}\nhttp_version=%{http_version}\ntime_connect=%{time_connect}\ntime_appconnect=%{time_appconnect}\nurl_effective=%{url_effective}\n' \
  "${base_url}/health" >"$health_meta" 2>"$health_stderr" || true
health_http="$(meta_value "$health_meta" "http_code")"
health_ssl_verify_result="$(meta_value "$health_meta" "ssl_verify_result")"
health_remote_ip="$(meta_value "$health_meta" "remote_ip")"
health_remote_port="$(meta_value "$health_meta" "remote_port")"
health_http_version="$(meta_value "$health_meta" "http_version")"
health_time_connect="$(meta_value "$health_meta" "time_connect")"
health_time_appconnect="$(meta_value "$health_meta" "time_appconnect")"
health_url_effective="$(meta_value "$health_meta" "url_effective")"
health_curl_error="$(tr -d '\r' <"$health_stderr" | tail -n 3 | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/[[:space:]]+$//')"
if [[ -z "$health_http" ]]; then
  health_http="000"
fi
tls_checked="$base_url_https"
tls_verified="false"
if [[ "$base_url_https" == "true" && "$health_ssl_verify_result" == "0" && "$health_http" != "000" ]]; then
  tls_verified="true"
fi
mtls_client_configured="false"
if [[ -n "$client_cert" && -n "$client_key" ]]; then
  mtls_client_configured="true"
fi
mtls_required="false"
if [[ "$require_mtls" == "1" ]]; then
  mtls_required="true"
fi
mtls_missing_client_cert_rejected="false"
mtls_missing_client_cert_health_http="skipped"
mtls_missing_client_cert_health_curl_rc=""
mtls_missing_client_cert_health_curl_error=""
mtls_missing_client_cert_health_effective_url=""
mtls_missing_client_cert_health_remote_ip=""
mtls_missing_client_cert_health_remote_port=""
mtls_missing_client_cert_same_endpoint="false"
mtls_missing_client_cert_rejection_signal="false"
if [[ "$require_mtls" == "1" ]]; then
  set +e
  curl "${curl_no_client_cert_args[@]}" \
    -o "$missing_client_cert_health_body" \
    -w $'http_code=%{http_code}\nssl_verify_result=%{ssl_verify_result}\nremote_ip=%{remote_ip}\nremote_port=%{remote_port}\nhttp_version=%{http_version}\ntime_connect=%{time_connect}\ntime_appconnect=%{time_appconnect}\nurl_effective=%{url_effective}\n' \
    "${base_url}/health" >"$missing_client_cert_health_meta" 2>"$missing_client_cert_health_stderr"
  mtls_missing_client_cert_health_curl_rc=$?
  set -e
  mtls_missing_client_cert_health_http="$(meta_value "$missing_client_cert_health_meta" "http_code")"
  if [[ -z "$mtls_missing_client_cert_health_http" ]]; then
    mtls_missing_client_cert_health_http="000"
  fi
  mtls_missing_client_cert_health_effective_url="$(meta_value "$missing_client_cert_health_meta" "url_effective")"
  mtls_missing_client_cert_health_remote_ip="$(meta_value "$missing_client_cert_health_meta" "remote_ip")"
  mtls_missing_client_cert_health_remote_port="$(meta_value "$missing_client_cert_health_meta" "remote_port")"
  mtls_missing_client_cert_health_curl_error="$(tr -d '\r' <"$missing_client_cert_health_stderr" | tail -n 3 | tr '\n' ' ' | sed -E 's/[[:space:]]+/ /g; s/[[:space:]]+$//')"
  if mtls_rejection_signal_01 "$mtls_missing_client_cert_health_http" "$missing_client_cert_health_body" "$mtls_missing_client_cert_health_curl_error"; then
    mtls_missing_client_cert_rejection_signal="true"
  fi
  if [[ -n "$mtls_missing_client_cert_health_effective_url" &&
    -n "$health_url_effective" &&
    "$mtls_missing_client_cert_health_effective_url" == "$health_url_effective" ]]; then
    if [[ "$mtls_missing_client_cert_health_http" == "000" && "$mtls_missing_client_cert_rejection_signal" == "true" ]]; then
      mtls_missing_client_cert_same_endpoint="true"
    elif [[ -n "$mtls_missing_client_cert_health_remote_ip" &&
      -n "$health_remote_ip" &&
      "$mtls_missing_client_cert_health_remote_ip" == "$health_remote_ip" &&
      -n "$mtls_missing_client_cert_health_remote_port" &&
      -n "$health_remote_port" &&
      "$mtls_missing_client_cert_health_remote_port" == "$health_remote_port" ]]; then
      mtls_missing_client_cert_same_endpoint="true"
    fi
  fi
  case "$mtls_missing_client_cert_health_http" in
    000|400|401|403|421|495|496)
      if [[ "$mtls_missing_client_cert_rejection_signal" == "true" &&
        "$mtls_missing_client_cert_same_endpoint" == "true" &&
        ! "$mtls_missing_client_cert_health_http" =~ ^2[0-9][0-9]$ ]]; then
        mtls_missing_client_cert_rejected="true"
      fi
      ;;
  esac
fi
mtls_client_used="$mtls_client_configured"
if [[ "$require_mtls" == "1" && ( "$mtls_client_configured" != "true" || "$mtls_missing_client_cert_rejected" != "true" || "$mtls_missing_client_cert_same_endpoint" != "true" || "$health_http" != "200" ) ]]; then
  mtls_client_used="false"
fi

missing_code_http="skipped"
wrong_code_http="skipped"
if [[ "$allow_unauthenticated" != "1" ]]; then
  missing_code_http="$(curl "${curl_common_args[@]}" -o "$missing_code_body" -w '%{http_code}' "${base_url}/bridge/${path_id}" || true)"
  printf 'header = "X-GPM-Bridge-Code: wrong-code-denied"\n' >"$wrong_code_header_config"
  wrong_code_http="$(curl "${curl_common_args[@]}" --config "$wrong_code_header_config" -o "$wrong_code_body" -w '%{http_code}' "${base_url}/bridge/${path_id}" || true)"
fi

curl_args=("${curl_common_args[@]}" -D "$bridge_headers" -o "$bridge_body" -w '%{http_code}')
if [[ -n "$code" ]]; then
  printf 'header = "X-GPM-Bridge-Code: %s"\n' "$code" >"$code_header_config"
  curl_args+=(--config "$code_header_config")
fi
bridge_http="$(curl "${curl_args[@]}" "${base_url}/bridge/${path_id}" || true)"

abuse_payload="$(jq -cn --arg path_id "$path_id" --arg message "$abuse_message" '{path_id:$path_id,message:$message}')"
abuse_http="$(curl "${curl_common_args[@]}" -X POST -H 'Content-Type: application/json' -d "$abuse_payload" -o "$abuse_body" -w '%{http_code}' "${base_url}/abuse" || true)"

health_status="$(jq -r '.status // ""' "$health_body" 2>/dev/null || true)"
health_helper_id="$(jq -r '.decision.helper_id // ""' "$health_body" 2>/dev/null || true)"
health_org_id="$(jq -r '.decision.organization_id // ""' "$health_body" 2>/dev/null || true)"
health_registry_id="$(jq -r '.decision.registry_id // ""' "$health_body" 2>/dev/null || true)"
health_config_sha256="$(jq -r '.config_sha256 // ""' "$health_body" 2>/dev/null || true)"
bridge_status="$(jq -r '.status // ""' "$bridge_body" 2>/dev/null || true)"
headers_ok="false"
if grep -iq '^Referrer-Policy: no-referrer' "$bridge_headers" &&
  grep -iq '^Cache-Control: no-store' "$bridge_headers" &&
  grep -iq '^X-Content-Type-Options: nosniff' "$bridge_headers"; then
  headers_ok="true"
fi

status="pass"
notes="bridge service smoke passed"
if [[ "$require_mtls" == "1" && "$base_url_https" != "true" ]]; then
  status="fail"
  notes="required mTLS needs HTTPS transport"
elif [[ "$require_mtls" == "1" && "$mtls_client_configured" != "true" ]]; then
  status="fail"
  notes="required mTLS client certificate was not configured"
elif [[ "$health_http" != "200" || "$health_status" != "ok" ]]; then
  status="fail"
  notes="health check failed"
elif [[ "$require_tls" == "1" && "$tls_verified" != "true" ]]; then
  status="fail"
  notes="required TLS verification was not proven"
elif [[ "$require_mtls" == "1" && "$tls_verified" != "true" ]]; then
  status="fail"
  notes="required mTLS TLS verification was not proven"
elif [[ "$require_mtls" == "1" && "$mtls_missing_client_cert_rejected" != "true" ]]; then
  status="fail"
  notes="required mTLS missing-client-certificate rejection was not proven"
elif [[ "$require_mtls" == "1" && "$mtls_missing_client_cert_same_endpoint" != "true" ]]; then
  status="fail"
  notes="required mTLS missing-client-certificate check did not hit the same endpoint"
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
  --arg base_url_scheme "$base_url_scheme" \
  --arg base_url_host "$base_url_host" \
  --arg base_url_port "$base_url_port" \
  --arg health_url_effective "$health_url_effective" \
  --arg health_remote_ip "$health_remote_ip" \
  --arg health_remote_port "$health_remote_port" \
  --arg health_http_version "$health_http_version" \
  --arg health_time_connect "$health_time_connect" \
  --arg health_time_appconnect "$health_time_appconnect" \
  --arg health_ssl_verify_result "$health_ssl_verify_result" \
  --arg health_curl_error "$health_curl_error" \
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
  --argjson base_url_loopback "$base_url_loopback" \
  --argjson base_url_https "$base_url_https" \
  --argjson tls_checked "$tls_checked" \
  --argjson tls_verified "$tls_verified" \
  --arg mtls_missing_client_cert_health_http "$mtls_missing_client_cert_health_http" \
  --arg mtls_missing_client_cert_health_curl_rc "$mtls_missing_client_cert_health_curl_rc" \
  --arg mtls_missing_client_cert_health_curl_error "$mtls_missing_client_cert_health_curl_error" \
  --arg mtls_missing_client_cert_health_effective_url "$mtls_missing_client_cert_health_effective_url" \
  --arg mtls_missing_client_cert_health_remote_ip "$mtls_missing_client_cert_health_remote_ip" \
  --arg mtls_missing_client_cert_health_remote_port "$mtls_missing_client_cert_health_remote_port" \
  --argjson mtls_missing_client_cert_rejection_signal "$mtls_missing_client_cert_rejection_signal" \
  --argjson mtls_required "$mtls_required" \
  --argjson mtls_client_configured "$mtls_client_configured" \
  --argjson mtls_client_used "$mtls_client_used" \
  --argjson mtls_missing_client_cert_rejected "$mtls_missing_client_cert_rejected" \
  --argjson mtls_missing_client_cert_same_endpoint "$mtls_missing_client_cert_same_endpoint" \
  --argjson headers_ok "$headers_ok" \
  --argjson auth_required "$( [[ "$allow_unauthenticated" == "1" ]] && echo false || echo true )" \
  '{version:1,schema:{id:"access_bridge_service_smoke_summary",major:1,minor:5},generated_at_utc:$generated_at_utc,status:$status,notes:$notes,base_url:$base_url,path_id:$path_id,transport:{base_url_scheme:$base_url_scheme,base_url_host:$base_url_host,base_url_port:$base_url_port,loopback:$base_url_loopback,https:$base_url_https,health:{effective_url:$health_url_effective,remote_ip:$health_remote_ip,remote_port:$health_remote_port,http_version:$health_http_version,time_connect_sec:$health_time_connect,time_appconnect_sec:$health_time_appconnect,curl_error:$health_curl_error},tls:{checked:$tls_checked,verified:$tls_verified,ssl_verify_result:$health_ssl_verify_result},mtls:{required:$mtls_required,client_certificate_configured:$mtls_client_configured,client_certificate_used:$mtls_client_used,missing_client_certificate_rejected:$mtls_missing_client_cert_rejected,missing_client_certificate_same_endpoint:$mtls_missing_client_cert_same_endpoint,missing_client_certificate_rejection_signal:$mtls_missing_client_cert_rejection_signal,missing_client_certificate_health_http_status:$mtls_missing_client_cert_health_http,missing_client_certificate_health_curl_rc:(if $mtls_missing_client_cert_health_curl_rc == "" then null else ($mtls_missing_client_cert_health_curl_rc | tonumber) end),missing_client_certificate_health_curl_error:$mtls_missing_client_cert_health_curl_error,missing_client_certificate_health_effective_url:$mtls_missing_client_cert_health_effective_url,missing_client_certificate_health_remote_ip:$mtls_missing_client_cert_health_remote_ip,missing_client_certificate_health_remote_port:$mtls_missing_client_cert_health_remote_port}},health:{http_status:$health_http,status:$health_status,helper_id:$health_helper_id,organization_id:$health_org_id,registry_id:$health_registry_id,config_sha256:$health_config_sha256},auth:{required:$auth_required,missing_code_http_status:$missing_code_http,wrong_code_http_status:$wrong_code_http,valid_code_http_status:$bridge_http},bridge:{http_status:$bridge_http,status:$bridge_status,security_headers_ok:$headers_ok},abuse:{http_status:$abuse_http}}')"

if [[ -n "$summary_json" ]]; then
  mkdir -p "$(dirname "$summary_json")"
  printf '%s\n' "$summary" >"$summary_json"
fi
printf '%s\n' "$summary"

if [[ "$status" != "pass" ]]; then
  exit 1
fi
