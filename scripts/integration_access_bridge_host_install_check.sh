#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash go jq mktemp sha256sum cp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "access bridge host install check integration failed: missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

BUNDLE_DIR="$TMP_DIR/access-recovery-demo"
SERVICE_CONFIG="$TMP_DIR/bridge-service-config.json"
DEPLOY_DIR="$TMP_DIR/bridge-deploy"
CODE_FILE="$TMP_DIR/bridge-code.txt"
CODE_HASH_JSON="$TMP_DIR/bridge-code-hash.json"
SUMMARY_JSON="$TMP_DIR/access_bridge_host_install_check_summary.json"

go run ./cmd/gpmrecover demo-bundle \
  --out-dir "$BUNDLE_DIR" \
  --org-id host-check-org \
  --org-name "Host Check Org" \
  --base-url https://host-check.gpm-pilot.net \
  --helper-id helper-host-check \
  --helper-name "Host Check Helper" \
  --helper-url https://helper.gpm-pilot.net/host-check/bootstrap \
  --helper-contact mailto:helper-host-check@example.com \
  >"$TMP_DIR/demo-bundle.stdout.json"

trust_store="$(jq -r '.files.trust_store' "$BUNDLE_DIR/demo-manifest.json")"
bridge_invite="$(jq -r '.files.bridge_invite_signed' "$BUNDLE_DIR/demo-manifest.json")"
signed_registry="$(jq -r '.files.bridge_helper_registry_signed' "$BUNDLE_DIR/demo-manifest.json")"

go run ./cmd/gpmrecover bridge-service-config \
  --invite "$bridge_invite" \
  --trust-store "$trust_store" \
  --signed-helper-registry "$signed_registry" \
  --out "$SERVICE_CONFIG" >/dev/null

config_sha256="$(sha256sum "$SERVICE_CONFIG" | awk '{print $1}')"
go run ./cmd/gpmrecover bridge-service-code-generate --code-out "$CODE_FILE" --hash-out "$CODE_HASH_JSON" >/dev/null
code_hash="$(jq -r '.sha256' "$CODE_HASH_JSON")"

go run ./cmd/gpmrecover bridge-service-deploy-pack \
  --out-dir "$DEPLOY_DIR" \
  --service-name gpm-access-bridge-host-check \
  --install-dir /etc/gpm/access-bridge-host-check \
  --config /etc/gpm/access-bridge-host-check/bridge-service-config.json \
  --config-sha256 "$config_sha256" \
  --access-code-sha256 "$code_hash" \
  >/dev/null

build_installed_host_fixture() {
  local proxy_kind="$1"
  local fixture_dir="$2"
  local install_dir="$fixture_dir/etc/gpm/access-bridge-host-check"
  local unit_dir="$fixture_dir/etc/systemd/system"
  local proxy_dir="$fixture_dir/etc/$proxy_kind"
  local systemd_unit="$unit_dir/gpm-access-bridge-host-check.service"
  local active_proxy=""

  mkdir -p "$install_dir" "$unit_dir" "$proxy_dir"
  cp "$DEPLOY_DIR/gpm-access-bridge-host-check.env" "$install_dir/gpm-access-bridge-host-check.env"
  cp "$DEPLOY_DIR/run-gpm-access-bridge-host-check.sh" "$install_dir/run-gpm-access-bridge-host-check.sh"
  cp "$DEPLOY_DIR/gpm-access-bridge-host-check.service" "$systemd_unit"
  sed -i "s#/etc/gpm/access-bridge-host-check#$install_dir#g" "$systemd_unit"

  if [[ "$proxy_kind" == "caddy" ]]; then
    active_proxy="$proxy_dir/Caddyfile"
    cp "$DEPLOY_DIR/gpm-access-bridge-host-check.Caddyfile.example" "$active_proxy"
  elif [[ "$proxy_kind" == "nginx" ]]; then
    active_proxy="$proxy_dir/gpm-access-bridge-host-check.conf"
    cp "$DEPLOY_DIR/gpm-access-bridge-host-check.nginx.example.conf" "$active_proxy"
  else
    echo "access bridge host install check integration failed: unknown fixture proxy kind: $proxy_kind"
    exit 1
  fi

  printf '%s\t%s\t%s\n' "$install_dir" "$systemd_unit" "$active_proxy"
}

run_installed_host_check() {
  local install_dir="$1"
  local systemd_unit="$2"
  local proxy_kind="$3"
  local active_proxy="$4"
  local summary_json="$5"

  ./scripts/access_bridge_host_install_check.sh \
    --evidence-mode installed-host \
    --install-dir "$install_dir" \
    --systemd-unit-file "$systemd_unit" \
    --proxy-kind "$proxy_kind" \
    --proxy-config-file "$active_proxy" \
    --deploy-pack-dir "$DEPLOY_DIR" \
    --service-name gpm-access-bridge-host-check \
    --config-json "$SERVICE_CONFIG" \
    --expected-base-url https://recovery-helper.gpm-pilot.net/bootstrap \
    --summary-json "$summary_json" \
    --print-summary-json 0
}

assert_installed_host_pass_summary() {
  local summary_json="$1"
  local install_dir="$2"
  local systemd_unit="$3"
  local proxy_kind="$4"
  local active_proxy="$5"

  if ! jq -e \
    --arg deploy_dir "$DEPLOY_DIR" \
    --arg install_dir "$install_dir" \
    --arg systemd_unit "$systemd_unit" \
    --arg proxy_kind "$proxy_kind" \
    --arg active_proxy "$active_proxy" \
    '
      .schema.id == "access_bridge_host_install_check_summary"
      and .status == "pass"
      and .inputs.evidence_mode == "installed-host"
      and .inputs.installed_host_mode == true
      and .inputs.deploy_pack_dir == $deploy_dir
      and .inputs.install_dir == $install_dir
      and .inputs.systemd_unit_file == $systemd_unit
      and .inputs.proxy_kind == $proxy_kind
      and .inputs.proxy_config_file == $active_proxy
      and (.observed.installed_host_mode == true or .observed.installed_host_mode == "true")
      and .observed.active_env_file == ($install_dir + "/gpm-access-bridge-host-check.env")
      and .observed.active_wrapper_file == ($install_dir + "/run-gpm-access-bridge-host-check.sh")
      and .observed.active_systemd_unit_file == $systemd_unit
      and .observed.active_proxy_kind == $proxy_kind
      and .observed.active_proxy_config_file == $active_proxy
      and .observed.active_proxy_is_deploy_pack_example == false
      and .observed.expected_public_host == "recovery-helper.gpm-pilot.net"
      and .observed.env_addr == "127.0.0.1:18980"
      and .summary.installed_host_mode == true
      and .summary.active_env_file == ($install_dir + "/gpm-access-bridge-host-check.env")
      and .summary.active_wrapper_file == ($install_dir + "/run-gpm-access-bridge-host-check.sh")
      and .summary.active_systemd_unit_file == $systemd_unit
      and .summary.active_proxy_kind == $proxy_kind
      and .summary.active_proxy_config_file == $active_proxy
      and .summary.active_proxy_is_deploy_pack_example == false
      and ([.checks[] | select((.id | startswith("active_proxy_")) and .status == "pass")] | length >= 4)
      and ([.checks[] | select((.id | startswith("active_proxy_")) and .status == "fail")] | length == 0)
      and .summary.checks_fail == 0
      and .recommended_next_action.id == "record_host_install_evidence"
    ' "$summary_json" >/dev/null; then
    echo "access bridge host install check integration failed: installed-host $proxy_kind pass summary mismatch"
    cat "$summary_json"
    exit 1
  fi
}

assert_installed_host_fail_summary() {
  local summary_json="$1"
  local description="$2"
  local fail_id_regex="$3"

  if ! jq -e \
    --arg fail_id_regex "$fail_id_regex" \
    '
      .status == "fail"
      and .inputs.evidence_mode == "installed-host"
      and .inputs.installed_host_mode == true
      and (.observed.installed_host_mode == true or .observed.installed_host_mode == "true")
      and .summary.installed_host_mode == true
      and ([.checks[] | select(.status == "fail" and (.id | test($fail_id_regex)))] | length >= 1)
    ' "$summary_json" >/dev/null; then
    echo "access bridge host install check integration failed: installed-host $description summary mismatch"
    cat "$summary_json"
    exit 1
  fi
}

for bad_deploy_arg in "--rps 0" "--rps 999999" "--max-sources 0" "--public-host helper.home.arpa" "--public-host helper.tailnet.ts.net"; do
  BAD_DEPLOY_ARG_DIR="$TMP_DIR/bad-deploy-arg-${bad_deploy_arg//[^A-Za-z0-9]/_}"
  set +e
  # shellcheck disable=SC2086
  go run ./cmd/gpmrecover bridge-service-deploy-pack \
    --out-dir "$BAD_DEPLOY_ARG_DIR" \
    --service-name gpm-access-bridge-host-check \
    --install-dir /etc/gpm/access-bridge-host-check \
    --config /etc/gpm/access-bridge-host-check/bridge-service-config.json \
    --config-sha256 "$config_sha256" \
    --access-code-sha256 "$code_hash" \
    $bad_deploy_arg >"$TMP_DIR/bad-deploy-arg.log" 2>&1
  bad_deploy_arg_rc=$?
  set -e
  if [[ "$bad_deploy_arg_rc" -eq 0 ]]; then
    echo "access bridge host install check integration failed: deploy pack accepted unsafe arg: $bad_deploy_arg"
    exit 1
  fi
done

IFS=$'\t' read -r INSTALL_DIR SYSTEMD_UNIT ACTIVE_PROXY < <(build_installed_host_fixture "caddy" "$TMP_DIR/installed-host-caddy")
CADDY_INSTALLED_SUMMARY="$TMP_DIR/installed-host-caddy-summary.json"
run_installed_host_check "$INSTALL_DIR" "$SYSTEMD_UNIT" "caddy" "$ACTIVE_PROXY" "$CADDY_INSTALLED_SUMMARY"
assert_installed_host_pass_summary "$CADDY_INSTALLED_SUMMARY" "$INSTALL_DIR" "$SYSTEMD_UNIT" "caddy" "$ACTIVE_PROXY"

set +e
./scripts/access_bridge_host_install_check.sh \
  --evidence-mode installed-host \
  --install-dir "$INSTALL_DIR" \
  --systemd-unit-file "$SYSTEMD_UNIT" \
  --proxy-kind caddy \
  --proxy-config-file "$ACTIVE_PROXY" \
  --deploy-pack-dir "$DEPLOY_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --expected-public-host recovery-helper.gpm-pilot.net \
  --summary-json "$TMP_DIR/installed-host-missing-expected-base-url-summary.json" \
  --print-summary-json 0 >"$TMP_DIR/installed-host-missing-expected-base-url.log" 2>&1
missing_expected_base_url_rc=$?
set -e
if [[ "$missing_expected_base_url_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: installed-host accepted expected-public-host without expected-base-url"
  cat "$TMP_DIR/installed-host-missing-expected-base-url-summary.json"
  exit 1
fi
if ! grep -Fq -- "--expected-base-url is required in installed-host mode" "$TMP_DIR/installed-host-missing-expected-base-url.log"; then
  echo "access bridge host install check integration failed: installed-host missing expected-base-url error mismatch"
  cat "$TMP_DIR/installed-host-missing-expected-base-url.log"
  exit 1
fi

IFS=$'\t' read -r INSTALL_DIR SYSTEMD_UNIT ACTIVE_PROXY < <(build_installed_host_fixture "nginx" "$TMP_DIR/installed-host-nginx")
NGINX_INSTALLED_SUMMARY="$TMP_DIR/installed-host-nginx-summary.json"
run_installed_host_check "$INSTALL_DIR" "$SYSTEMD_UNIT" "nginx" "$ACTIVE_PROXY" "$NGINX_INSTALLED_SUMMARY"
assert_installed_host_pass_summary "$NGINX_INSTALLED_SUMMARY" "$INSTALL_DIR" "$SYSTEMD_UNIT" "nginx" "$ACTIVE_PROXY"

IFS=$'\t' read -r INSTALL_DIR SYSTEMD_UNIT ACTIVE_PROXY < <(build_installed_host_fixture "caddy" "$TMP_DIR/installed-host-bad-active-proxy")
BAD_ACTIVE_PROXY="$DEPLOY_DIR/gpm-access-bridge-host-check.Caddyfile.example"
set +e
run_installed_host_check "$INSTALL_DIR" "$SYSTEMD_UNIT" "caddy" "$BAD_ACTIVE_PROXY" "$TMP_DIR/installed-host-bad-active-proxy-summary.json" >/dev/null 2>&1
bad_active_proxy_rc=$?
set -e
if [[ "$bad_active_proxy_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: installed-host proxy pointing at deploy-pack example should fail"
  cat "$TMP_DIR/installed-host-bad-active-proxy-summary.json"
  exit 1
fi
assert_installed_host_fail_summary "$TMP_DIR/installed-host-bad-active-proxy-summary.json" "deploy-pack proxy example" '^active_proxy_'

IFS=$'\t' read -r INSTALL_DIR SYSTEMD_UNIT ACTIVE_PROXY < <(build_installed_host_fixture "caddy" "$TMP_DIR/installed-host-bad-environment-file")
sed -i "s#^EnvironmentFile=.*#EnvironmentFile=$DEPLOY_DIR/gpm-access-bridge-host-check.env#" "$SYSTEMD_UNIT"
set +e
run_installed_host_check "$INSTALL_DIR" "$SYSTEMD_UNIT" "caddy" "$ACTIVE_PROXY" "$TMP_DIR/installed-host-bad-environment-file-summary.json" >/dev/null 2>&1
bad_environment_file_rc=$?
set -e
if [[ "$bad_environment_file_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: installed-host wrong EnvironmentFile should fail"
  cat "$TMP_DIR/installed-host-bad-environment-file-summary.json"
  exit 1
fi
assert_installed_host_fail_summary "$TMP_DIR/installed-host-bad-environment-file-summary.json" "wrong EnvironmentFile" '(EnvironmentFile|environment_file|env_file)'

IFS=$'\t' read -r INSTALL_DIR SYSTEMD_UNIT ACTIVE_PROXY < <(build_installed_host_fixture "caddy" "$TMP_DIR/installed-host-bad-exec-start")
sed -i "s#^ExecStart=.*#ExecStart=$DEPLOY_DIR/run-gpm-access-bridge-host-check.sh#" "$SYSTEMD_UNIT"
set +e
run_installed_host_check "$INSTALL_DIR" "$SYSTEMD_UNIT" "caddy" "$ACTIVE_PROXY" "$TMP_DIR/installed-host-bad-exec-start-summary.json" >/dev/null 2>&1
bad_exec_start_rc=$?
set -e
if [[ "$bad_exec_start_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: installed-host wrong ExecStart should fail"
  cat "$TMP_DIR/installed-host-bad-exec-start-summary.json"
  exit 1
fi
assert_installed_host_fail_summary "$TMP_DIR/installed-host-bad-exec-start-summary.json" "wrong ExecStart" '(ExecStart|exec_start|wrapper)'

./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$DEPLOY_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --expected-base-url https://recovery-helper.gpm-pilot.net/bootstrap \
  --summary-json "$SUMMARY_JSON" \
  --print-summary-json 0

if ! jq -e \
  --arg deploy_dir "$DEPLOY_DIR" \
  --arg config_sha256 "$config_sha256" \
  '
    .schema.id == "access_bridge_host_install_check_summary"
    and .status == "pass"
    and .inputs.deploy_pack_dir == $deploy_dir
    and .inputs.expected_base_url == "https://recovery-helper.gpm-pilot.net/bootstrap"
    and .inputs.expected_public_host == "recovery-helper.gpm-pilot.net"
    and .observed.expected_public_host == "recovery-helper.gpm-pilot.net"
    and .observed.expected_config_sha256 == $config_sha256
    and .observed.config_allow_local_access_paths == "false"
    and .observed.env_config_sha256 == $config_sha256
    and (.observed.env_access_code_sha256 | length == 64)
    and .observed.env_allow_query_code == "false"
    and .observed.env_trust_proxy_headers == "true"
    and .observed.env_addr == "127.0.0.1:18980"
    and .observed.env_rps == "2"
    and .observed.env_max_sources == "1024"
    and .observed.caddy_site_host == "recovery-helper.gpm-pilot.net"
    and .observed.caddy_reverse_proxy == "127.0.0.1:18980"
    and .observed.nginx_server_name == "recovery-helper.gpm-pilot.net"
    and .observed.nginx_proxy_pass == "127.0.0.1:18980"
    and ([.checks[] | select(.id == "rate_limit_configured" and .status == "pass")] | length == 1)
    and ([.checks[] | select(.id == "rate_limit_source_cap_configured" and .status == "pass")] | length == 1)
    and ([.checks[] | select(.id == "config_local_access_paths_disabled" and .status == "pass")] | length == 1)
    and ([.checks[] | select(.id == "loopback_bind" and .status == "pass")] | length == 1)
    and ([.checks[] | select(.id == "caddy_public_host_matches_expected" and .status == "pass")] | length == 1)
    and ([.checks[] | select(.id == "nginx_public_host_matches_expected" and .status == "pass")] | length == 1)
    and ([.checks[] | select(.id == "caddy_reverse_proxy_target" and .status == "pass")] | length == 1)
    and ([.checks[] | select(.id == "nginx_proxy_pass_target" and .status == "pass")] | length == 1)
    and .summary.checks_fail == 0
    and .recommended_next_action.id == "record_host_install_evidence"
  ' "$SUMMARY_JSON" >/dev/null; then
  echo "access bridge host install check integration failed: pass summary mismatch"
  cat "$SUMMARY_JSON"
  exit 1
fi

set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$DEPLOY_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --expected-base-url https://wrong-helper.gpm-pilot.net/bootstrap \
  --summary-json "$TMP_DIR/bad-expected-host-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_expected_host_rc=$?
set -e
if [[ "$bad_expected_host_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: mismatched expected helper host should fail"
  cat "$TMP_DIR/bad-expected-host-summary.json"
  exit 1
fi
if ! jq -e \
  '
    .status == "fail"
    and .observed.expected_public_host == "wrong-helper.gpm-pilot.net"
    and .observed.caddy_site_host == "recovery-helper.gpm-pilot.net"
    and .observed.nginx_server_name == "recovery-helper.gpm-pilot.net"
    and ([.checks[] | select(.id == "caddy_public_host_matches_expected" and .status == "fail")] | length == 1)
    and ([.checks[] | select(.id == "nginx_public_host_matches_expected" and .status == "fail")] | length == 1)
  ' "$TMP_DIR/bad-expected-host-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: mismatched expected helper host summary mismatch"
  cat "$TMP_DIR/bad-expected-host-summary.json"
  exit 1
fi

BAD_LOCAL_CONFIG="$TMP_DIR/bridge-service-config-local-diagnostic.json"
jq '.allow_local_access_paths = true' "$SERVICE_CONFIG" >"$BAD_LOCAL_CONFIG"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$DEPLOY_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$BAD_LOCAL_CONFIG" \
  --summary-json "$TMP_DIR/bad-local-config-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_local_config_rc=$?
set -e
if [[ "$bad_local_config_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: local-diagnostic service config should fail"
  cat "$TMP_DIR/bad-local-config-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and .observed.config_allow_local_access_paths == "true" and ([.checks[] | select(.id == "config_local_access_paths_disabled" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-local-config-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: local-diagnostic service config summary mismatch"
  cat "$TMP_DIR/bad-local-config-summary.json"
  exit 1
fi

bad_public_hosts=(
  "localhost"
  "10.0.0.8"
  "100.64.0.1"
  "169.254.1.1"
  "192.0.0.10"
  "192.0.2.10"
  "224.0.0.1"
  "helper.local"
  "helper.lan"
  "helper.internal"
  "helper.test"
  "helper.invalid"
  "helper.example"
  "helper"
  "com"
  "example.com"
  "example.net"
  "example.org"
  "home.arpa"
  "helper.home.arpa"
  "ts.net"
  "tailscale.net"
  "helper.tailnet.ts.net"
  "helper.tailscale.net"
  "user@public.tdpn.net"
  "public.tdpn.net."
)
bad_public_host_index=0
for bad_public_host in "${bad_public_hosts[@]}"; do
  bad_public_host_index=$((bad_public_host_index + 1))
  BAD_PUBLIC_HOST_DIR="$TMP_DIR/bad-public-host-$bad_public_host_index"
  cp -R "$DEPLOY_DIR" "$BAD_PUBLIC_HOST_DIR"
  sed -i "s/^recovery-helper.gpm-pilot.net {/$bad_public_host {/" "$BAD_PUBLIC_HOST_DIR/gpm-access-bridge-host-check.Caddyfile.example"
  sed -i "s/server_name recovery-helper.gpm-pilot.net;/server_name $bad_public_host;/" "$BAD_PUBLIC_HOST_DIR/gpm-access-bridge-host-check.nginx.example.conf"
  set +e
  ./scripts/access_bridge_host_install_check.sh \
    --deploy-pack-dir "$BAD_PUBLIC_HOST_DIR" \
    --service-name gpm-access-bridge-host-check \
    --config-json "$SERVICE_CONFIG" \
    --summary-json "$TMP_DIR/bad-public-host-$bad_public_host_index-summary.json" \
    --print-summary-json 0 >/dev/null 2>&1
  bad_public_host_rc=$?
  set -e
  if [[ "$bad_public_host_rc" -eq 0 ]]; then
    echo "access bridge host install check integration failed: unsafe public host should fail: $bad_public_host"
    cat "$TMP_DIR/bad-public-host-$bad_public_host_index-summary.json"
    exit 1
  fi
  if ! jq -e \
    --arg host "$bad_public_host" \
    '
      .status == "fail"
      and .observed.caddy_site_host == $host
      and .observed.nginx_server_name == $host
      and ([.checks[] | select(.id == "caddy_public_host_valid" and .status == "fail")] | length == 1)
      and ([.checks[] | select(.id == "nginx_public_host_valid" and .status == "fail")] | length == 1)
    ' "$TMP_DIR/bad-public-host-$bad_public_host_index-summary.json" >/dev/null; then
    echo "access bridge host install check integration failed: unsafe public host summary mismatch: $bad_public_host"
    cat "$TMP_DIR/bad-public-host-$bad_public_host_index-summary.json"
    exit 1
  fi
done

BAD_ADDR_DIR="$TMP_DIR/bad-addr"
cp -R "$DEPLOY_DIR" "$BAD_ADDR_DIR"
sed -i 's/GPM_BRIDGE_ADDR="127.0.0.1:18980"/GPM_BRIDGE_ADDR="127.evil.example:18980"/' "$BAD_ADDR_DIR/gpm-access-bridge-host-check.env"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_ADDR_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-addr-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_addr_rc=$?
set -e
if [[ "$bad_addr_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: non-loopback addr should fail"
  cat "$TMP_DIR/bad-addr-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and .observed.env_addr == "127.evil.example:18980" and ([.checks[] | select(.id == "loopback_bind" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-addr-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: bad addr summary mismatch"
  cat "$TMP_DIR/bad-addr-summary.json"
  exit 1
fi

BAD_CADDY_TARGET_DIR="$TMP_DIR/bad-caddy-target"
cp -R "$DEPLOY_DIR" "$BAD_CADDY_TARGET_DIR"
sed -i 's/reverse_proxy 127.0.0.1:18980/reverse_proxy evil.example:80/' "$BAD_CADDY_TARGET_DIR/gpm-access-bridge-host-check.Caddyfile.example"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_CADDY_TARGET_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-caddy-target-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_caddy_target_rc=$?
set -e
if [[ "$bad_caddy_target_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: mismatched Caddy reverse_proxy should fail"
  cat "$TMP_DIR/bad-caddy-target-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and .observed.caddy_reverse_proxy == "evil.example:80" and ([.checks[] | select(.id == "caddy_reverse_proxy_target" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-caddy-target-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: bad Caddy target summary mismatch"
  cat "$TMP_DIR/bad-caddy-target-summary.json"
  exit 1
fi

BAD_QUERY_DIR="$TMP_DIR/bad-query"
cp -R "$DEPLOY_DIR" "$BAD_QUERY_DIR"
sed -i 's/GPM_BRIDGE_ALLOW_QUERY_CODE="false"/GPM_BRIDGE_ALLOW_QUERY_CODE="true"/' "$BAD_QUERY_DIR/gpm-access-bridge-host-check.env"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_QUERY_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-query-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_query_rc=$?
set -e
if [[ "$bad_query_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: unsafe query env should fail"
  cat "$TMP_DIR/bad-query-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and ([.checks[] | select(.id == "query_access_code_disabled" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-query-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: unsafe query summary mismatch"
  cat "$TMP_DIR/bad-query-summary.json"
  exit 1
fi

BAD_UNAUTH_DIR="$TMP_DIR/bad-unauth"
cp -R "$DEPLOY_DIR" "$BAD_UNAUTH_DIR"
sed -i 's/GPM_BRIDGE_ACCESS_CODE_SHA256="[^"]*"/GPM_BRIDGE_ACCESS_CODE_SHA256=""/' "$BAD_UNAUTH_DIR/gpm-access-bridge-host-check.env"
sed -i 's/GPM_BRIDGE_ALLOW_UNAUTH_LOCAL="false"/GPM_BRIDGE_ALLOW_UNAUTH_LOCAL="true"/' "$BAD_UNAUTH_DIR/gpm-access-bridge-host-check.env"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_UNAUTH_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-unauth-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_unauth_rc=$?
set -e
if [[ "$bad_unauth_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: unauthenticated local env should fail"
  cat "$TMP_DIR/bad-unauth-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and .observed.env_allow_unauthenticated_local == "true" and ([.checks[] | select(.id == "access_code_gate_configured" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-unauth-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: unauthenticated local summary mismatch"
  cat "$TMP_DIR/bad-unauth-summary.json"
  exit 1
fi

BAD_HASH_DIR="$TMP_DIR/bad-hash"
cp -R "$DEPLOY_DIR" "$BAD_HASH_DIR"
sed -i 's/GPM_BRIDGE_ACCESS_CODE_SHA256="[^"]*"/GPM_BRIDGE_ACCESS_CODE_SHA256="not-a-valid-sha256"/' "$BAD_HASH_DIR/gpm-access-bridge-host-check.env"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_HASH_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-hash-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_hash_rc=$?
set -e
if [[ "$bad_hash_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: malformed access-code hash should fail"
  cat "$TMP_DIR/bad-hash-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and ([.checks[] | select(.id == "access_code_gate_configured" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-hash-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: bad hash summary mismatch"
  cat "$TMP_DIR/bad-hash-summary.json"
  exit 1
fi

BAD_RPS_DIR="$TMP_DIR/bad-rps"
cp -R "$DEPLOY_DIR" "$BAD_RPS_DIR"
sed -i 's/GPM_BRIDGE_RPS="2"/GPM_BRIDGE_RPS="0"/' "$BAD_RPS_DIR/gpm-access-bridge-host-check.env"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_RPS_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-rps-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_rps_rc=$?
set -e
if [[ "$bad_rps_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: disabled rate limit should fail"
  cat "$TMP_DIR/bad-rps-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and .observed.env_rps == "0" and ([.checks[] | select(.id == "rate_limit_configured" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-rps-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: bad rps summary mismatch"
  cat "$TMP_DIR/bad-rps-summary.json"
  exit 1
fi

BAD_HIGH_RPS_DIR="$TMP_DIR/bad-high-rps"
cp -R "$DEPLOY_DIR" "$BAD_HIGH_RPS_DIR"
sed -i 's/GPM_BRIDGE_RPS="2"/GPM_BRIDGE_RPS="999999"/' "$BAD_HIGH_RPS_DIR/gpm-access-bridge-host-check.env"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_HIGH_RPS_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-high-rps-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_high_rps_rc=$?
set -e
if [[ "$bad_high_rps_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: unbounded rate limit should fail"
  cat "$TMP_DIR/bad-high-rps-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and .observed.env_rps == "999999" and ([.checks[] | select(.id == "rate_limit_configured" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-high-rps-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: high rps summary mismatch"
  cat "$TMP_DIR/bad-high-rps-summary.json"
  exit 1
fi

BAD_MAX_SOURCES_DIR="$TMP_DIR/bad-max-sources"
cp -R "$DEPLOY_DIR" "$BAD_MAX_SOURCES_DIR"
sed -i 's/GPM_BRIDGE_MAX_SOURCES="1024"/GPM_BRIDGE_MAX_SOURCES="0"/' "$BAD_MAX_SOURCES_DIR/gpm-access-bridge-host-check.env"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_MAX_SOURCES_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-max-sources-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_max_sources_rc=$?
set -e
if [[ "$bad_max_sources_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: unbounded source tracking should fail"
  cat "$TMP_DIR/bad-max-sources-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and .observed.env_max_sources == "0" and ([.checks[] | select(.id == "rate_limit_source_cap_configured" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-max-sources-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: bad max-sources summary mismatch"
  cat "$TMP_DIR/bad-max-sources-summary.json"
  exit 1
fi

BAD_NGINX_DIR="$TMP_DIR/bad-nginx"
cp -R "$DEPLOY_DIR" "$BAD_NGINX_DIR"
sed -i 's/proxy_set_header X-Forwarded-For \$remote_addr;/proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;/' "$BAD_NGINX_DIR/gpm-access-bridge-host-check.nginx.example.conf"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_NGINX_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-nginx-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_nginx_rc=$?
set -e
if [[ "$bad_nginx_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: spoofable nginx XFF should fail"
  cat "$TMP_DIR/bad-nginx-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and ([.checks[] | select(.id == "nginx_xff_overwrite" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-nginx-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: bad nginx summary mismatch"
  cat "$TMP_DIR/bad-nginx-summary.json"
  exit 1
fi

BAD_NGINX_TARGET_DIR="$TMP_DIR/bad-nginx-target"
cp -R "$DEPLOY_DIR" "$BAD_NGINX_TARGET_DIR"
sed -i 's#proxy_pass http://127.0.0.1:18980;#proxy_pass http://evil.example:80;#' "$BAD_NGINX_TARGET_DIR/gpm-access-bridge-host-check.nginx.example.conf"
set +e
./scripts/access_bridge_host_install_check.sh \
  --deploy-pack-dir "$BAD_NGINX_TARGET_DIR" \
  --service-name gpm-access-bridge-host-check \
  --config-json "$SERVICE_CONFIG" \
  --summary-json "$TMP_DIR/bad-nginx-target-summary.json" \
  --print-summary-json 0 >/dev/null 2>&1
bad_nginx_target_rc=$?
set -e
if [[ "$bad_nginx_target_rc" -eq 0 ]]; then
  echo "access bridge host install check integration failed: mismatched nginx proxy_pass should fail"
  cat "$TMP_DIR/bad-nginx-target-summary.json"
  exit 1
fi
if ! jq -e '.status == "fail" and .observed.nginx_proxy_pass == "evil.example:80" and ([.checks[] | select(.id == "nginx_proxy_pass_target" and .status == "fail")] | length == 1)' "$TMP_DIR/bad-nginx-target-summary.json" >/dev/null; then
  echo "access bridge host install check integration failed: bad nginx target summary mismatch"
  cat "$TMP_DIR/bad-nginx-target-summary.json"
  exit 1
fi

echo "access bridge host install check integration ok"
