#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in bash mktemp rg sed; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TMP_DIR="$(mktemp -d)"
KEY_DIR="$TMP_DIR/client_vpn_keys"
mkdir -p "$KEY_DIR"

STATE_FILE="$ROOT_DIR/deploy/data/client_vpn.state"
STATE_BACKUP="$TMP_DIR/client_vpn.state.bak"
STATE_HAD_ORIGINAL="0"
if [[ -f "$STATE_FILE" ]]; then
  cp "$STATE_FILE" "$STATE_BACKUP"
  STATE_HAD_ORIGINAL="1"
fi

cleanup() {
  if [[ "$STATE_HAD_ORIGINAL" == "1" ]]; then
    mkdir -p "$(dirname "$STATE_FILE")"
    cp "$STATE_BACKUP" "$STATE_FILE"
  else
    rm -f "$STATE_FILE"
  fi
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "[client-vpn-trust-reset] scoped target by directory set"
OUT_SCOPED_DRY="$TMP_DIR/scoped_dry.log"
EASY_NODE_CLIENT_VPN_KEY_DIR="$KEY_DIR" \
  ./scripts/easy_node.sh client-vpn-trust-reset \
    --directory-urls "http://dir-b:8081,http://dir-a:8081" \
    --trust-scope scoped \
    --dry-run 1 >"$OUT_SCOPED_DRY" 2>&1
scoped_target="$(sed -n 's/^target_file: //p' "$OUT_SCOPED_DRY" | head -n 1)"
if [[ -z "$scoped_target" ]]; then
  echo "expected scoped target file in dry-run output"
  cat "$OUT_SCOPED_DRY"
  exit 1
fi
mkdir -p "$(dirname "$scoped_target")"
printf 'pinned-key\n' >"$scoped_target"
OUT_SCOPED="$TMP_DIR/scoped_reset.log"
EASY_NODE_CLIENT_VPN_KEY_DIR="$KEY_DIR" \
  ./scripts/easy_node.sh client-vpn-trust-reset \
    --directory-urls "http://dir-a:8081,http://dir-b:8081" \
    --trust-scope scoped >"$OUT_SCOPED" 2>&1
if ! rg -q "^removed_file: ${scoped_target}$" "$OUT_SCOPED"; then
  echo "expected scoped trust file removal output"
  cat "$OUT_SCOPED"
  exit 1
fi
if [[ -f "$scoped_target" ]]; then
  echo "scoped trust file should be removed"
  exit 1
fi

echo "[client-vpn-trust-reset] state fallback"
state_trust="$KEY_DIR/state_trust.txt"
printf 'state-key\n' >"$state_trust"
cat >"$STATE_FILE" <<EOF_STATE
CLIENT_VPN_PID=
CLIENT_VPN_TRUST_FILE=$state_trust
CLIENT_VPN_TRUST_SCOPE=scoped
CLIENT_VPN_DIRECTORY_URLS=
EOF_STATE
OUT_STATE="$TMP_DIR/state_reset.log"
EASY_NODE_CLIENT_VPN_KEY_DIR="$KEY_DIR" \
  ./scripts/easy_node.sh client-vpn-trust-reset >"$OUT_STATE" 2>&1
if ! rg -q "^removed_file: ${state_trust}$" "$OUT_STATE"; then
  echo "expected state trust file removal output"
  cat "$OUT_STATE"
  exit 1
fi
if [[ -f "$state_trust" ]]; then
  echo "state trust file should be removed"
  exit 1
fi

echo "[client-vpn-trust-reset] all scoped"
scoped_a="$KEY_DIR/trusted_directory_keys_aaa.txt"
scoped_b="$KEY_DIR/trusted_directory_keys_bbb.txt"
global_file="$KEY_DIR/trusted_directory_keys.txt"
printf 'a\n' >"$scoped_a"
printf 'b\n' >"$scoped_b"
printf 'g\n' >"$global_file"
OUT_ALL_SCOPED="$TMP_DIR/all_scoped.log"
EASY_NODE_CLIENT_VPN_KEY_DIR="$KEY_DIR" \
  ./scripts/easy_node.sh client-vpn-trust-reset --all-scoped 1 >"$OUT_ALL_SCOPED" 2>&1
if [[ -f "$scoped_a" || -f "$scoped_b" ]]; then
  echo "all-scoped reset should remove scoped trust files"
  cat "$OUT_ALL_SCOPED"
  exit 1
fi
if [[ ! -f "$global_file" ]]; then
  echo "all-scoped reset should not remove global trust file"
  cat "$OUT_ALL_SCOPED"
  exit 1
fi

echo "[client-vpn-trust-reset] global mode"
printf 'g2\n' >"$global_file"
OUT_GLOBAL="$TMP_DIR/global_reset.log"
EASY_NODE_CLIENT_VPN_KEY_DIR="$KEY_DIR" \
  ./scripts/easy_node.sh client-vpn-trust-reset --trust-scope global >"$OUT_GLOBAL" 2>&1
if ! rg -q "^removed_file: ${global_file}$" "$OUT_GLOBAL"; then
  echo "expected global trust file removal output"
  cat "$OUT_GLOBAL"
  exit 1
fi
if [[ -f "$global_file" ]]; then
  echo "global trust file should be removed"
  exit 1
fi

echo "[client-vpn-trust-reset] DIRECTORY_TRUSTED_KEYS_FILE override precedence"
override_file="$KEY_DIR/override_trust.txt"
printf 'override\n' >"$override_file"
printf 'global\n' >"$global_file"
OUT_OVERRIDE="$TMP_DIR/override_reset.log"
EASY_NODE_CLIENT_VPN_KEY_DIR="$KEY_DIR" \
DIRECTORY_TRUSTED_KEYS_FILE="$override_file" \
  ./scripts/easy_node.sh client-vpn-trust-reset --trust-scope global >"$OUT_OVERRIDE" 2>&1
if ! rg -q "^removed_file: ${override_file}$" "$OUT_OVERRIDE"; then
  echo "expected override trust file removal output"
  cat "$OUT_OVERRIDE"
  exit 1
fi
if [[ -f "$override_file" ]]; then
  echo "override trust file should be removed"
  exit 1
fi
if [[ ! -f "$global_file" ]]; then
  echo "global trust file should remain when override is set"
  exit 1
fi

echo "[client-vpn-trust-reset] invalid trust scope"
OUT_INVALID="$TMP_DIR/invalid_scope.log"
set +e
EASY_NODE_CLIENT_VPN_KEY_DIR="$KEY_DIR" \
  ./scripts/easy_node.sh client-vpn-trust-reset --trust-scope invalid >"$OUT_INVALID" 2>&1
rc_invalid=$?
set -e
if [[ "$rc_invalid" -eq 0 ]]; then
  echo "expected invalid trust scope to fail"
  cat "$OUT_INVALID"
  exit 1
fi
if ! rg -q 'requires --trust-scope.*scoped, global' "$OUT_INVALID"; then
  echo "missing invalid trust scope validation message"
  cat "$OUT_INVALID"
  exit 1
fi

echo "client-vpn trust reset integration check ok"
