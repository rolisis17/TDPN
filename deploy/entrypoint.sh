#!/bin/sh
set -eu

if [ "${WG_BACKEND:-noop}" = "command" ]; then
  key_path="${EXIT_WG_PRIVATE_KEY_PATH:-}"
  if [ -n "$key_path" ] && [ ! -s "$key_path" ]; then
    key_dir="$(dirname "$key_path")"
    mkdir -p "$key_dir"
    umask 077
    wg genkey >"$key_path"
    chmod 600 "$key_path" 2>/dev/null || true
  fi

  if [ "${EXIT_WG_AUTO_CREATE_INTERFACE:-0}" = "1" ]; then
    iface="${EXIT_WG_INTERFACE:-wg-exit0}"
    if ! ip link show dev "$iface" >/dev/null 2>&1; then
      ip link add dev "$iface" type wireguard >/dev/null 2>&1 || true
    fi
  fi
fi

exec /usr/local/bin/node "$@"
