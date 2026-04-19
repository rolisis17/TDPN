#!/bin/sh
set -eu

if [ "${WG_BACKEND:-noop}" = "command" ]; then
  key_path="${EXIT_WG_PRIVATE_KEY_PATH:-}"
  if [ -n "$key_path" ] && [ ! -s "$key_path" ]; then
    allowed_root="${EXIT_WG_PRIVATE_KEY_ROOT:-/app/data}"
    if command -v realpath >/dev/null 2>&1; then
      resolved_root="$(realpath -m "$allowed_root")"
      resolved_key="$(realpath -m "$key_path")"
      case "$resolved_key" in
        "$resolved_root"/*) ;;
        *)
          echo "refusing EXIT_WG_PRIVATE_KEY_PATH outside ${resolved_root}: $key_path" >&2
          exit 1
          ;;
      esac
    else
      case "$key_path" in
        "$allowed_root"/*) ;;
        *)
          echo "refusing EXIT_WG_PRIVATE_KEY_PATH outside ${allowed_root}: $key_path" >&2
          exit 1
          ;;
      esac
    fi
    case "$key_path" in
      *".."*)
        echo "refusing EXIT_WG_PRIVATE_KEY_PATH containing '..': $key_path" >&2
        exit 1
        ;;
    esac
    if [ -L "$key_path" ]; then
      echo "refusing EXIT_WG_PRIVATE_KEY_PATH symlink target: $key_path" >&2
      exit 1
    fi
    if [ -e "$key_path" ] && [ ! -f "$key_path" ]; then
      echo "refusing EXIT_WG_PRIVATE_KEY_PATH non-regular file target: $key_path" >&2
      exit 1
    fi
    key_dir="$(dirname "$key_path")"
    mkdir -p "$key_dir"
    if [ -L "$key_dir" ]; then
      echo "refusing EXIT_WG_PRIVATE_KEY_PATH parent symlink: $key_dir" >&2
      exit 1
    fi
    tmp_key="$(mktemp "$key_dir/.wgkey.XXXXXX")"
    trap 'rm -f "${tmp_key:-}"' EXIT
    umask 077
    wg genkey >"$tmp_key"
    mv -f "$tmp_key" "$key_path"
    tmp_key=""
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
