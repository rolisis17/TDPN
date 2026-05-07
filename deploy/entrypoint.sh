#!/bin/sh
set -eu

validate_wg_key_path() {
  key_path="$1"
  allowed_root="${EXIT_WG_PRIVATE_KEY_ROOT:-/app/data}"

  if command -v realpath >/dev/null 2>&1 && realpath -m "$allowed_root" >/dev/null 2>&1; then
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
    allowed_root_clean="${allowed_root%/}"
    case "$key_path" in
      "$allowed_root_clean"/*) ;;
      *)
        echo "refusing EXIT_WG_PRIVATE_KEY_PATH outside ${allowed_root_clean}: $key_path" >&2
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
  reject_wg_key_symlink_component "$key_dir" "$allowed_root"
  mkdir -p "$key_dir"
  reject_wg_key_symlink_component "$key_dir" "$allowed_root"
  if [ -L "$key_dir" ]; then
    echo "refusing EXIT_WG_PRIVATE_KEY_PATH parent symlink: $key_dir" >&2
    exit 1
  fi
}

reject_wg_key_symlink_component() {
  check_path="$1"
  root_path="${2%/}"

  case "$check_path" in
    "$root_path") return 0 ;;
    "$root_path"/*) ;;
    *) return 0 ;;
  esac

  remaining="${check_path#"$root_path"/}"
  current="$root_path"
  while [ -n "$remaining" ]; do
    component="${remaining%%/*}"
    if [ "$remaining" = "$component" ]; then
      remaining=""
    else
      remaining="${remaining#*/}"
    fi
    [ -z "$component" ] && continue
    current="${current%/}/$component"
    if [ -L "$current" ]; then
      echo "refusing EXIT_WG_PRIVATE_KEY_PATH parent symlink: $current" >&2
      exit 1
    fi
    if [ ! -e "$current" ]; then
      return 0
    fi
  done
}

owner_only_mode() {
  key_path="$1"
  mode="$(stat -c '%a' "$key_path" 2>/dev/null || true)"
  case "$mode" in
    *00) return 0 ;;
    *) return 1 ;;
  esac
}

copy_wg_key_to_runtime_secret() {
  key_path="$1"
  runtime_parent="${EXIT_WG_PRIVATE_KEY_RUNTIME_PARENT:-${TMPDIR:-/tmp}}"
  runtime_dir="$(mktemp -d "${runtime_parent%/}/privacynode-wg.XXXXXX")"
  chmod 700 "$runtime_dir" 2>/dev/null || true
  runtime_key="$runtime_dir/$(basename "$key_path")"
  cp "$key_path" "$runtime_key"
  chmod 600 "$runtime_key"
  if ! owner_only_mode "$runtime_key"; then
    echo "refusing runtime EXIT_WG_PRIVATE_KEY_PATH with broad permissions: $runtime_key" >&2
    exit 1
  fi
  export EXIT_WG_PRIVATE_KEY_PATH="$runtime_key"
  echo "entrypoint: copied EXIT_WG_PRIVATE_KEY_PATH to owner-only runtime secret: $runtime_key" >&2
}

if [ "${WG_BACKEND:-noop}" = "command" ]; then
  key_path="${EXIT_WG_PRIVATE_KEY_PATH:-}"
  if [ -n "$key_path" ]; then
    validate_wg_key_path "$key_path"
    if [ ! -s "$key_path" ]; then
      key_dir="$(dirname "$key_path")"
      tmp_key="$(mktemp "$key_dir/.wgkey.XXXXXX")"
      trap 'rm -f "${tmp_key:-}"' EXIT
      umask 077
      wg genkey >"$tmp_key"
      mv -f "$tmp_key" "$key_path"
      tmp_key=""
    fi
    chmod 600 "$key_path" 2>/dev/null || true
    if [ "${EXIT_WG_PRIVATE_KEY_FORCE_RUNTIME_COPY:-0}" = "1" ] || ! owner_only_mode "$key_path"; then
      copy_wg_key_to_runtime_secret "$key_path"
    fi
  fi

  if [ "${EXIT_WG_AUTO_CREATE_INTERFACE:-0}" = "1" ]; then
    iface="${EXIT_WG_INTERFACE:-wg-exit0}"
    if ! ip link show dev "$iface" >/dev/null 2>&1; then
      if ! ip link add dev "$iface" type wireguard >/dev/null 2>&1; then
        echo "entrypoint: failed to auto-create EXIT_WG_INTERFACE '$iface' (requires NET_ADMIN/privileged WireGuard-capable runtime)" >&2
        exit 1
      fi
    fi
  fi
fi

exec "${PRIVACYNODE_ENTRYPOINT_EXEC:-/usr/local/bin/node}" "$@"
