#!/usr/bin/env bash
set -euo pipefail

if ! command -v apt-get >/dev/null 2>&1; then
  echo "this installer supports Ubuntu/Debian systems with apt-get"
  exit 2
fi

as_root() {
  if [[ "${EUID:-$(id -u)}" -eq 0 ]]; then
    "$@"
  else
    if ! command -v sudo >/dev/null 2>&1; then
      echo "sudo is required (or run as root)"
      exit 2
    fi
    sudo "$@"
  fi
}

is_wsl() {
  grep -qiE '(microsoft|wsl)' /proc/version 2>/dev/null
}

bool_env_enabled() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    1|true|yes|on) return 0 ;;
    *) return 1 ;;
  esac
}

echo "[deps] installing Ubuntu project dependencies"
export DEBIAN_FRONTEND=noninteractive

base_packages=(
  ca-certificates
  coreutils
  curl
  gnupg
  iproute2
  jq
  lsb-release
  make
  git
  build-essential
  ripgrep
  golang-go
  wireguard-tools
)

as_root apt-get update -y
as_root apt-get install -y "${base_packages[@]}"

have_docker=0
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  have_docker=1
fi

if [[ "$have_docker" -eq 0 ]]; then
  echo "[deps] docker not fully available; installing docker engine + compose plugin"
  as_root install -m 0755 -d /etc/apt/keyrings
  docker_keyring="/etc/apt/keyrings/docker.asc"
  expected_docker_fingerprint="9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
  if [[ ! -f "$docker_keyring" ]]; then
    tmp_docker_key="$(mktemp)"
    trap 'rm -f "${tmp_docker_key:-}"' EXIT
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o "$tmp_docker_key"
    downloaded_fpr="$(gpg --show-keys --with-colons "$tmp_docker_key" 2>/dev/null | awk -F: '/^fpr:/ {print toupper($10); exit}')"
    if [[ "$downloaded_fpr" != "$expected_docker_fingerprint" ]]; then
      echo "[deps] docker apt key fingerprint mismatch: got '${downloaded_fpr:-<none>}' expected '$expected_docker_fingerprint'"
      exit 2
    fi
    as_root install -m 0644 "$tmp_docker_key" "$docker_keyring"
    rm -f "$tmp_docker_key"
    trap - EXIT
  fi
  existing_fpr="$(gpg --show-keys --with-colons "$docker_keyring" 2>/dev/null | awk -F: '/^fpr:/ {print toupper($10); exit}')"
  if [[ "$existing_fpr" != "$expected_docker_fingerprint" ]]; then
    echo "[deps] existing docker apt key fingerprint mismatch in $docker_keyring: got '${existing_fpr:-<none>}' expected '$expected_docker_fingerprint'"
    echo "[deps] remove the unexpected key file and retry after manual verification."
    exit 2
  fi
  as_root chmod a+r "$docker_keyring"

  arch="$(dpkg --print-architecture)"
  source /etc/os-release
  docker_repo="deb [arch=${arch} signed-by=${docker_keyring}] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable"
  echo "$docker_repo" | as_root tee /etc/apt/sources.list.d/docker.list >/dev/null

  as_root apt-get update -y
  as_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

target_user="${SUDO_USER:-${USER:-}}"
if [[ -n "$target_user" ]] && id "$target_user" >/dev/null 2>&1; then
  if bool_env_enabled "${INSTALL_DEPS_ADD_DOCKER_GROUP:-0}"; then
    if ! getent group docker >/dev/null 2>&1; then
      as_root groupadd docker
    fi
    if id -nG "$target_user" | tr ' ' '\n' | grep -qx docker; then
      echo "[deps] user '$target_user' is already in docker group"
    else
      as_root usermod -aG docker "$target_user"
      echo "[deps] added '$target_user' to docker group (log out/in required)"
    fi
  else
    echo "[deps] skipping docker group membership changes by default"
    echo "[deps] set INSTALL_DEPS_ADD_DOCKER_GROUP=1 to opt in (docker group is high privilege)."
  fi
fi

echo "[deps] completed"
docker --version || true
docker compose version || true
go version || true
g++ --version | head -n1 || true
rg --version | head -n1 || true

if is_wsl; then
  echo "[deps] note: WSL2 users should keep Docker Desktop WSL integration enabled."
fi
