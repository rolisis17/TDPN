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
  if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | as_root tee /etc/apt/keyrings/docker.asc >/dev/null
  fi
  as_root chmod a+r /etc/apt/keyrings/docker.asc

  arch="$(dpkg --print-architecture)"
  source /etc/os-release
  docker_repo="deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable"
  echo "$docker_repo" | as_root tee /etc/apt/sources.list.d/docker.list >/dev/null

  as_root apt-get update -y
  as_root apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi

target_user="${SUDO_USER:-${USER:-}}"
if [[ -n "$target_user" ]] && id "$target_user" >/dev/null 2>&1; then
  if ! getent group docker >/dev/null 2>&1; then
    as_root groupadd docker
  fi
  if id -nG "$target_user" | tr ' ' '\n' | grep -qx docker; then
    echo "[deps] user '$target_user' is already in docker group"
  else
    as_root usermod -aG docker "$target_user"
    echo "[deps] added '$target_user' to docker group (log out/in required)"
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
