#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
AUTO_INSTALL=0

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/install_wsl2_mode.sh [--auto-install]

Purpose:
  WSL2-oriented installer wrapper for the beta workflow.

What it checks:
  - running in WSL (warn if not)
  - Docker CLI + compose plugin available in WSL
  - Docker daemon reachable (typically Docker Desktop WSL integration)

What it installs (optional, Debian/Ubuntu only):
  - curl
  - g++
  - ripgrep

Then it runs:
  ./scripts/install_easy_mode.sh [--auto-install]
USAGE
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

is_wsl() {
  grep -qi microsoft /proc/version 2>/dev/null || [[ -n "${WSL_DISTRO_NAME:-}" ]]
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --auto-install)
      AUTO_INSTALL=1
      shift
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown arg: $1"
      usage
      exit 2
      ;;
  esac
done

if ! is_wsl; then
  echo "note: this script is intended for WSL2. Continuing anyway."
fi

if ! have_cmd docker; then
  echo "missing docker inside WSL."
  echo "Install Docker Desktop on Windows and enable WSL integration for this distro."
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "missing docker compose plugin inside WSL."
  echo "Enable Docker Desktop WSL integration or install docker compose plugin in distro."
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "docker daemon not reachable from WSL."
  echo "In Docker Desktop: Settings > Resources > WSL Integration > enable your distro."
  exit 1
fi

extra_pkgs=()
if ! have_cmd curl; then
  extra_pkgs+=(curl)
fi
if ! have_cmd g++; then
  extra_pkgs+=(g++)
fi
if ! have_cmd rg; then
  extra_pkgs+=(ripgrep)
fi

if [[ ${#extra_pkgs[@]} -gt 0 ]]; then
  if [[ "$AUTO_INSTALL" -eq 1 ]]; then
    if have_cmd apt-get; then
      sudo apt-get update -y
      sudo apt-get install -y "${extra_pkgs[@]}"
    else
      echo "missing packages: ${extra_pkgs[*]}"
      echo "auto-install only supports apt-get; install manually and rerun"
      exit 1
    fi
  else
    echo "missing packages: ${extra_pkgs[*]}"
    echo "rerun with --auto-install or install manually"
    exit 1
  fi
fi

cd "$ROOT_DIR"
if [[ "$AUTO_INSTALL" -eq 1 ]]; then
  ./scripts/install_easy_mode.sh --auto-install
else
  ./scripts/install_easy_mode.sh
fi

echo
echo "WSL2 beta setup complete."
echo "Next: ./bin/privacynode-easy"
