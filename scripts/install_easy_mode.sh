#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="$ROOT_DIR/tools/easy_mode/easy_mode_ui.cpp"
OUT_DIR="$ROOT_DIR/bin"
OUT_BIN="$OUT_DIR/privacynode-easy"
AUTO_INSTALL=0

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/install_easy_mode.sh [--auto-install]

What it does:
  1) Checks required dependencies.
  2) Optionally installs missing packages on Debian/Ubuntu (--auto-install).
  3) Builds the simple C++ launcher: bin/privacynode-easy

Dependencies:
  - docker + docker compose plugin
  - curl
  - g++
  - ripgrep (`rg`)
USAGE
}

have_cmd() {
  command -v "$1" >/dev/null 2>&1
}

maybe_install_pkg() {
  local pkg="$1"
  if [[ "$AUTO_INSTALL" -ne 1 ]]; then
    return 1
  fi
  if ! have_cmd apt-get; then
    echo "cannot auto-install $pkg (apt-get not found); install manually"
    return 1
  fi
  sudo apt-get update -y
  sudo apt-get install -y "$pkg"
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

missing=0

if ! have_cmd docker; then
  echo "missing: docker"
  maybe_install_pkg docker.io || missing=1
fi

if ! have_cmd docker || ! docker compose version >/dev/null 2>&1; then
  echo "missing: docker compose plugin"
  maybe_install_pkg docker-compose-plugin || missing=1
fi

if ! have_cmd curl; then
  echo "missing: curl"
  maybe_install_pkg curl || missing=1
fi

if ! have_cmd g++; then
  echo "missing: g++"
  maybe_install_pkg g++ || maybe_install_pkg build-essential || missing=1
fi

if ! have_cmd rg; then
  echo "missing: ripgrep (rg)"
  maybe_install_pkg ripgrep || missing=1
fi

if [[ "$missing" -ne 0 ]]; then
  echo "dependency check failed; install missing packages and rerun"
  exit 1
fi

mkdir -p "$OUT_DIR"
g++ -std=c++17 -O2 -Wall -Wextra -pedantic "$SRC" -o "$OUT_BIN"
chmod +x "$OUT_BIN"

"$ROOT_DIR/scripts/easy_node.sh" check || true

echo "easy launcher installed: $OUT_BIN"
echo "run: $OUT_BIN"
