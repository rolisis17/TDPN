#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REQUIRED_FILES=(
  "apps/web/index.html"
  "apps/web/assets/gpm.css"
)

for path in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "web home contract failed: missing required file: $path"
    exit 1
  fi
done
echo "[web-home] required files exist"

INDEX_HTML="apps/web/index.html"
GPM_CSS="apps/web/assets/gpm.css"

require_regex_marker() {
  local file="$1"
  local pattern="$2"
  local description="$3"
  if ! grep -qE "$pattern" "$file"; then
    echo "web home contract failed: missing ${description} marker /${pattern}/ in $file"
    exit 1
  fi
}

HOME_HTML_MARKERS=(
  '<body[^>]*class="[^"]*page-home'
  '<main[^>]*class="[^"]*home-main'
  '<section[^>]*class="[^"]*mesh-hero[^"]*reveal'
  'class="[^"]*mesh-hero__grid'
  'class="[^"]*mesh-visual-card'
  'class="[^"]*hero-badges'
  'id="why-gpm-heading"'
  'class="[^"]*product-card'
  'id="server-hosts-heading"'
  'class="[^"]*server-preview-card'
  'id="trust-heading"'
  'id="portal-cta-heading"'
  'class="[^"]*cta-panel'
  'href="./portal.html"'
)

for pattern in "${HOME_HTML_MARKERS[@]}"; do
  require_regex_marker "$INDEX_HTML" "$pattern" "homepage structure"
done
echo "[web-home] homepage structure markers are present"

if grep -qF 'portal.html#operator' "$INDEX_HTML"; then
  echo "web home contract failed: public homepage must not deep-link to hidden operator/admin portal routes"
  exit 1
fi
echo "[web-home] public homepage does not deep-link to operator/admin portal routes"

HOME_CSS_MARKERS=(
  '^:root[[:space:]]*\{'
  '\.page-home[[:space:]]*\{'
  '\.page-home[[:space:]]+\.home-main'
  '\.mesh-hero[[:space:]]*\{'
  '\.mesh-hero__grid[[:space:]]*\{'
  '\.mesh-visual-card[[:space:]]*\{'
  '\.hero-badges[[:space:]]*\{'
  '\.page-home[[:space:]]+\.premium-section[[:space:]]+\.wrap'
  '\.product-card'
  '\.server-preview-card'
  '\.reveal--1[[:space:]]*\{'
  '\.reveal--4[[:space:]]*\{'
  '@media[[:space:]]*\(prefers-reduced-motion:[[:space:]]*no-preference\)'
  '@media[[:space:]]*\(prefers-reduced-motion:[[:space:]]*reduce\)'
  '@keyframes[[:space:]]+gpm-orbit'
  '@media[[:space:]]*\(max-width:[[:space:]]*(640|720)px\)'
)

for pattern in "${HOME_CSS_MARKERS[@]}"; do
  require_regex_marker "$GPM_CSS" "$pattern" "homepage style"
done
echo "[web-home] homepage style markers are present"

echo "web home contract integration check ok"
