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
  '<section[^>]*class="[^"]*hero[^"]*reveal'
  'class="[^"]*hero__layout'
  'class="[^"]*hero-trust'
  'class="[^"]*home-signal-bar'
  'id="onboarding-lanes-heading"'
  'class="[^"]*lane-card--client'
  'class="[^"]*lane-card--operator'
  'id="flow-cues-heading"'
  'id="trust-posture-heading"'
  'id="portal-cta-heading"'
  'class="[^"]*cta-panel'
  'href="./portal.html"'
  'href="./portal.html#operator"'
)

for pattern in "${HOME_HTML_MARKERS[@]}"; do
  require_regex_marker "$INDEX_HTML" "$pattern" "homepage structure"
done
echo "[web-home] homepage structure markers are present"

HOME_CSS_MARKERS=(
  '^:root[[:space:]]*\{'
  '\.page-home[[:space:]]*\{'
  '\.page-home[[:space:]]+\.home-main'
  '\.page-home[[:space:]]+\.hero__panel'
  '\.page-home[[:space:]]+\.section--surface[[:space:]]+\.wrap'
  '\.page-home[[:space:]]+\.lane-card--client'
  '\.page-home[[:space:]]+\.lane-card--operator'
  '\.reveal--1[[:space:]]*\{'
  '\.reveal--4[[:space:]]*\{'
  '@media[[:space:]]*\(prefers-reduced-motion:[[:space:]]*no-preference\)'
  '@media[[:space:]]*\(prefers-reduced-motion:[[:space:]]*reduce\)'
  '@keyframes[[:space:]]+gpm-reveal-up'
  '@media[[:space:]]*\(max-width:[[:space:]]*(640|720)px\)'
)

for pattern in "${HOME_CSS_MARKERS[@]}"; do
  require_regex_marker "$GPM_CSS" "$pattern" "homepage style"
done
echo "[web-home] homepage style markers are present"

echo "web home contract integration check ok"
