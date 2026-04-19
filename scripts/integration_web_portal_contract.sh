#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

REQUIRED_FILES=(
  "apps/web/portal.html"
  "apps/web/assets/portal.js"
  "apps/web/README.md"
)

for path in "${REQUIRED_FILES[@]}"; do
  if [[ ! -f "$path" ]]; then
    echo "web portal contract failed: missing required file: $path"
    exit 1
  fi
done
echo "[web-portal] required files exist"

PORTAL_HTML="apps/web/portal.html"
PORTAL_JS="apps/web/assets/portal.js"
README_FILE="apps/web/README.md"

# Client-readiness UI markers in portal scaffold.
if ! grep -qF 'id="status_banner"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing readiness banner marker id=status_banner in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="status_title"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing readiness status marker id=status_title in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="status_detail"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing readiness guidance marker id=status_detail in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="onboarding_step_client"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing client-step readiness marker id=onboarding_step_client in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="register_client_btn"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing register-client action marker id=register_client_btn in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="client_readiness"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing client readiness marker id=client_readiness in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="client_readiness_status"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing client readiness status marker id=client_readiness_status in $PORTAL_HTML"
  exit 1
fi
if ! grep -qF 'id="client_readiness_guidance"' "$PORTAL_HTML"; then
  echo "web portal contract failed: missing client readiness guidance marker id=client_readiness_guidance in $PORTAL_HTML"
  exit 1
fi
echo "[web-portal] portal readiness UI markers are present"

# Readiness field markers (new + compatibility aliases).
if ! grep -qE 'client_tab_visible|tab_visible' "$PORTAL_JS"; then
  echo "web portal contract failed: missing readiness marker for client_tab_visible/tab_visible in $PORTAL_JS"
  exit 1
fi
if ! grep -qE 'client_lock_reason|lock_reason' "$PORTAL_JS"; then
  echo "web portal contract failed: missing readiness marker for client_lock_reason/lock_reason in $PORTAL_JS"
  exit 1
fi

# Compute/render/gating markers for client-readiness flow.
JS_MARKERS=(
  'function parseServerReadiness('
  'function parseClientRegistrationStatus('
  'function setClientReadiness('
  'function computeClientReadiness('
  'function refreshClientReadiness('
  'function syncClientRegistrationAction('
  'function refreshOnboardingSteps('
  'setStepState(onboardingStepClientEl'
  'const clientLockReason = nonEmptyString(firstDefined(readiness.client_lock_reason, readiness.clientLockReason));'
  'clientTabVisible: parseBooleanLike(firstDefined(readiness.client_tab_visible, readiness.clientTabVisible))'
  'function refreshServerReadinessStatus('
  'byId("register_client_btn").addEventListener'
  'session_token: byId("session_token").value.trim()'
  'compatibilityOverrideEnabled()'
)
for marker in "${JS_MARKERS[@]}"; do
  if ! grep -qF "$marker" "$PORTAL_JS"; then
    echo "web portal contract failed: missing portal JS readiness/gating marker '$marker' in $PORTAL_JS"
    exit 1
  fi
done
echo "[web-portal] portal JS readiness compute/render/gating markers are present"

if ! grep -qF 'client_tab_visible' "$README_FILE"; then
  echo "web portal contract failed: README must mention readiness.client_tab_visible"
  exit 1
fi
if ! grep -qF 'client_lock_reason' "$README_FILE"; then
  echo "web portal contract failed: README must mention readiness.client_lock_reason"
  exit 1
fi
if ! grep -qiE 'register(ing|ed)? client|client registration|register-client' "$README_FILE"; then
  echo "web portal contract failed: README must describe client registration lock/readiness behavior"
  exit 1
fi
echo "[web-portal] README readiness-field notes are present"

echo "web portal contract integration check ok"
