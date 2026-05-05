#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

for cmd in awk grep; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing required command: $cmd"
    exit 2
  fi
done

TARGET_FILES=(
  "scripts/integration_lifecycle_chaos.sh"
  "scripts/integration_multi_issuer.sh"
  "scripts/integration_revocation.sh"
)

require_marker() {
  local file="$1"
  local marker="$2"
  if ! grep -qF -- "$marker" "$file"; then
    echo "tokenpop redaction guardrail failed: missing marker '$marker' in $file"
    exit 1
  fi
}

check_no_raw_tokenpop_payload_prints() {
  local file="$1"
  local suspect_lines
  suspect_lines="$(awk '
    /(echo|printf)/ && /\$(tokenpop_output|popj)/ {
      if ($0 !~ /\|/) {
        print NR ":" $0
      }
    }
  ' "$file")"
  if [[ -n "$suspect_lines" ]]; then
    echo "tokenpop redaction guardrail failed: raw tokenpop payload print in $file"
    echo "$suspect_lines"
    exit 1
  fi
}

for file in "${TARGET_FILES[@]}"; do
  if [[ ! -f "$file" ]]; then
    echo "tokenpop redaction guardrail failed: missing target script $file"
    exit 1
  fi

  require_marker "$file" "redact_token_json()"
  require_marker "$file" "emit_redacted_tokenpop_error()"
  require_marker "$file" "read_tokenpop_keypair()"
  require_marker "$file" "tokenpop output redacted; rc="
  require_marker "$file" "emit_redacted_tokenpop_error \"failed to generate"
  require_marker "$file" "emit_redacted_tokenpop_error \"failed to parse"

  check_no_raw_tokenpop_payload_prints "$file"

  if grep -nF -- 'echo "$tokenpop_output"' "$file" >/dev/null; then
    echo "tokenpop redaction guardrail failed: forbidden raw echo marker in $file"
    grep -nF -- 'echo "$tokenpop_output"' "$file"
    exit 1
  fi
  if grep -nF -- 'echo "$popj"' "$file" >/dev/null; then
    echo "tokenpop redaction guardrail failed: forbidden raw echo marker in $file"
    grep -nF -- 'echo "$popj"' "$file"
    exit 1
  fi

  echo "[tokenpop-redaction-guardrails] pass: $file"
done

echo "tokenpop redaction guardrails passed"
