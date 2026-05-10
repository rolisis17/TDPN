#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

require_phrase() {
  local file="$1"
  local phrase="$2"
  if ! grep -Fq "$phrase" "$file"; then
    echo "access recovery pivot copy contract failed: missing phrase in $file"
    echo "phrase: $phrase"
    exit 1
  fi
}

reject_phrase() {
  local file="$1"
  local phrase="$2"
  if grep -Fq "$phrase" "$file"; then
    echo "access recovery pivot copy contract failed: stale phrase in $file"
    echo "phrase: $phrase"
    exit 1
  fi
}

require_phrase README.md "one-command local Access Recovery demo/rehearsal artifacts"
reject_phrase README.md "one-command local Access Recovery demo/pilot artifacts"
require_phrase README.md "contract/local coverage only"
require_phrase README.md "real pilot handoff still requires real helper HTTPS evidence, signed provenance, and trusted verification"

require_phrase docs/beta-playbook.md "legacy VPN closed-beta readiness only"
require_phrase docs/beta-playbook.md "It is not Access"
require_phrase docs/beta-playbook.md "Recovery pilot handoff"

require_phrase docs/access-recovery-operator-runbook.md "must target the real helper HTTPS host from"
require_phrase docs/access-recovery-operator-runbook.md "outside the helper machine"
require_phrase docs/access-recovery-operator-runbook.md "Loopback/local rehearsal output"
require_phrase docs/access-recovery-operator-runbook.md "not Access Recovery pilot handoff evidence"

require_phrase docs/access-recovery-toolkit-track.md "local integrity-only verifier output is not a pilot/operator handoff"
require_phrase docs/access-recovery-toolkit-track.md "receipt. Handoff requires the trusted verification command above, signed"
require_phrase docs/access-recovery-toolkit-track.md "provenance, and a verifier summary receipt"

echo "access recovery pivot copy integration check ok"
