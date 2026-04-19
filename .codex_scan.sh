#!/usr/bin/env bash
set -euo pipefail
cd /mnt/c/Users/dcella-d/TDPN1
printf '## risky transport and secrets\n'
rg -n -S --glob '!scripts/windows/**' --glob '*.sh' --glob '*.bash' --glob '*.run' 'curl --insecure|--insecure|http://|eval\(|bash -lc|sh -c|set -x|Authorization|TOKEN|PASSWORD|SECRET|change-me|entry-secret-default|safe default|AllowDuplicateIP' scripts deploy README.md SECURITY.md CONTRIBUTING.md GOVERNANCE.md SUPPORT.md || true
printf '\n## temp/perms and command execution\n'
rg -n -S --glob '!scripts/windows/**' --glob '*.sh' --glob '*.bash' --glob '*.run' 'mktemp|/tmp/|umask|chmod 600|chmod 700|openssl genrsa|trap|curl -k|--cacert|http://localhost|http://127.0.0.1|localhost:|127.0.0.1' scripts deploy README.md SECURITY.md CONTRIBUTING.md GOVERNANCE.md SUPPORT.md || true