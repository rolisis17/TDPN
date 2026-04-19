#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SINGLE_UPSERT="$ROOT_DIR/scripts/beta_subject_upsert.sh"

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/beta_subject_batch_upsert.sh \
    --issuer-url URL \
    [--admin-token TOKEN | --admin-token-file FILE] \
    --csv FILE \
    [--default-kind client|relay-exit] \
    [--default-tier 1|2|3] \
    [--continue-on-error [0|1]]

CSV format:
  subject,kind,tier,reputation,bond,stake

Notes:
  - Header row is optional and auto-detected when first column is "subject".
  - Empty lines and lines starting with "#" are ignored.
  - Missing values fall back to defaults:
    kind=client, tier=1, reputation=0, bond=0, stake=0
USAGE
}

trim() {
  local v="$1"
  v="${v#"${v%%[![:space:]]*}"}"
  v="${v%"${v##*[![:space:]]}"}"
  printf '%s' "$v"
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

issuer_url="${ISSUER_URL:-http://127.0.0.1:8082}"
admin_token="${ISSUER_ADMIN_TOKEN:-}"
admin_token_file="${ISSUER_ADMIN_TOKEN_FILE:-}"
csv_file=""
default_kind="client"
default_tier="1"
continue_on_error="0"
ephemeral_admin_token_file=""

cleanup() {
  if [[ -n "$ephemeral_admin_token_file" && -f "$ephemeral_admin_token_file" ]]; then
    rm -f "$ephemeral_admin_token_file"
  fi
}
trap cleanup EXIT

while [[ $# -gt 0 ]]; do
  case "$1" in
    --issuer-url)
      issuer_url="${2:-}"
      shift 2
      ;;
    --admin-token)
      admin_token="${2:-}"
      shift 2
      ;;
    --admin-token-file)
      admin_token_file="${2:-}"
      shift 2
      ;;
    --csv)
      csv_file="${2:-}"
      shift 2
      ;;
    --default-kind)
      default_kind="${2:-}"
      shift 2
      ;;
    --default-tier)
      default_tier="${2:-}"
      shift 2
      ;;
    --continue-on-error)
      if [[ $# -ge 2 && ( "${2:-}" == "0" || "${2:-}" == "1") ]]; then
        continue_on_error="${2:-}"
        shift 2
      else
        continue_on_error="1"
        shift
      fi
      ;;
    -h|--help|help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1"
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$csv_file" ]]; then
  echo "--csv is required"
  usage
  exit 2
fi
if [[ -n "$admin_token" && -n "$admin_token_file" ]]; then
  echo "use either --admin-token OR --admin-token-file"
  usage
  exit 2
fi
if [[ -n "$admin_token_file" ]]; then
  if [[ ! -f "$admin_token_file" ]]; then
    echo "admin token file not found: $admin_token_file"
    exit 2
  fi
fi
if [[ -z "$admin_token" && -z "$admin_token_file" ]]; then
  echo "admin auth is required: provide --admin-token or --admin-token-file"
  usage
  exit 2
fi
if [[ ! -f "$csv_file" ]]; then
  echo "csv file not found: $csv_file"
  exit 2
fi
if [[ "$default_kind" != "client" && "$default_kind" != "relay-exit" ]]; then
  echo "--default-kind must be client or relay-exit"
  exit 2
fi
if [[ "$default_tier" != "1" && "$default_tier" != "2" && "$default_tier" != "3" ]]; then
  echo "--default-tier must be 1, 2, or 3"
  exit 2
fi
if [[ "$continue_on_error" != "0" && "$continue_on_error" != "1" ]]; then
  echo "--continue-on-error must be 0 or 1"
  exit 2
fi
if [[ ! -x "$SINGLE_UPSERT" ]]; then
  echo "required helper script missing or not executable: $SINGLE_UPSERT"
  exit 2
fi

issuer_url="${issuer_url%/}"

if [[ -n "$admin_token" && -z "$admin_token_file" ]]; then
  ephemeral_admin_token_file="$(mktemp)"
  chmod 600 "$ephemeral_admin_token_file"
  printf '%s' "$admin_token" >"$ephemeral_admin_token_file"
  admin_token_file="$ephemeral_admin_token_file"
  admin_token=""
fi

total=0
ok=0
failed=0
line_no=0

while IFS=, read -r c_subject c_kind c_tier c_reputation c_bond c_stake _rest; do
  line_no=$((line_no + 1))
  row_raw="$(trim "${c_subject:-}")"
  if [[ -z "$row_raw" ]]; then
    continue
  fi
  if [[ "${row_raw:0:1}" == "#" ]]; then
    continue
  fi
  if [[ "$line_no" -eq 1 && "$(lower "$row_raw")" == "subject" ]]; then
    continue
  fi

  subject="$row_raw"
  kind="$(trim "${c_kind:-}")"
  tier="$(trim "${c_tier:-}")"
  reputation="$(trim "${c_reputation:-}")"
  bond="$(trim "${c_bond:-}")"
  stake="$(trim "${c_stake:-}")"

  [[ -z "$kind" ]] && kind="$default_kind"
  [[ -z "$tier" ]] && tier="$default_tier"
  [[ -z "$reputation" ]] && reputation="0"
  [[ -z "$bond" ]] && bond="0"
  [[ -z "$stake" ]] && stake="0"

  total=$((total + 1))
  echo "[batch-upsert] row=$line_no subject=$subject kind=$kind tier=$tier"
  upsert_cmd=(
    "$SINGLE_UPSERT"
    --issuer-url "$issuer_url"
    --subject "$subject"
    --kind "$kind"
    --tier "$tier"
    --reputation "$reputation"
    --bond "$bond"
    --stake "$stake"
  )
  upsert_cmd+=(--admin-token-file "$admin_token_file")
  if "${upsert_cmd[@]}"; then
    ok=$((ok + 1))
  else
    failed=$((failed + 1))
    echo "[batch-upsert] failed row=$line_no subject=$subject"
    if [[ "$continue_on_error" == "0" ]]; then
      break
    fi
  fi
done <"$csv_file"

echo "[batch-upsert] summary total=$total ok=$ok failed=$failed"
if ((failed > 0)); then
  exit 1
fi
