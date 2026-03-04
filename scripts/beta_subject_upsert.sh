#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage:
  ./scripts/beta_subject_upsert.sh \
    --issuer-url URL \
    --admin-token TOKEN \
    --subject ID \
    [--kind client|relay-exit] \
    [--tier 1|2|3] \
    [--reputation 0..1] \
    [--bond FLOAT] \
    [--stake FLOAT]

Purpose:
  Upsert one issuer subject profile for closed-beta allowlist control.
USAGE
}

issuer_url="${ISSUER_URL:-http://127.0.0.1:8082}"
admin_token="${ISSUER_ADMIN_TOKEN:-}"
subject=""
kind="client"
tier="1"
reputation="0"
bond="0"
stake="0"

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
    --subject)
      subject="${2:-}"
      shift 2
      ;;
    --kind)
      kind="${2:-}"
      shift 2
      ;;
    --tier)
      tier="${2:-}"
      shift 2
      ;;
    --reputation)
      reputation="${2:-}"
      shift 2
      ;;
    --bond)
      bond="${2:-}"
      shift 2
      ;;
    --stake)
      stake="${2:-}"
      shift 2
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

if [[ -z "$admin_token" || -z "$subject" ]]; then
  echo "--admin-token and --subject are required"
  usage
  exit 2
fi
if [[ "$kind" != "client" && "$kind" != "relay-exit" ]]; then
  echo "--kind must be client or relay-exit"
  exit 2
fi
if [[ "$tier" != "1" && "$tier" != "2" && "$tier" != "3" ]]; then
  echo "--tier must be 1, 2, or 3"
  exit 2
fi

issuer_url="${issuer_url%/}"

payload="$(cat <<EOF
{"subject":"${subject}","kind":"${kind}","tier":${tier},"reputation":${reputation},"bond":${bond},"stake":${stake}}
EOF
)"

echo "upserting subject profile: subject=${subject} kind=${kind} tier=${tier}"
curl -fsS -X POST "${issuer_url}/v1/admin/subject/upsert" \
  --connect-timeout 4 \
  --max-time 12 \
  -H "Authorization: Bearer ${admin_token}" \
  -H "Content-Type: application/json" \
  --data "$payload"
echo
echo "reading back subject profile:"
curl -fsS "${issuer_url}/v1/admin/subject/get?subject=${subject}" \
  --connect-timeout 4 \
  --max-time 12 \
  -H "Authorization: Bearer ${admin_token}"
echo
