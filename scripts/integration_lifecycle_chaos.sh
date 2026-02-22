#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

mkdir -p .gocache
export GOCACHE="${GOCACHE:-$ROOT_DIR/.gocache}"

DIR_PORT=8381
ISSUER_PORT=8382
ENTRY_PORT=8383
EXIT_PORT=8384
ENTRY_DATA_PORT=53820
EXIT_DATA_PORT=53821

DIRECTORY_ADDR="127.0.0.1:${DIR_PORT}" \
ISSUER_ADDR="127.0.0.1:${ISSUER_PORT}" \
ENTRY_ADDR="127.0.0.1:${ENTRY_PORT}" \
EXIT_ADDR="127.0.0.1:${EXIT_PORT}" \
ENTRY_DATA_ADDR="127.0.0.1:${ENTRY_DATA_PORT}" \
EXIT_DATA_ADDR="127.0.0.1:${EXIT_DATA_PORT}" \
DIRECTORY_URL="http://127.0.0.1:${DIR_PORT}" \
ISSUER_URL="http://127.0.0.1:${ISSUER_PORT}" \
ENTRY_URL="http://127.0.0.1:${ENTRY_PORT}" \
EXIT_CONTROL_URL="http://127.0.0.1:${EXIT_PORT}" \
DIRECTORY_ISSUER_TRUST_URLS="http://127.0.0.1:${ISSUER_PORT}" \
DIRECTORY_ISSUER_SYNC_SEC=1 \
EXIT_REVOCATION_REFRESH_SEC=1 \
timeout 60s go run ./cmd/node --directory --issuer --entry --exit >/tmp/lifecycle_chaos_node.log 2>&1 &
node_pid=$!

cleanup() {
  kill "$node_pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

ready=0
for _ in $(seq 1 40); do
  if curl -fsS "http://127.0.0.1:${ENTRY_PORT}/v1/health" >/dev/null && \
    curl -fsS "http://127.0.0.1:${ISSUER_PORT}/v1/pubkey" >/dev/null; then
    ready=1
    break
  fi
  sleep 0.25
done
if [[ "$ready" -ne 1 ]]; then
  echo "lifecycle chaos stack did not become ready"
  cat /tmp/lifecycle_chaos_node.log
  exit 1
fi

client_pub="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
pop_json=$(go run ./cmd/tokenpop gen)
pop_pub=$(echo "$pop_json" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
pop_priv=$(echo "$pop_json" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
if [[ -z "$pop_pub" || -z "$pop_priv" ]]; then
  echo "failed to generate seed token PoP keypair"
  echo "$pop_json"
  exit 1
fi

token_json=$(curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/token" -H 'Content-Type: application/json' \
  --data "{\"tier\":1,\"subject\":\"client-chaos-seed\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub\",\"exit_scope\":[\"exit-local-1\"]}")
token=$(echo "$token_json" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
jti=$(echo "$token_json" | sed -n 's/.*"jti":"\([^"]*\)".*/\1/p')

if [[ -z "$token" || -z "$jti" ]]; then
  echo "failed to parse token/jti for lifecycle chaos seed token"
  echo "$token_json"
  cat /tmp/lifecycle_chaos_node.log
  exit 1
fi

token_proof=$(go run ./cmd/tokenpop sign \
  --private-key "$pop_priv" \
  --token "$token" \
  --exit-id "exit-local-1" \
  --proof-nonce "seed-${jti}" \
  --client-inner-pub "$client_pub" \
  --transport "policy-json" \
  --requested-mtu 1280 \
  --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
if [[ -z "$token_proof" ]]; then
  echo "failed to sign seed token proof"
  exit 1
fi

payload_file=/tmp/lifecycle_chaos_payload.json
cat >"$payload_file" <<JSON
{"exit_id":"exit-local-1","token":"$token","token_proof":"$token_proof","token_proof_nonce":"seed-${jti}","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON

race_log=/tmp/lifecycle_chaos_race.log
: >"$race_log"

(
  for _ in $(seq 1 20); do
    curl -sS -X POST "http://127.0.0.1:${ENTRY_PORT}/v1/path/open" \
      -H 'Content-Type: application/json' \
      --data @"$payload_file" >>"$race_log" || true
    printf "\n" >>"$race_log"
    sleep 0.2
  done
) &
race_pid=$!

sleep 1
until_ts=$(( $(date +%s) + 180 ))
curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/revoke-token" \
  -H 'X-Admin-Token: dev-admin-token' \
  -H 'Content-Type: application/json' \
  --data "{\"jti\":\"$jti\",\"until\":$until_ts}" >/tmp/lifecycle_chaos_revoke.json

(
  for _ in $(seq 1 14); do
    du=$(( $(date +%s) + 180 ))
    curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/dispute" \
      -H 'X-Admin-Token: dev-admin-token' \
      -H 'Content-Type: application/json' \
      --data "{\"subject\":\"exit-local-1\",\"tier_cap\":1,\"until\":$du,\"reason\":\"chaos-cycle\"}" >/dev/null || true
    sleep 0.12
    curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/admin/subject/dispute/clear" \
      -H 'X-Admin-Token: dev-admin-token' \
      -H 'Content-Type: application/json' \
      --data '{"subject":"exit-local-1","reason":"chaos-cycle-clear"}' >/dev/null || true
    sleep 0.12
  done
) >/tmp/lifecycle_chaos_dispute.log 2>&1 &
dispute_pid=$!

fresh_log=/tmp/lifecycle_chaos_fresh.log
: >"$fresh_log"
(
  for _ in $(seq 1 18); do
    popj=$(go run ./cmd/tokenpop gen || true)
    pop_pub_iter=$(echo "$popj" | sed -n 's/.*"public_key":"\([^"]*\)".*/\1/p')
    pop_priv_iter=$(echo "$popj" | sed -n 's/.*"private_key":"\([^"]*\)".*/\1/p')
    if [[ -z "$pop_pub_iter" || -z "$pop_priv_iter" ]]; then
      sleep 0.15
      continue
    fi
    tj=$(curl -sS -X POST "http://127.0.0.1:${ISSUER_PORT}/v1/token" -H 'Content-Type: application/json' \
      --data "{\"tier\":1,\"subject\":\"client-chaos-fresh\",\"token_type\":\"client_access\",\"pop_pub_key\":\"$pop_pub_iter\",\"exit_scope\":[\"exit-local-1\"]}" || true)
    tk=$(echo "$tj" | sed -n 's/.*"token":"\([^"]*\)".*/\1/p')
    if [[ -n "$tk" ]]; then
      fresh_nonce="fresh-$RANDOM-$(date +%s%N)"
      tp=$(go run ./cmd/tokenpop sign \
        --private-key "$pop_priv_iter" \
        --token "$tk" \
        --exit-id "exit-local-1" \
        --proof-nonce "$fresh_nonce" \
        --client-inner-pub "$client_pub" \
        --transport "policy-json" \
        --requested-mtu 1280 \
        --requested-region "local" | sed -n 's/.*"proof":"\([^"]*\)".*/\1/p')
      if [[ -z "$tp" ]]; then
        sleep 0.15
        continue
      fi
      pl=$(cat <<JSON
{"exit_id":"exit-local-1","token":"$tk","token_proof":"$tp","token_proof_nonce":"$fresh_nonce","client_inner_pub":"$client_pub","transport":"policy-json","requested_mtu":1280,"requested_region":"local"}
JSON
)
      curl -sS -X POST "http://127.0.0.1:${ENTRY_PORT}/v1/path/open" -H 'Content-Type: application/json' --data "$pl" >>"$fresh_log" || true
      printf "\n" >>"$fresh_log"
    fi
    sleep 0.15
  done
) &
fresh_pid=$!

wait "$race_pid"
wait "$dispute_pid"
wait "$fresh_pid"

accepted_seed=$(rg -c '"accepted":true' "$race_log" || true)
revoked_seed=$(rg -c 'token revoked' "$race_log" || true)
if [[ "$accepted_seed" -lt 1 ]]; then
  echo "expected at least one accepted open before revocation in race loop"
  cat "$race_log"
  cat /tmp/lifecycle_chaos_node.log
  exit 1
fi
if [[ "$revoked_seed" -lt 1 ]]; then
  echo "expected revoked-token denial during race loop"
  cat "$race_log"
  cat /tmp/lifecycle_chaos_node.log
  exit 1
fi

accepted_fresh=$(rg -c '"accepted":true' "$fresh_log" || true)
if [[ "$accepted_fresh" -lt 3 ]]; then
  echo "expected fresh token opens to continue under dispute/revocation churn"
  cat "$fresh_log"
  cat /tmp/lifecycle_chaos_node.log
  exit 1
fi

if rg -q 'panic:' /tmp/lifecycle_chaos_node.log; then
  echo "unexpected panic during lifecycle chaos run"
  cat /tmp/lifecycle_chaos_node.log
  exit 1
fi

metrics=$(curl -sS "http://127.0.0.1:${EXIT_PORT}/v1/metrics")
revoked_drops=$(echo "$metrics" | sed -n 's/.*"dropped_token_revoked":\([0-9][0-9]*\).*/\1/p')
if [[ -z "$revoked_drops" || "$revoked_drops" -lt 1 ]]; then
  echo "expected dropped_token_revoked metrics > 0 after chaos race"
  echo "$metrics"
  cat /tmp/lifecycle_chaos_node.log
  exit 1
fi

audit=$(curl -sS "http://127.0.0.1:${ISSUER_PORT}/v1/admin/audit?limit=40" -H 'X-Admin-Token: dev-admin-token')
if ! echo "$audit" | rg -q 'subject-dispute-apply'; then
  echo "expected dispute apply events in issuer audit"
  echo "$audit"
  cat /tmp/lifecycle_chaos_node.log
  exit 1
fi

echo "lifecycle chaos integration check ok (accepted_seed=${accepted_seed}, revoked_seed=${revoked_seed}, accepted_fresh=${accepted_fresh})"
