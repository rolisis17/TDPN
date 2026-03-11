# Operator Lifecycle Runbook

This runbook documents repeatable onboarding/offboarding for provider/authority operators using:

`./scripts/easy_node.sh prod-operator-lifecycle-runbook`

It is designed for production-style operations with machine-readable summaries.

## 1) Onboard a provider operator

```bash
./scripts/easy_node.sh prod-operator-lifecycle-runbook \
  --action onboard \
  --mode provider \
  --public-host <PROVIDER_PUBLIC_IP_OR_DNS> \
  --authority-directory https://<AUTHORITY_IP_OR_DNS>:8081 \
  --authority-issuer https://<AUTHORITY_IP_OR_DNS>:8082 \
  --peer-directories https://<PEER_DIRECTORY_1>:8081,https://<PEER_DIRECTORY_2>:8081 \
  --peer-identity-strict 1 \
  --min-peer-operators 2 \
  --prod-profile 1 \
  --preflight-check 1 \
  --health-check 1 \
  --verify-relays 1 \
  --verify-relay-min-count 2
```

What it does:
- runs `server-preflight` (optional, enabled by default)
- runs `server-up`
- checks directory/entry/exit health (and issuer health in authority mode)
- verifies relay visibility in directory feed for the operator id
- writes summary JSON to `.easy-node-logs/...`

## 2) Onboard an authority operator

```bash
./scripts/easy_node.sh prod-operator-lifecycle-runbook \
  --action onboard \
  --mode authority \
  --public-host <AUTHORITY_PUBLIC_IP_OR_DNS> \
  --peer-directories https://<PEER_DIRECTORY_1>:8081,https://<PEER_DIRECTORY_2>:8081 \
  --peer-identity-strict 1 \
  --min-peer-operators 2 \
  --prod-profile 1 \
  --preflight-check 1 \
  --health-check 1 \
  --verify-relays 1
```

## 3) Offboard an operator cleanly

```bash
./scripts/easy_node.sh prod-operator-lifecycle-runbook \
  --action offboard \
  --operator-id <OPERATOR_ID> \
  --directory-url https://<AUTHORITY_OR_TRUSTED_DIRECTORY>:8081 \
  --verify-absent 1
```

What it does:
- runs `server-down`
- waits until operator relays disappear from directory feed
- writes summary JSON with pass/fail and failure step

## 4) Useful flags

- `--summary-json <path>`: explicit summary artifact path.
- `--print-summary-json 1`: print summary payload to stdout.
- `--verify-relay-timeout-sec <N>`: wait budget for relay publication/removal.
- `--verify-relay-min-count <N>`: minimum relays required for onboard verification.
- `--health-timeout-sec <N>`: per-endpoint readiness timeout.
- `--preflight-timeout-sec <N>`: preflight timeout.

## 5) Summary JSON fields

Main fields in output summary:
- `status`: `ok` or `fail`
- `action`: `onboard` or `offboard`
- `mode`: resolved mode (`authority` or `provider`)
- `completed_steps`: successful steps list
- `failure_step` and `failure_rc`: first failed stage
- `relay_policy.observed_count`: latest operator relay count seen
- `directory_url` and `operator_id`: verification target context

## 6) Troubleshooting

- `failure_step=server_preflight`:
  - peer/issuer reachability, identity floor, or strict peer-identity checks failed.
- `failure_step=server_up`:
  - stack start failed (`docker compose`/env/runtime issue).
- `failure_step=health_check`:
  - local services did not expose expected endpoints in timeout.
- `failure_step=relay_verify`:
  - relay feed did not show required operator relay count in timeout.
- `failure_step=relay_absent_verify`:
  - operator relays still present after offboard in timeout.
