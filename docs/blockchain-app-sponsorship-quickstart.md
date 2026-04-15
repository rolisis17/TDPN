# Blockchain App Sponsorship Quickstart (Issuer Sponsor APIs)

This quickstart shows how a blockchain app (dApp backend) can sponsor user VPN sessions through issuer sponsor APIs without requiring user wallet signing in the happy path.

## Goal

- dApp backend pays/reserves credits with issuer sponsor APIs.
- User receives a normal VPN client-access token.
- VPN dataplane remains off-chain and non-blocking; chain settlement confirmation happens asynchronously.

## Prerequisites

- Issuer service reachable (example: `http://127.0.0.1:8082`).
- Sponsor auth token configured on issuer: `ISSUER_SPONSOR_API_TOKEN`.
- dApp backend can set `X-Sponsor-Token` on requests.
- Client PoP key is available (`pop_pub_key` in base64url Ed25519 public key format).

## 1) Quote Session Price

```bash
curl -sS -X POST "$ISSUER_URL/v1/sponsor/quote" \
  -H "Content-Type: application/json" \
  -H "X-Sponsor-Token: $SPONSOR_TOKEN" \
  --data '{
    "subject": "client-123",
    "currency": "TDPNC"
  }'
```

Expected response shape:

```json
{
  "subject": "client-123",
  "price_per_mib_micros": 1000,
  "currency": "TDPNC",
  "quoted_at": 1771576000,
  "expires_at": 1771576300
}
```

## 2) Reserve Sponsor Credits

```bash
curl -sS -X POST "$ISSUER_URL/v1/sponsor/reserve" \
  -H "Content-Type: application/json" \
  -H "X-Sponsor-Token: $SPONSOR_TOKEN" \
  --data '{
    "reservation_id": "sres-client-123-001",
    "sponsor_id": "dapp-operator-1",
    "subject": "client-123",
    "session_id": "sess-client-123-001",
    "amount_micros": 200000,
    "currency": "TDPNC"
  }'
```

Expected response shape:

```json
{
  "accepted": true,
  "reservation_id": "sres-client-123-001",
  "sponsor_id": "dapp-operator-1",
  "subject": "client-123",
  "session_id": "sess-client-123-001",
  "amount_micros": 200000,
  "currency": "TDPNC",
  "status": "pending",
  "created_at": 1771576001,
  "expires_at": 1771576301
}
```

`status` follows settlement lifecycle semantics: `pending|submitted|confirmed|failed`.

## 3) Issue User VPN Token Using Sponsor Proof

Call sponsor token endpoint and include `payment_proof` with the reservation metadata:

```bash
curl -sS -X POST "$ISSUER_URL/v1/sponsor/token" \
  -H "Content-Type: application/json" \
  -H "X-Sponsor-Token: $SPONSOR_TOKEN" \
  --data '{
    "tier": 1,
    "subject": "client-123",
    "token_type": "client_access",
    "pop_pub_key": "'"$POP_PUB_KEY"'",
    "payment_proof": {
      "reservation_id": "sres-client-123-001",
      "sponsor_id": "dapp-operator-1",
      "subject": "client-123",
      "session_id": "sess-client-123-001"
    }
  }'
```

Expected response shape:

```json
{
  "token": "<signed-capability-token>",
  "expires": 1771576900,
  "jti": "tok-abc123"
}
```

The dApp returns this token to the client app for normal VPN connection flow.

## 4) Check Reservation Status

```bash
curl -sS "$ISSUER_URL/v1/sponsor/status?reservation_id=sres-client-123-001" \
  -H "X-Sponsor-Token: $SPONSOR_TOKEN"
```

After successful token issuance, `consumed_at` should be set:

```json
{
  "accepted": true,
  "reservation_id": "sres-client-123-001",
  "status": "submitted",
  "consumed_at": 1771576010
}
```

## Happy-Path Wallet UX

- User does not sign a wallet transaction for each VPN session in the happy path.
- dApp backend handles sponsor quote/reserve/token calls with `X-Sponsor-Token`.
- On-chain recording and confirmation are handled by settlement reconcile loops, not by blocking user session startup.

## Minimal Failure Handling

- `401 unauthorized sponsor`: missing/invalid `X-Sponsor-Token`.
- `400` validation errors: malformed request fields (`subject`, `reservation_id`, `amount_micros`, etc.).
- `402 payment required` on token issuance: missing/invalid/expired/insufficient sponsor payment proof.
- `404` on status: unknown reservation id.
