# Planned Exit Selection Policy (Country + Reputation)

## Goal
Allow clients to request exit locality (preferably country), while preserving decentralization and avoiding concentration on only top exits.

Status: implemented for MVP v0.
- Implemented now:
  - client preference inputs: country + region fallback with strict locality mode
  - configurable locality fallback order (`country`, `region`, `region-prefix`, `global`)
  - optional minimum geolocation-confidence gate (`geo_confidence`) for locality matching
  - reputation-weighted exit ordering with exploration floor
  - signed directory selection feed endpoint + client verification/consumption
  - signed directory trust-attestation feed endpoint + client verification/consumption
  - optional feed vote threshold before side-channel scores are applied
  - optional trust-feed vote threshold before bond/stake attestations are applied
  - federated peer score aggregation across directory operators with vote thresholding

## User-Facing Behavior (Target)
- User can select:
  - preferred country (ISO-3166-1 alpha-2, e.g. `US`, `DE`, `BR`)
  - optional broader region fallback (e.g. `us-east`)
- If no healthy exits exist in requested country:
  - fallback to requested region (if provided)
  - otherwise fallback to global policy selection

## Descriptor Metadata Needed
Planned/implemented signed fields in relay descriptors:
- `country_code` (implemented for country-aware selection)
- `geo_confidence` (implemented; client can require minimum confidence)
- `region` (already present)
- `operator_id` (implemented for per-operator caps and anti-concentration)
- optional `selection` metadata:
  - `reputation_score` (0..1)
  - `uptime_score` (0..1)
  - `capacity_score` (0..1)
  - `abuse_penalty` (0..1)
  - `bond_score` (0..1)
  - `stake_score` (0..1)

All selection inputs used by clients should be from signed descriptor data (or signed side-channel snapshots) so they cannot be tampered with in transit.

## Selection Pipeline (Planned)
1. Build candidate set from verified directories (quorum + vote threshold).
2. Filter by health and policy eligibility.
3. Apply locality filter:
   - country first
   - region fallback
   - region-prefix fallback (optional)
   - global fallback (optional)
4. Apply weighted selection among remaining candidates.
5. Enforce anti-concentration constraints (operator caps).
6. Select final exit by weighted random.

## Weighted Selection Model (Planned)
Base score example:
`score = a*reputation + b*uptime + c*capacity - d*abuse_penalty`

Then convert to probability weight with safety floors:
- `weight = max(min_weight, score)`
- exploration floor to protect new exits (e.g. 5-15% traffic reserved to non-top exits)

This keeps better exits preferred while still allowing new/lower-score exits to gain reputation over time.

## Anti-Centralization Constraints (Planned)
- Per-operator traffic share cap in client selection logic.
- Current scaffold includes a coarse per-operator candidate cap before pair ranking.
- Optional ASN/diversity guardrails.
- Deterministic tie-breakers + periodic reshuffle to avoid permanent lock-in.

## Reputation System Notes (Planned)
Reputation should combine:
- long-term reliability
- abuse/complaint penalties
- objective availability/performance signals
- optional bond/stake signal

Avoid pure “winner-takes-all” scoring; include decay and exploration.

## Privacy Notes (Planned)
- Avoid too-sticky exit affinity for long periods.
- Rotate exits with bounded lifetime policies to reduce fingerprintability.
- Keep selection logic local to client (no central selector required).

## Phased Implementation
1. Done: signed `country_code` + `operator_id` fields, client locality preferences, geo-confidence gate, and per-operator candidate cap.
2. Done: weighted random sampler with exploration floor.
3. Done: federated reputation feed exchange/aggregation across peer directories.
4. Done: signed trust-attestation exchange/aggregation across peer directories with bond/stake signals.
